(ns kanar.core.saml
  (:require
    [kanar.core :as kc]
    [kanar.core.util :as ku]
    [clojure.data.xml :as xml]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log])
  (:import (javax.xml.bind DatatypeConverter)
           (java.util.zip Deflater Inflater)
           (java.io ByteArrayOutputStream)))


(defn saml2-raw-req [{:keys [id provider url issuer]}]
  [:AuthnRequest {:ID (ku/random-string 32), :Version "2.0" :IssueInstant (ku/xml-time),
                  :ProtocolBinding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  :ProviderName provider
                  :AssertionConsumerServiceURL url}
   [:Issuer issuer]
   [:NameIDPolicy {:AllowCreate :true, :Format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}]])


(defn inflate-str [data]
  (let [zf (Inflater. true)
              buf (byte-array 65536)]
    (.setInput zf data)
    (let [len (.inflate zf buf)]
      (String. buf 0 len "UTF-8"))))



(defn saml2-parse-req [param]
  (if param
    (->
      param
      DatatypeConverter/parseBase64Binary
      inflate-str
      xml/parse-str
      :attrs)))


(defn saml2-raw-success-resp [svt]
  (let [idt (:id-template (:service svt) "{{id}}")
        uid (if idt (.replace idt "{{id}}" (get-in svt [:tgt :princ :id])))]
    [:samlp:Response
     {:xmlns:saml        "urn:oasis:names:tc:SAML:2.0:assertion"
      :xmlns:samlp  "urn:oasis:names:tc:SAML:2.0:protocol"
      :ID           (ku/random-string 40 "abcdefghijklmnopqrstuvwxyz")
      :InResponseTo (:ID (:saml-req svt))
      :IssueInstant (ku/xml-time)
      :Version      "2.0"}
     [:saml:Issuer "https://sso.resonant.io"]
     [:samlp:Status
      [:samlp:StatusCode {:Value "urn:oasis:names:tc:SAML:2.0:status:Success"}]]
     [:saml:Assertion
      {:ID           (ku/random-string 40 "abcdefghijklmnopqrstuvwxyz")
       :Version      "2.0"
       :IssueInstant (ku/xml-time)}
      [:saml:Issuer "https://sso.resonant.io"]
      [:saml:Subject
       [:saml:NameID {:Format "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"} uid]
       [:saml:SubjectConfirmation {:Method "urn:oasis:names:tc:SAML:2.0:cm:bearer"}
        [:saml:SubjectConfirmationData
         {:NotOnOrAfter (ku/xml-time (ku/cur-time -30000))
          :Recipient    (:url svt),
          :InResponseTo (:ID (:saml-req svt))}]]]
      [:saml:Conditions
       {:NotBefore    (ku/xml-time (ku/cur-time -30000))
        :NotOnOrAfter (ku/xml-time (ku/cur-time 300000))}
       [:saml:AudienceRestriction
        [:saml:Audience "google.com"]]]
      [:saml:AuthnStatement {:AuthnInstant (ku/xml-time)}
       [:saml:AuthnContext
        [:saml:AuthnContextClassRef "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"]]]
      ]]))


(defn deflate-str [data]
  (let [df (Deflater. 9 true)
        buf (byte-array 65536)]
    (.setInput df (.getBytes data))
    (.finish df)
    (let [len (.deflate df buf)
          is (ByteArrayOutputStream.)]
      (.write is buf 0 len)
      (.toByteArray is))))


(defn saml2-param-success-resp [svt kp]
  (-> svt
      saml2-raw-success-resp
      ku/emit-dom
      (ku/xml-sign kp)
      ku/dom-to-str))


(defn render-saml-redirect-form [url fields]
  (str
    "<!DOCTYPE html>"
    (ku/emit-xml
      [:html [:head]
       [:body {:onload "javascript:document.samlLoginForm.submit()"}
        [:div {:style "display: none;"}
         [:form {:name "samlLoginForm" :action url :method "post"}
          (for [[k v] fields]
            [:textarea {:name (name k)} v])
          [:input {:type "submit" :value "Submit SAML Response"}]]]]])))


; Core framework plugin functions.

(defn parse-saml2-req [{{:keys [SAMLRequest RelayState]} :params :as req}]
  "Parses SAML2 request. This function can be used with sso-request-parse-wfn."
  (when SAMLRequest
    (try+
      (let [saml-req (saml2-parse-req SAMLRequest)]
        (merge req
               {:protocol     :saml, :subprotocol (if RelayState :google :default),
                :service-url  (:AssertionConsumerServiceURL saml-req), :saml-req saml-req
                :hidden-params {:SAMLRequest SAMLRequest}}
               (if RelayState {:service-params {:RelayState RelayState}
                               :hidden-params {:RelayState RelayState :SAMLRequest SAMLRequest}} {})))
      (catch Object _
        (log/error "Unparsable SAML request:" SAMLRequest)
        nil))))


(defmethod kc/service-redirect :saml [{:keys [hidden-params service-url]}]
  (str
    "<!DOCTYPE html>"
    (ku/emit-xml
      [:html [:head]
       [:body {:onload "javascript:document.samlLoginForm.submit()"}
        [:div {:style "display: none;"}
         [:form {:name "samlLoginForm" :action service-url :method "post"}
          (for [[k v] hidden-params]
            [:textarea {:name (name k)} v])
          [:input {:type "submit" :value "Submit SAML Response"}]]]]])))








; Old stuff - to be removed

(defn service-allowed [& _])

(defn saml2-service-redirect [{:keys [services ticket-registry render-message-view saml2-key-pair] :as app-state}
                              {params :params :as req}
                              saml-req tgt]
  (let [svc-url (:AssertionConsumerServiceURL saml-req)
        svc (kc/service-lookup services svc-url)]
    (cond
      (not svc)                                             ; case 1: service not found
      (do
        (if svc-url
          (kc/audit app-state req tgt nil :SERVICE-TICKET-REJECTED))
        {:status  200
         :headers { "Content-Type" "text/html; charset=utf-8" }
         :body    (render-message-view :ok (if svc-url "Invalid service URL." "Login successful.")
                                       :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
      (not (service-allowed app-state req tgt svc svc-url)) ; case 2: service not allowed
      (do
        (kc/audit app-state req tgt svc :SERVICE-TICKET-REJECTED)
        {:status  200
         :body    (render-message-view :error "Service not allowed." :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
         :headers {"Content-Type" "text/html; charset=utf-8"}
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
      (contains? params :warn)                              ; case 3: 'warn' parameter present
      {:status 200
       :headers {"Content-Type" "text/html; charset=utf-8"}
       :body (render-message-view
               :ok "Login succesful."
               :url (str "saml2login?SAMLRequest=" (ku/url-enc (:SAMLRequest params)) "&RelayState=" (ku/url-enc (:RelayState params)))
               :dom (:dom tgt)) :tgt tgt, :req req}
      :else                                                 ; case 4: no 'warn' parameter present
      (let [svt (kt/grant-st-ticket ticket-registry svc-url svc (:tid tgt) :saml-req saml-req)
            sr (saml2-param-success-resp svt saml2-key-pair)]
        (kc/audit app-state req tgt svc :SERVICE-TICKET-GRANTED)
        {:status  302
         :body    (render-saml-redirect-form (:url svt) {:SAMLResponse sr :RelayState (:RelayState params)})
         :headers {"Content-Type" "text/html; charset=utf-8"}
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
      )))


(defn saml2-login-handler [login-flow-fn
                           {:keys [ticket-registry] :as app-state}
                           {{{CASTGC :value} "CASTGC"} :cookies, {:keys [SAMLRequest renew]} :params :as req}]
  (let [tgt (kt/get-ticket ticket-registry CASTGC)
        saml-req (saml2-parse-req SAMLRequest)]
    (log/info "RAW_SAML_REQ=" SAMLRequest)
    (log/info "SAML_REQ=" saml-req)
    (cond
      (or renew (empty? tgt))                               ; brak ticketu lub parametr renew
      (do
        (let [tgt (kt/get-ticket ticket-registry CASTGC)]
          (if tgt
            (kc/audit app-state req tgt nil :TGT-DESTROYED)
            (kt/clear-session ticket-registry CASTGC)))
        (try+
          (let [princ (login-flow-fn app-state req)
                tgt (kt/grant-tgt-ticket ticket-registry princ)]
            (kc/audit app-state req tgt nil :TGT-GRANTED)
            (saml2-service-redirect app-state req saml-req tgt))
          (catch [:type :login-cont] {:keys [resp]} resp)
          (catch [:type :login-failed] {:keys [resp]} resp)))
      :else
      (saml2-service-redirect app-state req saml-req tgt)
      )))


