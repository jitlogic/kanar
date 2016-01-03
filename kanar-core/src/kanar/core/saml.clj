(ns kanar.core.saml
  (:require
    [kanar.core :as kc]
    [kanar.core.util :as ku]
    [clojure.data.xml :as xml]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]])
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
  [:samlp:Response
   {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"
    :xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
    :ID (ku/random-string 32)
    :IssueInstant (ku/xml-time)
    :Version "2.0"}
   [:samlp:Status
    [:samlp:StatusCode {:Value "urn:oasis:names:tc:SAML:2.0:status:Success"}]]
   [:Assertion
    {:ID (ku/random-string 32)
     :Version "2.0"
     :IssueInstant (ku/xml-time)}
    [:Issuer "https://www.opensaml.org/IDP"]
    [:Subject
     [:NameID {:Format "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" } (get-in svt [:tgt :princ :id])]
     [:SubjectConfirmation { :Method "urn:oasis:names:tc:SAML:2.0:cm:bearer" }
      [:SubjectConfirmationData
       {:NotOnOrAfter (ku/xml-time (ku/cur-time -30000))
        :Recipient    (:url svt),
        :InResponseTo (:ID (:saml-req svt))}]]]
    [:Conditions
     {:NotBefore (ku/xml-time (ku/cur-time -30000))
      :NotOnOrAfter (ku/xml-time (ku/cur-time 300000))}]
    [:AuthnStatement {:AuthnInstant (ku/xml-time)}
     [:AuthnContext [:AuthnContextClassRef "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"]]]
    ]])


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
      ku/dom-to-str
      deflate-str
      DatatypeConverter/printBase64Binary))


(defn saml2-service-redirect [{:keys [services ticket-registry render-message-view saml2-key-pair] :as app-state}
                              {params :params :as req}
                              saml-req tgt]
  (let [svc-url (:AssertionConsumerServiceURL saml-req)
        svc (kc/kanar-service-lookup services svc-url)]
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
      (not (kc/service-allowed app-state req tgt svc svc-url)) ; case 2: service not allowed
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
               :url (str "saml2login?SAMLRequest=" (ku/url-enc (:SAMLRequest params)))
               :dom (:dom tgt)) :tgt tgt, :req req}
      :else                                                 ; case 4: no 'warn' parameter present
      (let [svt (kt/grant-st-ticket ticket-registry svc-url svc (:tid tgt) :saml-req saml-req)
            sr (saml2-param-success-resp svt saml2-key-pair)]
        (kc/audit app-state req tgt svc :SERVICE-TICKET-GRANTED)
        {:status  302
         :body    (render-message-view :ok "Login succesful.", :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
         :headers {"Location"     (str svc-url (if (.contains svc-url "?") "&" "?") "SAMLResponse=" (ku/url-enc sr))
                   "Content-Type" "text/html; charset=utf-8"}
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
      )))


(defn saml2-login-handler [login-flow-fn
                           {:keys [services ticket-registry render-message-view] :as app-state}
                           {{{CASTGC :value} "CASTGC"} :cookies, {:keys [SAMLRequest renew] :as params} :params :as req}]
  (let [tgc (kt/get-ticket ticket-registry CASTGC)
        saml-req (saml2-parse-req SAMLRequest)]
    (cond
      (or renew (empty? tgc))                               ; brak ticketu lub parametr renew
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
      )))

