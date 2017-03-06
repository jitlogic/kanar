(ns kanar.core.saml
  (:require
    [kanar.core :as kc]
    [kanar.core.util :as ku]
    [kanar.core.crypto :as kcc]
    [clojure.data.xml :as xml]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log]
    [kanar.core.sec :as kcs]
    [hiccup.util :refer [escape-html]])
  (:import (javax.xml.bind DatatypeConverter)
           (java.util.zip Inflater Deflater)))


(defn inflate-str [data]
  (let [zf (Inflater. true), buf (byte-array 65536)]
    (.setInput zf data)
    (let [len (.inflate zf buf)]
      (String. buf 0 len "UTF-8"))))

(defn deflate-str [s]
  (let [zf (Deflater. 6 true), buf (byte-array 65536), bs (.getBytes s)]
    (.setInput zf bs)
    (let [len (.deflate zf buf, 0, (alength buf), Deflater/FULL_FLUSH), buf1 (byte-array len)]
      (System/arraycopy buf 0 buf1 0 len)
      buf1)))

(defn saml2-parse-req [param]
  (if param
    (let [req-xml (-> param DatatypeConverter/parseBase64Binary inflate-str)]
      (merge {:req-xml req-xml} (:attrs (xml/parse-str req-xml))))))


(def SAML2-STATUS-CODE-URI-PREFIX "urn:oasis:names:tc:SAML:2.0:status")

(def SAML2-STATUS-CODES
  {:Success "Request processed succesfully."
   :Requester "Failed due to bad request."
   :Responder "Failed due to request processing error."
   :VersionMismatch "Protocol version mismatch."})

(defn saml2-gen-id []
  (str "KANAR_" (ku/random-string 32 "0123456789abcdef")))


(defn saml2-make-response [status req sso-url assertion]
  (let [saml-id (saml2-gen-id)
        saml-resp [:samlp:Response
                   {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"
                    :xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
                    :ID saml-id
                    :InResponseTo (-> req :saml-req :ID)
                    :IssueInstant (ku/xml-time)
                    :Version "2.0"}
                   [:saml:Issuer sso-url]
                   [:samlp:Status [:samlp:StatusCode {:Value (str SAML2-STATUS-CODE-URI-PREFIX status)}]]
                   assertion]]
    {:saml-id saml-id, :saml-resp saml-resp}))


(defn saml-make-assertion [sso-url subject conditions authn-statement]
  [:saml:Assertion
   {:ID (saml2-gen-id)
    :Version "2.0"
    :IssueInstant (ku/xml-time)
    :xmlns:xsi "http://www.w3.org/2001/XMLSchema-instance"
    :xmlns:xs "http://www.w3.org/2001/XMLSchema"}
   [:saml:Issuer sso-url]
   subject
   conditions
   authn-statement])


(defn saml-make-subject [{:keys [svt] :as req}]
  (let [idt (:id-template (:service svt) "@@ID@@")
        uid (if idt (.replace idt "@@ID@@" (get-in req [:principal :id])))]
    [:saml:Subject
     [:saml:NameID {:Format "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"} uid]
     [:saml:SubjectConfirmation {:Method "urn:oasis:names:tc:SAML:2.0:cm:bearer"}
      [:saml:SubjectConfirmationData
       {:NotOnOrAfter (ku/xml-time (ku/cur-time -30000))
        :Recipient    (:url svt),
        :InResponseTo (-> req :saml-req :ID)}]]]))


(defn saml-make-conditions [{:keys [service-url] :as _}]
  [:saml:Conditions
   {:NotBefore    (ku/xml-time (ku/cur-time -3600000))
    :NotOnOrAfter (ku/xml-time (ku/cur-time 3600000))}
   [:saml:AudienceRestriction
    [:saml:Audience service-url]]])

; TODO determine and add authentication context class ref

(defn saml-make-authn-statement [_]
  [:saml:AuthnStatement
   {:AuthnInstant (ku/xml-time)
    :SessionNotOnOrAfter (ku/xml-time (* 8 3600000))
    :SessionIndex (saml2-gen-id)}
   [:saml:AuthnContext
    [:saml:AuthnContextClassRef "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"]]])


; Core framework plugin functions.

(defn parse-saml2-req [{{:keys [SAMLRequest RelayState]} :params hp :hidden-params :as req}]
  "Parses SAML2 request. This function can be used with sso-request-parse-wfn."
  (when SAMLRequest
    (try+
      (let [{:keys [ForceAuth IsPassive Consent AssertionConsumerServiceURL] :as saml-req} (saml2-parse-req SAMLRequest)]
        (when-not (and AssertionConsumerServiceURL (re-matches kcs/SVC_URL_RE AssertionConsumerServiceURL))
          (throw+ [:type :input-error, :message "Invalid "]))
        (merge req
               {:protocol      :saml,
                :subprotocol   :saml20,
                :service-url   AssertionConsumerServiceURL,
                :saml-req      saml-req
                :login         (if (.equalsIgnoreCase "true" IsPassive) :none :page)
                :sesctl        (if (.equalsIgnoreCase "true" ForceAuth) :renew :none)
                :prompt        (if (= "urn:oasis:names:tc:SAML:2.0:consent:unavailable" Consent) :consent :none)
                :hidden-params (merge {:SAMLRequest SAMLRequest, :RelayState RelayState} hp)}
               (if RelayState {:service-params {:RelayState RelayState}
                               :hidden-params  (merge {:RelayState RelayState :SAMLRequest SAMLRequest} hp)} {})))
      (catch Object _
        (log/error "Unparsable SAML request:" SAMLRequest)
        nil))))


(defn saml-make-response-wfn
  ([ticket-registry keypair sso-url enabled]
    (saml-make-response-wfn identity ticket-registry keypair sso-url enabled))
  ([f ticket-registry keypair sso-url enabled]
   (fn [req]
     (if (= :saml (:protocol req))
       (let [subject (saml-make-subject req)
             conditions (saml-make-conditions req)
             authn-statement (saml-make-authn-statement req)
             assertion (saml-make-assertion sso-url subject conditions authn-statement)
             ; TODO add attributes statement
             {:keys [saml-resp]} (saml2-make-response :Success req sso-url assertion)
             ;_ (println "SAML-ID=" saml-id)
             ;_ (println "SAML-RESP-RAW=" (-> saml-resp ku/emit-dom ku/dom-to-str))
             ^String
             saml-resp-xml (-> saml-resp
                               ku/emit-dom
                               (kcc/xml-sign keypair enabled)
                               ku/dom-to-str)
             saml-response (-> saml-resp-xml
                               ;deflate-str
                               .getBytes
                               DatatypeConverter/printBase64Binary
                               ;ku/url-enc
                               )]
         ;(println "SAML-RESP-XML="  saml-resp-xml)
         (kt/update-ticket ticket-registry (-> req :svt :tid) {:saml-resp saml-resp})
         (f (-> req (assoc :saml-response saml-response) (assoc :saml-resp-xml saml-resp-xml))))
       (f req))
     )))


(defmethod kc/service-redirect :saml [{:keys [hidden-params service-url saml-response] :as req}]
  {:req req
   :body (str                                                ; TODO rozwarstwić to
           "<!DOCTYPE html>"
           (ku/emit-xml
             [:html [:head]
              [:body  {:onload "javascript:document.samlLoginForm.submit()"}
               "Redirecting, please wait ... "
               [:div {:style "display: none;"}
                [:form {:name "samlLoginForm" :action service-url :method "post"}
                 [:input {:type :hidden :name "SAMLResponse" :value (escape-html saml-response)}]
                 (for [[k v] (dissoc hidden-params :dom :SAMLRequest)]
                   [:input {:type :hidden :name (name k) :value (escape-html v)}])
                 [:input {:type "submit" :value "Submit SAML Response"}]]]]]))
   :content-security-policy "default-src 'self' 'unsafe-inline'; img-src 'self' data:"})


