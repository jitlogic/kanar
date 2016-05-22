(ns kanar.core.saml
  (:require
    [kanar.core :as kc]
    [kanar.core.util :as ku]
    [kanar.core.crypto :as kcc]
    [clojure.data.xml :as xml]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log]
    [kanar.core.sec :as kcs])
  (:import (javax.xml.bind DatatypeConverter)
           (java.util.zip Inflater)))


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


(def SAML2-STATUS-CODE-URI-PREFIX "urn:oasis:names:tc:SAML:2.0:status")

(def SAML2-STATUS-CODES
  {:Success "Request processed succesfully."
   :Requester "Failed due to bad request."
   :Responder "Failed due to request processing error."
   :VersionMismatch "Protocol version mismatch."})


(defn saml2-make-response [status req sso-url assertion]
  [:samlp:Response
   {:xmlns:saml        "urn:oasis:names:tc:SAML:2.0:assertion"
    :xmlns:samlp  "urn:oasis:names:tc:SAML:2.0:protocol"
    :ID           (ku/random-string 40 "abcdefghijklmnopqrstuvwxyz")
    :InResponseTo (-> req :saml-req :ID)
    :IssueInstant (ku/xml-time)}
    [:saml:Issuer sso-url]
    [:samlp:Status [:StatusCode {:Value (str SAML2-STATUS-CODE-URI-PREFIX status)}]]
    assertion])


(defn saml-make-assertion [sso-url subject conditions authn-statement]
  [:saml:Assertion
   {:ID (ku/random-string 40 "abcdefghijklmnopqrstuvwxyz")
    :Version "2.0"
    :IssueInstant (ku/xml-time)}
   [:saml:Issuer sso-url]
   subject
   conditions
   authn-statement])


(defn saml-make-subject [{:keys [svt] :as req}]
  (let [idt (:id-template (:service svt) "{{id}}")
        uid (if idt (.replace idt "{{id}}" (get-in svt [:tgt :princ :id])))]
    [:saml:Subject
     [:saml:NameID {:Format "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"} uid]
     [:saml:SubjectConfirmation {:Method "urn:oasis:names:tc:SAML:2.0:cm:bearer"}
      [:saml:SubjectConfirmationData
       {:NotOnOrAfter (ku/xml-time (ku/cur-time -30000))
        :Recipient    (:url svt),
        :InResponseTo (:ID (:saml-req svt))}]]]))


(defn saml-make-conditions [{:keys [service-url] :as req}]
  [:saml:Conditions
   {:NotBefore    (ku/xml-time (ku/cur-time -30000))
    :NotOnOrAfter (ku/xml-time (ku/cur-time 300000))}
   [:saml:AudienceRestriction
    [:saml:Audience (ku/domain-name service-url)]]])

; TODO determine and add authenticatio context class ref

(defn saml-make-authn-statement [req]
  [:saml:AuthnStatement {:AuthnInstant (ku/xml-time)}
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
                :hidden-params (merge {:SAMLRequest SAMLRequest} hp)}
               (if RelayState {:service-params {:RelayState RelayState}
                               :hidden-params  (merge {:RelayState RelayState :SAMLRequest SAMLRequest} hp)} {})))
      (catch Object _
        (log/error "Unparsable SAML request:" SAMLRequest)
        nil))))


(defn saml-make-response-wfn [f ticket-registry keypair sso-url]
  (fn [req]
    (if (= :oauth (:protocol req))
      (let [subject (saml-make-subject req)
            conditions (saml-make-conditions req)
            authn-statement (saml-make-authn-statement req)
            assertion (saml-make-assertion sso-url subject conditions authn-statement)
            ; TODO add attributes statement
            saml-resp (saml2-make-response :Success req sso-url assertion)
            saml-resp-xml (-> saml-resp ku/emit-dom (kcc/xml-sign keypair) ku/dom-to-str)]
        (kt/update-ticket ticket-registry (-> req :svt :tid) {:saml-resp saml-resp})
        (f (-> req (assoc :saml-response saml-resp) (assoc :saml-resp-xml saml-resp-xml))))
      (f req))
    ))


(defmethod kc/service-redirect :saml [{:keys [hidden-params service-url] :as req}]
  {:req  req
   :body (str                                                ; TODO rozwarstwić to
           "<!DOCTYPE html>"
           (ku/emit-xml
             [:html [:head]
              [:body {:onload "javascript:document.samlLoginForm.submit()"}
               [:div {:style "display: none;"}
                [:form {:name "samlLoginForm" :action service-url :method "post"}
                 [:textarea {:name "SAMLResponse"}]
                 (for [[k v] hidden-params]
                   [:textarea {:name (name k)} v])
                 [:input {:type "submit" :value "Submit SAML Response"}]]]]]))})










