(ns kanar.core.saml
  (:require
    [kanar.core.util :as ku]
    [clojure.data.xml :as xml])
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
  (->
    param
    DatatypeConverter/parseBase64Binary
    inflate-str
    xml/parse-str
    :attrs))


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

