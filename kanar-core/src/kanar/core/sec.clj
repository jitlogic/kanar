(ns kanar.core.sec
  "Various security related functions. Validators, filters etc."
  (:require
    [kanar.core.util :as kcu]
    [kanar.core.util :as ku]
    [slingshot.slingshot :refer [try+ throw+]]
    [ring.util.request :refer [body-string]]
    [clojure.java.io :as io]
    [taoensso.timbre :as log])
  (:import (javax.xml.validation SchemaFactory Schema Validator)
           (javax.xml XMLConstants)
           (javax.xml.transform.stream StreamSource)
           (java.io ByteArrayInputStream)
           (javax.xml.bind DatatypeConverter)))


; Use "default-src 'self'; img-src 'self' data: ; style-src 'self' 'unsafe-inline'" for inline images and styles.
(defn wrap-security-headers [f & [content-security-policy]]
  "Adds set of standard headers regarding web security."
  (fn [req]
    (let [resp (f req)
          csp (or content-security-policy "default-src 'self'")]
      (assoc resp :headers
                  (merge
                    (:headers resp {})
                    {"X-Frame-Options"             "DENY"
                     "X-XSS-Protection"            "1; mode=block"
                     "X-Content-Type-Options"      "nosniff"
                     "Strict-Transport-Security"   "max-age=16070400; includeSubDomains"
                     "X-Content-Security-Policy"   csp
                     "Content-Security-Policy"     csp
                     "X-Webkit-CSP"                csp}
                    (if (.startsWith (:uri req) "/static")
                      {"Cache-Control" "no-transform,public,max-age=3600,s-maxage=7200"}
                      {"Cache-Control"               "no-cache,no-store,max-age=0,must-revalidate"
                       "Pragma"                      "no-cache"}))))))


(defn create-xsd-validator [& schemas]
  (let [sf (SchemaFactory/newInstance XMLConstants/W3C_XML_SCHEMA_NS_URI)
        cl (.getContextClassLoader (Thread/currentThread))
        ss (for [schema schemas] (StreamSource. (.getResourceAsStream cl schema)))
        sc (.newSchema ^SchemaFactory sf (into-array ^StreamSource ss))]
    (.newValidator ^Schema sc)))


(defn validate-saml-xml [^Validator v xml]
  (try
    (locking v
      (.validate v (StreamSource. (ByteArrayInputStream. (.getBytes xml)))))
    xml
    (catch Exception e
      (log/error "SOAP_XML" (kcu/b64 xml))
      (ku/security-error (str "XML does not match schema." e)))))


(defn new-saml-vfn []
  "Creates validation function"
  (let [validator (create-xsd-validator "xsd/SamlReq.xsd" "xsd/SoapSamlReq.xsd")]
    (fn [val]
      (if (or (empty? val) (empty? (.trim val)))
        nil
        (validate-saml-xml validator val)))))


(def default-req-attrs [:remote-addr :server-port :content-type :character-encoding :uri
                        :server-name :scheme :request-method])


(defn- validate-and-filter-val [v {:keys [re re-grp vfn optional msg] :as vdc}]
  (let [s (if (map? v) (:value v) v)]
    (cond
      (empty? vdc) v
      (and optional (nil? v)) nil
      (nil? v) (do (log/error "VAL_NIL" vdc) (kcu/security-error msg))
      (some #(Character/isISOControl ^Character %) s) (do (log/error "VAL_ISO"  vdc (kcu/b64 v)) (kcu/security-error msg))
      re (if-let [rv (re-matches re s)]
           (if re-grp (nth rv re-grp) v)
           (do (log/error "VAL_RE" vdc (kcu/b64 v)) (kcu/security-error msg)))
      vfn (vfn s)
      :else s)))


(defn validate-and-filter-req [req vd]
  "Validates HTTP request and filters out unnecessary fields, headers, cookies, params."
  (when-not (contains? (set (keys vd)) (:request-method req))
    (kcu/security-error (str "Invalid request method " (:request-method req))))
  (let [md (get vd (:request-method req)),
        body (if (contains? vd :body) (kcu/oneliner (body-string req)) nil)]
    (into (merge {:body (validate-and-filter-val body (:body vd))} (select-keys req default-req-attrs))
          (for [dk [:headers :params :cookies]
                :let [vd-component (dk md), req-data (select-keys (dk req) (keys vd-component))]]
            {dk
             (into {}
                   (for [[k vdc] vd-component
                         :let [v (validate-and-filter-val (get req-data k) vdc)]
                         :when v]
                     {k v}))}))))


(defn merge-vd [vd ve]
  "Extends existing validator definition with additional rules."
  (into vd (for [[k1 ve1] ve :let [vd1 (get vd k1 {})]]
             {k1 (into vd1 (for [[k2 ve2] ve1 :let [vd2 (get vd1 k2 {})]]
                             {k2 (into vd2 ve2)}))})))


(defmacro guarded [req vdf vfn & body]
  "Useful for guarding a block of code with validators."
  `(try+
     (let ~[req (validate-and-filter-req req vdf)]
       ~@body)
     (catch [:type :security-error] {msg :msg}
        (vfn req msg))))


(defn with-http-validations [f vvdefs vfns]
  (fn [req]
    (let [vfn (vfns (:uri req) (:default vfns))]
      (try+
        (let [vd (vvdefs (:uri req) (:default vvdefs))
              vr (validate-and-filter-req req vd)]
          (f vr))
        (catch [:type :security-error] e
          (let [req (if (:body req) (update-in req [:body] body-string) req)]
            (log/error "Error parsing request" (:uri req) ":" e "encoded request:"
                       (kcu/b64 req)))
          (when (:body req)
            (log/error "encoded body: " ))
          {:status  200
           :headers {"Content-Type" "text/html; charset=utf-8"}
           :body    (vfn req (or (:msg e) ""))})))))


(defn extract-param-keys [vvdefs]
  (flatten
    (for [[_ vdefs] vvdefs]
      (for [[_ vd] vdefs :let [pd (:params vd)] :when pd]
        (keys pd)))))


(defn extract-param-names [pk]
  (vec (sort (for [p (set pk) :when (keyword? p)] (name p)))))


(defn wrap-only-params [f vvdefs]
  (let [pnames (extract-param-names (extract-param-keys vvdefs))]
    (fn [req]
      (f (update-in req [:params] #(select-keys % pnames))))))


; Rules for standard CAS requests

(def SVC_URL_RE #"https?://[a-zA-Z0-9\.\_\-\:]{3,64}(\/.{0,1024})?")

(def TGC_TICKET_RE #"TGC\-[0-9]+\-[a-zA-Z0-9]{32,128}\-[a-zA-Z0-9\.\_]{1,16}")
(def ST_TICKET_RE #"ST\-.*")
(def PGT_TICKET_RE #"PGT\-.*")
(def SPT_TICKET_RE #"[SP]T\-.*")

(def BOOL_RE #"(1|0|t|f|true|false|T|F|TRUE|FALSE|yes|no|YES|NO|Y|N)")

(def BOOL_TRUE #{"1" "t" "T" "true" "TRUE" "y" "Y" "yes" "YES"})
(def BOOL_FALSE #{"0" "f" "F" "false" "FALSE" "n" "N" "no" "NO"})

(def svc-url-vd {:re SVC_URL_RE :msg "Invalid target service URL"} )
(def svc-url-ovd (into svc-url-vd {:optional true}))

(def tgc-cookies-ovd {"CASTGC" {:re TGC_TICKET_RE :msg "Invalid TGC cookie" :optional true}})

(def xff-headers-vd {"x-forwarded-for" {:re #"[\d\.\, ]*" :msg "Invalid XFF header" :optional true}})

(defn tkt-vd [tre] {:re tre :msg "Invalid ticket"})


(def cas-login-vd
  {:get {:params {:service svc-url-ovd
                  :TARGET svc-url-ovd
                  :gateway  {:re BOOL_RE :msg "Invalid parameters" :optional true}
                  :warn     {:re BOOL_RE :msg "Invalid parameters" :optional true}}
         :cookies tgc-cookies-ovd
         :headers xff-headers-vd}
   :post {:params {:service  svc-url-ovd
                   :TARGET   svc-url-ovd
                   :username {:re #"\s*([A-Za-z0-9\.\-\_]{1,64})\s*" :re-grp 1 :msg "Invalid or missing username"}
                   :password {:re #".{1,64}" :msg "Invalid or missing password"}
                   :gateway  {:re BOOL_RE :msg "Invalid parameters" :optional true}
                   :warn     {:re BOOL_RE :msg "Invalid parameters" :optional true}}
          :cookies tgc-cookies-ovd
          :headers xff-headers-vd}})


(def cas-logout-vd
  {:get
   {:params {:service svc-url-ovd}
    :cookies tgc-cookies-ovd
    :headers xff-headers-vd}})


; HTTP request validators for /validate - CAS 1.0 validation URL;
(def cas10-ticket-vd
  {:get
   {:params
    {:service svc-url-vd
     :ticket (tkt-vd ST_TICKET_RE)}
    :headers xff-headers-vd}})


; /serviceValidate - CAS 2.0 validation URL
(def cas20-ticket-vd
  {:get
   {:params
    {:service svc-url-vd
     :ticket (tkt-vd ST_TICKET_RE)}
    :headers xff-headers-vd}})


; /proxyValidate - CAS 2.0 PGT validation URL
(def cas20-proxy-validate-vd
  {:get
   {:params
    {:service svc-url-vd
     :ticket  (tkt-vd SPT_TICKET_RE)
     :pgtUrl  (assoc svc-url-vd :optional true)}
    :headers xff-headers-vd}})


; /proxy - CAS 2.0 proxy validation
(def cas20-proxy-vd
  {:get
   {:params
    {:pgt {:re PGT_TICKET_RE :msg "Invalid ticket"}
     :targetService svc-url-vd}
    :headers xff-headers-vd}})


; /samlValidate - CAS SAML validation
(def saml-validate-vd
  {:post    {:params {:TARGET  svc-url-vd
                      :SAMLart {:re ST_TICKET_RE :msg "Invalid ticket" :optional true}}}
   :body    {:vfn (new-saml-vfn) :optional true}
   :headers xff-headers-vd})

