(ns kanar.testutil
  (:require
    [clojure.string :as s]
    [kanar.core.util :as ku]
    [kanar.core :as kc]
    [kanar.core.cas :as kcc]
    [kanar.core.oauth :as kco]
    [kanar.core.saml :as kcs]
    [kanar.core.crypto :as kccr]
    [kanar.core.ticket :as kt]
    [ring.util.response :refer [redirect]]
    [compojure.core :refer [routes GET ANY rfn]])
  (:import (java.security KeyPairGenerator SecureRandom)
           (javax.crypto KeyGenerator)
           (java.net URLDecoder)))


; Helper functions

(defn matches [re s]
  (and (string? s) (re-matches re s)))

(defn get-tgc [r]
  "Extracts SSO ticket ID from HTTP response."
  (get-in r [:cookies "CASTGC" :value]))


(defn get-rdr [r]
  "Extracts redirection URL from HTTP response."
  (get-in r [:headers "Location"]))


(defn parse-url [url]
  (if-let [[_ uri params] (re-matches #"((?i:https?://[^\?]+))\?(.*)$" url)]
    (into
      {::uri uri}
      (for [p (s/split params #"&") :let [pv (re-matches #"([^=]+)=(.*)" p)]
            :when pv :let [[_ k v] pv]]
        {(keyword (URLDecoder/decode k)) (URLDecoder/decode v)}))
    {::uri url}))


(defn parse-rdr [r]
  (when-let [rdr (get-rdr r)]
    (parse-url rdr)))


(defn parse-json [s]
  (when s
    (into {}
          (for [[k v] (clojure.data.json/read-str s)]
            {(keyword k) v}))))


(defn get-ticket [r]
  (let [rdr (get-rdr r)
        m (matches #".*ticket=(.*)" rdr)]
    (second m)))


(defn get-samlart [r]
  (let [rdr (get-rdr r)
        m (matches #".*SAMLart=(.*)" rdr)]
    (second m)))


(defn get-samlresp [r]
  (let [rdr (get-rdr r)
        m (matches #".*SAMLResponse=(.*)" rdr)]
    (second m)))


(defn gen-pub-keypair [type len]
  (let [kg (KeyPairGenerator/getInstance (name type) "SUN")
        _ (.initialize kg ^Integer len)
        kp (.generateKeyPair kg)]
    {:pub-key (.getPublic kp), :prv-key (.getPrivate kp)}))


(defn gen-sym-keypair [type len]
  (let [kg (KeyGenerator/getInstance (name type))
        _ (.init kg len)
        k (.generateKey kg)]
    {:pub-key k, :prv-key k}))


; Generic end-to-end test fixture

(defn test-audit-fn [_ _ _ _ _])

(def ^:dynamic *dsa-key-pair* (gen-pub-keypair :DSA 1024))
(def ^:dynamic *treg-atom* (atom {}))
(def ^:dynamic kanar nil)
(def ^:dynamic *sso-logouts* (atom []))
(def ^:dynamic *jose-cfg* {:sign-alg :HS256, :sign-key {:secret "6tON3t4h7MAnfmg+A87Kwq72n9JTEUgiIREQMaYs+6k="}})
(def ^:dynamic jwt-decode (kccr/jwt-decode-fn *jose-cfg*))

(defn reset-fixture []
  (reset! *treg-atom* {})
  (reset! *sso-logouts* []))


(defn view-testfn [type req]
  (assoc req :test/view-type type))


(defn auth-testfn [{{:keys [username password]} :credentials :as req}]
  (if (= username password)
    (assoc req :principal {:id username})
    (assoc-in req [:view-params :message] "Invalid username or password.")))


(defn select-kanar-domain [{{:keys [dom]} :params}]
  (if (string? dom) (keyword dom) :unknown))


(def ^:dynamic *test-services*
  [{:id :verboten :url #"https://verboten.com" :verboten true}
   {:id :test1 :url #"https://test1.com" :app-urls [ "http://srv1:8080/test1" "http://srv2:8080/test1" ] }
   {:id :all :url #"https://.*"}])


; TODO przenieść konsturkcję tego do dedykowanego config namespace;
(defn kanar-routes-new [{:keys [ticket-registry view-fn services auth-fn svc-access-fn jose-cfg jwt-enc sso-url]}]
  (let [login-fn (kc/-->
                   (kc/sso-request-parse-wfn kcc/parse-cas-req (kco/parse-oauth-params-fn jose-cfg))
                   (kc/tgt-lookup-wfn ticket-registry)
                   (kc/login-flow-wfn ticket-registry (kc/form-login-flow-wfn auth-fn view-fn))
                   (kc/prompt-consent-screen-wfn view-fn)
                   (kc/service-lookup-wfn ticket-registry view-fn services svc-access-fn)
                   (kco/id-token-wfn ticket-registry jwt-enc sso-url)
                   kc/service-redirect)
        validate-fn (kcc/cas10-validate-handler ticket-registry)
        validate2-fn (kcc/cas20-validate-handler ticket-registry #"ST-.*")
        validate-pfn (kcc/cas20-validate-handler ticket-registry #"(ST|PT)-.*")
        logout-fn (kcc/logout-handler ticket-registry view-fn)
        proxy-fn (kcc/proxy-handler ticket-registry)
        saml-validate-fn (kcc/saml-validate-handler ticket-registry)
        oauth-token-fn (kco/token-request-handler-fn ticket-registry (kccr/jwt-encode-fn *jose-cfg*))
        oauth-userinfo-fn (kco/token-userinfo-handler-fn ticket-registry)]
    (routes
      (ANY "/login" req (login-fn req))
      (ANY "/authorize" req (login-fn req))
      (ANY "/logout" req (logout-fn req))
      (ANY "/token" req (oauth-token-fn req))
      (ANY "/validate" req (validate-fn req))
      (ANY "/serviceValidate" req (validate2-fn req))
      (ANY "/proxyValidate" req (validate-pfn req))
      (ANY "/proxy" req (proxy-fn req))
      (ANY "/samlValidate" req (saml-validate-fn req))
      (ANY "/userinfo" req (oauth-userinfo-fn req))
      (ANY "/*" [] (redirect "login")))))


(defn basic-test-fixture [f]
  (reset-fixture)
  (binding [kanar (ku/wrap-set-param
                    (kanar-routes-new
                      {:services        *test-services*
                       :ticket-registry (kt/atom-ticket-store *treg-atom*)
                       :view-fn         view-testfn
                       :svc-access-fn   (fn [req] (not (:verboten (:service req))))
                       :auth-fn         auth-testfn
                       :saml2-key-pair  *dsa-key-pair*
                       :jose-cfg        *jose-cfg*
                       :jwt-enc         (kccr/jwt-encode-fn *jose-cfg*)
                       :sso-url         "http://my.sso.com/"
                       })
                    :dom select-kanar-domain)]
    (with-redefs
      [kc/service-logout (fn [_ _] nil)]
      (f))))


(defn dummy-service-logout [url {tid :tid}]
  (swap! *sso-logouts* #(conj % {:url url :tid tid})))

