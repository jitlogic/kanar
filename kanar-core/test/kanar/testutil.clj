(ns kanar.testutil
  (:require
    [kanar.core.util :as ku]
    [kanar.core :as kc]
    [kanar.core.cas :as kcc]
    [kanar.core.saml :as kcs]
    [kanar.core.ticket :as kt]
    [ring.util.response :refer [redirect]]
    [compojure.core :refer [routes GET ANY rfn]])
  (:import (java.security KeyPairGenerator SecureRandom)))


; Helper functions

(defn get-tgc [r]
  "Extracts SSO ticket ID from HTTP response."
  (get-in r [:cookies "CASTGC" :value]))


(defn get-rdr [r]
  "Extracts redirection URL from HTTP response."
  (get-in r [:headers "Location"]))


(defn get-ticket [r]
  (let [rdr (get-rdr r)
        m (re-matches #".*ticket=(.*)" rdr)]
    (second m)))


(defn get-samlart [r]
  (let [rdr (get-rdr r)
        m (re-matches #".*SAMLart=(.*)" rdr)]
    (second m)))


(defn get-samlresp [r]
  (let [rdr (get-rdr r)
        m (re-matches #".*SAMLResponse=(.*)" rdr)]
    (second m)))


(defn gen-dsa-keypair [len]
  (let [kg (KeyPairGenerator/getInstance "DSA" "SUN")]
    (.initialize kg ^Integer len)
    (.generateKeyPair kg)))


(defn matches [re s]
  (and s (re-matches re s)))


; Generic end-to-end test fixture

(defn test-audit-fn [_ _ _ _ _])

(def ^:dynamic *dsa-key-pair* (gen-dsa-keypair 1024))
(def ^:dynamic *treg-atom* (atom {}))
(def ^:dynamic kanar nil)
(def ^:dynamic *sso-logouts* (atom []))

(defn reset-fixture []
  (reset! *treg-atom* {})
  (reset! *sso-logouts* []))


(defn view-testfn [type req]
  (assoc req :test/view-type type))


(defn auth-testfn [{{:keys [username password]} :credentials :as req}]
  (if (= username password)
    (assoc req :principal {:id username})
    (assoc-in req [:view-params :message ] "Invalid username or password.")))


(defn select-kanar-domain [{{:keys [dom]} :params}]
  (if (string? dom) (keyword dom) :unknown))


(def ^:dynamic *test-services*
  [{:id :verboten :url #"https://verboten.com" :verboten true}
   {:id :test1 :url #"https://test1.com" :app-urls [ "http://srv1:8080/test1" "http://srv2:8080/test1" ] }
   {:id :all :url #"https://.*"}])


; TODO przenieść konsturkcję tego do dedykowanego config namespace;
(defn kanar-routes-new [{:keys [ticket-registry view-fn services auth-fn svc-access-fn]}]
  (let [login-fn (kc/-->
                   (kc/sso-request-parse-wfn kcc/parse-cas-req)
                   (kc/tgt-lookup-wfn ticket-registry)
                   (kc/login-flow-wfn ticket-registry (kc/form-login-flow-wfn auth-fn view-fn))
                   (kc/prompt-consent-screen-wfn view-fn)
                   (kc/service-lookup-wfn ticket-registry view-fn services svc-access-fn)
                   kc/service-redirect)
        validate-fn (kcc/cas10-validate-handler ticket-registry)
        validate2-fn (kcc/cas20-validate-handler ticket-registry #"ST-.*")
        validate-pfn (kcc/cas20-validate-handler ticket-registry #"(ST|PT)-.*")
        logout-fn (kcc/logout-handler ticket-registry view-fn)
        proxy-fn (kcc/proxy-handler ticket-registry)
        saml-validate-fn (kcc/saml-validate-handler ticket-registry)]
    (routes
      (ANY "/login" req (login-fn req))
      (ANY "/logout" req (logout-fn req))
      (ANY "/validate" req (validate-fn req))
      (ANY "/serviceValidate" req (validate2-fn req))
      (ANY "/proxyValidate" req (validate-pfn req))
      (ANY "/proxy" req (proxy-fn req))
      (ANY "/samlValidate" req (saml-validate-fn req))
      (ANY "/*" [] (redirect "login")))))


(defn basic-test-fixture [f]
  (reset-fixture)
  (binding [kanar (ku/wrap-set-param
                    (kanar-routes-new
                      {:services            *test-services*
                       :ticket-registry     (kt/atom-ticket-store *treg-atom*)
                       :view-fn             view-testfn
                       :svc-access-fn       (fn [req] (not (:verboten (:service req))))
                       :auth-fn             auth-testfn
                       :saml2-key-pair      *dsa-key-pair*
                       })
                    :dom select-kanar-domain)]
    (with-redefs
      [kc/service-logout (fn [_ _] nil)]
      (f))))


(defn dummy-service-logout [url {tid :tid}]
  (swap! *sso-logouts* #(conj % {:url url :tid tid})))

