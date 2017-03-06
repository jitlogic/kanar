(ns {{name}}.app
  "Main KANAR app namespace."
  (:gen-class)
  (:require
    [clojure.tools.nrepl.server :as nrepl]
    [compojure.core :refer [routes GET POST ANY rfn]]
    [compojure.route :refer [not-found resources]]
    [kanar.core :as kc]
    [kanar.core.sec :as kcs]
    [kanar.core.cas :as kcc]
    [kanar.core.otp :as kco]
    [kanar.core.crypto :as kccr]
    [kanar.core.ticket :as kt]
    [kanar.core.system :as kcd]
    [kanar.core.util :as ku]
    [kanar.core.fileauth :as kf]
    [kanar.hazelcast :as kh]
    [clj-ldap.client :as ldap]
    [kanar.ldap :as kl]
    [kanar.core.jetty :as kcj]
    [{{name}}.views :as kav]
    [ring.middleware.reload :refer [wrap-reload]]
    [ring.middleware.keyword-params :refer [wrap-keyword-params]]
    [ring.middleware.params :refer [wrap-params]]
    [ring.middleware.cookies :refer [wrap-cookies]]
    [ring.util.response :refer [redirect]]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre.appenders.3rd-party.rotor :refer [rotor-appender]]
    [taoensso.timbre :as log]
    [kanar.core.util :as kcu]
    [clojure.string :as cs])
  (:import (java.text SimpleDateFormat)
           (java.util Date)
           (java.io File)
           (com.hazelcast.core HazelcastInstance)
           (java.util.concurrent Executors)
           (clojure.lang IAtom)))


(def DEFAULT-ATTR-MAP
  {:sn :sn, :givenName :givenName, :cn :cn})


(defn app-routes-new [{:keys [login-fn su-login-fn logout-fn tkt-validate-cas10-fn
                              tkt-validate-cas20-fn tkt-validate-proxy-fn
                              tkt-proxy-fn tkt-validate-saml-fn]}]
  (routes
    (GET "/login" req (login-fn req))
    (POST "/login" req (login-fn req))
    (GET "/sulogin" req (su-login-fn req))
    (POST "/sulogin" req (su-login-fn req))
    (GET "/logout" req (logout-fn req))
    (GET "/validate" req (tkt-validate-cas10-fn req))
    (GET "/serviceValidate" req (tkt-validate-cas20-fn req))
    (GET "/proxyValidate" req (tkt-validate-proxy-fn req))
    (GET "/proxy" req (tkt-proxy-fn req))
    (GET "/samlValidate" req (tkt-validate-saml-fn req))
    (POST "/samlValidate" req (tkt-validate-saml-fn req))
    (resources "/")
    (ANY "/*" req
      (ku/redirect-with-params "/login"
                               (dissoc (:params req) :*)
                               nil))))


(defn new-app-state [old-app-state conf services]
  "Creates new application state structure with configuration and current state."
  (let [ldap-conf (:ldap (:ldap-conf conf))
        ldap-conn (ldap/connect ldap-conf)
        hazelcast (kh/hz-reconnect old-app-state conf)
        ticket-map (.getReplicatedMap ^HazelcastInstance hazelcast "kanar.tickets")
        otp-lockout-map (.getReplicatedMap ^HazelcastInstance hazelcast "kanar.otp.lockouts")
        otp-tokens-map (.getReplicatedMap ^HazelcastInstance hazelcast "kanar.otp.tokens")
        otp-lockout-registry (kh/hazelcast-ticket-store otp-lockout-map)
        otp-tokens-registry (kh/hazelcast-ticket-store otp-tokens-map)
        ticket-registry (kh/hazelcast-ticket-store ticket-map)
        audit-pool (or (:audit-pool old-app-state (Executors/newFixedThreadPool 8)))
        log-conf (:log-conf conf)
        proxies (set (:intranet-proxies conf []))

        force-otp (-> conf :otp :force)

        otp-enabler-fn #(or (not (get-in % [:params :intranet])) force-otp)

        auth-fn (kc/traced-->
                  [:login :auth]
                  kc/form-login-flow-wfn
                  (kco/otp-verify-wfn (:otp conf)
                                      otp-enabler-fn
                                      (kl/ldap-otp-lookup-fn
                                        ldap-conn kl/edir-err-defs ldap-conf
                                        :cn :mozillaCustom2 :mozillaCustom1)
                                      otp-tokens-registry otp-lockout-registry)
                  (kl/ldap-auth-wfn ldap-conn ldap-conf kl/edir-err-defs)
                  (kl/ldap-attr-wfn
                    ldap-conn (-> ldap-conf :attr-fetch)
                    (kl/precompile-attr-map (:attr-map ldap-conf DEFAULT-ATTR-MAP)))
                  (kl/ldap-roles-wfn ldap-conn :memberOf :roles #"cn=([^,]+),.*")
                  kc/login-flow-success)

        login-fn (kc/traced-->
                   [:login]
                   (kc/sso-request-parse-wfn kcc/parse-cas-req)
                   (kc/tgt-lookup-wfn ticket-registry)
                   (kc/login-flow-wfn ticket-registry (kc/form-login-flow-wfn auth-fn))
                   kc/prompt-consent-screen-wfn
                   (kc/service-lookup-wfn ticket-registry services kc/role-based-service-auth)
                   kc/service-redirect)

        su-auth-fn (kc/traced-->
                     [:su-login :auth]
                     (kl/ldap-auth-wfn ldap-conn ldap-conf kl/edir-err-defs)
                     (kl/ldap-roles-wfn ldap-conn :memberOf :roles #"cn=([^,]+),.*")
                     (kc/su-auth-wfn (:su-admin-role ldap-conf "su-admins"))
                     (kl/ldap-lookup-wfn ldap-conn ldap-conf kl/edir-err-defs)
                     (kl/ldap-attr-wfn
                       ldap-conn (-> ldap-conf :attr-fetch)
                       (kl/precompile-attr-map (:attr-map ldap-conf DEFAULT-ATTR-MAP)))
                     (kl/ldap-roles-wfn ldap-conn :memberOf :roles #"cn=([^,]+),.*")
                     (kc/su-deny-wfn (:su-deny-grp ldap-conn "su-deny"))
                     kc/login-flow-success)

        su-login-fn (kc/traced-->
                      [:su-login]
                      (kc/sso-request-parse-wfn kcc/parse-cas-req)
                      (kc/tgt-lookup-wfn ticket-registry)
                      (kc/login-flow-wfn ticket-registry (kc/form-login-flow-wfn su-auth-fn))
                      kc/prompt-consent-screen-wfn
                      (kc/service-lookup-wfn ticket-registry services kc/role-based-service-auth)
                      kc/service-redirect)

        logout-fn (kc/traced-->
                    [:logout]
                    (kcc/cas-logout-handler-wfn ticket-registry))

        tkt-validate-cas10-fn (kcc/cas10-validate-handler-wfn ticket-registry)

        tkt-validate-cas20-fn (kcc/cas20-validate-handler-wfn ticket-registry #"ST-.*")

        tkt-validate-proxy-fn (kcc/cas20-validate-handler-wfn ticket-registry #"(ST|PT)-.*")

        tkt-validate-saml-fn (kcc/saml-validate-handler-wfn ticket-registry)

        tkt-proxy-fn (kcc/proxy-handler ticket-registry)

        req-handlers
        {:login-fn              login-fn
         :su-login-fn           su-login-fn
         :logout-fn             logout-fn
         :tkt-validate-cas10-fn tkt-validate-cas10-fn
         :tkt-validate-cas20-fn tkt-validate-cas20-fn
         :tkt-validate-proxy-fn tkt-validate-proxy-fn
         :tkt-validate-saml-fn  tkt-validate-saml-fn
         :tkt-proxy-fn          tkt-proxy-fn}

        render-error #(println "Error: " %)                 ; TODO proper render function

        raw-handler (kc/traced-->
                      [:main]
                      kc/trace-begin-wfn
                      (kc/trace-log-wfn (-> log-conf :trace))
                      (kc/wrap-error-screen
                        render-error
                        (-> log-conf :dump :path))
                      (kc/audit-log-wfn
                        kc/DEFAULT-AUDIT-ATTR-DEFS
                        (kc/audit-file-output (-> log-conf :audit :path)))
                      (kcs/wrap-security-headers "default-src 'self'; img-src 'self' data:")
                      (kcs/wrap-http-validations kcs/cas-standard-vdefs kcs/cas-standard-vfns :pass-attrs [:audit-log :trace-log])
                      ;(kcs/wrap-check-referer #"https://sso\.mycompany\.com/.*")
                      (kcs/intranet-flag-wfn proxies (not force-otp))
                      (app-routes-new req-handlers))

        main-handler (-> raw-handler
                         (kc/wrap-render-view {{name}}.views/render-view)
                         (kc/trace [:main :render-view])
                         (kc/wrap-error-screen render-error (-> conf :log-conf :dump :path))
                         kc/trace-begin-wfn)

        kanar-handler-fn (-> main-handler
                             wrap-cookies
                             wrap-keyword-params
                             (kcs/wrap-only-params kcs/cas-standard-vdefs)
                             wrap-params)
        ]
    {:conf             conf
     :services         services
     :hazelcast        hazelcast
     :audit-pool       audit-pool
     :ticket-map       ticket-map
     :ticket-registry  ticket-registry
     :auth-fn          auth-fn
     :otp-lockout-map  otp-lockout-map
     :otp-tokens-map   otp-tokens-map
     :req-handlers     req-handlers
     :raw-handler      raw-handler
     :main-handler     main-handler
     :kanar-handler-fn kanar-handler-fn
     }))


(defonce kanar-app-state {})


(defn kanar-main-handler-fn [req]
  (if (:kanar-handler-fn kanar-app-state)
    ((:kanar-handler-fn kanar-app-state) req)
    {:status 500, :body "Application not configured."}))

; Start and stop functions

(def KANAR-PASSWORDS
  [[:ldap :password]])

(defn reload
  ([] (reload (System/getProperty "kanar.home")))
  ([home-dir]
   (let [conf (-> (read-string (slurp (kcu/to-path home-dir "kanar.conf")))
                  (kccr/translate-config-passwords KANAR-PASSWORDS kccr/process-password))
         svcs (read-string (slurp (kcu/to-path home-dir "services.conf")))
         app-state (new-app-state kanar-app-state conf svcs)]
     (alter-var-root #'kanar-app-state (constantly app-state))
     (taoensso.timbre/merge-config!
       {:appenders {:rotor   (rotor-appender (-> conf :log-conf :main))
                    :println {:enabled? false}}})
     (taoensso.timbre/set-level! (-> conf :log-conf :level))
     :ok)))


(defonce stopf (atom nil))
(defonce repl-server (atom nil))
(defonce conf-autoreload-f (atom nil))


(defn stop-server []
  (when-let [f @stopf]
    (.stop f))
  (when-let [cf @conf-autoreload-f]
    (future-cancel cf)
    (reset! conf-autoreload-f nil)))


(defn start-server []
  (stop-server)
  (reload)
  (let [{:keys [http-conf https-conf nrepl-conf]} (:conf kanar-app-state)]
    (when (:enabled nrepl-conf)
      (when-not @repl-server
        (reset! repl-server (nrepl/start-server :bind (:addr nrepl-conf "0.0.0.0") :port (:port nrepl-conf 7979)))))
    (reset! conf-autoreload-f
            (kcd/conf-reload-task reload (System/getProperty "kanar.home") "kanar.conf" "services.conf"))
    (reset! stopf (kcj/run-jetty-container
                    (kcd/wrap-kanar-reload kanar-main-handler-fn reload)
                    {:http-conf http-conf, :https-conf https-conf, :daemon? true}))))


(defn restart []
  (stop-server)
  (Thread/sleep 100)
  (start-server))


(defn -main [ & [cmd & _]]
  (case cmd
    "gen-kmk"
    (do
      (println (kccr/gen-kmk))
      (System/exit 0))
    "encrypt-password"
    (do
      (let [p1 (String. (.readPassword (System/console) "Enter password: " (object-array 0)))
            p2 (String. (.readPassword (System/console) "Re-enter password: " (object-array 0)))]
        (cond
          (empty? p1) (println "Empty password. Try again.")
          (not= p1 p2) (println "Passwords do not match. Try again.")
          :else (println (kccr/unprocess-password p1)))))
    (do
      (log/info "Starting KANAR server.")
      (start-server))))

