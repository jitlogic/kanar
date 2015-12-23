(ns {{name}}.app
  "Main KANAR app namespace."
  (:gen-class)
  (:require
    [clojure.tools.nrepl.server :as nrepl]
    [compojure.core :refer [routes GET POST ANY rfn]]
    [compojure.route :refer [not-found resources]]
    [kanar.core :as kc]
    [kanar.core.sec :as kcs]
    [kanar.core.ticket :as kt]
    [kanar.core.util :as ku]
    [kanar.core.fileauth :as kf] {{#with-ldap}}
    [clj-ldap.client :as ldap]
    [kanar.ldap :as kl] {{/with-ldap}} {{#with-hazelcast}}
    [kanar.hazelcast :as kh] {{/with-hazelcast}}
    [org.httpkit.server :refer [run-server]]
    [ring.adapter.jetty :refer [run-jetty]]
    [{{name}}.views :as kav]
    [ring.middleware.reload :refer [wrap-reload]]
    [ring.middleware.keyword-params :refer [wrap-keyword-params]]
    [ring.middleware.params :refer [wrap-params]]
    [ring.middleware.cookies :refer [wrap-cookies]]
    [ring.util.response :refer [redirect]]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre.appenders.3rd-party.rotor :refer [rotor-appender]]
    [taoensso.timbre :as log])
  (:import (java.text SimpleDateFormat)
           (java.util Date)
           (java.io File)))


; This is application state.
(defonce ^:dynamic *app-state* (atom {}))

(defn to-path [home-dir path]
  (if (.startsWith path "/") path (str home-dir "/" path)))

(defn wrap-error-screen [f]
  (fn [req]
    (try
      (f req)
      (catch Throwable e
        (log/error "Fatal error: " e)
        (.printStackTrace e)
        {:status  200
         :headers {"Content-Type" "text/html; charset=utf-8"}
         :body    (kav/message-view :error "Unexpected error.")}))))


(defn kanar-routes-new [app-state]
  (routes
    (GET "/login" req
      (kc/login-handler (:form-login-flow @app-state) @app-state req))
    (POST "/login" req
      (kc/login-handler (:form-login-flow @app-state) @app-state req))
    (GET "/logout" req
      (kc/logout-handler @app-state req))
    (GET "/validate" req
      (kc/cas10-validate-handler @app-state req))
    (GET "/serviceValidate" req
      (kc/cas20-validate-handler @app-state req #"ST-.*"))
    (GET "/proxyValidate" req
      (kc/cas20-validate-handler @app-state req #"(ST|PT)-.*"))
    (GET "/proxy" req
      (kc/proxy-handler @app-state req))
    (POST "/samlValidate" req
      (kc/saml-validate-handler @app-state req))
    (resources "/")
    (ANY "/*" []
      (redirect "login"))))



(def kanar-routes (kanar-routes-new *app-state*))

(def kanar-app-vfns
  (merge kcs/cas-standard-vfns
         {"/login" (fn [{ {:keys [username service TARGET]} :params} msg]
                     (kav/login-view :username username, :error-msg msg
                                     :service service, :TARGET TARGET))}))

(def kanar-handler
  (wrap-reload
    (-> #'kanar-routes
        wrap-error-screen
        (kcs/wrap-http-validations kcs/cas-standard-vdefs kanar-app-vfns)
        (kcs/wrap-check-referer #"https://myapp\.com(/.*)?")
        (kcs/wrap-security-headers)
        wrap-cookies
        wrap-keyword-params
        wrap-params)))


(defn {{name}}-audit-fn [path]
  "Logs audit information to a file."
  (fn [app-state { {:keys [username]} :params :as req} { {id :id} :princ :as tgt} svc action]
    (let [user (or id username)]
      (spit
        (str path "." (.format (SimpleDateFormat. "yyyy-MM-dd") (Date.)))
        (str (.format (SimpleDateFormat. "yyyy-MM-dd HH:MM:ss ") (Date.)) "WHO=" user " ACTION=" (name action) "\n")
        :append true)
      )))


(def ATTR-MAP
  {:sn :sn,
   :dn :dn,
   :givenName :givenName,
   :cn :cn})


(defn new-app-state [old-app-state conf services{{#with-file}} users{{/with-file}} home-dir]
  "Creates new application state structure with configuration and current state."
  (let [{{#with-ldap}}ldap-conn (ldap/connect (:ldap-conf conf))
        auth-fn (ku/chain-auth-fn
                  (kl/ldap-auth-fn ldap-conn (:ldap-conf conf) [])
                  (kl/ldap-attr-fn ldap-conn ATTR-MAP)){{/with-ldap}}
        {{#with-file}}auth-db (atom users)
         auth-fn (kf/file-auth-fn auth-db){{/with-file}}
        {{#with-hazelcast}} hci (or (:hazelcast old-app-state) (kh/new-hazelcast (:hazelcast conf))) {{/with-hazelcast}}]
    {:ticket-seq          (or (:ticket-seq old-app-state) (atom 0))
     :conf                conf
     :services            services {{#with-hazelcast}}
     :hazelcast           hci {{/with-hazelcast}}
     :ticket-registry     (or (:ticket-registry old-app-state)
          {{#with-atom-tr}}(kt/atom-ticket-registry (atom {}) (:server-id conf)) {{/with-atom-tr}}
          {{#with-hazelcast}} (kh/hazelcast-ticket-registry (.getReplicatedMap hci "kanar.tickets")) {{/with-hazelcast}})
     :render-message-view kav/message-view
     :form-login-flow     (kc/form-login-flow auth-fn kav/login-view){{#with-file}}
     :auth-db             auth-db{{/with-file}}
     :audit-fn            ({{name}}-audit-fn (to-path home-dir (-> conf :log-conf :audit :path)))}))


; Start and stop functions

(defn configure-logs [{:keys [main level] :or {:level :debug :main {}}}]
  (taoensso.timbre/merge-config!
    {:appenders {:rotor   (rotor-appender main)
                 :println {:enabled? false}}})
  (taoensso.timbre/set-level! level))



(defn reload
  ([] (reload (System/getProperty "kanar.home")))
  ([home-dir]
   (let [conf (read-string (slurp (to-path home-dir "kanar.conf")))
         {{#with-file}}users (kf/file-auth-load-file (to-path home-dir "users.conf")) {{/with-file}}
         svcs (read-string (slurp (to-path home-dir "services.conf")))]
     (swap! *app-state* new-app-state conf svcs {{#with-file}}users {{/with-file}}home-dir)
     (configure-logs (:log-conf conf))
     :ok
     )))


(defn conf-reload-task-auto []
  (let [home (System/getProperty "kanar.home")
        conf (to-path home "kanar.conf")
        svcs (to-path home "services.conf")
        usrs (to-path home "users.conf")
        fok (File. (str home "/logs/reload.ok"))
        fer (File. (str home "/logs/reload.error"))]
    (log/info "Starting automatic configuration reload task ...")
    (future
      (loop [tcnf1 (.lastModified (File. conf))
             tsvc1 (.lastModified (File. svcs))
             {{#with-file}}tusr1 (.lastModified (File. usrs)){{/with-file}}]
        (Thread/sleep 5000)
        (let [tcnf2 (.lastModified (File. conf))
              tsvc2 (.lastModified (File. svcs)){{#with-file}}
              tusr2 (.lastModified (File. usrs)){{/with-file}}]
          (try+
            (log/trace "Checking conf: " tcnf1 "<->" tcnf2 " ; " tsvc1 "<->" tsvc2)
            (when (or (not= tcnf1 tcnf2) (not= tsvc1 tsvc2) {{#with-file}}(not= tusr1 tusr2){{/with-file}})
              (log/info "Configuration change detected. Reloading...")
              (reload)
              (spit fok (str "New config: \n" (clojure.pprint/write (:conf @*app-state*) :stream nil))))
            (catch Object e
              (spit fer (str "Error:" e))
              (log/error "Error reloading configuration: " e)))
          (recur tcnf2 tsvc2{{#with-file}} tusr2{{/with-file}}))))))


(defonce stopf (atom nil))
(defonce repl-server (atom nil))
(defonce ticket-cleaner-f (atom nil))
(defonce conf-autoreload-f (atom nil))


(defn stop-server []
  (when-let [f @stopf]
    (.stop f))
  (when-let [cf @ticket-cleaner-f]
    (future-cancel cf))
  (when-let [cf @conf-autoreload-f]
    (future-cancel cf)
    (reset! conf-autoreload-f nil)))


(defn start-server []
  (stop-server)
  (reload)
  (let [{:keys [http-port https-enabled https-port https-keystore https-keypass reload nrepl-port]} (:conf @*app-state*)]
    (reset! stopf (run-jetty kanar-handler
                             (merge
                               {:port http-port :join? false}
                               (if https-enabled
                                 {:ssl? true :ssl-port https-port
                                  :keystore https-keystore :key-password https-keypass}
                                 {}))))
    (reset! ticket-cleaner-f (kc/ticket-cleaner-task *app-state*))
    (when-not @repl-server
      (reset! repl-server (nrepl/start-server :bind "0.0.0.0" :port nrepl-port)))
    (if (= reload :auto)
      (reset! conf-autoreload-f (conf-reload-task-auto)))))


(defn restart []
  (stop-server)
  (Thread/sleep 100)
  (start-server))


(defn -main [& args]
  (println "Starting KANAR server.")
  (start-server))



