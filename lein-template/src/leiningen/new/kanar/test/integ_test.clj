(ns {{name}}.integ-test
  (:require
    [clojure.test :refer [use-fixtures deftest is testing]]
    [clj-ldap.client :as ldap]
    [compojure.core :refer [routes GET ANY rfn]]
    [ring.util.response :refer [redirect]]
    [kanar.core :as kc]
    [kanar.core.cas :as kcc]
    [kanar.core.oauth :as kco]
    [kanar.core.protocol :as kcp]
    [kanar.core.crypto :as kccr]
    [kanar.spnego]
    [kanar.core.util :as kcu])
  (:import (com.unboundid.ldap.listener InMemoryDirectoryServer InMemoryDirectoryServerConfig)
           (java.util.regex Pattern)))


; Configure LDAP environment for integration testing
(defn new-ldap-server [base-dn ldif-path]
  (doto
    (InMemoryDirectoryServer. ^InMemoryDirectoryServerConfig
      (doto (InMemoryDirectoryServerConfig. (into-array String [base-dn]))
        (.setSchema nil)))
    (.importFromLDIF true ^String ldif-path)))


(def ldap-server (new-ldap-server "dc=com", "testdata/ldapdata.ldif"))

(def ldap-servers {:ldap ldap-server})


; LDAP bind mockup function
(defn ldap-bind-fn [conf _ dn password]
  (let [conn (ldap-servers (:test-tag conf))
        user (ldap/get conn dn)]
    ; TODO handle various situations (around ldap-defs)
    (if (empty? user)
      {:error "Login failed."})
    (if-not (= password (:userPassword user))
      {:error "Login failed."})))


(defn ldap-connect-fn [c]
  (ldap-servers (:test-tag c)))


; SPNEGO authentication mockup
(defn spnego-auth-fn [token _]
  {:id (String. (bytes token) "utf-8")})


; Aktualny czas (na testy przeterminowania różnych rzeczy)
(def cur-time-override (atom nil))

(defn cur-time-fn
  ([] (cur-time-fn 0))
  ([o] (+ o (or @cur-time-override (System/currentTimeMillis)))))

(def audit-file-output-log (atom []))

(defn audit-file-output-fn [_]
  (fn [r] (swap! audit-file-output-log conj r)))


(def service-logout-log (atom []))

(defn service-logout-mock [url svt]
  (swap! service-logout-log conj {:url url, :svt svt}))


; Virtual logs
(def dummy-log (atom []))


(defn print-logs []
  (doseq [log @dummy-log]
    (println log)))

(defmacro check-dumps [] `(is (= 0 @kc/trace-dump-counter) "Error dumps detected."))

(defn setup-logs []
  (taoensso.timbre/merge-config!
    {:appenders {:rotor {:enabled? true
                         :fn (fn [data] (swap! dummy-log conj ((:output-fn data) data)))}
                 :println {:enabled? false}}})
  (taoensso.timbre/set-level! :trace))


(def ^:dynamic kanar nil)
(def ^:dynamic kanarv nil)
(def ^:dynamic app-state nil)

(defn reset-fixture [{:keys [ticket-map otp-lockout-map otp-tokens-map]}]
  (doseq [m [ticket-map otp-lockout-map otp-tokens-map]] (.clear m))
  (doseq [a [dummy-log service-logout-log audit-file-output-log]] (reset! a []))
  (reset! cur-time-override nil)
  (reset! kc/trace-dump-counter 0)
  )

(defonce test-app-state (atom {}))


(defn kanar-instance []
  (let [conf (read-string (slurp "testdata/kanar.conf"))
        services (read-string (slurp "testdata/services.conf"))
        app-state ({{name}}.app/new-app-state @test-app-state conf services)]
    (reset! test-app-state app-state)))


(defn kanar-global-fixture [f]
  (with-redefs [kanar.core/service-logout service-logout-mock
                kanar.core/audit-file-output audit-file-output-fn
                kanar.core.util/async-pooled (fn [f _] f)
                kanar.core.util/cur-time cur-time-fn
                kanar.spnego/spnego-authenticate spnego-auth-fn
                clj-ldap.client/connect ldap-connect-fn
                kanar.ldap/ldap-bind ldap-bind-fn]
    (setup-logs)
    (f)))


(use-fixtures :once kanar-global-fixture)

(defn kanar-fixture [f]
  (let [app-state (kanar-instance)]
    (reset-fixture app-state)
    (binding [kanar (:raw-handler app-state),               ; Raw request handler (bez renderowania HTML);
              kanarv (:main-handler app-state),             ; Full request handler (z renderowaniem HTML);
              app-state app-state]                          ; Application state
      (f))))

(use-fixtures :each kanar-fixture)


(defn matches [re s]
  (and (string? s) (re-matches re s)))


(defn get-tgc [r]
  "Extracts SSO ticket ID from HTTP response."
  (get-in r [:cookies "CASTGC" :value]))


(defn get-rdr [r]
  "Extracts redirection URL from HTTP response."
  (get-in r [:headers "Location"] ""))


(defn get-ticket [r]
  (let [rdr (get-rdr r)
        m (matches #".*ticket=(.*)" rdr)]
    (when m (second m))))


(defn audit-log
  ([db action]
   (audit-log db action 0))
  ([db action n]
   (let [action (keyword action)
         logs (for [r @audit-file-output-log :when (= action (:action r))] r)
         n (if (>= n 0) n (- (count logs) n))]
     (when (and (>= n 0) (< n (count logs)))
       (nth logs n)))))


(defn audit-matches [type ref]
  (let [rec (audit-log (:kanar-db app-state) type)]
    (if (nil? ref)
      (if (nil? rec) nil (str "Audit record of type " type " found but should NOT be there."))
      (filter
        (complement nil?)
        (cons
          (if (nil? rec) (str "Audit record of type " type " not found."))
          (when rec
            (for [[k v] ref]
              (cond
                (nil? v) (if-not (nil? (get rec k)) (str "Attribute " k " should NOT appear in audit record."))
                (instance? Pattern v) (if-not (and (get rec k) (re-matches v (get rec k))) (str "Attribute " k " does not match."))
                :else (if-not (= v (get rec k)) (str "Attribute " k " does not match."))))))))))


(defn audit-clean []
  (when-let [db (:kanar-db app-state)]
    (reset! audit-file-output-log [])))


(defmacro check-audit [type ref]
  `(is (empty? (audit-matches ~type ~ref)) (str "REC: " (audit-log (:kanar-db app-state) ~type))))


(def otp-users
  {:bromba {:login "bromba", :initial_key "2486617d7c2260ac", :pin "7586"}
   :gopher {:login "gopher", :initial_key "2486617d7c2260ad", :pin "7586"}
   })

(defn gen-otp
  ([uid] (gen-otp uid 0))
  ([uid offs]
   (let [{:keys [initial_key pin]} (get otp-users uid)]
     (.substring (kccr/md5 (str (long (/ (kcu/cur-time (* 1000 offs)) 10000)) initial_key pin)) 0 6))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;  Basic login process  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest test-display-login-form
         (testing "Display basic login form."
                  (let [r (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :get, :remote-addr "10.0.0.1"})]
                    (is (= :login-screen (-> r :body :type)))
                    (is (nil? (-> r :body :message))))
                  (check-dumps)))


(deftest login-success-test
  (testing "Successful login, no redirection."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post, :remote-addr "10.0.0.1",
                    :headers     {"x-forwarded-for" "192.168.1.1"}
                    :params      {:username "bromba" :password "1qaz2wsx"}})]
      (is (= 200 (:status r)))
      (println (get-tgc r))
      (is (not (empty? (get-tgc r))) "No CASTGC cookie. User did not log in.")
      (println @audit-file-output-log)
      (check-audit
        "LOGIN"
        {:who "bromba", :remote_addr "192.168.1.1", :user_login "bromba", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :tgt #"TGC-.*-XXX", :protocol :none, :status :SUCCESS,
         :intranet 1})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :remote_addr "192.168.1.1", :user_login "bromba", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :tgt #"TGC-.*-XXX", :protocol :none, :status :SUCCESS,
         :intranet 1})
      (check-dumps))))


(deftest login-check-visual-login-form-test                 ; TODO
  (testing "Successfull login, no redirection. Check rendering."
    (let [r (kanarv {:server-name "sso.myapp.com" :uri "/login" :remote-addr "10.0.0.1"
                     :headers {"x-forwarded-for" "192.168.1.1"}
                     :params {:username "bromba" :password "1qaz2wsx"} :request-method :post})]
      (is (= 200 (:status r)))
      (is (not (nil? (:body r))))
      (is (re-matches #".*Login success..*" (:body r)))
      (is (not (empty? (get-tgc r))) "Brak ciasteczka CASTGC. Użytkownik nie zalogował się.")
      (check-audit
        "LOGIN"
        {:who "bromba", :remote_addr "192.168.1.1", :user_login "bromba", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :tgt #"TGC-.*-XXX", :protocol :none, :status :SUCCESS,
         :intranet 1})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :remote_addr "192.168.1.1", :user_login "bromba", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :tgt #"TGC-.*-XXX", :protocol :none, :status :SUCCESS
         :intranet 1})
      (check-dumps))))


(deftest login-fail-test
  (testing "Unsuccessful login."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post, :remote-addr "10.0.0.1"
                    :headers { "x-forwarded-for" "192.168.1.1" }
                    :params {:username "bromba" :password "badpassword"}})]
      (is (= 200 (:status r)))
      (is (empty? (get-tgc r)) "Login process should fail.")
      (println (:cause (first @audit-file-output-log)))
      (check-audit
        "LOGIN"
        {:who "bromba", :origin :login-flow-wfn, :remote_addr "192.168.1.1", :cause "Login failed."
         :tgt nil, :protocol :none, :status :FAILED, :intranet 1})
      (check-audit "TGT-GRANT" nil)
      (check-dumps))))


(deftest login-invalid-username-test
  (testing "Illegal user name (should not pass through kanar.core.sec filters)."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post, :remote-addr "10.0.0.1"
                    :headers { "x-forwarded-for" "192.168.1.1" }
                    :params {:username "b_romba" :password "badpassword"}})]
      (is (= 200 (:status r)))
      (println (:body r))
      (is (empty? (get-tgc r)) "Login process should fail.")
      (check-audit
        "LOGIN"
        {:who "b_romba", :origin :login-flow-wfn, :remote_addr "192.168.1.1", :cause "Invalid user name."
         :tgt nil, :protocol :none, :status :FAILED, :intranet 1})
      (check-audit "TGT-GRANT" nil)
      (check-dumps))))


(deftest login-and-grant-svt-in-separate-request
  (testing "Login and then grant service ticket in separate request."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params {:username "bromba", :password "1qaz2wsx"}})
          r2 (kanar {:server-name "sso.inspol.biz" :uri "/login" :request-method :get
                     :cookies {"CASTGC" {:value (get-tgc r1)}}
                     :params {:service "https://chat.myapp.com/"}})]
      (is (= 302 (:status r2)))
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :none
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com"
         :origin :login-flow-wfn, :tgt #"TGC-.*" :status :SUCCESS, :intranet 1})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :none
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com"
         :origin :login-flow-wfn, :tgt #"TGC-.*" :status :SUCCESS, :intranet 1})
      (check-audit
        "SVT-GRANT"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :protocol :cas, :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com",
         :origin :service-lookup-wfn, :service_id :all, :principal "bromba", :svt #"ST-.*", :intranet 1}))))


(deftest login-and-check-validation-cas20
  (testing "Log in, obtain service ticket and validate it using CAS 2.0 protocol."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params {:username "bromba", :password "1qaz2wsx", :service "https://chat.myapp.com/"}})
          r2 (kanar {:server-name "sso.myapp.com" :uri "/serviceValidate" :request-method :get
                     :params { :service "https://chat.myapp.com/" :ticket (get-ticket r1)}})
          rr (kcp/cas20-parse-response (:body r2))]
      (is (= (dissoc (:attributes rr) :roles)
             {:cn "bromba", :dn "cn=bromba,ou=users,dc=mycompany,dc=com",
              :givenName "Bromba", :sn "Brombowicz", :email "Bromba.Brombowicz@mycompany.com" })
          "User attributes do not match.")
      (is (= "USERS" (get-in rr [:attributes :roles]))      ; Only one attribute -> maps to string;
          "User roles do not match.")
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com"
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS, :intranet 1})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com"
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS, :intranet 1})
      (check-audit
        "SVT-GRANT"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :protocol :cas, :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :user_login "bromba", :intranet 1,
         :origin :service-lookup-wfn, :service_id :all, :principal "bromba", :svt #"ST-.*"})
      (check-audit
        "SVT-VALIDATE"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :cas20-validate-handler, :service_id :all, :principal "bromba", :svt #"ST-.*"})
      (check-dumps))))


(deftest login-and-check-validation-cas10
  (testing "Log in, obtain service ticket and validate it using CAS 1.0 protocol."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params {:username "bromba", :password "1qaz2wsx", :service "https://chat.myapp.com/"}})
          r2 (kanar {:server-name "sso.myapp.com" :uri "/validate" :request-method :get
                     :params { :service "https://chat.myapp.com/" :ticket (get-ticket r1)}})]
      (is (= "yes\nbromba\n" (:body r2)))
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "SVT-GRANT"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :protocol :cas, :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :user_login "bromba", :intranet 1,
         :origin :service-lookup-wfn, :service_id :all, :principal "bromba", :svt #"ST-.*"})
      (check-audit
        "SVT-VALIDATE"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :cas10-validate-handler, :service_id :all, :principal "bromba", :svt #"ST-.*",})
      (check-dumps))))



(deftest login-and-check-validation-saml
  (testing "Log in, obtain service ticket and validate it using SAML 1.1 protocol."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params {:username "bromba", :password "1qaz2wsx", :service "https://chat.myapp.com/"}})
          r2 (kanar {:server-name "sso.myapp.com" :uri "/samlValidate" :request-method :post
                     :params { :TARGET "https://chat.myapp.com/" }
                     :body (kcc/saml-validate-request (get-ticket r1))})]
      (is (matches #".*saml1p.Response.*" (:body r2)))
      ; TODO parse SAML 1.1 response and check attributes
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "SVT-GRANT"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :protocol :cas, :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :user_login "bromba", :intranet 1,
         :origin :service-lookup-wfn, :service_id :all, :principal "bromba", :svt #"ST-.*"})
      (check-audit
        "SVT-VALIDATE"
        {:status :SUCCESS, :who "bromba", :service_url "https://chat.myapp.com/", :tgt #"TGC.*",
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin :saml11-validate-handler, :service_id :all, :principal "bromba", :svt #"ST-.*"})
      (check-dumps))))



(deftest login-logout-and-check-audit-logs
  (testing "Log in (with service ticket grant), logout and check audit logs."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params      {:username "bromba", :password "1qaz2wsx" :service "https://chat.myapp.com/"}})
          _ (kanar {:server-name "sso.myapp.com" :uri "/logout" :request-method :get
                    :cookies     {"CASTGC" {:value (get-tgc r1)}}})]
      (is (= 5 (count @audit-file-output-log)))
      (is (= 1 (count @service-logout-log)))                ; TODO check what we have in this log
      (is (= 302 (:status r1)))
      (check-audit
        "LOGIN"
        {:who      "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt      #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "TGT-GRANT"
        {:who      "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :login-flow-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt      #"TGC-.*" :svt #"ST-.*", :status :SUCCESS })
      (check-audit
        "SVT-GRANT"
        {:who      "bromba", :user_login "bromba", :principal "bromba", :protocol :cas
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :service-lookup-wfn, :service_id :all, :service_url "https://chat.myapp.com/"
         :tgt      #"TGC-.*" :svt #"ST-.*", :status :SUCCESS})
      (check-audit
        "TGT-DESTROY"
        {:who      "bromba", :principal "bromba", :protocol :cas
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :logout-handler,  :tgt  #"TGC-.*" :svt nil, :status :SUCCESS})
      (check-audit
        "SVT-DESTROY"
        {:who         "bromba", :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :service_url "https://chat.myapp.com/", :protocol :cas, :tgt #"TGC-.*", :status :SUCCESS, :origin :logout-handler
         :service_id  :all, :principal "bromba", :svt #"ST-.*"})
      (check-dumps))))



(deftest login-onto-2-services-logout-and-check-audit
  (testing "Log in to two services, log out and check service logout queue."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params      {:username "bromba", :password "1qaz2wsx" :service "https://chat.myapp.com/"}})
          _ (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :get
                    :params      {:service "https://mail.myapp.com/"}, :cookies {"CASTGC" {:value (get-tgc r1)}}})
          _ (kanar {:server-name "sso.myapp.com" :uri "/logout" :request-method :get
                    :cookies     {"CASTGC" {:value (get-tgc r1)}}})]
      (is (= 7 (count @audit-file-output-log)))
      (is (= 2 (count @service-logout-log)))
      (is (= 302 (:status r1)))
      (is (= #{"https://chat.myapp.com/" "https://mail.myapp.com/" nil}
             (set (map :service_url @audit-file-output-log))))
      (is (= ["https://chat.myapp.com/" "https://mail.myapp.com/"]
             (vec (sort (map :url @service-logout-log)))))
      (check-dumps))))


(deftest login-logout-with-service-and-check-audit-logs
  (testing "SSO login, logout, check if login screen appears again after logout."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params      {:username "bromba", :password "1qaz2wsx"}})
          r2 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :get
                     :cookies     {"CASTGC" {:value (get-tgc r1)}}})
          _ (kanar {:server-name "sso.myapp.com" :uri "/logout" :request-method :get
                    :cookies     {"CASTGC" {:value (get-tgc r1)}}})
          r4 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :get
                     :cookies     {"CASTGC" {:value (get-tgc r1)}}})]
      (is (= :message (-> r2 :body :type)))
      (is (= :login-screen (-> r4 :body :type)))
      (check-audit
        "LOGIN"
        {:who      "bromba", :user_login "bromba", :principal "bromba", :protocol :none
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :login-flow-wfn,  :tgt #"TGC-.*" :svt nil, :status :SUCCESS})
      (check-audit
        "TGT-GRANT"
        {:who      "bromba", :user_login "bromba", :principal "bromba", :protocol :none,
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :login-flow-wfn, :tgt #"TGC-.*" :svt nil, :status :SUCCESS})
      (check-audit
        "TGT-DESTROY"
        {:who      "bromba", :principal "bromba", :protocol :cas
         :user_dn  "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :origin   :logout-handler, :tgt #"TGC-.*" :svt nil, :status :SUCCESS})
      (is (= 3 (count @audit-file-output-log)))
      (check-dumps))))


(deftest login-to-forbidden-service
  (testing "Log in and try going to service that is not allowed."
    (let [r1 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params      {:username "bromba", :password "1qaz2wsx"
                                   :service "https://bean-counter.myapp.com/"}})]
      (is (= "Service not allowed.", (-> r1 :body :message)))
      (is (= :message (-> r1 :body :type)))
      (is (= 200 (:status r1))))
    (let [r2 (kanar {:server-name "sso.myapp.com" :uri "/login" :request-method :post
                     :params      {:username "gopher", :password "1qaz2wsx", :intranet 1,
                                   :service "https://bean-counter.myapp.com/"}})]
      (is (matches #"https://bean\-counter.myapp.com/.ticket=ST.*", (get (:headers r2) "Location")))
      (is (= 302 (:status r2))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;     One Time Passwords     ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(deftest otp-login-form-display-test                        ; TODO visuals
  (testing "Check if OTP field is displayed."
    (let [r (kanarv {:request-method :get, :server-name "sso.myapp.com", :uri "/login"})]
      (is (not (re-matches #".*name=.token.*" (:body r)))))
    (let [r (kanarv {:request-method :get, :server-name "sso.myapp.com", :uri "/login",
                     :headers { "x-forwarded-for" "192.168.1.2"}})]
      (is (re-matches #".*name=.token.*" (:body r))))
    (let [r (kanarv {:request-method :get, :server-name "sso.myapp.com", :uri "/login",
                     :headers        { "x-forwarded-for" "192.168.1.1"}})]
      (println (-> r :req :params))
      (is (not (re-matches #".*name=.token.*" (:body r)))))
    (is (empty? @audit-file-output-log))
    (check-dumps)))


(deftest otp-login-from-public-internet-without-token-test
  (testing "Check if OTP is required from extranet."
    (let [r (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                    :params {:username "bromba", :password "1qaz2wsx"}
                    :headers { "x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r)))
      (is (= "Token is required." (get-in r [:body :message]))))
    (let [r (kanarv {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params          {:username "bromba", :password "1qaz2wsx"}
                     :headers         { "x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r)))
      (is (re-matches #".*Token is required.*", (:body r))))
    (check-audit
      "LOGIN"
      {:who "bromba", :intranet 0, :cause "Token is required.", :protocol :none, :user_login "bromba",
       :remote_addr "192.168.1.2", :status :FAILED, :action :LOGIN, :origin :login-flow-wfn,
       :tgt nil, :svt nil, :service_url nil, :service_id nil})
    (check-audit "TGT-GRANT" nil)
    (check-audit "SVT-GRANT" nil)
    (check-dumps)))


(deftest otp-login-from-public-internet-with-valid-token-test
  (testing "Log in with valid OTP token."
    (let [r (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                    :params         {:username "bromba", :password "1qaz2wsx", :token (gen-otp :bromba)}
                    :headers        {"x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r)))
      (is (= "Login successful." (get-in r [:body :message])))
      (check-audit
        "LOGIN"
        {:status     :SUCCESS, :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 0,
         :user_login "bromba", :origin :login-flow-wfn, :principal "bromba",
         :protocol   :none, :service_id nil, :service_url nil, :svt nil, :otp 1})
      (check-dumps))))


(deftest otp-login-from-public-internet-with-invalid-token-test
  (testing "Log in with invalid token."
    (let [r (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                    :params         {:username "bromba", :password "1qaz2wsx", :token "000000"}
                    :headers        {"x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r)))
      (is (= "Invalid OTP token." (get-in r [:body :message])))
      (check-audit
        "LOGIN"
        {:status     :FAILED, :user_login "bromba", :origin :login-flow-wfn, :intranet 0,
         :protocol   :none, :service_id nil, :service_url nil, :svt nil, :sulogin 0, :otp 1,
         :cause "Invalid OTP token."}))
    ;(let [r (kanarv {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
    ;                 :params          {:username "bromba", :password "1qaz2wsx", :token "000000"}
    ;                 :headers         {"x-forwarded-for" "192.168.1.2"}})]
    ;  (is (= 200 (:status r)))
    ;  (is (re-matches #".*Invalid OTP token.*" (:body r))))
    (let [r (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                    :params         {:username "bromba", :password "1qaz2wsx", :token "111111"}
                    :headers        {"x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r)))
      (is (= "Invalid OTP token." (get-in r [:body :message])))
      (check-audit
        "LOGIN"
        {:status     :FAILED, :user_login "bromba", :origin :login-flow-wfn, :intranet 0,
         :protocol   :none, :service_id nil, :service_url nil, :svt nil, :sulogin 0, :otp 1,
         :cause "Invalid OTP token."})
      (check-dumps))))


; TODO tokens still can be (ab)used
(deftest otp-login-from-public-internet-with-abused-token-test
  (testing "Try reusing OTP token."
    (let [t (gen-otp :bromba)
          r1 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token t}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})
          _ (audit-clean)
          r2 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token t}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})]
      (is (= "Login successful." (get-in r1 [:body :message])))
      (is (= 200 (:status r2)))
      (is (= "Token already used." (get-in r2 [:body :message])))
      (check-audit
        "LOGIN"
        {:status     :FAILED, :user_login "bromba", :origin :login-flow-wfn, :intranet 0,
         :protocol   :none, :service_id nil, :service_url nil, :svt nil, :sulogin 0, :otp 1, :tgt nil,
         :cause "Token already used."})
      (check-dumps))))


(deftest otp-login-from-public-internet-with-locked-token-test
  (testing "Try using locked out token."
    (let [r1 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token "333333"}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})
          r2 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token "333333"}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})
          r3 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token "333333"}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})
          _ (audit-clean)
          r4 (kanar {:request-method :post, :server-name "sso.myapp.com", :uri "/login",
                     :params         {:username "bromba", :password "1qaz2wsx", :token (gen-otp :n0100105)}
                     :headers        {"x-forwarded-for" "192.168.1.2"}})]
      (is (= 200 (:status r4)))
      (is (= "Invalid OTP token." (get-in r1 [:body :message])))
      (is (= "Invalid OTP token." (get-in r2 [:body :message])))
      (is (= "Invalid OTP token." (get-in r3 [:body :message])))
      (is (= "Too many OTP attempts." (get-in r4 [:body :message])))
      (check-audit
        "LOGIN"
        {:status     :FAILED, :user_login "bromba", :origin :login-flow-wfn, :intranet 0,
         :protocol   :none, :service_id nil, :service_url nil, :svt nil, :sulogin 0, :otp 1,
         :cause "Too many OTP attempts."})
      (check-dumps))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;     Impersonification     ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(deftest su-login-test
  (testing "Log in via impersonification."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/sulogin" :request-method :post, :remote-addr "10.0.0.1"
                    :params      {:username "suadmin" :password "1qaz2wsx" :runas "bromba" :case "SD-12345"}})]
      (is (= 200 (:status r)))
      (is (not (empty? (get-tgc r))) "User did not log in.")
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "suadmin", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :tgt #"TGC-.*", :protocol :none, :status :SUCCESS, :sulogin 1, :sucase "SD-12345", :runas "bromba"})
      (check-audit
        "TGT-GRANT"
        {:who "bromba", :user_login "suadmin", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :tgt #"TGC-.*", :protocol :none, :status :SUCCESS, :sulogin 1, :sucase "SD-12345", :runas "bromba"})))
  (check-dumps))


(deftest su-login-without-privileves-test
  (testing "Try impersonification with insufficient privileges."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/sulogin" :request-method :post, :remote-addr "10.0.0.1"
                    :params      {:username "bromba" :password "1qaz2wsx" :runas "gopher" :case "SD-12345"}})]
      (is (= 200 (:status r)))
      (is (empty? (get-tgc r)) "Should NOT log in.")
      (check-audit
        "LOGIN"
        {:who "bromba", :user_login "bromba", :principal "bromba", :origin :login-flow-wfn,
         :user_dn "cn=bromba,ou=users,dc=mycompany,dc=com", :intranet 1,
         :protocol :none, :status :FAILED, :sulogin 1, :sucase "SD-12345", :runas "gopher",
         :cause "This user has no SU privileges."})))
  (check-dumps))


(deftest su-login-check-attributes-test
  (testing "Impersonificate and look for additional attributes related to impersonification."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/sulogin" :request-method :post, :remote-addr "10.0.0.1"
                    :params      {:username "suadmin" :password "1qaz2wsx" :runas "bromba" :case "SD-12345",
                                  :service "https://chat.myapp.com/"}})
          r2 (kanar {:server-name "sso.myapp.com" :uri "/serviceValidate" :request-method :get
                     :params { :service "https://chat.myapp.com/" :ticket (get-ticket r)}})
          rr (kcp/cas20-parse-response (:body r2))]
      (is (= 302 (:status r)))
      (is (not (empty? (get-tgc r))) "User did not log in.")
      (is (= "bromba" (:id rr)))
      (is (= "true" (-> rr :attributes :impersonificated)))
      (is (= "SD-12345" (-> rr :attributes :caseNum)))
      (is (= "suadmin" (-> rr :attributes :adminLogin)))
      (is (= ["su-admins" "su-deny" "USERS"] (-> rr :attributes :adminRoles)))))
  (check-dumps))


(deftest su-login-su-deny-test
  (testing "Try impersonificating onto user that no one can impersonificate to."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/sulogin" :request-method :post, :remote-addr "10.0.0.1"
                    :params {:username "suadmin" :password "1qaz2wsx" :runas "suadmin" :case "SD-12345"}})]
      (is (= 200 (:status r)))
      (is (empty? (get-tgc r)) "Should not log in.")
      (check-audit
        "LOGIN"
        {:who "suadmin", :user_login "suadmin", :principal "suadmin", :origin :login-flow-wfn, :intranet 1,
         :protocol :none, :status :FAILED, :sulogin 1, :sucase "SD-12345", :runas "suadmin",
         :cause "Cannot SU onto this user."})))
  (check-dumps))


(deftest su-login-su-non-existent-user-test
  (testing "Try impersonificating onto non-existent account."
    (let [r (kanar {:server-name "sso.myapp.com" :uri "/sulogin" :request-method :post, :remote-addr "10.0.0.1"
                    :params      {:username "suadmin" :password "1qaz2wsx" :runas "ufok" :case "SD-12345"}})]
      (is (= 200 (:status r)))
      (is (= "No such user." (-> r :body :message)))        ; TODO "No such user to impersonificate."
      (is (empty? (get-tgc r)) "Should not log in.")
      (check-audit
        "LOGIN"
        {:who "suadmin", :user_login "suadmin", :principal nil, :origin :login-flow-wfn,
         :intranet 1, :protocol :none, :status :FAILED, :sulogin 1, :sucase "SD-12345", :runas "ufok",
         :tgt nil, :cause "No such user."})))
  (check-dumps))

