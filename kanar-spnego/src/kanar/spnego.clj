(ns kanar.spnego
  (:require
    [kanar.core.util :as ku]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log]
    [kanar.core :as kc])
  (:import (jcifs.spnego Authentication)
           (javax.xml.bind DatatypeConverter)))


(defn- configure-spnego-globals [{:keys [enabled login-conf] :as spnego-conf}]
  (when spnego-conf
    (log/info "Creating SPNEGO config: " spnego-conf)
    (System/setProperty "java.security.auth.login.config" login-conf)
    (System/setProperty "javax.security.auth.useSubjectCredsOnly" "false")
    (System/setProperty "java.security.krb5.conf" (:krb-conf-path spnego-conf "/etc/krb5.conf"))
    (System/setProperty "sun.security.spnego.debug" "all")))


(defn spnego-authenticator [{:keys [login-conf realm kdc principal]} token]
  (doto (Authentication.)
    (.setProperty "java.security.auth.login.config" login-conf)
    (.setProperty "sun.security.krb5.debug" "all")
    (.setProperty "javax.security.auth.useSubjectCredsOnly" "false")
    (.setProperty "java.security.krb5.conf" "/etc/krb5.conf")
    (.setProperty "java.security.krb5.realm" realm)
    (.setProperty "java.security.krb5.kdc" kdc)
    (.setProperty "jcifs.spnego.servicePrincipal" principal)
    (.setProperty "jcifs.http.domainController" kdc)
    (.reset)
    (.process token)))


(defn spnego-authenticate [token spnego-conf]
  (try+
    (let [auth (spnego-authenticator spnego-conf token)
          princ (.getPrincipal auth)]
      (if princ
        {:id (.getName princ)}
        {:error "Cannot authenticate user."}))
    (catch Throwable e
      {:error (str "Error authenticating: " (ku/error-with-trace e))})
    (catch Object o
      {:error (str "Error authenticating: " o)})))

(defn ntlm? [token]
  (and
    (>= (alength token) 7)
    (= (byte \N) (aget token 0)) (= (byte \T) (aget token 1)) (= (byte \L) (aget token 2)) (= (byte \M) (aget token 3))
    (= (byte \S) (aget token 4)) (= (byte \S) (aget token 5)) (= (byte \P) (aget token 6))))

; TODO zaimplementować poprawnie tę funkcję
(defn spnego-auth-wfn
  "Implements SPNEGO login sequence. If integrated authentication succeeds, [spnego-chain] is executed, otherwise
   [form-chain] is executed.
   conf - SPNEGO configuration;
   spnego-enable-fn - function called before authentication; if returns true, server should attempt SPNEGO authentication;
   spnego-chain - request handler that should be called when SPNEGO sequence succeeds;
   form-chain - request handler that should be called when SPNEGO sequence didn't succeed;"
  ([conf spnego-enable-fn spnego-chain form-chain]
    (spnego-auth-wfn identity conf spnego-enable-fn spnego-chain form-chain))
  ([f {:keys [enabled] :as spnego-conf} spnego-enable-fn spnego-chain form-chain]
   (configure-spnego-globals spnego-conf)
   (fn [{:keys [request-method] :as req}]
     (let [^String authdr (get (:headers req) "authorization")
           r (cond
               (not enabled) (form-chain req)
               (= request-method :post) (form-chain req)
               (not (spnego-enable-fn req)) (form-chain req)
               (nil? authdr) (merge
                               (kc/login-screen req "Integrated login didn't succeed. Try with password.")
                               {:status  401,
                                :headers {"WWW-Authenticate" "Negotiate", "Content-Type" "text/html; charset=utf-8"}})
               (not (.startsWith authdr "Negotiate")) (form-chain req)
               :else (let [token (DatatypeConverter/parseBase64Binary (.substring authdr 10))]
                       (cond
                         (ntlm? token)
                         (do
                           (log/info "Expected SPNEGO token but obtained NTLM. Please check client browser or domain configuration.")
                           (form-chain req))
                         :else
                         (let [{:keys [id error]} (spnego-authenticate token spnego-conf)]
                           (if id
                             (spnego-chain (assoc req :principal {:id id, :attributes {}},
                                                      :spnego-authenticated true,
                                                      :credentials {:username id}))
                             (do
                               (log/info "SPNEGO login failed with: " error)
                               (form-chain req)))))))]
       (if (:principal r) (f r) r)))))


; TODO to jest właściwa część spnego-auth-wfn


