(ns kanar.spnego
  (:require
    [kanar.core.util :as ku]
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log])
  (:import (jcifs.spnego Authentication AuthenticationException)
           (javax.xml.bind DatatypeConverter)))


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


(defn spnego-auth-fn [{:keys [login-conf] :as spnego-conf}]
  (log/info "Creating SPNEGO config: " spnego-conf)
  (System/setProperty "java.security.auth.login.config" login-conf)
  (System/setProperty "javax.security.auth.useSubjectCredsOnly" "false")
  (System/setProperty "java.security.krb5.conf" "/etc/krb5.conf")
  (System/setProperty "sun.security.spnego.debug" "all")
  (fn [_ req]
    (try+
      (let [^String authdr (get (:headers req) "authorization")
            token (DatatypeConverter/parseBase64Binary (.substring authdr 10))
            auth (spnego-authenticator spnego-conf token)
            princ (.getPrincipal auth)]
        (if princ
          {:id (.getName princ) :attributes {}}
          (ku/login-failed "User not authenticated.")))
      (catch Exception e
        (ku/login-failed "User not authenticated.")))))


(defn spnego-login-flow [spnego-enable-fn spnego-auth-fn form-login-flow-fn render-login-fn]
  "SPNEGO login flow."
  (fn [app-state {{:keys [dom service TARGET]} :params :as req}]
    (let [^String authdr (get (:headers req) "authorization")]
      (cond
        (not (spnego-enable-fn req))
          (form-login-flow-fn app-state req)
        (nil? authdr)
          (ku/login-cont
            {:status 401, :headers {"WWW-Authenticate" "Negotiate", "Content-Type" "text/html; charset=utf-8"}
             :body   (render-login-fn :dom dom :service service, :TARGET TARGET
                                      :req req, :app-state app-state)})
        (not (.startsWith authdr "Negotiate"))
          (form-login-flow-fn app-state req)
        :else
        (let [princ (spnego-auth-fn nil req)]
          (log/debug "Resolved principal: " princ)
          princ)))))

