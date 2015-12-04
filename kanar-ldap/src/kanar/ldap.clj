(ns kanar.ldap
  "LDAP authentication and principal resolve."
  (:require
    [clj-ldap.client :as ldap]
    [slingshot.slingshot :refer [try+ throw+]]
    [kanar.core.util :as ku]
    [taoensso.timbre :as log])
  (:import (com.unboundid.ldap.sdk LDAPConnectionOptions)
           (java.text SimpleDateFormat)))


(def LDAP_TSTAMP_RE #"([0-9]{14})Z")


(def edir-err-defs
  [[#"NDS error.*197.*"                          {:type :login-failed :msg "Account locked."}]
   [#"NDS error.*215.*"                          {:type :chpass-failed :msg "Password previously used."}]
   [#"NDS error.*220.*",                         {:type :login-failed :msg "Account expired."}]
   [#"NDS error: bad password ..222.",           {:type :login-failed, :msg "Login failed."}]
   [#"NDS error.*222.*"                          {:type :login-failed :msg "Password expired."}]
   [#"NDS error: failed authentication ..669."   {:type :login-failed :msg "Login failed."}]
   [#"NDS error.*669.*"                          {:type :chpass-failed :msg "Wrong password."}]
   [#"NDS error: ds locked.*663.*"               {:type :login-failed :msg "LDAP unavailable."}]
   [#".*"                                        {:type :login-failed :msg "Login failed." }]])


(def msad-err-defs
  [[#".*error, data 530.*"                       {:type :login-failed :msg "Not permitted at this time."}]
   [#".*error, data 532.*"                       {:type :login-failed :msg "Password expired."}]
   [#".*error, data 533.*"                       {:type :login-failed :msg "Account disabled."}]
   [#".*error, data 701.*"                       {:type :login-failed :msg "Account expired."}]
   [#".*error, data 701.*"                       {:type :login-failed :msg "Password must be reset."}]
   [#".*error, data 775.*"                       {:type :login-failed :msg "Account locked."}]
   [#".*"                                        {:type :login-failed :msg "Login failed." }]])


(defn dispatch-error [err-defs e]
  (doseq [[rex exc] err-defs]
    (when (re-matches rex (.getMessage e))
      (log/debug "KLDAP-D001: dispatch-error: Dispatched error as" exc "message=" (.getMessage e))
      (throw+ exc)))
  (log/error "KLDAP-E001: dispatch-error: Unknown LDAP error (not dispatched):" (.getMessage e))
  (ku/login-failed "Login failed."))


(defn ldap-bind [ldap-conf err-defs dn password]
  (try+
    (let [conn (ldap/connect (assoc ldap-conf :num-connections 1 :bind-dn dn :password password))]
      (log/debug "KLDAP-D002: ldap-bind: Successfully bound as " dn)
      (.close conn))
    (catch Exception e
      (log/debug "KLDAP-D003: ldap-bind: Error binding user account " dn ":" e)
      (dispatch-error err-defs e))))

(defn user-connect [ldap-conf err-defs dn password]
  (try
    (ldap/connect (assoc ldap-conf :num-connections 1 :bind-dn dn :password password))
    (catch Exception e
      (log/warn "KLDAP-W001: user-connect Error connecting as user" dn ":" e)
      (dispatch-error err-defs e))))

(def ^:private DEFAULT_USER_RE #"[a-zA-Z0-9_\-\.]+")

; TODO uporządkować zarządzanie wyjątkami - nie ma sensu sprawdzać wyjątki LDAP na wielu poziomach jednocześnie

; TODO test na defaultowe wartości (bo chyba nie działają)
(defn ldap-lookup-dn [conn err-defs {:keys [base-dn user-query user-re login-tmout]} id]
  (try+
    (if (and (not (empty? id)) (re-matches (or user-re DEFAULT_USER_RE) id))
      (let [query (.replaceAll user-query "@@USER@@" id)
            base-dns (if (vector? base-dn) base-dn [base-dn])
            entries (flatten (for [b base-dns
                                   :let [r (ldap/search conn b {:attributes [:dn] :filter query})]
                                   :when (not (nil? r))] r))]
        (log/debug "KLDAP-D004: ldap-lookup-id query:" query "results:" (vec entries))
        (cond
          (empty? entries)
          (do
            (if login-tmout (Thread/sleep login-tmout))
            (log/warn "KLDAP-W002: ldap-lookup-id: user not found" id)
            (ku/login-failed "Invalid username or password."))
          (not (empty? (next entries)))
          (do
            (log/error "KLDAP-E002: ldap-lookup-dn: Error in users database: query=" query "base-dn=" base-dn "found records:" entries)
            (ku/login-failed "Error in users database. Please contact administrator."))
          :else (:dn (first entries))))
      (do
        (if login-tmout (Thread/sleep login-tmout))
        (ku/login-failed "Invalid user name.")))
    (catch Exception e
      (log/warn "KLDAP-E003: ldap-lookup-dn: Error searching for user" id ":" e)
      (dispatch-error err-defs e))))


(defn ldap-auth-fn [conn ldap-conf err-defs]
  (fn [_ {{username :username password :password} :params :as req}]
    (let [dn (ldap-lookup-dn conn err-defs ldap-conf username)]
      (log/trace "KLDAP-T001: ldap-auth-fn: Found user DN: " dn)
      (ldap-bind ldap-conf err-defs dn password)
      {:id username :dn dn :attributes {}})))


(defn ldap-lookup-fn [conn ldap-conf err-defs]
  (fn [{id :id :as princ} _]
    (let [dn (ldap-lookup-dn conn err-defs ldap-conf id)]
      (log/trace "Found user DN: " dn)
      (assoc princ :dn dn))))


(defn ldap-attr-fn [conn attr-map]
  (fn [{:keys [dn attributes] :as princ} _]
    (let [entry (ldap/get conn dn (keys attr-map))]
      (if entry
        (assoc princ
          :attributes
          (into (or attributes {}) (for [[k1 k2] attr-map] {k2 (k1 entry)})))
        (ku/login-failed "Cannot obtain user data.")))))


(defn ldap-roles-fn [conn attr to-attr regex]
  (fn [princ _]
    (let [entry (ldap/get conn (:dn princ) [attr])
          attrs (if (string? (attr entry)) [(attr entry)] (attr entry))]
      (if entry
        (assoc-in
          princ [:attributes to-attr]
          (filterv not-empty
                   (for [g attrs] (second (re-find regex g)))))
        (ku/login-failed "Cannot obtain user data.")))))

; TODO recursive LDAP group resolver

(defn parse-dt [s]
  "Parses LDAP datetime string."
  (if s
    (let [[_ ss] (re-matches #"(\d{14})Z" s)]
      (if ss (.parse (SimpleDateFormat. "yyyyMMddHHmmss") ss)))))


(defn ldap-connection-options-patch
  "Patch for clj-ldap.client/connection-options function. Add auto-reconnect and follow-referrals options."
  [{:keys [connect-timeout timeout auto-reconnect follow-referrals tcp-keepalive abandon-timeout synchronous-mode capture-stack-trace] :as opts}]
  (let [opt (LDAPConnectionOptions.)]
    (when connect-timeout  (.setConnectTimeoutMillis opt connect-timeout))
    (when timeout          (.setResponseTimeoutMillis opt timeout))
    (when auto-reconnect   (.setAutoReconnect opt auto-reconnect))
    (when follow-referrals (.setFollowReferrals opt follow-referrals))
    (when tcp-keepalive    (.setUseKeepAlive opt tcp-keepalive))
    (when abandon-timeout (.setAbandonOnTimeout opt abandon-timeout))
    (when synchronous-mode (.setUseSynchronousMode opt synchronous-mode))
    (when capture-stack-trace (.setCaptureConnectStackTrace opt true))
    opt))


(alter-var-root #'clj-ldap.client/connection-options (constantly ldap-connection-options-patch))

