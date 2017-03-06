(ns kanar.ldap
  "LDAP authentication and principal resolve."
  (:require
    [clj-ldap.client :as ldap]
    [kanar.core.util :as ku]
    [taoensso.timbre :as log]
    [kanar.core :as kc])
  (:import (com.unboundid.ldap.sdk LDAPConnectionOptions)
           (java.text SimpleDateFormat)))


(def LDAP_TSTAMP_RE #"([0-9]{14})Z")


(def edir-err-defs
  [[#"NDS error.*197.*"                          {:type :login-failed :msg "Account locked."}]
   [#"NDS error.*215.*"                          {:type :chpass-failed :msg "Password previously used."}]
   [#"NDS error.*220.*",                         {:type :login-failed :msg "Account expired."}]
   [#"NDS error: bad password ..222.",           {:type :login-failed :msg "Login failed."}]
   [#"NDS error.*222.*"                          {:type :login-failed :msg "Password expired."}]
   [#"NDS error: failed authentication ..669."   {:type :login-failed :msg "Login failed."}]
   [#"NDS error.*669.*"                          {:type :chpass-failed :msg "Wrong password."}]
   [#"NDS error: ds locked.*663.*"               {:type :login-failed :msg "LDAP unavailable."}]
   [#"NDS error: duplicate password.* ..215."    {:type :chpass-failed :msg "Duplicate password."}]
   [#".*"                                        {:type :login-failed :msg "Login failed." }]])


(def msad-err-defs
  [[#".*error, data 530.*"                       {:type :login-failed :msg "Not permitted at this time."}]
   [#".*error, data 532.*"                       {:type :login-failed :msg "Password expired."}]
   [#".*error, data 533.*"                       {:type :login-failed :msg "Account disabled."}]
   [#".*error, data 701.*"                       {:type :login-failed :msg "Account expired."}]
   [#".*error, data 701.*"                       {:type :login-failed :msg "Password must be reset."}]
   [#".*error, data 775.*"                       {:type :login-failed :msg "Account locked."}]
   [#".*"                                        {:type :login-failed :msg "Login failed." }]])


(defn dispatch-error
  ([err-defs e]
    (dispatch-error err-defs e "Login failed."))
  ([err-defs e def-msg]
   (or
     (first
       (filter (complement nil?)
               (for [[rex exc] err-defs]
                 (cond
                   (map? e) e
                   (nil? (.getMessage e)) {:error (ku/error-with-trace e)}
                   (re-matches rex (.getMessage e)) {:error (:msg exc)}
                   :else nil))))
     {:error def-msg, :e e})))


(defn ldap-bind [ldap-conf err-defs dn password]
  (try
    (let [conn (ldap/connect (assoc ldap-conf :num-connections 1 :bind-dn dn :password password))]
      (log/debug "KLDAP-D002: ldap-bind: Successfully bound as " dn)
      (.close conn)
      {:dn dn})
    (catch Exception e
      (log/debug "KLDAP-D003: ldap-bind: Error binding user account " dn ":" (ku/error-with-trace e))
      (dispatch-error err-defs e))))


(defn user-connect [ldap-conf err-defs dn password]
  (try
    (ldap/connect (assoc ldap-conf :num-connections 1 :bind-dn dn :password password))
    (catch Exception e
      (log/warn "KLDAP-W001: user-connect Error connecting as user" dn ":" e)
      (dispatch-error err-defs e))))


(def ^:private DEFAULT_USER_RE #"[a-zA-Z0-9_\-\.]+")


; TODO test na defaultowe wartości (bo chyba nie działają)
; TODO przenieść tutaj pobieranie extra atrybutów za jednym zamachem (dodatkowy argument z listą atrybutów)
(defn ldap-lookup-dn
  ([conn err-defs conf id]
    (ldap-lookup-dn conn err-defs conf id []))
  ([conn err-defs {:keys [base-dn user-query user-re login-tmout not-found-msg id-attr] :or {id-attr :cn}} id x-attrs]
   (try
     (if (and (not (empty? id)) (re-matches (or user-re DEFAULT_USER_RE) id))
       (let [query (.replaceAll user-query "@@USER@@" id)
             base-dns (if (vector? base-dn) base-dn [base-dn])
             attrs (into [:dn id-attr] x-attrs)
             entries (flatten (for [b base-dns
                                    :let [r (ldap/search conn b {:attributes attrs :filter query})]
                                    :when (not (nil? r))] r))
             rec (first entries)]
         (log/debug "KLDAP-D004: ldap-lookup-id query:" query "results:" (vec entries))
         (cond
           (empty? entries)
           (do
             (if login-tmout (Thread/sleep login-tmout))
             (log/warn "KLDAP-W002: ldap-lookup-id: user not found" id)
             {:error (or not-found-msg "Login failed.")})
           (not (empty? (next entries)))
           (do
             (log/error "KLDAP-E002: ldap-lookup-dn: Error in users database: query=" query "base-dn=" base-dn "found records:" entries)
             {:error "Error in users database. Please contact administrator."})
           :else (into {:dn (:dn rec), :id (id-attr rec)} (select-keys rec x-attrs))))
       (do
         (if login-tmout (Thread/sleep login-tmout))
         {:error "Invalid user name."}))
     (catch Exception e
       (log/warn "KLDAP-E003: ldap-lookup-dn: Error searching for user" id ":" (ku/error-with-trace e))
       (dispatch-error err-defs e)))))


(defn ldap-auth-wfn
  ([conn ldap-conf err-defs]
    (ldap-auth-wfn identity conn ldap-conf err-defs))
  ([f conn ldap-conf err-defs]
    (fn [{{:keys [username password]} :credentials :as req}]
      (let [{:keys [dn id] lkup-error :error} (ldap-lookup-dn conn err-defs ldap-conf username)
            req (assoc req :principal {:id id :dn dn :attributes {}})
            {bind-error :error} (when dn (ldap-bind ldap-conf err-defs dn password))
            error (or lkup-error bind-error)]
        (if error (kc/login-failed req error) (f req))))))


(defn ldap-lookup-wfn
  ([conn ldap-conf err-defs]
    (ldap-lookup-wfn identity conn ldap-conf err-defs))
  ([f conn ldap-conf err-defs]
    (fn [{{id :id :as princ} :principal :as req}]
      (let [{:keys [dn id error]} (ldap-lookup-dn conn err-defs ldap-conf id)
            req (assoc req :principal (merge {} princ {:id id :dn dn}))]
        (if error (kc/login-failed req error) (f req))))))


(defn ldap-otp-lookup-fn [conn err-defs ldap-conf login-attr key-attr pin-attr]
  (fn [username]
    (let [{:keys [dn error]} (ldap-lookup-dn conn err-defs ldap-conf username)]
      (if-not error
        (when-let [rec (ldap/get conn dn [login-attr key-attr pin-attr])]
          {:login (login-attr rec), :initial_key (key-attr rec), :pin (pin-attr rec)})))))


(defn precompile-attr-map [attr-map]
  (into
    {}
    (for [[k v] attr-map]
      (cond
        (list? v)                             {k (eval `(fn [~'e] ~v))}
        (and (vector? v) (list? (first v)))   {k (vec (cons (eval `(fn [~'e] ~(first v))) (rest v)))}
        :else                                 {k v}))))


(defn from-msad-time [t]
  "Convert timestamp from Microsoft FILETIME to Java System/currentTimeMillis."
  (/ (- t 116444736000000000) 10000))


(defn to-msad-time [t]
  "Convert timestamp from Java System/currentTimeMillis to Microsoft FILETIME. "
  (* (+ t 116444736000000000) 10000))


(def MSAD_ACCOUNT_DISABLE 0x0002)

(def MSAD_LOCKOUT 0x0010)

(defn msad-expiry-wfn
  ([] (msad-expiry-wfn identity))
  ([f]
    (fn [{{{:keys [userAccountControl accountExpires]} :attributes} :principal :as req}]
      (let [uac (when userAccountControl (Integer/parseInt userAccountControl))
            aet (when accountExpires (Long/parseLong accountExpires))]
        (cond
          (and uac (not= 0 (bit-and uac (bit-or MSAD_ACCOUNT_DISABLE MSAD_LOCKOUT))))
            (kc/login-failed req "Account disabled.")
          (and aet (> aet 0) (< (from-msad-time aet) (ku/cur-time)))
            (kc/login-failed req "Account expired.")
          :else
            (f req))))))


(defn ldap-attr-wfn
  ([conn attr-fetch attr-map]
    (ldap-attr-wfn identity conn attr-fetch attr-map))
  ([f conn attr-fetch attr-map]
    (fn [{{:keys [dn attributes]} :principal :as req}]
      (let [entry (ldap/get conn dn attr-fetch)]
        (if entry
          (let [na (for [[k v] attr-map
                         :let [rslt (if (vector? v) (or ((first v) k entry) (second v)) (v entry))]
                         :when rslt] {k rslt})]
            (f (assoc-in req [:principal :attributes] (into (or attributes {}) na))))
          (kc/login-failed req "Cannot obtain user data."))))))


(defn ldap-roles-wfn
  ([conn attr to-attr regex]
    (ldap-roles-wfn identity conn attr to-attr regex))
  ([f conn attr to-attr regex]
    (fn [{{:keys [dn]} :principal :as req}]
      (let [entry (ldap/get conn dn [attr])
            attrs (if (string? (attr entry)) [(attr entry)] (attr entry))]
        (if entry
          (f (assoc-in req [:principal :attributes to-attr]
                       (filterv not-empty (for [g attrs] (second (re-find regex g))))))
          (kc/login-failed req "Cannot obtain user roles."))))))



(defn- expand-roles-recursive [conn g-attr in-grps rslt-grps]
  in-grps)



(defn ldap-recursive-roles-wfn
  ([conn u-attr g-attr to-attr regex]
    (ldap-recursive-roles-wfn identity conn u-attr g-attr to-attr regex))
  ([f conn u-attr g-attr to-attr regex]
    (fn [{{:keys [dn]} :principal :as req}]
       (let [entry (ldap/get conn dn [u-attr])
             attrs (if (string? (u-attr entry)) [(u-attr entry)] (u-attr entry))
             attrs (into [] (expand-roles-recursive conn g-attr (set attrs) #{}))]
         (if entry
           (f (assoc-in req [:principal :attributes to-attr]
                        (filterv not-empty (for [g attrs] (second (re-find regex g))))))
           (kc/login-failed req "Cannot obtain user roles."))))))


; TODO recursive LDAP group resolver

(defn parse-dt [s]
  "Parses LDAP datetime string."
  (when s
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

