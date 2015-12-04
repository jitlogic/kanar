(ns kanar.core.fileauth
  "File based authentication plugin. This is useful for test and development, not really for production."
  (:require
    [taoensso.timbre :as log]
    [kanar.core.util :as ku])
  (:import
    (java.io File)
    (java.security MessageDigest)))


(def ^:private sha2-format (apply str (for [_ (range 32)] "%02x")))

(defn- sha2 [^String s]
  (let [d (.digest (MessageDigest/getInstance "SHA-256") (.getBytes s))]
    (String/format sha2-format (to-array (for [b d] b)))))

; TODO parametrize salt length
(defn check-password [pwd-hash password & {:keys [salt-length]} ]
  (cond
    (re-matches #"SHA:[0-9a-f]{64}" pwd-hash)
      (= (.substring pwd-hash 4) (sha2 password))
    (re-matches #"SHS:[0-9a-f]{64}" pwd-hash)
      (some #(= (.substring pwd-hash 4) (sha2 (str password %))) (range (or salt-length 2048)))
    :else
      (= pwd-hash password)))


(defn file-auth-fn [fdb-state]
  "File-based user authenticator. "
  (fn [_ {{username :username password :password} :params}]
    (let [princ (get @fdb-state username)]
      (log/trace "Principal found: " princ)
      (if (or (nil? princ) (not (check-password (:password princ) password)))
        (ku/login-failed "Invalid username or password."))
      (ku/merge-principals (or princ {}) (dissoc princ :password)))))


; TODO enhance principal attributes instead of overwriting it (with option to switch between overwrite/enhance modes);
(defn file-lookup-fn [fdb-state & {:keys [optional]}]
  (fn [{:keys [id] :as princ} _]
    (let [urec (get @fdb-state id)]
      (if-not urec
        (if optional
          princ
          (ku/login-failed "Invalid username or password.")))
      (ku/merge-principals (or princ {}) (dissoc urec :password)))))


(defn file-auth-load-file [^String path]
  (let [users (read-string (slurp path))]
    ; TODO sanity check here
    (into {} (for [u users :when (:id u)] {(:id u) u}))))


(defn file-auth-reload-task [fdb-state ^String path]
  "Starts automated user file monitoring and reloading task."
  (future
    (log/info "Starting user file reloading task.")
    (let [f (File. path)]
      (loop [tstamp 0]
        (let [t (.lastModified f)]
          (when-not (= t tstamp)
            (log/info "Reloading user file: " path)
            (reset! fdb-state (file-auth-load-file path)))
          (Thread/sleep 5000)
          (recur t))))))

