(ns kanar.core.otp
  (:require
    [kanar.core.util :as kcu]
    [kanar.core.crypto :as kcc]
    [kanar.core :as kc]
    [kanar.core.ticket :as kct]
    [clojure.string :as cs]))


(defn otp-verify [otp pin secret tolerance otp-length]
  (when (and otp pin secret tolerance)
    (let [t0 (long (/ (kcu/cur-time) 10000))]
      (first
        (for [dt (range (- 0 tolerance) tolerance)
              :let [sum (kcc/md5 (str (+ t0 dt) secret pin))]
              :when (= otp (.substring sum 0 otp-length))]
          true)))))


(defn otp-verify-wfn
  ([conf otp-enable-fn user-fn used-tokens lockouts]
    (otp-verify-wfn identity conf otp-enable-fn user-fn used-tokens lockouts))
  ([f {:keys [enabled tolerance lockout-time max-attempts otp-length]
       :or   {tolerance 90, lockout-time 1800, max-attempts 3, otp-length 6}}
    otp-enable-fn user-fn used-tokens lockouts]
   (let [lockout-time (* 1000 lockout-time)]
     (fn [{{:keys [username token]} :credentials :as req}]
       (if (and enabled (otp-enable-fn req))
         (let [req (assoc req :otp-authenticated true)
               token (if token (cs/trim (cs/lower-case token)) "")
               {:keys [initial_key pin login] :as user} (user-fn (cs/trim (cs/upper-case username)))
               {:keys [until attempts] :or {attempts 0}} (when login (kct/get-obj lockouts login))
               match (otp-verify token pin initial_key (quot tolerance 10) otp-length)
               used (kct/get-obj used-tokens token)]
           (cond
             (empty? token)
             (kc/login-failed req "Token is required.")
             used
             (kc/login-failed req "Token already used.")
             (nil? user)
             (kc/login-failed req "No token configured.")
             (and attempts (>= attempts max-attempts) until (> until (kcu/cur-time)))
             (kc/login-failed req "Too many OTP attempts.")
             match
             (do
               (kct/del-obj lockouts login)
               (kct/put-obj used-tokens {:tid token, :timeout (* 1000 tolerance)})
               (f req))
             :else
             (do
               (kct/put-obj lockouts {:tid      login, :until (+ (kcu/cur-time lockout-time)),
                                      :attempts (inc attempts), :timeout lockout-time})
               (kc/login-failed req "Invalid OTP token."))))
         (f req))))))


; Returned values
; 0 - valid token
; 1 - invalid token
; 2 - invalid or missing parameters
; 3 - no such user (token not initialized ?)
; 4 - insiffucient privileges
; 5 - temporary lockout
(defn otp-check-wfn [{:keys [tolerance otp-length otp-check-clients max-attempts]
                      :or {tolerance 90, otp-length 6, max-attempts 3}} user-fn lockouts]
  (let [addrs (set otp-check-clients)]
    (fn [{{:keys [username token]} :params :keys [remote-addr] :as req}]
      (let [token (if token (cs/trim (cs/lower-case token)) "")
            username (if username (cs/trim (cs/upper-case username)) "")
            {:keys [initial_key pin login] :as user} (user-fn username)
            {:keys [until attempts] :or {attempts 0}} (when login (kct/get-obj lockouts login))
            match (otp-verify token pin initial_key (quot tolerance 10) otp-length)
            ]
        {:req req,
         :body (cond
                 (and (not (empty? addrs)) (not (contains? addrs remote-addr))) "4"
                 (or (empty? token) (empty? username)) "2"
                 (nil? (re-matches #"[0-9a-f]{6}" token)) "2"
                 (nil? (re-matches #"[0-9A-Z]{6}" username)) "2"
                 (nil? user) "3"
                 (not match) "1"
                 (and attempts (>= attempts max-attempts) until (> until (kcu/cur-time))) "5"
                 :else "0")}))))

