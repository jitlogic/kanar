(ns kanar.testutil
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


(defn gen-dsa-keypair [len]
  (let [kg (KeyPairGenerator/getInstance "DSA" "SUN")
        sr (SecureRandom/getInstance "SHA1PRNG" "SUN")]
    (.initialize kg ^Integer len)
    (.generateKeyPair kg)))

