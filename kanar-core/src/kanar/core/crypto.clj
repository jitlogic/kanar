(ns kanar.core.crypto
  "Cryptographic utility functions for signing XML and JSON data."
  (:import
    (net.minidev.json JSONObject JSONArray)
    (com.nimbusds.jose JWSAlgorithm JWSObject JWSHeader JWEAlgorithm Payload EncryptionMethod JWEHeader JWEHeader$Builder JWEObject)
    (com.nimbusds.jose.crypto MACSigner MACVerifier RSASSASigner RSASSAVerifier ECDSASigner ECDSAVerifier DirectEncrypter
                              DirectDecrypter RSAEncrypter RSADecrypter AESEncrypter AESDecrypter ECDHEncrypter ECDHDecrypter)
    (java.security.interfaces RSAPrivateKey RSAPublicKey ECPrivateKey ECPublicKey)
    (javax.crypto SecretKey)
    (com.nimbusds.jwt SignedJWT)
    (java.util Collections)
    (org.w3c.dom Document)
    (java.security KeyStore)
    (java.io FileInputStream)
    (javax.xml.bind DatatypeConverter)
    (javax.xml.crypto.dsig XMLSignatureFactory DigestMethod Transform CanonicalizationMethod SignatureMethod XMLSignature)
    (javax.xml.crypto.dsig.spec TransformParameterSpec C14NMethodParameterSpec)
    (javax.xml.crypto.dsig.dom DOMSignContext DOMValidateContext)
    (javax.xml.crypto KeySelector)
    (javax.crypto.spec SecretKeySpec))
  (:require
    [kanar.core.util :as kcu]
    [slingshot.slingshot :refer [try+ throw+]]
    [schema.core :as s]))


(def key-config-schema
  (s/enum
    {:secret s/Str}
    {:keystore s/Str,
     :keypass s/Str,
     :alias s/Str}))


(def JOSE-SIGN-ALGORITHMS
  "JWS Signature algorithms."
  {:HS256 JWSAlgorithm/HS256,                               ; HMAC + SHA-256
   :HS384 JWSAlgorithm/HS384,                               ; HMAC + SHA-384
   :HS512 JWSAlgorithm/HS512,                               ; HMAC + SHA-512
   :RS256 JWSAlgorithm/RS256,                               ; RSASSA-PKCS-v1_5 + SHA-256
   :RS384 JWSAlgorithm/RS384,                               ; RSASSA-PKCS-v1_5 + SHA-384
   :RS512 JWSAlgorithm/RS512,                               ; RSASSA-PKCS-v1_5 + SHA-512
   :ES256 JWSAlgorithm/ES256,                               ; ECDSA + P-256 + SHA-256
   :ES384 JWSAlgorithm/ES384,                               ; ECDSA + P-384 + SHA-384
   :ES512 JWSAlgorithm/ES512,                               ; ECDSA + P-512 + SHA-512
   :PS256 JWSAlgorithm/PS256,                               ; RSASSA-PSS + SHA-256
   :PS384 JWSAlgorithm/PS384,                               ; RSASSA-PSS + SHA-384
   :PS512 JWSAlgorithm/PS512                                ; RSASSA-PSS + SHA-512
   })


(def JOSE-ENC-ALGORITHMS
  {:RSA1_5 JWEAlgorithm/RSA1_5,                             ; RSAES-PKCS1-V1_5
   :RSA_OAEP JWEAlgorithm/RSA_OAEP,                         ; RSAES + OAEP (Optimal Asymmetric Encryption Padding)
   :RSA_OAEP_256 JWEAlgorithm/RSA_OAEP_256                  ; RSAES + OEAP + SHA-256 + MGF1
   :A128KW JWEAlgorithm/A128KW,                             ; AES Key Wrap Algorithm (128bit)
   :A192KW JWEAlgorithm/A192KW,                             ; AES Key Wrap Algorithm (192bit)
   :A256KW JWEAlgorithm/A256KW,                             ; AES Key Wrap Algorithm (256bit)
   :DIR JWEAlgorithm/DIR,                                   ; Direct use of Content Encryption Key
   :ECDH_ES_A128KW JWEAlgorithm/ECDH_ES_A128KW,             ; Elliptic Curve Diffie-Hellman Ephemeral Static + AES-128 key wrap
   :ECDH_ES_A192KW JWEAlgorithm/ECDH_ES_A192KW,             ; Elliptic Curve Diffie-Hellman Ephemeral Static + AES-192 key wrap
   :ECDH_ES_A256KW JWEAlgorithm/ECDH_ES_A256KW,             ; Elliptic Curve Diffie-Hellman Ephemeral Static + AES-256 key wrap
   :ECDH_ES JWEAlgorithm/ECDH_ES,                           ; Elliptic Curve Diffie-Hellman Ephemeral Static + direct key
   :A128GCMKW JWEAlgorithm/A128GCMKW,                       ; AES-128 in Galois/Counter Mode
   :A192GCMKW JWEAlgorithm/A192GCMKW,                       ; AES-192 in Galois/Counter Mode
   :A256GCMKW JWEAlgorithm/A256GCMKW,                       ; AES-256 in Galois/Counter Mode
   :PBES2_HS256_A128KW JWEAlgorithm/PBES2_HS256_A128KW,     ; PBES2 + HMAC SHA-256 + AES-128 Key Wrap
   :PBES2_HS384_A192KW JWEAlgorithm/PBES2_HS384_A192KW,     ; PBES2 + HMAC SHA-256 + AES-128 Key Wrap
   :PBES2_HS512_A256KW JWEAlgorithm/PBES2_HS512_A256KW      ; PBES2 + HMAC SHA-256 + AES-128 Key Wrap
   })


(def JOSE-ENC-METHODS
  {:A128CBC_HS256 EncryptionMethod/A128CBC_HS256,           ; AES_128_CBC_HMAC_SHA_256
   :A192CBC_HS384 EncryptionMethod/A192CBC_HS384,           ; AES_192_CBC_HMAC_SHA_384
   :A256CBC_HS512 EncryptionMethod/A256CBC_HS512,           ; AES_256_CBC_HMAC_SHA_512
   :A128GCM EncryptionMethod/A128GCM,                       ; AES-128 in Galois/Counter Mode (GCM)
   :A192GCM EncryptionMethod/A192GCM,                       ; AES-192 in Galois/Counter Mode (GCM)
   :A256GCM EncryptionMethod/A256GCM,                       ; AES-256 in Galois/Counter Mode (GCM)
   })


(def jose-config-schema
  "Configuration for JOSE signing and encryption"
  {:sign-alg       (apply s/enum (keys JOSE-SIGN-ALGORITHMS)) ; Signature algorithm
   :sign-key key-config-schema                                ; Signature key
   :enc-alg        (s/maybe (apply s/enum (keys JOSE-ENC-ALGORITHMS))) ; Encryption algorithms
   :enc-method     (s/maybe (apply s/enum (keys JOSE-ENC-METHODS)))    ; Encryption method
   :enc-key        key-config-schema                        ; Signature key
   })


(defn read-keys [{:keys [secret keystore keypass alias]}]
  (cond
    secret
    (let [k (SecretKeySpec. (DatatypeConverter/parseBase64Binary secret) "AES")] {:prv-key k :pub-key k})
    keystore
    (with-open [f (FileInputStream. ^String keystore)]
      (let [ks (KeyStore/getInstance (KeyStore/getDefaultType))]
        (.load ks f (.toCharArray keypass))
        {:prv-key (.getKey ks alias (.toCharArray keypass))
         :pub-key (.getPublicKey (.getCertificate ks alias))}))
    :else nil))


; TODO parametrize transform and signature parameters
(defn xml-sign [^Document doc kp]
  (let [sc (DOMSignContext. ^RSAPrivateKey (:prv-key kp) (.getDocumentElement doc))
        xf (XMLSignatureFactory/getInstance "DOM")
        dm (.newDigestMethod xf DigestMethod/SHA1 nil)
        ^TransformParameterSpec tp nil
        tr (.newTransform xf Transform/ENVELOPED tp)
        rf (.newReference xf "" dm (Collections/singletonList tr) nil nil)
        ^C14NMethodParameterSpec mp nil
        cm (.newCanonicalizationMethod xf CanonicalizationMethod/INCLUSIVE mp)
        sm (.newSignatureMethod xf SignatureMethod/RSA_SHA1 nil)
        si (.newSignedInfo xf cm sm (Collections/singletonList rf))
        kf (.getKeyInfoFactory xf)
        kv (.newKeyValue kf (:pub-key kp))
        ki (.newKeyInfo kf (Collections/singletonList kv))
        xs (.newXMLSignature xf si ki)]
    (.sign xs sc)
    doc))


(defn xml-validate [^Document doc, kp]
  (let [nl (.getElementsByTagNameNS doc XMLSignature/XMLNS "Signature")]
    (when (= 0 (.getLength nl))
      (throw+ {:type :xml-validation :msg "Cannot find signature element"}))
    (let [vc (DOMValidateContext. (KeySelector/singletonKeySelector (:pub-key kp)) (.item nl 0))
          xf (XMLSignatureFactory/getInstance "DOM")
          sg (.unmarshalXMLSignature xf vc)
          cv (.validate sg vc)]
      (when-not (.validate sg vc)
        (throw+ {:type :xml-validation :msg "Cannot validate signature."})))))


(defn- jose-signer [{:keys [sign-alg]} sign-key]
  (case (.substring (name sign-alg) 0 2)
    "HS" (MACSigner. ^SecretKey sign-key)
    "PS" (RSASSASigner. ^RSAPrivateKey sign-key)
    "RS" (RSASSASigner. ^RSAPrivateKey sign-key)
    "EC" (ECDSASigner. ^ECPrivateKey sign-key)))


(defn- jose-verifier [{:keys [sign-alg]} verify-key]
  (case (.substring (name sign-alg) 0 2)
    "HS" (MACVerifier. ^SecretKey verify-key)
    "PS" (RSASSAVerifier. ^RSAPublicKey verify-key)
    "RS" (RSASSAVerifier. ^RSAPublicKey verify-key)
    "EC" (ECDSAVerifier. ^ECPublicKey verify-key)))


(defn jose-sign [^JSONObject json-obj {:keys [sign-alg] :as jose-cfg} sign-key]
  (let [signer (jose-signer jose-cfg sign-key)
        jws-obj (JWSObject. (JWSHeader. ^JWSAlgorithm (JOSE-SIGN-ALGORITHMS sign-alg)) (Payload. json-obj))]
    (.sign jws-obj signer)
    jws-obj))


(defn jose-verify [^String jws-str jose-cfg sign-key]
  (let [verifier (jose-verifier jose-cfg sign-key)
        jws-obj (JWSObject/parse jws-str)]
    (if (.verify jws-obj verifier)
      (.toJSONObject (.getPayload jws-obj)))))


(defn- jose-encrypter [{:keys [enc-alg]} enc-key]
  (cond
    (= enc-alg :DIR) (DirectEncrypter. ^SecretKey enc-key)
    (re-matches #"^RSA.*" (name enc-alg)) (RSAEncrypter. ^RSAPublicKey enc-key)
    (re-matches #"^A.*" (name enc-alg)) (AESEncrypter. ^SecretKey enc-key)
    (re-matches #"^EC.*" (name enc-alg)) (ECDHEncrypter. ^ECPublicKey enc-key)
    ))


(defn- jose-decrypter [{:keys [enc-alg]} dec-key]
  (cond
    (= enc-alg :DIR) (DirectDecrypter. ^SecretKey dec-key)
    (re-matches #"^RSA.*" (name enc-alg)) (RSADecrypter. ^RSAPrivateKey dec-key)
    (re-matches #"^A.*" (name enc-alg)) (AESDecrypter. ^SecretKey dec-key)
    (re-matches #"^EC.*" (name enc-alg)) (ECDHDecrypter. ^ECPrivateKey dec-key)
    ))


(defn jose-encrypt [^SignedJWT jwt-obj {:keys [enc-alg enc-method] :as jose-cfg} enc-key]
  (let [encrypter (jose-encrypter jose-cfg enc-key)
        jwe-hb (JWEHeader$Builder. ^JWEAlgorithm (JOSE-ENC-ALGORITHMS enc-alg) ^EncryptionMethod (JOSE-ENC-METHODS enc-method))
        jwe-hdr (-> jwe-hb (.contentType "JWT") .build)
        jwe-obj (JWEObject. jwe-hdr (Payload. jwt-obj))]
    (.encrypt jwe-obj encrypter)
    jwe-obj))


(defn jose-decrypt [^String jwe-str jose-cfg dec-key]
  (let [jwe-obj (JWEObject/parse jwe-str)
        jwe-dec (jose-decrypter jose-cfg dec-key)]
    (.decrypt jwe-obj jwe-dec)
    (.toSignedJWT (.getPayload jwe-obj))))


(defn jwt-encode-fn [{:keys [sign-key enc-key] :as jose-cfg}]
  "Creates JWT encoding function (based on JOSE configuration)"
  (let [sgn-kp (read-keys sign-key)
        enc-kp (read-keys enc-key)]
    (fn [obj]
      (let [json-obj (kcu/to-json-object obj)
            jws-obj (jose-sign jose-cfg json-obj (:prv-key sgn-kp))
            jwt-obj (if enc-kp (jose-encrypt jws-obj jose-cfg (:pub-key enc-kp)) jws-obj)]
        (.serialize jwt-obj)))
    ))


(defn jwt-decode-fn [{:keys [sign-key enc-key] :as jose-cfg}]
  "Creates JWT decoding function (based on JOSE configuration)"
  (let [sgn-kp (read-keys sign-key)
        enc-kp (read-keys enc-key)]
    (fn [s]
      (let [jws-obj (jose-decrypt s jose-cfg (:prv-key enc-kp))
            json-obj (jose-verify jws-obj jose-cfg (:pub-key sgn-kp))]
        (kcu/from-json-object json-obj)))
    ))


