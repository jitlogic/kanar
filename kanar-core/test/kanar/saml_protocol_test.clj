(ns kanar.saml-protocol-test
  (:require
    [clojure.test :refer :all]
    [kanar.testutil :refer :all]
    [kanar.core.util :as ku])
  (:import (java.util.zip Deflater)
           (java.io ByteArrayOutputStream)))

(use-fixtures :each basic-test-fixture)

(def REQ "ZZC7bgIxFER7vsJysxX7AAUpFgaRpAgSiRCQFOm83pvFYF+DrxcIX5/lUURKPzNndIbjk7PsAIGMR5kUaZ4wigorZT2CTH6AkvGoMyTl7E5MmrjGBewboMimRA1M8ZKOkvfyYtDNi27eX+WP4mEgev0vziZEEGI7/eyRGgdhCeFgNHwsZpKvY9yRyLLaKWNT7V1msPQnzqYvkpfwXZoSNqbakDodndbnPZ4btansdnteEyl/dMdtzdk8+Oi1t08GK4O15E1A4RUZEqgcUBq1WE7eZqKX5qK8hUi8rlbz7gIqE0DH68jBVBDe24bktfe1hcslzj7vbnhb56y1hSSuNv6BxF/Q7v6Ks2zU+QU=")

(defn saml2-raw-req [{:keys [id provider url issuer]}]
  [:AuthnRequest {:ID                          (ku/random-string 32), :Version "2.0" :IssueInstant (ku/xml-time),
                  :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  :ProviderName                provider
                  :AssertionConsumerServiceURL url}
   [:Issuer issuer]
   [:NameIDPolicy {:AllowCreate :true, :Format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}]])


(defn deflate-str [data]
  (let [df (Deflater. 9 true)
        buf (byte-array 65536)]
    (.setInput df (.getBytes data))
    (.finish df)
    (let [len (.deflate df buf)
          is (ByteArrayOutputStream.)]
      (.write is buf 0 len)
      (.toByteArray is))))



(deftest saml2-login-success-sequence
  (let [r (kanar { :uri "/samlLogin" :params {:SAMLRequest REQ :username "test" :password "test" :RelayState "asdasdasd"}})]
    (is (not (nil? r)))
    (let [rst (:body r)]
      (println rst))))

