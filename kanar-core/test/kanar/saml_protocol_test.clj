(ns kanar.saml-protocol-test
  (:require
    [clojure.test :refer :all]
    [kanar.testutil :refer :all]))

(use-fixtures :each basic-test-fixture)

(def REQ "ZZC7bgIxFER7vsJysxX7AAUpFgaRpAgSiRCQFOm83pvFYF+DrxcIX5/lUURKPzNndIbjk7PsAIGMR5kUaZ4wigorZT2CTH6AkvGoMyTl7E5MmrjGBewboMimRA1M8ZKOkvfyYtDNi27eX+WP4mEgev0vziZEEGI7/eyRGgdhCeFgNHwsZpKvY9yRyLLaKWNT7V1msPQnzqYvkpfwXZoSNqbakDodndbnPZ4btansdnteEyl/dMdtzdk8+Oi1t08GK4O15E1A4RUZEqgcUBq1WE7eZqKX5qK8hUi8rlbz7gIqE0DH68jBVBDe24bktfe1hcslzj7vbnhb56y1hSSuNv6BxF/Q7v6Ks2zU+QU=")

(deftest saml2-login-success-sequence
  (let [r (kanar { :uri "/samlLogin" :params {:SAMLRequest REQ :username "test" :password "test" :RelayState "asdasdasd"}})]
    (is (not (nil? r)))
    (let [rst (:body r)]
      (println rst))))

