(ns kanar.saml-protocol-test
  (:require
    [clojure.test :refer :all]
    [kanar.core.saml :as kcs]
    [kanar.core.util :as kcu]
    [clojure.data.xml :as xml]
    [kanar.testutil :refer :all])
  (:import (javax.xml.bind DatatypeConverter)
           (java.net URLDecoder)))

(use-fixtures :each basic-test-fixture)

(def REQ "ZZC7bgIxFER7vsJysxX7AAUpFgaRpAgSiRCQFOm83pvFYF+DrxcIX5/lUURKPzNndIbjk7PsAIGMR5kUaZ4wigorZT2CTH6AkvGoMyTl7E5MmrjGBewboMimRA1M8ZKOkvfyYtDNi27eX+WP4mEgev0vziZEEGI7/eyRGgdhCeFgNHwsZpKvY9yRyLLaKWNT7V1msPQnzqYvkpfwXZoSNqbakDodndbnPZ4btansdnteEyl/dMdtzdk8+Oi1t08GK4O15E1A4RUZEqgcUBq1WE7eZqKX5qK8hUi8rlbz7gIqE0DH68jBVBDe24bktfe1hcslzj7vbnhb56y1hSSuNv6BxF/Q7v6Ks2zU+QU=")

(deftest saml2-login-success-sequence
  (let [r (kanar { :uri "/samlLogin" :params {:SAMLRequest REQ :username "test" :password "test"}})]
    (is (not (nil? (get-rdr r))))
    (let [rst (get-samlresp r)
          xst (xml/parse-str (kcs/inflate-str (DatatypeConverter/parseBase64Binary (URLDecoder/decode rst "UTF-8"))))]
      (is (= "test" (-> xst :content second :content second :content first :content first))))))

