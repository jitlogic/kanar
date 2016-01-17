(ns kanar.core-login-chain-test
  (:require
    [clojure.test :refer :all]
    [kanar.core :as kc]
    [kanar.core.cas :as kcc]
    [kanar.core.saml :as kcs]))

(deftest test-parse-cas-req
  (let [pfn (kc/sso-request-parse-wfn identity kcc/parse-cas-req kcs/parse-saml2-req)]
    (is (= {:protocol :none} (pfn {})))))

(def SAMPLE-SAML-REQ "ZZC7bgIxFER7vsJysxX7AAUpFgaRpAgSiRCQFOm83pvFYF+DrxcIX5/lUURKPzNndIbjk7PsAIGMR5kUaZ4wigorZT2CTH6AkvGoMyTl7E5MmrjGBewboMimRA1M8ZKOkvfyYtDNi27eX+WP4mEgev0vziZEEGI7/eyRGgdhCeFgNHwsZpKvY9yRyLLaKWNT7V1msPQnzqYvkpfwXZoSNqbakDodndbnPZ4btansdnteEyl/dMdtzdk8+Oi1t08GK4O15E1A4RUZEqgcUBq1WE7eZqKX5qK8hUi8rlbz7gIqE0DH68jBVBDe24bktfe1hcslzj7vbnhb56y1hSSuNv6BxF/Q7v6Ks2zU+QU=")

(deftest test-parse-saml-req
  (let [pfn (kc/sso-request-parse-wfn identity kcc/parse-cas-req kcs/parse-saml2-req)
        r (pfn {:params {:SAMLRequest SAMPLE-SAML-REQ, :RelayState "https://some.svc"}})]
    (is (= "https://gmail.com/inbox" (:service-url r)))))


; TODO dokładny test service-lookup-wfn

