(ns kanar.oauth-protocol-test
  (:require
    [clojure.test :refer :all]
    [kanar.core.oauth :as kco]))


(deftest parse-response-type-param-test
  (is (= nil (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS nil)))
  (is (= nil (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS 123)))
  (is (= #{} (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS "")))
  (is (= #{} (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS "qpa")))
  (is (= #{:code} (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS "code")))
  (is (= #{:id_token} (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS "id_token")))
  (is (= #{:code  :id_token} (kco/parse-kw-param kco/RESPONSE-TYPE-PARAMS "CODE  id_token"))))



