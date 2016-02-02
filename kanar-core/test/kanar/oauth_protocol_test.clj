(ns kanar.oauth-protocol-test
  (:require
    [clojure.test :refer :all]
    [kanar.testutil :refer :all]
    [kanar.core.oauth :as kco]))


(use-fixtures :each basic-test-fixture)


(deftest parse-response-type-param-test
  (is (= nil (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS nil)))
  (is (= nil (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS 123)))
  (is (= #{} (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS "")))
  (is (= #{} (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS "qpa")))
  (is (= #{:code} (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS "code")))
  (is (= #{:id_token} (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS "id_token")))
  (is (= #{:code  :id_token} (kco/parse-kw-params kco/RESPONSE-TYPE-PARAMS "CODE  id_token"))))


(deftest basic-oauth-login-token-renew-test
  (testing "Log in with correct password and then logout"
    (let [r1 (kanar {:uri    "/authorize",
                     :params {:response_type "code", :scope "openid", :client_id "testcli",
                              :state         "teststate", :redirect_uri "https://myapp.com",
                              :username      "test" :password "test"}})
          {:keys [code state]} (parse-rdr r1)]
      (is (matches #"ST-.*-XXX" code))
      (is (= "teststate" state))
      (is (= 302 (:status r1)))
      (let [r2 (kanar {:uri "/token", :params {:code code, :redirect_uri "https://myapp.com", :grant_type "authorization_code"}})]
        (is (= 200 (:status r2)))
        (let [jr2 (parse-json (:body r2))]
          (is (= "Bearer" (:token_type jr2)))
          ; obtain access token
          (let [token (jwt-decode (:id_token jr2))]
            (is (integer? (:exp token)))
            (is (integer? (:iat token)))
            (is (integer? (:auth_time token)))
            (is (= "test" (:sub token)))
            (is (= "all" (:aud token))))
          ; refresh token
          (let [r3 (kanar {:uri "/token" :params {:refresh_token (:refresh_token jr2), :grant_type "refresh_token"}})
                jr3 (parse-json (:body r3))]
            (is (= 200 (:status r3)))
            (is (= (:access_token jr3) (:access_token jr2))))
          ; user info
          (let [r4 (kanar {:uri "/userinfo" :headers {"Authorization" {:value (str "Bearer " (:access_token jr2))}}})
                jr4 (parse-json (:body r4))]
            (is (= 200 (:status r4)))
            (is (= "test" (:sub jr4))))
          )))))

