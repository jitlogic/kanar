(ns kanar.cas3-specification-test
  "CAS 3.0 specification compliance test suite."
  (:require
    [clojure.test :refer :all]
    [compojure.route :refer [not-found]]
    [ring.util.response :refer [redirect]]
    [kanar.core :as kc]
    [kanar.core.protocol :as kp]
    [kanar.testutil :refer :all]
    [slingshot.slingshot :refer [try+ throw+]]
    ))



(use-fixtures :each basic-test-fixture)



; Unit Tests

(deftest basic-redirections-test
  (testing "Basic redirection test"
    (let [resp (kanar {:uri "/"})]
      (is (= 302 (:status resp)))
      (is (= "login" (get-rdr resp))))))


(deftest basic-login-logout-test
  (testing "Log in with correct password and then logout"
    (let [r1 (kanar { :uri "/login" :params {:username "test" :password "test"}})]
      (is (= 200 (:status r1)))
      (is (= 1 (count @*treg-atom*)) "Should create exactly one SSO session.")
      (is (not (empty? (get-tgc r1))) "Should return CASTGC cookie.")

      (testing "Logout with no ticket."
        (let [r2 (kanar {:uri "/logout"})]
          (is (= 200 (:status r2)))
          (is (= 1 (count @*treg-atom*)))) "Original CASTGC cookie should still be there.")

      (testing "Logout successfully with existing ticket."
        (let [_ (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})]
          (is (= 0 (count @*treg-atom*)))))))

  (testing "Log in with bad password."
    (let [r1 (kanar { :uri "/login" :params {:username "test" :password "bad"}})]
      (is (= 200 (:status r1)))
      (is (= 0 (count @*treg-atom*)) "Should not create SSO session."))))


(deftest basic-login-with-cas-redirection-test
  (testing "Log in with correct password and CAS service redirection."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.ticket=ST-.*-XXX", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket."))))


(deftest basic-login-with-saml-redirection-test
  (testing "Log in with correct password and SAML service redirection."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :TARGET "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.SAMLart=ST-.*-XXX", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket."))))


(deftest login-with-redirection-and-warn-screen-test
  (testing "Log in with service redirection and warning screen enabled."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :service "https://my-app.com" :warn nil}})
          v (read-string (:body r))]
      (is (= 200 (:status r)) "Should not make redirect.")
      (is  (re-matches #"login.service=https%3A%2F%2Fmy-app.com.*", (:url (:args v)))) ; TODO tutaj ticket nie jest podawany
      (is (= 1 (count @*treg-atom*)) "Should create only ticket granting ticket."))))


(deftest login-check-if-login-form-passes-sso-parameters
  (testing "Open login form and check if service parameter is passed properly."
    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com"}})]
      (is (= 200 (:status r)) "Should return login form")
      (is (re-matches #".*https://my-app.com.*", (:body r))))))


(deftest login-check-if-login-is-bypassed-with-gateway-parameter
  (testing "Try opening login form without credentials and with gateway parameter"
    (let [r (kanar { :uri "/login" :params {:service "https://my-app.com" :gateway nil}})]
      (is (= 302 (:status r)))
      (is (re-matches #"https://my-app.com", (get-rdr r))))))


; TODO opcje renew i gateway
;(deftest login-with-renew-option-test
;  (testing "Log in once and then use renew option and check if login form appears."
;    (let [r (kanar {:uri "/login" :params {:username "test" :password "test"}})]
;      (is (= 1 (count @*treg-atom*)) "New ticket should appear.")
;      (let [l (kanar {:uri "/login" :params {:renew nil}
;                      :cookies {"CASTGC" {:value (get-tgc r)}}})]
;        (is (= 200 (:status l)) "Should ask for login once again")
;        (is (= 0 (count @*treg-atom*)) "Old ticket should be removed."))))
;
;  (testing "Log in once, then use renew to log in for the second time."
;    (let [r (kanar {:uri "/login" :params {:username "t" :password "t" :renew nil}})]
;      (is (= 1 (count @*treg-atom*)) "New ticket should appear.")
;      (let [l (kanar {:uri "/login" :params {:username "t" :password "t" :renew nil}
;                      :cookies {"CASTGC" {:value (get-tgc r)}}})]
;        (is (= 1 (count @*treg-atom*)) "Only new ticket exist (old one removed).")
;        (is (not= (get-tgc r) (get-tgc l))))))
;
;  (testing "Log in once, then use both renew and gateway options."
;    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com" :renew nil :gateway nil}})]
;      (is (= 302 (:status r)) "Should redirect straight to application (no ticket).")
;      (is (= "https://my-app.com" (get-rdr r)) "Should immediately redirect to application."))))


(deftest try-login-to-forbidden-service-test
  (testing "Try logging in to a service that is not allowed."
    (let [r (kanar {:uri "/login" :params {:service "https://verboten.com" :username "t" :password "t"}})]
      (is (= 200 (:status r)) "Should not redirect anywhere.")
      (is (re-matches #".*not allowed.*" (:body r))))))


; TODO zalogować do kilku serwisów (jeden bez jawnego URL, drugi z dwoma jawnymi URL), wylogować, stwierdzić że wylogowanie przyszło;


(deftest basic-login-redirect-logout-check-ticket-cache-test
  (testing "Log in with correct password and CAS service redirection, log out and check if all tickets are remoted."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.ticket=ST-.*-XXX", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
      (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r)}}})
      (is (= 0 (count @*treg-atom*))))))


; TODO test na bezpieczne przenoszenie parametru URL przez formatki zalogowania / przekierowania itd.


(deftest login-and-logout-with-service-parameter
  (testing "Log in and then log out with passing 'service' parameter to logout URL"
    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com" :username "t" :password "t"}})
          l (kanar {:uri "/logout" :params {:service "https://other-app.com"} :cookies (:cookies r)})]
      (is (= 302 (:status l)) "Should return redirect status")
      (is (= "https://other-app.com" (get-rdr l)) "Should redirect to given application."))))


(deftest basic-cas10-validate-test
  (testing "Log in with correct password and validate service ticket using CAS 1.0 protocol"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [sid (re-find (re-matcher #"ST-.*-XXX" (get-rdr r)))]
        (is sid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar { :uri "/validate" :params {:service "https://my-app" :ticket "XXX"}})]
          (is (= "no\n" (:body v)) "Should verify ticket negatively."))
        (let [v (kanar { :uri "/validate" :params {:service "https://my-app" :ticket sid}})]
          (is (= "yes\ntest\n" (:body v)) "Should verify ticket positively."))
        (let [v (kanar { :uri "/validate" :params {:service "https://my-app" :ticket sid}})]
          (is (= "no\n" (:body v)) "Should NOT verify ticket."))))))


(deftest basic-cas20-validate-test
  (testing "Log in with correct password and validate service ticket using CAS 2.0 protocol (no proxies)"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [tid (re-find (re-matcher #"ST-.*-XXX" (get-rdr r)))]
        (is tid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar { :uri "/serviceValidate" :params {:service "https://my-app" :ticket "XXX"}})]
          (is (re-matches #".*INVALID_TICKET_SPEC.*" (:body v))))
        (let [v (kanar { :uri "/serviceValidate" :params {:service "https://my-app" :ticket tid}})]
          (is (re-matches #".*cas:user>test</cas:user.*" (:body v))))
        (let [v (kanar { :uri "/serviceValidate" :params {:service "https://my-app" :ticket tid}})]
          (is (re-matches #".*INVALID_TICKET_SPEC.*" (:body v))))))))


(deftest basic-saml-validate-test
  (testing "Log in with correct password and validate service ticket using SAML protocol"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :TARGET "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [sid (get-samlart r)]
        (is sid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar {:uri "/samlValidate" :params {:TARGET "https://my-app" }
                        :body (kp/saml-validate-request "xxx")})]
          (is (= "Error executing SAML validation.\n" (:body v))))
        (let [v (kanar {:uri "/samlValidate" :params {:TARGET "https://my-app" }
                        :body (kp/saml-validate-request sid)})]
          (is (re-matches #".*saml1:NameIdentifier.test..saml1:NameIdentifier.*" (:body v))))
        (let [v (kanar {:uri "/samlValidate" :params {:TARGET "https://my-app"}
                        :body (kp/saml-validate-request sid)})]
          (is (= "Error executing SAML validation.\n" (:body v))))))))


(deftest test-single-sign-out
  (testing "Log in to a service, check single sign out."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://my-app.com"}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})
            lo [{:url "https://my-app.com", :tid (get-ticket r1)}]]
        (is (= lo @*sso-logouts*))))))


(deftest test-single-sign-out-with-custom-app-urls
  (testing "Log in to a service, check single sign out for application with custom URLs."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://test1.com"}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})
            lo [{:url "http://srv1:8080/test1", :tid (get-ticket r1)}
                {:url "http://srv2:8080/test1", :tid (get-ticket r1)}]]
        (is (= lo @*sso-logouts*))))))


(deftest test-single-sign-out-with-two-services
  (testing "Log in to a service, log in to a second service, sign out from both apps, check if service notified."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://test1.com"}})
            _  (kanar {:uri "/login" :params {:service "https://my-app.com"} :cookies {"CASTGC" {:value (get-tgc r1)}}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})]
        (is (= 3 (count @*sso-logouts*)))))))


(deftest test-single-sign-out-with-verified-service
  (testing "Log in to a service, use service ticket, sign out, check if service notified."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://my-app.com"}})
            _  (kanar {:uri "/validate" :params {:service "https://my-app.com" :ticket (get-ticket r1)}})
            _ (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})]
        (is (= 1 (count @*sso-logouts*)) "Application should be notified.")))))

; TODO test na weryfikacje ticketów CAS1 z opcją renew


; TODO test na weryfikacje ticketów CAS2 z opcją renew


; TODO proxy ticket tests

(deftest test-pass-domain-args
  (testing "Testing if domain argument is passed correctly to login view."
    (let [r1 (kanar {:uri "/login" :params {:dom "test1"}})
          v1 (read-string (:body r1))]
      (is (= :test1 (:dom (:args v1))) "Domain 'test1' should appear in login view.")))
  (testing "Test if domain argument is passed to login success view."
    (let [r1 (kanar {:uri "/login" :params {:dom "test1" :username "test" :password "test"}})
          v1 (read-string (:body r1))]
      (is (= :test1 (:dom (:args v1))))))
  (testing "Test if domain argument is passed to logout view."
    (let [r1 (kanar {:uri "/login" :params {:dom "test1" :username "test" :password "test"}})
          r2 (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})
          v2 (read-string (:body r2))]
      (is (= :test1 (:dom (:args v2)))))))


(deftest test-pass-req-and-tgt
  (testing "Test if HTTP request is passed to login screen rendering fn"
    (let [r1 (kanar {:uri "/login" :params {:dom "test1"}})
          v1 (read-string (:body r1))]
      (is (not-empty (:req (:args v1))) "HTTP request should be passed." )))
  (testing "Test if HTTP request and TGT is passed to login success view."
    (let [r1 (kanar {:uri "/login" :params {:dom "test1" :username "test" :password "test" :service "https://test1.com"}})
          v1 (read-string (:body r1))]
      (is (not-empty (:req (:args v1))))
      (is (not-empty (:tgt (:args v1))))
      )))

