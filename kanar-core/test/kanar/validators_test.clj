(ns kanar.validators-test
  (:require
    [clojure.test :refer :all]
    [kanar.core.sec :as kcs]))


(deftest test-validate-empty-login-request
  (testing "Validating login requests"
    (is (= {:request-method :get, :params {}, :headers {}, :cookies {}, :body nil}
           (kcs/validate-and-filter-req
             {:request-method :get, :params {:some "param"}, :headers {"X" "Y"}, :cookies {"A" "B"} :obsolete "val"},
             kcs/cas-login-vd))))

  (testing "Validating login request with TGC cookie"
    (is (= {:request-method :get, :params {}, :headers {}, :body nil,
            :cookies {"CASTGC" "TGC-773-7zKxIm2us6JFnYi97nSI4V1AjLZGVaGSZQoq5IQGbf9QIVhxTHbdPsxa1x78ilz8-S_VR.1"}}
           (kcs/validate-and-filter-req
             {:request-method :get, :cookies {"CASTGC" "TGC-773-7zKxIm2us6JFnYi97nSI4V1AjLZGVaGSZQoq5IQGbf9QIVhxTHbdPsxa1x78ilz8-S_VR.1"}}
             kcs/cas-login-vd))))

  (testing "Validating request with bad TGC."
    (is (thrown? Exception (kcs/validate-and-filter-req
                             {:request-method :get, :cookies {"CASTGC" "TGC-773-7zKxIm2us6JFnYi97nSI4V1AjLZGVaGSZQoq5IQGbf9QIVhxTHbdPsxa1x78ilz8-SVR*"}}
                             kcs/cas-login-vd))))

  (testing "Validating request with missing fields."
    (is (thrown? Exception (kcs/validate-and-filter-req
                             {:request-method :post} kcs/cas-login-vd))))

  (testing "Validating login request with proper parameters"
    (is (= {:request-method :post, :params {:username "juzer" :password "passlord"}, :headers {}, :cookies {}, :body nil}
           (kcs/validate-and-filter-req
             {:request-method :post :params {:username "juzer" :password "passlord"}}
             kcs/cas-login-vd))))

  (testing "Validating and trimming username field"
    (is (= {:request-method :post, :params {:username "juzer" :password "passlord"}, :headers {}, :cookies {}, :body nil}
           (kcs/validate-and-filter-req
             {:request-method :post :params {:username " juzer " :password "passlord"}}
             kcs/cas-login-vd)))))


(deftest test-merge-vd
  (testing "Add sample field to login screen and check if it works."
    (let [evdef (kcs/merge-vd kcs/cas-login-vd {:post {:params {:otp {:re ".*" :msg "A"}}}})]
      (println evdef)
      (is (= {:re ".*" :msg "A"} (get-in evdef [:post :params :otp]))))))


(deftest test-validate-saml-request
  (testing "Test validation of SAML tickets"
    (let [xml1 (slurp "test/testSamlReq1.xml")
          vfn (kcs/new-saml-vfn)]
      (is (= xml1 (vfn xml1)))
      (is (thrown? Exception (vfn (slurp "test/testSamlReq2.xml")))))))

