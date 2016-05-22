(ns kanar.ldap-test
  (:require
    [clojure.test :refer :all]
    [kanar.ldap :as kl]
    [slingshot.slingshot :refer [try+ throw+]])
  (:import
    (com.unboundid.ldap.listener InMemoryDirectoryServerConfig InMemoryDirectoryServer)))


(def BASE-DN "o=kanar,dc=io")
(def LDAP-CONF {:base-dn "ou=users,o=kanar,dc=io" :user-query "(cn=%s)" :user-re #".*"
                :host {:address "127.0.0.1" :port 33389}})

;(defn ldap-server []
;  (doto
;    (InMemoryDirectoryServer. (InMemoryDirectoryServerConfig. (into-array String [BASE-DN])))
;    (.importFromLDIF srvr true "testdata/ldap/basic-test.ldif")))
;

;(deftest test-simple-ldap-search-authenticator
;  (let [authfn (kl/ldap-lookup-fn (ldap-server) LDAP-CONF)]
;    (is (= {:dn " cn=test1, ou=users, o=kanar, dc=io", :id " test1"}) (authfn {:id "test1"} nil))
;    (try+
;      (authfn {:id "nobody"} nil)
;      (is false "Should throw login-failed exception !")
;      (catch [:type :login-failed] _ (is true "Login failed")))))


; TODO testowanie ról

; TODO test na konto bez ról;

; TODO test na konto z jedną rolą;

; TODO test na konto z kilkoma rolami;