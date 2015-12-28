(ns kanar.ticket-registry-test
  "Ticket registry unit tests."
  (:require
    [clojure.test :refer :all]
    [kanar.core.ticket :as kt]
    [kanar.core.util :as ku]
    [clojure.test.check :as tc]
    [clojure.test.check.generators :as gen])
  (:import (java.util HashMap)))

(def ^:dynamic *treg-atom* (atom {}))
(def ^:dynamic *atr* (kt/atom-ticket-registry *treg-atom*))

(def ^:dynamic *treg-map* (HashMap.))
(def ^:dynamic *mtr* (kt/map-ticket-registry *treg-map*))

(def ^:dynamic *cur-time* (atom 0))

(defn TT [t]
  "TT stands for 'Time Travel'. "
  (reset! *cur-time* t))

(defn ticket-registry-test-fixture [f]
  (reset! *treg-atom* {})
  (.clear *treg-map*)
  (reset! *cur-time* 0)
  (with-redefs [ku/cur-time (fn [] @*cur-time*)] (f)))


(use-fixtures :each ticket-registry-test-fixture)

(defn  grant-some-session-ticket-and-list-them [tr]
  (let [tgt1 (kt/grant-tgt-ticket tr {:id "a"})
        tgt2 (kt/grant-tgt-ticket tr {:id "b"})
        _ (kt/grant-st-ticket tr "url11" {} (:tid tgt1))
        _ (kt/grant-st-ticket tr "url12" {} (:tid tgt1))
        _ (kt/grant-st-ticket tr "url21" {} (:tid tgt2))]
    (is (= 2 (count (kt/session-tickets tr (:tid tgt1)))))
    (is (= 1 (count (kt/session-tickets tr (:tid tgt2)))))
    ))


(deftest grant-session-ticket-and-list-atr
  (grant-some-session-ticket-and-list-them *atr*))


(deftest grant-session-ticket-and-list-mtr
  (grant-some-session-ticket-and-list-them *mtr*))


;(deftest grant-tgt-and-check-if-atime-is-updated
;  (let [tgt (kt/grant-tgt-ticket *treg* {:id "a"})
;        st (kt/grant-st-ticket *treg* "" {} tgt)
;        pgt (kt/grant-pgt-ticket *treg* st "")]
;    (is (= 0 (:atime tgt)))
;    (is (= 0 (:atime pgt)))
;    (is (= 0 (:atime st)))
;    (TT 100)
;    (kt/grant-st-ticket *treg* "url1" {} tgt)
;    (is (= 100 (:atime (kt/get-ticket *treg* (:tid tgt)))))
;    (kt/grant-pt-ticket *treg* pgt "")
;    (is (= 100 (:atime (kt/get-ticket *treg* (:tid pgt)))))
;    ))



;(deftest grant-and-cleanup-tgt-tickets
;  (kt/grant-tgt-ticket *treg* {:id "blah"})
;  (TT 100)
;  (kt/grant-tgt-ticket *treg* {:id "blee"})
;  (TT 150)
;  (kt/clean-tickets *treg* :tgt 100)
;  (is (= 1 (count @*treg-atom*)) "Should remove only oldest ticket.")
;  (TT 201)
;  (kt/clean-tickets *treg* :tgt 100)
;  (is (= 0 (count @*treg-atom*)) "Should remove only "))


