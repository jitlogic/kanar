(ns kanar.kanar-util-test
  (:require
    [clojure.test :refer :all]
    [kanar.core.util :as kcu]))


(deftest to-json-obj-test
  (is (= 123 (kcu/to-json-object 123)))
  (is (= "abc" (kcu/to-json-object "abc")))
  (is (= "[1,2,3]" (str (kcu/to-json-object [1 2 3]))))
  (is (= "{\"a\":\"aaa\",\"b\":\"bbb\"}" (str (kcu/to-json-object {:a "aaa" :b "bbb"})))))


(deftest to-from-json-obj-test
  (is (= 123 (kcu/from-json-object (kcu/to-json-object 123))))
  (is (= "a" (kcu/from-json-object (kcu/to-json-object "a"))))
  (is (= [1 2 3] (kcu/from-json-object (kcu/to-json-object [1 2 3]))))
  (is (= {:a 1 :b "c"} (kcu/from-json-object (kcu/to-json-object {:a 1 :b "c"})))))

