(ns kanar.fileauth-test
  "File-based user database and authentication test"
  (:require
    [kanar.core.fileauth :as kf]
    [clojure.test :refer :all]))


(deftest password-check-test
  (is (kf/check-password "asdasdasd" "asdasdasd"))
  (is (not (kf/check-password "asdasdasd" "12345")))
  (is (kf/check-password "SHA:d8a928b2043db77e340b523547bf16cb4aa483f0645fe0a290ed1f20aab76257" "asdasdasd"))
  (is (not (kf/check-password "SHA:d8a928b2043db77e340b523547bf16cb4aa483f0645fe0a290ed1f20aab76257" "12345")))
  (is (kf/check-password "SHS:fab49c73f444b5d97fbf9659a9e3f2cfa19200b4fe9de705fb2a51870cdd4934", "asdasdasd"))
  (is (not (kf/check-password "SHS:fab49c73f444b5d97fbf9659a9e3f2cfa19200b4fe9de705fb2a51870cdd4934" "12345")))
  (is (not (kf/check-password "SHS:fab49c73f444b5d97fbf9659a9e3f2cfa19200b4fe9de705fb2a51870cdd4934", "asdasdasd" :salt-length 8))))



