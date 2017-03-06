(ns kanar.core.system
  (:require
    [ns-tracker.core :refer [ns-tracker]]
    [slingshot.slingshot :refer [try+]]
    [taoensso.timbre :as log]
    [kanar.core.util :as ku]
    [clojure.string :as cs]
    [kanar.core.util :as kcu])
  (:import (java.io File)
           (java.text SimpleDateFormat)))


(defn wrap-kanar-reload [handler reload-fn & [options]]
  (if-not (System/getProperty "kanar.devel")
    handler
    (let [source-dirs (:dirs options ["src"])
          modified-namespaces (ns-tracker source-dirs)]
      (fn [request]
        (let [ns-syms (modified-namespaces)]
          (when-not (empty? ns-syms)
            (.println System/err "Code changes detected. Reloading required namespaces.")
            (doseq [ns-sym ns-syms]
              (require ns-sym :reload))
            (reload-fn)))
        (handler request)))))


(defn conf-reload-task [reload-fn home & files]
  (log/info "Starting automatic configuration reload task ..." reload-fn)
  (future
    (loop [tst1 (vec (for [f files] (.lastModified (File. ^String home ^String f))))]
      (Thread/sleep 5000)
      (let [tst2 (vec (for [f files] (.lastModified (File. ^String home ^String f))))]
        (try
          (when-not (= tst1 tst2)
            (log/info "Configuration change detected. Reloading ...")
            (reload-fn)
            (log/info "Configuration reloaded succesfully."))
          (catch Throwable e
            (log/error "Error reloading configuration: " e)
            (.printStackTrace e)))
        (recur tst2)))))



