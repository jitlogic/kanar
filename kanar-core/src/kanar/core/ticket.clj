(ns kanar.core.ticket
  (:require
    [schema.core :as s]
    [kanar.core.util :as ku]))

(def ^:dynamic TGT-TIMEOUT (* 24 60 60 1000))
(def ^:dynamic ST-FRESH-TIMEOUT (* 2 60 1000))
(def ^:dynamic ST-EXPENDED-TIMEOUT (* 4 60 60 1000))

(def ^:dynamic TID-SUFFIX "XXX")

(defonce TID-SEQ (atom 0))


(def ticket-object
  {:tid s/Str
   :atime s/Num
   :ctime s/Num
   :mtime s/Num
   :timeout s/Num
   })


(def ticket-record
  (into
    ticket-object
    {::refs #{ s/Str }
     }))


(def ticket-alias
  (into
    ticket-object
    {:type s/Keyword
     ::ref s/Str
     }))


(defprotocol ticket-store
  "Protocol to ticket registry backend store"
  (get-obj [tr oid]
    "Returns data item from store.")
  (put-obj [tr obj]
    "Puts item into store.")
  (del-obj [tr oid]
    "Removes item from store."))


(defn atom-ticket-store [reg-atom]
  (reify
    ticket-store

    (get-obj [_ tid]
      (@reg-atom tid))

    (put-obj [_ obj]
      (swap! reg-atom assoc (:tid obj) obj))

    (del-obj [_ tid]
      (swap! reg-atom dissoc tid))

    ))


(defn new-object [ts ticket]
  (let [t (ku/cur-time)
        r (into ticket {:atime t, :ctime t, :mtime t})]
    (put-obj ts r)
    r))


(defn get-ticket [ts tid]
  (when-let [obj (get-obj ts tid)]
    (put-obj ts (assoc obj :atime (ku/cur-time)))
    (if (::ref obj)
      (get-ticket ts (::ref obj))
      obj)))


(defn update-ticket [ts tid data]
  (let [t (ku/cur-time)
        obj (get-ticket ts tid)]
    (if (::ref obj)
      (do
        (put-obj ts (merge obj {:atime t, :mtime t}))
        (update-ticket ts (::ref obj) data))
      (put-obj ts (merge obj data {:atime t, :mtime t})))))


(defn delete-ticket
  ([ts tid]
   (delete-ticket ts tid true))
  ([ts tid recursive]
   (let [obj (get-ticket ts tid)]
     (when (and recursive obj)
       (if (::ref obj)
         (delete-ticket ts (::ref obj) recursive)
         (doseq [ref (or (::refs obj) #{})]
           (delete-ticket ts ref recursive))))
     (del-obj ts tid))))


(defn ref-ticket [ts tid ref]
  (when-let [ticket (get-ticket ts tid)]
    (update-ticket ts tid {::refs (into #{ref} (::refs ticket))})))


(defn session-tickets [ts tid]
  (when-let [ticket (get-ticket ts tid)]
    (for [rid (or (::refs ticket) #{})
          :let [rt (get-ticket ts rid)]
          :when (= :svt (:type rt))] rt)))


(defn alias-ticket [ts tid alias data]
  (when (get-ticket ts tid)
    (new-object ts (into {:tid alias, ::ref tid} data))
    (ref-ticket ts tid alias)))


(defn new-tid [prefix]
  "Generates new ticket ID."
  (str prefix "-" (swap! TID-SEQ inc) "-" (ku/random-string 64) "-" TID-SUFFIX))


;(defn clear-session [tr tid]
;  (if-let [tgt (get-ticket tr tid)]
;    (doseq [tkt (keys (:sts tgt))]
;      (del-ticket tr tkt)))
;  (del-ticket tr tid))


(defn tkt-atom-cleaner-task [reg-atom]
  ; TODO implement ticker registry here
  )


;(defn ticket-cleaner-task-old [app-state & {:keys [interval] :or {:interval 60000}}]
;  (future
;    (loop []
;      (Thread/sleep interval)
;      (try
;        (let [ticket-registry (:ticket-registry @app-state)]
;          (log/debug "KCORE-D002: Cleaning up timed out tickets ...")
;          ;(kt/clean-tickets ticket-registry :svt 300000)
;          ;(kt/clean-tickets ticket-registry :pt 300000)
;          ;(kt/clean-tickets ticket-registry :pgt 36000000)
;          ;(kt/clean-tickets ticket-registry :tgt 36000000)
;          )                                                 ; TODO wylogowywanie sesji z przeterminowanych ticketów TGT (?? czy na pewno ??)
;        (catch Throwable e
;          (log/error "KCODE-E002: Error while cleaning up ticket registry:" e)))
;      (recur))))
;



;(defn ticket-atom-cleaner-task [tickets-atom]
;  "TODO implement this for atom ticket registry")
