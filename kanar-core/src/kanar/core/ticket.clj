(ns kanar.core.ticket
  (:require [kanar.core.util :as ku])
  (:import (java.util Map)))

(def ^:dynamic TGT-TIMEOUT (* 24 60 60 1000))
(def ^:dynamic ST-FRESH-TIMEOUT (* 2 60 1000))
(def ^:dynamic ST-USED-TIMEOUT (* 4 60 60 1000))

(def ^:dynamic TID-SUFFIX "XXX")

(defonce TID-SEQ (atom 0))


(defprotocol ticket-registry
  "Protocol for ticket registry implementations. "
  (get-ticket [tr tid]
    "Returns ticket with given tid or nil if ticket was not found.")
  (put-ticket [tr ticket timeout]
    "Adds ticket to registry. Ticket will be removed after [timeout]
     milliseconds if not updated. Also returns added ticket.")
  (del-ticket [tr ticket]
    "Removes ticket from registry. Note that ticket might be either
     full ticket record of just string representing ticket ID."))


(defn new-tid [prefix]
  "Generates new ticket ID."
  (str prefix "-" (swap! TID-SEQ inc) "-" (ku/random-string 64) "-" TID-SUFFIX))


(defn atom-ticket-registry [reg-atom]
  "Memory-only ticket registry implementation using an atom containing Clojure map."
  (reify
    ticket-registry

    (get-ticket [_ tid]
      (get @reg-atom tid))

    (put-ticket [_ ticket timeout]
      (let [ticket (assoc ticket :timeout (+ (ku/cur-time) timeout))]
        (swap! reg-atom #(assoc % (:tid ticket) ticket))) ticket)

    (del-ticket [_ ticket]
      (swap! reg-atom #(dissoc % (or (:tid ticket) ticket))))

    ))


(defn map-ticket-registry [^Map tm]
  "Memory-only ticket registry implementation using Java map."
  (reify
    ticket-registry

    (get-ticket [_ tid]
      (locking tm
        (when tid (.get tm tid))))

    (put-ticket [_ {tid :tid :as ticket} timeout]
      (when tid
        (locking tm
          (.put tm tid (assoc ticket :timeout (+ (ku/cur-time) timeout))))
        ticket))

    (del-ticket [_ {tid :tid :as ticket}]
      (let [t (or tid ticket)]
        (when t
          (locking tm
            (.remove tm t)))))

    ))


(defn grant-tgt-ticket [ticket-registry princ]
  (let [tid (new-tid "TGC")
        tgt {:type :tgt, :tid tid, :princ princ :sts {}}]
    (put-ticket ticket-registry tgt TGT-TIMEOUT)))


(defn grant-st-ticket [ticket-registry svc-url service tid & {:as extras}]
  (let [tgt (get-ticket ticket-registry tid)
        sid (new-tid "ST")
        sts (assoc (:sts tgt) sid (+ (ku/cur-time) ST-FRESH-TIMEOUT))
        svt (merge extras {:type :svt :tid sid, :url svc-url :service service :tgt tgt, :used false})]
    (put-ticket ticket-registry (assoc tgt :sts sts) TGT-TIMEOUT)
    (put-ticket ticket-registry svt ST-FRESH-TIMEOUT)))


(defn expend-ticket [ticket-registry sid]
  (let [svt (get-ticket ticket-registry sid)
        tgt (get-ticket ticket-registry (:tid (:tgt svt)))
        sts (assoc (:sts tgt) (:sid svt) (+ (ku/cur-time) ST-USED-TIMEOUT))]
    (put-ticket ticket-registry (assoc tgt :sts sts, :timeout (+ (ku/cur-time) TGT-TIMEOUT)) TGT-TIMEOUT)
    (put-ticket ticket-registry (assoc svt :used true) ST-USED-TIMEOUT)))


(defn grant-pgt-ticket [ticket-registry tid pgt-url]
  (let [svt (get-ticket ticket-registry tid)
        tgt (get-ticket ticket-registry (:tid (:tgt svt)))
        tid (new-tid "PGT")
        iou (new-tid "PGTIOU")
        pgt {:type :pgt, :tid tid, :iou iou, :url pgt-url, :service (:service tgt), :tgt tgt, :atime (ku/cur-time)}]
    ; TODO alokowanie i usuwanie ticketów PGT jest kompletnie skasztanione ...
    ; TODO check if service is allowed to issue PGT on given pgt-url
    ; TODO check if pgt-url is secure
    (put-ticket ticket-registry pgt TGT-TIMEOUT)))


(defn grant-pt-ticket
  [ticket-registry {:keys [service tid] :as pgt} svc-url]
  (let [tgt (get-ticket ticket-registry tid)
        tid (new-tid "PT")
        sts (assoc (:sts tgt) tid (+ (ku/cur-time) ST-FRESH-TIMEOUT))
        pt {:type :pt, :tid tid, :url svc-url, :service service, :pgt pgt, :atime (ku/cur-time)}]
    ; TODO check ticket validity etc.
    (put-ticket ticket-registry pt ST-FRESH-TIMEOUT)
    (put-ticket ticket-registry pgt TGT-TIMEOUT)
    (put-ticket ticket-registry (assoc tgt :sts sts) TGT-TIMEOUT)))

(defn session-tickets [ticket-registry tid]
  (let [tgt (get-ticket ticket-registry tid)]
    (for [tid (keys (:sts tgt))
          :let [t (get-ticket ticket-registry tid)]
          :when t] t)))


(defn clear-session [tr tid]
  (if-let [tgt (get-ticket tr tid)]
    (doseq [tkt (keys (:sts tgt))]
      (del-ticket tr tkt)))
  (del-ticket tr tid))



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



(defn ticket-atom-cleaner-task [tickets-atom]
  "TODO implement this for atom ticket registry")
