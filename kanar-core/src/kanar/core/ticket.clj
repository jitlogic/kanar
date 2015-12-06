(ns kanar.core.ticket
  (:require [kanar.core.util :as ku])
  (:import (java.util Map)))


(defprotocol ticket-registry
  (get-ticket [tr tid])
  (put-ticket [tr ticket])
  (del-ticket [tr ticket])
  (new-tid [tr prefix])
  (session-tickets [tr tgt])
  (clean-tickets [tr type timeout]))                            ; TODO clean-tickets -> old-tickets (listowanie)


(defn gen-tid [seq-num prefix len suffix]
  "Generates new ticket ID."
  (str prefix "-" (swap! seq-num inc) "-" (ku/random-string len) "-" suffix))


(defn atom-ticket-registry [reg-atom sid]
  (let [seq-num (atom 0)]
    (reify
      ticket-registry

      (get-ticket [_ tid]
        (get @reg-atom tid))

      (put-ticket [_ ticket]
        (swap! reg-atom #(assoc % (:tid ticket) ticket)) ticket)

      (del-ticket [_ ticket]
        (swap! reg-atom #(dissoc % (or (:tid ticket) ticket))))

      (new-tid [_ prefix]
        (gen-tid seq-num prefix 64 sid))

      (session-tickets [_ {tid :tid}]
        (for [[_ v] @reg-atom :when (= tid (:tid (:tgt v)))] v))

      (clean-tickets [this type timeout]
        (let [tstart (- (ku/cur-time) timeout)]
          (doseq [[_ t] @reg-atom]
            (if (and (= type (:type t)) (< (:atime t) tstart) (not (:used t)))
              (del-ticket this t)))))
      )))


(defn map-ticket-registry [^Map tm sid]
  (let [seq-num (atom 0)]
    (reify
      ticket-registry

      (get-ticket [_ tid]
        (when tid (.get tm tid)))

      (put-ticket [_ {tid :tid :as ticket}]
        (when tid
          (.put tm tid ticket)
          ticket))

      (del-ticket [_ {tid :tid :as ticket}]
        (let [t (or tid ticket)]
          (when t
            (.remove tm t))))

      (new-tid [_ prefix]
        (gen-tid seq-num prefix 64 sid))

      (session-tickets [_ {tid :tid}]
        (when tid
          (for [e (.entrySet tm)
                :let [v (.getValue e)]
                :when (= tid (:tid (:tgt v)))] v)))

      (clean-tickets [this type timeout]
        (let [tstart (- (ku/cur-time) timeout)]
          (doseq [t (doall
                      (for [e (.entrySet tm)
                            :let [v (.getValue e)]
                            :when (and (= type (:type v)) (< (:atime v) tstart) (not (:used v)))]
                        v))]
            (del-ticket this t)))))))


(defn grant-tgt-ticket
  [ticket-registry
   princ]
  (let [tid (new-tid ticket-registry "TGC")
        tgt {:type :tgt, :tid tid, :atime (ku/cur-time), :princ princ}]
    (put-ticket ticket-registry tgt)))


(defn grant-st-ticket
  [ticket-registry
   svc-url service tgt]
  (let [sid (new-tid ticket-registry "ST")
        svt {:type :svt :tid sid, :url svc-url :service service :tgt tgt :used false :atime (ku/cur-time)}]
    (put-ticket ticket-registry (assoc tgt :atime (ku/cur-time)))
    (put-ticket ticket-registry svt)))


; TODO odsyłanie IOU przeniesc do innego modułu
(defn send-pgt-iou [pgt-url tid iou]
  ; TODO configure IOU
  true)


(defn grant-pgt-ticket
  [ticket-registry
   {service :service tgt :tgt}
   pgt-url]
  (let [tid (new-tid ticket-registry "PGT")
        iou (new-tid ticket-registry "PGTIOU")
        pgt {:type :pgt :tid tid :iou iou :url pgt-url :service service :tgt tgt :atime (ku/cur-time)}]
    ; TODO check if service is allowed to issue PGT on given pgt-url
    ; TODO check if pgt-url is secure
    (when (send-pgt-iou pgt-url tid iou)
      (put-ticket ticket-registry pgt))))


(defn grant-pt-ticket
  [ticket-registry
   {service :service :as pgt}
   svc-url]
  (let [tid (new-tid ticket-registry "PT")
        pt {:type :pt :tid tid :url svc-url :service service :pgt pgt :atime (ku/cur-time)}]
    ; TODO check ticket validity etc.
    (put-ticket ticket-registry (assoc pgt :atime (ku/cur-time)))
    (put-ticket ticket-registry pt)))


(defn clear-session
  [tr tid]
  (if-let [tgt (get-ticket tr tid)]
    (doseq [tkt (session-tickets tr tgt)]
      (del-ticket tr tkt)))
  (del-ticket tr tid))
