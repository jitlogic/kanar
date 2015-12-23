(ns kanar.hazelcast
  (:require
    [kanar.core.ticket :as kt]
    [taoensso.timbre :as log])
  (:import
    (com.hazelcast.config Config)
    (com.hazelcast.core Hazelcast ReplicatedMap EntryListener)
    (java.util.concurrent TimeUnit)))

; See hazelcast documentation, pg . 254
(defn new-hazelcast [{:keys [multicast tcp group-name group-pass]}]
  (let [config (Config.)
        group-config (.getGroupConfig config)
        network-config (.getNetworkConfig config)
        join-config (.getJoin network-config)
        multicast-config (.getMulticastConfig join-config)
        tcp-config (.getTcpIpConfig join-config)
        tickets-config (.getReplicatedMapConfig config "tickets")]
    (.setName group-config group-name)
    (.setPassword group-config group-pass)
    (.setEnabled tcp-config (:enabled tcp true))
    (when (.isEnabled tcp-config)
      (.setPort network-config (:port tcp 5701))
      (doseq [member (:members tcp)] (.addMember tcp-config member)))
    (.setEnabled multicast-config (:enabled multicast false))
    (when (.isEnabled multicast-config)
      (.setMulticastGroup multicast-config (:addr multicast "224.2.2.99"))
      (.setMulticastPort multicast-config (:port multicast 54999)))
    (.setConcurrencyLevel tickets-config 64)
    (Hazelcast/newHazelcastInstance config)))


; TODO tutaj dodać listener do usuwania session ticketów z mapy :sts w master ticketach
(defn ticket-removal-listener  [tr]
  (reify
    EntryListener

    (entry-added [_ _] nil)

    (entry-updated [_ _] nil)

    (entry-removed [_ _] nil)

    (entry-evicted [_ e]
      (let [{tid :tid, tgt :tgt} (.getValue e)]
        (log/debug "Removing ticket: " tid)
        (when tgt
          (kt/put-ticket tr (assoc tgt :sts (dissoc (:sts tgt) tid)) kt/TGT-TIMEOUT))))

    (map-cleared [_ _] nil)

    (map-evicted [_ _] nil)
    ))


(defn hazelcast-ticket-registry [^ReplicatedMap tm]
  (reify
    kt/ticket-registry

    (get-ticket [_ tid]
      (when tid (.get tm tid)))

    (put-ticket [_ {tid :tid :as ticket} timeout]
      (when tid
        (.put tm tid ticket timeout TimeUnit/MILLISECONDS)
        ticket))

    (del-ticket [_ {tid :tid :as ticket}]
      (let [t (or tid ticket)]
        (when t
          (.remove tm t))))
    ))


