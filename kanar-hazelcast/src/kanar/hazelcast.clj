(ns kanar.hazelcast
  (:import
    (com.hazelcast.config Config)
    (com.hazelcast.core Hazelcast)))

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

