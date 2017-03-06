(ns kanar.hazelcast
  (:require
    [kanar.core.ticket :as kt]
    [taoensso.timbre :as log])
  (:import
    (com.hazelcast.config Config)
    (com.hazelcast.core Hazelcast ReplicatedMap HazelcastInstance)
    (java.util.concurrent TimeUnit)
    (com.hazelcast.instance GroupProperties)))

; See hazelcast documentation, pg . 254
(defn new-hazelcast [{:keys [instance-name multicast tcp group-name group-pass] :or {instance-name "kanar"} :as conf}]
  (log/info "Creating new hazelcast configuration: " (dissoc conf :group-pass))
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
    (.setProperty config GroupProperties/PROP_ENABLE_JMX "true")
    (.setProperty config GroupProperties/PROP_ENABLE_JMX_DETAILED "true")
    (.setInstanceName config instance-name)
    (Hazelcast/newHazelcastInstance config)))


(defn hz-reconnect [{{old-conf :hazelcast-conf} :conf, old-conn :hazelcast} {new-conf :hazelcast-conf}]
  "Connects (or reconnects) to hazelcast cluster."
  (if (or (not= old-conf new-conf) (nil? old-conn))
    (try
      (log/info "Hazelcast configuration changed. Restarting hazelcast.")
      (let [new-conn (new-hazelcast new-conf)]
        (log/info "Hazelcast instance created.")
        (when old-conn
          (log/info "Old hazelcast instance closing delayed.")
          (future
            (Thread/sleep 30000)
            (.shutdown ^HazelcastInstance old-conn)
            (log/info "Old hazelcast instance closed.")))
        new-conn)
      (catch Exception e
        (log/error "Error reconfiguring hazelcast instance. Leaving old instance (if any) intact." e)
        old-conn))
    (do
      (log/info "Hazelcast configuration not changed. Leaving old instance intact.")
      old-conn)))


; TODO aktywujemy jeżeli będzie do czegoś potrzebne
;(defn ticket-removal-listener  [tr]
;  (reify
;    EntryListener
;
;    (entry-added [_ _] nil)
;
;    (entry-updated [_ _] nil)
;
;    (entry-removed [_ _] nil)
;
;    (entry-evicted [_ e]
;      (let [{tid :tid, tgt :tgt} (.getValue e)]
;        (log/debug "Removing ticket: " tid)))
;
;    (map-cleared [_ _] nil)
;
;    (map-evicted [_ _] nil)
;    ))

(defn hazelcast-ticket-store [^ReplicatedMap rm]
  (reify kt/ticket-store
    (get-obj [_ tid]
      (when tid (.get rm tid)))
    (put-obj [_ {:keys [tid timeout] :as tkt}]
      (when (and tid timeout) (.put rm tid tkt timeout TimeUnit/MILLISECONDS)))
    (del-obj [_ tid]
      (when tid (.remove rm tid)))
    ))


