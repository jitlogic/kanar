(defproject kanar/kanar-hazelcast "0.2"
  :description "Distributed ticket registry based on Hazelcast for Kanar."
  :url "http://kanar.io/devel/hazelcast.html"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [kanar/kanar-core "0.1.1"]
                 [com.hazelcast/hazelcast "3.5.3"]])
