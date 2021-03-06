(defproject kanar/kanar-core "0.2"
  :description "Kanar core framework"
  :url "http://kanar.io/devel/core.html"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies
  [[org.clojure/clojure "1.7.0"]
   [org.clojure/data.xml "0.0.8"]
   [org.clojure/data.json "0.2.6"]
   [ring/ring-core "1.3.2"]
   [slingshot "0.12.2"]
   [compojure "1.3.3"]
   [com.taoensso/timbre "4.0.2"]
   [com.cemerick/valip "0.3.2"]
   [clj-http "2.0.0"]
   [org.clojure/test.check "0.9.0"]
   [prismatic/schema "1.0.4"]
   [com.nimbusds/nimbus-jose-jwt "4.3"]])
