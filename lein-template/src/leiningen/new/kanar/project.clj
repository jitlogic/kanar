(defproject {{name}} "0.1.0-SNAPSHOT"
  :description "{{name}} SSO application."
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies 
  [[org.clojure/clojure "1.6.0"]
   [org.clojure/tools.nrepl "0.2.10"]
   [kanar/kanar-core "0.1.1"]
   {{#with-ldap}} [kanar/kanar-ldap "0.1.1"] {{/with-ldap}}
   {{#with-hazelcast}} [kanar/kanar-hazelcast "0.1.1"] {{/with-hazelcast}}
   [ring/ring-core "1.3.2"]
   [ring/ring-devel "1.3.2"]
   [compojure "1.3.3"]
   [hiccup "1.0.5"]
   [http-kit "2.1.18"]
   [ring/ring-jetty-adapter "1.3.2"]
   [com.taoensso/timbre "4.0.2"]
   ]

  :plugins [[lein-environ "1.0.0"]]

  :profiles
  {:dev
   {:repl-options {:init-ns {{name}}.app}
    :env {:kanar-env :dev}}
   :uberjar
   {:env {:kanar-env :prd}
    :aot :all
    :main {{name}}.app}
   })
