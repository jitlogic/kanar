(defproject kanar "0.1.1"
  :description "Extensible SSO solution."
  :plugins [[lein-sub "0.2.4"]]
  :sub [ "kanar-core" "kanar-ldap" "kanar-spnego" "kanar-hazelcast" "lein-template" ])
