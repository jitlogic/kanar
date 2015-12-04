(ns leiningen.new.kanar
  (:use [leiningen.new.templates :only [renderer name-to-path ->files]]))

(def render (renderer "kanar"))

(def non-src-files
  [".gitignore" "LICENSE" "project.clj" "README.md"])

(def conf-files
  ["kanar.conf" "services.conf" "users.conf" "kanar.sh"])

(def src-files
  ["app.clj" "views.clj"])

(def rsrc-files
  ["kanar.css"])

(defn parse-opts [opts]
  (let [optss (set opts)
        with-ldap (contains? optss "--with-ldapauth")
        with-file (contains? optss "--with-fileauth")]
       {:with-file (or with-file (not with-ldap))
        :with-ldap with-ldap}))


(defn kanar
  "Create new Kanar project."
  [name & opts]
  (let [popt (parse-opts opts)
        data (into popt {:name name, :sanitized (name-to-path name)})]
    (apply
      ->files
      (cons
        data
        (concat
          (for [f non-src-files] [f (render f data)])
          (for [f src-files] [(str "src/{{sanitized}}/" f) (render (str "src/" f) data)])
          (for [f conf-files] [(str "conf/" f) (render (str "conf/" f) data)])
          (for [f rsrc-files] [(str "resources/public/static/" f) (render (str "resources/public/static/" f) data)]))
        ))))
