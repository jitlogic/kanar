(ns kanar.core.util
  (:import (java.text SimpleDateFormat)
           (java.util Date TimeZone)
           (java.net URLEncoder)
           (javax.xml.bind DatatypeConverter))
  (:require
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log]
    [clojure.string :as cs]
    [clojure.data.xml :as xml]))


(defn random-string
  "Generates random string of alphanumeric characters of given length."
  ([len]
    (random-string len "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
  ([len s]
    (apply str (for [_ (range len)] (rand-nth s)))))


(defn cur-time [] (System/currentTimeMillis))


(defn xml-time
  ([] (xml-time (.getTime (Date.))))
  ([^Long t]
   (let [sf (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
     (.setTimeZone sf (TimeZone/getTimeZone "UTC"))
     (.format sf (Date. t)))))


(defn- xml-element? [e]
  (and
    (map? e)
    (contains? e :tag)
    (contains? e :content)
    (seq? (:content e))))


(defn xml-to-map [{:keys [tag content]}]
  (let [tc (for [c content] (if (xml-element? c) (xml-to-map c) c))
        tc (if (every? map? tc) [(into (first tc) (rest tc))] tc)
        tc (if (= 1 (count tc)) (first tc) tc)]
    {tag tc}))


(defn emit-xml [el]
  (.substring (xml/emit-str (xml/sexp-as-element el)) 38))


(defn secure-cookie [val]
  {:value val, :http-only true, :secure true})


(defn url-enc [s] (URLEncoder/encode s "UTF-8"))


(defn redirect-with-params [url params reason]
  (let [fp (for [[k v] params] (str (url-enc (name k)) "=" (url-enc v)))
        url (if (or (nil? params) (empty? fp)) url (str url "?" (reduce #(str %1 "&" %2) fp)))]
    (if reason
      (log/debug "Redirecting with params: " reason))
    {:status  302
     :body    "Redirecting..."
     :headers {"Location" url}}))


(defn login-failed [msg]
  (throw+ {:type :login-failed :msg msg}))


(defn chpass-failed [msg]
  (throw+ {:type :chpass-failed :msg msg}))


(defn login-cont [resp]
  (throw+ {:type :login-cont :resp resp}))


(defn fatal-error [msg & {:as args}]
  (throw+ {:type :fatal-error :msg msg :args args}))


(defn security-error [msg & {:as args}]
  (throw+ {:type :security-error :msg msg :args args}))


(defn log-auth-fn [msg]
  (fn [princ _]
    (log/debug msg princ)
    princ))


(defn parse-domain-auth-fn [dom-map]
  (fn [{id :id idom :dom :as princ} {{dom :dom} :params :as req}]
    (let [[un & [ud & _]] (clojure.string/split id #"@")]
      (into princ {:id un, :dom (or (dom-map ud) idom dom)}))))


(defn multidomain-auth-fn [& {:as domains}]
  (fn [princ {{dom :dom} :params :as req}]
    (let [afn (domains dom)]
      (if (fn? afn)
        (afn princ req)
        (login-failed "Invalid login domain.")))))


(defn chain-auth-fn [& auth-fns]
  "Chains several auth functions together. Returns auth function that will sequentially call all passed auth-fn
   and pass result principal to next fn."
  (fn [princ req]
    (loop [[f & fns] auth-fns, p princ]
      (if f (recur fns (f p req)) p))))


(defn const-attr-fn [& {:as attrs}]
  ""
  (fn [{:keys [attributes] :as princ} _]
    (assoc princ
      :attributes
      (into (or attributes {}) attrs))))


(defn wrap-set-param [f param pfn]
  "Ring wrapper settings arbitrary parameter [param] with result result of function [pfn] called with request as argument."
  (fn [req]
    (let [val (if (keyword? pfn) pfn (pfn req))]
      (f (assoc-in req [:params param] val)))))


(defn auth-domain-fn [default-dom]
  (fn [princ {{dom :dom} :params}]
    (assoc princ :dom (or dom default-dom))))


(defn merge-principals [{attr1 :attributes :as p1} {attr2 :attributes :as p2}]
  "Merges attributes of "
  (merge p1 p2 {:attributes (merge attr1 attr2)}))


(defn get-svt-attrs [{{attrs :attrs} :service :as svt}]
  (let [attrv (get-in svt [:tgt :princ :attributes])]
    (if (vector? attrs) (select-keys attrv attrs) attrv)))

(defn b64 [v]
  (DatatypeConverter/printBase64Binary (.getBytes (str v))))

(def SKIP_CHARS #{\newline \return \tab \backspace \formfeed})

(defn oneliner [s]
  (cs/join
    (for [c s :when (not (contains? SKIP_CHARS c))] c)))
