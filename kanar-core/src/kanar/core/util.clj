(ns kanar.core.util
  (:import (java.text SimpleDateFormat)
           (java.util Date TimeZone)
           (java.net URLEncoder)
           (javax.xml.bind DatatypeConverter)
           (javax.xml.transform.dom DOMResult)
           (javax.xml.stream XMLOutputFactory)
           (javax.xml.parsers DocumentBuilderFactory)
           (com.sun.org.apache.xml.internal.serialize OutputFormat XMLSerializer)
           (org.w3c.dom Document)
           (java.io StringWriter PrintWriter)
           (net.minidev.json JSONObject JSONArray)
           (java.util.concurrent ExecutorService))
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


(defn cur-time
  ([] (System/currentTimeMillis))
  ([^Long o] (+ (System/currentTimeMillis) o)))


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


(defn emit-dom [el]
  (let [xmlf (XMLOutputFactory/newInstance)
        docf (DocumentBuilderFactory/newInstance)
        docb (.newDocumentBuilder docf)
        rslt (DOMResult. (.newDocument docb))
        e (xml/sexp-as-element el)
        writer (-> xmlf (.createXMLStreamWriter rslt))]
    (doseq [event (xml/flatten-elements [e])]
      (xml/emit-event event writer))
    (.getNode rslt)))



(defn dom-to-str [node]
  (let [f (OutputFormat. node)
        sw (StringWriter.)]
    (.setIndenting f false)
    (.serialize (XMLSerializer. sw f) ^Document node)
    (.toString sw)))


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


(defn wrap-set-param [f param pfn]
  "Ring wrapper settings arbitrary parameter [param] with result result of function [pfn] called with request as argument."
  (fn [req]
    (let [val (if (keyword? pfn) pfn (pfn req))]
      (f (assoc-in req [:params param] val)))))


(defn merge-principals [{attr1 :attributes :as p1} {attr2 :attributes :as p2}]
  "Merges attributes of "
  (merge p1 p2 {:attributes (merge attr1 attr2)}))


(defn get-svt-attrs [{:keys [attributes] :as princ} {{attrs :attrs} :service :as svt}]
  (if (vector? attrs) (select-keys attributes attrs) (or attributes {})))

(defn b64 [v]
  (DatatypeConverter/printBase64Binary (.getBytes (str v))))

(def SKIP_CHARS #{\newline \return \tab \backspace \formfeed})

(defn oneliner [s]
  (cs/join
    (for [c s :when (not (contains? SKIP_CHARS c))] c)))


(defn to-json-object [x]
  "Converts Clojure data structure to JSONObject."
  (cond
    (map? x)
    (let [o (JSONObject.)]
      (doseq [[k v] x] (.put o (if (keyword? k) (name k) (str k)) (to-json-object v)))
      o)
    (or (vector? x) (seq? x))
    (let [a (JSONArray.)]
      (doseq [v x] (.add a v))
      a)
    (or (string? x) (number? x)) x))


(defn from-json-object [x]
  "Converts JSONObject to Clojure data structure."
  (cond
    (instance? JSONObject x) (into {} (for [[k v] x] { (keyword k) (from-json-object v)}))
    (instance? JSONArray x)  (vec (for [v x] (from-json-object v)))
    (or (string? x) (number? x)) x))


(defn domain-name [url]
  (and url (second (re-matches #"^(?i:https?)://([^\/]+)(/.*)?" url))))


(defn error-with-trace [e]
  (if (instance? Throwable e)
    (let [sw (StringWriter.) pw (PrintWriter. sw)]
      (.printStackTrace e pw)
      (.toString sw))
    (str e)))


(defn no-nulls [x]
  (cond
    (map? x) (into {} (for [[k v] x :when v] {k v}))
    (list? x) (for [v x :when v] v)
    (vector? x) (vec (for [v x :when v] v))
    :else x))


(defn async-pooled [f ^ExecutorService pool]
  (fn [& args]
    (.submit pool ^Callable
      (cast Callable (fn [] (apply f args))))))

(defn combine-maps [& vals]
  (let [vals (filter (complement nil?) vals)]
    (if (every? map? vals)
      (apply merge-with combine-maps vals)
      (last vals))))
