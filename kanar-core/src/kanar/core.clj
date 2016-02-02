(ns kanar.core
  (:require
    [taoensso.timbre :as log]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [clj-http.client :as http]
    [schema.core :as s]
    [clojure.string :as cs])
  (:import (java.util.concurrent ExecutorService Executors)))


(def http-request-schema
  "Schema for base (filtered) HTTP request."
  {:uri s/Str
   :headers s/Any
   :cookies s/Any})


(def sso-principal-schema
  "Defines SSO principal"
  {:id         s/Str                                        ; principal ID
   :attributes s/Any                                        ; Principal attributes
   :dn         s/Str                                        ; DN (for LDAP principals)
   :domain     (s/maybe s/Keyword)                          ; Authentication domain (optional - for multidomain setups)
   })


(def sso-service-schema
  {:id          s/Keyword                                   ; Service ID
   :url         (s/enum s/Regex s/Str)                      ; Service URL mask
   :app-urls    (s/maybe [s/Str])                           ; Direct URLs to application instances (for backwards communication)
   :id-template (s/maybe s/Str)                             ;
   :allow-roles (s/maybe [s/Str])
   :deny-roles  (s/maybe [s/Str])
   :domains     (s/maybe [s/Keyword])
   :http-params (s/maybe s/Any)                             ; Parameters for HTTP client
   })


(def tgt-ticket-schema
  {:type :tgt                                               ; Ticket type = TGT
   :tid s/Str                                               ; Ticket ID
   :princ sso-principal-schema                              ; Ticket owner (SSO principal)
   :sts s/Any                                               ; Associated session tickets
   :ctime s/Num                                             ; Ticket creation time
   :timeout s/Num                                           ; Time instant TGT will be discarded
   })


(def svt-ticket-schema
  {:type :svt                                               ; Ticket type = SVT
   :tid s/Str                                               ; Ticket ID
   :url s/Str                                               ;
   :expended s/Bool
   :service sso-service-schema
   :tgt s/Str
   :ctime s/Num
   :timeout s/Num
   })


(def pgt-ticket-schema
  {:type :pgt
   :tid s/Str
   :iou s/Str
   :url s/Str
   :service sso-service-schema
   :tgt s/Str
   })



(def sso-request-schema
  "Schema for parsed and processed SSO request data. This is extention to standard http request data."
  (merge
    http-request-schema
    {:protocol       (s/enum :cas :saml :oauth2)            ; SSO protocol used
     :service-url    s/Str                                  ; URL to redirect back to service
     :credentials    s/Any                                  ; Login credentials
     :principal      sso-principal-schema                   ; Logged in principal
     :view-params    s/Any                                  ; Parameters for rendered views
     :hidden-params  s/Any                                  ; Hidden form parameters in rendered views
     :service-params s/Any                                  ; SSO parameters passed
     :login          (s/enum :none :page)                   ; Login page display mode
     :prompt         (s/enum :none :consent)                ; SSO
     :sesctl         (s/enum :none :renew :login)           ; Whenever session should be renewed (user requthenticated)
     :tgt            tgt-ticket-schema                      ; Ticket Granting Ticket
     :svt            s/Any                                  ; Service Granting Ticket
     :service        s/Any                                  ; Service
     }))


(defn login-failed [req view-fn msg]
  {:status 200
   :body   (view-fn :login (assoc-in (dissoc req :principal) [:view-params :message] msg))
   :headers {"Content-type" "text/html; charset=utf-8"}})   ; TODO dodawać ciasteczko CASTGC zawsze jeżeli jest TGT


(defn message-screen [{:keys [tgt] :as req} view-fn status msg]
  {:status  200
   :body    (view-fn :message (assoc req :view-params (merge (:view-params req) {:status status :message msg})))
   :headers {"Content-type" "text/html; charset=utf-8"}
   :cookies (if tgt {"CASTGC" (ku/secure-cookie (:tid tgt))} {})
   })


(defn consent-screen [{:keys [tgt] :as req} view-fn msg options]
  {:status 200
   :body (view-fn :consent (assoc req :view-params (merge (:view-params req) {:message msg, :options options})))
   :headers {"Content-type" "text/html; charset=utf-8"}
   :cookies (if tgt {"CASTGC" (ku/secure-cookie (:tid tgt))} {})
   })


(defn service-lookup [services svc-url]
  (if svc-url
    (first
      (for [s services
            :when (re-matches (:url s) svc-url)]
        s))))


(defn audit [{audit-fn :audit-fn :as app-state} req tgt svc action]
  (if audit-fn
    (audit-fn app-state req tgt svc action)
    (log/report "AUDIT:" action "Principal: " (:princ tgt) "Service: " svc)))


; Functions for constructing SSO workflows.

(defn sso-request-parse-wfn [f & pfns]
  "Parses request parameters and detects SSO protocol (eg. CAS, OAuth20 etc.)."
  (fn [{{:keys [gateway renew warn]} :params :as req}]
    (let [sso-reqs (for [pfn pfns :let [v (pfn req)] :when v] v)
          sso-req (first sso-reqs)]
      (f (merge req (or sso-req
                        {:protocol :none,
                         :login (if gateway :none :page),
                         :prompt (if warn :consent :none),
                         :sesctl (if renew :renew :none)} ))))))


(defn tgt-lookup-wfn [f ticket-registry]
  "WFN: Looks up for TGC ticket."
  (fn [{{{CASTGC :value} "CASTGC"} :cookies :keys [login sesctl] :as req}]
    (if (= :renew sesctl)
      (kt/delete-ticket ticket-registry CASTGC true))
    (if-let [tgt (and CASTGC (kt/get-ticket ticket-registry CASTGC))]
      (f (assoc req :tgt tgt))
      (if (= login :none)
        {:status  302
         :body    "Redirecting to service ..."
         :headers {"Location" (:service-url req), "Content-type" "text/plain; charset=utf-8"}}
        (f req)))))


(defn login-flow-wfn [f ticket-registry lf]
  "WFN: Handles login flow if no user session was detected."
  (fn [req]
    (if (:tgt req)
      (f req)
      (let [r (lf req)]
        (if-let [princ (:principal r)]
          (let [tkt {:type :tgt, :tid (kt/new-tid "TGC"), :princ princ, :timeout kt/TGT-TIMEOUT}]
            (f (assoc r :tgt (kt/new-object ticket-registry tkt))))
          r)))))


(defn form-login-flow-wfn [f view-fn]
  (fn [{{:keys [username password]} :params :as req}]
    (if (and username password)
      (f (assoc req :credentials {:type :form, :username username, :password password}))
      (login-failed req view-fn ""))))


(defn prompt-consent-screen-wfn [f view-fn]
  (fn [{:keys [prompt service uri hidden-params] :as req}]
    (if (= prompt :consent)
      (consent-screen
        req view-fn (str "Redirect to " (:description service) " ?")
        [["Yes" (str uri "?" (cs/join "&" (for [[k v] hidden-params] (str (name k) "&" (ku/url-enc v)))))]
         ["No" (:url service)]])
      (f req))))


(defn service-lookup-wfn [f ticket-registry view-fn services svc-access-fn]
  "Performs service lookup (or redirect)."
  (fn [{:keys [service-url tgt] :as req}]
    (if-let [svc (service-lookup services service-url)]
      (let [r (assoc req :service svc)]
        (if (svc-access-fn r)
          (let [sid (kt/new-tid "ST"), svc-url (:service-url r)
                tkt {:type :svt :tid sid, :url svc-url :service svc :tgt (:tid tgt), :expended false, :timeout kt/ST-FRESH-TIMEOUT}]
            (kt/ref-ticket ticket-registry (:tid tgt) sid)
            (f (assoc r :svt (kt/new-object ticket-registry tkt))))
          (message-screen r view-fn :error "Service not allowed.")))
      (if service-url
        (message-screen req view-fn :error "Invalid service URL.")
        (message-screen req view-fn :ok "Login successful.")))))


(defmulti service-redirect "Renders redirect response from SSO to given service." :protocol)


(defmethod service-redirect :default [req]
  {:status 302
   :body "Redirecting to application ..."
   :headers {"Location" (:service-url req)}
   :cookies {"CASTGC" (ku/secure-cookie (:tid (:tgt req) ""))}})


(defmulti error-response "Renders error response from SSO. Depending on protocol it might be redirect or error screen." :protocol)


(defn login-failed [req msg]
  (assoc-in (dissoc req :principal) [:view-params :message] msg))



(defmethod error-response :default [{{:keys [error error_description]} :error :as req}]
  {:status 200
   :body   (str "Error occured: " error ": " error_description)})


(def ^:private ^ExecutorService logout-pool (Executors/newFixedThreadPool 16))


(defn service-logout [url {:keys [service tid] :as svt}]
  "Single Sign-Out.

  Arguments:
  url - URL to send;
  svt - service ticket (whole structure);
  "
  (.submit logout-pool
           ^Callable (cast Callable
                           (fn []
                             (log/debug "KCORE-I001: Logging out ticket" tid "from service" url)
                             (try+
                               (let [res (http/post
                                           url
                                           (into (:http-params service {})
                                                 {          ; TODO :form-params     {:logoutRequest (cas-logout-msg tid)}
                                                  :force-redirects false
                                                  :socket-timeout  5000
                                                  :conn-timeout    5000}))]
                                 (if (not (contains? #{200 202 301 302 304} (:status res)))
                                   (log/warn "KCORE-W001: Warning: cannot log out session " tid " from service " url ": " (str res))
                                   (log/debug "KCORE-I002: Successfully logged out session " tid " from service " url "->" (:status res))))
                               (catch Object e
                                 (log/error "KCORE-E001: Error logging out session from" url ":" (str e)))
                               )))))


(defmacro --> [& args]
  "Useful macro for defining chains of wrapper functions.
  This is equivalent of `->` with reversed argument order."
  (let [ra# (reverse args)]
    `(-> ~@ra#)))

