(ns kanar.core
  (:require
    [taoensso.timbre :as log]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.protocol :as kp]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [clj-http.client :as http]
    [schema.core :as s])
  (:import (java.util.concurrent ExecutorService Executors)))


(def sso-principal-schema
  "Defines SSO principal"
  {:id s/Str                                                ; principal ID
   :attributes s/Any                                        ; Principal attributes
   :dn s/Str                                                ; DN (for LDAP principals)
   :dom s/Keyword                                           ; Authentication domain (optional - for multidomain setups)
   })


(def sso-request-schema
  "Schema for parsed SSO request data. This is extention to standard http request data."
  {:protocol (s/enum :cas :saml :oauth2)                    ; SSO protocol used
   :service-url s/Str                                       ; URL to redirect back to service
   :credentials s/Any                                       ; Login credentials
   :principal sso-principal-schema                          ; Logged in principal
   :view-params s/Any                                       ; Parameters for rendered views
   :hidden-params s/Any                                     ; Hidden form parameters in rendered views
   :service-params s/Any                                    ; SSO parameters passed
   :tgt s/Any                                               ; Ticket Granting Ticket
   :svt s/Any                                               ; Service Granting Ticket
   :service s/Any                                           ; Service
   })


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
  (fn [r]
    (let [sso-reqs (for [pfn pfns :let [v (pfn r)]] v)
          sso-req (first sso-reqs)]
      (f (merge r (or sso-req {:protocol :none}))))))


(defn tgt-lookup-wfn [f ticket-registry]
  "WFN: Looks up for TGC ticket."
  (fn [{{{CASTGC :value} "CASTGC"} :cookies {:keys [gateway]} :params :as req}]
    (if-let [tgt (and CASTGC (kt/get-ticket ticket-registry CASTGC))]
      (f (assoc req :tgt tgt))
      (if gateway
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
        (if (:principal r)
          (f (assoc r :tgt (kt/grant-tgt-ticket ticket-registry (:principal r))))
          r)))))


(defn form-login-flow-wfn [f view-fn]
  (fn [{{:keys [username password]} :params :as req}]
    (if (and username password)
      (f (assoc req :credentials {:type :form, :username username, :password password}))
      (login-failed req view-fn ""))))


(defn service-lookup-wfn [f ticket-registry view-fn services svc-access-fn]
  "Performs service lookup (or redirect)."
  (fn [{:keys [service-url tgt] :as req}]
    (if-let [svc (service-lookup services service-url)]
      (let [r (assoc req :service svc)]
        (if (svc-access-fn r)
          (f (assoc r :svt (kt/grant-st-ticket ticket-registry (:service-url r) svc (:tid tgt))))
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
                                                 {:form-params     {:logoutRequest (kp/cas-logout-msg tid)}
                                                  :force-redirects false
                                                  :socket-timeout  5000
                                                  :conn-timeout    5000}))]
                                 (if (not (contains? #{200 202 301 302 304} (:status res)))
                                   (log/warn "KCORE-W001: Warning: cannot log out session " tid " from service " url ": " (str res))
                                   (log/debug "KCORE-I002: Successfully logged out session " tid " from service " url "->" (:status res))))
                               (catch Object e
                                 (log/error "KCORE-E001: Error logging out session from" url ":" (str e)))
                               )))))










