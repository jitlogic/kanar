(ns kanar.core
  (:require
    [taoensso.timbre :as log]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.protocol :as kp]
    [kanar.core.sec :as kcs]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [clj-http.client :as http])
  (:import (java.util.concurrent ExecutorService Executors)))


(defn audit [{audit-fn :audit-fn :as app-state} req tgt svc action]
  (if audit-fn
    (audit-fn app-state req tgt svc action)
    (log/report "AUDIT:" action "Principal: " (:princ tgt) "Service: " svc)))


(defn form-login-flow [auth-fn render-login-fn]
  "Simple login flow with login form."
  (fn [app-state {{:keys [dom username password service TARGET runas]} :params :as req}]
    (if (and username password)
      (try+
        (let [princ (auth-fn nil req)]
          (audit app-state req {:princ princ} nil :LOGIN-SUCCESS)
          princ)
        (catch [:type :login-failed] {msg :msg :as e}
          (audit app-state req nil nil :LOGIN-FAILED)
          (log/info "KCORE-I003: login failed" e)
          (ku/login-cont (render-login-fn :dom dom :username username :runas runas
                                          :error-msg msg :service service, :TARGET TARGET
                                          :req req, :app-state app-state))))
      (ku/login-cont (render-login-fn :dom dom :service service, :TARGET TARGET
                                      :req req, :app-state app-state)))))


(defn service-allowed [{svc-auth-fn :svc-auth-fn} req tgt svc svc-url]
  "Decides if user can access given service."
  (if svc-auth-fn
    (svc-auth-fn req tgt svc svc-url)
    true))


(defn kanar-service-lookup [services svc-url]
  (if svc-url
    (first
      (for [s services
            :when (re-matches (:url s) svc-url)]
        s))))


(defn kanar-service-redirect
  [{:keys [services ticket-registry render-message-view] :as app-state}
   {{:keys [service TARGET] :as params} :params :as req}
   tgt]
  (let [svc-url (or service TARGET)
        tid-param (if service "ticket" "SAMLart")
        svc-param (if service "service" "TARGET")]
    (let [svc (kanar-service-lookup services svc-url)]
      (cond
        (not svc)                                             ; case 1: service not found
        (do
          (if svc-url
            (audit app-state req tgt nil :SERVICE-TICKET-REJECTED))
          {:status  200
           :headers { "Content-Type" "text/html; charset=utf-8" }
           :body    (render-message-view :ok (if svc-url "Invalid service URL." "Login successful.")
                                         :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
           :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
        (not (service-allowed app-state req tgt svc svc-url)) ; case 2: service not allowed
        (do
          (audit app-state req tgt svc :SERVICE-TICKET-REJECTED)
          {:status  200
           :body    (render-message-view :error "Service not allowed." :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
           :headers {"Content-Type" "text/html; charset=utf-8"}
           :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
        (contains? params :warn)                              ; case 3: 'warn' parameter present
        {:status 200
         :headers {"Content-Type" "text/html; charset=utf-8"}
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}
         :body (render-message-view
                 :ok "Login succesful."
                 :url (str "login?" svc-param "=" (ku/url-enc svc-url))
                 :dom (:dom tgt)) :tgt tgt, :req req}
        :else                                                 ; case 4: no 'warn' parameter present
        (let [svt (kt/grant-st-ticket ticket-registry svc-url svc (:tid tgt))]
          (audit app-state req tgt svc :SERVICE-TICKET-GRANTED)
          {:status  302
           :body    (render-message-view :ok "Login succesful.", :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
           :headers {"Location"     (str svc-url (if (.contains svc-url "?") "&" "?") tid-param "=" (:tid svt))
                     "Content-Type" "text/html; charset=utf-8"}
           :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})))))


(defn login-internal
  [auth-flow-fn
   {:keys [ticket-registry services render-message-view] :as app-state}
   {{{CASTGC :value} "CASTGC"} :cookies,
    {:keys [renew gateway service TARGET]} :params :as req}]

  (let [tgc (kt/get-ticket ticket-registry CASTGC)
        svc-url (or service TARGET)]
    (cond
      (and (not tgc) (contains? kcs/BOOL_TRUE gateway))     ; Brak ticketu i parametr gateway
      (do
        (log/info "KCORE-I004: gateway redirect to" svc-url)
        (if (kanar-service-lookup services svc-url)
          {:status  302
           :headers {"Location" svc-url}
           :body    "Gateway redirect..."}
          {:status  200
           :headers {"Content-Type" "text/html; charset=utf-8"}
           :body    (render-message-view :error "Service not allowed.")}))
      (or renew (empty? tgc))                               ; brak ticketu lub parametr renew
      (do
        (let [tgt (kt/get-ticket ticket-registry CASTGC)]
          (if tgt
            (audit app-state req tgt nil :TGT-DESTROYED)
            (kt/clear-session ticket-registry CASTGC)))
        (try+
          (let [princ (auth-flow-fn app-state req)
                tgt (kt/grant-tgt-ticket ticket-registry princ)]
            (audit app-state req tgt nil :TGT-GRANTED)
            (kanar-service-redirect app-state req tgt))
          (catch [:type :login-cont] {:keys [resp]} resp)
          (catch [:type :login-failed] {:keys [resp]} resp)))
      :else                                                 ; jest ticket
      (kanar-service-redirect app-state req tgc))))



(defn login-handler [login-flow-fn app-state {{:as params} :params :as req}]
  "Handler for /login and /sulogin requests.

  Arguments:
  app-state - application state
  req - HTTP request
  auth-flow-fn - "
  (let [resp (login-internal login-flow-fn app-state req)]
    (if (and (contains? params :gateway) (not (contains? #{302 401} (:status resp))))
      {:status  302
       :body    "Redirecting ..."
       :headers {"Location" (:service params)}}
      resp)))

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


(defn logout-handler
  [{:keys [ticket-registry render-message-view] :as app-state}
   {{service :service} :params, {{CASTGC :value} "CASTGC"} :cookies :as req}]
  (let [tgt (kt/get-ticket ticket-registry CASTGC)]
    (when tgt
      (doseq [{{asu :app-urls} :service, url :url, :as svt} (kt/session-tickets ticket-registry (:tid tgt))
              :when (.startsWith (:tid svt) "ST")]
        (if (empty? asu)                                    ; TODO co z pozostałymi typami ticketów ?
          (service-logout url svt)
          (doseq [url asu] (service-logout url svt))))
      (kt/clear-session ticket-registry CASTGC)
      (audit app-state req tgt nil :TGT-DESTROYED))
    (if service
      {:status  302
       :body    "Redirecting to service"
       :headers {"Location" service, "Content-type" "text/html; charset=utf-8"}}
      {:status 200
       :headers {"Content-type" "text/html; charset=utf-8"}
       :body (render-message-view :ok "User logged out." :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)})))


(defn cas10-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :service sid :ticket} :params :as req}]
  (let [svt (kt/get-ticket ticket-registry sid)
        valid (and svc-url sid svt (re-matches #"ST-.*" sid) (not (:used svt)) (= svc-url (:url svt)))] ; TODO obsłużenie opcji 'renew'
    (if svt
      (kt/expend-ticket ticket-registry (:tid svt)))
    (audit app-state req nil nil (if valid :SERVICE-TICKET-VALIDATED :SERVICE-TICKET-NOT-VALIDATED))
    (log/trace "KCORE-D001: validating ticket" svt "-->" valid)
    (if valid
      (str "yes\n" (:id (:princ (:tgt svt))) "\n") "no\n")))

; TODO odsyłanie IOU przeniesc do innego modułu
; TODO wyprowadzić send-pgt-iou do głównego modułu
(defn send-pgt-iou [pgt-url tid iou]
  ; TODO configure IOU
  true)


(defn cas20-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :service sid :ticket pgt-url :pgtUrl} :params :as req}
   re-tid]
  (let [svt (kt/get-ticket ticket-registry sid)]
    (if svt
      (kt/expend-ticket ticket-registry (:tid svt)))
    (cond
      (empty? svc-url)
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'service' parameter; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_REQUEST" "Missing 'service' parameter."))
      (empty? sid)
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'ticket' parameter; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_REQUEST", "Missing 'ticket' parameter."))
      (not (re-matches re-tid sid))
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
      (or (empty? svt) (:used svt))
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
      (not= svc-url (:url svt))
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W004: cas20-validate-handler returns INVALID_SERVICE: Invalid service; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_SERVICE" "Invalid service."))
      (and (not (empty? pgt-url)) (= :svt (:type svt)))
        (if-let [pgt (kt/grant-pgt-ticket ticket-registry (:tid svt) pgt-url)]
          (do
            (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
            (log/info "KCORE-I005: cas20-validate-handler returns grant-pgt-ticket: PGT ticket granted; sid:" sid "url:" svc-url)
            (kp/cas20-validate-response svt pgt))
          (do
            (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
            (log/warn "KCORE-W005: cas20-validate-handler returns UNAUTHORIZED_SERVICE_PROXY: Cannot grant proxy ticket sid:" sid "url:" svc-url)
            (kp/cas20-validate-error "UNAUTHORIZED_SERVICE_PROXY" "Cannot grant proxy granting ticket.")))
      :else
        (do
          (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
          (log/info "KCORE-I006: cas20-validate-handler returns service-ticket-validated: Service ticket validated; sid:" sid "url:" svc-url)
          (kp/cas20-validate-response svt nil)))))


(defn proxy-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{pgt :pgt svc-url :targetService} :params :as req}]
  (let [ticket (kt/get-ticket ticket-registry pgt)]
    (cond
      (empty? pgt)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W006: proxy-handler returns INVALID_REQUEST: Missing 'pgt' parameter; pgt:" pgt "targetService:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'pgt' parameter."))
      (empty? svc-url)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W007: proxy-handler returns INVALID_REQUEST: Missing 'targetService' parameter; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'targetService' parameter."))
      (not (re-matches #"PGT-.*" pgt))
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W008: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
      (empty? ticket)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W009: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
      (not= svc-url (:url pgt))
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W010: proxy-handler returns BAD_PGT: Missing ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Invalid 'targetService' parameter."))
      :else
        (if-let [pt (kt/grant-pt-ticket ticket-registry pgt svc-url)]
          (do
            (audit app-state req nil nil :PROXY-TICKET-VALIDATED)
            (log/warn "KCORE-I007: proxy-handler returns SUCCESS: Ticket correctly validated; pgt:" pgt "url:" svc-url)
            (kp/cas20-proxy-success pt))
          (do
            (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
            (log/warn "KCORE-W011: proxy-handler returns BAD_PGT: Cannot grant proxy ticker; pgt:" pgt "url:" svc-url)
            (kp/cas20-proxy-failure "BAD_PGT" "Cannot grant proxy ticket."))))))


(defn saml-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :TARGET SAMLart :SAMLart} :params :as req}]
  (let [saml (body-string req)
        sid (or SAMLart (kp/saml-parse-lookup-tid saml))
        svt (kt/get-ticket ticket-registry sid)]
    (if svt
      (kt/expend-ticket ticket-registry (:tid svt)))
    (when-not (= svc-url (:url svt))
      (log/warn "KCORE-W012: Service and validation URL do not match: svc-url=" svc-url "but should be " (:url svt)))
    (if (and svc-url sid svt (not (:used svt)) (re-matches #"ST-.*" sid) ; TODO (= svc-url (:url svt))
             )
      (do
        (let [res (kp/saml-validate-response svt)]
          (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
          (log/trace "KCORE-T001: SAML response: " res)
          res))
      (do
        (log/warn "KCORE-W013: Service ticket NOT validated: svc-url=" svc-url "sid=" sid "svt=" svt " SAML=" saml)
        (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
        "Error executing SAML validation.\n"))))


