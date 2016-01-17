(ns kanar.core.cas
  (:require
    [kanar.core :refer :all]
    [kanar.core.util :as ku]
    [taoensso.timbre :as log]
    [kanar.core.ticket :as kt]
    [kanar.core.sec :as kcs]
    [kanar.core.protocol :as kp]
    [ring.util.request :refer [body-string]]
    [slingshot.slingshot :refer [try+ throw+]]
    [kanar.core :as kc]))


(defn parse-cas-req [{{:keys [service TARGET]} :params :as req}]
  (cond
    service (merge req {:protocol :cas, :subprotocol :cas, :service-url service :hidden-params {:service service}})
    TARGET  (merge req {:protocol :cas, :subprotocol :saml, :service-url TARGET :hidden-params {:TARGET TARGET}})
    :else   nil))


(defmethod service-redirect :cas [{:keys [subprotocol service-url tgt svt] :as req}]
  (let [suffix (str (if (= subprotocol :cas) "ticket=" "SAMLart=") (:tid svt))]
    {:status  302
     :body    "Redirecting ..."
     :headers {"Location" (str service-url (if (.contains service-url "?") "&" "?") suffix)}
     :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}}))





; Old stuff, to be removed soon


(defn logout-handler [ticket-registry view-fn]
  (fn [{{service :service} :params, {{CASTGC :value} "CASTGC"} :cookies :as req}]
    (let [tgt (kt/get-ticket ticket-registry CASTGC)]
      (when tgt
        (doseq [{{asu :app-urls} :service, url :url, :as svt} (kt/session-tickets ticket-registry (:tid tgt))
                :when (.startsWith (:tid svt) "ST")]
          (if (empty? asu)                                  ; TODO co z pozostałymi typami ticketów ?
            (service-logout url svt)
            (doseq [url asu] (service-logout url svt))))
        (kt/clear-session ticket-registry CASTGC)
        ;(audit app-state req tgt nil :TGT-DESTROYED) ; TODO uzupełnić audit trail
        )
      (if service
        {:status  302
         :body    "Redirecting to service"
         :headers {"Location" service, "Content-type" "text/html; charset=utf-8"}}
        {:status  200
         :headers {"Content-type" "text/html; charset=utf-8"}
         :body    (kc/message-screen req view-fn :ok "User logged out.")}))))


(defn cas10-validate-handler [ticket-registry]
  (fn [{{svc-url :service sid :ticket} :params :as req}]
    (let [svt (kt/get-ticket ticket-registry sid)
          valid (and svc-url sid svt (re-matches #"ST-.*" sid) (not (:used svt)) (= svc-url (:url svt)))] ; TODO obsłużenie opcji 'renew'
      (if svt
        (kt/expend-ticket ticket-registry (:tid svt)))
      ;(audit app-state req nil nil (if valid :SERVICE-TICKET-VALIDATED :SERVICE-TICKET-NOT-VALIDATED)) ; TODO uzupełnić audit trail
      (log/trace "KCORE-D001: validating ticket" svt "-->" valid)
      (if valid
        (str "yes\n" (:id (:princ (:tgt svt))) "\n") "no\n"))))


; TODO odsyłanie IOU przeniesc do innego modułu
; TODO wyprowadzić send-pgt-iou do głównego modułu
(defn send-pgt-iou [pgt-url tid iou]
  ; TODO configure IOU
  true)


(defn cas20-validate-handler [ticket-registry re-tid]
  (fn [{{svc-url :service sid :ticket pgt-url :pgtUrl} :params :as req}]
    (let [svt (kt/get-ticket ticket-registry sid)]
      (if svt
        (kt/expend-ticket ticket-registry (:tid svt)))
      (cond
        (empty? svc-url)
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'service' parameter; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_REQUEST" "Missing 'service' parameter."))
        (empty? sid)
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'ticket' parameter; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_REQUEST", "Missing 'ticket' parameter."))
        (not (re-matches re-tid sid))
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
        (or (empty? svt) (:used svt))
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
        (not= svc-url (:url svt))
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W004: cas20-validate-handler returns INVALID_SERVICE: Invalid service; sid:" sid "url:" svc-url)
          (kp/cas20-validate-error "INVALID_SERVICE" "Invalid service."))
        (and (not (empty? pgt-url)) (= :svt (:type svt)))
        (if-let [pgt (kt/grant-pgt-ticket ticket-registry (:tid svt) pgt-url)]
          (do
            ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
            (log/info "KCORE-I005: cas20-validate-handler returns grant-pgt-ticket: PGT ticket granted; sid:" sid "url:" svc-url)
            (kp/cas20-validate-response svt pgt))
          (do
            ;(audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
            (log/warn "KCORE-W005: cas20-validate-handler returns UNAUTHORIZED_SERVICE_PROXY: Cannot grant proxy ticket sid:" sid "url:" svc-url)
            (kp/cas20-validate-error "UNAUTHORIZED_SERVICE_PROXY" "Cannot grant proxy granting ticket.")))
        :else
        (do
          ;(audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
          (log/info "KCORE-I006: cas20-validate-handler returns service-ticket-validated: Service ticket validated; sid:" sid "url:" svc-url)
          (kp/cas20-validate-response svt nil))))))


(defn proxy-handler [ticket-registry]
  (fn [{{pgt :pgt svc-url :targetService} :params :as req}]
    (let [ticket (kt/get-ticket ticket-registry pgt)]
      (cond
        (empty? pgt)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W006: proxy-handler returns INVALID_REQUEST: Missing 'pgt' parameter; pgt:" pgt "targetService:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'pgt' parameter."))
        (empty? svc-url)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W007: proxy-handler returns INVALID_REQUEST: Missing 'targetService' parameter; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'targetService' parameter."))
        (not (re-matches #"PGT-.*" pgt))
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W008: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
        (empty? ticket)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W009: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
        (not= svc-url (:url pgt))
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W010: proxy-handler returns BAD_PGT: Missing ticket; pgt:" pgt "url:" svc-url)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Invalid 'targetService' parameter."))
        :else
        (if-let [pt (kt/grant-pt-ticket ticket-registry pgt svc-url)]
          (do
            ;(audit app-state req nil nil :PROXY-TICKET-VALIDATED)
            (log/warn "KCORE-I007: proxy-handler returns SUCCESS: Ticket correctly validated; pgt:" pgt "url:" svc-url)
            (kp/cas20-proxy-success pt))
          (do
            ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
            (log/warn "KCORE-W011: proxy-handler returns BAD_PGT: Cannot grant proxy ticker; pgt:" pgt "url:" svc-url)
            (kp/cas20-proxy-failure "BAD_PGT" "Cannot grant proxy ticket.")))))))


(defn saml-validate-handler [ticket-registry]
  (fn [{{svc-url :TARGET SAMLart :SAMLart} :params :as req}]
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
            ;(audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
            (log/trace "KCORE-T001: SAML response: " res)
            res))
        (do
          (log/warn "KCORE-W013: Service ticket NOT validated: svc-url=" svc-url "sid=" sid "svt=" svt " SAML=" saml)
          ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          "Error executing SAML validation.\n")))))


