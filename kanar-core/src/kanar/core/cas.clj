(ns kanar.core.cas
  (:require
    [kanar.core :refer :all]
    [kanar.core.util :as ku]
    [taoensso.timbre :as log]
    [clojure.data.xml :as xml]
    [kanar.core.ticket :as kt]
    [ring.util.request :refer [body-string]]
    [slingshot.slingshot :refer [try+ throw+]]
    [kanar.core :as kc]
    [schema.core :as s]
    ))


(def cas-params-schema
  {:service s/Str
   :TARGET s/Str
   :warn s/Str
   :gateway s/Str
   :renew s/Str
   })


(def cas-sso-request-schema
  (merge
    kc/sso-request-schema
    {:cas-params cas-params-schema}))


(defn parse-cas-req [{{:keys [service TARGET gateway renew warn]} :params hp :hidden-params :as req}]
  (let [login (if gateway :none :page)
        prompt (if warn :consent :none)
        sesctl (if renew :renew :none)
        r1 (merge req {:protocol :cas, :login login, :prompt prompt, :sesctl sesctl})]
    (cond
      service (merge r1 {:subprotocol :cas, :service-url service :hidden-params (merge {:service service} hp)})
      TARGET (merge r1 {:subprotocol :saml, :service-url TARGET :hidden-params (merge {:TARGET TARGET} hp)})
      :else nil)))


(defmethod service-redirect :cas [{:keys [subprotocol service-url tgt svt] :as req}]
  (let [suffix (str (if (= subprotocol :cas) "ticket=" "SAMLart=") (:tid svt))]
    {:status  302
     :body    "Redirecting to CAS service ..."
     :req     req
     :headers {"Location" (str service-url (if (.contains service-url "?") "&" "?") suffix)}
     :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}}))





; Old stuff, to be removed soon


(defn cas-logout-handler-wfn [ticket-registry]
  (fn [{{service :service} :params, {{CASTGC :value} "CASTGC"} :cookies :as req}]
    (let [tgt (kt/get-ticket ticket-registry CASTGC)
          req (assoc req :tgt tgt :principal (:princ tgt))]
      (when tgt
        (doseq [{{asu :app-urls :as service} :service, url :url, :as svt} (kt/session-tickets ticket-registry (:tid tgt))
                :when (.startsWith (:tid svt) "ST")]
          (audit (assoc req :svt svt, :service service, :service-url url)
                 :logout-handler :SVT-DESTROY :SUCCESS :protocol :cas )
          (if (empty? asu)                                  ; TODO co z pozostałymi typami ticketów ?
            (service-logout url svt)
            (doseq [url asu]
              (service-logout url svt))))
        (kt/delete-ticket ticket-registry CASTGC)
        (audit req :logout-handler :TGT-DESTROY :SUCCESS :protocol :cas))
      (if service
        {:status  302
         :body    "Redirecting to service"
         :headers {"Location" service, "Content-type" "text/html; charset=utf-8"}}
        (kc/message-screen req :ok "User logged out.")))))


(defn cas10-validate-handler-wfn [ticket-registry]
  (fn [{{svc-url :service sid :ticket} :params :as req}]
    (let [{:keys [ctime timeout tgt service] :as svt} (kt/get-ticket ticket-registry sid)
          {:keys [princ] :as tgt} (if tgt (kt/get-ticket ticket-registry tgt))
          req (into req {:tgt tgt, :svt svt, :service service, :principal princ, :service-url (:url svt)})
          valid (and svc-url sid svt
                     (re-matches #"ST-.*" sid)
                     (not (:expended svt))
                     (= svc-url (:url svt))
                     (< (ku/cur-time) (+ ctime timeout)))] ; TODO obsłużenie opcji 'renew'
      (when svt
        (kt/update-ticket ticket-registry sid {:expended true}))
      (audit (into req {:tgt tgt, :svt svt, :service service, :service_url (:service-url svt)})
             :cas10-validate-handler :SVT-VALIDATE (if valid :SUCCESS :FAIL)) ; TODO dopisać cause itd. do audit rekordu
      (log/trace "KCORE-D001: validating ticket" svt "-->" valid)
      (if valid
        (let [tgt (kt/get-ticket ticket-registry (:tgt svt))]
          (str "yes\n" (:id (:princ tgt)) "\n")) "no\n"))))


; TODO odsyłanie IOU przeniesc do innego modułu
; TODO wyprowadzić send-pgt-iou do głównego modułu
(defn send-pgt-iou [pgt-url tid iou]
  ; TODO configure IOU
  true)


(defn saml-validate-request [tid]
  (let [t1 (ku/xml-time (ku/cur-time))]
    (ku/emit-xml
      [:SOAP-ENV:Envelope {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope"}
       [:SOAP-ENV:Header]
       [:SOAP-ENV:Body
        [:samlp:Request {:xmlns:samlp  "urn:oasis:names:tc:SAML:1.0:protocol"
                         :MajorVersion "1" :MinorVersion "1"
                         :RequestID    "_192.168.16.51.1024506224022"
                         :IssueInstant t1}
         [:samlp:AssertionArtifact tid]]]])))


(defn saml-validate-response [princ svt]
  (let [t1 (ku/xml-time (ku/cur-time)), t2 (ku/xml-time (+ 30000 (ku/cur-time)))]
    (ku/emit-xml
      [:SOAP-ENV:Envelope {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope/"}
       [:SOAP-ENV:Body
        [:saml1p:Response {:xmlns:saml1p  "urn:oasis:names:tc:SAML:1.0:protocol"
                           :IssueInstant t1
                           :MajorVersion "1" :MinorVersion "1"
                           :Recipient    (:url svt)
                           :ResponseID   (str "_" (ku/random-string 32))}
         [:saml1p:Status [:saml1p:StatusCode {:Value "saml1p:Success"}]]
         [:saml1:Assertion
          {:xmlns:saml1        "urn:oasis:names:tc:SAML:1.0:assertion"
           :AssertionID  (str "_" (ku/random-string 32))
           :IssueInstant t1
           :Issuer       "localhost"     ; TODO place correct service name
           :MajorVersion "1" :MinorVersion "1"}
          [:saml1:Conditions {:NotBefore t1, :NotOnOrAfter t2}
           [:saml1:AudienceRestrictionCondition [:saml1:Audience (:url svt)]]]
          [:saml1:AuthenticationStatement
           {:AuthenticationInstant t1
            :AuthenticationMethod  "urn:oasis:names:tc:SAML:1.0:am:unspecified"}
           [:saml1:Subject
            [:saml1:NameIdentifier (:id princ)]
            [:saml1:SubjectConfirmation
             [:saml1:ConfirmationMethod "urn:oasis:names:tc:SAML:1.0:cm:artifact"]]]]
          [:saml1:AttributeStatement
           [:saml1:Subject
            [:saml1:NameIdentifier (:id princ)]
            [:saml1:SubjectConfirmation
             [:saml1:ConfirmationMethod "urn:oasis:names:tc:SAML:1.0:cm:artifact"]]]
           (for [[k v] (ku/get-svt-attrs princ svt)]
             (if (or (vector? v) (list? v) (seq? v))
               (if-not (empty? v)
                 [:saml1:Attribute {:AttributeName (name k) :AttributeNamespace "http://www.ja-sig.org/products/cas"}
                  (for [x v] [:saml1:AttributeValue (str x)])])
               [:saml1:Attribute {:AttributeName (name k) :AttributeNamespace "http://www.ja-sig.org/products/cas"}
                [:saml1:AttributeValue (str v)]]))]
          ]]]])))


; TODO potential security concern: stack overflow if parsed XML is too deep
; TODO zastąpić to przez xml-to-map
(defn saml-lookup-tid [{:keys [tag content]}]
  (if (= :AssertionArtifact tag)
    (first content)
    (first
      (for [el content
            :when (:tag el)
            :let [tid (saml-lookup-tid el)]
            :when tid]
        tid))))


(defn saml-parse-lookup-tid [body]
  (saml-lookup-tid (xml/parse-str body)))


(defn- cas20 [o]
  (ku/emit-xml [:cas:serviceResponse {:xmlns:cas "http://yale.edu/tp/cas"} o]))


(defn cas-logout-msg [svt]
  (ku/emit-xml
    [:samlp:LogoutRequest {:xmlns:samlp  "urn:oasis:names:tc:SAML:2.0:protocol"
                           :ID           (ku/random-string 32) :Version "2.0"
                           :IssueInstant (ku/xml-time (ku/cur-time))}
     [:saml:NameID {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"} "@NOT_USED@"]
     [:samlp:SessionIndex svt]]))


(defn cas20-validate-error [code msg]
  (cas20 [:cas:authenticationFailure {:code code} msg]))


(defn v2s [v]
  (cond
    (keyword? v) (name v)
    :else (str v)))


; TODO dotestować porządnie serializację i parsowanie CAS20
(defn cas20-validate-response
  [{:keys [princ] :as tgt}
   svt
   {iou :iou}]
  (let [attrs (ku/get-svt-attrs princ svt)]
    (cas20
      [:cas:authenticationSuccess
       [:cas:user (:id princ)]
       (if iou [:cas:proxyGrantingTicket iou])
       (if-not (empty? attrs)
         [:cas:attributes
          (for [[k v] attrs]
            (if (vector? v)
              (for [vv v]
                [(keyword (str "cas" k)) (v2s vv)])
              [(keyword (str "cas" k)) (v2s v)]))])])))


(defn cas20-parse-response [r]
  ; TODO NOT good implementation - fix this and test thoroughly
  (let [[un {an :content}] (-> (xml/parse-str r) :content first :content)
        at (for [{t :tag c :content} an] [t (first c)])
        ag (for [[k [v & vs :as vv]] (group-by first at)]
             {k (if vs
                  (vec (map second vv))
                  (second v))})]
    {:id         (-> un :content first)
     :attributes (into {} ag)
     }))


(defn cas20-proxy-success [{tid :tid}]
  (cas20 [:cas:proxySuccess [:cas:proxyTicket tid]]))


(defn cas20-proxy-failure [code msg]
  (cas20 [:cas:proxyFailure {:code code} msg]))

; TODO przejść na 'renderowany' chain podobny do login chainu
(defn cas20-validate-handler-wfn [ticket-registry re-tid]
  (fn [{{svc-url :service sid :ticket pgt-url :pgtUrl} :params :as req}]
    (let [{:keys [ctime timeout tgt service] :as svt} (kt/get-ticket ticket-registry sid)
          {:keys [princ] :as tgt} (if tgt (kt/get-ticket ticket-registry tgt))
          req (into req {:tgt tgt, :svt svt, :service service, :principal princ, :service-url (:url svt)})]
      (if svt
        (kt/update-ticket ticket-registry (:tid svt) {:expended true}))
      (cond
        (empty? svc-url)
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "INVALID_REQUEST" "Missing 'service' parameter.")
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'service' parameter; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_REQUEST" "Missing 'service' parameter."))
        (empty? sid)
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "Missing 'ticket' parameter.")
          (log/warn "KCORE-W002: cas20-validate-handler returns INVALID_REQUEST: Missing 'ticket' parameter; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_REQUEST", "Missing 'ticket' parameter."))
        (not (re-matches re-tid sid))
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "Invalid ticket (SID does not conform).", :svt sid)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID_TICKET_SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
        (or (empty? svt) (:expended svt))
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "Invalid ticket (such ticket not found).", :svt sid)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
        (> (ku/cur-time) (+ ctime timeout))
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "Invalid ticket (ticket expired).", :svt sid)
          (log/warn "KCORE-W003: cas20-validate-handler returns INVALID-TICKET-SPEC: Invalid ticket; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
        (not= svc-url (:url svt))
        (do
          (audit req :cas20-validate-handler :SVT-VALIDATE :FAIL :cause "Invalid ticket (service URL does not match).",
                 :svt sid, :service_url svc-url)
          (log/warn "KCORE-W004: cas20-validate-handler returns INVALID_SERVICE: Invalid service; sid:" sid "url:" svc-url)
          (cas20-validate-error "INVALID_SERVICE" "Invalid service."))
        (and (not (empty? pgt-url)) (= :svt (:type svt)))
        (let [pid (kt/new-tid "PGT"), iou (kt/new-tid "PGTIOU"),
              pgt {:type :pgt, :tid pid, :iou iou, :url pgt-url, :service (:service svt), :svt sid, :timeout kt/ST-EXPENDED-TIMEOUT}
              tgt (kt/get-ticket ticket-registry (:tgt svt))]
          (do
            ; TODO send IOU here
            ; TODO audit trail here
            (kt/new-object ticket-registry pgt)
            ;(audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
            (log/info "KCORE-I005: cas20-validate-handler returns grant-pgt-ticket: PGT ticket granted; sid:" sid "url:" svc-url)
            (cas20-validate-response tgt svt pgt)))
        :else
        (let [tgt (kt/get-ticket ticket-registry (:tgt svt))]
          (audit req :cas20-validate-handler :SVT-VALIDATE :SUCCESS)
          (log/debug "KCORE-I006: cas20-validate-handler returns service-ticket-validated: Service ticket validated; sid:" sid "url:" svc-url)
          (cas20-validate-response tgt svt nil))))))


(defn proxy-handler [ticket-registry]
  (fn [{{pgt :pgt svc-url :targetService} :params :as req}]
    (let [ticket (kt/get-ticket ticket-registry pgt)]
      (cond
        (empty? pgt)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W006: proxy-handler returns INVALID_REQUEST: Missing 'pgt' parameter; pgt:" pgt "targetService:" svc-url)
          (cas20-proxy-failure "INVALID_REQUEST" "Missing 'pgt' parameter."))
        (empty? svc-url)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W007: proxy-handler returns INVALID_REQUEST: Missing 'targetService' parameter; pgt:" pgt "url:" svc-url)
          (cas20-proxy-failure "INVALID_REQUEST" "Missing 'targetService' parameter."))
        (not (re-matches #"PGT-.*" pgt))
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W008: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
        (empty? ticket)
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W009: proxy-handler returns BAD_PGT: Invalid ticket; pgt:" pgt "url:" svc-url)
          (cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
        (not= svc-url (:url pgt))
        (do
          ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (log/warn "KCORE-W010: proxy-handler returns BAD_PGT: Missing ticket; pgt:" pgt "url:" svc-url)
          (cas20-proxy-failure "INVALID_REQUEST" "Invalid 'targetService' parameter."))
        :else
        (let [tid (kt/new-tid "PT"),
              pxt {:type :pt, :tid tid, :url svc-url, :service (:service pgt), :pgt (:tid pgt), :timeout kt/ST-FRESH-TIMEOUT}]
          (do
            (kt/new-object ticket-registry pxt)
            ;(audit app-state req nil nil :PROXY-TICKET-VALIDATED)
            ; TODO audit trail here
            (log/warn "KCORE-I007: proxy-handler returns SUCCESS: Ticket correctly validated; pgt:" pgt "url:" svc-url)
            (cas20-proxy-success pxt))
          ;(do
          ;  ;(audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          ;  (log/warn "KCORE-W011: proxy-handler returns BAD_PGT: Cannot grant proxy ticker; pgt:" pgt "url:" svc-url)
          ;  (cas20-proxy-failure "BAD_PGT" "Cannot grant proxy ticket."))
          )))))


(defn saml-validate-handler-wfn [ticket-registry]
  (fn [{{svc-url :TARGET SAMLart :SAMLart} :params :as req}]
    (let [saml (body-string req)
          sid (or SAMLart (saml-parse-lookup-tid saml))
          {:keys [ctime timeout tgt service] :as svt} (kt/get-ticket ticket-registry sid)   ; TODO zbadać timeout podczas walidacji ticketu
          {:keys [princ] :as tgt} (if tgt (kt/get-ticket ticket-registry tgt))
          req (into req {:tgt tgt, :svt svt, :service service, :principal princ, :service-url (:url svt)})]
      (when svt
        (kt/update-ticket ticket-registry sid {:expended true}))
      (when-not (= svc-url (:url svt))
        (log/warn "KCORE-W012: Service and validation URL do not match: svc-url=" svc-url "but should be " (:url svt)))
      (if (and svc-url sid (re-matches #"ST-.*" sid) svt (not (:expended svt))  ; TODO (= svc-url (:url svt))
               )
        (do
          (let [res (saml-validate-response (:princ tgt) svt)]
            (audit req :saml11-validate-handler :SVT-VALIDATE :SUCCESS)
            (log/trace "KCORE-T001: SAML response: " res)
            res))
        (do
          (log/warn "KCORE-W013: Service ticket NOT validated: svc-url=" svc-url "sid=" sid "svt=" svt " SAML=" saml)
          (audit req :saml11-validate-handler :SVT-VALIDATE :FAILURE)
          "Error executing SAML validation.\n")))))


