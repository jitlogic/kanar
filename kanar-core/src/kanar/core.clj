(ns kanar.core
  (:require
    [taoensso.timbre :as log]
    [clojure.inspector :refer [atom?]]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [clj-http.client :as http]
    [schema.core :as s]
    [clojure.string :as cs])
  (:import (java.util.concurrent ExecutorService Executors)
           (java.text SimpleDateFormat)
           (java.util Date)
           (clojure.lang IAtom)))

(def http-request-schema
  "Schema for base (filtered) HTTP request."
  {:uri s/Str
   :params s/Any
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
    {:protocol             (s/maybe (s/enum :cas :saml :oauth2 :radius)) ; SSO protocol used
     :subprotocol          (s/maybe s/Keyword)                           ; Subprotocol (eg. authentication protocol in RADIUS)
     :service-url          s/Str                                  ; URL to redirect back to service
     :credentials          s/Any                                  ; Login credentials
     :principal            sso-principal-schema                   ; Logged in principal
     :view-params          s/Any                                  ; Parameters for rendered views
     :hidden-params        s/Any                                  ; Hidden form parameters in rendered views
     :service-params       s/Any                                  ; SSO parameters passed
     :login                (s/enum :none :page)                   ; Login page display mode
     :prompt               (s/enum :none :consent)                ; SSO
     :sesctl               (s/enum :none :renew :login)           ; Whenever session should be renewed (user requthenticated)
     :tgt                  tgt-ticket-schema                      ; Ticket Granting Ticket
     :svt                  svt-ticket-schema                      ; Service Granting Ticket
     :service              s/Any                                  ; Service
     :otp-authenticated    (s/maybe s/Bool)                    ; TRUE if OTP authentication was attempted
     :spnego-authenticated (s/maybe s/Bool)                 ; TRUE if SPNEGO authentication was attempted
     :audit-log            s/Any                                  ; Audit log
     :trace-log            s/Any                                  ; Trace log
     }))


(def render-body-schema
  "Schema for body to be rendered."
  {:type     (s/enum :message :login-screen :select)   ; view type
   :params   {s/Keyword s/Any}                         ; view type specific parameters
   :hidden   {s/Keyword s/Any}                         ; hidden view parameters (eg. forwarded from previous request)
   :message  (s/maybe s/Str)                           ; message text
   :options  (s/maybe [[s/Any]])                       ; option list (for :select type)
   })


(defn screen
  ([req type msg]
    (screen req type msg {} {}))
  ([req type msg view-params]
    (screen req type msg view-params {}))
  ([req type msg view-params hidden-params]
   {:type    :response, :req req
    :status  200
    :body    {:type type,
              :view-params (into (:view-params req {}) view-params),
              :hidden-params (merge {} (:hidden-params req {}) hidden-params), :message msg}
    :headers {"Content-type" "text/html; charset=utf-8"}}))


(defn login-screen [req msg]
  {:type :response, :req req
   :status 200
   :body   {:type :login-screen,
            :view-params (:view-params req),
            :hidden-params (:hidden-params req), :message msg}
   :headers {"Content-type" "text/html; charset=utf-8"}})


(defn login-failed [req msg]
  (assoc (login-screen req msg) :login :failed))


(defn message-screen [{:keys [tgt] :as req} status msg & {:as view-params}]
  {:type    :response, :req req,
   :status  200
   :body    {:type :message, :status status, :message msg,
             :view-params (merge {} (:view-params req {}) (or view-params {}))}
   :headers {"Content-type" "text/html; charset=utf-8"}
   :cookies (if tgt {"CASTGC" (ku/secure-cookie (:tid tgt))} {})
   })


(defn consent-screen [{:keys [tgt] :as req} msg options]
  {:status 200
   :body {:type :select, :message msg,
          :view-params (:view-params req),
          :hidden-params (:hidden-params req) :options options}
   :headers {"Content-type" "text/html; charset=utf-8"}
   :cookies (if tgt {"CASTGC" (ku/secure-cookie (:tid tgt))} {})
   })


(defn service-lookup [services svc-url]
  (if svc-url
    (first
      (for [s services
            :when (re-matches (:url s) svc-url)]
        s))))


(def SANITIZE_KEYWORDS #{:password :newPassword :currentPassword :repeatPassword :token})


(defn sanitize-rec [r]
  (cond
    (instance? IAtom r) nil
    (vector? r) (vec (for [v r] (sanitize-rec v)))
    (list? r) (for [v r] (sanitize-rec v))
    (map? r) (into {} (for [[k v] r] {k (if (contains? SANITIZE_KEYWORDS k) "..." (sanitize-rec v))}))
    :else r))


(defn audit [r origin action status & {:as opts}]
  (let [audit-log (or (-> r :audit-log) (-> r :req :audit-log))]
    (if audit-log
      (swap! audit-log conj (merge {} opts {:action action, :origin origin, :req (:req r r),
                                            :when (ku/cur-time), :status status}))
      (log/error "No :audit-log attribute found in request-reply structure: " (sanitize-rec r))))
  r)


(def audit-record-schema
  {:action         s/Keyword
   :when           s/Num
   :who            (s/maybe s/Str)
   :tgt            (s/maybe s/Str)
   :service-url    (s/maybe s/Str)
   :source-ip      (s/maybe s/Str)
   :host           (s/maybe s/Str)

   })


(def DEFAULT-AUDIT-ATTR-DEFS
  {:who         [#(or (get-in % [:principal :id]) (get-in % [:params :username])) "<unknown>"]
   :service_url [:service-url]
   :service_id  [#(-> % :service :id)]
   :remote_addr [#(or (get (:headers %) "x-forwarded-for") (:remote-addr %))]
   :server-name [:server-name]
   :protocol    [:protocol]
   :principal   [#(get-in % [:principal :id])]
   :tgt         [#(-> % :tgt :tid)]
   :svt         [#(-> % :svt :tid)]
   :user_dn     [#(-> % :principal :dn)]
   :username    [#(-> % :params :username)]
   :user_login  [#(or (get-in % [:credentials :username]) (get-in % [:params :username]))]
   :spnego      [#(if (:spnego-authenticated %) 1 0)]
   :otp         [#(if (:otp-authenticated %) 1 0)]
   ; TODO ? user agent ?
   ; TODO :login, :prompt, :sesctl
   })

; TODO obsłużyć błędy walidacji parametrów formularza tak aby były logowane jako audit events
; :field - pole niewłaściwie wypełnione
; :msg - komunikat


(defn new-audit-record [attr-defs audit-rec lreq]
  (let [areq (:req audit-rec)]
    (into
      (dissoc audit-rec :req)
      (for [[attr [affn dv]] attr-defs :let [av (or (affn areq) (affn lreq) dv)] :when av]
        {attr av}))))


(defn audit-log-wfn
  ([f attr-defs & audit-fns]
   (fn [req]
     (let [audit-log (atom [])
           rslt (f (assoc req :audit-log audit-log))
           lreq (:req (last @audit-log))]
       (doseq [al @audit-log
               :let [al (new-audit-record attr-defs al lreq)]
               afn audit-fns]
         (afn al))
       rslt))))


(defn audit-file-output [path]
  (if path
    (do
      (log/info "Audit records will be logged to " path)
      (fn [rec]
        (locking path                                       ; ... so it will work within thread pools
          (spit
            (str path "." (.format (SimpleDateFormat. "yyyy-MM-dd") (Date.)))
            (str
              (.format
                (SimpleDateFormat. "yyyy-MM-dd HH:mm:ss.SSS ")
                (:tstamp rec (Date. (System/currentTimeMillis))))
              (pr-str (into (sorted-map) rec)) "\n")
            :append true))))
    (do
      (log/info "No path for local audit log specified. None will be logged.")
      (fn [_] nil))))


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


(defn tgt-lookup-wfn
  ([ticket-registry]
    (tgt-lookup-wfn identity ticket-registry))
  ([f ticket-registry]
   "WFN: Looks up for TGC ticket."
   (fn [{{{CASTGC :value} "CASTGC"} :cookies :keys [login sesctl] :as req}]
     (if (= :renew sesctl)
       (kt/delete-ticket ticket-registry CASTGC true))
     (if-let [tgt (and CASTGC (kt/get-ticket ticket-registry CASTGC))]
       (f (assoc req :tgt tgt :principal (:princ tgt)))
       (if (= login :none)
         {:status  302
          :body    "Redirecting to service ..."
          :headers {"Location" (:service-url req), "Content-type" "text/plain; charset=utf-8"}}
         (f req))))))


(defn login-flow-success [req]
  (assoc req :login :success))


(defn login-flow-wfn
  "WFN: Handles login flow if no user session was detected."
  ([ticket-registry lf]
    (login-flow-wfn identity ticket-registry lf))
  ([f ticket-registry lf]
   (fn [req]
     (if (:tgt req)
       (f req)
       (let [r (lf req)]
         (if (= :success (:login r))
           (let [tkt {:type :tgt, :tid (kt/new-tid "TGC"), :princ (:principal r), :timeout kt/TGT-TIMEOUT}]
             (-> (f (assoc r :tgt (kt/new-object ticket-registry tkt)))
                 (audit :login-flow-wfn :LOGIN :SUCCESS)
                 (audit :login-flow-wfn :TGT-GRANT :SUCCESS)))
           (if (= :failed (:login r))
             (audit r :login-flow-wfn :LOGIN :FAILED :cause (-> r :body :message))
             r)))))))


(defn form-login-flow-wfn [f]                               ; TODO tutaj wariant dla OAuth
  (fn [{{:keys [username password] :as params} :params :as req}]
    (if (and username password)
      (f (assoc req :credentials (into {:type :form} params)))
      (login-screen req nil))))


(defn multidomain-auth-wfn [& {:as dom-chains}]
  (fn [{{dom :dom} :params :as req}]
    (let [wfn (dom-chains dom)]
      (if (fn? wfn)
        (wfn req)
        (login-screen req "Invalid login domain.")))))


(defn log-principal-wfn
  ([msg]
    (log-principal-wfn identity msg))
  ([f msg]
   (fn [req]
     (log/debug msg (:principal req))
     (f req))))


(defn principal-id-wfn
  ([id-attr]
   (principal-id-wfn identity id-attr))
  ([f id-attr]
   (fn [{:keys [principal] :as req}]
     (if-let [id (get (:attributes principal) id-attr)]
       (f (assoc-in req [:principal :id] id))
       (login-failed req "Cannot obtain user data.")))))


(defn const-principal-attrs-wfn [f & {:as attrs}]
  "Sets some (constant) principal attributes to a request."
  (fn [req]
    (f
      (assoc-in
        req
        [:principal :attributes]
        (into (-> req :principal (:attributes {})) attrs)))))


(defn auth-domain-wfn
  "Sets principal's authentication domain to the one passed by parameters (or default-dom if no one was passed)"
  ([default-dom]
    (auth-domain-wfn identity default-dom))
  ([f default-dom]
   (fn [req]
     (f (assoc-in req [:principal :dom]
                  (-> req :params (:dom default-dom)))))))


(defn parse-domain-auth-wfn
  ([dom-map ddom]
    (parse-domain-auth-wfn identity dom-map ddom))
  ([f dom-map ddom]
   (fn [{{id :id idom :dom} :principal {dom :dom} :params :as req}]
     (let [[un & [ud & _]] (clojure.string/split id #"@")]
       (f (assoc-in req [:principal] {:id un, :attributes {}, :dom (or (dom-map ud) idom dom ddom)}))))))


(defn prompt-consent-screen-wfn
  ([] (prompt-consent-screen-wfn identity))
  ([f]
   (fn [{:keys [prompt service uri hidden-params] :as req}]
     (if (= prompt :consent)
       (consent-screen
         req (str "Redirect to " (:description service) " ?")
         [["Yes" (str uri "?" (cs/join "&" (for [[k v] hidden-params] (str (name k) "&" (ku/url-enc v)))))]
          ["No" (:url service)]])
       (f req)))))


(defn service-lookup-wfn
  "Performs service lookup (or redirect)."
  ([ticket-registry services svc-access-fn]
    (service-lookup-wfn identity ticket-registry services svc-access-fn))
  ([f ticket-registry services svc-access-fn]
   (fn [{:keys [service-url tgt] :as req}]
     (if-let [svc (service-lookup services service-url)]
       (let [r (assoc req :service svc)]
         (if (svc-access-fn r)
           (let [sid (kt/new-tid "ST"), svc-url (:service-url r)
                 tkt {:type :svt :tid sid, :url svc-url :service svc :tgt (:tid tgt), :expended false, :timeout kt/ST-FRESH-TIMEOUT}]
             (kt/ref-ticket ticket-registry (:tid tgt) sid)
             (-> (f (assoc r :svt (kt/new-object ticket-registry tkt)))
                 (audit :service-lookup-wfn :SVT-GRANT :SUCCESS)))
           (-> (message-screen r :error "Service not allowed.")
               (audit :service-lookup-wfn :SVT-GRANT :FAILED))))
       (if service-url
         (let [req (assoc req :service_url service-url)]
           (-> (message-screen req :error "Invalid service URL.")
               (audit :service-lookup-wfn :SVT-GRANT :FAILED)))
         (message-screen req :ok "Login successful."))))))


(defmulti service-redirect "Renders redirect response from SSO to given service." :protocol)


(defmethod service-redirect :default [req]
  {:status 302
   :body "Redirecting to application ..."
   :headers {"Location" (:service-url req)}
   :cookies {"CASTGC" (ku/secure-cookie (:tid (:tgt req) ""))}})


(defmulti error-response "Renders error response from SSO. Depending on protocol it might be redirect or error screen." :protocol)


(defmethod error-response :default [{{:keys [error error_description]} :error :as req}]
  {:status 200
   :body   (str "Error occured: " error ": " error_description)})


(def ^:private ^ExecutorService logout-pool (Executors/newFixedThreadPool 16))



(defn service-logout [url {:keys [service tid]}]
  "Single Sign-Out.

  Arguments:
  url - URL to send;
  svt - service ticket (whole structure);
  "
  (.submit logout-pool                                      ; TODO użyć async-pooled zamiast rękodzielniczej puli
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
  `(-> ~@(reverse args)))


(defn format-trace-rec [{:keys [req res tstamp type tags]}]
  (let [sf (SimpleDateFormat. "yyyy-MM-dd HH:mm:ss.SSS")]
    (str
      (.format sf (Date. ^Long tstamp))
      " " (name type)
      " " (cs/join "," (map name tags))
      " " (pr-str (or req res)))))


(defn trace
  ([tags]
    (trace identity tags))
  ([f tags]
   (fn [{:keys [trace-log] :as req}]
     (when (instance? IAtom trace-log)
       (swap! trace-log conj {:type :ENTER, :tstamp (ku/cur-time), :tags (set tags), :req req}))
     (let [res (f req)]
       (when (instance? IAtom trace-log)
         (swap! trace-log conj {:type :EXIT, :tstamp (ku/cur-time), :tags (set tags), :res res}))
       res))))


(defn trace-begin-wfn [f]
  (fn [{:keys [trace-log] :as req}]
    (f (assoc req :trace-log (or trace-log (atom []))))))


(defn trace-log-wfn
  ([conf] (trace-log-wfn identity conf))
  ([f {:keys [enabled filter path] :or {enabled false}}]
   (if (and filter path enabled)
     (try
       (log/info "Enabling trace log filtering: " filter)
       (let [cond-fn (eval `(fn [~'r] ~filter))]
         (fn [{:keys [trace-log] :as req}]
           (let [rslt (f req), r (ku/combine-maps (sanitize-rec req) (sanitize-rec (:req rslt)))]
             (try
               (when (cond-fn r)
                 (let [trace (for [r @trace-log] (-> r sanitize-rec format-trace-rec))
                       trace (when (instance? IAtom trace-log) (cs/join "\n" trace))
                       tst (.format (SimpleDateFormat. "yyyy-MM-dd HH:mm:ss.SSS ") (Date. (System/currentTimeMillis)))]
                   (locking path (spit path (str tst " REQUEST: " (:uri r) "  " r "\n" trace "\n\n") :append true))))
               (catch Throwable e
                 (log/error "Error capturing trace: " (ku/error-with-trace e))))
             rslt)))
       (catch Throwable e
         (log/error "Error configuring request trace. Tracing will be disabled. " (ku/error-with-trace e)) f))
     f)))

; TODO macro (traced--> log-level x & forms)


(defn traced-fn [tags expr]
  (if (symbol? expr)
    [expr `(trace ~(into [(keyword (name expr))] tags))]
    (let [[f & args] expr]
      [(cons f (if (nil? (first args)) (rest args) args))
       `(trace ~(into [(keyword (name f))] tags))])))


(defmacro traced--> [tags & fns]
  (let [body (mapcat (partial traced-fn tags) (reverse fns))]
    `(-> ~@body)))

