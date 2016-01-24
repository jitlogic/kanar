(ns kanar.core.oauth
  "Support for OAuth 2.0 + OpenID Core 1.0 protocol stack.
   This implementation contains references with section numbers in form (REF/X.Y) to following specs:
   OCC10 - OpenID Connect Core 1.0
   RFC6749 - OAuth 2.0 RFC"
  (:require
    [clojure.string :as cs]
    [kanar.core :refer :all]
    [kanar.core.crypto :as kcc]
    [kanar.core.util :as kcu]
    [schema.core :as s]
    [kanar.core.util :as ku]
    [kanar.core :as kc]
    [kanar.core.ticket :as kt]
    [taoensso.timbre :as log]
    [clojure.data.json :as json]))


(def id-token-schema                                        ; JSON Web Token (OCC10/2 pg.9)
  "Defines schema for ID token."
  {:iss       s/Str                                         ; Issuer Identifier [URL] (OCC10/2 pg.9)
   :sub       s/Str                                         ; Subject Identifier (OCC10/2 pg.9)
   :aud       s/Str                                         ; Audience (client_id) (OCC10/2 pg.9)
   :exp       s/Num                                         ; Expiration time (OCC10/2 pg.9)
   :iat       s/Num                                         ; Issue time (OCC10/2 pg.9)
   :auth-time (s/maybe s/Num)                               ; End-User authentication time
   :nonce     (s/maybe s/Str)                               ; Prevention of replay attacks
   :acr       (s/maybe s/Str)                               ; Authentication Context Class Reference
   :amr       (s/maybe s/Str)                               ; Authentication Methods References
   :azp       (s/maybe s/Str)                               ; Authorized Party
   })


(def oauth-params-schema                                    ; Authentication parameters (OCC10/3.1.2.1 pg.13)
  "Authentication request parameters"
  {:response_type s/Any                                     ; Response type (OCC10/3.1.2.1 pg.14)
   :client_id     s/Str                                     ; Client ID (OCC10/3.1.2.1 pg.14)
   :scope         s/Any                                     ; Scope (OCC10/5.1) (OCC10/3.1.2.1 pg.13)
   :redirect_uri  s/Str                                     ; Redirection URI (OCC10/3.1.2.1 pg.14)
   :state         (s/maybe s/Str)                           ; State (OCC10/3.1.2.1 pg.14)
   :response_mode (s/maybe s/Any)                           ; OAuth Response Encoding Mode (RFC6749/?) TODO
   :display       (s/maybe (s/enum :page :popup :touch :wap)) ; Display mode for authentication process (OCC10/3.1.2.1 pg.14)
   :nonce         (s/maybe s/Str)                           ; Prevent replay attacks (OCC10/3.1.2.1 pg.14)
   :prompt        (s/maybe (s/enum :none :login :consent :select-account)) ; (OCC10/3.1.2.1 pg.15)
   :max_age       (s/maybe s/Num)                           ; Maximum Authentication Age (OCC10/3.1.2.1 pg.15)
   :ui_locales    (s/maybe [s/Str])                         ; UI locales (OCC10/3.1.2.1 pg.16)
   :id_token_hint (s/maybe s/Str)                           ; ID token hint (OCC10/3.1.2.1 pg.16)
   :login_hint    (s/maybe s/Str)                           ; Login hint (OCC10/3.1.2.1 pg.16)
   :acr_values    (s/maybe [s/Str])                         ; Authentication Context Class Reference (OCC10/3.1.2.1 pg.16)
   })


(def oauth-sso-request-schema
  (merge
    kc/sso-request-schema
    {:oauth-params oauth-params-schema                      ; Parsed and validated OAuth parameters
     :id-token id-token-schema                              ; ID token (as clojure data structure)
     :id-token-encoded s/Str                                ; Encoded ID token (ready to send back)
     }))


(def RESPONSE-TYPE-PARAMS
  #{"code"
    "id_token"
    "token"
    })


(def SCOPE-PARAMS
  "Standard scope parameters (additional names can be added if necessary)."
  #{"openid"
    "name"                                                  ; Full name (OCC10/5.1)
    "given_name"                                            ; First name(s) (OCC10/5.1)
    "family_name"                                           ; Last name(s) (OCC10/5.1)
    "middle_name"                                           ; Middle name(s) (OCC10/5.1)
    "nickname"                                              ; Casual name (OCC10/5.1)
    "preferred_username"                                    ; Preferred username (OCC10/5.1)
    "profile"                                               ; Profile page URL (OCC10/5.1)
    "picture"                                               ; Picture URL (OCC10/5.1)
    "website"                                               ; Website or Blog URL (OCC10/5.1)
    "email"                                                 ; Email (OCC10/5.1)
    "email_verified"                                        ; True if email is verified (OCC10/5.1)
    "gender"                                                ; Gender (OCC10/5.1)
    "birthdate"                                             ; Birthday (OCC10/5.1)
    "zoneinfo"                                              ; Time zone (OCC10/5.1)
    "locale"                                                ; Locale (OCC10/5.1)
    "phone_number"                                          ; Phone number (OCC10/5.1)
    "phone_number_verified"                                 ; True if phone number is verified (OCC10/5.1)
    "address"                                               ; Postal address (OCC10/5.1)
    "updated_at"                                            ; Time the information was last time updated (OCC10/5.1)
    "azp"                                                   ; Authorized party (OCC10/2)
    "nonce"                                                 ; Reply attacks prevention (OCC10/2)
    "auth_time"                                             ; Time authentication occured (OCC10/2)
    "at_hash"                                               ; Access Token hash value (OCC10/2)
    "c_hash"                                                ; Code hash value (OCC10/3.3.2.11)
    "acr"                                                   ; Authentication Context Class Reference (OCC10/2)
    "amr"                                                   ; Authentication Method References (OCC10/2)
    "sub_jwk"                                               ; Public key used to check signature of an ID token (OCC10/7.4)
    })


(def DISPLAY-MODES
  "Display modes for login page."
  {"page"  :page
   "popup" :popup
   "touch" :touch
   "wap"   :wap
    })


(def PROMPT-MODES
  "Prompt modes for authentication process."
  {"none" :none                                             ; No prompt
   "login" :login                                           ; Force login
   "consent" :consent                                       ; Ask for consent
   "select_account" :select_account                         ; Select account (if more than one used)
   })


(def TOKEN-GRANT-TYPES
  {"authorization_code" :authorization_code                 ; Grant ID token based on authorization code
   "refresh_token" :refresh_token                           ; Refresh token request
   })


(def AUTH-ERROR-CODES
  {:interaction_required "Interactive login required."
   :login_required "Login required."
   :account_selection_required "Account selection required."
   :consent_required "User consent required."
   :invalid_request_uri "Invalid request URI."
   :invalid_request_object "Invalid request object."
   :request_not_supported "Request object parameter not supported."
   :request_uri_not_supported "Request object via URI not supported."
   :registration_not_supported "Registration parameter not supported."
   })


(defn parse-kw-params [param-set s]
  "Parses space-delimited sequence of words, converts them to keywords and returns as a set.
   param-set - set of allowed words;
   "
  (when (string? s)
    (set
      (for [x (cs/split s #"\s+")
            :let [x (cs/lower-case x)]
            :when (contains? param-set x)]
        (keyword x)))))


(defn parse-kw-param [param-map s]
  (when (string? s)
    (param-map (cs/lower-case s))))


(defn- parse-oauth-params-raw [{:keys [response_type client_id scope redirect_uri state response_mode display nonce
                                   prompt max_age ui_locales id_token_hint login_hint acr_values]}]
  (when (and scope response_type client_id redirect_uri)
    (let [response_type (parse-kw-params RESPONSE-TYPE-PARAMS response_type)
          scope (parse-kw-params SCOPE-PARAMS scope)]
      {:response_type response_type,
       :client_id     client_id,                            ; TODO validation
       :scope         scope
       :redirect_uri  redirect_uri                          ; TODO validation
       :state         state                                 ; TODO validation
       :response_mode response_mode
       :display       (parse-kw-param DISPLAY-MODES display)
       :nonce         nonce                                 ; TODO validation
       :prompt        (parse-kw-param PROMPT-MODES prompt)
       :max_age       (if max_age (Long/parseLong max_age))
       :ui_locales    (if ui_locales (vec (cs/split ui_locales #"\s+")))
       :id_token_hint id_token_hint                         ; TODO validation
       :login_hint    login_hint                            ; TODO validation
       :acr_values    (if acr_values (vec (cs/split acr_values #"\s+")))
       })))


(defn parse-oauth-params-jwt [{:keys [request]} jwt-decode]
  (when request
    (if-let [params (jwt-decode request)]
      (parse-oauth-params-raw params))))


(defn parse-oauth-params-fn [jose-cfg]
  (let [jwt-decode (kcc/jwt-decode-fn jose-cfg)]
    (fn [{:keys [params] :as req}]
      (if-let [oauth-params (or (parse-oauth-params-raw params) (parse-oauth-params-jwt params jwt-decode))]
        (merge
          req
          {:protocol      :oauth
           :subprotocol   :openid-connect
           :service-url   (:redirect_uri oauth-params)
           :oauth-params  oauth-params
           :hidden-params oauth-params})))))


(defn new-id-token [{:keys [tgt svt oauth-params] :as req} sso-url]
  (merge
    {:iss       sso-url
     :sub       (:id (:princ tgt))
     :aud       (:id (:service svt))                   ; TODO this should be service id ?
     :exp       (/ (:timeout svt) 1000)
     :iat       (/ (kcu/cur-time) 1000)
     :auth_time (/ (:ctime tgt) 1000)}
    (if (:nonce oauth-params) {:nonce (:nonce oauth-params)} {})
    ; TODO tutaj claims - atrybuty użytkownika itd. jako pole "claims" z elementami "userinfo" i "id_tokne" w środku;
    ))


(defn id-token-wfn [f ticket-registry jwt-encode sso-url]
  "Creates and adds ID token (both raw data structure and encoded)"
  (fn [req]
    (if (= :oauth (:protocol req))
      (let [id-token (new-id-token req sso-url)]
        (kt/update-ticket ticket-registry (:tid (:svt req)) {:id-token id-token})
        (f (-> req
               (assoc :id-token id-token)
               (assoc :id-token-encoded (jwt-encode id-token)))))
      (f req)
      )))


(defmethod service-redirect :oauth [{:keys [service-url tgt svt oauth-params id-token-encoded]}]
  (let [code_arg (if (:tid svt) (str "code=" (ku/url-enc (:tid svt))))
        state_arg (if (contains? (:scope oauth-params) :code) (str "state=" (ku/url-enc (:state oauth-params))))
        token_arg (if (contains? (:scope oauth-params) :id_token) (str "id_token=" (ku/url-enc id-token-encoded)))
        suffix (cs/join "&" (filter string? [code_arg state_arg token_arg]))]
    {:status  302
     :body    "Redirecting ..."
     :headers {"Location" (str service-url (if (.contains service-url "?") "&" "?") suffix)}
     :cookies {"CASTGC" (kcu/secure-cookie (:tid tgt))}}))


(defmethod error-response :oauth [{{:keys [error error_description]} :error service-url :service-url}]
  {:status 302
   :body "Redirecting to OAuth service ..."
   :headers {"Location" (str service-url (if (.contains service-url "?") "&" "?")
                             "error=" error "&error_description=" (ku/url-enc error_description))}
   })


(defn json-response [status data]
  {:status status
   :headers {"Content-Type" "application/json"}
   :body (json/write-str data)})


;(defn token-error-response [error-code]
;  (json-response 400 {:error (name error-code)}))


(defn- handle-token-authorization-code-cmd [{{:keys [code redirect_uri]} :params :as req} ticket-registry jwt-encode]
  (let [svt (kt/get-ticket ticket-registry code)]
    (cond
      (or (empty? code) (empty? redirect_uri))
      (do
        ; TODO audit here
        (log/warn "KOAUTH-W007: token-request-handler: missing token_code or redirect_uri")
        (json-response 400 {:error :invalid_request}))
      (nil? svt)
      (do
        ; TODO audit here
        (log/warn "KOAUTH-W006: token-request-handler: invalid token  code: " code)
        (json-response 400 {:error :invalid_request}))
      (not= redirect_uri (:url svt))
      (do
        ; TODO audit here
        (log/warn "KOAUTH-W009: token-request-handler: invalid redirect_uri: " redirect_uri " for token code " code)
        (json-response 400 {:error :invalid_request})
        )
      (:expended svt)
      (do
        ; TODO audit here
        (log/warn "KOAUTH-W008: token-request-handler: token already expended: " code)
        (json-response 400 {:error :invalid_request}))
      :else
      (do
        ; TODO audit here
        (log/info "KOAUTH-I008: token-request-handler: validated token code " code)
        (kt/update-ticket ticket-registry (:tid svt) {:expended true})
        (let [access-token (kt/new-tid "AT")
              refresh-token ((kt/new-tid "RT"))]
          (kt/alias-ticket ticket-registry (:tid svt) access-token {:type :access-token})
          (kt/alias-ticket ticket-registry (:tid svt) refresh-token {:type :refresh-token})
          (json-response 200
            {:access_token  access-token
             :token_type    "Bearer"
             :refresh_token refresh-token
             :expires_in    (/ kt/ST-EXPENDED-TIMEOUT 1000)
             :id_token      (jwt-encode (:id-token svt))})))
      )))


(defn handle-token-refresh-cmd [{:keys [refresh_token] :as req} ticket-registry jwt-encode]
  (let [{sid :sid :as rt} (kt/get-ticket ticket-registry refresh_token)
        svt (kt/get-ticket ticket-registry sid)]
    (cond
      (not refresh_token)
      (do
        ; TODO audit here
        (log/warn "KOAUTH-W001: token-refresh-handler: missing refresh_token")
        (json-response 400 {:error :invalid-request}))
      (nil? svt)
      (do
        ; TODO audit here
        (nil? svt)
        (log/warn "KOAUTH-W002: token-token-refresh-handler-handler; no such token" refresh_token)
        (json-response 400 {:error :invalid-request}))
      :else
      (let [t (/ (ku/cur-time) 1000)]
        (kt/update-ticket ticket-registry refresh_token {:id-token (assoc (:id-token svt) :iat t)})
        (json-response 200 (assoc (:id-token svt) :iat t)))
      )))


(defn token-request-handler-fn [ticket-registry jwt-encode]
  (fn [{{:keys [grant_type]} :params :as req}]
    ; TODO request authorization here (eg. Authorization header)
    (case (parse-kw-param TOKEN-GRANT-TYPES grant_type)
      :authorization_code (handle-token-authorization-code-cmd req ticket-registry jwt-encode)
      :refresh_token (handle-token-refresh-cmd req ticket-registry jwt-encode)
      (json-response 400 {:error :invalid_request}))))


(defn token-userinfo-handler-fn [ticket-registry]
  (fn [{{{auth :value} "Authorization"} :headers :as req}]
    (if-let [access-token (if (and auth (re-matches #"^(?i)(Bearer)\s+\S+$" auth)) (second (cs/split auth #"\s+")))]
      (if-let [svt (kt/get-ticket ticket-registry access-token)]
        (json-response 200 (ku/get-svt-attrs svt))
        (json-response 401 {:error :invalid_token, :error_description "Access token invalid or expired."}))
      (json-response 401 {:error :invalid_token, :error_description "Access token missing or malformed."}))))


