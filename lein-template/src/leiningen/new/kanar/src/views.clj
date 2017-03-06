(ns {{name}}.views
  (:require
    [hiccup.core :refer [html]]
    [hiccup.util :refer [escape-html url-encode]]))

(def ^:private eh escape-html)
(def ^:method ue url-encode)

(defmulti render-view #(:type (:body %)))


(defmethod render-view :message [{ {:keys [message] {:keys [url link]} :view-params } :body {tgt :tgt} :req :as res}]
  (html
    [:html
     [:head
      [:title "Kanar"]
      [:link {:rel "stylesheet" :href "static/kanar.css"}]]
     [:body
      [:div.container
       [:div.login-box
        [:div.line message]
        (if link [:div.line [:a {:href url} link]])]]]]))


(defmethod render-view :error [{ {:keys [message] {:keys [url link]} :view-params } :body {tgt :tgt} :req :as res}]
  (html
    [:html                                                  ; TODO
     [:head
      [:title "Kanar"]
      [:link {:rel "stylesheet" :href "static/kanar.css"}]]
     [:body
      [:div.container
       [:div.login-box
        [:div.line message]
        (if link [:div.line [:a {:href url} link]])]]]]))


(defmethod render-view :login-screen [{ {:keys [hidden-params message] {:keys [username runas case]} :params} :body :as res}]
  (let [intranet (-> res :req :params :intranet)
        sulogin (= "/sulogin" (-> res :req :uri))]
    (html
      [:html
       [:head
        [:title "Kanar Login"]
        [:link {:rel "stylesheet" :href "static/kanar.css"}]]
       [:body
        [:div.container
         (if message [:div.error-msg (eh message)])
         [:div.login-box
          [:form {:method :post :action (if sulogin :sulogin :login)}
           [:table.login-int
            [:tbody
             [:tr
              [:td {:colspan 2, :align :center}
               [:h1 "Kanar Login"]]]
             [:tr
              [:td {:width "40%" :align :right} "Username:"]
              [:td [:input#username {:type  :text :autocomplete :false :size "25"
                                     :value (or username "") :tabindex "1" :name :username}]]]
             [:tr
              [:td {:align :right} "Password:"]
              [:td [:input#password {:type  :password :autocomplete :false :size "25"
                                     :value "" :tabindex "1" :name :password}]]]
             (when-not (or intranet sulogin)
               [:tr
                [:td {:align :right} "OTP token:"]
                [:td [:input#token {:type  :password, :autocomplete :false, :size 6
                                    :value "", :tabindex "1", :name :token}]]])
             (when sulogin
               [:tr
                [:td {:align :right} "Run as:"]
                [:td [:input#runas {:type :text, :autocomplete :true, :size "25"
                                    :value (or runas ""), :tabindex "1", :name :runas}]]])
             (when sulogin
               [:tr
                [:td {:align :right} "Case no:"]
                [:td [:input#case {:type :text, :autocomplete :true, :size "25"
                                   :value (or case "") :tabindex "1", :name :case}]]])
             [:tr
              [:td {:colspan 2 :align :center}
               [:input {:type :submit :value "Login"}]]]]]
           [:input#lt {:type :hidden :name :lt :value "lt"}]
           (for [[hk hv] hidden-params]
             [:input {:id (name hk) :type :hidden :name hk :value (eh hv)}])]]]]])))

