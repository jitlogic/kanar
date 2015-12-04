(ns {{name}}.views
  (:require
    [hiccup.core :refer [html]]))


(defn login-view [& {:keys [username error-msg service TARGET]}]
  (html
    [:html
     [:head
      [:title "Kanar Login"]
      [:link {:rel "stylesheet" :href "static/kanar.css"}]]
     [:body
      [:div.container
       (if error-msg [:div.error-msg error-msg])
       [:div.login-box
        [:form {:method :post :action :login}
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
           [:tr
            [:td {:colspan 2 :align :center}
             [:input {:type :submit :value "Login"}]]]]]
         [:input#lt {:type :hidden :name :lt :value "lt"}]
         (if service [:input#service {:type :hidden :name :service :value service}])
         (if TARGET [:input#TARGET {:type :hidden :name :TARGET :value TARGET}])
         ]]]]]))


(defn message-view [_ msg & {:keys [url link]}]
  (html
    [:html
     [:head
      [:title "Kanar"]
      [:link {:rel "stylesheet" :href "static/kanar.css"}]]
     [:body
      [:div.container
       [:div.login-box
        [:div.line msg]
        (if link [:div.line [:a {:href url} link]])]]]]))

