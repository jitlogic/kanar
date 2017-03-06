(ns kanar.core.jetty
  (:require [taoensso.timbre :as log]
            [ring.util.servlet :as servlet])
  (:import (org.eclipse.jetty.util.ssl SslContextFactory)
           (java.security KeyStore)
           (org.eclipse.jetty.server.ssl SslSelectChannelConnector)
           (org.eclipse.jetty.server.nio SelectChannelConnector)
           (org.eclipse.jetty.server Server Request)
           (org.eclipse.jetty.server.handler AbstractHandler)
           (org.eclipse.jetty.util.thread QueuedThreadPool)))


(defn ssl-context-factory [options]
  (let [context (SslContextFactory.)]
    (if (string? (options :keystore))
      (.setKeyStorePath context (options :keystore))
      (.setKeyStore context ^KeyStore (options :keystore)))
    (.setKeyStorePassword context (options :keypass))
    (cond
      (string? (options :truststore))
      (.setTrustStore context ^String (options :truststore))
      (instance? KeyStore (options :truststore))
      (.setTrustStore context ^KeyStore (options :truststore)))
    (when (options :trustpass)
      (.setTrustStorePassword context (options :trustpass)))
    (when (options :include-ciphers)
      (.setIncludeCipherSuites context (into-array String (options :include-ciphers))))
    (when (options :exclude-ciphers)
      (.setExcludeCipherSuites context (into-array String (options :exclude-ciphers))))
    (when (options :include-protocols)
      (.setIncludeProtocols context (into-array String (options :include-protocols))))
    (when (options :exclude-protocols)
      (.setExcludeProtocols context (into-array String (options :exclude-protocols))))
    (case (options :client-auth)
      :need (.setNeedClientAuth context true)
      :want (.setWantClientAuth context true)
      nil)
    context))


(defn https-connector [options]
  (log/info "Enabling HTTPS connector on port: " (options :port 443))
  (doto
    (SslSelectChannelConnector. (ssl-context-factory options))
    (.setPort (options :port 8443))
    (.setHost (options :host))
    (.setMaxIdleTime (options :max-idle-time 200000))
    (.setRequestHeaderSize (options :request-header-size 65536))
    (.setRequestBufferSize (options :request-buffer-size 65536))))


(defn http-connector [options]
  (doto (SelectChannelConnector.)
    (.setPort (options :port 8080))
    (.setHost (options :host))
    (.setRequestHeaderSize (options :request-header-size 65536))
    (.setRequestBufferSize (options :request-buffer-size 65536))
    (.setMaxIdleTime (options :max-idle-time 200000))))


(defn create-container [{:keys [http-conf https-conf] :as options}]
  (log/info "Creating JETTY container: " options)
  (let [server (doto (Server.)
                 (.setSendDateHeader true)
                 (.setSendServerVersion false))]
    (when (:enabled http-conf)
      (.addConnector server (http-connector http-conf)))
    (when (:enabled https-conf)
      (.addConnector server (https-connector https-conf)))
    server))


(defn jetty-proxy-handler
  "Returns an Jetty Handler implementation for the given Ring handler."
  [handler]
  (proxy [AbstractHandler] []
    (handle [_ ^Request base-request request response]
      (let [request-map  (servlet/build-request-map request)
            response-map (handler request-map)]
        (when response-map
          (servlet/update-servlet-response response response-map)
          (.setHandled base-request true))))))


(defn ^Server run-jetty-container
  "Start a Jetty webserver to serve the given handler according to the supplied options:

  :http-conf      - options for plaintext connector;
  :https-conf     - options for SSL connector;
  :join?          - blocks the thread until server ends (defaults to true)
  :daemon?        - use daemon threads (defaults to false)
  :max-threads    - the maximum number of threads to use (default 50)
  :min-threads    - the minimum number of threads to use (default 8)
  :max-queued     - the maximum number of requests to queue (default unbounded)

  HTTP configurations have the following options:
  :port - listen port;
  :host - listen address;
  :max-idle-time - max time unused connection will be kept open;
  :request-header-size - max size of request header;
  :request-buffer-size - request buffer size;
  :keystore, :keypass, :truststore, :trustpass - keystore and trust store for SSL communication;
  :client-auth - set to :need or :want if client authentication is needed/wanted;
  :include-ciphers, :exclude-ciphers - include/exclude SSL ciphers (list of strings);
  :include-protocols, :exclude-protocols - include/exclude SSL protocols (list of strings);
  "
  [handler options]
  (let [^Server s (create-container options)
        ^QueuedThreadPool p (QueuedThreadPool. ^Integer (options :max-threads 50))]
    (.setMinThreads p (options :min-threads 8))
    (when-let [max-queued (:max-queued options)]
      (.setMaxQueued p max-queued))
    (when (:daemon? options false)
      (.setDaemon p true))
    (doto s
      (.setHandler (jetty-proxy-handler handler))
      (.setThreadPool p))
    (try
      (.start s)
      (when (:join? options true) (.join s))
      s
      (catch Exception ex
        (.stop s)
        (throw ex)))))


