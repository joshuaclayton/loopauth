/// Abstracts over HTTP and HTTPS server transports (internal).
///
/// Implementations handle redirect URI construction and server lifecycle.
/// `CliTokenClient` stores an `Arc<dyn Transport>` selected at build time
/// by the builder's type-state, avoiding conditional branching in the
/// authorization flow.
///
/// End users do not interact with this trait directly. Use
/// [`CliTokenClientBuilder::use_https`](crate::CliTokenClientBuilder::use_https) or
/// [`CliTokenClientBuilder::use_https_with`](crate::CliTokenClientBuilder::use_https_with)
/// to select the transport.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Build the redirect URI (including scheme) from the bound listener.
    fn redirect_uri(&self, listener: &tokio::net::TcpListener) -> std::io::Result<String>;

    /// Run the callback server until `shutdown_rx` fires.
    async fn run_server(
        &self,
        listener: tokio::net::TcpListener,
        state: ServerState,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()>;
}

/// Plain HTTP transport for the loopback callback server.
pub struct HttpTransport;

#[async_trait::async_trait]
impl Transport for HttpTransport {
    fn redirect_uri(&self, listener: &tokio::net::TcpListener) -> std::io::Result<String> {
        let port = listener.local_addr()?.port();
        Ok(format!("http://127.0.0.1:{port}/callback"))
    }

    async fn run_server(
        &self,
        listener: tokio::net::TcpListener,
        state: ServerState,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()> {
        run_callback_server(listener, state, shutdown_rx).await
    }
}

/// HTTPS transport using a self-signed certificate.
///
/// Generates a fresh ephemeral certificate for `localhost` / `127.0.0.1` at
/// server start time.
pub struct HttpsSelfSignedTransport;

#[async_trait::async_trait]
impl Transport for HttpsSelfSignedTransport {
    fn redirect_uri(&self, listener: &tokio::net::TcpListener) -> std::io::Result<String> {
        let port = listener.local_addr()?.port();
        Ok(format!("https://127.0.0.1:{port}/callback"))
    }

    async fn run_server(
        &self,
        listener: tokio::net::TcpListener,
        state: ServerState,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()> {
        // Use Error::new (not Error::other) to preserve the typed SelfSignedCertError
        // as a source() for the error chain.
        #[expect(
            clippy::io_other_error,
            reason = "preserves typed source error via Error::new"
        )]
        let acceptor = crate::tls::self_signed_localhost_acceptor()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        run_callback_server_tls(listener, acceptor, state, shutdown_rx).await
    }
}

/// HTTPS transport using a user-provided [`TlsCertificate`](crate::TlsCertificate).
///
/// The `TlsAcceptor` was validated and built at [`TlsCertificate`](crate::TlsCertificate)
/// construction time, so no further validation occurs here.
pub struct HttpsCustomTransport {
    pub(crate) acceptor: tokio_rustls::TlsAcceptor,
}

#[async_trait::async_trait]
impl Transport for HttpsCustomTransport {
    fn redirect_uri(&self, listener: &tokio::net::TcpListener) -> std::io::Result<String> {
        let port = listener.local_addr()?.port();
        Ok(format!("https://127.0.0.1:{port}/callback"))
    }

    async fn run_server(
        &self,
        listener: tokio::net::TcpListener,
        state: ServerState,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()> {
        run_callback_server_tls(listener, self.acceptor.clone(), state, shutdown_rx).await
    }
}

/// Rendered HTML page to be returned to the browser after the OAuth callback.
#[derive(Debug)]
pub struct RenderedHtml(pub(crate) String);

#[derive(Debug, serde::Deserialize)]
pub struct CallbackParams {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

#[derive(Debug)]
pub enum CallbackResult {
    Success {
        code: String,
        state: String,
    },
    ProviderError {
        error: String,
        description: Option<String>,
    },
}

#[derive(Clone)]
pub struct ServerState {
    pub(crate) outer_tx: tokio::sync::mpsc::Sender<CallbackResult>,
    pub(crate) inner_rx:
        std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<RenderedHtml>>>>,
    pub(crate) shutdown_tx:
        std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

/// Controls how the loopback callback server binds to a local port.
#[derive(Debug, Clone, Copy)]
pub enum PortConfig {
    /// OS assigns an available port (default).
    Random,
    /// Try this port; fall back to an OS-assigned port on failure.
    Hint(u16),
    /// Require this exact port; return [`std::io::Error`] on failure.
    Required(u16),
}

pub async fn bind_listener(port_config: PortConfig) -> std::io::Result<tokio::net::TcpListener> {
    match port_config {
        PortConfig::Random => tokio::net::TcpListener::bind("127.0.0.1:0").await,
        PortConfig::Hint(hint) => {
            if let Ok(listener) = tokio::net::TcpListener::bind(format!("127.0.0.1:{hint}")).await {
                return Ok(listener);
            }
            tracing::debug!("port hint {hint} unavailable, falling back to :0");
            tokio::net::TcpListener::bind("127.0.0.1:0").await
        }
        PortConfig::Required(port) => {
            tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await
        }
    }
}

async fn callback_handler(
    axum::extract::State(state): axum::extract::State<ServerState>,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> (axum::http::StatusCode, axum::response::Html<String>) {
    let result = if let Some(error) = params.error {
        CallbackResult::ProviderError {
            error,
            description: params.error_description,
        }
    } else if let Some(code) = params.code {
        CallbackResult::Success {
            code,
            state: params.state.unwrap_or_else(String::new),
        }
    } else {
        CallbackResult::ProviderError {
            error: "invalid_request".to_string(),
            description: Some("authorization response is missing the code parameter".to_string()),
        }
    };

    let _ = state.outer_tx.send(result).await;

    let html = {
        let mut guard = state.inner_rx.lock().await;
        if let Some(ref mut rx) = *guard {
            rx.recv().await.map(|r| r.0).unwrap_or_default()
        } else {
            String::default()
        }
    };

    {
        let mut guard = state.shutdown_tx.lock().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }

    (axum::http::StatusCode::OK, axum::response::Html(html))
}

async fn run_callback_server(
    listener: tokio::net::TcpListener,
    state: ServerState,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    use axum::routing::get;
    let app = axum::Router::new()
        .route("/callback", get(callback_handler))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
}

/// A TLS-wrapping listener that implements [`axum::serve::Listener`].
///
/// Accepts TCP connections from the inner listener and performs a TLS handshake
/// before handing the stream to axum.
struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    const fn new(listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        Self {
            inner: listener,
            acceptor,
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => match self.acceptor.accept(stream).await {
                    Ok(tls_stream) => return (tls_stream, addr),
                    Err(e) => {
                        tracing::debug!("TLS handshake failed: {e}");
                    }
                },
                Err(e) => {
                    tracing::debug!("TCP accept failed: {e}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

async fn run_callback_server_tls(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    state: ServerState,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    use axum::routing::get;
    let app = axum::Router::new()
        .route("/callback", get(callback_handler))
        .with_state(state);

    let tls_listener = TlsListener::new(listener, acceptor);

    axum::serve(tls_listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic,
        clippy::expect_used,
        reason = "tests do not need to meet production lint standards"
    )]

    use super::{
        CallbackResult, HttpTransport, PortConfig, RenderedHtml, ServerState, Transport,
        bind_listener,
    };

    /// Spawn an HTTP callback server via the Transport trait, matching how
    /// `run_authorization_flow` uses it in production.
    fn spawn_http_server(
        listener: tokio::net::TcpListener,
        state: ServerState,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        let transport = HttpTransport;
        tokio::spawn(async move { transport.run_server(listener, state, shutdown_rx).await });
    }

    #[tokio::test]
    async fn bind_default_uses_loopback() {
        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let addr = listener.local_addr().expect("local_addr should work");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn bind_hint_uses_hint_port_when_available() {
        // Bind a socket to get a free port, then release it
        let temp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp");
        let port = temp.local_addr().expect("local_addr").port();
        drop(temp);

        // Now bind with hint using the freed port
        let listener = bind_listener(PortConfig::Hint(port))
            .await
            .expect("bind with hint should succeed");
        assert_eq!(listener.local_addr().expect("local_addr").port(), port);
    }

    #[tokio::test]
    async fn bind_hint_falls_back_when_port_busy() {
        // Keep the socket alive to keep the port busy
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind busy");
        let busy_port = busy.local_addr().expect("local_addr").port();

        // bind_listener should fall back to :0 without returning Err
        let listener = bind_listener(PortConfig::Hint(busy_port))
            .await
            .expect("bind with busy hint should fall back, not error");
        assert_ne!(listener.local_addr().expect("local_addr").port(), busy_port);
    }

    #[tokio::test]
    async fn bind_required_returns_err_when_port_busy() {
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind busy");
        let busy_port = busy.local_addr().expect("local_addr").port();
        let result = bind_listener(PortConfig::Required(busy_port)).await;
        assert!(result.is_err(), "Required port should error when busy");
    }

    #[tokio::test]
    async fn bind_required_succeeds_when_port_available() {
        let temp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp");
        let port = temp.local_addr().expect("local_addr").port();
        drop(temp);
        let listener = bind_listener(PortConfig::Required(port))
            .await
            .expect("bind required");
        assert_eq!(listener.local_addr().expect("local_addr").port(), port);
    }

    #[tokio::test]
    async fn redirect_uri_format() {
        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let uri = HttpTransport
            .redirect_uri(&listener)
            .expect("redirect_uri should work");
        assert!(uri.starts_with("http://127.0.0.1:"));
        assert!(uri.ends_with("/callback"));
    }

    #[tokio::test]
    async fn bound_address_is_not_wildcard() {
        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let addr = listener.local_addr().expect("local_addr");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn success_callback_sends_code_and_state_through_outer_mpsc() {
        let (outer_tx, mut outer_rx) = tokio::sync::mpsc::channel::<CallbackResult>(1);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel::<RenderedHtml>(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let state = ServerState {
            outer_tx,
            inner_rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(inner_rx))),
            shutdown_tx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(shutdown_tx))),
        };

        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let port = listener.local_addr().expect("local_addr").port();

        spawn_http_server(listener, state, shutdown_rx);

        // Spawn a task to send HTML via inner_tx after a brief moment
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let _ = inner_tx
                .send(RenderedHtml("<html>ok</html>".to_string()))
                .await;
        });

        let response = reqwest::get(format!(
            "http://127.0.0.1:{port}/callback?code=test_code&state=test_state"
        ))
        .await
        .expect("request should succeed");

        assert_eq!(response.status(), 200);
        let body = response.text().await.expect("body should be readable");
        assert_eq!(body, "<html>ok</html>");

        let result = outer_rx.recv().await.expect("should receive result");
        match result {
            CallbackResult::Success { code, state } => {
                assert_eq!(code, "test_code");
                assert_eq!(state, "test_state");
            }
            CallbackResult::ProviderError { .. } => panic!("expected Success, got ProviderError"),
        }
    }

    #[tokio::test]
    async fn error_callback_sends_provider_error_through_outer_mpsc() {
        let (outer_tx, mut outer_rx) = tokio::sync::mpsc::channel::<CallbackResult>(1);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel::<RenderedHtml>(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let state = ServerState {
            outer_tx,
            inner_rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(inner_rx))),
            shutdown_tx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(shutdown_tx))),
        };

        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let port = listener.local_addr().expect("local_addr").port();

        spawn_http_server(listener, state, shutdown_rx);

        // Spawn inner_tx sender so handler doesn't block forever
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let _ = inner_tx
                .send(RenderedHtml("<html>error</html>".to_string()))
                .await;
        });

        let response = reqwest::get(format!(
            "http://127.0.0.1:{port}/callback?error=access_denied&error_description=User+denied"
        ))
        .await
        .expect("request should succeed");

        assert_eq!(response.status(), 200);

        let result = outer_rx.recv().await.expect("should receive result");
        match result {
            CallbackResult::ProviderError { error, .. } => {
                assert_eq!(error, "access_denied");
            }
            CallbackResult::Success { .. } => panic!("expected ProviderError, got Success"),
        }
    }

    #[tokio::test]
    async fn response_body_is_non_empty_before_server_exits() {
        let (outer_tx, _outer_rx) = tokio::sync::mpsc::channel::<CallbackResult>(1);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel::<RenderedHtml>(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let state = ServerState {
            outer_tx,
            inner_rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(inner_rx))),
            shutdown_tx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(shutdown_tx))),
        };

        let listener = bind_listener(PortConfig::Random)
            .await
            .expect("bind should succeed");
        let port = listener.local_addr().expect("local_addr").port();

        spawn_http_server(listener, state, shutdown_rx);

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let _ = inner_tx
                .send(RenderedHtml("<html>done</html>".to_string()))
                .await;
        });

        let response = reqwest::get(format!("http://127.0.0.1:{port}/callback?code=x&state=y"))
            .await
            .expect("request should succeed");

        let body = response.text().await.expect("body should be readable");
        assert_eq!(body, "<html>done</html>");
    }
}
