use crate::error::{AuthError, CallbackError, ConfigError, RefreshError};
use crate::jwks::{JwksValidator, JwksValidatorStorage, RemoteJwksValidator};
use crate::oidc::OpenIdConfiguration;
use crate::pages::{
    ErrorPageRenderer, ErrorRendererStorage, OAuth2Scope, SuccessPageRenderer,
    SuccessRendererStorage,
};
use crate::server::{
    CallbackResult, PortConfig, RenderedHtml, ServerState, bind_listener,
    redirect_uri_from_listener, run_callback_server,
};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};

type OnAuthUrlCallback = Box<dyn Fn(&mut url::Url) + Send + Sync + 'static>;
type OnUrlCallback = Box<dyn Fn(&url::Url) + Send + Sync + 'static>;
type OnServerReadyCallback = Box<dyn Fn(u16) + Send + Sync + 'static>;

/// An OAuth 2.0 client identifier.
#[derive(Debug, Clone)]
pub struct ClientId(String);

impl ClientId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

const TIMEOUT_DURATION_IN_SECONDS: u64 = 300;

/// Acquires OAuth 2.0 provider tokens for CLI applications via the Authorization
/// Code + PKCE flow.
///
/// Construct with [`CliTokenClient::builder`] and call
/// [`CliTokenClient::run_authorization_flow`] to run the full flow. Use
/// [`CliTokenClient::refresh`] or [`CliTokenClient::refresh_if_expiring`] to
/// renew tokens without re-running the authorization flow.
pub struct CliTokenClient {
    client_id: ClientId,
    client_secret: Option<String>,
    auth_url: url::Url,
    token_url: url::Url,
    scopes: Vec<OAuth2Scope>,
    port_config: PortConfig,
    success_html: Option<String>,
    error_html: Option<String>,
    success_renderer: Option<SuccessRendererStorage>,
    error_renderer: Option<ErrorRendererStorage>,
    open_browser: bool,
    timeout: std::time::Duration,
    on_auth_url: Option<OnAuthUrlCallback>,
    on_url: Option<OnUrlCallback>,
    on_server_ready: Option<OnServerReadyCallback>,
    jwks_validator: Option<JwksValidatorStorage>,
}

impl CliTokenClient {
    /// Create a new [`CliTokenClientBuilder`].
    #[must_use]
    pub fn builder() -> CliTokenClientBuilder {
        CliTokenClientBuilder::default()
    }

    /// Run the full OAuth 2.0 Authorization Code + PKCE flow.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::ServerBind` if the loopback server cannot bind.
    /// Returns `AuthError::Browser` if `open_browser` is true and the browser fails to open.
    /// Returns `AuthError::Timeout` if the callback is not received within the configured timeout.
    /// Returns `AuthError::Callback(CallbackError::StateMismatch)` if the callback state parameter does not match.
    /// Returns `AuthError::Callback(CallbackError::ProviderError)` if the callback contains an `error` parameter.
    /// Returns `AuthError::TokenExchange` if the token endpoint returns non-2xx.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use loopauth::{CliTokenClient, OAuth2Scope};
    /// use loopauth::test_support::FakeOAuthServer;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let server = FakeOAuthServer::start("my_token").await;
    /// let (tx, rx) = tokio::sync::oneshot::channel::<url::Url>();
    /// let tx = Arc::new(Mutex::new(Some(tx)));
    /// let client = CliTokenClient::builder()
    ///     .client_id("test-client")
    ///     .auth_url(server.auth_url())
    ///     .token_url(server.token_url())
    ///     .open_browser(false)
    ///     .on_url(move |url| {
    ///         if let Some(tx) = tx.lock().unwrap().take() {
    ///             let _ = tx.send(url.clone());
    ///         }
    ///     })
    ///     .build()
    ///     .unwrap();
    ///
    /// // Spawn a task to fire the redirect (simulates the browser callback)
    /// tokio::spawn(async move {
    ///     if let Ok(url) = rx.await {
    ///         let _ = reqwest::get(url).await;
    ///     }
    /// });
    ///
    /// let tokens = client.run_authorization_flow().await.unwrap();
    /// assert_eq!(tokens.access_token().as_str(), "my_token");
    /// # }
    /// ```
    pub async fn run_authorization_flow(&self) -> Result<crate::token::TokenSet, AuthError> {
        // 1. Bind listener
        let listener = bind_listener(self.port_config)
            .await
            .map_err(AuthError::ServerBind)?;

        // 2. Build redirect URI from listener
        let redirect_uri_url = redirect_uri_from_listener(&listener)
            .map_err(AuthError::ServerBind)
            .and_then(|redirect_uri| {
                url::Url::parse(&redirect_uri).map_err(AuthError::InvalidUrl)
            })?;

        // 3. Generate PKCE challenge
        let pkce = crate::pkce::PkceChallenge::generate();
        tracing::info!(
            code_verifier = pkce.code_verifier.as_str(),
            code_challenge = pkce.code_challenge.as_str(),
            code_challenge_method = pkce.code_challenge_method,
            "pkce challenge generated"
        );

        // 4. Generate state token
        let state_token = uuid::Uuid::new_v4().to_string();

        // 5. Build auth URL with query params
        let mut auth_url = self.auth_url.clone();
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client_id.as_str())
            .append_pair("redirect_uri", redirect_uri_url.as_str())
            .append_pair("state", &state_token)
            .append_pair("code_challenge", &pkce.code_challenge)
            .append_pair("code_challenge_method", pkce.code_challenge_method);

        if !self.scopes.is_empty() {
            let scope_str = self
                .scopes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            auth_url.query_pairs_mut().append_pair("scope", &scope_str);
        }

        // 6. Call on_auth_url hook
        if let Some(ref hook) = self.on_auth_url {
            hook(&mut auth_url);
        }

        // 7. Create channels
        let (outer_tx, outer_rx) = mpsc::channel::<CallbackResult>(1);
        let (inner_tx, inner_rx) = mpsc::channel::<RenderedHtml>(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // 8. Build ServerState
        let server_state = ServerState {
            outer_tx,
            inner_rx: Arc::new(Mutex::new(Some(inner_rx))),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        };

        // 9. Spawn callback server
        let port = listener.local_addr().map_err(AuthError::ServerBind)?.port();
        let shutdown_arc = Arc::clone(&server_state.shutdown_tx);
        tokio::spawn(run_callback_server(listener, server_state, shutdown_rx));

        // 10. Call on_server_ready hook
        if let Some(ref hook) = self.on_server_ready {
            hook(port);
        }

        // 11. Call on_url hook AFTER server is spawned
        if let Some(ref hook) = self.on_url {
            hook(&auth_url);
        }

        // 12. Open browser or log URL
        if self.open_browser {
            webbrowser::open(auth_url.as_str()).map_err(|e| AuthError::Browser(e.to_string()))?;
        } else {
            tracing::info!(url = auth_url.as_str(), "authorization URL");
        }

        // 13-17. Wait for callback, exchange code, send HTML response
        handle_callback(
            self,
            &redirect_uri_url,
            &state_token,
            &pkce.code_verifier,
            inner_tx,
            outer_rx,
            shutdown_arc,
        )
        .await
    }

    /// Exchange a refresh token for a new [`crate::TokenSet`].
    ///
    /// # Errors
    ///
    /// Returns [`RefreshError::NoRefreshToken`] when `refresh_token` is empty.
    /// Returns [`RefreshError::TokenExchange`] when the token endpoint returns non-2xx.
    /// Returns [`RefreshError::Request`] on network failure.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use loopauth::CliTokenClient;
    /// use loopauth::test_support::FakeOAuthServer;
    ///
    /// let server = FakeOAuthServer::start_with_refresh("new_token", "rt_value").await;
    /// let client = CliTokenClient::builder()
    ///     .client_id("test-client")
    ///     .auth_url(server.auth_url())
    ///     .token_url(server.token_url())
    ///     .build()
    ///     .unwrap();
    ///
    /// let tokens = client.refresh("rt_value").await.unwrap();
    /// assert_eq!(tokens.access_token().as_str(), "new_token");
    /// # }
    /// ```
    pub async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<crate::token::TokenSet, RefreshError> {
        if refresh_token.is_empty() {
            return Err(RefreshError::NoRefreshToken);
        }
        let unvalidated = exchange_refresh_token(
            &self.token_url,
            self.client_id.as_str(),
            self.client_secret.as_deref(),
            refresh_token,
            &self.scopes,
        )
        .await?;
        if self.scopes.contains(&crate::pages::OAuth2Scope::OpenId) {
            validate_jwks(self.jwks_validator.as_ref(), unvalidated)
                .await
                .map_err(RefreshError::IdToken)
        } else {
            Ok(unvalidated.into_validated())
        }
    }

    /// Refresh `tokens` if they expire within `threshold`; otherwise return [`crate::RefreshOutcome::NotNeeded`].
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::refresh`].
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use loopauth::{CliTokenClient, RefreshOutcome};
    /// use loopauth::test_support::FakeOAuthServer;
    /// use std::time::Duration;
    ///
    /// let server = FakeOAuthServer::start_with_refresh("new_token", "rt_value").await;
    /// let client = CliTokenClient::builder()
    ///     .client_id("test-client")
    ///     .auth_url(server.auth_url())
    ///     .token_url(server.token_url())
    ///     .build()
    ///     .unwrap();
    ///
    /// // Build an already-expired TokenSet so the refresh branch is taken
    /// let tokens: loopauth::TokenSet = serde_json::from_value(serde_json::json!({
    ///     "access_token": "old_token",
    ///     "token_type": "Bearer",
    ///     "refresh_token": "rt_value",
    ///     "expires_at": 0
    /// })).unwrap();
    ///
    /// let outcome = client.refresh_if_expiring(&tokens, Duration::from_secs(300)).await.unwrap();
    /// assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
    /// # }
    /// ```
    pub async fn refresh_if_expiring(
        &self,
        tokens: &crate::token::TokenSet,
        threshold: std::time::Duration,
    ) -> Result<crate::token::RefreshOutcome, RefreshError> {
        if !tokens.expires_within(threshold) {
            return Ok(crate::token::RefreshOutcome::NotNeeded);
        }
        let refresh_token = tokens.refresh_token().ok_or(RefreshError::NoRefreshToken)?;
        let new_tokens = self.refresh(refresh_token.as_str()).await?;
        Ok(crate::token::RefreshOutcome::Refreshed(Box::new(
            new_tokens,
        )))
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    token_type: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

/// Parse a space-separated scope string into a `Vec<OAuth2Scope>`.
fn parse_scopes(scope_str: &str) -> Vec<OAuth2Scope> {
    scope_str
        .split_whitespace()
        .map(OAuth2Scope::from)
        .collect()
}

async fn trigger_shutdown(shutdown_arc: &Arc<Mutex<Option<oneshot::Sender<()>>>>) {
    let mut guard = shutdown_arc.lock().await;
    if let Some(tx) = guard.take() {
        let _ = tx.send(());
    }
}

async fn resolve_callback_code(
    callback_result: CallbackResult,
    state_token: &str,
    auth: &CliTokenClient,
    redirect_uri_url: &url::Url,
    inner_tx: &mpsc::Sender<RenderedHtml>,
) -> Result<String, CallbackError> {
    match validate_callback_code(callback_result, state_token) {
        Err(err) => {
            let html = render_error_html(&err.clone().into(), auth, redirect_uri_url).await;
            let _ = inner_tx.send(RenderedHtml(html)).await;
            Err(err)
        }
        v => v,
    }
}

fn validate_callback_code(
    callback_result: CallbackResult,
    state_token: &str,
) -> Result<String, CallbackError> {
    match callback_result {
        CallbackResult::Success { code, state } if state == state_token => Ok(code),
        CallbackResult::Success { .. } => Err(CallbackError::StateMismatch),
        CallbackResult::ProviderError { error, description } => Err(CallbackError::ProviderError {
            error,
            description: description.unwrap_or_default(),
        }),
    }
}

async fn validate_jwks(
    validator: Option<&crate::jwks::JwksValidatorStorage>,
    token_set: crate::token::TokenSet<crate::token::Unvalidated>,
) -> Result<crate::token::TokenSet<crate::token::Validated>, crate::error::IdTokenError> {
    match (validator, token_set.id_token_raw()) {
        (Some(validator), Some(raw)) => {
            validator
                .validate(raw)
                .await
                .map_err(crate::error::IdTokenError::JwksValidationFailed)?;

            Ok(token_set.into_validated())
        }
        (None, Some(_)) => Ok(token_set.into_validated()),
        _ => Err(crate::error::IdTokenError::NoIdToken),
    }
}

async fn handle_callback(
    auth: &CliTokenClient,
    redirect_uri_url: &url::Url,
    state_token: &str,
    code_verifier: &str,
    inner_tx: mpsc::Sender<RenderedHtml>,
    mut outer_rx: mpsc::Receiver<CallbackResult>,
    shutdown_arc: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> Result<crate::token::TokenSet<crate::token::Validated>, AuthError> {
    // Wait for callback, racing against timeout and Ctrl+C
    let callback_result = tokio::select! {
        result = tokio::time::timeout(auth.timeout, outer_rx.recv()) => {
            match result {
                Err(_) => {
                    trigger_shutdown(&shutdown_arc).await;
                    return Err(AuthError::Timeout);
                }
                Ok(None) => return Err(AuthError::Server("channel closed".to_string())),
                Ok(Some(r)) => r,
            }
        }
        _ = tokio::signal::ctrl_c() => {
            trigger_shutdown(&shutdown_arc).await;
            return Err(AuthError::Cancelled);
        }
    };

    // Match callback result - send error HTML before returning Err
    let code = resolve_callback_code(
        callback_result,
        state_token,
        auth,
        redirect_uri_url,
        &inner_tx,
    )
    .await?;

    // Exchange code for token - send error HTML on failure
    let token_set = match exchange_code(
        &auth.token_url,
        auth.client_id.as_str(),
        auth.client_secret.as_deref(),
        &code,
        redirect_uri_url.as_str(),
        code_verifier,
        &auth.scopes,
    )
    .await
    {
        Ok(ts) => ts,
        Err(e) => {
            let html = render_error_html(&e, auth, redirect_uri_url).await;
            let _ = inner_tx.send(RenderedHtml(html)).await;
            return Err(e);
        }
    };

    // Run JWKS validation when openid scope was requested; otherwise promote directly
    let token_set = if auth.scopes.contains(&crate::pages::OAuth2Scope::OpenId) {
        match validate_jwks(auth.jwks_validator.as_ref(), token_set)
            .await
            .map_err(AuthError::IdToken)
        {
            Ok(ts) => ts,
            Err(e) => {
                let html = render_error_html(&e, auth, redirect_uri_url).await;
                let _ = inner_tx.send(RenderedHtml(html)).await;
                return Err(e);
            }
        }
    } else {
        token_set.into_validated()
    };

    // Send success HTML to callback handler (renderer > html string > default)
    let html = render_success_html(
        &token_set,
        &auth.scopes,
        redirect_uri_url,
        auth.client_id.as_str(),
        auth.success_renderer.as_deref(),
        auth.success_html.as_deref(),
    )
    .await;
    let _ = inner_tx.send(RenderedHtml(html)).await;

    Ok(token_set)
}

async fn render_error_html(
    err: &AuthError,
    auth: &CliTokenClient,
    redirect_uri_url: &url::Url,
) -> String {
    let ctx = crate::pages::ErrorPageContext::new(
        err,
        &auth.scopes,
        redirect_uri_url,
        auth.client_id.as_str(),
    );
    if let Some(renderer) = auth.error_renderer.as_deref() {
        renderer.render_error(&ctx).await
    } else if let Some(html) = auth.error_html.as_deref() {
        html.to_string()
    } else {
        crate::pages::DefaultErrorPageRenderer
            .render_error(&ctx)
            .await
    }
}

async fn render_success_html(
    token_set: &crate::token::TokenSet,
    scopes: &[OAuth2Scope],
    redirect_uri_url: &url::Url,
    client_id: &str,
    success_renderer: Option<&(dyn crate::pages::SuccessPageRenderer + Send + Sync)>,
    success_html: Option<&str>,
) -> String {
    let ctx = crate::pages::PageContext::new(
        token_set.oidc().map(crate::oidc::Token::claims),
        scopes,
        redirect_uri_url,
        client_id,
        token_set.expires_at(),
        token_set.refresh_token().is_some(),
    );
    if let Some(renderer) = success_renderer {
        renderer.render_success(&ctx).await
    } else if let Some(html) = success_html {
        html.to_string()
    } else {
        crate::pages::DefaultSuccessPageRenderer
            .render_success(&ctx)
            .await
    }
}

async fn exchange_code(
    token_url: &url::Url,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    scopes: &[crate::pages::OAuth2Scope],
) -> Result<crate::token::TokenSet<crate::token::Unvalidated>, AuthError> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }

    tracing::info!(url = token_url.as_str(), params = ?params, "token exchange request");

    let response = reqwest::Client::new()
        .post(token_url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| AuthError::Server(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(AuthError::TokenExchange { status, body });
    }

    let body = response
        .text()
        .await
        .map_err(|e| AuthError::Server(e.to_string()))?;
    let token_response: TokenResponse =
        serde_json::from_str(&body).map_err(|e| AuthError::Server(format!("{e}: {body}")))?;

    let expires_at = token_response
        .expires_in
        .map(|secs| std::time::SystemTime::now() + std::time::Duration::from_secs(secs));

    let oidc = if scopes.contains(&crate::pages::OAuth2Scope::OpenId) {
        token_response
            .id_token
            .as_deref()
            .and_then(crate::oidc::Token::from_raw_jwt)
    } else {
        None
    };

    // RFC 6749 §5.1: if scope omitted, use requested scopes
    let resolved_scopes = token_response
        .scope
        .as_deref()
        .map_or_else(|| scopes.to_vec(), parse_scopes);

    Ok(crate::token::TokenSet::new(
        token_response.access_token,
        token_response.refresh_token,
        expires_at,
        token_response
            .token_type
            .unwrap_or_else(|| "Bearer".to_string()),
        oidc,
        resolved_scopes,
    ))
}

async fn exchange_refresh_token(
    token_url: &url::Url,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
    scopes: &[crate::pages::OAuth2Scope],
) -> Result<crate::token::TokenSet<crate::token::Unvalidated>, RefreshError> {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }

    let response = reqwest::Client::new()
        .post(token_url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await?; // RefreshError::Request via #[from] reqwest::Error

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(RefreshError::TokenExchange { status, body });
    }

    let token_response: TokenResponse = response.json().await?; // RefreshError::Request via #[from] reqwest::Error

    let expires_at = token_response
        .expires_in
        .map(|secs| std::time::SystemTime::now() + std::time::Duration::from_secs(secs));

    let oidc = if scopes.contains(&crate::pages::OAuth2Scope::OpenId) {
        token_response
            .id_token
            .as_deref()
            .and_then(crate::oidc::Token::from_raw_jwt)
    } else {
        None
    };

    // RFC 6749 §5.1: if scope omitted, use requested scopes
    let resolved_scopes = token_response
        .scope
        .as_deref()
        .map_or_else(|| scopes.to_vec(), parse_scopes);

    Ok(crate::token::TokenSet::new(
        token_response.access_token,
        token_response.refresh_token,
        expires_at,
        token_response
            .token_type
            .unwrap_or_else(|| "Bearer".to_string()),
        oidc,
        resolved_scopes,
    ))
}

/// Builder for [`CliTokenClient`].
///
/// Obtain via [`CliTokenClient::builder`]. The three fields `client_id`, `auth_url`,
/// and `token_url` are required - [`CliTokenClientBuilder::build`] returns a
/// [`ConfigError`] if any are absent or not valid URLs. All other fields are
/// optional with the defaults described below.
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `client_secret` | `None` (public client - PKCE only) |
/// | `scopes` | empty |
/// | `port` | OS assigns port (use `port_hint` for soft preference, `require_port` for hard requirement) |
/// | `open_browser` | `true` |
/// | `timeout` | 5 minutes |
///
/// # Page rendering priority
///
/// Both the success and error pages follow the same three-tier priority:
///
/// 1. **Custom renderer** - [`CliTokenClientBuilder::success_renderer`] /
///    [`CliTokenClientBuilder::error_renderer`] (called dynamically with full context).
/// 2. **Custom HTML string** - [`CliTokenClientBuilder::success_html`] /
///    [`CliTokenClientBuilder::error_html`] (returned verbatim, no templating).
/// 3. **Default embedded page** - used when neither of the above is set.
///
/// # Example
///
/// ```no_run
/// use loopauth::{CliTokenClient, OAuth2Scope};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = CliTokenClient::builder()
///     .client_id("my-client-id")
///     .auth_url("https://provider.example.com/authorize")
///     .token_url("https://provider.example.com/token")
///     .scopes([OAuth2Scope::OpenId, OAuth2Scope::Email, OAuth2Scope::OfflineAccess])
///     .on_auth_url(|url| {
///         url.query_pairs_mut().append_pair("access_type", "offline");
///     })
///     .build()?;
///
/// let tokens = client.run_authorization_flow().await?;
/// println!("access token: {}", tokens.access_token());
/// # Ok(())
/// # }
/// ```
pub struct CliTokenClientBuilder {
    client_id: Option<ClientId>,
    client_secret: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    scopes: Vec<OAuth2Scope>,
    port_config: PortConfig,
    success_html: Option<String>,
    error_html: Option<String>,
    success_renderer: Option<SuccessRendererStorage>,
    error_renderer: Option<ErrorRendererStorage>,
    open_browser: bool,
    timeout: std::time::Duration,
    on_auth_url: Option<OnAuthUrlCallback>,
    on_url: Option<OnUrlCallback>,
    on_server_ready: Option<OnServerReadyCallback>,
    jwks_validator: Option<JwksValidatorStorage>,
    from_open_id_configuration_used: bool,
}

impl Default for CliTokenClientBuilder {
    fn default() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            auth_url: None,
            token_url: None,
            scopes: Vec::new(),
            port_config: PortConfig::Random,
            success_html: None,
            error_html: None,
            success_renderer: None,
            error_renderer: None,
            open_browser: true,
            timeout: std::time::Duration::from_secs(TIMEOUT_DURATION_IN_SECONDS),
            on_auth_url: None,
            on_url: None,
            on_server_ready: None,
            jwks_validator: None,
            from_open_id_configuration_used: false,
        }
    }
}

impl CliTokenClientBuilder {
    /// Create a builder pre-filled from an [`OpenIdConfiguration`].
    ///
    /// Sets `auth_url` from `open_id_configuration.authorization_endpoint()` and `token_url` from
    /// `open_id_configuration.token_endpoint()`. [`CliTokenClientBuilder::build`] will require
    /// [`OAuth2Scope::OpenId`] in scopes when this constructor is used.
    ///
    /// Callers must still call `.client_id()` before `.build()`.
    #[must_use]
    pub fn from_open_id_configuration(open_id_configuration: &OpenIdConfiguration) -> Self {
        Self {
            auth_url: Some(
                open_id_configuration
                    .authorization_endpoint()
                    .as_str()
                    .to_owned(),
            ),
            token_url: Some(open_id_configuration.token_endpoint().as_str().to_owned()),
            from_open_id_configuration_used: true,
            ..Self::default()
        }
    }

    /// Set the OAuth 2.0 client ID. Required.
    #[must_use]
    pub fn client_id(mut self, v: impl Into<String>) -> Self {
        self.client_id = Some(ClientId(v.into()));
        self
    }

    /// Set the client secret. Optional - omit for public clients using PKCE only.
    #[must_use]
    pub fn client_secret(mut self, v: impl Into<String>) -> Self {
        self.client_secret = Some(v.into());
        self
    }

    /// Set the authorization endpoint URL. Required.
    #[must_use]
    pub fn auth_url(mut self, v: impl Into<String>) -> Self {
        self.auth_url = Some(v.into());
        self
    }

    /// Set the token endpoint URL. Required.
    #[must_use]
    pub fn token_url(mut self, v: impl Into<String>) -> Self {
        self.token_url = Some(v.into());
        self
    }

    /// Set the OAuth 2.0 scopes to request. Include [`OAuth2Scope::OpenId`] to enable OIDC claim decoding.
    #[must_use]
    pub fn scopes(mut self, v: impl IntoIterator<Item = OAuth2Scope>) -> Self {
        self.scopes = v.into_iter().collect();
        self
    }

    /// Suggest a preferred local port for the loopback callback server.
    ///
    /// Falls back to an OS-assigned port if the hint is unavailable.
    /// Use [`CliTokenClientBuilder::require_port`] for hard-failure semantics.
    #[must_use]
    pub const fn port_hint(mut self, v: u16) -> Self {
        self.port_config = PortConfig::Hint(v);
        self
    }

    /// Require a specific local port for the loopback callback server.
    ///
    /// When set, [`CliTokenClient::run_authorization_flow`] returns
    /// [`AuthError::ServerBind`] if the port cannot be bound, rather than
    /// falling back to an OS-assigned port.
    ///
    /// # Example
    ///
    /// ```
    /// use loopauth::CliTokenClient;
    ///
    /// let builder = CliTokenClient::builder()
    ///     .client_id("my-client")
    ///     .auth_url("https://provider.example.com/authorize")
    ///     .token_url("https://provider.example.com/token")
    ///     .require_port(8080);
    /// // If port 8080 is unavailable when run_authorization_flow() is called,
    /// // it returns Err(AuthError::ServerBind(...)) immediately.
    /// ```
    #[must_use]
    pub const fn require_port(mut self, v: u16) -> Self {
        self.port_config = PortConfig::Required(v);
        self
    }

    /// Override the default success page with custom HTML, shown after a successful callback.
    #[must_use]
    pub fn success_html(mut self, v: impl Into<String>) -> Self {
        self.success_html = Some(v.into());
        self
    }

    /// Override the default error page with custom HTML, shown when the callback contains an error.
    #[must_use]
    pub fn error_html(mut self, v: impl Into<String>) -> Self {
        self.error_html = Some(v.into());
        self
    }

    /// Provide a custom [`SuccessPageRenderer`] for dynamic success page rendering.
    ///
    /// Takes precedence over [`CliTokenClientBuilder::success_html`].
    #[must_use]
    pub fn success_renderer(mut self, r: impl SuccessPageRenderer + 'static) -> Self {
        self.success_renderer = Some(Box::new(r));
        self
    }

    /// Provide a custom [`ErrorPageRenderer`] for dynamic error page rendering.
    ///
    /// Takes precedence over [`CliTokenClientBuilder::error_html`].
    #[must_use]
    pub fn error_renderer(mut self, r: impl ErrorPageRenderer + 'static) -> Self {
        self.error_renderer = Some(Box::new(r));
        self
    }

    /// Whether to open the authorization URL in the user's browser (default: `true`).
    ///
    /// When `false`, the URL is emitted via `tracing::info!` instead - useful for
    /// testing or headless environments.
    #[must_use]
    pub const fn open_browser(mut self, v: bool) -> Self {
        self.open_browser = v;
        self
    }

    /// Set the maximum time to wait for the authorization callback (default: 5 minutes).
    ///
    /// Returns [`AuthError::Timeout`] if the deadline is exceeded.
    #[must_use]
    pub const fn timeout(mut self, v: std::time::Duration) -> Self {
        self.timeout = v;
        self
    }

    /// Lets callers mutate the authorization URL before it is opened or logged. The closure
    /// receives a mutable `&mut url::Url` and may append custom query parameters (e.g.,
    /// `access_type=offline` for Google). Called after PKCE and state parameters are set.
    #[must_use]
    pub fn on_auth_url(mut self, f: impl Fn(&mut url::Url) + Send + Sync + 'static) -> Self {
        self.on_auth_url = Some(Box::new(f));
        self
    }

    /// Fires with the authorization URL string after the loopback server is ready to accept
    /// connections. Called regardless of the `open_browser` setting, before the browser opens or
    /// the URL is logged. Primary mechanism for headless/CI environments and test harnesses.
    #[must_use]
    pub fn on_url(mut self, f: impl Fn(&url::Url) + Send + Sync + 'static) -> Self {
        self.on_url = Some(Box::new(f));
        self
    }

    /// Fires with the bound port number once the loopback callback server is ready to accept
    /// connections. Useful for test coordination (wait for port before triggering a browser
    /// flow) and custom tooling that needs to know the redirect URI port in advance.
    #[must_use]
    pub fn on_server_ready(mut self, f: impl Fn(u16) + Send + Sync + 'static) -> Self {
        self.on_server_ready = Some(Box::new(f));
        self
    }

    /// Register an optional JWKS validator callback. When set, the raw `id_token`
    /// string is passed to [`JwksValidator::validate`] after a successful token
    /// exchange. If validation fails, [`CliTokenClient::run_authorization_flow`]
    /// returns [`AuthError::IdToken`] wrapping an [`crate::IdTokenError::JwksValidationFailed`].
    ///
    /// Requires [`OAuth2Scope::OpenId`] to be in the configured scopes -
    /// [`CliTokenClientBuilder::build`] returns [`ConfigError::MissingField`]
    /// if the scope is absent.
    #[must_use]
    pub fn jwks_validator(mut self, v: Box<dyn JwksValidator>) -> Self {
        self.jwks_validator = Some(v);
        self
    }

    /// Set the JWKS validator from an [`OpenIdConfiguration`].
    ///
    /// Uses `open_id_configuration.jwks_uri()` and the `client_id` already set on this builder.
    /// Call `.client_id()` before this method to ensure the audience is set correctly.
    /// If called before `.client_id()`, the validator uses an empty string as the audience.
    #[must_use]
    pub fn with_open_id_configuration_jwks_validator(
        mut self,
        open_id_configuration: &OpenIdConfiguration,
    ) -> Self {
        let client_id = self
            .client_id
            .as_ref()
            .map(|c| c.as_str().to_owned())
            .unwrap_or_default();
        self.jwks_validator = Some(Box::new(RemoteJwksValidator::from_open_id_configuration(
            open_id_configuration,
            client_id,
        )));
        self
    }

    /// Build a [`CliTokenClient`] instance from the configured builder.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingField`] if `client_id`, `auth_url`, or `token_url` is not set.
    /// Returns [`ConfigError::MissingField`] if `jwks_validator` is set but [`OAuth2Scope::OpenId`] is absent.
    /// Returns [`ConfigError::InvalidUrl`] if `auth_url` or `token_url` cannot be parsed as a URL.
    pub fn build(self) -> Result<CliTokenClient, ConfigError> {
        let client_id = self
            .client_id
            .ok_or_else(|| ConfigError::MissingField("client_id".to_string()))?;

        let auth_url_str = self
            .auth_url
            .ok_or_else(|| ConfigError::MissingField("auth_url".to_string()))?;
        let auth_url =
            url::Url::parse(&auth_url_str).map_err(|source| ConfigError::InvalidUrl {
                field: "auth_url".to_string(),
                source,
            })?;

        let token_url_str = self
            .token_url
            .ok_or_else(|| ConfigError::MissingField("token_url".to_string()))?;
        let token_url =
            url::Url::parse(&token_url_str).map_err(|source| ConfigError::InvalidUrl {
                field: "token_url".to_string(),
                source,
            })?;

        if self.jwks_validator.is_some()
            && !self.scopes.contains(&crate::pages::OAuth2Scope::OpenId)
        {
            return Err(ConfigError::MissingField(
                "jwks_validator requires OpenId scope".to_string(),
            ));
        }

        if self.from_open_id_configuration_used
            && !self.scopes.contains(&crate::pages::OAuth2Scope::OpenId)
        {
            return Err(ConfigError::MissingField(
                "from_open_id_configuration requires OpenId scope".to_string(),
            ));
        }

        Ok(CliTokenClient {
            client_id,
            client_secret: self.client_secret,
            auth_url,
            token_url,
            scopes: self.scopes,
            port_config: self.port_config,
            success_html: self.success_html,
            error_html: self.error_html,
            success_renderer: self.success_renderer,
            error_renderer: self.error_renderer,
            open_browser: self.open_browser,
            timeout: self.timeout,
            on_auth_url: self.on_auth_url,
            on_url: self.on_url,
            on_server_ready: self.on_server_ready,
            jwks_validator: self.jwks_validator,
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic,
        clippy::indexing_slicing,
        reason = "tests do not need to meet production lint standards"
    )]

    use super::{CliTokenClient, CliTokenClientBuilder, ConfigError, parse_scopes};
    use crate::jwks::{JwksValidationError, JwksValidator};
    use crate::oidc::Token;
    use crate::pages::OAuth2Scope;
    use async_trait::async_trait;

    fn fake_jwt(sub: &str, email: &str) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"sub":"{sub}","email":"{email}","iss":"https://accounts.example.com","iat":1000000000}}"#
        ));
        format!("{header}.{claims}.fakesig")
    }

    fn fake_jwt_google_style(
        sub: &str,
        email: &str,
        name: &str,
        picture: &str,
        aud: &str,
    ) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"iss":"https://accounts.google.com","aud":"{aud}","sub":"{sub}","email":"{email}","email_verified":true,"name":"{name}","picture":"{picture}","iat":1000000000,"exp":9999999999}}"#
        ));
        format!("{header}.{claims}.fakesig")
    }

    #[test]
    fn oidc_token_from_raw_jwt_returns_some_for_valid_fake_jwt() {
        let jwt = fake_jwt("user_42", "user@example.com");
        let result = Token::from_raw_jwt(&jwt);
        assert!(
            result.is_some(),
            "expected Some(OidcToken) for valid fake JWT"
        );
        let oidc = result.unwrap();
        assert_eq!(oidc.claims().sub().as_str(), "user_42");
        assert_eq!(
            oidc.claims().email().map(crate::oidc::Email::as_str),
            Some("user@example.com")
        );
    }

    #[test]
    fn oidc_token_from_raw_jwt_returns_none_for_invalid_input() {
        let result = Token::from_raw_jwt("not.a.jwt");
        assert!(result.is_none(), "expected None for invalid JWT");
    }

    #[test]
    fn oidc_token_from_raw_jwt_with_aud_claim_returns_some() {
        // Google-style JWTs always include an `aud` claim (the client ID).
        // Ensure we decode them without requiring audience validation.
        let jwt = fake_jwt_google_style(
            "1234567890",
            "user@gmail.com",
            "Test User",
            "https://example.com/photo.jpg",
            "my-client-id.apps.googleusercontent.com",
        );
        let result = Token::from_raw_jwt(&jwt);
        assert!(result.is_some(), "expected Some for JWT with aud claim");
        let oidc = result.unwrap();
        assert_eq!(oidc.claims().sub().as_str(), "1234567890");
        assert_eq!(
            oidc.claims().email().map(crate::oidc::Email::as_str),
            Some("user@gmail.com")
        );
        assert_eq!(oidc.claims().name(), Some("Test User"));
        assert_eq!(
            oidc.claims().picture().map(|p| p.as_url().as_str()),
            Some("https://example.com/photo.jpg")
        );
        assert!(oidc.claims().email().unwrap().is_verified());
    }

    fn valid_builder() -> CliTokenClientBuilder {
        CliTokenClient::builder()
            .client_id("test-client")
            .auth_url("https://example.com/auth")
            .token_url("https://example.com/token")
    }

    #[test]
    fn builder_returns_cli_token_client_builder() {
        let _builder: CliTokenClientBuilder = CliTokenClient::builder();
    }

    #[test]
    fn build_without_client_id_returns_missing_field_error() {
        let result = CliTokenClient::builder()
            .auth_url("https://example.com/auth")
            .token_url("https://example.com/token")
            .build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(s.contains("client_id")),
            Err(other) => panic!("Expected MissingField(client_id), got different error: {other}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn build_without_auth_url_returns_missing_field_error() {
        let result = CliTokenClient::builder()
            .client_id("test-client")
            .token_url("https://example.com/token")
            .build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(s.contains("auth_url")),
            Err(other) => panic!("Expected MissingField(auth_url), got different error: {other}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn build_without_token_url_returns_missing_field_error() {
        let result = CliTokenClient::builder()
            .client_id("test-client")
            .auth_url("https://example.com/auth")
            .build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(s.contains("token_url")),
            Err(other) => panic!("Expected MissingField(token_url), got different error: {other}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn build_with_invalid_auth_url_returns_invalid_url_error() {
        let result = CliTokenClient::builder()
            .client_id("test-client")
            .auth_url("not a url")
            .token_url("https://example.com/token")
            .build();
        match result {
            Err(ConfigError::InvalidUrl { field, .. }) => assert_eq!(field, "auth_url"),
            Err(other) => panic!("Expected InvalidUrl(auth_url), got different error: {other}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn build_with_invalid_token_url_returns_invalid_url_error() {
        let result = CliTokenClient::builder()
            .client_id("test-client")
            .auth_url("https://example.com/auth")
            .token_url("also not a url")
            .build();
        match result {
            Err(ConfigError::InvalidUrl { field, .. }) => assert_eq!(field, "token_url"),
            Err(other) => panic!("Expected InvalidUrl(token_url), got different error: {other}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn build_with_valid_inputs_returns_ok() {
        let result = valid_builder().build();
        assert!(result.is_ok(), "Expected Ok(CliTokenClient)");
    }

    /// RFC 6749 §5.1: when the token response omits the scope field,
    /// the client SHOULD assume the requested scopes were granted.
    #[test]
    fn rfc_6749_s5_1_scope_fallback_uses_requested_scopes_when_response_omits_scope() {
        // parse_scopes is the core helper; fallback logic is:
        //   token_response.scope.as_deref().map(parse_scopes).unwrap_or_else(|| scopes.to_vec())
        // Test the parse_scopes helper and the fallback identity directly.
        let requested = vec![OAuth2Scope::OpenId, OAuth2Scope::Email];
        // When scope is absent from response, resolved = requested
        let resolved: Vec<OAuth2Scope> = None::<String>
            .as_deref()
            .map_or_else(|| requested.clone(), parse_scopes);
        assert_eq!(resolved, requested);

        // When scope IS present in response, it is parsed
        let resolved_from_response: Vec<OAuth2Scope> = Some("openid profile".to_string())
            .as_deref()
            .map_or_else(|| requested.clone(), parse_scopes);
        assert_eq!(
            resolved_from_response,
            vec![OAuth2Scope::OpenId, OAuth2Scope::Profile]
        );
    }

    #[test]
    fn oidc_token_from_raw_jwt_populates_iss_aud_iat_exp() {
        let jwt = fake_jwt_google_style(
            "sub-iss-test",
            "user@example.com",
            "Test User",
            "https://example.com/photo.jpg",
            "my-client-id",
        );
        let oidc = Token::from_raw_jwt(&jwt).expect("should decode");
        let claims = oidc.claims();
        assert_eq!(
            claims.iss().as_url(),
            &url::Url::parse("https://accounts.google.com").unwrap()
        );
        assert_eq!(claims.aud().len(), 1);
        assert_eq!(claims.aud()[0].as_str(), "my-client-id");
        // iat and exp should be non-epoch values
        assert!(
            claims.iat() > std::time::UNIX_EPOCH,
            "iat should be after epoch"
        );
        assert!(
            claims.exp() > std::time::UNIX_EPOCH,
            "exp should be after epoch"
        );
    }

    struct AcceptAll;

    #[async_trait]
    impl JwksValidator for AcceptAll {
        async fn validate(&self, _raw_token: &str) -> Result<(), JwksValidationError> {
            Ok(())
        }
    }

    #[test]
    fn build_with_jwks_validator_and_openid_scope_succeeds() {
        let result = valid_builder()
            .scopes([OAuth2Scope::OpenId])
            .jwks_validator(Box::new(AcceptAll))
            .build();
        assert!(result.is_ok(), "expected Ok when OpenId scope is present");
    }

    #[test]
    fn build_with_jwks_validator_but_no_openid_scope_returns_missing_field() {
        let result = valid_builder().jwks_validator(Box::new(AcceptAll)).build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(
                s.contains("OpenId"),
                "expected message to mention OpenId, got: {s}"
            ),
            Err(other) => panic!("expected MissingField, got: {other}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    fn make_open_id_configuration() -> crate::oidc::OpenIdConfiguration {
        use url::Url;
        crate::oidc::OpenIdConfiguration::new_for_test(
            Url::parse("https://accounts.example.com").unwrap(),
            Url::parse("https://accounts.example.com/authorize").unwrap(),
            Url::parse("https://accounts.example.com/token").unwrap(),
            Url::parse("https://accounts.example.com/.well-known/jwks.json").unwrap(),
        )
    }

    #[test]
    fn from_open_id_configuration_without_openid_scope_fails_build() {
        let config = make_open_id_configuration();
        let result = CliTokenClientBuilder::from_open_id_configuration(&config)
            .client_id("test-client")
            .build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(
                s.contains("from_open_id_configuration"),
                "expected message to mention from_open_id_configuration, got: {s}"
            ),
            Err(other) => panic!("expected MissingField, got: {other}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn from_open_id_configuration_with_openid_scope_passes_build() {
        let config = make_open_id_configuration();
        let result = CliTokenClientBuilder::from_open_id_configuration(&config)
            .client_id("test-client")
            .scopes([OAuth2Scope::OpenId])
            .build();
        assert!(
            result.is_ok(),
            "expected Ok when from_open_id_configuration + OpenId scope"
        );
    }

    #[test]
    fn with_open_id_configuration_jwks_validator_sets_jwks_validator() {
        let config = make_open_id_configuration();
        // Verify via the build failure path: with_open_id_configuration_jwks_validator sets
        // the jwks_validator, which requires OpenId scope.
        let result = valid_builder()
            .with_open_id_configuration_jwks_validator(&config)
            .build();
        match result {
            Err(ConfigError::MissingField(s)) => assert!(
                s.contains("OpenId"),
                "expected message to mention OpenId, got: {s}"
            ),
            Err(other) => panic!("expected MissingField, got: {other}"),
            Ok(_) => panic!("expected Err when OpenId scope absent"),
        }
    }
}
