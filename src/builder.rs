use crate::error::{AuthError, CallbackError, RefreshError};
use crate::jwks::{JwksValidator, JwksValidatorStorage, RemoteJwksValidator};
use crate::oidc::OpenIdConfiguration;
use crate::token_response::{TokenParser, default_token_parser};

/// Whether JWKS signature verification is performed on received ID tokens.
///
/// Constructed by the builder type-state; never constructed directly.
#[non_exhaustive]
pub enum OidcJwksConfig {
    /// Verify the ID token signature against the provider's JWKS endpoint.
    Enabled(JwksValidatorStorage),
    /// Skip JWKS signature verification.
    ///
    /// Claims (`exp`, `nbf`, `aud`, `iss`) are still validated. Use only when
    /// you have an out-of-band trust anchor (e.g., a mTLS-secured private network
    /// or a test environment where real JWKS validation is not possible).
    Disabled,
}
use crate::pages::{
    ErrorPageRenderer, ErrorRendererStorage, SuccessPageRenderer, SuccessRendererStorage,
};
use crate::scope::{OAuth2Scope, RequestScope};
use crate::server::{
    CallbackResult, HttpTransport, PortConfig, RenderedHtml, ServerState, Transport, bind_listener,
};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};

/// Holds the security-critical authorization URL parameters owned by `loopauth`.
///
/// Constructed just before the auth URL is finalized; `append_to` writes all
/// parameters to the URL.  `KEYS` is the authoritative list of reserved
/// parameter names — [`ExtraAuthParams`] uses it to reject hook-supplied
/// values that would collide with these fields.
struct AuthUrlParams<'a> {
    client_id: &'a str,
    redirect_uri: &'a url::Url,
    state_token: &'a str,
    pkce: &'a crate::pkce::PkceChallenge,
    nonce: Option<&'a str>,
    scopes: &'a [OAuth2Scope],
}

impl AuthUrlParams<'_> {
    /// The query-parameter keys set by [`AuthUrlParams::append_to`].
    ///
    /// Used by [`ExtraAuthParams`] to reject hook-supplied pairs whose keys
    /// would collide with library-controlled values.
    const KEYS: &'static [&'static str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ];

    fn append_to(&self, url: &mut url::Url) {
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client_id)
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("state", self.state_token)
            .append_pair("code_challenge", &self.pkce.code_challenge)
            .append_pair("code_challenge_method", self.pkce.code_challenge_method);

        if let Some(nonce) = self.nonce {
            url.query_pairs_mut().append_pair("nonce", nonce);
        }

        if !self.scopes.is_empty() {
            let scope_str = self
                .scopes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            url.query_pairs_mut().append_pair("scope", &scope_str);
        }
    }
}

/// Accumulates extra query parameters to append to the authorization URL.
///
/// Passed by `&mut` reference to the callback registered with
/// [`CliTokenClientBuilder::on_auth_url`].  Call [`ExtraAuthParams::append`]
/// to add provider-specific parameters such as `access_type=offline` for
/// Google OAuth 2.0.
///
/// The following keys are **reserved** and cannot be overridden via this
/// interface; any attempt is dropped and a `tracing::warn!` is emitted:
/// `response_type`, `client_id`, `redirect_uri`, `state`,
/// `code_challenge`, `code_challenge_method`, `nonce`, `scope`.
///
/// The library sets those parameters unconditionally to satisfy RFC 6749
/// §4.1.1, RFC 7636, and OIDC Core §3.1.2.1 security requirements.
pub struct ExtraAuthParams {
    pairs: Vec<(String, String)>,
}

impl ExtraAuthParams {
    const fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Append a query parameter to the authorization URL.
    ///
    /// Parameters whose key matches a reserved name are dropped with a
    /// `tracing::warn!`; see the type-level docs for the full list of reserved
    /// keys.
    pub fn append(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.pairs.push((key.into(), value.into()));
        self
    }

    fn apply_to(self, url: &mut url::Url) {
        for (key, value) in self.pairs {
            if AuthUrlParams::KEYS.contains(&key.as_str()) {
                tracing::warn!(
                    key = key.as_str(),
                    "on_auth_url hook attempted to set a reserved parameter; ignoring"
                );
            } else {
                url.query_pairs_mut().append_pair(&key, &value);
            }
        }
    }
}

type OnAuthUrlCallback = Box<dyn Fn(&mut ExtraAuthParams) + Send + Sync + 'static>;
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
const HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 30;

/// Acquires OAuth 2.0 provider tokens for CLI applications via the Authorization
/// Code + PKCE flow.
///
/// Construct with [`CliTokenClient::builder`] and call
/// [`CliTokenClient::run_authorization_flow`] to run the full flow. Use
/// [`CliTokenClient::refresh`] or [`CliTokenClient::refresh_if_expiring`] to
/// renew tokens without re-running the authorization flow.
///
/// The callback server runs over plain HTTP by default. For providers that
/// require HTTPS redirect URIs, use
/// [`CliTokenClientBuilder::use_https_with`] with a [`crate::TlsCertificate`].
pub struct CliTokenClient {
    client_id: ClientId,
    client_secret: Option<String>,
    auth_url: url::Url,
    token_url: url::Url,
    issuer: Option<url::Url>,
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
    oidc_jwks: Option<OidcJwksConfig>,
    http_client: reqwest::Client,
    transport: Arc<dyn Transport>,
    token_parser: TokenParser,
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
    /// Returns `AuthError::ServerBind` if the loopback server cannot bind (including TLS setup failures in HTTPS mode).
    /// Returns `AuthError::Browser` if `open_browser` is true and the browser fails to open.
    /// Returns `AuthError::Timeout` if the callback is not received within the configured timeout (default: 5 minutes).
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
    ///     .build();
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
        let redirect_uri_url = self
            .transport
            .redirect_uri(&listener)
            .map_err(AuthError::ServerBind)
            .and_then(|redirect_uri| {
                url::Url::parse(&redirect_uri).map_err(AuthError::InvalidUrl)
            })?;

        // 3. Generate PKCE challenge
        let pkce = crate::pkce::PkceChallenge::generate();

        // 4. Generate state token
        let state_token = uuid::Uuid::new_v4().to_string();

        // 5. Generate nonce when OIDC is active (OIDC Core §3.1.2.1)
        let nonce = self
            .oidc_jwks
            .is_some()
            .then(|| uuid::Uuid::new_v4().to_string());

        // 6. Build auth URL with query params
        let mut auth_url = self.auth_url.clone();
        AuthUrlParams {
            client_id: self.client_id.as_str(),
            redirect_uri: &redirect_uri_url,
            state_token: &state_token,
            pkce: &pkce,
            nonce: nonce.as_deref(),
            scopes: &self.scopes,
        }
        .append_to(&mut auth_url);

        // 7. Call on_auth_url hook to collect extra parameters
        if let Some(ref hook) = self.on_auth_url {
            let mut extras = ExtraAuthParams::new();
            hook(&mut extras);
            extras.apply_to(&mut auth_url);
        }

        // 8. Create channels
        let (outer_tx, outer_rx) = mpsc::channel::<CallbackResult>(1);
        let (inner_tx, inner_rx) = mpsc::channel::<RenderedHtml>(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // 9. Build ServerState
        let server_state = ServerState {
            outer_tx,
            inner_rx: Arc::new(Mutex::new(Some(inner_rx))),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        };

        // 10. Spawn callback server
        let port = listener.local_addr().map_err(AuthError::ServerBind)?.port();
        let shutdown_arc = Arc::clone(&server_state.shutdown_tx);
        let transport = Arc::clone(&self.transport);
        tokio::spawn(async move {
            transport
                .run_server(listener, server_state, shutdown_rx)
                .await
        });

        // 11. Call on_server_ready hook
        if let Some(ref hook) = self.on_server_ready {
            hook(port);
        }

        // 12. Call on_url hook AFTER server is spawned
        if let Some(ref hook) = self.on_url {
            hook(&auth_url);
        }

        // 13. Open browser or log URL
        if self.open_browser {
            webbrowser::open(auth_url.as_str()).map_err(|e| AuthError::Browser(e.to_string()))?;
        } else {
            tracing::info!(url = auth_url.as_str(), "authorization URL");
        }

        // 14-18. Wait for callback, exchange code, send HTML response
        handle_callback(
            self,
            &redirect_uri_url,
            &state_token,
            &pkce.code_verifier,
            nonce.as_deref(),
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
    ///     .build();
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
            &self.http_client,
            &self.token_url,
            self.client_id.as_str(),
            self.client_secret.as_deref(),
            &self.token_parser,
            refresh_token,
            &self.scopes,
        )
        .await?;
        if let Some(oidc_jwks) = &self.oidc_jwks {
            validate_id_token_if_present(
                oidc_jwks,
                unvalidated,
                self.client_id.as_str(),
                self.issuer.as_ref().map_or(
                    crate::oidc::IssuerValidation::Skip,
                    crate::oidc::IssuerValidation::MustMatch,
                ),
            )
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
    ///     .build();
    ///
    /// // Build an already-expired TokenSet so the refresh branch is taken
    /// let tokens: loopauth::TokenSet<loopauth::Unvalidated> = serde_json::from_value(serde_json::json!({
    ///     "access_token": "old_token",
    ///     "token_type": "Bearer",
    ///     "refresh_token": "rt_value",
    ///     "expires_at": 0
    /// })).unwrap();
    /// let tokens = tokens.into_validated();
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

/// Parse an `id_token` JWT from a token response, if `openid` was in the requested scopes.
///
/// Returns `Ok(None)` when `openid` was not requested or when the provider omitted `id_token`.
/// Returns `Err(IdTokenError)` when parsing the JWT fails.
fn parse_oidc_if_requested(
    id_token: Option<&str>,
    scopes: &[crate::scope::OAuth2Scope],
) -> Result<Option<crate::oidc::Token>, crate::error::IdTokenError> {
    if !scopes.contains(&crate::scope::OAuth2Scope::OpenId) {
        return Ok(None);
    }
    id_token.map(crate::oidc::Token::from_raw_jwt).transpose()
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
    use subtle::ConstantTimeEq as _;

    match callback_result {
        CallbackResult::Success { code, state }
            if state.as_bytes().ct_eq(state_token.as_bytes()).into() =>
        {
            Ok(code)
        }
        CallbackResult::Success { .. } => Err(CallbackError::StateMismatch),
        CallbackResult::ProviderError { error, description } => Err(CallbackError::ProviderError {
            error,
            description: description.unwrap_or_default(),
        }),
    }
}

/// Validate an ID token that MUST be present; used in the initial authorization flow.
///
/// Two-phase validation per RFC 7519 §7.2:
/// 1. Cryptographic signature check via JWKS (when [`OidcJwksConfig::Enabled`]).
/// 2. Standard claims: `exp`, `nbf`, `aud`, optionally `iss`, and optionally `nonce`.
///
/// Claims are only checked after the signature is verified to prevent accepting
/// claims from a tampered or unsigned token.
///
/// Returns [`crate::error::IdTokenError::NoIdToken`] when the token set carries no `id_token`.
async fn validate_id_token_required(
    oidc_jwks: &OidcJwksConfig,
    token_set: crate::token::TokenSet<crate::token::Unvalidated>,
    client_id: &str,
    issuer: crate::oidc::IssuerValidation<'_>,
    expected_nonce: Option<&str>,
) -> Result<crate::token::TokenSet<crate::token::Validated>, crate::error::IdTokenError> {
    use crate::error::IdTokenError;

    let oidc = token_set.oidc_token().ok_or(IdTokenError::NoIdToken)?;

    if let OidcJwksConfig::Enabled(validator) = oidc_jwks {
        validator
            .validate(oidc.raw())
            .await
            .map_err(IdTokenError::JwksValidationFailed)?;
    }

    // RFC 7519 §7.2: validate standard claims after signature check
    oidc.validate_standard_claims(client_id, issuer, expected_nonce)?;

    Ok(token_set.into_validated())
}

/// Validate an ID token if present; used in the refresh flow.
///
/// Most OIDC providers do not return an `id_token` on refresh. When absent the
/// token set is promoted directly without validation. When present, full two-phase
/// validation is performed (signature + standard claims). Nonce is never checked
/// on refresh (OIDC Core §3.1.3.7).
async fn validate_id_token_if_present(
    oidc_jwks: &OidcJwksConfig,
    token_set: crate::token::TokenSet<crate::token::Unvalidated>,
    client_id: &str,
    issuer: crate::oidc::IssuerValidation<'_>,
) -> Result<crate::token::TokenSet<crate::token::Validated>, crate::error::IdTokenError> {
    use crate::error::IdTokenError;

    let Some(oidc) = token_set.oidc_token() else {
        return Ok(token_set.into_validated());
    };

    if let OidcJwksConfig::Enabled(validator) = oidc_jwks {
        validator
            .validate(oidc.raw())
            .await
            .map_err(IdTokenError::JwksValidationFailed)?;
    }

    // RFC 7519 §7.2: validate standard claims after signature check; nonce skipped on refresh
    oidc.validate_standard_claims(client_id, issuer, None)?;

    Ok(token_set.into_validated())
}

#[expect(
    clippy::too_many_arguments,
    reason = "private orchestrator function; all args are distinct concerns that cannot be bundled without noise"
)]
async fn handle_callback(
    auth: &CliTokenClient,
    redirect_uri_url: &url::Url,
    state_token: &str,
    code_verifier: &str,
    nonce: Option<&str>,
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
        &auth.http_client,
        &auth.token_url,
        auth.client_id.as_str(),
        auth.client_secret.as_deref(),
        &auth.token_parser,
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

    // Run JWKS validation when OIDC is configured; otherwise promote directly
    let token_set = if let Some(oidc_jwks) = &auth.oidc_jwks {
        match validate_id_token_required(
            oidc_jwks,
            token_set,
            auth.client_id.as_str(),
            auth.issuer.as_ref().map_or(
                crate::oidc::IssuerValidation::Skip,
                crate::oidc::IssuerValidation::MustMatch,
            ),
            nonce,
        )
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

#[expect(
    clippy::too_many_arguments,
    reason = "all arguments are distinct OAuth2 code exchange parameters; grouping them would obscure their individual meanings"
)]
async fn exchange_code(
    http_client: &reqwest::Client,
    token_url: &url::Url,
    client_id: &str,
    client_secret: Option<&str>,
    token_parser: &TokenParser,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    scopes: &[crate::scope::OAuth2Scope],
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

    let t0 = std::time::SystemTime::now();
    let response = http_client
        .post(token_url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body_bytes = response.bytes().await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        return Err(AuthError::TokenExchange { status, body });
    }

    let body = response.text().await?;
    let fields = token_parser(&body).map_err(|e| AuthError::TokenParse(format!("{e}: {body}")))?;

    let expires_at = fields
        .expires_in
        .and_then(|secs| t0.checked_add(std::time::Duration::from_secs(secs)));

    let oidc =
        parse_oidc_if_requested(fields.id_token.as_deref(), scopes).map_err(AuthError::IdToken)?;

    // RFC 6749 §5.1: if scope omitted, use requested scopes
    let resolved_scopes = fields
        .scope
        .as_deref()
        .map_or_else(|| scopes.to_vec(), parse_scopes);

    Ok(crate::token::TokenSet::new(
        fields.access_token,
        fields.refresh_token,
        expires_at,
        fields.token_type.unwrap_or_else(|| "Bearer".to_string()),
        oidc,
        resolved_scopes,
    ))
}

async fn exchange_refresh_token(
    http_client: &reqwest::Client,
    token_url: &url::Url,
    client_id: &str,
    client_secret: Option<&str>,
    token_parser: &TokenParser,
    refresh_token: &str,
    scopes: &[crate::scope::OAuth2Scope],
) -> Result<crate::token::TokenSet<crate::token::Unvalidated>, RefreshError> {
    // RFC 6749 §6: scope is optional on refresh but required by some providers
    let scope_str = (!scopes.is_empty()).then(|| {
        scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    });

    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    if let Some(ref s) = scope_str {
        params.push(("scope", s.as_str()));
    }

    let t0 = std::time::SystemTime::now();
    let response = http_client
        .post(token_url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await?; // RefreshError::Request via #[from] reqwest::Error

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body_bytes = response.bytes().await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        return Err(RefreshError::TokenExchange { status, body });
    }

    let body = response.text().await?;
    let fields =
        token_parser(&body).map_err(|e| RefreshError::TokenParse(format!("{e}: {body}")))?;

    let expires_at = fields
        .expires_in
        .and_then(|secs| t0.checked_add(std::time::Duration::from_secs(secs)));

    let oidc = parse_oidc_if_requested(fields.id_token.as_deref(), scopes)
        .map_err(RefreshError::IdToken)?;

    // RFC 6749 §5.1: if scope omitted, use requested scopes
    let resolved_scopes = fields
        .scope
        .as_deref()
        .map_or_else(|| scopes.to_vec(), parse_scopes);

    // RFC 6749 §6: the server MAY issue a new refresh token, in which case
    // the client MUST discard the old one and replace it with the new one.
    // When the server omits refresh_token from the response, the original
    // refresh token remains valid and must be preserved.
    let resolved_refresh_token = fields
        .refresh_token
        .or_else(|| Some(refresh_token.to_string()));

    Ok(crate::token::TokenSet::new(
        fields.access_token,
        resolved_refresh_token,
        expires_at,
        fields.token_type.unwrap_or_else(|| "Bearer".to_string()),
        oidc,
        resolved_scopes,
    ))
}

// ── Type-state markers ────────────────────────────────────────────────────────
//
// `CliTokenClientBuilder` carries four type parameters that track required
// configuration at compile time. `build()` is only reachable once all required
// fields are in their `Has*` state, turning omitted-field bugs into compile
// errors rather than runtime panics.
//
// Three parameters track the individually-required fields:
//   C — client_id   (NoClientId | HasClientId)
//   A — auth_url    (NoAuthUrl  | HasAuthUrl)
//   T — token_url   (NoTokenUrl | HasTokenUrl)
//
// One parameter tracks OIDC + JWKS state:
//   O — oidc        (NoOidc | OidcPending | JwksEnabled | JwksDisabled)
//
// OIDC mode is entered via `with_openid_scope()` or `from_open_id_configuration()`,
// which transitions to `OidcPending`. From `OidcPending`, callers must resolve JWKS
// by calling either `jwks_validator()` (→ `JwksEnabled`) or `without_jwks_validation()`
// (→ `JwksDisabled`) before `build()` becomes available. This ensures that opting out
// of signature verification is always an explicit, visible choice rather than a silent
// default.

/// Type-state: loopback server uses plain HTTP (default).
#[non_exhaustive]
pub struct Http;

/// Type-state: loopback server uses HTTPS.
///
/// Created by [`CliTokenClientBuilder::use_https`] (self-signed) or
/// [`CliTokenClientBuilder::use_https_with`] (user-provided certificate).
pub struct Https(Option<crate::tls::TlsCertificate>);

/// Converts a scheme type-state marker into a transport implementation.
///
/// Keeps `build()` generic over `S` while ensuring the transport is fully
/// determined by the type.
pub trait IntoTransport: sealed::Sealed {
    /// Create the transport implementation for this scheme.
    fn into_transport(self) -> Arc<dyn Transport>;
}

impl sealed::Sealed for Http {}
impl IntoTransport for Http {
    fn into_transport(self) -> Arc<dyn Transport> {
        Arc::new(HttpTransport)
    }
}

impl sealed::Sealed for Https {}
impl IntoTransport for Https {
    fn into_transport(self) -> Arc<dyn Transport> {
        match self.0 {
            Some(cert) => Arc::new(crate::server::HttpsCustomTransport {
                acceptor: cert.acceptor,
            }),
            None => Arc::new(crate::server::HttpsSelfSignedTransport),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Type-state: `client_id` not yet provided.
#[non_exhaustive]
pub struct NoClientId;
/// Type-state: `client_id` has been provided.
#[non_exhaustive]
pub struct HasClientId(ClientId);
/// Type-state: `auth_url` not yet provided.
#[non_exhaustive]
pub struct NoAuthUrl;
/// Type-state: `auth_url` has been provided.
#[non_exhaustive]
pub struct HasAuthUrl(url::Url);
/// Type-state: `token_url` not yet provided.
#[non_exhaustive]
pub struct NoTokenUrl;
/// Type-state: `token_url` has been provided.
#[non_exhaustive]
pub struct HasTokenUrl(url::Url);
/// Type-state: OIDC mode not yet engaged; `openid` scope is not included.
#[non_exhaustive]
pub struct NoOidc;
/// Type-state: OIDC mode engaged but JWKS decision not yet made.
///
/// Call [`CliTokenClientBuilder::jwks_validator`] to enable signature verification
/// or [`CliTokenClientBuilder::without_jwks_validation`] to explicitly opt out.
/// `build()` is not available in this state.
#[non_exhaustive]
pub struct OidcPending;
/// Type-state: OIDC mode engaged with JWKS signature verification enabled.
///
/// `build()` is available.
pub struct JwksEnabled(JwksValidatorStorage);
/// Type-state: OIDC mode engaged with JWKS signature verification explicitly disabled.
///
/// Claims (`exp`, `nbf`, `aud`, `iss`) are still validated. `build()` is available.
#[non_exhaustive]
pub struct JwksDisabled;

// All optional builder fields live in a private inner struct. This means the
// state-transition methods (`client_id`, `auth_url`, `token_url`,
// `with_openid_scope`) only need to forward one `config` field when
// reconstructing the builder with a new type, rather than copying every
// individual optional field.
struct BuilderConfig {
    client_secret: Option<String>,
    issuer: Option<url::Url>,
    scopes: std::collections::BTreeSet<OAuth2Scope>,
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
    token_parser: Option<TokenParser>,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            client_secret: None,
            scopes: std::collections::BTreeSet::new(),
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
            issuer: None,
            token_parser: None,
        }
    }
}

/// Builder for [`CliTokenClient`].
///
/// Obtain via [`CliTokenClient::builder`]. The three required fields `client_id`,
/// `auth_url`, and `token_url` are tracked at the type level — [`build`] is only
/// callable once all three have been set, so omitting any of them is a **compile
/// error**. OIDC mode is tracked separately: JWKS validator methods are only
/// available after calling [`with_openid_scope`] or using
/// [`from_open_id_configuration`].
///
/// [`build`]: CliTokenClientBuilder::build
/// [`with_openid_scope`]: CliTokenClientBuilder::with_openid_scope
/// [`from_open_id_configuration`]: CliTokenClientBuilder::from_open_id_configuration
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `client_secret` | `None` (public client - PKCE only) |
/// | `scopes` | empty (plus `openid` when OIDC mode is engaged) |
/// | `port` | OS assigns port (use `port_hint` for soft preference, `require_port` for hard requirement) |
/// | `transport` | HTTP (use [`use_https_with`](CliTokenClientBuilder::use_https_with) for trusted HTTPS, or [`use_https`](CliTokenClientBuilder::use_https) for self-signed) |
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
/// use loopauth::{CliTokenClient, RequestScope};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = CliTokenClient::builder()
///     .client_id("my-client-id")
///     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
///     .token_url(url::Url::parse("https://provider.example.com/token")?)
///     .with_openid_scope()
///     .without_jwks_validation() // or .jwks_validator(Box::new(my_validator))
///     .add_scopes([RequestScope::Email, RequestScope::OfflineAccess])
///     .on_auth_url(|params| {
///         params.append("access_type", "offline");
///     })
///     .build();
///
/// let tokens = client.run_authorization_flow().await?;
/// println!("access token: {}", tokens.access_token());
/// # Ok(())
/// # }
/// ```
pub struct CliTokenClientBuilder<
    C = NoClientId,
    A = NoAuthUrl,
    T = NoTokenUrl,
    O = NoOidc,
    S = Http,
> {
    client_id: C,
    auth_url: A,
    token_url: T,
    oidc: O,
    scheme: S,
    config: BuilderConfig,
}

impl Default for CliTokenClientBuilder {
    fn default() -> Self {
        Self {
            client_id: NoClientId,
            auth_url: NoAuthUrl,
            token_url: NoTokenUrl,
            oidc: NoOidc,
            scheme: Http,
            config: BuilderConfig::default(),
        }
    }
}

// Named constructor — pre-fills both URLs from an OIDC discovery document and
// enters OidcPending mode (adding `openid` to scopes). Placed on the default
// (all-unset) state so `CliTokenClientBuilder::from_open_id_configuration`
// remains the natural call site.
impl CliTokenClientBuilder {
    /// Create a builder pre-filled from an [`OpenIdConfiguration`].
    ///
    /// Sets `auth_url` and `token_url` from the discovery document and
    /// automatically enters OIDC mode (equivalent to calling
    /// [`with_openid_scope`]). The issuer URL from the discovery document is
    /// stored automatically, enabling `iss` claim validation on every received
    /// ID token. Callers must still call `.client_id()` before `.build()`.
    ///
    /// [`with_openid_scope`]: CliTokenClientBuilder::with_openid_scope
    #[must_use]
    pub fn from_open_id_configuration(
        open_id_configuration: &OpenIdConfiguration,
    ) -> CliTokenClientBuilder<NoClientId, HasAuthUrl, HasTokenUrl, OidcPending, Http> {
        CliTokenClientBuilder {
            client_id: NoClientId,
            auth_url: HasAuthUrl(open_id_configuration.authorization_endpoint().clone()),
            token_url: HasTokenUrl(open_id_configuration.token_endpoint().clone()),
            oidc: OidcPending,
            scheme: Http,
            config: BuilderConfig {
                issuer: Some(open_id_configuration.issuer().clone()),
                scopes: std::collections::BTreeSet::from([OAuth2Scope::OpenId]),
                ..BuilderConfig::default()
            },
        }
    }
}

// ── Setters available in any state ───────────────────────────────────────────

impl<C, A, T, O, S> CliTokenClientBuilder<C, A, T, O, S> {
    /// Set the OAuth 2.0 client ID. Required.
    #[must_use]
    pub fn client_id(self, v: impl Into<String>) -> CliTokenClientBuilder<HasClientId, A, T, O, S> {
        CliTokenClientBuilder {
            client_id: HasClientId(ClientId(v.into())),
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: self.oidc,
            scheme: self.scheme,
            config: self.config,
        }
    }

    /// Set the authorization endpoint URL. Required.
    #[must_use]
    pub fn auth_url(self, v: url::Url) -> CliTokenClientBuilder<C, HasAuthUrl, T, O, S> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: HasAuthUrl(v),
            token_url: self.token_url,
            oidc: self.oidc,
            scheme: self.scheme,
            config: self.config,
        }
    }

    /// Set the token endpoint URL. Required.
    #[must_use]
    pub fn token_url(self, v: url::Url) -> CliTokenClientBuilder<C, A, HasTokenUrl, O, S> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: HasTokenUrl(v),
            oidc: self.oidc,
            scheme: self.scheme,
            config: self.config,
        }
    }

    /// Set the client secret. Optional - omit for public clients using PKCE only.
    #[must_use]
    pub fn client_secret(mut self, v: impl Into<String>) -> Self {
        self.config.client_secret = Some(v.into());
        self
    }

    /// Add OAuth 2.0 scopes to the request.
    ///
    /// Scopes accumulate across multiple calls and are deduplicated. Call order
    /// does not affect the final scope set.
    ///
    /// [`RequestScope`] intentionally excludes `openid` — use
    /// [`with_openid_scope`] to enable OIDC mode and unlock JWKS validator methods.
    ///
    /// [`with_openid_scope`]: CliTokenClientBuilder::with_openid_scope
    /// [`RequestScope`]: crate::RequestScope
    #[must_use]
    pub fn add_scopes(mut self, v: impl IntoIterator<Item = RequestScope>) -> Self {
        self.config
            .scopes
            .extend(v.into_iter().map(OAuth2Scope::from));
        self
    }

    /// Suggest a preferred local port for the loopback callback server.
    ///
    /// Falls back to an OS-assigned port if the hint is unavailable.
    /// Use [`CliTokenClientBuilder::require_port`] for hard-failure semantics.
    #[must_use]
    pub const fn port_hint(mut self, v: u16) -> Self {
        self.config.port_config = PortConfig::Hint(v);
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
    ///     .auth_url(url::Url::parse("https://provider.example.com/authorize").unwrap())
    ///     .token_url(url::Url::parse("https://provider.example.com/token").unwrap())
    ///     .require_port(8080);
    /// // If port 8080 is unavailable when run_authorization_flow() is called,
    /// // it returns Err(AuthError::ServerBind(...)) immediately.
    /// ```
    #[must_use]
    pub const fn require_port(mut self, v: u16) -> Self {
        self.config.port_config = PortConfig::Required(v);
        self
    }

    /// Override the default success page with custom HTML, shown after a successful callback.
    #[must_use]
    pub fn success_html(mut self, v: impl Into<String>) -> Self {
        self.config.success_html = Some(v.into());
        self
    }

    /// Override the default error page with custom HTML, shown when the callback contains an error.
    #[must_use]
    pub fn error_html(mut self, v: impl Into<String>) -> Self {
        self.config.error_html = Some(v.into());
        self
    }

    /// Provide a custom [`SuccessPageRenderer`] for dynamic success page rendering.
    ///
    /// Takes precedence over [`CliTokenClientBuilder::success_html`].
    #[must_use]
    pub fn success_renderer(mut self, r: impl SuccessPageRenderer + 'static) -> Self {
        self.config.success_renderer = Some(Box::new(r));
        self
    }

    /// Provide a custom [`ErrorPageRenderer`] for dynamic error page rendering.
    ///
    /// Takes precedence over [`CliTokenClientBuilder::error_html`].
    #[must_use]
    pub fn error_renderer(mut self, r: impl ErrorPageRenderer + 'static) -> Self {
        self.config.error_renderer = Some(Box::new(r));
        self
    }

    /// Whether to open the authorization URL in the user's browser (default: `true`).
    ///
    /// When `false`, the URL is emitted via `tracing::info!` instead - useful for
    /// testing or headless environments.
    #[must_use]
    pub const fn open_browser(mut self, v: bool) -> Self {
        self.config.open_browser = v;
        self
    }

    /// Set the maximum time to wait for the authorization callback (default: 5 minutes).
    ///
    /// Returns [`AuthError::Timeout`] if the deadline is exceeded.
    #[must_use]
    pub const fn timeout(mut self, v: std::time::Duration) -> Self {
        self.config.timeout = v;
        self
    }

    /// Use a custom token response type for non-standard providers.
    ///
    /// The type `R` must implement [`serde::Deserialize`] and
    /// <code>Into<[TokenResponseFields](crate::TokenResponseFields)></code>. It will be deserialized from the
    /// token endpoint's JSON response and converted into the standard fields.
    /// This is useful for providers like Slack that nest tokens inside a
    /// sub-object rather than placing them at the top level.
    ///
    /// When not called, the standard OAuth 2.0 flat response format is used.
    ///
    /// [`TokenResponseFields`]: crate::TokenResponseFields
    #[must_use]
    pub fn token_response_type<R>(mut self) -> Self
    where
        R: serde::de::DeserializeOwned
            + Into<crate::token_response::TokenResponseFields>
            + Send
            + 'static,
    {
        self.config.token_parser = Some(crate::token_response::custom_token_parser::<R>());
        self
    }

    /// Register a callback that appends extra query parameters to the authorization URL.
    ///
    /// The callback receives a `&mut` [`ExtraAuthParams`] and may call
    /// [`ExtraAuthParams::append`] to add provider-specific parameters, for
    /// example `access_type=offline` required by Google OAuth 2.0.
    ///
    /// The callback is invoked after PKCE, state, nonce, and scope parameters
    /// have already been set.  Parameters with reserved keys
    /// (`response_type`, `client_id`, `redirect_uri`, `state`,
    /// `code_challenge`, `code_challenge_method`, `nonce`, `scope`) are
    /// dropped and a `tracing::warn!` is emitted; the library controls
    /// those values unconditionally.
    ///
    /// # Example
    ///
    /// ```
    /// use loopauth::{CliTokenClient, ExtraAuthParams};
    ///
    /// let _client = CliTokenClient::builder()
    ///     .client_id("my-client")
    ///     .auth_url(url::Url::parse("https://accounts.example.com/authorize").unwrap())
    ///     .token_url(url::Url::parse("https://accounts.example.com/token").unwrap())
    ///     .on_auth_url(|params: &mut ExtraAuthParams| {
    ///         params.append("access_type", "offline");
    ///     })
    ///     .build();
    /// ```
    #[must_use]
    pub fn on_auth_url(mut self, f: impl Fn(&mut ExtraAuthParams) + Send + Sync + 'static) -> Self {
        self.config.on_auth_url = Some(Box::new(f));
        self
    }

    /// Fires with the authorization URL string after the loopback server is ready to accept
    /// connections. Called regardless of the `open_browser` setting, before the browser opens or
    /// the URL is logged. Primary mechanism for headless/CI environments and test harnesses.
    #[must_use]
    pub fn on_url(mut self, f: impl Fn(&url::Url) + Send + Sync + 'static) -> Self {
        self.config.on_url = Some(Box::new(f));
        self
    }

    /// Fires with the bound port number once the loopback callback server is ready to accept
    /// connections. Useful for test coordination (wait for port before triggering a browser
    /// flow) and custom tooling that needs to know the redirect URI port in advance.
    #[must_use]
    pub fn on_server_ready(mut self, f: impl Fn(u16) + Send + Sync + 'static) -> Self {
        self.config.on_server_ready = Some(Box::new(f));
        self
    }

    /// Serve the loopback callback over HTTPS with a self-signed certificate.
    ///
    /// A fresh ephemeral certificate valid for `localhost` and `127.0.0.1` is
    /// generated each time
    /// [`run_authorization_flow`](CliTokenClient::run_authorization_flow) runs.
    ///
    /// **Note:** browsers will display a certificate warning for the self-signed
    /// certificate. Users must click through the warning for the callback to
    /// complete. For a seamless experience, use
    /// [`use_https_with`](CliTokenClientBuilder::use_https_with) with a
    /// locally-trusted certificate from `mkcert`.
    #[must_use]
    pub fn use_https(self) -> CliTokenClientBuilder<C, A, T, O, Https> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: self.oidc,
            scheme: Https(None),
            config: self.config,
        }
    }

    /// Serve the loopback callback over HTTPS with a trusted certificate.
    ///
    /// Use a [`TlsCertificate`](crate::TlsCertificate) created via
    /// [`ensure_localhost`](crate::TlsCertificate::ensure_localhost)
    /// (recommended) or
    /// [`from_pem_files`](crate::TlsCertificate::from_pem_files). The
    /// certificate is validated at construction time, so this method is
    /// infallible.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use loopauth::{CliTokenClient, TlsCertificate};
    /// use std::path::PathBuf;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generates certs via mkcert on first run, loads existing on subsequent runs
    /// let tls_dir = PathBuf::from("/home/user/.config/my-cli/tls");
    /// let cert = TlsCertificate::ensure_localhost(&tls_dir)?;
    ///
    /// let client = CliTokenClient::builder()
    ///     .client_id("my-client")
    ///     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
    ///     .token_url(url::Url::parse("https://provider.example.com/token")?)
    ///     .use_https_with(cert)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn use_https_with(
        self,
        certificate: crate::tls::TlsCertificate,
    ) -> CliTokenClientBuilder<C, A, T, O, Https> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: self.oidc,
            scheme: Https(Some(certificate)),
            config: self.config,
        }
    }
}

// ── OIDC mode transition ──────────────────────────────────────────────────────

impl<C, A, T, S> CliTokenClientBuilder<C, A, T, NoOidc, S> {
    /// Add `openid` to the requested scopes and enter OIDC mode.
    ///
    /// Transitions to [`OidcPending`] — you must then call either
    /// [`jwks_validator`] (to enable JWKS signature verification) or
    /// [`without_jwks_validation`] (to explicitly opt out) before [`build`]
    /// becomes available.
    ///
    /// Note: [`from_open_id_configuration`] implicitly enters OIDC mode, so
    /// this method is not needed when using that constructor.
    ///
    /// [`jwks_validator`]: CliTokenClientBuilder::jwks_validator
    /// [`without_jwks_validation`]: CliTokenClientBuilder::without_jwks_validation
    /// [`build`]: CliTokenClientBuilder::build
    /// [`from_open_id_configuration`]: CliTokenClientBuilder::from_open_id_configuration
    #[must_use]
    pub fn with_openid_scope(mut self) -> CliTokenClientBuilder<C, A, T, OidcPending, S> {
        self.config.scopes.insert(OAuth2Scope::OpenId);
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: OidcPending,
            scheme: self.scheme,
            config: self.config,
        }
    }
}

// ── OIDC pending → resolved ───────────────────────────────────────────────────

impl<C, A, T, S> CliTokenClientBuilder<C, A, T, OidcPending, S> {
    /// Set the expected issuer URL for ID token `iss` claim validation (RFC 7519 §4.1.1).
    ///
    /// When set, the `iss` claim in every returned `id_token` must exactly match this URL.
    /// When using [`CliTokenClientBuilder::from_open_id_configuration`] the issuer is set
    /// automatically from the discovery document and this method is not needed.
    ///
    /// Only available in OIDC mode — `iss` validation only applies to ID tokens.
    #[must_use]
    pub fn issuer(mut self, v: url::Url) -> Self {
        self.config.issuer = Some(v);
        self
    }

    /// Enable JWKS signature verification and transition to [`JwksEnabled`].
    ///
    /// The raw `id_token` string is passed to [`JwksValidator::validate`] after
    /// every successful token exchange. If validation fails,
    /// [`CliTokenClient::run_authorization_flow`] returns
    /// [`AuthError::IdToken`] wrapping [`crate::IdTokenError::JwksValidationFailed`].
    #[must_use]
    pub fn jwks_validator(
        self,
        v: Box<dyn JwksValidator>,
    ) -> CliTokenClientBuilder<C, A, T, JwksEnabled, S> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: JwksEnabled(v),
            scheme: self.scheme,
            config: self.config,
        }
    }

    /// Explicitly opt out of JWKS signature verification and transition to [`JwksDisabled`].
    ///
    /// **Security warning**: without JWKS validation, the `id_token` is not
    /// cryptographically authenticated. Any party that can craft a JWT with
    /// valid claims (including `"alg":"none"` tokens) will be accepted. Claims
    /// (`exp`, `nbf`, `aud`, `iss`) are still validated per RFC 7519, but
    /// those checks are only meaningful if the token's authenticity is
    /// guaranteed by other means.
    ///
    /// Use only in test environments or when an out-of-band trust anchor (e.g.,
    /// mTLS-secured private network) guarantees token authenticity. In
    /// production, always prefer [`jwks_validator`].
    ///
    /// [`jwks_validator`]: CliTokenClientBuilder::jwks_validator
    #[must_use]
    pub fn without_jwks_validation(self) -> CliTokenClientBuilder<C, A, T, JwksDisabled, S> {
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: JwksDisabled,
            scheme: self.scheme,
            config: self.config,
        }
    }
}

impl<A, T, S> CliTokenClientBuilder<HasClientId, A, T, OidcPending, S> {
    /// Configure JWKS validation from an [`OpenIdConfiguration`] and transition
    /// to [`JwksEnabled`].
    ///
    /// Uses `open_id_configuration.jwks_uri()` and the `client_id` already set
    /// on this builder as the expected audience. Requires both `client_id` and
    /// OIDC mode to be set first — enforced at compile time.
    #[must_use]
    pub fn with_open_id_configuration_jwks_validator(
        self,
        open_id_configuration: &OpenIdConfiguration,
    ) -> CliTokenClientBuilder<HasClientId, A, T, JwksEnabled, S> {
        let client_id = self.client_id.0.as_str().to_owned();
        let validator = Box::new(RemoteJwksValidator::from_open_id_configuration(
            open_id_configuration,
            client_id,
        ));
        CliTokenClientBuilder {
            client_id: self.client_id,
            auth_url: self.auth_url,
            token_url: self.token_url,
            oidc: JwksEnabled(validator),
            scheme: self.scheme,
            config: self.config,
        }
    }
}

impl<C, A, T, S> CliTokenClientBuilder<C, A, T, JwksEnabled, S> {
    /// Set the expected issuer URL for ID token `iss` claim validation (RFC 7519 §4.1.1).
    ///
    /// When set, the `iss` claim in every returned `id_token` must exactly match this URL.
    ///
    /// Only available in OIDC mode — `iss` validation only applies to ID tokens.
    #[must_use]
    pub fn issuer(mut self, v: url::Url) -> Self {
        self.config.issuer = Some(v);
        self
    }
}

impl<C, A, T, S> CliTokenClientBuilder<C, A, T, JwksDisabled, S> {
    /// Set the expected issuer URL for ID token `iss` claim validation (RFC 7519 §4.1.1).
    ///
    /// When set, the `iss` claim in every returned `id_token` must exactly match this URL.
    ///
    /// Only available in OIDC mode — `iss` validation only applies to ID tokens.
    #[must_use]
    pub fn issuer(mut self, v: url::Url) -> Self {
        self.config.issuer = Some(v);
        self
    }
}

impl<S: IntoTransport> CliTokenClientBuilder<HasClientId, HasAuthUrl, HasTokenUrl, JwksEnabled, S> {
    /// Build a [`CliTokenClient`] from the configured builder.
    ///
    /// All required fields (`client_id`, `auth_url`, `token_url`) are enforced
    /// at compile time. This method is infallible. JWKS signature verification
    /// is enabled; ID tokens will have their signatures verified on every exchange.
    #[must_use]
    pub fn build(mut self) -> CliTokenClient {
        self.config.scopes.insert(OAuth2Scope::OpenId);
        build_client(
            self.client_id.0,
            self.auth_url.0,
            self.token_url.0,
            self.config,
            Some(OidcJwksConfig::Enabled(self.oidc.0)),
            self.scheme.into_transport(),
        )
    }
}

impl<S: IntoTransport>
    CliTokenClientBuilder<HasClientId, HasAuthUrl, HasTokenUrl, JwksDisabled, S>
{
    /// Build a [`CliTokenClient`] from the configured builder.
    ///
    /// All required fields (`client_id`, `auth_url`, `token_url`) are enforced
    /// at compile time. This method is infallible. JWKS signature verification
    /// is disabled; claims are still validated per RFC 7519.
    #[must_use]
    pub fn build(mut self) -> CliTokenClient {
        self.config.scopes.insert(OAuth2Scope::OpenId);
        build_client(
            self.client_id.0,
            self.auth_url.0,
            self.token_url.0,
            self.config,
            Some(OidcJwksConfig::Disabled),
            self.scheme.into_transport(),
        )
    }
}

impl<S: IntoTransport> CliTokenClientBuilder<HasClientId, HasAuthUrl, HasTokenUrl, NoOidc, S> {
    /// Build a [`CliTokenClient`] without OIDC mode.
    ///
    /// No `openid` scope is added, no `id_token` is expected or validated,
    /// and no nonce is generated. Use this path for pure OAuth 2.0
    /// access-token-only flows. To enable OIDC, call
    /// [`with_openid_scope`](CliTokenClientBuilder::with_openid_scope) before
    /// building.
    ///
    /// All required fields (`client_id`, `auth_url`, `token_url`) are enforced
    /// at compile time. This method is infallible.
    #[must_use]
    pub fn build(self) -> CliTokenClient {
        build_client(
            self.client_id.0,
            self.auth_url.0,
            self.token_url.0,
            self.config,
            None,
            self.scheme.into_transport(),
        )
    }
}

fn build_client(
    client_id: ClientId,
    auth_url: url::Url,
    token_url: url::Url,
    config: BuilderConfig,
    oidc_jwks: Option<OidcJwksConfig>,
    transport: Arc<dyn Transport>,
) -> CliTokenClient {
    CliTokenClient {
        client_id,
        client_secret: config.client_secret,
        auth_url,
        token_url,
        issuer: config.issuer,
        scopes: config.scopes.into_iter().collect(),
        port_config: config.port_config,
        success_html: config.success_html,
        error_html: config.error_html,
        success_renderer: config.success_renderer,
        error_renderer: config.error_renderer,
        open_browser: config.open_browser,
        timeout: config.timeout,
        on_auth_url: config.on_auth_url,
        on_url: config.on_url,
        on_server_ready: config.on_server_ready,
        oidc_jwks,
        http_client: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECONDS))
            .timeout(std::time::Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECONDS))
            .build()
            .unwrap_or_default(),
        transport,
        token_parser: config.token_parser.unwrap_or_else(default_token_parser),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests do not need to meet production lint standards"
    )]

    use super::{
        AuthUrlParams, CliTokenClient, CliTokenClientBuilder, ExtraAuthParams, HasAuthUrl,
        HasClientId, HasTokenUrl, NoOidc, parse_scopes,
    };
    use crate::jwks::{JwksValidationError, JwksValidator};
    use crate::oidc::Token;
    use crate::scope::OAuth2Scope;
    use async_trait::async_trait;

    fn fake_jwt(sub: &str, email: &str) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"sub":"{sub}","email":"{email}","iss":"https://accounts.example.com","iat":1000000000,"exp":9999999999}}"#
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
    fn oidc_token_from_raw_jwt_returns_ok_for_valid_fake_jwt() {
        let jwt = fake_jwt("user_42", "user@example.com");
        let oidc = Token::from_raw_jwt(&jwt).expect("expected Ok for valid fake JWT");
        assert_eq!(oidc.claims().sub().as_str(), "user_42");
        assert_eq!(
            oidc.claims().email().map(crate::oidc::Email::as_str),
            Some("user@example.com")
        );
    }

    #[test]
    fn oidc_token_from_raw_jwt_returns_err_for_invalid_input() {
        let result = Token::from_raw_jwt("not.a.jwt");
        assert!(result.is_err(), "expected Err for invalid JWT");
    }

    #[test]
    fn oidc_token_from_raw_jwt_with_aud_claim_returns_ok() {
        // Google-style JWTs always include an `aud` claim (the client ID).
        // Ensure we decode them without requiring audience validation.
        let jwt = fake_jwt_google_style(
            "1234567890",
            "user@gmail.com",
            "Test User",
            "https://example.com/photo.jpg",
            "my-client-id.apps.googleusercontent.com",
        );
        let oidc = Token::from_raw_jwt(&jwt).expect("expected Ok for JWT with aud claim");
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

    fn valid_builder() -> CliTokenClientBuilder<HasClientId, HasAuthUrl, HasTokenUrl, NoOidc> {
        CliTokenClient::builder()
            .client_id("test-client")
            .auth_url(url::Url::parse("https://example.com/auth").unwrap())
            .token_url(url::Url::parse("https://example.com/token").unwrap())
    }

    #[test]
    fn builder_returns_cli_token_client_builder() {
        // Verifies the unparameterized alias resolves to the all-unset initial state.
        let _builder: CliTokenClientBuilder = CliTokenClient::builder();
    }

    // NOTE: build_without_client_id, build_without_auth_url, and
    // build_without_token_url are intentionally absent — omitting any of these
    // fields now produces a *compile error* rather than a runtime Err, so there
    // is no runtime behavior to test.

    #[test]
    fn build_with_valid_inputs_returns_client() {
        let _client = valid_builder().build();
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
        let _client = valid_builder()
            .with_openid_scope()
            .jwks_validator(Box::new(AcceptAll))
            .build();
    }

    // NOTE: build_with_jwks_validator_but_no_openid_scope is intentionally
    // absent — calling jwks_validator() on a NoOidc builder no longer compiles.

    fn make_open_id_configuration() -> crate::oidc::OpenIdConfiguration {
        use url::Url;
        crate::oidc::OpenIdConfiguration::new_for_test(
            Url::parse("https://accounts.example.com").unwrap(),
            Url::parse("https://accounts.example.com/authorize").unwrap(),
            Url::parse("https://accounts.example.com/token").unwrap(),
            Url::parse("https://accounts.example.com/.well-known/jwks.json").unwrap(),
        )
    }

    // NOTE: from_open_id_configuration_without_openid_scope_fails_build is
    // intentionally absent — from_open_id_configuration() always returns an
    // OidcPending builder, so a NoOidc build is impossible to construct.

    #[test]
    fn from_open_id_configuration_always_includes_openid_scope() {
        let config = make_open_id_configuration();
        // from_open_id_configuration enters OidcPending mode and pre-populates
        // the openid scope; no explicit scope call needed.
        let _client = CliTokenClientBuilder::from_open_id_configuration(&config)
            .client_id("test-client")
            .without_jwks_validation()
            .build();
    }

    // ── ExtraAuthParams ───────────────────────────────────────────────────────

    #[test]
    fn extra_auth_params_append_accumulates_pairs() {
        let mut params = ExtraAuthParams::new();
        params.append("access_type", "offline");
        params.append("prompt", "consent");
        assert_eq!(params.pairs.len(), 2);
        assert_eq!(
            params.pairs[0],
            ("access_type".to_string(), "offline".to_string())
        );
        assert_eq!(
            params.pairs[1],
            ("prompt".to_string(), "consent".to_string())
        );
    }

    #[test]
    fn extra_auth_params_apply_to_adds_non_reserved_keys() {
        let mut params = ExtraAuthParams::new();
        params.append("access_type", "offline");
        let mut url = url::Url::parse("https://example.com/auth").unwrap();
        params.apply_to(&mut url);
        let pairs: Vec<(_, _)> = url.query_pairs().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "access_type");
        assert_eq!(pairs[0].1, "offline");
    }

    #[test]
    fn extra_auth_params_apply_to_drops_reserved_keys() {
        // Each reserved key should be filtered out; none should appear in the URL.
        for reserved in AuthUrlParams::KEYS {
            let mut params = ExtraAuthParams::new();
            params.append(*reserved, "injected");
            let mut url = url::Url::parse("https://example.com/auth").unwrap();
            params.apply_to(&mut url);
            assert!(
                url.query_pairs().next().is_none(),
                "reserved key '{reserved}' should have been dropped"
            );
        }
    }

    #[test]
    fn extra_auth_params_apply_to_passes_non_reserved_and_drops_reserved() {
        let mut params = ExtraAuthParams::new();
        params.append("state", "injected"); // reserved — dropped
        params.append("access_type", "offline"); // not reserved — kept
        let mut url = url::Url::parse("https://example.com/auth").unwrap();
        params.apply_to(&mut url);
        let pairs: Vec<(_, _)> = url.query_pairs().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "access_type");
    }
}
