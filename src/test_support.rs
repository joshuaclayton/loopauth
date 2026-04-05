//! Test support utilities for doctests and unit tests.
#![expect(
    clippy::pedantic,
    clippy::unwrap_used,
    reason = "test support code does not need to meet production lint standards"
)]

use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;

const RSA_KEY_BITS: usize = 2048;
const DEFAULT_TOKEN_EXPIRY_SECS: u64 = 3600;

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
}

#[derive(Debug, Serialize)]
struct FakeTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

/// Builder for [`FakeOAuthServer`] with opt-in discovery and JWKS capabilities.
#[doc(hidden)]
pub struct FakeOAuthServerBuilder {
    with_open_id_configuration: bool,
    with_jwks: bool,
}

impl FakeOAuthServerBuilder {
    /// Enable the `/.well-known/openid-configuration` route.
    pub const fn with_open_id_configuration(mut self) -> Self {
        self.with_open_id_configuration = true;
        self
    }

    /// Enable the `/jwks` route with a generated 2048-bit RSA key pair.
    pub const fn with_jwks(mut self) -> Self {
        self.with_jwks = true;
        self
    }

    /// Start the fake server and return a [`FakeOAuthServer`].
    pub async fn start(self) -> FakeOAuthServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Generate RSA key pair if JWKS is requested
        let rsa_private_key = if self.with_jwks {
            let mut rng = rsa::rand_core::OsRng;
            Some(
                #[expect(
                    clippy::expect_used,
                    reason = "test support: key gen failure is a hard stop"
                )]
                rsa::RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("RSA key generation failed"),
            )
        } else {
            None
        };

        // Pre-compute JWKS document from the public key
        let jwks_doc: Option<Arc<serde_json::Value>> = rsa_private_key.as_ref().map(|priv_key| {
            let public_key = rsa::RsaPublicKey::from(priv_key);
            let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
            Arc::new(serde_json::json!({
                "keys": [{ "kty": "RSA", "kid": "test-key", "n": n, "e": e }]
            }))
        });

        // Build the router
        let mut app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route(
                "/token",
                post(move || async move { StatusCode::NOT_IMPLEMENTED }),
            );

        if let Some(jwks) = &jwks_doc {
            let jwks_clone = Arc::clone(jwks);
            app = app.route(
                "/jwks",
                get(move || {
                    let jwks = Arc::clone(&jwks_clone);
                    async move { Json((*jwks).clone()) }
                }),
            );
        }

        if self.with_open_id_configuration {
            let p = port;
            app = app.route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    Json(serde_json::json!({
                        "issuer": format!("http://127.0.0.1:{p}"),
                        "authorization_endpoint": format!("http://127.0.0.1:{p}/authorize"),
                        "token_endpoint": format!("http://127.0.0.1:{p}/token"),
                        "jwks_uri": format!("http://127.0.0.1:{p}/jwks"),
                    }))
                }),
            );
        }

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        FakeOAuthServer {
            port,
            access_token: String::new(),
            refresh_token: String::new(),
            rsa_private_key,
        }
    }
}

/// A fake OAuth 2.0 server for use in tests and doctests.
#[derive(Clone)]
pub struct FakeOAuthServer {
    port: u16,
    access_token: String,
    refresh_token: String,
    rsa_private_key: Option<rsa::RsaPrivateKey>,
}

impl FakeOAuthServer {
    /// Create a builder for a `FakeOAuthServer` with opt-in discovery and JWKS capabilities.
    pub const fn builder() -> FakeOAuthServerBuilder {
        FakeOAuthServerBuilder {
            with_open_id_configuration: false,
            with_jwks: false,
        }
    }

    /// Start a fake OAuth server that returns the given access token.
    pub async fn start(token_value: impl Into<String>) -> Self {
        let token = Arc::new(token_value.into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let token_clone = Arc::clone(&token);
        let app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route("/token", post(token_handler))
            .with_state(token_clone);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: token.as_ref().clone(),
            refresh_token: String::new(),
            rsa_private_key: None,
        }
    }

    /// Like `start`, but the /token endpoint always returns the given HTTP error status.
    pub async fn start_error(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route(
                "/token",
                post(move || async move {
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                }),
            );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: String::new(),
            refresh_token: String::new(),
            rsa_private_key: None,
        }
    }

    /// Like `start`, but the /token endpoint supports both `authorization_code` and
    /// `refresh_token` grant types and returns a refresh token in the response.
    pub async fn start_with_refresh(
        token_value: impl Into<String>,
        refresh_token_value: impl Into<String>,
    ) -> Self {
        Self::start_with_refresh_expiring_in(
            token_value,
            refresh_token_value,
            DEFAULT_TOKEN_EXPIRY_SECS,
        )
        .await
    }

    /// Like `start_with_refresh`, but issues tokens with a custom `expires_in` value (in seconds).
    pub async fn start_with_refresh_expiring_in(
        token_value: impl Into<String>,
        refresh_token_value: impl Into<String>,
        expires_in: u64,
    ) -> Self {
        let state = Arc::new((token_value.into(), refresh_token_value.into(), expires_in));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let state_clone = Arc::clone(&state);
        let app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route("/token", post(refresh_token_handler))
            .with_state(state_clone);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: state.0.clone(),
            refresh_token: state.1.clone(),
            rsa_private_key: None,
        }
    }

    /// Like `start_with_refresh`, but the /token endpoint omits `refresh_token` from
    /// the response body — matching the behavior of providers like Google that keep the
    /// original refresh token valid without echoing it back (RFC 6749 §6).
    pub async fn start_with_refresh_token_omitted_from_response(
        token_value: impl Into<String>,
    ) -> Self {
        let state = Arc::new((token_value.into(), DEFAULT_TOKEN_EXPIRY_SECS));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let state_clone = Arc::clone(&state);
        let app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route("/token", post(refresh_no_rt_handler))
            .with_state(state_clone);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: state.0.clone(),
            refresh_token: String::new(),
            rsa_private_key: None,
        }
    }

    /// Like `start`, but the /token endpoint includes an `id_token` in the response.
    ///
    /// The `nonce` sent in the authorization request is captured and included in the
    /// returned `id_token`, enabling nonce validation in tests.
    pub async fn start_with_oidc(
        token_value: impl Into<String>,
        id_token_sub: impl Into<String>,
        id_token_email: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        let access_token = Arc::new(token_value.into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Shared state: nonce is captured from the authorize request and read by token handler
        let nonce_store: Arc<tokio::sync::Mutex<Option<String>>> =
            Arc::new(tokio::sync::Mutex::new(None));

        let oidc_state = Arc::new(OidcTokenState {
            access_token: Arc::clone(&access_token),
            sub: id_token_sub.into(),
            email: id_token_email.into(),
            client_id: client_id.into(),
            iss: format!("http://127.0.0.1:{port}"),
            nonce: Arc::clone(&nonce_store),
        });

        let nonce_store_clone = Arc::clone(&nonce_store);
        let app = Router::new()
            .route(
                "/authorize",
                get(move |Query(params): Query<AuthorizeParams>| {
                    let nonce_store = Arc::clone(&nonce_store_clone);
                    async move {
                        // Capture nonce from authorize request for use during token exchange;
                        // drop guard before constructing the redirect to minimize lock scope
                        *nonce_store.lock().await = params.nonce;
                        let redirect_url = format!(
                            "{}?code=fake_code&state={}",
                            params.redirect_uri, params.state
                        );
                        Redirect::temporary(&redirect_url)
                    }
                }),
            )
            .route("/token", post(oidc_token_handler))
            .with_state(Arc::clone(&oidc_state));

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: access_token.as_ref().clone(),
            refresh_token: String::new(),
            rsa_private_key: None,
        }
    }

    /// Returns the access token this server will return.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the refresh token this server will return (empty string if not configured).
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// Returns the authorization URL for this fake server.
    #[must_use]
    pub fn auth_url(&self) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}/authorize", self.port)).unwrap()
    }

    /// Returns the token URL for this fake server.
    #[must_use]
    pub fn token_url(&self) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}/token", self.port)).unwrap()
    }

    /// Returns the issuer URL for this fake server (`http://127.0.0.1:{port}`).
    ///
    /// Only meaningful when builder was used with `.with_open_id_configuration()`.
    #[must_use]
    pub fn issuer_url(&self) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}", self.port)).unwrap()
    }

    /// Returns the JWKS URL for this fake server (`http://127.0.0.1:{port}/jwks`).
    ///
    /// Only meaningful when builder was used with `.with_jwks()`.
    #[must_use]
    pub fn jwks_url(&self) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}/jwks", self.port)).unwrap()
    }

    /// Returns the OpenID configuration URL for this fake server.
    ///
    /// Only meaningful when builder was used with `.with_open_id_configuration()`.
    #[must_use]
    pub fn open_id_configuration_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/.well-known/openid-configuration",
            self.port
        )
    }

    /// Sign a JWT with the server's internal RSA key pair.
    ///
    /// # Panics
    ///
    /// Panics if the server was not started with `.with_jwks()` via the builder.
    #[must_use]
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> String {
        #[expect(
            clippy::expect_used,
            reason = "test support: misconfigured server is a hard stop"
        )]
        let private_key = self
            .rsa_private_key
            .as_ref()
            .expect("sign_jwt requires FakeOAuthServer::builder().with_jwks().start()");
        #[expect(
            clippy::expect_used,
            reason = "test support: PEM export failure is a hard stop"
        )]
        let pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PEM export failed");
        #[expect(
            clippy::expect_used,
            reason = "test support: encoding key failure is a hard stop"
        )]
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())
            .expect("encoding key from PEM failed");
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        #[expect(
            clippy::expect_used,
            reason = "test support: JWT encoding failure is a hard stop"
        )]
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT signing failed")
    }
}

async fn authorize_handler(Query(params): Query<AuthorizeParams>) -> Redirect {
    let redirect_url = format!(
        "{}?code=fake_code&state={}",
        params.redirect_uri, params.state
    );
    Redirect::temporary(&redirect_url)
}

async fn token_handler(
    State(token): State<Arc<String>>,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<FakeTokenResponse>, StatusCode> {
    // Validate code_verifier is present and non-empty
    match body.get("code_verifier") {
        Some(cv) if !cv.is_empty() => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    Ok(Json(FakeTokenResponse {
        access_token: token.as_ref().clone(),
        token_type: "Bearer".to_string(),
        expires_in: DEFAULT_TOKEN_EXPIRY_SECS,
        refresh_token: None,
        id_token: None,
    }))
}

async fn refresh_token_handler(
    State(state): State<Arc<(String, String, u64)>>,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<FakeTokenResponse>, StatusCode> {
    let grant_type = body.get("grant_type").map_or("", String::as_str);

    match grant_type {
        "refresh_token" => match body.get("refresh_token") {
            Some(rt) if !rt.is_empty() => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        },
        "authorization_code" => match body.get("code_verifier") {
            Some(cv) if !cv.is_empty() => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        },
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    Ok(Json(FakeTokenResponse {
        access_token: state.0.clone(),
        token_type: "Bearer".to_string(),
        expires_in: state.2,
        refresh_token: Some(state.1.clone()),
        id_token: None,
    }))
}

/// Like `refresh_token_handler` but omits `refresh_token` from the response,
/// simulating providers (e.g. Google) that don't echo the refresh token back.
async fn refresh_no_rt_handler(
    State(state): State<Arc<(String, u64)>>,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<FakeTokenResponse>, StatusCode> {
    let grant_type = body.get("grant_type").map_or("", String::as_str);

    match grant_type {
        "refresh_token" => match body.get("refresh_token") {
            Some(rt) if !rt.is_empty() => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        },
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    Ok(Json(FakeTokenResponse {
        access_token: state.0.clone(),
        token_type: "Bearer".to_string(),
        expires_in: state.1,
        refresh_token: None,
        id_token: None,
    }))
}

/// Shared state for the OIDC fake token endpoint.
struct OidcTokenState {
    access_token: Arc<String>,
    sub: String,
    email: String,
    client_id: String,
    /// Issuer URL used in the `iss` claim of the `id_token`.
    iss: String,
    /// Nonce captured from the authorize request; included in the `id_token` when present.
    nonce: Arc<tokio::sync::Mutex<Option<String>>>,
}

/// Build a minimal fake JWT string (unsigned) with the given claims.
///
/// When `nonce` is `Some`, it is included as the `nonce` claim so that nonce
/// validation can be exercised in tests.
pub fn make_fake_id_token(
    sub: &str,
    email: &str,
    client_id: &str,
    iss: &str,
    nonce: Option<&str>,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let nonce_field = nonce
        .map(|n| format!(r#","nonce":"{n}""#))
        .unwrap_or_default();
    let claims = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"sub":"{sub}","email":"{email}","iss":"{iss}","aud":["{client_id}"],"iat":1000000000,"exp":9999999999{nonce_field}}}"#
    ));
    format!("{header}.{claims}.fakesig")
}

async fn oidc_token_handler(
    State(state): State<Arc<OidcTokenState>>,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<FakeTokenResponse>, StatusCode> {
    match body.get("code_verifier") {
        Some(cv) if !cv.is_empty() => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let nonce = state.nonce.lock().await.clone();
    let id_token = make_fake_id_token(
        &state.sub,
        &state.email,
        &state.client_id,
        &state.iss,
        nonce.as_deref(),
    );
    Ok(Json(FakeTokenResponse {
        access_token: state.access_token.as_ref().clone(),
        token_type: "Bearer".to_string(),
        expires_in: DEFAULT_TOKEN_EXPIRY_SECS,
        refresh_token: None,
        id_token: Some(id_token),
    }))
}

/// A token response that nests the access token inside a sub-object,
/// matching the pattern used by Slack OAuth v2 and similar providers.
#[derive(Debug, Serialize)]
struct NestedFakeTokenResponse {
    ok: bool,
    authed_user: NestedAuthedUser,
}

#[derive(Debug, Serialize)]
struct NestedAuthedUser {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

impl FakeOAuthServer {
    /// Like `start`, but the /token endpoint returns a nested response where
    /// `access_token` lives inside an `authed_user` sub-object (Slack v2 style).
    pub async fn start_with_nested_response(token_value: impl Into<String>) -> Self {
        let token = Arc::new(token_value.into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let token_clone = Arc::clone(&token);
        let app = Router::new()
            .route("/authorize", get(authorize_handler))
            .route("/token", post(nested_token_handler))
            .with_state(token_clone);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            port,
            access_token: token.as_ref().clone(),
            refresh_token: String::new(),
            rsa_private_key: None,
        }
    }
}

async fn nested_token_handler(
    State(token): State<Arc<String>>,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<NestedFakeTokenResponse>, StatusCode> {
    match body.get("code_verifier") {
        Some(cv) if !cv.is_empty() => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    Ok(Json(NestedFakeTokenResponse {
        ok: true,
        authed_user: NestedAuthedUser {
            access_token: token.as_ref().clone(),
            token_type: "Bearer".to_string(),
            expires_in: DEFAULT_TOKEN_EXPIRY_SECS,
            refresh_token: None,
        },
    }))
}
