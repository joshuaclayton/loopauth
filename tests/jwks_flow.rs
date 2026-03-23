#![expect(
    clippy::panic,
    reason = "tests do not need to meet production lint standards"
)]
use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use loopauth::{
    AuthError, CliTokenClient, JwksValidationError, JwksValidator, RemoteJwksValidator,
    test_support::FakeOAuthServer,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use std::sync::Arc;
use tokio::net::TcpListener;
use url::Url;

/// A mock JWKS HTTP server for integration tests requiring custom key material.
///
/// Serves a static set of JWK keys at GET /jwks.
/// Spawn once per test; port is OS-assigned (TcpListener:0).
struct JwksServer {
    port: u16,
}

impl JwksServer {
    /// Start the mock JWKS server with the given JWK key objects.
    ///
    /// `keys` is a `Vec<serde_json::Value>` where each element is a JWK
    /// object (e.g. `{"kty":"RSA","kid":"key1","n":"...","e":"AQAB"}`).
    pub async fn start(keys: Vec<serde_json::Value>) -> Self {
        let keys = Arc::new(keys);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let keys_clone = Arc::clone(&keys);
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let keys = Arc::clone(&keys_clone);
                async move { Json(serde_json::json!({ "keys": *keys })) }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self { port }
    }

    /// The full URL of the JWKS endpoint (e.g. `http://127.0.0.1:PORT/jwks`).
    #[must_use]
    pub fn jwks_url(&self) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}/jwks", self.port)).unwrap()
    }
}
struct AlwaysPass;

#[async_trait]
impl JwksValidator for AlwaysPass {
    async fn validate(&self, _raw_token: &str) -> Result<(), JwksValidationError> {
        Ok(())
    }
}

struct AlwaysReject;

#[async_trait]
impl JwksValidator for AlwaysReject {
    async fn validate(&self, _raw_token: &str) -> Result<(), JwksValidationError> {
        Err(JwksValidationError::new("test rejection"))
    }
}

#[tokio::test]
async fn jwks_validator_passing_returns_ok() {
    let fake = FakeOAuthServer::start_with_oidc("oidc_token", "user_42", "user@example.com").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    tokio::spawn(async move {
        if let Ok(url) = url_rx.recv() {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let response = client.get(&url).send().await.expect("authorize request");
            if let Some(location) = response.headers().get("location") {
                let callback_url = location.to_str().unwrap().to_string();
                reqwest::get(&callback_url).await.ok();
            }
        }
    });

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .with_openid_scope()
        .open_browser(false)
        .jwks_validator(Box::new(AlwaysPass))
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let result = cli_auth.run_authorization_flow().await;
    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

fn generate_rsa_test_key_2048() -> (rsa::RsaPrivateKey, String, String) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("key generation failed");
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
    (private_key, n, e)
}

fn sign_rs256_jwt(private_key: &rsa::RsaPrivateKey, kid: Option<&str>, client_id: &str) -> String {
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem export failed");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())
        .expect("encoding key from pem failed");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    let claims = serde_json::json!({
        "aud": client_id,
        "exp": 9_999_999_999_u64,
        "iat": 1_000_000_000_u64,
        "sub": "test-user"
    });
    jsonwebtoken::encode(&header, &claims, &encoding_key).expect("jwt signing failed")
}

#[tokio::test]
async fn jwks_validator_rejecting_returns_jwks_validation_failed() {
    let fake = FakeOAuthServer::start_with_oidc("oidc_token", "user_42", "user@example.com").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    tokio::spawn(async move {
        if let Ok(url) = url_rx.recv() {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let response = client.get(&url).send().await.expect("authorize request");
            if let Some(location) = response.headers().get("location") {
                let callback_url = location.to_str().unwrap().to_string();
                reqwest::get(&callback_url).await.ok();
            }
        }
    });

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .with_openid_scope()
        .open_browser(false)
        .jwks_validator(Box::new(AlwaysReject))
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let result = cli_auth.run_authorization_flow().await;
    match result {
        Err(AuthError::IdToken(loopauth::IdTokenError::JwksValidationFailed(_))) => {}
        other => panic!("expected IdToken(JwksValidationFailed), got {other:?}"),
    }
}

#[tokio::test]
async fn remote_jwks_validator_rs256() {
    let client_id = "test-client";
    let server = FakeOAuthServer::builder().with_jwks().start().await;
    let claims = serde_json::json!({
        "aud": client_id,
        "exp": 9_999_999_999_u64,
        "iat": 1_000_000_000_u64,
        "sub": "test-user",
    });
    let token = server.sign_jwt(&claims);
    let validator = RemoteJwksValidator::new(server.jwks_url(), client_id);
    let result: Result<(), JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}

#[tokio::test]
async fn remote_jwks_validator_wrong_key_rejected() {
    let (_correct_key, _n, _e) = generate_rsa_test_key_2048();
    let (wrong_key, _, _) = generate_rsa_test_key_2048();
    let kid = "correct-key";
    let client_id = "test-client";
    // Sign with wrong_key but advertise correct-key in JWKS
    let token = sign_rs256_jwt(&wrong_key, Some(kid), client_id);

    // JWKS has correct key's components (n_correct, e_correct) - but token signed with wrong key
    let (_correct_key2, n_correct, e_correct) = generate_rsa_test_key_2048();
    let jwk = serde_json::json!({ "kty": "RSA", "kid": kid, "n": n_correct, "e": e_correct });
    let server = JwksServer::start(vec![jwk]).await;

    let validator = RemoteJwksValidator::new(server.jwks_url(), client_id);
    let result: Result<(), JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_err(), "expected Err (wrong key), got Ok");
}

#[tokio::test]
async fn remote_jwks_validator_unknown_kid_rejected() {
    let (private_key, n, e) = generate_rsa_test_key_2048();
    let client_id = "test-client";
    // Token has kid="missing-kid" but JWKS only has kid="other-key"
    let token = sign_rs256_jwt(&private_key, Some("missing-kid"), client_id);

    let jwk = serde_json::json!({ "kty": "RSA", "kid": "other-key", "n": n, "e": e });
    let server = JwksServer::start(vec![jwk]).await;

    let validator = RemoteJwksValidator::new(server.jwks_url(), client_id);
    let result: Result<(), JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_err(), "expected Err (unknown kid), got Ok");
    let err = result.unwrap_err();
    assert!(
        err.message().contains("no key found for kid=missing-kid"),
        "expected error mentioning kid, got: {}",
        err.message()
    );
}

#[tokio::test]
async fn remote_jwks_validator_unsupported_alg() {
    // HS256 token - RemoteJwksValidator does not support symmetric algorithms
    let secret = b"super-secret-key-for-testing-only";
    let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let claims = serde_json::json!({
        "aud": "test-client",
        "exp": 9_999_999_999_u64,
        "sub": "test-user"
    });
    let token =
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("hs256 token signing failed");

    let server = JwksServer::start(vec![]).await;
    let validator = RemoteJwksValidator::new(server.jwks_url(), "test-client");
    let result: Result<(), JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_err(), "expected Err for HS256, got Ok");
}

#[tokio::test]
async fn remote_jwks_validator_no_kid_fallthrough() {
    let (private_key, n, e) = generate_rsa_test_key_2048();
    let client_id = "test-client";
    // Token has NO kid
    let token = sign_rs256_jwt(&private_key, None, client_id);

    // JWKS has the matching key but with NO kid field
    let jwk = serde_json::json!({ "kty": "RSA", "n": n, "e": e });
    let server = JwksServer::start(vec![jwk]).await;

    let validator = RemoteJwksValidator::new(server.jwks_url(), client_id);
    let result: Result<(), JwksValidationError> = validator.validate(&token).await;
    assert!(
        result.is_ok(),
        "expected Ok for no-kid fallthrough, got: {result:?}"
    );
}
