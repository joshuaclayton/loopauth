#![expect(
    clippy::string_slice,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "CLI examples can be more lax"
)]
// # Usage
//   cargo run --example jwks_demo
//
// Runs offline using an in-process mock OAuth server.
// Demonstrates the JWKS validation hook by running two auth flows:
//   1. A validator that always accepts - flow succeeds, token set returned.
//   2. A validator that always rejects - flow returns AuthError::IdToken(IdTokenError::JwksValidationFailed).

use async_trait::async_trait;
use loopauth::test_support::FakeOAuthServer;
use loopauth::{AuthError, CliTokenClient, JwksValidationError, JwksValidator};

struct AlwaysAccept;

#[async_trait]
impl JwksValidator for AlwaysAccept {
    async fn validate(&self, _raw_token: &str) -> Result<(), JwksValidationError> {
        Ok(())
    }
}

struct AlwaysReject;

#[async_trait]
impl JwksValidator for AlwaysReject {
    async fn validate(&self, raw_token: &str) -> Result<(), JwksValidationError> {
        tracing::info!(
            token_prefix = &raw_token[..20.min(raw_token.len())],
            "rejecting token"
        );
        Err(JwksValidationError::new("signature verification failed"))
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    run_flow("passing validator", AlwaysAccept).await;
    run_flow("rejecting validator", AlwaysReject).await;
}

async fn run_flow(label: &str, validator: impl JwksValidator + 'static) {
    let fake =
        FakeOAuthServer::start_with_oidc("demo_token", "user_1", "user@example.com", "demo-client")
            .await;
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

    let client = CliTokenClient::builder()
        .client_id("demo-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .with_openid_scope()
        .open_browser(false)
        .jwks_validator(Box::new(validator))
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    match client.run_authorization_flow().await {
        Ok(tokens) => tracing::info!(
            scenario = label,
            subject = tokens
                .oidc()
                .map_or("<none>", |t| t.claims().sub().as_str()),
            "auth succeeded"
        ),
        Err(AuthError::IdToken(loopauth::IdTokenError::JwksValidationFailed(e))) => tracing::warn!(
            scenario = label,
            reason = e.message(),
            "auth rejected by validator"
        ),
        Err(e) => tracing::error!(scenario = label, error = %e, "auth failed"),
    }
}
