#![expect(clippy::expect_used, reason = "CLI examples can be more lax")]
// # Usage
//   cargo run --example refresh_demo
//
// Runs offline using an in-process mock OAuth server.
// Demonstrates refresh_if_expiring() over ~15 seconds.
// Each token is issued with a 10s expiry and a 3s refresh threshold,
// so you see: countdown → refresh triggered → countdown → refresh triggered.

use loopauth::{CliTokenClient, RefreshOutcome, test_support::FakeOAuthServer};
use std::time::{Duration, SystemTime};

const TOKEN_LIFETIME_SECS: u64 = 10;
const REFRESH_THRESHOLD_SECS: u64 = 3;
const REFRESH_DURATION_SECS: u64 = 15;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let server = FakeOAuthServer::start_with_refresh_expiring_in(
        "demo_token",
        "demo_refresh_token",
        TOKEN_LIFETIME_SECS,
    )
    .await;

    let client = CliTokenClient::builder()
        .client_id("demo-client")
        .auth_url(server.auth_url())
        .token_url(server.token_url())
        .build();

    let mut current_tokens = client
        .refresh(server.refresh_token())
        .await
        .expect("initial token fetch");

    tracing::info!(
        valid_for_secs = ttl(&current_tokens).as_secs(),
        refresh_threshold_secs = REFRESH_THRESHOLD_SECS,
        "starting refresh loop"
    );

    for _ in 0..REFRESH_DURATION_SECS {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let remaining = ttl(&current_tokens);

        match client
            .refresh_if_expiring(&current_tokens, Duration::from_secs(REFRESH_THRESHOLD_SECS))
            .await
        {
            Ok(RefreshOutcome::Refreshed(new_tokens)) => {
                tracing::info!(
                    was_expiring_in_secs = remaining.as_secs(),
                    new_valid_for_secs = ttl(&new_tokens).as_secs(),
                    "token refreshed"
                );
                current_tokens = *new_tokens;
            }
            Ok(RefreshOutcome::NotNeeded) => {
                tracing::info!(valid_for_secs = remaining.as_secs(), "no refresh needed");
            }
            Err(e) => {
                tracing::error!(error = %e, "refresh failed");
                std::process::exit(1);
            }
        }
    }

    tracing::info!("refresh loop complete");
}

fn ttl(tokens: &loopauth::TokenSet) -> Duration {
    tokens
        .expires_at()
        .and_then(|t| t.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
}
