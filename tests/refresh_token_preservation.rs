#![expect(
    clippy::panic,
    clippy::expect_used,
    reason = "tests do not need to meet production lint standards"
)]

//! Tests for refresh token preservation when the provider omits `refresh_token`
//! from the token response (RFC 6749 §6).
//!
//! Providers like Google keep the original refresh token valid and simply don't
//! echo it back in the refresh response. The library must preserve the original
//! refresh token in the returned `TokenSet` so that downstream CLIs can persist
//! it and use it for future refreshes.

use loopauth::{CliTokenClient, RefreshOutcome, test_support::FakeOAuthServer};
use std::time::Duration;

fn make_client(server: &FakeOAuthServer) -> CliTokenClient {
    CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(server.auth_url())
        .token_url(server.token_url())
        .build()
}

/// When the provider omits `refresh_token` from the refresh response,
/// `refresh()` must preserve the original refresh token in the returned `TokenSet`.
#[tokio::test]
async fn refresh_preserves_token_when_provider_omits_it() {
    let server =
        FakeOAuthServer::start_with_refresh_token_omitted_from_response("new_access").await;

    let client = make_client(&server);
    let result = client.refresh("rt_original").await;

    match result {
        Ok(token_set) => {
            assert_eq!(
                token_set.access_token().as_str(),
                "new_access",
                "access token should be the new value from the provider"
            );
            assert!(
                token_set.refresh_token().is_some(),
                "refresh token must be preserved when the provider omits it from the response"
            );
            assert_eq!(
                token_set
                    .refresh_token()
                    .expect("just asserted Some")
                    .as_str(),
                "rt_original",
                "preserved refresh token must match the one that was sent"
            );
        }
        Err(e) => panic!("expected Ok(token_set), got {e:?}"),
    }
}

/// Same scenario but exercised through `refresh_if_expiring`, which is the
/// typical CLI code path: load expired tokens from disk, refresh, persist.
#[tokio::test]
async fn refresh_if_expiring_preserves_token_when_provider_omits_it() {
    let server =
        FakeOAuthServer::start_with_refresh_token_omitted_from_response("new_access").await;

    let client = make_client(&server);

    // Build an already-expired TokenSet with a refresh token, simulating
    // what a CLI would load from disk.
    let expired_tokens: loopauth::TokenSet<loopauth::Unvalidated> =
        serde_json::from_value(serde_json::json!({
            "access_token": "old_access",
            "token_type": "Bearer",
            "refresh_token": "rt_original",
            "expires_at": 0
        }))
        .expect("deserialize expired token set");
    let expired_tokens = expired_tokens.into_validated();

    let outcome = client
        .refresh_if_expiring(&expired_tokens, Duration::from_secs(300))
        .await;

    match outcome {
        Ok(RefreshOutcome::Refreshed(new_tokens)) => {
            assert_eq!(new_tokens.access_token().as_str(), "new_access");
            assert!(
                new_tokens.refresh_token().is_some(),
                "refresh token must be preserved when the provider omits it from the response"
            );
            assert_eq!(
                new_tokens
                    .refresh_token()
                    .expect("just asserted Some")
                    .as_str(),
                "rt_original",
                "preserved refresh token must match the one from the original TokenSet"
            );
        }
        Ok(RefreshOutcome::NotNeeded) => {
            panic!("expected Refreshed, got NotNeeded — token should be expired")
        }
        Err(e) => panic!("expected Refreshed, got error: {e:?}"),
    }
}
