#![expect(
    clippy::panic,
    clippy::expect_used,
    reason = "tests do not need to meet production lint standards"
)]
use loopauth::{CliTokenClient, RefreshError, RefreshOutcome, test_support::FakeOAuthServer};
use std::time::Duration;

fn make_auth(server: &FakeOAuthServer) -> CliTokenClient {
    CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(server.auth_url())
        .token_url(server.token_url())
        .build()
}

#[tokio::test]
async fn empty_refresh_token() {
    let server = FakeOAuthServer::start_with_refresh("access_token", "refresh_token").await;
    tokio::task::yield_now().await;

    let auth = make_auth(&server);
    let result = auth.refresh("").await;

    match result {
        Err(RefreshError::NoRefreshToken) => {}
        other => panic!("expected NoRefreshToken, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_returns_token_set() {
    let server = FakeOAuthServer::start_with_refresh("new_access_token", "my_refresh_token").await;
    tokio::task::yield_now().await;

    let auth = make_auth(&server);
    let result = auth.refresh("my_refresh_token").await;

    match result {
        Ok(token_set) => assert_eq!(token_set.access_token().as_str(), server.access_token()),
        Err(e) => panic!("expected Ok(token_set), got {e:?}"),
    }
}

#[tokio::test]
async fn non_2xx_refresh() {
    let server = FakeOAuthServer::start_error(500).await;
    tokio::task::yield_now().await;

    let auth = make_auth(&server);
    let result = auth.refresh("some_rt").await;

    match result {
        Err(RefreshError::TokenExchange { status: 500, .. }) => {}
        other => panic!("expected TokenExchange(500), got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_if_expiring_not_needed() {
    let server = FakeOAuthServer::start_with_refresh("access_token", "refresh_token_value").await;
    tokio::task::yield_now().await;

    let auth = make_auth(&server);
    let token_set = auth
        .refresh(server.refresh_token())
        .await
        .expect("initial refresh should succeed");

    // Token has ~3600s expiry; 60s threshold means it is NOT expiring soon
    let result = auth
        .refresh_if_expiring(&token_set, Duration::from_secs(60))
        .await;

    match result {
        Ok(RefreshOutcome::NotNeeded) => {}
        other => panic!("expected NotNeeded, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_if_expiring_refreshed() {
    let server = FakeOAuthServer::start_with_refresh("access_token", "refresh_token_value").await;
    tokio::task::yield_now().await;

    let auth = make_auth(&server);
    let token_set = auth
        .refresh(server.refresh_token())
        .await
        .expect("initial refresh should succeed");

    // Token has ~3600s expiry; 7200s threshold means it IS expiring soon
    let result = auth
        .refresh_if_expiring(&token_set, Duration::from_secs(7200))
        .await;

    match result {
        Ok(RefreshOutcome::Refreshed(_)) => {}
        other => panic!("expected Refreshed(_), got {other:?}"),
    }
}
