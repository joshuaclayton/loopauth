#![expect(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests do not need to meet production lint standards"
)]
use loopauth::{CliTokenClient, TokenResponseFields, test_support::FakeOAuthServer};

#[derive(serde::Deserialize)]
struct NestedTokenResponse {
    authed_user: NestedAuthedUser,
}

#[derive(serde::Deserialize)]
struct NestedAuthedUser {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl From<NestedTokenResponse> for TokenResponseFields {
    fn from(resp: NestedTokenResponse) -> Self {
        Self::new(resp.authed_user.access_token)
            .with_refresh_token(resp.authed_user.refresh_token)
            .with_expires_in(resp.authed_user.expires_in)
            .with_token_type(Some("Bearer".to_string()))
    }
}

#[tokio::test]
async fn nested_response_smoke_test() {
    let fake = FakeOAuthServer::start_with_nested_response("nested_token").await;
    tokio::task::yield_now().await;

    let client = reqwest::Client::new();
    let response = client
        .post(fake.token_url())
        .form(&[("code_verifier", "test_verifier"), ("code", "fake_code")])
        .send()
        .await
        .expect("token request should succeed");
    assert_eq!(response.status(), 200, "should return 200");
    let body: serde_json::Value = response.json().await.expect("body should be JSON");
    assert_eq!(
        body["authed_user"]["access_token"], "nested_token",
        "access_token should be nested"
    );
    assert!(
        body.get("access_token").is_none(),
        "no top-level access_token"
    );
}

#[tokio::test]
async fn full_round_trip_with_custom_token_response_type() {
    let fake = FakeOAuthServer::start_with_nested_response("xoxp-nested-token").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();

    tokio::spawn(async move {
        if let Ok(url) = url_rx.recv() {
            let _ = reqwest::get(url).await;
        }
    });

    let client = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .open_browser(false)
        .token_response_type::<NestedTokenResponse>()
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let tokens = client.run_authorization_flow().await.unwrap();
    assert_eq!(
        tokens.access_token().as_str(),
        "xoxp-nested-token",
        "should extract token from nested response"
    );
}

#[tokio::test]
async fn default_parser_rejects_nested_response() {
    let fake = FakeOAuthServer::start_with_nested_response("xoxp-nested-token").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();

    tokio::spawn(async move {
        if let Ok(url) = url_rx.recv() {
            let _ = reqwest::get(url).await;
        }
    });

    // Build WITHOUT .token_response_type — should fail to parse nested response
    let client = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .open_browser(false)
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let result = client.run_authorization_flow().await;
    assert!(
        result.is_err(),
        "default parser should fail on nested response"
    );
}
