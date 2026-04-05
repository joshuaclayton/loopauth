#![expect(
    clippy::unwrap_used,
    reason = "tests do not need to meet production lint standards"
)]

use async_trait::async_trait;
use loopauth::{
    CliTokenClient, PageContext, RequestScope, SuccessPageRenderer, test_support::FakeOAuthServer,
};
use std::sync::{Arc, Mutex};

/// Captures the scopes from `PageContext` during rendering.
struct ScopeCapturingRenderer {
    captured_scopes: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl SuccessPageRenderer for ScopeCapturingRenderer {
    async fn render_success(&self, ctx: &PageContext<'_>) -> String {
        let scopes: Vec<String> = ctx.scopes().iter().map(ToString::to_string).collect();
        *self.captured_scopes.lock().unwrap() = scopes;
        "ok".to_string()
    }
}

/// When the provider returns a narrower scope than requested, `PageContext.scopes()`
/// should reflect the provider-granted scopes, not the builder-configured scopes.
///
/// RFC 6749 §5.1: "If the scope of the access token is identical to the scope
/// requested by the client, the authorization server MAY omit the scope
/// response parameter. If the issued scope differs, the authorization server
/// MUST include the scope response parameter."
#[tokio::test]
async fn page_context_shows_response_granted_scopes_not_builder_scopes() {
    // Server grants only "read", even though client requests "read" and "write"
    let fake = FakeOAuthServer::start_with_scope("tok", "read").await;
    tokio::task::yield_now().await;

    let captured_scopes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let renderer_scopes = Arc::clone(&captured_scopes);

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
        .add_scopes([
            RequestScope::Custom("read".into()),
            RequestScope::Custom("write".into()),
        ])
        .open_browser(false)
        .success_renderer(ScopeCapturingRenderer {
            captured_scopes: renderer_scopes,
        })
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let tokens = client.run_authorization_flow().await.unwrap();

    // TokenSet.scopes() should reflect the response-granted scope
    let token_scopes: Vec<String> = tokens.scopes().iter().map(ToString::to_string).collect();
    assert_eq!(
        token_scopes,
        vec!["read"],
        "TokenSet should have response-granted scopes"
    );

    // PageContext.scopes() should ALSO reflect the response-granted scope,
    // not the builder-configured ["read", "write"]
    let page_scopes = captured_scopes.lock().unwrap().clone();
    assert_eq!(
        page_scopes,
        vec!["read"],
        "PageContext should show response-granted scopes, not builder-configured scopes"
    );
}

/// When the provider omits scope from the response, `PageContext.scopes()` should
/// fall back to the requested scopes per RFC 6749 §5.1.
#[tokio::test]
async fn page_context_falls_back_to_requested_scopes_when_response_omits_scope() {
    // Server returns no scope field — standard FakeOAuthServer behavior
    let fake = FakeOAuthServer::start("tok").await;
    tokio::task::yield_now().await;

    let captured_scopes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let renderer_scopes = Arc::clone(&captured_scopes);

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
        .add_scopes([
            RequestScope::Custom("read".into()),
            RequestScope::Custom("write".into()),
        ])
        .open_browser(false)
        .success_renderer(ScopeCapturingRenderer {
            captured_scopes: renderer_scopes,
        })
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let tokens = client.run_authorization_flow().await.unwrap();

    // When provider omits scope, TokenSet uses the requested scopes
    let token_scopes: Vec<String> = tokens.scopes().iter().map(ToString::to_string).collect();
    assert!(
        token_scopes.contains(&"read".to_string()),
        "TokenSet should fall back to requested scopes"
    );
    assert!(
        token_scopes.contains(&"write".to_string()),
        "TokenSet should fall back to requested scopes"
    );

    // PageContext should match TokenSet — both use response-granted (or fallback) scopes
    let page_scopes = captured_scopes.lock().unwrap().clone();
    assert_eq!(
        page_scopes, token_scopes,
        "PageContext scopes should match TokenSet scopes"
    );
}
