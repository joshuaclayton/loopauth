use loopauth::{CliTokenClient, OAuth2Scope, test_support::FakeOAuthServer};

#[tokio::test]
async fn oidc_round_trip_with_openid_scope_populates_claims() {
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
        .scopes(vec![OAuth2Scope::OpenId, OAuth2Scope::Email])
        .open_browser(false)
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build()
        .unwrap();

    let result = cli_auth
        .run_authorization_flow()
        .await
        .expect("run_authorization_flow should succeed");
    let oidc = result
        .oidc()
        .expect("oidc should be Some when openid scope present");
    assert_eq!(oidc.claims().sub().as_str(), "user_42");
    assert_eq!(
        oidc.claims().email().map(loopauth::oidc::Email::as_str),
        Some("user@example.com")
    );
}

#[tokio::test]
async fn no_openid_scope_oidc_is_none() {
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
        .open_browser(false)
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build()
        .unwrap();

    let result = cli_auth
        .run_authorization_flow()
        .await
        .expect("run_authorization_flow should succeed");
    assert!(
        result.oidc().is_none(),
        "oidc should be None when openid scope absent"
    );
}
