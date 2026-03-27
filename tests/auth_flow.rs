#![expect(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "tests do not need to meet production lint standards"
)]
use loopauth::{
    AuthError, CallbackError, CliTokenClient, ExtraAuthParams, test_support::FakeOAuthServer,
};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn fake_oauth_server_smoke_test() {
    let fake = FakeOAuthServer::start("smoke_token").await;
    tokio::task::yield_now().await;

    let client = reqwest::Client::new();
    let response = client
        .post(fake.token_url())
        .form(&[("code_verifier", "test_verifier"), ("code", "fake_code")])
        .send()
        .await
        .expect("token request should succeed");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("body should be JSON");
    assert_eq!(body["access_token"], "smoke_token");
}

#[tokio::test]
async fn full_round_trip_returns_token_set() {
    let fake = FakeOAuthServer::start("expected_token").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();

    // Spawn a task that drives the browser flow by following the authorize redirect
    tokio::spawn(async move {
        if let Ok(url) = url_rx.recv() {
            // Follow the authorize URL - FakeOAuthServer will redirect to redirect_uri with code+state
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            // Get the redirect location from /authorize
            let response = client.get(&url).send().await.expect("authorize request");
            if let Some(location) = response.headers().get("location") {
                let callback_url = location.to_str().unwrap().to_string();
                // Follow the redirect to the loopback server
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
        .build();

    let result = cli_auth.run_authorization_flow().await;
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert_eq!(result.unwrap().access_token().as_str(), "expected_token");
}

#[tokio::test]
async fn state_mismatch_returns_err() {
    let port = Arc::new(Mutex::new(None::<u16>));
    let port_clone = Arc::clone(&port);

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(url::Url::parse("http://127.0.0.1:1/authorize").unwrap()) // won't be called
        .token_url(url::Url::parse("http://127.0.0.1:1/token").unwrap()) // won't be called
        .open_browser(false)
        .on_server_ready(move |p| {
            let mut guard = port_clone.lock().unwrap();
            *guard = Some(p);
        })
        .build();

    let auth_handle = tokio::spawn(async move { cli_auth.run_authorization_flow().await });

    // Wait for server to be ready
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if port.lock().unwrap().is_some() {
            break;
        }
    }
    let loopback_port = port.lock().unwrap().unwrap();

    // Drive /callback with the wrong state
    reqwest::get(format!(
        "http://127.0.0.1:{loopback_port}/callback?code=fake_code&state=WRONG_STATE"
    ))
    .await
    .ok();

    let result = auth_handle.await.unwrap();
    match result {
        Err(AuthError::Callback(CallbackError::StateMismatch)) => {}
        other => panic!("expected StateMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn timeout_returns_err() {
    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(url::Url::parse("http://127.0.0.1:1/authorize").unwrap()) // won't be called
        .token_url(url::Url::parse("http://127.0.0.1:1/token").unwrap())
        .open_browser(false)
        .timeout(std::time::Duration::from_millis(100))
        .build();

    let result = cli_auth.run_authorization_flow().await;
    match result {
        Err(AuthError::Timeout) => {}
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_error_in_callback_returns_err() {
    let port = Arc::new(Mutex::new(None::<u16>));
    let port_clone = Arc::clone(&port);

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(url::Url::parse("http://127.0.0.1:1/authorize").unwrap()) // won't be called
        .token_url(url::Url::parse("http://127.0.0.1:1/token").unwrap())
        .open_browser(false)
        .on_server_ready(move |p| {
            let mut guard = port_clone.lock().unwrap();
            *guard = Some(p);
        })
        .build();

    let auth_handle = tokio::spawn(async move { cli_auth.run_authorization_flow().await });

    // Wait for server to be ready
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if port.lock().unwrap().is_some() {
            break;
        }
    }
    let loopback_port = port.lock().unwrap().unwrap();

    // Drive /callback with provider error
    reqwest::get(format!(
        "http://127.0.0.1:{loopback_port}/callback?error=access_denied&error_description=User+denied"
    ))
    .await
    .ok();

    let result = auth_handle.await.unwrap();
    match result {
        Err(AuthError::Callback(CallbackError::ProviderError { error, .. })) => {
            assert_eq!(error, "access_denied");
        }
        other => panic!("expected ProviderError, got {other:?}"),
    }
}

#[tokio::test]
async fn non_2xx_token_response_returns_token_exchange_err() {
    let fake_error_server = FakeOAuthServer::start_error(400).await;
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
        .auth_url(fake_error_server.auth_url())
        .token_url(fake_error_server.token_url())
        .open_browser(false)
        .on_url(move |url| {
            let _ = url_tx.send(url.to_string());
        })
        .build();

    let result = cli_auth.run_authorization_flow().await;
    match result {
        Err(AuthError::TokenExchange { status: 400, .. }) => {}
        other => panic!("expected TokenExchange(400), got {other:?}"),
    }
}

#[tokio::test]
async fn code_verifier_sent_in_token_exchange() {
    // FakeOAuthServer::start() already validates code_verifier presence.
    // If PKCE code_verifier is missing, /token returns 400.
    // This test verifies the full round-trip succeeds, confirming code_verifier was sent.
    let fake = FakeOAuthServer::start("pkce_token").await;
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
        .build();

    let result = cli_auth.run_authorization_flow().await;
    assert!(
        result.is_ok(),
        "expected Ok (code_verifier was sent), got {result:?}"
    );
    assert_eq!(result.unwrap().access_token().as_str(), "pkce_token");
}

/// Drives the browser side of the auth flow: follows the authorize redirect and
/// fires the loopback callback.  Used by `on_auth_url` integration tests.
async fn drive_browser(url_rx: std::sync::mpsc::Receiver<String>) {
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
}

#[tokio::test]
async fn on_auth_url_extra_param_appears_in_auth_url() {
    let fake = FakeOAuthServer::start("tok").await;
    tokio::task::yield_now().await;

    // Channel for driving the browser; channel for capturing the auth URL.
    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    let (capture_tx, capture_rx) = std::sync::mpsc::channel::<String>();

    tokio::spawn(async move { drive_browser(url_rx).await });

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .open_browser(false)
        .on_auth_url(|params: &mut ExtraAuthParams| {
            params.append("access_type", "offline");
        })
        .on_url(move |url| {
            let _ = capture_tx.send(url.to_string());
            let _ = url_tx.send(url.to_string());
        })
        .build();

    cli_auth.run_authorization_flow().await.unwrap();

    let auth_url = url::Url::parse(&capture_rx.recv().unwrap()).unwrap();
    let pairs: std::collections::HashMap<_, _> = auth_url.query_pairs().collect();
    assert_eq!(
        pairs.get("access_type").map(std::convert::AsRef::as_ref),
        Some("offline"),
        "extra param 'access_type=offline' should appear in the auth URL"
    );
}

#[tokio::test]
async fn on_auth_url_reserved_param_is_not_overridden() {
    let fake = FakeOAuthServer::start("tok").await;
    tokio::task::yield_now().await;

    let (url_tx, url_rx) = std::sync::mpsc::channel::<String>();
    let (capture_tx, capture_rx) = std::sync::mpsc::channel::<String>();

    tokio::spawn(async move { drive_browser(url_rx).await });

    let cli_auth = CliTokenClient::builder()
        .client_id("test-client")
        .auth_url(fake.auth_url())
        .token_url(fake.token_url())
        .open_browser(false)
        .on_auth_url(|params: &mut ExtraAuthParams| {
            // Attempt to override a security-critical parameter.
            params.append("state", "INJECTED_STATE");
        })
        .on_url(move |url| {
            let _ = capture_tx.send(url.to_string());
            let _ = url_tx.send(url.to_string());
        })
        .build();

    cli_auth.run_authorization_flow().await.unwrap();

    let auth_url = url::Url::parse(&capture_rx.recv().unwrap()).unwrap();
    let state_values: Vec<_> = auth_url
        .query_pairs()
        .filter(|(k, _)| k == "state")
        .collect();
    // Exactly one `state` value (the library-generated UUID), not our injected value.
    assert_eq!(state_values.len(), 1, "state should appear exactly once");
    assert_ne!(
        state_values[0].1, "INJECTED_STATE",
        "reserved 'state' param must not be overridden by the hook"
    );
}
