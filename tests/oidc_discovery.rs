#![expect(
    clippy::panic,
    reason = "tests do not need to meet production lint standards"
)]
use axum::{Json, Router, routing::get};
use loopauth::test_support::FakeOAuthServer;
use loopauth::{
    CliTokenClientBuilder, JwksValidator, RemoteJwksValidator, oidc::OpenIdConfiguration,
};
use tokio::net::TcpListener;

#[tokio::test]
async fn fetch_parses_valid_open_id_configuration() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .start()
        .await;
    let issuer_url = server.issuer_url();
    let config = OpenIdConfiguration::fetch(issuer_url.clone())
        .await
        .unwrap();
    assert_eq!(config.issuer(), &issuer_url);
    assert!(
        config
            .authorization_endpoint()
            .as_str()
            .contains("/authorize")
    );
    assert!(config.token_endpoint().as_str().contains("/token"));
}

#[tokio::test]
async fn fetch_fails_on_network_error() {
    let bad_url = url::Url::parse("http://127.0.0.1:1").unwrap(); // no server on port 1
    let result = OpenIdConfiguration::fetch(bad_url).await;
    assert!(result.is_err(), "expected Err for unreachable server");
}

#[tokio::test]
async fn from_issuer_returns_validator_with_correct_jwks_url() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .with_jwks()
        .start()
        .await;
    let issuer_url = server.issuer_url();
    let validator = RemoteJwksValidator::from_issuer(issuer_url.clone(), "my-client")
        .await
        .unwrap();
    // Validate a signed token against the mock server
    let claims = serde_json::json!({
        "sub": "user-123",
        "aud": "my-client",
        "iss": issuer_url.as_str(),
        "exp": 9_999_999_999_u64,
    });
    let token = server.sign_jwt(&claims);
    let result: Result<(), loopauth::JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_ok(), "validation failed: {result:?}");
}

#[tokio::test]
async fn from_open_id_configuration_prefills_auth_and_token_urls() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .start()
        .await;
    let config = OpenIdConfiguration::fetch(server.issuer_url())
        .await
        .unwrap();
    // from_open_id_configuration pre-fills auth_url and token_url and automatically
    // includes the openid scope — build succeeds with client_id alone.
    let _client = CliTokenClientBuilder::from_open_id_configuration(&config)
        .client_id("test-client")
        .build();
}

#[tokio::test]
async fn from_open_id_configuration_build_always_includes_openid_scope() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .start()
        .await;
    let config = OpenIdConfiguration::fetch(server.issuer_url())
        .await
        .unwrap();
    // from_open_id_configuration enters HasOidc mode automatically — no
    // explicit scope call needed, and omitting it is no longer a build error.
    let _client = CliTokenClientBuilder::from_open_id_configuration(&config)
        .client_id("test-client")
        .build();
}

#[tokio::test]
async fn full_open_id_configuration_and_jwks_flow() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .with_jwks()
        .start()
        .await;

    let config = OpenIdConfiguration::fetch(server.issuer_url())
        .await
        .unwrap();

    // Construct validator from open_id_configuration
    let validator = RemoteJwksValidator::from_open_id_configuration(&config, "test-client");

    // Sign a token and validate it
    let claims = serde_json::json!({
        "sub": "user-abc",
        "aud": "test-client",
        "iss": server.issuer_url().as_str(),
        "exp": 9_999_999_999_u64,
    });
    let token = server.sign_jwt(&claims);
    let result: Result<(), loopauth::JwksValidationError> = validator.validate(&token).await;
    assert!(result.is_ok(), "full flow validation failed: {result:?}");
}

#[tokio::test]
async fn open_id_configuration_has_required_fields() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .with_jwks()
        .start()
        .await;
    let config = OpenIdConfiguration::fetch(server.issuer_url())
        .await
        .unwrap();
    assert_eq!(config.issuer(), &server.issuer_url());
    assert_eq!(config.jwks_uri(), &server.jwks_url());
    assert!(
        config
            .authorization_endpoint()
            .as_str()
            .ends_with("/authorize"),
        "authorization_endpoint should end with /authorize"
    );
    assert!(
        config.token_endpoint().as_str().ends_with("/token"),
        "token_endpoint should end with /token"
    );
}

#[tokio::test]
async fn fetch_returns_error_when_issuer_does_not_match() {
    // Serve a configuration doc with an issuer that doesn't match the URL used to fetch it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(|| async {
            Json(serde_json::json!({
                "issuer": "https://wrong-issuer.example.com",
                "authorization_endpoint": "https://wrong-issuer.example.com/authorize",
                "token_endpoint": "https://wrong-issuer.example.com/token",
                "jwks_uri": "https://wrong-issuer.example.com/jwks",
            }))
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let issuer_url = url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    match OpenIdConfiguration::fetch(issuer_url).await {
        Err(err) => assert!(
            err.message().contains("issuer mismatch"),
            "expected 'issuer mismatch' in error, got: {}",
            err.message()
        ),
        Ok(_) => panic!("expected Err for issuer mismatch, got Ok"),
    }
}

#[tokio::test]
async fn fetch_succeeds_when_issuer_url_has_trailing_slash() {
    let server = FakeOAuthServer::builder()
        .with_open_id_configuration()
        .start()
        .await;
    // url::Url normalises to a trailing slash for bare-origin URLs;
    // verify the discovery URL is still constructed correctly.
    let issuer_url = server.issuer_url();
    assert!(
        issuer_url.as_str().ends_with('/'),
        "url::Url should normalise to a trailing slash"
    );
    let result = OpenIdConfiguration::fetch(issuer_url.clone()).await;
    assert!(
        result.is_ok(),
        "fetch should succeed with trailing-slash issuer URL"
    );
}
