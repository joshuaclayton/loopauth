#![expect(
    clippy::print_stdout,
    clippy::exit,
    clippy::expect_used,
    reason = "CLI examples can be more lax"
)]
//! End-to-end Slack OAuth v2 token acquisition example.
//!
//! Slack's OAuth v2 deviates from RFC 6749 in several ways:
//!
//! - **Nested token response**: The access token lives inside an `authed_user`
//!   sub-object, not at the top level. This example uses
//!   [`CliTokenClientBuilder::token_response_type`] with a custom
//!   [`From<SlackV2TokenResponse> for TokenResponseFields`] to extract the
//!   standard fields from the nested structure.
//!
//! - **Comma-delimited scopes**: Slack returns granted scopes separated by
//!   commas instead of the RFC 6749 §3.3 space delimiter. The `From` impl
//!   normalizes commas to spaces so loopauth's scope resolution works
//!   correctly.
//!
//! - **`user_scope` parameter**: Slack uses a non-standard `user_scope` query
//!   parameter on the authorization URL (rather than the standard `scope`
//!   parameter). [`ExtraAuthParams`] handles this via `on_auth_url`.
//!
//! - **HTTPS redirect required**: Slack requires `https://` redirect URIs,
//!   even on localhost. This example uses [`TlsCertificate::ensure_localhost`]
//!   with a fixed port.
//!
//! # Required environment variables
//!
//! | Variable                 | Description                                 |
//! |--------------------------|---------------------------------------------|
//! | `LOOPAUTH_CLIENT_ID`     | OAuth 2.0 client ID from api.slack.com      |
//! | `LOOPAUTH_CLIENT_SECRET` | OAuth 2.0 client secret                     |
//! | `LOOPAUTH_TLS_DIR`       | Directory for managed TLS certs (via mkcert)|
//!
//! # Optional environment variables
//!
//! | Variable          | Description                    | Default                                                   |
//! |-------------------|--------------------------------|-----------------------------------------------------------|
//! | `LOOPAUTH_SCOPES` | Comma-separated user scopes    | `channels:history,channels:read,groups:history,groups:read`|
//! | `LOOPAUTH_PORT`   | Port for the HTTPS loopback    | `8443`                                                    |
//!
//! # Setup
//!
//! 1. Go to <https://api.slack.com/apps> and create a new app.
//! 2. Under **OAuth & Permissions**, add `https://127.0.0.1:8443/callback`
//!    as a redirect URL.
//! 3. Under **User Token Scopes**, add the scopes you need.
//! 4. Copy the **Client ID** and **Client Secret** from **Basic Information**.
//! 5. Install [`mkcert`](https://github.com/FiloSottile/mkcert) and run
//!    `mkcert -install` once to trust the local CA.
//!
//! ```sh
//! LOOPAUTH_CLIENT_ID=... \
//! LOOPAUTH_CLIENT_SECRET=... \
//! LOOPAUTH_TLS_DIR=~/.config/loopauth-slack/tls \
//! cargo run --example auth_slack
//! ```

use loopauth::{CliTokenClient, TlsCertificate, TokenResponseFields};

const SLACK_AUTH_URL: &str = "https://slack.com/oauth/v2/authorize";
const SLACK_TOKEN_URL: &str = "https://slack.com/api/oauth.v2.access";
const DEFAULT_SCOPES: &str = "channels:history,channels:read,groups:history,groups:read";
const DEFAULT_PORT: u16 = 8443;
const FAILURE_EXIT_CODE: i32 = 1;
const SIGINT_EXIT_CODE: i32 = 130;

// Slack nests user tokens inside `authed_user` rather than at the top level.
// We deserialize into this shape and then convert to `TokenResponseFields`.

#[derive(serde::Deserialize)]
struct SlackV2TokenResponse {
    authed_user: SlackAuthedUser,
}

#[derive(serde::Deserialize)]
struct SlackAuthedUser {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

impl From<SlackV2TokenResponse> for TokenResponseFields {
    fn from(resp: SlackV2TokenResponse) -> Self {
        // Slack returns scopes comma-separated; RFC 6749 §3.3 uses spaces.
        let scope = resp.authed_user.scope.map(|s| s.replace(',', " "));

        Self::new(resp.authed_user.access_token)
            .with_refresh_token(resp.authed_user.refresh_token)
            .with_expires_in(resp.authed_user.expires_in)
            .with_token_type(Some("Bearer".to_string()))
            .with_scope(scope)
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let client_id = require_env("LOOPAUTH_CLIENT_ID");
    let client_secret = require_env("LOOPAUTH_CLIENT_SECRET");
    let user_scopes =
        std::env::var("LOOPAUTH_SCOPES").unwrap_or_else(|_| DEFAULT_SCOPES.to_string());
    let port: u16 = std::env::var("LOOPAUTH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let auth_url = url::Url::parse(SLACK_AUTH_URL).expect("Slack auth URL is valid");
    let token_url = url::Url::parse(SLACK_TOKEN_URL).expect("Slack token URL is valid");

    // Slack requires HTTPS redirect URIs, even on localhost.
    let tls_dir = require_env("LOOPAUTH_TLS_DIR");
    tracing::info!("using managed TLS certificates in {tls_dir}");
    let cert = TlsCertificate::ensure_localhost(&tls_dir).unwrap_or_else(|e| {
        tracing::error!("TLS certificate setup failed: {e}");
        if matches!(e, loopauth::TlsCertificateError::MkcertNotFound) {
            println!("\n{}", TlsCertificate::SETUP_GUIDE_MANAGED);
        }
        std::process::exit(FAILURE_EXIT_CODE);
    });

    let client = CliTokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .auth_url(auth_url)
        .token_url(token_url)
        // Parse Slack's nested `authed_user` response into standard fields.
        .token_response_type::<SlackV2TokenResponse>()
        .use_https_with(cert)
        .require_port(port)
        // Slack uses `user_scope` instead of the standard `scope` parameter.
        .on_auth_url(move |params| {
            params.append("user_scope", &user_scopes);
        })
        .on_url(|url| {
            tracing::info!("opening: {url}");
            tracing::info!("waiting for browser callback... (Ctrl+C to cancel)");
        })
        .build();

    tracing::info!("starting Slack OAuth v2 authorization flow");

    match client.run_authorization_flow().await {
        Ok(tokens) => {
            println!("\n=== Authentication successful ===");
            println!("access_token : {}", tokens.access_token());

            if let Some(rt) = tokens.refresh_token() {
                println!("refresh_token: {rt}");
            }

            let scopes: Vec<String> = tokens.scopes().iter().map(ToString::to_string).collect();
            if !scopes.is_empty() {
                println!("scopes       : {}", scopes.join(", "));
            }

            if let Some(expires) = tokens.expires_at()
                && let Ok(remaining) = expires.duration_since(std::time::SystemTime::now())
            {
                println!("expires in   : {}s", remaining.as_secs());
            }
        }
        Err(loopauth::AuthError::Cancelled) => {
            tracing::info!("cancelled");
            std::process::exit(SIGINT_EXIT_CODE);
        }
        Err(e) => {
            tracing::error!("authentication failed: {e}");
            std::process::exit(FAILURE_EXIT_CODE);
        }
    }
}

fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        tracing::error!("{name} ENV var not set");
        std::process::exit(FAILURE_EXIT_CODE);
    })
}
