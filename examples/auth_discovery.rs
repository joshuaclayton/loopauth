#![expect(
    clippy::print_stdout,
    clippy::exit,
    reason = "CLI examples can be more lax"
)]
//! End-to-end provider token acquisition example (OIDC discovery).
//!
//! Fetches provider endpoints and JWKS from the issuer's discovery document,
//! eliminating manual endpoint configuration.
//!
//! # Required environment variables
//!
//! | Variable               | Description                           |
//! |------------------------|---------------------------------------|
//! | `LOOPAUTH_CLIENT_ID`   | `OAuth2` client ID from your provider |
//! | `LOOPAUTH_ISSUER_URL`  | OIDC issuer URL                       |
//!
//! # Optional environment variables
//!
//! | Variable                 | Description                                    | Default                |
//! |--------------------------|------------------------------------------------|------------------------|
//! | `LOOPAUTH_CLIENT_SECRET` | Client secret                                  | -                      |
//! | `LOOPAUTH_SCOPES`        | Comma-separated scopes (must include `openid`) | `openid,email,profile` |
//! | `LOOPAUTH_PORT`          | Port hint for the loopback server              | OS-assigned            |
//!
//! # Security note
//!
//! The `client_secret` cannot be kept confidential once distributed (it is trivially
//! extractable from the executable). This is an accepted limitation of desktop OAuth clients.
//! PKCE mitigates authorization code interception but does not protect the secret.
//!
//! # Provider quick-start
//!
//! **Google**
//! ```
//! LOOPAUTH_CLIENT_ID=...apps.googleusercontent.com \
//! LOOPAUTH_CLIENT_SECRET=... \
//! LOOPAUTH_ISSUER_URL=https://accounts.google.com \
//! cargo run --example auth_discovery
//! ```
//! Add `http://127.0.0.1` (any port) to your Google OAuth app's Authorized Redirect URIs.
//!
//! Note: Google's token endpoint requires `LOOPAUTH_CLIENT_SECRET` even for desktop app
//! credentials - include the value from your credentials JSON.

use loopauth::{CliTokenClientBuilder, OAuth2Scope, oidc::OpenIdConfiguration};
use url::Url;

const DEFAULT_SCOPES: &str = "openid,email,profile";
const FAILURE_EXIT_CODE: i32 = 1;
const SIGINT_EXIT_CODE: i32 = 130; // conventional exit code for Ctrl+C

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let client_id = require_env("LOOPAUTH_CLIENT_ID");
    let issuer_url = Url::parse(&require_env("LOOPAUTH_ISSUER_URL")).unwrap_or_else(|e| {
        tracing::error!("LOOPAUTH_ISSUER_URL is not a valid URL: {e}");
        std::process::exit(FAILURE_EXIT_CODE);
    });

    let client_secret = std::env::var("LOOPAUTH_CLIENT_SECRET").ok();
    let scopes = parse_scopes(
        &std::env::var("LOOPAUTH_SCOPES").unwrap_or_else(|_| DEFAULT_SCOPES.to_string()),
    );
    let port_hint = std::env::var("LOOPAUTH_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if !scopes.contains(&OAuth2Scope::OpenId) {
        tracing::error!("LOOPAUTH_SCOPES must include 'openid'");
        std::process::exit(FAILURE_EXIT_CODE);
    }

    tracing::info!(issuer = issuer_url.as_str(), "fetching OIDC configuration");
    let open_id_configuration = OpenIdConfiguration::fetch(issuer_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("OIDC discovery failed: {e}");
            std::process::exit(FAILURE_EXIT_CODE);
        });

    let mut builder = CliTokenClientBuilder::from_open_id_configuration(&open_id_configuration)
        .client_id(client_id)
        .scopes(scopes)
        .with_open_id_configuration_jwks_validator(&open_id_configuration)
        .on_url(|url| {
            tracing::info!("opening: {url}");
            tracing::info!("waiting for browser callback... (Ctrl+C to cancel)");
        });

    if let Some(secret) = client_secret {
        builder = builder.client_secret(secret);
    }
    if let Some(port) = port_hint {
        builder = builder.port_hint(port);
    }

    let auth = builder.build().unwrap_or_else(|e| {
        tracing::error!("configuration error: {e}");
        std::process::exit(FAILURE_EXIT_CODE);
    });

    tracing::info!("starting authorization flow");

    match auth.run_authorization_flow().await {
        Ok(tokens) => {
            println!("\n=== Authentication successful ===");
            println!("access_token : {}", tokens.access_token());

            if let Some(rt) = tokens.refresh_token() {
                println!("refresh_token: {rt}");
            }

            if let Some(oidc) = tokens.oidc() {
                println!("\n=== OIDC claims ===");
                println!("sub   : {}", oidc.claims().sub());
                if let Some(email) = oidc.claims().email() {
                    println!("email : {email}");
                }
                if let Some(name) = oidc.claims().name() {
                    println!("name  : {name}");
                }
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

fn parse_scopes(s: &str) -> Vec<OAuth2Scope> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(OAuth2Scope::from)
        .collect()
}
