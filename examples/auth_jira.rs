#![expect(
    clippy::print_stdout,
    clippy::exit,
    clippy::expect_used,
    reason = "CLI examples can be more lax"
)]
//! End-to-end Jira token acquisition example.
//!
//! Atlassian's OAuth 2.0 (3LO) flow differs from generic providers in two ways:
//! `audience` and `prompt=consent` are required on the authorization request,
//! and redirect URIs must include an exact port number.
//!
//! # Required environment variables
//!
//! | Variable             | Description                                        |
//! |----------------------|----------------------------------------------------|
//! | `LOOPAUTH_CLIENT_ID` | OAuth 2.0 client ID from developer.atlassian.com   |
//!
//! # Optional environment variables
//!
//! | Variable                 | Description                        | Default                                             |
//! |--------------------------|------------------------------------|-----------------------------------------------------|
//! | `LOOPAUTH_CLIENT_SECRET` | Client secret                      | -                                                   |
//! | `LOOPAUTH_SCOPES`        | Comma-separated scopes             | `read:issue:jira,read:issue:jira-software,...`      |
//! | `LOOPAUTH_PORT`          | Port for the loopback server       | OS-assigned — **must** match your registered callback |
//!
//! # Setup
//!
//! 1. Go to <https://developer.atlassian.com/console/myapps/> and create an
//!    OAuth 2.0 (3LO) app.
//! 2. Under **Permissions**, add the Jira API and enable the relevant
//!    granular scopes you need. See `DEFAULT_SCOPES` below for a
//!    minimal set of Jira read scopes.
//! 3. Under **Authorization**, add `http://127.0.0.1:<PORT>/callback` as a
//!    callback URL. Atlassian requires an exact URI match including port;
//!    pick a fixed port (e.g. `8080`) and use it consistently.
//! 4. Under **Settings**, copy the **Client ID** and **Secret**.
//!
//! ```sh
//! LOOPAUTH_CLIENT_ID=... \
//! LOOPAUTH_CLIENT_SECRET=... \
//! LOOPAUTH_PORT=8080 \
//! cargo run --example auth_jira
//! ```
//!
//! # Security note
//!
//! The `client_secret` cannot be kept confidential once distributed (it is trivially
//! extractable from the executable). This is an accepted limitation of desktop OAuth clients.
//! PKCE mitigates authorization code interception but does not protect the secret.

use loopauth::{CliTokenClient, RequestScope};

const ATLASSIAN_AUTH_URL: &str = "https://auth.atlassian.com/authorize";
const ATLASSIAN_TOKEN_URL: &str = "https://auth.atlassian.com/oauth/token";
const ATLASSIAN_RESOURCES_URL: &str = "https://api.atlassian.com/oauth/token/accessible-resources";
const DEFAULT_SCOPES: &str = "read:issue:jira,read:issue:jira-software,read:comment:jira,read:project:jira,read:user:jira,read:issue.changelog:jira,offline_access";
const FAILURE_EXIT_CODE: i32 = 1;
const SIGINT_EXIT_CODE: i32 = 130;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let client_id = require_env("LOOPAUTH_CLIENT_ID");
    let auth_url = url::Url::parse(ATLASSIAN_AUTH_URL).expect("Atlassian auth URL is valid");
    let token_url = url::Url::parse(ATLASSIAN_TOKEN_URL).expect("Atlassian token URL is valid");

    let client_secret = std::env::var("LOOPAUTH_CLIENT_SECRET").ok();
    let scopes = parse_scopes(
        &std::env::var("LOOPAUTH_SCOPES").unwrap_or_else(|_| DEFAULT_SCOPES.to_string()),
    );
    let port_hint = std::env::var("LOOPAUTH_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    let mut builder = CliTokenClient::builder()
        .client_id(client_id)
        .auth_url(auth_url)
        .token_url(token_url)
        .add_scopes(scopes)
        .on_auth_url(|params| {
            params.append("audience", "api.atlassian.com");
            params.append("prompt", "consent");
        })
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

    let auth = builder.build();

    tracing::info!("starting authorization flow");

    match auth.run_authorization_flow().await {
        Ok(tokens) => {
            println!("\n=== Authentication successful ===");
            println!("access_token : {}", tokens.access_token());

            if let Some(rt) = tokens.refresh_token() {
                println!("refresh_token: {rt}");
            }

            print_accessible_resources(tokens.access_token().as_str()).await;
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

async fn print_accessible_resources(access_token: &str) {
    let client = reqwest::Client::new();
    let response = client
        .get(ATLASSIAN_RESOURCES_URL)
        .bearer_auth(access_token)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Vec<serde_json::Value>>().await {
                Ok(sites) => {
                    println!("\n=== Accessible Jira sites ===");
                    for site in &sites {
                        let id = site.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        let name = site.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let url = site.get("url").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("name : {name}");
                        println!("url  : {url}");
                        println!("api  : https://api.atlassian.com/ex/jira/{id}/rest/api/3");
                    }
                }
                Err(e) => tracing::warn!("could not parse accessible-resources response: {e}"),
            }
        }
        Ok(resp) => tracing::warn!(
            status = resp.status().as_u16(),
            "accessible-resources request failed"
        ),
        Err(e) => tracing::warn!("accessible-resources request error: {e}"),
    }
}

fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        tracing::error!("{name} ENV var not set");
        std::process::exit(FAILURE_EXIT_CODE);
    })
}

fn parse_scopes(s: &str) -> Vec<RequestScope> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(RequestScope::from)
        .collect()
}
