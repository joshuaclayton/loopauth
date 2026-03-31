#![expect(
    clippy::print_stdout,
    clippy::exit,
    clippy::expect_used,
    reason = "CLI examples can be more lax"
)]
//! HTTPS provider token acquisition example using locally-trusted certificates.
//!
//! This example demonstrates two approaches for OAuth providers that require
//! HTTPS redirect URIs (e.g. Slack):
//!
//! - **Managed mode** (recommended): Set `LOOPAUTH_TLS_DIR` and loopauth
//!   generates certs automatically via `mkcert` on first run.
//! - **Manual mode**: Set `LOOPAUTH_CERT_FILE` and `LOOPAUTH_KEY_FILE` to
//!   load pre-existing PEM files.
//!
//! # One-time setup (both modes)
//!
//! Install [`mkcert`](https://github.com/FiloSottile/mkcert) and trust the
//! local CA:
//!
//! ```sh
//! brew install mkcert    # macOS; see mkcert docs for Linux/Windows
//! mkcert -install         # one-time, may prompt for password
//! ```
//!
//! For managed mode, that's all you need. Certs are generated on first run.
//!
//! For manual mode, also generate the cert files:
//!
//! ```sh
//! mkcert -cert-file localhost-cert.pem -key-file localhost-key.pem localhost 127.0.0.1
//! ```
//!
//! Print the full guide from code:
//!
//! ```sh
//! cargo run --example auth_https -- --setup-guide
//! ```
//!
//! # Required environment variables
//!
//! | Variable             | Description                           |
//! |----------------------|---------------------------------------|
//! | `LOOPAUTH_CLIENT_ID` | `OAuth 2.0` client ID from your provider  |
//! | `LOOPAUTH_AUTH_URL`  | Authorization endpoint URL            |
//! | `LOOPAUTH_TOKEN_URL` | Token endpoint URL                    |
//!
//! Plus one of the following certificate configurations:
//!
//! | Variable             | Description                                     |
//! |----------------------|-------------------------------------------------|
//! | `LOOPAUTH_TLS_DIR`   | Directory for managed certs (recommended)       |
//! | `LOOPAUTH_CERT_FILE` + `LOOPAUTH_KEY_FILE` | Paths to PEM files (manual) |
//!
//! # Optional environment variables
//!
//! | Variable                 | Description                        | Default                |
//! |--------------------------|------------------------------------|------------------------|
//! | `LOOPAUTH_CLIENT_SECRET` | Client secret                      | -                      |
//! | `LOOPAUTH_SCOPES`        | Comma-separated scopes             | `openid,email,profile` |
//! | `LOOPAUTH_PORT`          | Port hint for the loopback server  | OS-assigned            |
//!
//! # Provider quick-start
//!
//! **Slack (managed mode)**
//! ```sh
//! LOOPAUTH_CLIENT_ID=... \
//! LOOPAUTH_CLIENT_SECRET=... \
//! LOOPAUTH_AUTH_URL=https://slack.com/oauth/v2/authorize \
//! LOOPAUTH_TOKEN_URL=https://slack.com/api/oauth.v2.access \
//! LOOPAUTH_TLS_DIR=~/.config/my-cli/tls \
//! LOOPAUTH_SCOPES=openid,email,profile \
//! LOOPAUTH_PORT=8443 \
//! cargo run --example auth_https
//! ```
//! Add `https://127.0.0.1:8443/callback` to your Slack app's Redirect URLs.
//! Use `LOOPAUTH_PORT` to pin the port so it matches the registered redirect URL.

use loopauth::{CliTokenClient, RequestScope, TlsCertificate};

const DEFAULT_SCOPES: &str = "email,profile";
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

    // Print setup guide and exit if requested
    if std::env::args().any(|a| a == "--setup-guide") {
        println!("{}", TlsCertificate::SETUP_GUIDE);
        return;
    }

    let client_id = require_env("LOOPAUTH_CLIENT_ID");
    let auth_url = url::Url::parse(&require_env("LOOPAUTH_AUTH_URL"))
        .expect("LOOPAUTH_AUTH_URL must be a valid URL");
    let token_url = url::Url::parse(&require_env("LOOPAUTH_TOKEN_URL"))
        .expect("LOOPAUTH_TOKEN_URL must be a valid URL");

    let client_secret = std::env::var("LOOPAUTH_CLIENT_SECRET").ok();
    let scopes = parse_scopes(
        &std::env::var("LOOPAUTH_SCOPES").unwrap_or_else(|_| DEFAULT_SCOPES.to_string()),
    );
    let port_hint = std::env::var("LOOPAUTH_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    // Load TLS certificate: managed mode (LOOPAUTH_TLS_DIR) or manual mode (CERT_FILE + KEY_FILE)
    let certificate = load_certificate();

    // Enter OIDC mode explicitly (adds the openid scope and enables id_token processing).
    // We skip JWKS signature verification here for simplicity; production code should
    // use .jwks_validator() or .with_open_id_configuration_jwks_validator() instead.
    let mut builder = CliTokenClient::builder()
        .client_id(client_id)
        .auth_url(auth_url)
        .token_url(token_url)
        .with_openid_scope()
        .without_jwks_validation()
        .use_https_with(certificate)
        .add_scopes(scopes)
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

    tracing::info!("starting HTTPS authorization flow");

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

fn load_certificate() -> TlsCertificate {
    // Prefer managed mode (LOOPAUTH_TLS_DIR) over manual mode (CERT_FILE + KEY_FILE)
    if let Ok(tls_dir) = std::env::var("LOOPAUTH_TLS_DIR") {
        tracing::info!("using managed TLS certificates in {tls_dir}");
        return TlsCertificate::ensure_localhost(&tls_dir).unwrap_or_else(|e| {
            tracing::error!("TLS certificate setup failed: {e}");
            if matches!(e, loopauth::TlsCertificateError::MkcertNotFound) {
                println!("\n{}", TlsCertificate::SETUP_GUIDE_MANAGED);
            }
            std::process::exit(FAILURE_EXIT_CODE);
        });
    }

    if let (Ok(cert_file), Ok(key_file)) = (
        std::env::var("LOOPAUTH_CERT_FILE"),
        std::env::var("LOOPAUTH_KEY_FILE"),
    ) {
        tracing::info!("loading TLS certificate from {cert_file} + {key_file}");
        return TlsCertificate::from_pem_files(&cert_file, &key_file).unwrap_or_else(|e| {
            tracing::error!("failed to load TLS certificate: {e}");
            tracing::info!("run with --setup-guide for certificate setup instructions");
            std::process::exit(FAILURE_EXIT_CODE);
        });
    }

    tracing::error!("set LOOPAUTH_TLS_DIR (recommended) or LOOPAUTH_CERT_FILE + LOOPAUTH_KEY_FILE");
    std::process::exit(FAILURE_EXIT_CODE);
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
