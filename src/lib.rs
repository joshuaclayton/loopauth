//! `loopauth` acquires OAuth 2.0 provider tokens for CLI applications via the
//! Authorization Code + PKCE flow ([RFC 6749], [RFC 7636]). It is **provider token
//! acquisition only**, rather than app authentication or session management.
//!
//! [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
//! [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
//!
//! Given a `client_id`, `auth_url`, and `token_url`, [`CliTokenClient`] opens the
//! user's browser to the authorization URL, spins up a short-lived loopback
//! server to receive the redirect callback, exchanges the authorization code for
//! tokens, and returns a [`TokenSet`] to the caller.
//!
//! The callback server runs over plain HTTP by default. For providers that
//! require HTTPS redirect URIs (e.g. Slack), call
//! [`.use_https_with()`](CliTokenClientBuilder::use_https_with) with a
//! [`TlsCertificate`] to serve over TLS instead. See the
//! [HTTPS callbacks](#https-callbacks) section below.
//!
//! Token storage and downstream identity consumption are intentionally out of
//! scope; use the [`TokenStore`] trait to provide your own persistence.
//!
//! # Two-Layer Pattern
//!
//! `loopauth` returns provider tokens only. Your backend handles app identity:
//!
//! 1. Call [`CliTokenClient::run_authorization_flow`] → provider returns a [`TokenSet`]
//! 2. Send [`TokenSet::id_token_raw`] to your backend → validate and issue your own session token
//!
//! # Quick start
//!
//! With explicit URLs:
//!
//! ```no_run
//! use loopauth::{CliTokenClient, RequestScope};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = CliTokenClient::builder()
//!     .client_id("my-client-id")
//!     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
//!     .token_url(url::Url::parse("https://provider.example.com/token")?)
//!     .with_openid_scope()
//!     .add_scopes([RequestScope::Email])
//!     .without_jwks_validation() // or .jwks_validator(Box::new(my_validator))
//!     .build();
//!
//! // let tokens = client.run_authorization_flow().await?;
//! # Ok(())
//! # }
//! ```
//!
//! With OIDC auto-discovery (provider URLs are fetched automatically):
//!
//! ```no_run
//! use loopauth::{CliTokenClientBuilder, RequestScope, oidc::OpenIdConfiguration};
//! use url::Url;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let open_id_configuration = OpenIdConfiguration::fetch(
//!     Url::parse("https://provider.example.com")?,
//! ).await?;
//!
//! let client = CliTokenClientBuilder::from_open_id_configuration(&open_id_configuration)
//!     .client_id("my-client-id")
//!     .with_open_id_configuration_jwks_validator(&open_id_configuration)
//!     .add_scopes([RequestScope::Email])
//!     .build();
//!
//! // let tokens = client.run_authorization_flow().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # HTTPS callbacks
//!
//! Some providers require `https://` redirect URIs, even for localhost.
//! [`TlsCertificate::ensure_localhost`] handles certificate generation via
//! [`mkcert`](https://github.com/FiloSottile/mkcert) automatically:
//!
//! ```no_run
//! use loopauth::{CliTokenClient, TlsCertificate};
//! use std::path::PathBuf;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // First run: generates certs via mkcert. Later runs: loads existing.
//! let tls_dir = PathBuf::from("/home/user/.config/my-cli/tls");
//! let cert = TlsCertificate::ensure_localhost(&tls_dir)?;
//!
//! let client = CliTokenClient::builder()
//!     .client_id("my-client-id")
//!     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
//!     .token_url(url::Url::parse("https://provider.example.com/token")?)
//!     .use_https_with(cert)
//!     .build();
//!
//! // let tokens = client.run_authorization_flow().await?;
//! # Ok(())
//! # }
//! ```
//!
//! End users need `mkcert` installed and its CA trusted (`mkcert -install`,
//! one-time). See [`TlsCertificate::SETUP_GUIDE_MANAGED`] for end-user
//! instructions tailored to this workflow, or [`TlsCertificate::SETUP_GUIDE`]
//! for the full manual guide.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod builder;
mod error;
mod jwks;
pub mod oidc;
mod pages;
mod pkce;
mod scope;
mod server;
mod store;
mod tls;
mod token;
mod token_response;

#[cfg(any(test, doctest, feature = "testing"))]
#[doc(hidden)]
pub mod test_support;

pub use builder::{
    CliTokenClient, CliTokenClientBuilder, ExtraAuthParams, HasAuthUrl, HasClientId, HasTokenUrl,
    JwksDisabled, JwksEnabled, NoAuthUrl, NoClientId, NoOidc, NoTokenUrl, OidcPending,
};
pub use error::{AuthError, CallbackError, IdTokenError, RefreshError, TokenStoreError};
pub use jwks::{JwksValidationError, JwksValidator, RemoteJwksValidator};
pub use pages::{ErrorPageContext, ErrorPageRenderer, PageContext, SuccessPageRenderer};
pub use scope::{OAuth2Scope, RequestScope};
pub use store::TokenStore;
pub use tls::{TlsCertificate, TlsCertificateError};
pub use token::{
    AccessToken, RefreshOutcome, RefreshToken, TokenSet, Unvalidated, Validated, ValidationState,
};
pub use token_response::TokenResponseFields;
