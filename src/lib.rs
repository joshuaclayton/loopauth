//! `loopauth` acquires OAuth 2.0 provider tokens for CLI applications via the
//! Authorization Code + PKCE flow ([RFC 6749], [RFC 7636]). It is **provider token
//! acquisition only**, rather than app authentication or session management.
//!
//! [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
//! [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
//!
//! Given a `client_id`, `auth_url`, and `token_url`, [`CliTokenClient`] opens the
//! user's browser to the authorization URL, spins up a short-lived loopback HTTP
//! server to receive the redirect callback, exchanges the authorization code for
//! tokens, and returns a [`TokenSet`] to the caller.
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
//! use loopauth::{CliTokenClient, OAuth2Scope};
//!
//! # async fn run() -> Result<(), loopauth::ConfigError> {
//! let client = CliTokenClient::builder()
//!     .client_id("my-client-id")
//!     .auth_url("https://provider.example.com/authorize")
//!     .token_url("https://provider.example.com/token")
//!     .scopes([OAuth2Scope::OpenId, OAuth2Scope::Email])
//!     .build()?;
//!
//! // let tokens = client.run_authorization_flow().await?;
//! # Ok(())
//! # }
//! ```
//!
//! With OIDC auto-discovery (provider URLs are fetched automatically):
//!
//! ```no_run
//! use loopauth::{CliTokenClientBuilder, OAuth2Scope, oidc::OpenIdConfiguration};
//! use url::Url;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let open_id_configuration = OpenIdConfiguration::fetch(
//!     Url::parse("https://provider.example.com")?,
//! ).await?;
//!
//! let client = CliTokenClientBuilder::from_open_id_configuration(&open_id_configuration)
//!     .client_id("my-client-id")
//!     .scopes([OAuth2Scope::OpenId, OAuth2Scope::Email])
//!     .build()?;
//!
//! // let tokens = client.run_authorization_flow().await?;
//! # Ok(())
//! # }
//! ```
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod builder;
mod error;
mod jwks;
pub mod oidc;
mod pages;
mod pkce;
mod server;
mod store;
mod token;

#[doc(hidden)]
pub mod test_support;

pub use builder::{CliTokenClient, CliTokenClientBuilder};
pub use error::{
    AuthError, CallbackError, ConfigError, IdTokenError, RefreshError, TokenStoreError,
};
pub use jwks::{JwksValidationError, JwksValidator, RemoteJwksValidator};
pub use pages::{
    ErrorPageContext, ErrorPageRenderer, OAuth2Scope, PageContext, SuccessPageRenderer,
};
pub use store::TokenStore;
pub use token::{
    AccessToken, RefreshOutcome, RefreshToken, TokenSet, Unvalidated, Validated, ValidationState,
};
