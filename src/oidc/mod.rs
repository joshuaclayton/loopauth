//! `OpenID` Connect support: discovery document fetching and ID token claims.
//!
//! The central entry point is [`OpenIdConfiguration`], which fetches and parses
//! the provider's `.well-known/openid-configuration` discovery document. The
//! resulting struct exposes the `authorization_endpoint`, `token_endpoint`, and
//! `jwks_uri` needed to drive the authorization flow and validate ID tokens.
//!
//! [`Claims`] represents the standard set of OIDC claims decoded from an ID
//! token after a successful token exchange. Individual claim values are
//! represented as typed newtypes — [`Email`], [`Audience`], [`Issuer`],
//! [`PictureUrl`], and [`SubjectIdentifier`] — which enforce their invariants
//! at construction time.

mod claims;
mod configuration;
mod error;
mod token;

pub use claims::{Audience, Claims, Email, Issuer, PictureUrl, SubjectIdentifier};
pub use configuration::OpenIdConfiguration;
pub use error::OpenIdConfigurationError;
pub use token::Token;
