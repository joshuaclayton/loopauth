use serde::{Deserialize, Serialize};
use std::fmt;

/// An OAuth 2.0 access token.
///
/// Obtained from [`crate::TokenSet::access_token`]. Use [`AccessToken::as_str`] to
/// get the raw token string for HTTP headers or API calls.
///
/// # Example
///
/// ```
/// use loopauth::TokenSet;
///
/// let json = r#"{
///   "access_token": "tok123",
///   "refresh_token": null,
///   "expires_at": 9999999999,
///   "token_type": "Bearer",
///   "oidc": null,
///   "scopes": []
/// }"#;
/// let tokens: TokenSet = serde_json::from_str(json).unwrap();
/// let at = tokens.access_token();
/// assert_eq!(at.as_str(), "tok123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(String);

impl AccessToken {
    /// Create a new [`AccessToken`] from an owned string.
    pub(crate) const fn new(s: String) -> Self {
        Self(s)
    }

    /// Return the access token as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
