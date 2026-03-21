use serde::{Deserialize, Serialize};
use std::fmt;

/// An OAuth 2.0 refresh token.
///
/// Obtained from [`crate::TokenSet::refresh_token`]. Use [`RefreshToken::as_str`] to
/// get the raw token string for refresh grant requests.
///
/// # Example
///
/// ```
/// use loopauth::TokenSet;
///
/// let json = r#"{
///   "access_token": "tok123",
///   "refresh_token": "ref456",
///   "expires_at": 9999999999,
///   "token_type": "Bearer",
///   "oidc": null,
///   "scopes": []
/// }"#;
/// let tokens: TokenSet = serde_json::from_str(json).unwrap();
/// let rt = tokens.refresh_token().unwrap();
/// assert_eq!(rt.as_str(), "ref456");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshToken(String);

impl RefreshToken {
    /// Create a new [`RefreshToken`] from an owned string.
    pub(crate) const fn new(s: String) -> Self {
        Self(s)
    }

    /// Return the refresh token as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
