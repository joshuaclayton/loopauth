use serde::{Deserialize, Serialize};
use std::fmt;

/// An OAuth 2.0 audience value.
///
/// Obtained from [`crate::oidc::Claims::aud`]. Use [`Audience::as_str`] to
/// get the raw audience string for validation against your client ID.
///
/// # Example
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "iss": "https://accounts.example.com",
///     "aud": ["my-client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let aud = &claims.aud()[0];
/// assert_eq!(aud.as_str(), "my-client-id");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Audience(String);

impl Audience {
    /// Create a new [`Audience`] from an owned string.
    pub(crate) const fn new(s: String) -> Self {
        Self(s)
    }

    /// Return the audience as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Audience {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
