use serde::{Deserialize, Serialize};
use std::fmt;

/// The OIDC subject identifier (`sub` claim).
///
/// Obtained from [`crate::oidc::Claims::sub`]. Use [`SubjectIdentifier::as_str`] to
/// get the raw subject string for identity comparisons.
///
/// # Example
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let sub = claims.sub();
/// assert_eq!(sub.as_str(), "user123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubjectIdentifier(String);

impl SubjectIdentifier {
    /// Create a new [`SubjectIdentifier`] from an owned string.
    pub(crate) const fn new(s: String) -> Self {
        Self(s)
    }

    /// Return the subject as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SubjectIdentifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SubjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
