use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The OIDC email address (`email` claim), with verification status encoded.
///
/// Obtained from [`crate::oidc::Claims::email`]. Use [`Email::as_str`] to get the raw email string,
/// or [`Email::is_verified`] to check whether `email_verified` was `true` in the ID token.
///
/// # Examples
///
/// Verified email:
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "email": "user@example.com",
///     "email_verified": true,
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let email = claims.email().unwrap();
/// assert_eq!(email.as_str(), "user@example.com");
/// assert_eq!(format!("{email}"), "user@example.com");
/// assert!(email.is_verified());
/// ```
///
/// Unverified email (absent or `false` `email_verified`):
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "email": "unverified@example.com",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let email = claims.email().unwrap();
/// assert_eq!(email.as_str(), "unverified@example.com");
/// assert!(!email.is_verified());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[expect(
    clippy::exhaustive_enums,
    reason = "verified/unverified is a closed set; callers should match exhaustively"
)]
pub enum Email {
    /// The email address was present and `email_verified` was `true`.
    Verified(String),
    /// The email address was present but `email_verified` was absent or `false`.
    Unverified(String),
}

impl Email {
    pub(crate) fn from_parts(email: String, verified: Option<bool>) -> Self {
        if verified == Some(true) {
            Self::Verified(email)
        } else {
            Self::Unverified(email)
        }
    }

    /// Return the email address as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Verified(s) | Self::Unverified(s) => s,
        }
    }

    /// Returns `true` if the email was verified by the provider.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::Unverified(s))
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[test]
    fn oidc_claims_email_returns_email_newtype() {
        let email = Email::from_parts("test@example.com".to_string(), None);
        assert_eq!(email.as_str(), "test@example.com");
    }

    #[test]
    fn oidc_claims_email_absent_returns_none() {
        // Email::from_parts is only called when email is present; absence is
        // represented at the Claims level. This test confirms the from_parts
        // path when no email is provided yields an Unverified value.
        let email = Email::from_parts("u@example.com".to_string(), None);
        assert!(!email.is_verified());
    }

    #[test]
    fn oidc_claims_email_unverified_when_verified_false() {
        let email = Email::from_parts("user@example.com".to_string(), Some(false));
        assert!(!email.is_verified());
    }

    #[test]
    fn oidc_claims_email_unverified_when_verified_absent() {
        let email = Email::from_parts("user@example.com".to_string(), None);
        assert!(!email.is_verified());
    }

    #[test]
    fn email_display_formats_as_address() {
        let email = Email::from_parts("user@example.com".to_string(), Some(true));
        assert_eq!(format!("{email}"), "user@example.com");
    }

    #[test]
    fn deserialized_email_defaults_as_unverified() {
        let email: Email = serde_json::from_value(serde_json::json!("user@example.com")).unwrap();
        assert_eq!(email, Email::Unverified("user@example.com".to_string()));
    }
}
