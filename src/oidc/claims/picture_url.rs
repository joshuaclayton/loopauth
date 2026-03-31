use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A validated picture URL from the OIDC `picture` claim.
///
/// Obtained from [`crate::oidc::Claims::picture`]. The URL is parsed on construction;
/// invalid URLs are omitted and `picture()` returns `None`.
///
/// # Examples
///
/// Valid picture URL:
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "picture": "https://example.com/avatar.jpg",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let picture = claims.picture().unwrap();
/// assert_eq!(picture.as_url().as_str(), "https://example.com/avatar.jpg");
/// assert_eq!(format!("{picture}"), "https://example.com/avatar.jpg");
/// ```
///
/// Invalid or absent picture URL is silently dropped:
///
/// ```
/// use loopauth::oidc;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "picture": "not-a-url",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// assert!(claims.picture().is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PictureUrl(url::Url);

impl PictureUrl {
    pub(super) fn parse(s: &str) -> Option<Self> {
        s.parse().ok().map(Self)
    }

    /// Returns the picture URL.
    #[must_use]
    pub const fn as_url(&self) -> &url::Url {
        &self.0
    }
}

impl fmt::Display for PictureUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl Serialize for PictureUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for PictureUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<url::Url>()
            .map(PictureUrl)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::PictureUrl;

    #[test]
    fn oidc_claims_picture_returns_picture_url() {
        let p = PictureUrl::parse("https://example.com/avatar.jpg").unwrap();
        assert_eq!(p.as_url().as_str(), "https://example.com/avatar.jpg");
        assert_eq!(p.to_string(), "https://example.com/avatar.jpg");
    }

    #[test]
    fn oidc_claims_picture_invalid_url_returns_none() {
        assert!(PictureUrl::parse("not-a-url").is_none());
    }
}
