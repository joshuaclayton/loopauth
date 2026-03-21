use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use url::Url;

/// The OIDC issuer identifier (`iss` claim).
///
/// Obtained from [`crate::oidc::Claims::iss`]. Backed by [`url::Url`],
/// consistent with [`crate::oidc::OpenIdConfiguration::issuer`], which
/// enables direct comparison between the two.
///
/// # Example
///
/// ```
/// use loopauth::oidc;
/// use url::Url;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: oidc::Claims = serde_json::from_value(json).unwrap();
/// let iss = claims.iss();
/// assert_eq!(iss.as_url(), &Url::parse("https://accounts.example.com").unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Issuer(Url);

impl Issuer {
    /// Create a new [`Issuer`] from a [`Url`].
    pub(crate) const fn new(url: Url) -> Self {
        Self(url)
    }

    /// Return the issuer as a [`Url`].
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    /// Return the issuer as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<Url> for Issuer {
    fn as_ref(&self) -> &Url {
        self.as_url()
    }
}

impl AsRef<str> for Issuer {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl PartialEq<Url> for Issuer {
    fn eq(&self, other: &Url) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Issuer> for Url {
    fn eq(&self, other: &Issuer) -> bool {
        self == &other.0
    }
}

impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for Issuer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map(Self).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Issuer;
    use url::Url;

    fn example_url() -> Url {
        Url::parse("https://accounts.example.com").unwrap()
    }

    fn example_issuer() -> Issuer {
        Issuer::new(example_url())
    }

    #[test]
    fn issuer_as_url_returns_inner_url() {
        assert_eq!(example_issuer().as_url(), &example_url());
    }

    #[test]
    fn issuer_as_str_returns_url_string() {
        assert_eq!(example_issuer().as_str(), "https://accounts.example.com/");
    }

    #[test]
    fn issuer_display_matches_url_string() {
        assert_eq!(
            example_issuer().to_string(),
            "https://accounts.example.com/"
        );
    }

    #[test]
    fn issuer_partial_eq_url() {
        let issuer = example_issuer();
        let url = example_url();
        assert_eq!(issuer, url);
        assert_eq!(url, issuer);
    }

    #[test]
    fn issuer_serde_roundtrip() {
        let issuer = example_issuer();
        let json = serde_json::to_string(&issuer).unwrap();
        let roundtripped: Issuer = serde_json::from_str(&json).unwrap();
        assert_eq!(issuer, roundtripped);
    }

    #[test]
    fn issuer_deserialize_rejects_invalid_url() {
        let result = serde_json::from_value::<Issuer>(serde_json::json!("not-a-url"));
        assert!(result.is_err(), "expected error for invalid URL");
    }
}
