use std::fmt;

/// An OAuth 2.0 scope value.
///
/// Scopes are passed to [`crate::CliTokenClientBuilder::add_scopes`] to request
/// specific permissions from the authorization server.
///
/// # Example
///
/// ```
/// use loopauth::OAuth2Scope;
///
/// // Display produces the wire-format string
/// assert_eq!(OAuth2Scope::OpenId.to_string(), "openid");
/// assert_eq!(OAuth2Scope::Custom("read:data".to_string()).to_string(), "read:data");
///
/// // Serde round-trip
/// let json = serde_json::to_string(&OAuth2Scope::OpenId).unwrap();
/// assert_eq!(json, r#""openid""#);
/// let roundtrip: OAuth2Scope = serde_json::from_str(&json).unwrap();
/// assert_eq!(roundtrip, OAuth2Scope::OpenId);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[expect(
    clippy::exhaustive_enums,
    reason = "callers should be able to match all scopes exhaustively; new variants are a breaking change by design"
)]
pub enum OAuth2Scope {
    /// The `openid` scope, required for OIDC ID token issuance.
    OpenId,
    /// The `email` scope, requests the user's email address claim.
    Email,
    /// The `profile` scope, requests basic profile claims (name, picture, etc.).
    Profile,
    /// The `offline_access` scope, requests a refresh token.
    OfflineAccess,
    /// A custom or provider-specific scope value.
    Custom(String),
}

impl fmt::Display for OAuth2Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenId => f.write_str("openid"),
            Self::Email => f.write_str("email"),
            Self::Profile => f.write_str("profile"),
            Self::OfflineAccess => f.write_str("offline_access"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}

impl serde::Serialize for OAuth2Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl std::str::FromStr for OAuth2Scope {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl From<&str> for OAuth2Scope {
    fn from(s: &str) -> Self {
        match s {
            "openid" => Self::OpenId,
            "email" => Self::Email,
            "profile" => Self::Profile,
            "offline_access" => Self::OfflineAccess,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl<'de> serde::Deserialize<'de> for OAuth2Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s.as_str()))
    }
}

/// An OAuth 2.0 scope value for use with [`crate::CliTokenClientBuilder::add_scopes`].
///
/// Intentionally excludes the `openid` scope — use
/// [`crate::CliTokenClientBuilder::with_openid_scope`] to enable OIDC mode. This
/// separation ensures that opting into OIDC (and its associated JWKS decision) is
/// always an explicit, type-checked step rather than a silent side effect of scope
/// accumulation.
///
/// # Example
///
/// ```
/// use loopauth::{OAuth2Scope, RequestScope};
///
/// assert_eq!(OAuth2Scope::from(RequestScope::Email).to_string(), "email");
/// assert_eq!(OAuth2Scope::from(RequestScope::OfflineAccess).to_string(), "offline_access");
/// assert_eq!(
///     OAuth2Scope::from(RequestScope::Custom("read:data".to_string())).to_string(),
///     "read:data"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[expect(
    clippy::exhaustive_enums,
    reason = "callers should be able to match all request scopes exhaustively; new variants are a breaking change by design"
)]
pub enum RequestScope {
    /// The `email` scope, requests the user's email address claim.
    Email,
    /// The `profile` scope, requests basic profile claims (name, picture, etc.).
    Profile,
    /// The `offline_access` scope, requests a refresh token.
    OfflineAccess,
    /// A custom or provider-specific scope value.
    Custom(String),
}

impl From<RequestScope> for OAuth2Scope {
    fn from(s: RequestScope) -> Self {
        match s {
            RequestScope::Email => Self::Email,
            RequestScope::Profile => Self::Profile,
            RequestScope::OfflineAccess => Self::OfflineAccess,
            RequestScope::Custom(s) => Self::Custom(s),
        }
    }
}

impl From<&str> for RequestScope {
    fn from(s: &str) -> Self {
        match s {
            "email" => Self::Email,
            "profile" => Self::Profile,
            "offline_access" => Self::OfflineAccess,
            other => Self::Custom(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::{OAuth2Scope, RequestScope};

    #[test]
    fn oauth2_scope_serde_openid_roundtrips() {
        let serialized = serde_json::to_string(&OAuth2Scope::OpenId).unwrap();
        assert_eq!(serialized, "\"openid\"");
        let deserialized: OAuth2Scope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Scope::OpenId);
    }

    #[test]
    fn oauth2_scope_serde_email_roundtrips() {
        let serialized = serde_json::to_string(&OAuth2Scope::Email).unwrap();
        assert_eq!(serialized, "\"email\"");
        let deserialized: OAuth2Scope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Scope::Email);
    }

    #[test]
    fn oauth2_scope_serde_profile_roundtrips() {
        let serialized = serde_json::to_string(&OAuth2Scope::Profile).unwrap();
        assert_eq!(serialized, "\"profile\"");
        let deserialized: OAuth2Scope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Scope::Profile);
    }

    #[test]
    fn oauth2_scope_serde_offline_access_roundtrips() {
        let serialized = serde_json::to_string(&OAuth2Scope::OfflineAccess).unwrap();
        assert_eq!(serialized, "\"offline_access\"");
        let deserialized: OAuth2Scope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Scope::OfflineAccess);
    }

    #[test]
    fn oauth2_scope_serde_custom_roundtrips() {
        let scope = OAuth2Scope::Custom("read:user".to_string());
        let serialized = serde_json::to_string(&scope).unwrap();
        assert_eq!(serialized, "\"read:user\"");
        let deserialized: OAuth2Scope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Scope::Custom("read:user".to_string()));
    }

    #[test]
    fn scope_open_id_displays_as_openid() {
        assert_eq!(OAuth2Scope::OpenId.to_string(), "openid");
    }

    #[test]
    fn scope_email_displays_as_email() {
        assert_eq!(OAuth2Scope::Email.to_string(), "email");
    }

    #[test]
    fn scope_profile_displays_as_profile() {
        assert_eq!(OAuth2Scope::Profile.to_string(), "profile");
    }

    #[test]
    fn scope_offline_access_displays_as_offline_access() {
        assert_eq!(OAuth2Scope::OfflineAccess.to_string(), "offline_access");
    }

    #[test]
    fn scope_custom_displays_as_inner_string() {
        assert_eq!(
            OAuth2Scope::Custom("custom:read".to_string()).to_string(),
            "custom:read"
        );
    }

    #[test]
    fn request_scope_email_converts_to_oauth2_scope_email() {
        assert_eq!(OAuth2Scope::from(RequestScope::Email), OAuth2Scope::Email);
    }

    #[test]
    fn request_scope_custom_converts_to_oauth2_scope_custom() {
        assert_eq!(
            OAuth2Scope::from(RequestScope::Custom("read:data".to_string())),
            OAuth2Scope::Custom("read:data".to_string())
        );
    }

    #[test]
    fn request_scope_from_str_email() {
        assert_eq!(RequestScope::from("email"), RequestScope::Email);
    }

    #[test]
    fn request_scope_from_str_unknown_becomes_custom() {
        assert_eq!(
            RequestScope::from("openid"),
            RequestScope::Custom("openid".to_string())
        );
    }
}
