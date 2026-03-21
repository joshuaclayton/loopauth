use super::{Audience, Claims};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A decoded OIDC ID token, present on [`crate::TokenSet`] when `"openid"` was in the
/// requested scopes and the provider returned an `id_token`.
///
/// Bundles the raw JWT string with its decoded [`Claims`] to prevent the
/// invalid state of having claims without a raw token or vice versa.
///
/// # Example
///
/// ```
/// use loopauth::TokenSet;
///
/// // A TokenSet with an embedded OIDC token (decoded from the id_token JWT)
/// let json = r#"{
///   "access_token": "tok",
///   "refresh_token": null,
///   "expires_at": 9999999999,
///   "token_type": "Bearer",
///   "oidc": {
///     "raw": "header.payload.sig",
///     "claims": {
///       "sub": "user123",
///       "email": "user@example.com",
///       "email_verified": true,
///       "name": "Test User",
///       "picture": null,
///       "iss": "https://accounts.example.com",
///       "aud": ["client-id"],
///       "iat": 1000000000,
///       "exp": 9999999999
///     }
///   },
///   "scopes": ["openid"]
/// }"#;
/// let tokens: TokenSet = serde_json::from_str(json).unwrap();
/// let oidc = tokens.oidc().unwrap();
/// assert_eq!(oidc.raw(), "header.payload.sig");
/// assert_eq!(oidc.claims().sub().as_str(), "user123");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    raw: String,
    claims: Claims,
}

impl Token {
    pub(crate) const fn new(raw: String, claims: Claims) -> Self {
        Self { raw, claims }
    }

    /// Decode a [`Token`] from a raw JWT string.
    ///
    /// Returns `None` if the JWT is malformed, the payload cannot be
    /// base64-decoded, the claims cannot be deserialized, or the `iss`
    /// claim is absent or not a valid URL.
    #[must_use]
    pub(crate) fn from_raw_jwt(raw: &str) -> Option<Self> {
        use base64::Engine as _;

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum StringOrVec {
            Single(String),
            Multiple(Vec<String>),
        }

        #[derive(serde::Deserialize)]
        struct RawClaims {
            sub: String,
            email: Option<String>,
            email_verified: Option<bool>,
            name: Option<String>,
            picture: Option<String>,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default)]
            aud: Option<StringOrVec>,
            #[serde(default)]
            iat: Option<u64>,
            #[serde(default)]
            exp: Option<u64>,
        }

        let payload = raw.split('.').nth(1)?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let c: RawClaims = serde_json::from_slice(&decoded).ok()?;

        let iss = c.iss.as_deref().and_then(|s| url::Url::parse(s).ok())?;
        let aud = match c.aud {
            None => vec![],
            Some(StringOrVec::Single(s)) => vec![Audience::new(s)],
            Some(StringOrVec::Multiple(v)) => v.into_iter().map(Audience::new).collect(),
        };
        let iat = std::time::UNIX_EPOCH + Duration::from_secs(c.iat.unwrap_or(0));
        let exp = std::time::UNIX_EPOCH + Duration::from_secs(c.exp.unwrap_or(0));

        let claims = Claims::new(
            c.sub,
            c.email,
            c.email_verified,
            c.name,
            c.picture,
            iss,
            aud,
            iat,
            exp,
        );
        Some(Self::new(raw.to_string(), claims))
    }

    /// Returns the raw JWT string.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the decoded OIDC claims.
    #[must_use]
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }
}
