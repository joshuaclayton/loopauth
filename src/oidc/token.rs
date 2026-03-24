use super::{Audience, Claims};
use serde::Serialize;
use std::time::{Duration, SystemTime};

/// Controls whether the `iss` claim is validated during ID token verification.
///
/// Passing [`IssuerValidation::Skip`] is a deliberate opt-out of issuer validation.
/// Passing [`IssuerValidation::MustMatch`] requires the `iss` claim to equal the
/// provided URL exactly.
#[derive(Clone, Copy)]
pub enum IssuerValidation<'a> {
    /// Do not validate the `iss` claim.
    Skip,
    /// Require the `iss` claim to equal this URL.
    MustMatch(&'a url::Url),
}

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
/// // A TokenSet with an embedded OIDC token (decoded from the id_token JWT).
/// // The `claims` field is informational; only `raw` is used during deserialization.
/// let raw_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
///     eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJUZXN0IFVzZXIiLCJpc3MiOiJodHRwczovL2FjY291bnRzLmV4YW1wbGUuY29tIiwiYXVkIjpbImNsaWVudC1pZCJdLCJpYXQiOjEwMDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0.\
///     fakesig";
/// let json = format!(r#"{{
///   "access_token": "tok",
///   "refresh_token": null,
///   "expires_at": 9999999999,
///   "token_type": "Bearer",
///   "oidc": {{
///     "raw": "{raw_jwt}",
///     "claims": {{
///       "sub": "user123",
///       "email": "user@example.com",
///       "email_verified": true,
///       "name": "Test User",
///       "picture": null,
///       "iss": "https://accounts.example.com",
///       "aud": ["client-id"],
///       "iat": 1000000000,
///       "exp": 9999999999
///     }}
///   }},
///   "scopes": ["openid"]
/// }}"#);
/// let tokens: TokenSet = serde_json::from_str(&json).unwrap();
/// let oidc = tokens.oidc().unwrap();
/// assert_eq!(oidc.claims().sub().as_str(), "user123");
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct Token {
    raw: String,
    claims: Claims,
    /// The `nbf` (not before) time, if present in the JWT. Not serialized — re-derived from `raw` on deserialization so it is always consistent with the raw JWT.
    #[serde(skip)]
    nbf: Option<SystemTime>,
}

impl<'de> serde::Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Helper {
            raw: String,
        }
        let h = Helper::deserialize(deserializer)?;
        Self::from_raw_jwt(&h.raw).map_err(serde::de::Error::custom)
    }
}

impl Token {
    pub(crate) const fn new(raw: String, claims: Claims, nbf: Option<SystemTime>) -> Self {
        Self { raw, claims, nbf }
    }

    /// Decode a [`Token`] from a raw JWT string.
    ///
    /// # Errors
    ///
    /// Returns [`crate::IdTokenError::MalformedIdToken`] if:
    /// - The JWT has fewer than two `.`-separated segments
    /// - The payload cannot be base64-decoded
    /// - The payload cannot be deserialized as JSON
    /// - The `sub` claim is missing
    /// - The `iss` claim is absent or not a valid URL
    pub(crate) fn from_raw_jwt(raw: &str) -> Result<Self, crate::error::IdTokenError> {
        use super::string_or_vec::StringOrVec;
        use base64::Engine as _;

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
            #[serde(default)]
            nbf: Option<u64>,
        }

        let malformed = |msg: String| crate::error::IdTokenError::MalformedIdToken(msg);

        let payload = raw
            .split('.')
            .nth(1)
            .ok_or_else(|| malformed("missing payload segment".to_owned()))?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| malformed(format!("base64 decode failed: {e}")))?;
        let c: RawClaims = serde_json::from_slice(&decoded)
            .map_err(|e| malformed(format!("JSON parse failed: {e}")))?;

        let iss = c
            .iss
            .as_deref()
            .ok_or_else(|| malformed("missing iss claim".to_owned()))
            .and_then(|s| {
                url::Url::parse(s).map_err(|e| malformed(format!("invalid iss URL: {e}")))
            })?;

        let aud = match c.aud {
            None => vec![],
            Some(StringOrVec::Single(s)) => vec![Audience::new(s)],
            Some(StringOrVec::Multiple(v)) => v.into_iter().map(Audience::new).collect(),
        };
        let iat_secs = c
            .iat
            .ok_or_else(|| malformed("missing iat claim".to_owned()))?;
        let exp_secs = c
            .exp
            .ok_or_else(|| malformed("missing exp claim".to_owned()))?;
        let iat = std::time::UNIX_EPOCH + Duration::from_secs(iat_secs);
        let exp = std::time::UNIX_EPOCH + Duration::from_secs(exp_secs);
        let nbf = c
            .nbf
            .map(|secs| std::time::UNIX_EPOCH + Duration::from_secs(secs));

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
        Ok(Self::new(raw.to_string(), claims, nbf))
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

    /// Returns the `nbf` (not before) time, if present in the JWT.
    #[must_use]
    pub const fn nbf(&self) -> Option<SystemTime> {
        self.nbf
    }

    /// Validate standard JWT/OIDC claims per RFC 7519 §7.2 and OIDC Core §2.
    ///
    /// Checks, in order:
    /// - `exp` (§4.1.4) — token must not be expired
    /// - `nbf` (§4.1.5) — token must not be used before its not-before time
    /// - `aud` — must be present and must contain `client_id`
    /// - `iss` — must match `issuer` when one is configured
    ///
    /// # Errors
    ///
    /// Returns the first failing [`crate::error::IdTokenError`] variant encountered.
    pub(crate) fn validate_standard_claims(
        &self,
        client_id: &str,
        issuer: IssuerValidation<'_>,
    ) -> Result<(), crate::error::IdTokenError> {
        use crate::error::IdTokenError;

        // §4.1.4 — exp
        if self.claims.is_expired() {
            return Err(IdTokenError::Expired);
        }

        // §4.1.5 — nbf
        if let Some(nbf) = self.nbf
            && SystemTime::now() < nbf
        {
            return Err(IdTokenError::NotYetValid);
        }

        // OIDC Core §2: aud is required for ID tokens and MUST contain client_id.
        if self.claims.aud().is_empty() {
            return Err(IdTokenError::MalformedIdToken(
                "missing aud claim".to_owned(),
            ));
        }
        if !self.claims.aud_contains(client_id) {
            return Err(IdTokenError::InvalidAudience);
        }

        // §4.1.1 — iss must match configured issuer (when one is configured)
        if let IssuerValidation::MustMatch(expected_issuer) = issuer
            && self.claims.iss().as_url() != expected_issuer
        {
            return Err(IdTokenError::InvalidIssuer {
                expected: expected_issuer.to_string(),
                got: self.claims.iss().as_url().to_string(),
            });
        }

        Ok(())
    }
}
