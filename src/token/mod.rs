mod access_token;
mod refresh_token;
mod validation_state;

use crate::oidc;
use crate::pages::OAuth2Scope;
pub use access_token::AccessToken;
pub use refresh_token::RefreshToken;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
pub use validation_state::{Unvalidated, Validated, ValidationState};

#[expect(
    clippy::ref_option,
    reason = "serde requires &Option<T> for custom serializers"
)]
fn serialize_optional_system_time<S>(
    time: &Option<SystemTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match time {
        Some(t) => {
            let secs = t
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            serializer.serialize_some(&secs)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_system_time<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<u64>::deserialize(deserializer)?;
    Ok(opt.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

/// The set of tokens returned by a successful OAuth 2.0 authorization or refresh flow.
///
/// Obtain a `TokenSet` by calling [`crate::CliTokenClient::run_authorization_flow`] or
/// [`crate::CliTokenClient::refresh`]. Persist it with [`crate::TokenStore`].
///
/// Serializes `expires_at` as a Unix timestamp (`u64`) or `null` when the provider did not
/// return `expires_in`.
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
///   "scopes": ["openid", "email"]
/// }"#;
/// let tokens: TokenSet = serde_json::from_str(json).unwrap();
///
/// assert_eq!(tokens.access_token().as_str(), "tok123");
/// assert_eq!(tokens.refresh_token().unwrap().as_str(), "ref456");
/// assert_eq!(tokens.token_type(), "Bearer");
/// assert_eq!(tokens.scopes().len(), 2);
/// assert!(!tokens.is_expired());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TokenSet<S: ValidationState = Validated> {
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    #[serde(
        default,
        serialize_with = "serialize_optional_system_time",
        deserialize_with = "deserialize_optional_system_time"
    )]
    expires_at: Option<SystemTime>,
    token_type: String,
    oidc: Option<oidc::Token>,
    #[serde(default)]
    scopes: Vec<OAuth2Scope>,
    #[serde(skip)]
    _state: std::marker::PhantomData<S>,
}

impl<S: ValidationState> TokenSet<S> {
    /// Returns the access token.
    #[must_use]
    pub const fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the refresh token, if present.
    #[must_use]
    pub const fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Returns the token type (e.g., "Bearer").
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns the time at which the access token expires, if the provider returned one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<std::time::SystemTime> {
        self.expires_at
    }

    /// Returns the raw ID token JWT string, if present.
    #[must_use]
    pub fn id_token_raw(&self) -> Option<&str> {
        self.oidc.as_ref().map(oidc::Token::raw)
    }

    /// Returns the OIDC token regardless of validation state. Used internally for claim validation.
    #[must_use]
    pub(crate) const fn oidc_token(&self) -> Option<&oidc::Token> {
        self.oidc.as_ref()
    }

    /// Returns the scopes granted with this token set.
    #[must_use]
    pub fn scopes(&self) -> &[OAuth2Scope] {
        &self.scopes
    }

    /// Returns `true` if the token has expired.
    ///
    /// Returns `false` when the provider did not return an expiry time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|t| SystemTime::now() >= t)
    }

    /// Returns `true` if the token expires within the given threshold duration,
    /// or if the token has already expired.
    ///
    /// Returns `false` when the provider did not return an expiry time.
    #[must_use]
    pub fn expires_within(&self, threshold: Duration) -> bool {
        self.expires_at.is_some_and(|t| {
            t.duration_since(SystemTime::now())
                .map_or(true, |remaining| remaining <= threshold)
        })
    }
}

impl TokenSet<Unvalidated> {
    pub(crate) fn new(
        access_token: String,
        refresh_token: Option<String>,
        expires_at: Option<SystemTime>,
        token_type: String,
        oidc: Option<oidc::Token>,
        scopes: Vec<OAuth2Scope>,
    ) -> Self {
        Self {
            access_token: AccessToken::new(access_token),
            refresh_token: refresh_token.map(RefreshToken::new),
            expires_at,
            token_type,
            oidc,
            scopes,
            _state: std::marker::PhantomData,
        }
    }

    pub(crate) fn into_validated(self) -> TokenSet<Validated> {
        TokenSet {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at: self.expires_at,
            token_type: self.token_type,
            oidc: self.oidc,
            scopes: self.scopes,
            _state: std::marker::PhantomData,
        }
    }
}

impl TokenSet<Validated> {
    /// Returns the OIDC token, if present. Only available on validated token sets.
    #[must_use]
    pub const fn oidc(&self) -> Option<&oidc::Token> {
        self.oidc.as_ref()
    }
}

/// Outcome of [`crate::CliTokenClient::refresh_if_expiring`].
///
/// # Example
///
/// ```no_run
/// # use loopauth::{CliTokenClient, RefreshOutcome};
/// # use std::time::Duration;
/// # async fn run(auth: CliTokenClient, mut tokens: loopauth::TokenSet) -> Result<(), loopauth::RefreshError> {
/// match auth.refresh_if_expiring(&tokens, Duration::from_secs(300)).await? {
///     RefreshOutcome::Refreshed(new_tokens) => {
///         tokens = *new_tokens;
///     }
///     RefreshOutcome::NotNeeded => {}
/// }
/// # Ok(())
/// # }
/// ```
#[must_use]
#[derive(Debug, Clone)]
#[expect(
    clippy::exhaustive_enums,
    reason = "refresh outcomes are a closed set; callers should match exhaustively"
)]
pub enum RefreshOutcome {
    /// Tokens were refreshed - new [`TokenSet`] is returned.
    Refreshed(Box<TokenSet>),
    /// Token is not expiring within the threshold - no refresh was needed.
    NotNeeded,
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        clippy::expect_used,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::{AccessToken, RefreshToken, TokenSet, Validated};
    use crate::oidc;
    use crate::pages::OAuth2Scope;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn make_token_set_expiring_at(expires_at: SystemTime) -> TokenSet<Validated> {
        TokenSet::new(
            "access_token_value".to_string(),
            Some("refresh_token_value".to_string()),
            Some(expires_at),
            "Bearer".to_string(),
            None,
            Vec::new(),
        )
        .into_validated()
    }

    #[test]
    fn token_set_expired_at_unix_epoch_is_expired() {
        let token = make_token_set_expiring_at(UNIX_EPOCH);
        assert!(token.is_expired());
    }

    #[test]
    fn token_set_future_expiry_is_not_expired() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        assert!(!token.is_expired());
    }

    #[test]
    fn token_set_expiring_soon_is_within_threshold() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(30));
        assert!(token.expires_within(Duration::from_secs(60)));
    }

    #[test]
    fn token_set_far_future_not_within_threshold() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        assert!(!token.expires_within(Duration::from_secs(60)));
    }

    #[test]
    fn token_set_already_expired_is_within_any_threshold() {
        let token = make_token_set_expiring_at(UNIX_EPOCH);
        assert!(token.expires_within(Duration::from_secs(60)));
    }

    #[test]
    fn token_set_serde_roundtrip_access_token() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        let json = serde_json::to_string(&token).expect("serialize");
        let decoded: TokenSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.access_token().as_str(), "access_token_value");
    }

    #[test]
    fn token_set_expires_at_serializes_as_u64() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        let json = serde_json::to_string(&token).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(
            value["expires_at"].is_number(),
            "expires_at should be a number"
        );
        assert!(
            value["expires_at"].as_u64().is_some(),
            "expires_at should be a u64"
        );
    }

    #[test]
    fn oidc_token_raw_returns_original_string() {
        let claims = oidc::Claims::new(
            "user123".to_string(),
            None,
            None,
            None,
            None,
            url::Url::parse("https://accounts.example.com").unwrap(),
            vec![],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        let oidc = oidc::Token::new("raw.jwt.string".to_string(), claims, None, None);
        assert_eq!(oidc.raw(), "raw.jwt.string");
    }

    #[test]
    fn access_token_getter_returns_access_token_newtype() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        let at: &AccessToken = token.access_token();
        assert_eq!(at.as_str(), "access_token_value");
    }

    #[test]
    fn refresh_token_getter_returns_refresh_token_newtype() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        let rt: Option<&RefreshToken> = token.refresh_token();
        assert!(rt.is_some());
        assert_eq!(rt.unwrap().as_str(), "refresh_token_value");
    }

    #[test]
    fn refresh_token_absent_returns_none() {
        let token = TokenSet::new(
            "access".to_string(),
            None,
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "Bearer".to_string(),
            None,
            Vec::new(),
        )
        .into_validated();
        assert!(token.refresh_token().is_none());
    }

    #[test]
    fn id_token_raw_absent_returns_none() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        assert!(token.id_token_raw().is_none());
    }

    #[test]
    fn id_token_raw_present_returns_jwt_string() {
        let claims = oidc::Claims::new(
            "sub".to_string(),
            None,
            None,
            None,
            None,
            url::Url::parse("https://accounts.example.com").unwrap(),
            vec![],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        let oidc = oidc::Token::new("header.payload.sig".to_string(), claims, None, None);
        let token = TokenSet::new(
            "access".to_string(),
            None,
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "Bearer".to_string(),
            Some(oidc),
            Vec::new(),
        )
        .into_validated();
        assert_eq!(token.id_token_raw(), Some("header.payload.sig"));
    }

    #[test]
    fn expires_at_is_publicly_callable() {
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let token = make_token_set_expiring_at(expiry);
        // expires_at() must be pub - compile-time check
        let _ = token.expires_at();
    }

    #[test]
    fn scopes_returns_empty_slice_when_empty() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        assert_eq!(token.scopes(), &[] as &[OAuth2Scope]);
    }

    #[test]
    fn scopes_returns_scopes_when_populated() {
        let token = TokenSet::new(
            "access".to_string(),
            None,
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "Bearer".to_string(),
            None,
            vec![OAuth2Scope::OpenId, OAuth2Scope::Email],
        )
        .into_validated();
        assert_eq!(token.scopes().len(), 2);
        assert_eq!(token.scopes()[0], OAuth2Scope::OpenId);
    }

    #[test]
    fn scopes_field_deserializes_with_default_when_absent() {
        // RFC 6749 §5.1 scope fallback: when scopes field absent from JSON,
        // it deserializes as empty (serde(default)) - documents getter behavior
        let json = r#"{"access_token":"tok","refresh_token":null,"expires_at":9999999999,"token_type":"Bearer","oidc":null}"#;
        let token: TokenSet = serde_json::from_str(json).expect("deserialize");
        assert_eq!(token.scopes(), &[] as &[OAuth2Scope]);
    }

    #[test]
    fn token_set_token_type_returns_bearer() {
        let token = make_token_set_expiring_at(SystemTime::now() + Duration::from_secs(3600));
        assert_eq!(token.token_type(), "Bearer");
    }
}
