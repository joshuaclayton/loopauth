//! Custom token response parsing for non-standard OAuth providers.
//!
//! Standard OAuth 2.0 token responses place `access_token` at the top level.
//! Some providers (e.g., Slack v2) nest tokens inside a sub-object. To support
//! these, define a custom [`serde::Deserialize`] type and implement
//! `Into<TokenResponseFields>`, then pass it to
//! [`CliTokenClientBuilder::token_response_type`](crate::CliTokenClientBuilder::token_response_type).
//!
//! By default, [`TokenResponseFields`] is deserialized directly from the
//! response body, which handles the standard flat OAuth 2.0 format.

/// The standard fields extracted from a token endpoint response.
///
/// Consumed internally by loopauth to build a [`crate::TokenSet`].
///
/// For the standard flat OAuth 2.0 response format, this struct is
/// deserialized directly. For non-standard providers, define a custom type
/// that implements `Into<TokenResponseFields>` and pass it to
/// [`CliTokenClientBuilder::token_response_type`](crate::CliTokenClientBuilder::token_response_type).
///
/// # Example: Custom provider response
///
/// ```
/// use loopauth::TokenResponseFields;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct SlackV2TokenResponse {
///     authed_user: SlackAuthedUser,
/// }
///
/// #[derive(Deserialize)]
/// struct SlackAuthedUser {
///     access_token: String,
///     refresh_token: Option<String>,
///     expires_in: Option<u64>,
/// }
///
/// impl From<SlackV2TokenResponse> for TokenResponseFields {
///     fn from(resp: SlackV2TokenResponse) -> Self {
///         TokenResponseFields::new(resp.authed_user.access_token)
///             .with_refresh_token(resp.authed_user.refresh_token)
///             .with_expires_in(resp.authed_user.expires_in)
///             .with_token_type(Some("Bearer".to_string()))
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TokenResponseFields {
    /// The access token issued by the authorization server.
    pub access_token: String,
    /// The refresh token, if the server issued one.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// The lifetime in seconds of the access token.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// The token type (e.g., `"Bearer"`).
    #[serde(default)]
    pub token_type: Option<String>,
    /// The ID token JWT, if `OpenID Connect` was requested.
    #[serde(default)]
    pub id_token: Option<String>,
    /// The scope granted by the server (space-separated).
    #[serde(default)]
    pub scope: Option<String>,
}

impl TokenResponseFields {
    /// Create a new `TokenResponseFields` with the required access token.
    ///
    /// All optional fields default to `None`. Use the `with_*` methods to set them.
    #[must_use]
    pub const fn new(access_token: String) -> Self {
        Self {
            access_token,
            refresh_token: None,
            expires_in: None,
            token_type: None,
            id_token: None,
            scope: None,
        }
    }

    /// Set the refresh token.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: Option<String>) -> Self {
        self.refresh_token = refresh_token;
        self
    }

    /// Set the token lifetime in seconds.
    #[must_use]
    pub const fn with_expires_in(mut self, expires_in: Option<u64>) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Set the token type.
    #[must_use]
    pub fn with_token_type(mut self, token_type: Option<String>) -> Self {
        self.token_type = token_type;
        self
    }

    /// Set the ID token JWT.
    #[must_use]
    pub fn with_id_token(mut self, id_token: Option<String>) -> Self {
        self.id_token = id_token;
        self
    }

    /// Set the granted scope.
    #[must_use]
    pub fn with_scope(mut self, scope: Option<String>) -> Self {
        self.scope = scope;
        self
    }
}

// ── Parser closure type ─────────────────────────────────────────────────────

pub type TokenParser = Box<dyn Fn(&str) -> Result<TokenResponseFields, String> + Send + Sync>;

pub fn default_token_parser() -> TokenParser {
    Box::new(|body: &str| serde_json::from_str(body).map_err(|e| e.to_string()))
}

pub fn custom_token_parser<R>() -> TokenParser
where
    R: serde::de::DeserializeOwned + Into<TokenResponseFields> + Send + 'static,
{
    Box::new(|body: &str| {
        let response: R = serde_json::from_str(body).map_err(|e| e.to_string())?;
        Ok(response.into())
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests use unwrap for brevity")]
    use super::*;

    #[test]
    fn default_parser_parses_standard_flat_response() {
        let json = r#"{
            "access_token": "tok_abc",
            "refresh_token": "ref_xyz",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "read write"
        }"#;
        let parser = default_token_parser();
        let fields = parser(json).unwrap();
        assert_eq!(fields.access_token, "tok_abc", "access_token should match");
        assert_eq!(
            fields.refresh_token.as_deref(),
            Some("ref_xyz"),
            "refresh_token should match"
        );
        assert_eq!(fields.expires_in, Some(3600), "expires_in should match");
        assert_eq!(
            fields.token_type.as_deref(),
            Some("Bearer"),
            "token_type should match"
        );
        assert_eq!(
            fields.scope.as_deref(),
            Some("read write"),
            "scope should match"
        );
        assert!(fields.id_token.is_none(), "id_token should be None");
    }

    #[test]
    fn default_parser_handles_minimal_response() {
        let json = r#"{"access_token": "tok"}"#;
        let parser = default_token_parser();
        let fields = parser(json).unwrap();
        assert_eq!(fields.access_token, "tok", "access_token should match");
        assert!(
            fields.refresh_token.is_none(),
            "refresh_token should be None"
        );
        assert!(fields.expires_in.is_none(), "expires_in should be None");
    }

    #[test]
    fn default_parser_rejects_missing_access_token() {
        let json = r#"{"refresh_token": "ref"}"#;
        let parser = default_token_parser();
        assert!(parser(json).is_err(), "should fail without access_token");
    }

    // ── Custom nested response (Slack-style) ────────────────────────────

    #[derive(serde::Deserialize)]
    struct NestedTokenResponse {
        authed_user: NestedUser,
    }

    #[derive(serde::Deserialize)]
    struct NestedUser {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<u64>,
    }

    impl From<NestedTokenResponse> for TokenResponseFields {
        fn from(resp: NestedTokenResponse) -> Self {
            Self::new(resp.authed_user.access_token)
                .with_refresh_token(resp.authed_user.refresh_token)
                .with_expires_in(resp.authed_user.expires_in)
                .with_token_type(Some("Bearer".to_string()))
        }
    }

    #[test]
    fn custom_parser_parses_nested_response() {
        let json = r#"{
            "ok": true,
            "authed_user": {
                "access_token": "xoxp-slack-token",
                "refresh_token": "xoxe-refresh",
                "expires_in": 43200
            }
        }"#;
        let parser = custom_token_parser::<NestedTokenResponse>();
        let fields = parser(json).unwrap();
        assert_eq!(
            fields.access_token, "xoxp-slack-token",
            "should extract nested access_token"
        );
        assert_eq!(
            fields.refresh_token.as_deref(),
            Some("xoxe-refresh"),
            "should extract nested refresh_token"
        );
        assert_eq!(
            fields.expires_in,
            Some(43200),
            "should extract nested expires_in"
        );
        assert_eq!(
            fields.token_type.as_deref(),
            Some("Bearer"),
            "should use impl-provided token_type"
        );
    }

    #[test]
    fn custom_parser_rejects_flat_response() {
        let json = r#"{"access_token": "tok"}"#;
        let parser = custom_token_parser::<NestedTokenResponse>();
        assert!(
            parser(json).is_err(),
            "nested parser should reject flat response"
        );
    }
}
