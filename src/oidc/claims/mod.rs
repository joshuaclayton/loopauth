mod audience;
mod email;
mod issuer;
mod picture_url;
mod serde;
mod subject_identifier;

pub use audience::Audience;
pub use email::Email;
pub use issuer::Issuer;
pub use picture_url::PictureUrl;
use std::time::SystemTime;
pub use subject_identifier::SubjectIdentifier;

/// Standard OIDC claims decoded from an ID token.
///
/// JWT signature validation is optional but strongly encouraged. Configure a
/// [`crate::jwks::JwksValidator`] via the builder to enable cryptographic validation of the ID token.
///
/// # Examples
///
/// Accessing claims:
///
/// ```
/// use loopauth::oidc::Claims;
/// use std::time::UNIX_EPOCH;
/// use url::Url;
///
/// let json = serde_json::json!({
///     "sub": "user123",
///     "email": "user@example.com",
///     "email_verified": true,
///     "name": "Test User",
///     "picture": "https://example.com/avatar.jpg",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: Claims = serde_json::from_value(json).unwrap();
///
/// assert_eq!(claims.sub().as_str(), "user123");
/// assert_eq!(claims.email().unwrap().as_str(), "user@example.com");
/// assert!(claims.email().unwrap().is_verified());
/// assert_eq!(claims.name(), Some("Test User"));
/// assert_eq!(claims.picture().unwrap().as_url().as_str(), "https://example.com/avatar.jpg");
/// assert_eq!(claims.iss().as_url(), &Url::parse("https://accounts.example.com").unwrap());
/// assert_eq!(claims.aud().len(), 1);
/// assert!(claims.iat() > UNIX_EPOCH);
/// assert!(claims.exp() > UNIX_EPOCH);
/// ```
///
/// Serde roundtrip preserves all fields including `email_verified` and `picture`:
///
/// ```
/// use loopauth::oidc::Claims;
///
/// let original = serde_json::json!({
///     "sub": "user123",
///     "email": "user@example.com",
///     "email_verified": true,
///     "name": "Test User",
///     "picture": "https://example.com/avatar.jpg",
///     "iss": "https://accounts.example.com",
///     "aud": ["client-id"],
///     "iat": 1_000_000_000_u64,
///     "exp": 9_999_999_999_u64
/// });
/// let claims: Claims = serde_json::from_value(original).unwrap();
/// let serialized = serde_json::to_string(&claims).unwrap();
/// let roundtripped: Claims = serde_json::from_str(&serialized).unwrap();
///
/// assert_eq!(roundtripped.email().unwrap().as_str(), "user@example.com");
/// assert!(roundtripped.email().unwrap().is_verified());
/// assert_eq!(roundtripped.picture().unwrap().as_url().as_str(), "https://example.com/avatar.jpg");
/// ```
#[derive(Debug, Clone)]
pub struct Claims {
    sub: SubjectIdentifier,
    email: Option<Email>,
    name: Option<String>,
    picture: Option<PictureUrl>,
    iss: Issuer,
    aud: Vec<Audience>,
    iat: SystemTime,
    exp: SystemTime,
}

impl Claims {
    #[expect(
        clippy::too_many_arguments,
        reason = "all OIDC claims are required parameters for construction"
    )]
    pub(crate) fn new(
        sub: String,
        email: Option<String>,
        email_verified: Option<bool>,
        name: Option<String>,
        picture: Option<String>,
        iss: url::Url,
        aud: Vec<Audience>,
        iat: SystemTime,
        exp: SystemTime,
    ) -> Self {
        Self {
            sub: SubjectIdentifier::new(sub),
            email: email.map(|e| Email::from_parts(e, email_verified)),
            name,
            picture: picture.and_then(|s| PictureUrl::parse(&s)),
            iss: Issuer::new(iss),
            aud,
            iat,
            exp,
        }
    }

    /// Returns the subject identifier.
    #[must_use]
    pub const fn sub(&self) -> &SubjectIdentifier {
        &self.sub
    }

    /// Returns the email address, if present.
    #[must_use]
    pub const fn email(&self) -> Option<&Email> {
        self.email.as_ref()
    }

    /// Returns the display name, if present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the picture URL, if present.
    #[must_use]
    pub const fn picture(&self) -> Option<&PictureUrl> {
        self.picture.as_ref()
    }

    /// Returns the issuer identifier.
    #[must_use]
    pub const fn iss(&self) -> &Issuer {
        &self.iss
    }

    /// Returns the audience values.
    #[must_use]
    pub fn aud(&self) -> &[Audience] {
        &self.aud
    }

    /// Returns `true` if `client_id` appears in the `aud` claim.
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
    /// assert!(claims.aud_contains("my-client-id"));
    /// assert!(!claims.aud_contains("other-client"));
    /// ```
    #[must_use]
    pub fn aud_contains(&self, client_id: &str) -> bool {
        self.aud.iter().any(|a| a.as_str() == client_id)
    }

    /// Returns the time at which the ID token was issued.
    #[must_use]
    pub const fn iat(&self) -> SystemTime {
        self.iat
    }

    /// Returns the expiration time of the ID token.
    #[must_use]
    pub const fn exp(&self) -> SystemTime {
        self.exp
    }

    /// Returns `true` if the ID token has expired (`exp` is in the past).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.exp
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        clippy::expect_used,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::Claims;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use url::Url;

    fn placeholder_iss() -> Url {
        Url::parse("https://accounts.example.com").unwrap()
    }

    struct ClaimsBuilder {
        sub: String,
        email: Option<String>,
        email_verified: Option<bool>,
        name: Option<String>,
        picture: Option<String>,
        iss: Url,
        iat: SystemTime,
        exp: SystemTime,
    }

    impl ClaimsBuilder {
        fn for_sub(sub: impl Into<String>) -> Self {
            Self {
                sub: sub.into(),
                email: None,
                email_verified: None,
                name: None,
                picture: None,
                iss: placeholder_iss(),
                iat: UNIX_EPOCH,
                exp: UNIX_EPOCH,
            }
        }

        fn email(mut self, addr: impl Into<String>) -> Self {
            self.email = Some(addr.into());
            self
        }

        fn name(mut self, name: impl Into<String>) -> Self {
            self.name = Some(name.into());
            self
        }

        fn iss(mut self, iss: Url) -> Self {
            self.iss = iss;
            self
        }

        fn iat(mut self, iat: SystemTime) -> Self {
            self.iat = iat;
            self
        }

        fn exp(mut self, exp: SystemTime) -> Self {
            self.exp = exp;
            self
        }

        fn build(self) -> Claims {
            Claims::new(
                self.sub,
                self.email,
                self.email_verified,
                self.name,
                self.picture,
                self.iss,
                vec![],
                self.iat,
                self.exp,
            )
        }
    }

    #[test]
    fn oidc_claims_sub_returns_subject() {
        let claims = ClaimsBuilder::for_sub("user123").build();
        assert_eq!(claims.sub().as_str(), "user123");
    }

    #[test]
    fn oidc_claims_sub_returns_subject_newtype() {
        let claims = ClaimsBuilder::for_sub("sub-999").build();
        assert_eq!(claims.sub().as_str(), "sub-999");
    }

    #[test]
    fn oidc_claims_email_absent_returns_none() {
        let claims = ClaimsBuilder::for_sub("sub").build();
        assert!(claims.email().is_none());
    }

    #[test]
    fn oidc_claims_email_returns_email_newtype() {
        let claims = ClaimsBuilder::for_sub("sub")
            .email("test@example.com")
            .build();
        assert!(claims.email().is_some());
        assert_eq!(claims.email().unwrap().as_str(), "test@example.com");
    }

    #[test]
    fn oidc_claims_name_returns_name() {
        let claims = ClaimsBuilder::for_sub("sub").name("Test User").build();
        assert_eq!(claims.name(), Some("Test User"));
    }

    #[test]
    fn oidc_claims_iss_iat_exp_getters_return_correct_values() {
        let iss = Url::parse("https://accounts.example.com").unwrap();
        let iat = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let exp = UNIX_EPOCH + Duration::from_secs(9_999_999_999);
        let claims = ClaimsBuilder::for_sub("sub-xyz")
            .iss(iss.clone())
            .iat(iat)
            .exp(exp)
            .build();
        assert_eq!(claims.iss().as_url(), &iss);
        assert_eq!(claims.iat(), iat);
        assert_eq!(claims.exp(), exp);
    }

    #[test]
    fn oidc_claims_aud_contains_returns_true_for_matching_client_id() {
        let json = serde_json::json!({
            "sub": "user1",
            "iss": "https://accounts.example.com",
            "aud": ["my-client-id", "other-client"],
            "iat": 1_000_000_000_u64,
            "exp": 9_999_999_999_u64
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert!(
            claims.aud_contains("my-client-id"),
            "expected true for matching client_id"
        );
        assert!(
            claims.aud_contains("other-client"),
            "expected true for second audience"
        );
        assert!(
            !claims.aud_contains("unknown"),
            "expected false for non-matching client_id"
        );
    }

    #[test]
    fn oidc_claims_aud_normalizes_single_string_to_vec() {
        let json = serde_json::json!({
            "sub": "user1",
            "iss": "https://issuer.example.com",
            "aud": "single-client-id",
            "iat": 1_000_000_000_u64,
            "exp": 9_999_999_999_u64
        });
        let claims: Claims = serde_json::from_value(json).expect("deserialize");
        assert_eq!(claims.aud().len(), 1);
        assert_eq!(claims.aud()[0].as_str(), "single-client-id");
    }

    #[test]
    fn oidc_claims_serde_roundtrip_preserves_email_verified_and_picture() {
        let json = serde_json::json!({
            "sub": "user123",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
            "iss": "https://accounts.example.com",
            "aud": ["client-id"],
            "iat": 1_000_000_000_u64,
            "exp": 9_999_999_999_u64
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        let serialized = serde_json::to_string(&claims).unwrap();
        let roundtripped: Claims = serde_json::from_str(&serialized).unwrap();

        assert_eq!(roundtripped.email().unwrap().as_str(), "user@example.com");
        assert!(roundtripped.email().unwrap().is_verified());
        assert_eq!(
            roundtripped.picture().unwrap().as_url().as_str(),
            "https://example.com/avatar.jpg"
        );
        assert_eq!(roundtripped.name(), Some("Test User"));
        assert_eq!(
            roundtripped.iss().as_url(),
            &Url::parse("https://accounts.example.com").unwrap()
        );
    }
}
