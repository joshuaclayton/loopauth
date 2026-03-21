/// An error returned when fetching an [`crate::oidc::OpenIdConfiguration`] fails.
///
/// Wraps a human-readable reason string covering network failures, JSON parse
/// failures, missing required fields, and issuer mismatches.
#[derive(Debug, thiserror::Error)]
#[error("OpenID configuration fetch failed: {message}")]
pub struct OpenIdConfigurationError {
    message: String,
}

impl OpenIdConfigurationError {
    /// Create a new `OpenIdConfigurationError` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The failure reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
