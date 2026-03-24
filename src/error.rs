use thiserror::Error;

/// Errors that can occur during [`crate::CliTokenClient::run_authorization_flow`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The loopback callback server failed to bind.
    #[error("failed to bind loopback server: {0}")]
    ServerBind(#[source] std::io::Error),
    /// The system browser could not be opened.
    #[error("failed to open browser: {0}")]
    Browser(String),
    /// A URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// The callback was not received within the configured timeout.
    #[error("authentication timed out")]
    Timeout,
    /// The user cancelled the flow (Ctrl+C).
    #[error("authentication cancelled")]
    Cancelled,
    /// The token endpoint returned a non-2xx response.
    #[error("token exchange failed (HTTP {status}): {body}")]
    TokenExchange {
        /// HTTP status code returned by the token endpoint.
        status: u16,
        /// Response body from the token endpoint.
        body: String,
    },
    /// A network-level request error occurred.
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// An internal server or channel error occurred.
    #[error("server error: {0}")]
    Server(String),
    /// A required query parameter was absent from the callback request.
    #[error("missing callback parameter: {0}")]
    MissingCallbackParam(String),
    /// An error occurred during callback validation (state mismatch or provider error).
    #[error(transparent)]
    Callback(#[from] CallbackError),
    /// An error occurred while validating the `id_token`.
    #[error(transparent)]
    IdToken(#[from] IdTokenError),
}

/// Errors that can occur during OAuth 2.0 callback validation.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum CallbackError {
    /// The `state` parameter in the callback did not match - possible CSRF attack.
    #[error("state parameter mismatch: possible CSRF attack")]
    StateMismatch,
    /// The authorization provider returned an error in the callback.
    #[error("provider error: {error}: {description}")]
    ProviderError {
        /// The OAuth 2.0 error code (e.g. `access_denied`).
        error: String,
        /// Human-readable description from the provider.
        description: String,
    },
}

/// Errors that can occur during [`crate::CliTokenClient::refresh`] or
/// [`crate::CliTokenClient::refresh_if_expiring`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// No refresh token is available to exchange.
    #[error("no refresh token available")]
    NoRefreshToken,
    /// The token endpoint returned a non-2xx response.
    #[error("token exchange failed (HTTP {status}): {body}")]
    TokenExchange {
        /// HTTP status code returned by the token endpoint.
        status: u16,
        /// Response body from the token endpoint.
        body: String,
    },
    /// A network-level request error occurred.
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// An error occurred while validating the `id_token`.
    #[error(transparent)]
    IdToken(#[from] IdTokenError),
}

/// Errors that can occur while validating an `id_token` after a successful token exchange.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdTokenError {
    /// The JWKS validator rejected the `id_token`.
    #[error("JWKS validation failed: {0}")]
    JwksValidationFailed(#[source] crate::JwksValidationError),
    /// The `openid` scope was requested but the provider did not return an `id_token`.
    #[error("openid scope was requested but no id_token was returned")]
    NoIdToken,
    /// The `id_token` could not be parsed (malformed JWT, missing required claims).
    #[error("malformed id_token: {0}")]
    MalformedIdToken(String),
    /// The `id_token` has expired (`exp` claim is in the past).
    #[error("id_token has expired")]
    Expired,
    /// The `id_token` is not yet valid (`nbf` claim is in the future).
    #[error("id_token is not yet valid")]
    NotYetValid,
    /// The `aud` claim does not include the configured `client_id`.
    #[error("id_token audience does not include client_id")]
    InvalidAudience,
    /// The `iss` claim does not match the configured issuer.
    #[error("id_token issuer mismatch: expected {expected}, got {got}")]
    InvalidIssuer {
        /// The issuer that was expected (from configuration).
        expected: String,
        /// The issuer found in the `id_token`.
        got: String,
    },
}

/// Errors that can occur in [`crate::TokenStore`] implementations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenStoreError {
    /// An I/O error occurred while reading or writing token storage.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Token data could not be serialized or deserialized.
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::{AuthError, CallbackError, RefreshError, TokenStoreError};

    #[test]
    fn auth_error_state_mismatch_message() {
        assert_eq!(
            AuthError::Callback(CallbackError::StateMismatch).to_string(),
            "state parameter mismatch: possible CSRF attack"
        );
    }

    #[test]
    fn auth_error_timeout_message() {
        assert_eq!(AuthError::Timeout.to_string(), "authentication timed out");
    }

    #[test]
    fn auth_error_cancelled_message() {
        assert_eq!(AuthError::Cancelled.to_string(), "authentication cancelled");
    }

    #[test]
    fn auth_error_token_exchange_contains_status() {
        let err = AuthError::TokenExchange {
            status: 401,
            body: "Unauthorized".to_string(),
        };
        assert!(err.to_string().contains("401"));
    }

    #[test]
    fn refresh_error_no_refresh_token_message() {
        assert_eq!(
            RefreshError::NoRefreshToken.to_string(),
            "no refresh token available"
        );
    }

    #[test]
    fn token_store_error_serialization_contains_message() {
        let err = TokenStoreError::Serialization("bad json".to_string());
        assert!(err.to_string().contains("bad json"));
    }
}
