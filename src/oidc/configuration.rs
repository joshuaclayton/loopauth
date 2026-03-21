use super::OpenIdConfigurationError;
use serde::Deserialize;
use url::Url;

/// A parsed OIDC discovery document (`.well-known/openid-configuration`).
///
/// All four required fields are typed as [`Url`] - invalid URLs in the
/// discovery document are rejected at construction time via
/// [`OpenIdConfiguration::fetch`].
#[derive(Deserialize)]
pub struct OpenIdConfiguration {
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
}

impl OpenIdConfiguration {
    /// The issuer identifier for the OIDC provider.
    #[must_use]
    pub const fn issuer(&self) -> &Url {
        &self.issuer
    }

    /// The authorization endpoint URL.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// The token endpoint URL.
    #[must_use]
    pub const fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// The JWKS URI for fetching public signing keys.
    #[must_use]
    pub const fn jwks_uri(&self) -> &Url {
        &self.jwks_uri
    }

    /// Construct an `OpenIdConfiguration` directly for use in tests.
    ///
    /// This constructor is only available in `#[cfg(test)]` builds.
    #[cfg(test)]
    #[must_use]
    pub const fn new_for_test(
        issuer: Url,
        authorization_endpoint: Url,
        token_endpoint: Url,
        jwks_uri: Url,
    ) -> Self {
        Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
        }
    }

    /// Fetches and parses the OIDC discovery document at
    /// `{issuer_url}/.well-known/openid-configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`OpenIdConfigurationError`] when:
    /// - The discovery URL cannot be constructed (malformed issuer URL)
    /// - A network error occurs while fetching the document
    /// - The response body is not valid JSON
    /// - Any of the four required fields (`issuer`, `authorization_endpoint`,
    ///   `token_endpoint`, `jwks_uri`) is missing or not a valid URL
    /// - The returned `issuer` field does not match `issuer_url`
    pub async fn fetch(issuer_url: Url) -> Result<Self, OpenIdConfigurationError> {
        let discovery_url_str = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.as_str().trim_end_matches('/')
        );
        let discovery_url = Url::parse(&discovery_url_str).map_err(|err| {
            OpenIdConfigurationError::new(format!("invalid discovery URL: {err}"))
        })?;

        tracing::debug!("fetching OIDC discovery from {discovery_url}");

        let doc = reqwest::get(discovery_url.as_str())
            .await
            .map_err(|err| OpenIdConfigurationError::new(format!("network error: {err}")))?
            .json::<Self>()
            .await
            .map_err(|err| OpenIdConfigurationError::new(format!("JSON parse error: {err}")))?;

        if doc.issuer != issuer_url {
            return Err(OpenIdConfigurationError::new(format!(
                "issuer mismatch (expected {issuer_url}, got {})",
                doc.issuer
            )));
        }

        Ok(doc)
    }
}
