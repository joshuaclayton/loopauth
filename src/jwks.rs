use async_trait::async_trait;
use url::Url;

use crate::oidc::{CLOCK_SKEW_LEEWAY_SECONDS, OpenIdConfiguration, OpenIdConfigurationError};

const JWKS_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const JWKS_REQUEST_TIMEOUT_SECONDS: u64 = 30;

/// An error returned by a [`JwksValidator`] when the `id_token` fails validation.
///
/// Callers implementing [`JwksValidator`] construct this via [`JwksValidationError::new`]
/// and return it as the `Err` variant of their `validate` implementation.
#[derive(Debug, thiserror::Error)]
#[error("JWKS validation failed: {message}")]
pub struct JwksValidationError {
    message: String,
}

impl JwksValidationError {
    /// Create a new `JwksValidationError` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The validation failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Validates the raw `id_token` string returned from the token endpoint.
///
/// Implement this trait to perform JWKS-based (or any other) signature
/// verification on the `id_token`. Register the implementation via
/// [`crate::CliTokenClientBuilder::jwks_validator`].
///
/// **Scope**: this validator is responsible for cryptographic signature
/// verification only. After `validate` returns `Ok(())`, the library
/// separately validates the standard JWT claims (`exp`, `nbf`, `iat`, `aud`,
/// `iss`, and `nonce`). Do not re-validate those claims here.
///
/// # Example
///
/// ```no_run
/// use async_trait::async_trait;
/// use loopauth::{JwksValidationError, JwksValidator};
///
/// struct AlwaysAccept;
///
/// #[async_trait]
/// impl JwksValidator for AlwaysAccept {
///     async fn validate(&self, _raw_token: &str) -> Result<(), JwksValidationError> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait JwksValidator: Send + Sync {
    /// Validate `raw_token`.
    ///
    /// Return `Ok(())` if the token is valid, or `Err(JwksValidationError)` to
    /// reject it and short-circuit the authorization flow.
    async fn validate(&self, raw_token: &str) -> Result<(), JwksValidationError>;
}

/// Boxed [`JwksValidator`] for storage in the client.
pub type JwksValidatorStorage = Box<dyn JwksValidator + Send + Sync>;

#[derive(serde::Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

enum JwkKey {
    RsaWithKid {
        kid: String,
        n: String,
        e: String,
    },
    Rsa {
        n: String,
        e: String,
    },
    EcWithKid {
        kid: String,
        x: String,
        y: String,
        crv: String,
    },
    Ec {
        x: String,
        y: String,
        crv: String,
    },
    Unsupported {
        kty: String,
        crv: Option<String>,
    },
}

impl<'de> serde::Deserialize<'de> for JwkKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let kty = value
            .get("kty")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let kid = value
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        match kty.as_str() {
            "RSA" => {
                let n = value
                    .get("n")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                let e = value
                    .get("e")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);

                match (n, e, kid) {
                    (Some(n), Some(e), Some(kid)) => Ok(Self::RsaWithKid { kid, n, e }),
                    (Some(n), Some(e), None) => Ok(Self::Rsa { n, e }),
                    _ => Ok(Self::Unsupported {
                        kty: "RSA".to_owned(),
                        crv: None,
                    }),
                }
            }
            "EC" => {
                let crv = value
                    .get("crv")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                let is_supported_crv = matches!(crv.as_deref(), Some("P-256" | "P-384"));
                if is_supported_crv {
                    let x = value
                        .get("x")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let y = value
                        .get("y")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);

                    match (x, y, crv, kid) {
                        (Some(x), Some(y), Some(crv), Some(kid)) => {
                            Ok(Self::EcWithKid { kid, x, y, crv })
                        }
                        (Some(x), Some(y), Some(crv), None) => Ok(Self::Ec { x, y, crv }),
                        _ => Ok(Self::Unsupported {
                            kty: "EC".to_owned(),
                            crv: None,
                        }),
                    }
                } else {
                    Ok(Self::Unsupported {
                        kty: "EC".to_owned(),
                        crv,
                    })
                }
            }
            _ => Ok(Self::Unsupported { kty, crv: None }),
        }
    }
}

/// Describes a JWK key type for error reporting.
fn jwk_key_description(key: &JwkKey) -> String {
    match key {
        JwkKey::RsaWithKid { .. } => "RSA(with-kid)".to_owned(),
        JwkKey::Rsa { .. } => "RSA".to_owned(),
        JwkKey::EcWithKid { crv, .. } => format!("EC({crv},with-kid)"),
        JwkKey::Ec { crv, .. } => format!("EC({crv})"),
        JwkKey::Unsupported { kty, crv } => crv
            .as_ref()
            .map_or_else(|| kty.clone(), |c| format!("{kty}({c})")),
    }
}

/// Validates JWTs against a remote JWKS endpoint.
///
/// Fetches the JWKS on every call. Supports RSA (RS256/384/512, PS256/384/512)
/// and EC (ES256/384) algorithms. Algorithm is read from the JWT header `alg` field.
///
/// **Availability**: if the JWKS endpoint is unreachable, every token exchange
/// fails with a [`crate::IdTokenError::JwksValidationFailed`] error. Ensure the
/// endpoint is reachable before using this validator in production.
///
/// Construct via [`RemoteJwksValidator::new`].
pub struct RemoteJwksValidator {
    jwks_url: Url,
    client_id: String,
    http_client: reqwest::Client,
}

impl RemoteJwksValidator {
    /// Create a new validator.
    ///
    /// `jwks_url` is the JWKS endpoint.
    /// `client_id` is used for audience validation.
    #[must_use]
    pub fn new(jwks_url: Url, client_id: impl Into<String>) -> Self {
        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(JWKS_CONNECT_TIMEOUT_SECONDS))
            .timeout(std::time::Duration::from_secs(JWKS_REQUEST_TIMEOUT_SECONDS))
            .build()
            .unwrap_or_default();
        Self {
            jwks_url,
            client_id: client_id.into(),
            http_client,
        }
    }

    /// Create a validator from an OIDC configuration.
    ///
    /// Uses `open_id_configuration.jwks_uri()` as the JWKS endpoint. `client_id` is used
    /// for audience validation.
    #[must_use]
    pub fn from_open_id_configuration(
        open_id_configuration: &OpenIdConfiguration,
        client_id: impl Into<String>,
    ) -> Self {
        Self::new(open_id_configuration.jwks_uri().clone(), client_id)
    }

    /// Fetch the OIDC configuration from `issuer_url` and create a validator.
    ///
    /// # Errors
    ///
    /// Returns `OpenIdConfigurationError` if the fetch fails or the document
    /// is missing required fields.
    pub async fn from_issuer(
        issuer_url: Url,
        client_id: impl Into<String>,
    ) -> Result<Self, OpenIdConfigurationError> {
        let open_id_configuration = OpenIdConfiguration::fetch(issuer_url).await?;
        Ok(Self::from_open_id_configuration(
            &open_id_configuration,
            client_id,
        ))
    }
}

fn select_key_with_kid<'a>(keys: &'a [JwkKey], kid: &str) -> (Option<&'a JwkKey>, String) {
    let mut skipped = Vec::new();
    let mut found = None;
    for key in keys {
        match key {
            JwkKey::RsaWithKid { kid: k, .. } if k == kid => {
                found = Some(key);
                break;
            }
            JwkKey::EcWithKid { kid: k, .. } if k == kid => {
                found = Some(key);
                break;
            }
            JwkKey::RsaWithKid { .. }
            | JwkKey::Rsa { .. }
            | JwkKey::Ec { .. }
            | JwkKey::EcWithKid { .. }
            | JwkKey::Unsupported { .. } => {
                skipped.push(jwk_key_description(key));
            }
        }
    }
    let skip_str = if skipped.is_empty() {
        String::new()
    } else {
        format!("; {} keys skipped ({})", skipped.len(), skipped.join(", "))
    };
    (found, skip_str)
}

fn build_decoding_key_and_validation(
    key: &JwkKey,
    alg: jsonwebtoken::Algorithm,
    client_id: &str,
) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Validation), JwksValidationError> {
    use jsonwebtoken::Algorithm::{
        ES256, ES384, EdDSA, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512,
    };

    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.leeway = CLOCK_SKEW_LEEWAY_SECONDS;
    validation.set_audience(&[client_id]);

    match (alg, key) {
        (
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512,
            JwkKey::Rsa { n, e } | JwkKey::RsaWithKid { n, e, .. },
        ) => {
            let decoding_key =
                jsonwebtoken::DecodingKey::from_rsa_components(n, e).map_err(|err| {
                    JwksValidationError::new(format!("failed to build RSA decoding key: {err}"))
                })?;
            Ok((decoding_key, validation))
        }
        (ES256 | ES384, JwkKey::Ec { x, y, crv } | JwkKey::EcWithKid { x, y, crv, .. }) => {
            let expected_crv = match alg {
                ES256 => "P-256",
                ES384 => "P-384",
                // The outer match arm constrains `alg` to ES256|ES384,
                // so this branch is unreachable; kept as a defensive guard.
                other @ (HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | PS256 | PS384 | PS512
                | EdDSA) => {
                    return Err(JwksValidationError::new(format!(
                        "unexpected EC algorithm: {other:?}"
                    )));
                }
            };
            if crv.as_str() != expected_crv {
                return Err(JwksValidationError::new(format!(
                    "algorithm mismatch: JWT wants {alg:?} but key crv is {crv}"
                )));
            }
            let decoding_key =
                jsonwebtoken::DecodingKey::from_ec_components(x, y).map_err(|err| {
                    JwksValidationError::new(format!("failed to build EC decoding key: {err}"))
                })?;
            Ok((decoding_key, validation))
        }
        _ => Err(JwksValidationError::new(format!(
            "algorithm/key type mismatch for {alg:?}"
        ))),
    }
}

#[async_trait]
impl JwksValidator for RemoteJwksValidator {
    async fn validate(&self, raw_token: &str) -> Result<(), JwksValidationError> {
        use jsonwebtoken::Algorithm::{ES256, ES384, PS256, PS384, PS512, RS256, RS384, RS512};

        let header = jsonwebtoken::decode_header(raw_token).map_err(|err| {
            JwksValidationError::new(format!("failed to decode JWT header: {err}"))
        })?;

        let alg = header.alg;
        let supported = matches!(
            alg,
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | ES256 | ES384
        );
        if !supported {
            return Err(JwksValidationError::new(format!(
                "unsupported algorithm: {alg:?}"
            )));
        }

        tracing::debug!("fetching JWKS from {}", self.jwks_url);
        let jwks: JwksResponse = self
            .http_client
            .get(self.jwks_url.as_str())
            .send()
            .await
            .map_err(|err| JwksValidationError::new(format!("failed to fetch JWKS: {err}")))?
            .json::<JwksResponse>()
            .await
            .map_err(|err| {
                JwksValidationError::new(format!("failed to parse JWKS response: {err}"))
            })?;

        if let Some(kid) = header.kid {
            tracing::debug!("JWT has kid={kid}, looking for matching key");
            let (found, skip_str) = select_key_with_kid(&jwks.keys, &kid);
            let key = found.ok_or_else(|| {
                JwksValidationError::new(format!("no key found for kid={kid}{skip_str}"))
            })?;
            let (decoding_key, validation) =
                build_decoding_key_and_validation(key, alg, &self.client_id)?;
            jsonwebtoken::decode::<serde_json::Value>(raw_token, &decoding_key, &validation)
                .map(|_| ())
                .map_err(|err| JwksValidationError::new(format!("JWT validation failed: {err}")))
        } else {
            tracing::debug!("JWT has no kid, trying all no-kid keys");
            let no_kid_keys: Vec<&JwkKey> = jwks
                .keys
                .iter()
                .filter(|k| matches!(k, JwkKey::Rsa { .. } | JwkKey::Ec { .. }))
                .collect();

            let mut last_err = JwksValidationError::new(
                "token validation failed against all available keys: no keys available",
            );
            for key in &no_kid_keys {
                match build_decoding_key_and_validation(key, alg, &self.client_id) {
                    Err(err) => {
                        tracing::warn!("key skipped: {}", err.message());
                        last_err = JwksValidationError::new(format!(
                            "token validation failed against all available keys: {}",
                            err.message()
                        ));
                    }
                    Ok((decoding_key, validation)) => {
                        match jsonwebtoken::decode::<serde_json::Value>(
                            raw_token,
                            &decoding_key,
                            &validation,
                        ) {
                            Ok(_) => return Ok(()),
                            Err(err) => {
                                tracing::warn!("key rejected: {err}");
                                last_err = JwksValidationError::new(format!(
                                    "token validation failed against all available keys: {err}"
                                ));
                            }
                        }
                    }
                }
            }
            Err(last_err)
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::{JwksValidationError, RemoteJwksValidator};
    use crate::oidc::OpenIdConfiguration;
    use url::Url;

    fn make_open_id_configuration() -> OpenIdConfiguration {
        OpenIdConfiguration::new_for_test(
            Url::parse("https://accounts.example.com").unwrap(),
            Url::parse("https://accounts.example.com/authorize").unwrap(),
            Url::parse("https://accounts.example.com/token").unwrap(),
            Url::parse("https://accounts.example.com/.well-known/jwks.json").unwrap(),
        )
    }

    #[test]
    fn from_open_id_configuration_uses_jwks_uri() {
        let config = make_open_id_configuration();
        let validator = RemoteJwksValidator::from_open_id_configuration(&config, "my-client");
        assert_eq!(
            validator.jwks_url.as_str(),
            "https://accounts.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn from_open_id_configuration_sets_client_id() {
        let config = make_open_id_configuration();
        let validator = RemoteJwksValidator::from_open_id_configuration(&config, "my-client");
        assert_eq!(validator.client_id, "my-client");
    }

    #[test]
    fn jwks_validation_error_message_roundtrip() {
        let err = JwksValidationError::new("bad sig");
        assert_eq!(err.message(), "bad sig");
    }

    #[test]
    fn jwks_validation_error_display_includes_message() {
        let err = JwksValidationError::new("expired token");
        let display = err.to_string();
        assert!(
            display.contains("expired token"),
            "expected display to contain message text, got: {display}"
        );
    }

    #[test]
    fn jwks_validation_error_implements_std_error() {
        let err = JwksValidationError::new("some error");
        // Coerce to &dyn std::error::Error to confirm the trait is implemented
        let _: &dyn std::error::Error = &err;
    }
}
