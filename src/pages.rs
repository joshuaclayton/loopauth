use crate::oidc::Email;
use async_trait::async_trait;
use std::fmt;
use std::fmt::Write as _;

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

/// Context provided to [`SuccessPageRenderer`] implementations.
pub struct PageContext<'a> {
    oidc: Option<&'a crate::oidc::Claims>,
    scopes: &'a [OAuth2Scope],
    redirect_uri: &'a url::Url,
    client_id: &'a str,
    expires_at: Option<std::time::SystemTime>,
    has_refresh_token: bool,
}

impl<'a> PageContext<'a> {
    /// Create a new `PageContext`.
    pub(crate) const fn new(
        oidc: Option<&'a crate::oidc::Claims>,
        scopes: &'a [OAuth2Scope],
        redirect_uri: &'a url::Url,
        client_id: &'a str,
        expires_at: Option<std::time::SystemTime>,
        has_refresh_token: bool,
    ) -> Self {
        Self {
            oidc,
            scopes,
            redirect_uri,
            client_id,
            expires_at,
            has_refresh_token,
        }
    }

    /// OIDC claims decoded from the `id_token`, if present.
    #[must_use]
    pub const fn oidc(&self) -> Option<&crate::oidc::Claims> {
        self.oidc
    }

    /// Scopes that were requested.
    #[must_use]
    pub const fn scopes(&self) -> &[OAuth2Scope] {
        self.scopes
    }

    /// Redirect URI used in the authorization request.
    #[must_use]
    pub const fn redirect_uri(&self) -> &url::Url {
        self.redirect_uri
    }

    /// OAuth 2.0 client ID.
    #[must_use]
    pub const fn client_id(&self) -> &str {
        self.client_id
    }

    /// Time at which the access token expires, if the provider returned one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<std::time::SystemTime> {
        self.expires_at
    }

    /// Whether a refresh token was obtained.
    #[must_use]
    pub const fn has_refresh_token(&self) -> bool {
        self.has_refresh_token
    }
}

/// Context provided to [`ErrorPageRenderer`] implementations.
pub struct ErrorPageContext<'a> {
    error: &'a crate::error::AuthError,
    scopes: &'a [OAuth2Scope],
    redirect_uri: &'a url::Url,
    client_id: &'a str,
}

impl<'a> ErrorPageContext<'a> {
    /// Create a new `ErrorPageContext`.
    pub(crate) const fn new(
        error: &'a crate::error::AuthError,
        scopes: &'a [OAuth2Scope],
        redirect_uri: &'a url::Url,
        client_id: &'a str,
    ) -> Self {
        Self {
            error,
            scopes,
            redirect_uri,
            client_id,
        }
    }

    /// The authentication error that occurred.
    #[must_use]
    pub const fn error(&self) -> &crate::error::AuthError {
        self.error
    }

    /// Scopes that were requested.
    #[must_use]
    pub const fn scopes(&self) -> &[OAuth2Scope] {
        self.scopes
    }

    /// Redirect URI used in the authorization request.
    #[must_use]
    pub const fn redirect_uri(&self) -> &url::Url {
        self.redirect_uri
    }

    /// OAuth 2.0 client ID.
    #[must_use]
    pub const fn client_id(&self) -> &str {
        self.client_id
    }
}

/// Renders the success page HTML shown to the user after authentication.
///
/// Register with [`crate::CliTokenClientBuilder::success_renderer`]. Takes precedence
/// over a plain HTML string set via [`crate::CliTokenClientBuilder::success_html`].
///
/// # Example
///
/// ```no_run
/// use async_trait::async_trait;
/// use loopauth::{PageContext, SuccessPageRenderer};
///
/// struct MySuccessPage;
///
/// #[async_trait]
/// impl SuccessPageRenderer for MySuccessPage {
///     async fn render_success(&self, ctx: &PageContext<'_>) -> String {
///         let name = ctx.oidc().and_then(|c| c.name()).unwrap_or("there");
///         format!("<h1>Hi, {name}! You can close this tab.</h1>")
///     }
/// }
/// ```
#[async_trait]
pub trait SuccessPageRenderer: Send + Sync {
    /// Render the success page, returning the full HTML string.
    async fn render_success(&self, ctx: &PageContext<'_>) -> String;
}

/// Renders the error page HTML shown to the user when authentication fails.
///
/// Register with [`crate::CliTokenClientBuilder::error_renderer`]. Takes precedence
/// over a plain HTML string set via [`crate::CliTokenClientBuilder::error_html`].
///
/// # Example
///
/// ```no_run
/// use async_trait::async_trait;
/// use loopauth::{ErrorPageContext, ErrorPageRenderer};
///
/// struct MyErrorPage;
///
/// #[async_trait]
/// impl ErrorPageRenderer for MyErrorPage {
///     async fn render_error(&self, ctx: &ErrorPageContext<'_>) -> String {
///         format!("<h1>Authentication failed: {}</h1>", ctx.error())
///     }
/// }
/// ```
#[async_trait]
pub trait ErrorPageRenderer: Send + Sync {
    /// Render the error page, returning the full HTML string.
    async fn render_error(&self, ctx: &ErrorPageContext<'_>) -> String;
}

// Type aliases to avoid clippy::type_complexity

/// Boxed [`SuccessPageRenderer`] for storage in the client.
pub type SuccessRendererStorage = Box<dyn SuccessPageRenderer + Send + Sync>;

/// Boxed [`ErrorPageRenderer`] for storage in the client.
pub type ErrorRendererStorage = Box<dyn ErrorPageRenderer + Send + Sync>;

// Embedded HTML assets (compile-time)

/// The default success page HTML template. Contains a `{{CONTENT}}` placeholder.
pub const DEFAULT_SUCCESS_HTML: &str = include_str!("../assets/success.html");
/// The default error page HTML template. Contains a `{{CONTENT}}` placeholder.
pub const DEFAULT_ERROR_HTML: &str = include_str!("../assets/error.html");

/// Default success page renderer - uses the embedded `assets/success.html` template.
pub struct DefaultSuccessPageRenderer;

#[async_trait]
impl SuccessPageRenderer for DefaultSuccessPageRenderer {
    async fn render_success(&self, ctx: &PageContext<'_>) -> String {
        let mut content = String::new();

        if let Some(claims) = ctx.oidc() {
            let has_identity = claims.name().is_some() || claims.email().is_some();
            if has_identity {
                let name_html = claims
                    .name()
                    .map(|n| {
                        format!(
                            "<p class=\"text-base font-semibold leading-snug text-app-text-header\">{}</p>",
                            html_escape(n)
                        )
                    })
                    .unwrap_or_default();
                let email_html = claims
                    .email()
                    .map(|e| {
                        let cls = if claims.name().is_some() {
                            "text-base leading-snug"
                        } else {
                            "text-base font-semibold leading-snug"
                        };
                        format!("<p class=\"{}\">{}</p>", cls, html_escape(e.as_str()))
                    })
                    .unwrap_or_default();

                if let Some(picture) = claims.picture() {
                    let _ = write!(
                        content,
                        "<div class=\"flex items-center gap-3 mb-5\"><img src=\"{}\" alt=\"\" class=\"h-12 w-12 rounded-full shrink-0 ring-2 ring-white shadow-md\"><div>{}{}</div></div>",
                        html_escape(picture.as_url().as_str()),
                        name_html,
                        email_html
                    );
                } else {
                    let _ = write!(content, "<div class=\"mb-5\">{name_html}{email_html}</div>");
                }
            }
        }

        if !ctx.scopes().is_empty() {
            let scope_list = ctx
                .scopes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
            let _ = write!(
                content,
                "<p class=\"text-sm lg:text-base font-mono text-app-text-header\">{}</p>",
                html_escape(&scope_list)
            );
        }

        let _ = write!(
            content,
            "<details class=\"mt-4 pt-4 border-t border-app-border text-sm lg:text-base font-mono\"><summary class=\"cursor-pointer select-none\">token details</summary><dl class=\"mt-2 space-y-1\">"
        );
        if let Some(claims) = ctx.oidc() {
            let _ = write!(
                content,
                "<div class=\"flex gap-2\"><dt class=\"w-20 shrink-0\">sub</dt><dd class=\"break-all text-app-text-header\">{}</dd></div>",
                html_escape(claims.sub().as_str())
            );
            if let Some(verified) = claims.email().map(Email::is_verified) {
                let label = if verified { "yes" } else { "no" };
                let _ = write!(
                    content,
                    "<div class=\"flex gap-2\"><dt class=\"w-20 shrink-0\">verified</dt><dd class=\"text-app-text-header\">{label}</dd></div>"
                );
            }
        }
        let _ = write!(
            content,
            "<div class=\"flex gap-2\"><dt class=\"w-20 shrink-0\">expires</dt><dd class=\"text-app-text-header\">{}</dd></div>",
            html_escape(
                &ctx.expires_at()
                    .map_or_else(|| "unknown".to_string(), format_expiry)
            )
        );
        let refresh_label = if ctx.has_refresh_token() {
            "obtained"
        } else {
            "not requested"
        };
        let _ = write!(
            content,
            "<div class=\"flex gap-2\"><dt class=\"w-20 shrink-0\">refresh</dt><dd class=\"text-app-text-header\">{refresh_label}</dd></div>"
        );
        let _ = write!(content, "</dl></details>");

        DEFAULT_SUCCESS_HTML.replace("{{CONTENT}}", &content)
    }
}

/// Default error page renderer - uses the embedded `assets/error.html` template.
pub struct DefaultErrorPageRenderer;

#[async_trait]
impl ErrorPageRenderer for DefaultErrorPageRenderer {
    async fn render_error(&self, ctx: &ErrorPageContext<'_>) -> String {
        let mut content = String::new();

        match ctx.error() {
            crate::error::AuthError::Callback(crate::error::CallbackError::ProviderError {
                error,
                description,
            }) => {
                let _ = write!(
                    content,
                    "<p class=\"text-base text-red-700 dark:text-red-300\">{}</p><p class=\"mt-1 font-mono text-sm text-red-400 dark:text-red-100\">{}</p>",
                    html_escape(description),
                    html_escape(error)
                );
            }
            other => {
                let _ = write!(
                    content,
                    "<p class=\"text-base text-red-700 dark:text-red-300\">{}</p>",
                    html_escape(&other.to_string())
                );
            }
        }

        if !ctx.scopes().is_empty() {
            let scope_list = ctx
                .scopes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
            let _ = write!(
                content,
                "<p class=\"mt-3 text-sm lg:text-base font-mono text-app-text-header\">{}</p>",
                html_escape(&scope_list)
            );
        }

        DEFAULT_ERROR_HTML.replace("{{CONTENT}}", &content)
    }
}

fn format_expiry(expires_at: std::time::SystemTime) -> String {
    expires_at
        .duration_since(std::time::SystemTime::now())
        .map_or_else(
            |_| "expired".to_string(),
            |remaining| {
                let secs = remaining.as_secs();
                if secs < 60 {
                    format!("in {secs}s")
                } else if secs < 3600 {
                    format!("in {}m", secs / 60)
                } else {
                    let h = secs / 3600;
                    let m = (secs % 3600) / 60;
                    if m == 0 {
                        format!("in {h}h")
                    } else {
                        format!("in {h}h {m}m")
                    }
                }
            },
        )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic,
        reason = "tests do not need to meet production lint standards"
    )]
    use super::{
        DefaultErrorPageRenderer, DefaultSuccessPageRenderer, ErrorPageContext, ErrorPageRenderer,
        OAuth2Scope, PageContext, SuccessPageRenderer,
    };
    use crate::error::{AuthError, CallbackError};
    use crate::oidc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use url::Url;

    fn test_url() -> Url {
        Url::parse("http://127.0.0.1:8080/callback").unwrap()
    }

    fn future_expiry() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

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
    fn page_context_accessors_return_expected_values() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId, OAuth2Scope::Email];
        let ctx = PageContext::new(
            None,
            &scopes,
            &url,
            "my-client",
            Some(future_expiry()),
            false,
        );
        assert!(ctx.oidc().is_none());
        assert_eq!(ctx.scopes().len(), 2);
        assert_eq!(
            ctx.redirect_uri().as_str(),
            "http://127.0.0.1:8080/callback"
        );
        assert_eq!(ctx.client_id(), "my-client");
    }

    #[test]
    fn page_context_with_oidc_claims() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId];
        let claims = oidc::Claims::new(
            "sub-123".to_string(),
            Some("user@example.com".to_string()),
            Some(true),
            None,
            None,
            url::Url::parse("https://accounts.example.com").unwrap(),
            vec![],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        let ctx = PageContext::new(
            Some(&claims),
            &scopes,
            &url,
            "client",
            Some(future_expiry()),
            false,
        );
        assert!(ctx.oidc().is_some());
        assert_eq!(ctx.oidc().unwrap().sub().as_str(), "sub-123");
    }

    #[test]
    fn error_page_context_accessors_return_expected_values() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId];
        let err = AuthError::Timeout;
        let ctx = ErrorPageContext::new(&err, &scopes, &url, "my-client");
        assert_eq!(ctx.client_id(), "my-client");
        assert_eq!(ctx.scopes().len(), 1);
        assert_eq!(
            ctx.redirect_uri().as_str(),
            "http://127.0.0.1:8080/callback"
        );
        match ctx.error() {
            AuthError::Timeout => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_success_renderer_returns_non_empty_with_authentication_successful() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId];
        let ctx = PageContext::new(None, &scopes, &url, "client", Some(future_expiry()), false);
        let renderer = DefaultSuccessPageRenderer;
        let html = renderer.render_success(&ctx).await;
        assert!(!html.is_empty());
        assert!(
            html.contains("Authentication successful"),
            "missing heading in: {html}"
        );
    }

    #[tokio::test]
    async fn default_success_renderer_with_claims_includes_email() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId, OAuth2Scope::Email];
        let claims = oidc::Claims::new(
            "sub-abc".to_string(),
            Some("alice@example.com".to_string()),
            Some(true),
            Some("Alice".to_string()),
            None,
            url::Url::parse("https://accounts.example.com").unwrap(),
            vec![],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        let ctx = PageContext::new(
            Some(&claims),
            &scopes,
            &url,
            "client",
            Some(future_expiry()),
            false,
        );
        let renderer = DefaultSuccessPageRenderer;
        let html = renderer.render_success(&ctx).await;
        assert!(
            html.contains("alice@example.com"),
            "email missing in: {html}"
        );
        assert!(html.contains("openid"), "scopes missing in: {html}");
    }

    #[tokio::test]
    async fn default_error_renderer_returns_non_empty_with_return_to_terminal() {
        let url = test_url();
        let scopes = vec![OAuth2Scope::OpenId];
        let err = AuthError::Timeout;
        let ctx = ErrorPageContext::new(&err, &scopes, &url, "client");
        let renderer = DefaultErrorPageRenderer;
        let html = renderer.render_error(&ctx).await;
        assert!(!html.is_empty());
        assert!(
            html.contains("Return to your terminal"),
            "missing instruction in: {html}"
        );
    }

    #[tokio::test]
    async fn default_error_renderer_includes_error_info() {
        let url = test_url();
        let scopes: Vec<OAuth2Scope> = vec![];
        let err = AuthError::Callback(CallbackError::ProviderError {
            error: "access_denied".to_string(),
            description: "User denied".to_string(),
        });
        let ctx = ErrorPageContext::new(&err, &scopes, &url, "client");
        let renderer = DefaultErrorPageRenderer;
        let html = renderer.render_error(&ctx).await;
        assert!(
            html.contains("access_denied"),
            "error code missing in: {html}"
        );
    }

    struct MySuccessRenderer;
    #[async_trait::async_trait]
    impl SuccessPageRenderer for MySuccessRenderer {
        async fn render_success(&self, _ctx: &PageContext<'_>) -> String {
            "custom success".to_string()
        }
    }

    struct MyErrorRenderer;
    #[async_trait::async_trait]
    impl ErrorPageRenderer for MyErrorRenderer {
        async fn render_error(&self, _ctx: &ErrorPageContext<'_>) -> String {
            "custom error".to_string()
        }
    }

    #[tokio::test]
    async fn custom_success_renderer_renders_expected_string() {
        let url = test_url();
        let scopes: Vec<OAuth2Scope> = vec![];
        let ctx = PageContext::new(None, &scopes, &url, "client", Some(future_expiry()), false);
        let renderer = MySuccessRenderer;
        let result = renderer.render_success(&ctx).await;
        assert_eq!(result, "custom success");
    }

    #[tokio::test]
    async fn custom_error_renderer_renders_expected_string() {
        let url = test_url();
        let scopes: Vec<OAuth2Scope> = vec![];
        let err = AuthError::Timeout;
        let ctx = ErrorPageContext::new(&err, &scopes, &url, "client");
        let renderer = MyErrorRenderer;
        let result = renderer.render_error(&ctx).await;
        assert_eq!(result, "custom error");
    }
}
