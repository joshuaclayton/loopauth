use std::sync::Arc;

/// A validated TLS certificate and private key pair for HTTPS serving.
///
/// Validation happens at construction time: PEM parsing, certificate chain
/// formation, and key compatibility are all checked eagerly so errors
/// surface immediately rather than at server start.
///
/// # Recommended: `ensure_localhost`
///
/// For most CLI applications, [`TlsCertificate::ensure_localhost`] is the
/// simplest integration. It manages certificate generation via `mkcert`
/// automatically, generating on first run and loading on subsequent runs:
///
/// ```no_run
/// use loopauth::{CliTokenClient, TlsCertificate};
/// use std::path::PathBuf;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let tls_dir = PathBuf::from("/home/user/.config/my-cli/tls");
/// let cert = TlsCertificate::ensure_localhost(&tls_dir)?;
///
/// let client = CliTokenClient::builder()
///     .client_id("my-client-id")
///     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
///     .token_url(url::Url::parse("https://provider.example.com/token")?)
///     .use_https_with(cert)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// # Manual loading
///
/// For full control over file paths, use [`TlsCertificate::from_pem_files`]
/// or [`TlsCertificate::from_pem`] directly.
///
/// # End-user prerequisites
///
/// The end user must have [`mkcert`](https://github.com/FiloSottile/mkcert)
/// installed and its local CA trusted (`mkcert -install`, one-time). See
/// [`TlsCertificate::SETUP_GUIDE_MANAGED`] for instructions tailored to
/// `ensure_localhost`, or [`TlsCertificate::SETUP_GUIDE`] for the full
/// manual guide.
pub struct TlsCertificate {
    pub(crate) acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsCertificate {
    /// End-user-facing instructions for generating locally-trusted HTTPS
    /// certificates with `mkcert`.
    ///
    /// This text is written for the person **running** your CLI, not for you
    /// (the CLI author). Embed it in your `--help` output, a setup wizard, or
    /// first-run documentation. It covers macOS, Linux, and Windows.
    ///
    /// This guide includes all four steps (install, trust CA, generate certs,
    /// provide to app). If your CLI uses [`TlsCertificate::ensure_localhost`]
    /// (which generates certs automatically), use
    /// [`SETUP_GUIDE_MANAGED`](TlsCertificate::SETUP_GUIDE_MANAGED) instead,
    /// which only includes the two steps the end user actually needs.
    ///
    /// # Example
    ///
    /// ```
    /// use loopauth::TlsCertificate;
    ///
    /// // Print setup instructions when the user hasn't configured certs yet
    /// println!("{}", TlsCertificate::SETUP_GUIDE);
    /// ```
    pub const SETUP_GUIDE: &'static str = "\
HTTPS Certificate Setup
========================

This application uses HTTPS for secure OAuth login. A one-time setup is
required to create a locally-trusted certificate so your browser can
complete the login without security warnings.

Steps 1 and 2 can be run from any directory; they are global operations.

1. Install mkcert (https://github.com/FiloSottile/mkcert#installation):

   macOS:          brew install mkcert
   Other platforms: see the link above

2. Create and install a local certificate authority (one-time, may prompt
   for your password). This adds a root certificate to your system trust
   store so browsers accept localhost certificates. It does not affect
   other machines or network traffic:

   mkcert -install

3. Generate a certificate for localhost (run from any directory):

   mkcert -cert-file localhost-cert.pem -key-file localhost-key.pem \\
          localhost 127.0.0.1

   This creates two files in your current directory:
   - localhost-cert.pem  (certificate, safe to share)
   - localhost-key.pem   (private key, keep secure)

   Generating multiple certificates is fine; each is independently valid,
   all signed by the same local CA from step 2.

4. Provide the generated files to this application. See the application's
   documentation for the specific command or configuration.

The certificate files are reusable across sessions and are not tied to
the directory where they were generated. The private key is only valid
for localhost connections on this machine.";

    /// Shorter setup guide for CLI authors using [`TlsCertificate::ensure_localhost`].
    ///
    /// When your CLI manages certificate generation automatically via
    /// `ensure_localhost`, the end user only needs to install `mkcert` and
    /// trust the local CA. This guide covers just those two steps.
    ///
    /// For manual cert generation and file paths (with
    /// [`from_pem_files`](TlsCertificate::from_pem_files)), see
    /// [`SETUP_GUIDE`](TlsCertificate::SETUP_GUIDE) instead.
    ///
    /// # Example
    ///
    /// ```
    /// use loopauth::TlsCertificate;
    ///
    /// // Show when ensure_localhost returns MkcertNotFound
    /// println!("{}", TlsCertificate::SETUP_GUIDE_MANAGED);
    /// ```
    pub const SETUP_GUIDE_MANAGED: &'static str = "\
HTTPS Certificate Setup
========================

This application uses HTTPS for secure OAuth login. A one-time setup is
required so your browser can complete the login without security warnings.

Both commands below can be run from any directory; they are global
operations that apply to your entire machine.

1. Install mkcert (https://github.com/FiloSottile/mkcert#installation):

   macOS:          brew install mkcert
   Other platforms: see the link above

2. Create and install a local certificate authority (one-time, may prompt
   for your password). This adds a root certificate to your system trust
   store so browsers accept localhost certificates. It does not affect
   other machines or network traffic:

   mkcert -install

That's it; there is no step 3. Certificate files are generated
automatically the next time you run this application. If you have already
run `mkcert -install` for another tool, you only need step 1.";

    /// Parse PEM-encoded certificate chain and private key from byte slices.
    ///
    /// Validates that:
    /// - At least one certificate is present in `cert_pem`
    /// - Exactly one private key is present in `key_pem`
    /// - The key is compatible with the certificate (checked by `rustls`)
    ///
    /// # Errors
    ///
    /// Returns [`TlsCertificateError`] if parsing fails or the cert/key are
    /// incompatible.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsCertificateError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(TlsCertificateError::ParseCert)?;

        if certs.is_empty() {
            return Err(TlsCertificateError::NoCertificates);
        }

        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(TlsCertificateError::ParseKey)?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(TlsCertificateError::Rustls)?;

        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        })
    }

    /// Read PEM-encoded certificate and private key from files.
    ///
    /// Convenience wrapper around [`TlsCertificate::from_pem`] that reads the
    /// files first.
    ///
    /// # Errors
    ///
    /// Returns [`TlsCertificateError::ReadCert`] or
    /// [`TlsCertificateError::ReadKey`] if the files cannot be read, or any
    /// error from [`TlsCertificate::from_pem`] if the contents are invalid.
    pub fn from_pem_files(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, TlsCertificateError> {
        let cert_pem = std::fs::read(cert_path).map_err(TlsCertificateError::ReadCert)?;
        let key_pem = std::fs::read(key_path).map_err(TlsCertificateError::ReadKey)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Ensure locally-trusted localhost certificates exist in `dir`.
    ///
    /// If `dir` already contains `localhost-cert.pem` and `localhost-key.pem`,
    /// they are loaded and validated. Otherwise, `mkcert` is invoked to
    /// generate them in-place.
    ///
    /// This is the recommended single-call integration point for CLI authors.
    /// Pass your application's config directory (e.g.
    /// `~/.config/my-cli/tls/`) and loopauth handles the rest.
    ///
    /// # What this does
    ///
    /// 1. Checks for existing `localhost-cert.pem` and `localhost-key.pem` in
    ///    `dir`
    /// 2. If both exist, loads and validates them
    /// 3. If either is missing, creates `dir` (if needed) and runs:
    ///    ```text
    ///    mkcert -cert-file <dir>/localhost-cert.pem \
    ///           -key-file <dir>/localhost-key.pem \
    ///           localhost 127.0.0.1
    ///    ```
    /// 4. Sets the private key file to mode `0o600` (owner read/write only)
    ///    on Unix systems
    /// 5. Loads and validates the generated files
    ///
    /// # Prerequisites
    ///
    /// The end user must have `mkcert` installed and its CA trusted:
    ///
    /// ```sh
    /// brew install mkcert   # or equivalent for their platform
    /// mkcert -install        # one-time CA setup
    /// ```
    ///
    /// See [`TlsCertificate::SETUP_GUIDE_MANAGED`] for end-user instructions
    /// tailored to this workflow.
    ///
    /// # Blocking
    ///
    /// This function calls `std::process::Command::new("mkcert")`
    /// synchronously on first run. Call it at CLI startup (before entering
    /// async hot paths) or wrap in `tokio::task::spawn_blocking` if needed.
    /// Subsequent runs (when certs already exist) perform only file I/O.
    ///
    /// # Certificate lifetime
    ///
    /// `mkcert` certificates are valid for approximately 27 months by
    /// default. When a certificate expires, delete the files in `dir` and
    /// call this method again to regenerate.
    ///
    /// # Errors
    ///
    /// Returns [`TlsCertificateError::MkcertNotFound`] if `mkcert` is not on
    /// `PATH`.
    /// Returns [`TlsCertificateError::MkcertFailed`] if `mkcert` exits
    /// non-zero (typically because `mkcert -install` has not been run).
    /// Returns other [`TlsCertificateError`] variants for I/O or PEM
    /// validation failures.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use loopauth::{CliTokenClient, TlsCertificate};
    /// use std::path::PathBuf;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let tls_dir = PathBuf::from("/home/user/.config/my-cli/tls");
    ///
    /// let cert = TlsCertificate::ensure_localhost(&tls_dir)?;
    ///
    /// let client = CliTokenClient::builder()
    ///     .client_id("my-client-id")
    ///     .auth_url(url::Url::parse("https://provider.example.com/authorize")?)
    ///     .token_url(url::Url::parse("https://provider.example.com/token")?)
    ///     .use_https_with(cert)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn ensure_localhost(dir: impl AsRef<std::path::Path>) -> Result<Self, TlsCertificateError> {
        let dir = dir.as_ref();
        let cert_path = dir.join("localhost-cert.pem");
        let key_path = dir.join("localhost-key.pem");

        if cert_path.exists() && key_path.exists() {
            return Self::from_pem_files(&cert_path, &key_path);
        }

        std::fs::create_dir_all(dir).map_err(TlsCertificateError::CreateDir)?;

        let output = std::process::Command::new("mkcert")
            .arg("-cert-file")
            .arg(&cert_path)
            .arg("-key-file")
            .arg(&key_path)
            .arg("localhost")
            .arg("127.0.0.1")
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TlsCertificateError::MkcertNotFound
                } else {
                    TlsCertificateError::MkcertFailed {
                        message: e.to_string(),
                    }
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(TlsCertificateError::MkcertFailed { message: stderr });
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&key_path, perms)
                .map_err(TlsCertificateError::SetPermissions)?;
        }

        Self::from_pem_files(&cert_path, &key_path)
    }
}

/// Errors that can occur when constructing a [`TlsCertificate`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsCertificateError {
    /// The certificate file could not be read.
    #[error("failed to read certificate file: {0}")]
    ReadCert(#[source] std::io::Error),
    /// The private key file could not be read.
    #[error("failed to read key file: {0}")]
    ReadKey(#[source] std::io::Error),
    /// The certificate PEM data could not be parsed.
    #[error("failed to parse certificate PEM: {0}")]
    ParseCert(#[source] rustls::pki_types::pem::Error),
    /// The private key PEM data could not be parsed.
    #[error("failed to parse private key PEM: {0}")]
    ParseKey(#[source] rustls::pki_types::pem::Error),
    /// No certificates were found in the PEM data.
    #[error("no certificates found in PEM data")]
    NoCertificates,
    /// The certificate and key are incompatible or TLS configuration failed.
    #[error("TLS configuration failed: {0}")]
    Rustls(#[source] rustls::Error),
    /// The certificate directory could not be created.
    #[error("failed to create certificate directory: {0}")]
    CreateDir(#[source] std::io::Error),
    /// `mkcert` was not found on `PATH`.
    ///
    /// The end user needs to install `mkcert`. See
    /// [`TlsCertificate::SETUP_GUIDE_MANAGED`] for instructions.
    #[error("mkcert is not installed (see https://github.com/FiloSottile/mkcert#installation)")]
    MkcertNotFound,
    /// `mkcert` exited with an error.
    ///
    /// This typically means the local CA has not been set up. The end user
    /// should run `mkcert -install` once.
    #[error("mkcert failed: {message}")]
    MkcertFailed {
        /// Stderr output from the `mkcert` process.
        message: String,
    },
    /// Failed to set file permissions on the private key.
    #[error("failed to set key file permissions: {0}")]
    SetPermissions(#[source] std::io::Error),
}

/// Errors from self-signed certificate generation.
///
/// Returned by [`self_signed_localhost_acceptor`] when the ephemeral
/// certificate or TLS configuration cannot be created.
#[derive(Debug, thiserror::Error)]
pub enum SelfSignedCertError {
    /// The `rcgen` certificate generation library returned an error.
    #[error("certificate generation failed: {0}")]
    Rcgen(#[source] rcgen::Error),
    /// The generated certificate could not be loaded into a `rustls` server
    /// configuration.
    #[error("TLS configuration failed: {0}")]
    Rustls(#[source] rustls::Error),
}

/// Generate a self-signed TLS acceptor for the loopback callback server.
///
/// Creates a certificate valid for both `localhost` and `127.0.0.1` using
/// `rcgen`, then builds a `tokio_rustls::TlsAcceptor` from it. The certificate
/// is ephemeral, generated fresh for each authorization flow.
pub fn self_signed_localhost_acceptor() -> Result<tokio_rustls::TlsAcceptor, SelfSignedCertError> {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::net::{IpAddr, Ipv4Addr};

    let mut params =
        CertificateParams::new(vec!["localhost".to_owned()]).map_err(SelfSignedCertError::Rcgen)?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    // rcgen defaults to ECDSA P-256, appropriate for ephemeral localhost certs.
    let key_pair = KeyPair::generate().map_err(SelfSignedCertError::Rcgen)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(SelfSignedCertError::Rcgen)?;

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(SelfSignedCertError::Rustls)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}
