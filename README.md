[![crates.io](https://img.shields.io/crates/v/loopauth.svg)](https://crates.io/crates/loopauth)
[![docs.rs](https://docs.rs/loopauth/badge.svg)](https://docs.rs/loopauth)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

# loopauth

OAuth 2.0 Authorization Code + PKCE flow for CLI applications.

`loopauth` opens the user's browser to the authorization URL, spins up a short-lived loopback server to receive the redirect callback, exchanges the authorization code for tokens, and returns a `TokenSet` containing access and refresh tokens. Your application can then use those tokens (e.g., the ID token) to authenticate users against your own backend.

It is not a full OAuth 2.0 or OIDC library. Other grant types (client credentials, device flow, etc.), token introspection, and app-level authentication are out of scope.

Token storage and downstream identity consumption are intentionally out of scope; implement the `TokenStore` trait to provide your own persistence.

## Quick start

### OIDC auto-discovery

Provider URLs are fetched automatically via `.well-known/openid-configuration`:

```rust
use loopauth::{CliTokenClientBuilder, RequestScope, oidc::OpenIdConfiguration};
use url::Url;

let open_id_configuration = OpenIdConfiguration::fetch(
    Url::parse("https://provider.example.com")?,
).await?;

// from_open_id_configuration automatically includes the openid scope
let client = CliTokenClientBuilder::from_open_id_configuration(&open_id_configuration)
    .client_id("my-client-id")
    .with_open_id_configuration_jwks_validator(&open_id_configuration)
    .add_scopes([RequestScope::Email])
    .build();

let tokens = client.run_authorization_flow().await?;
```

### Explicit URLs

```rust
use loopauth::{CliTokenClient, RequestScope};
use url::Url;

let client = CliTokenClient::builder()
    .client_id("my-client-id")
    .auth_url(Url::parse("https://provider.example.com/authorize")?)
    .token_url(Url::parse("https://provider.example.com/token")?)
    .with_openid_scope()
    .without_jwks_validation() // or .jwks_validator(Box::new(my_validator))
    .add_scopes([RequestScope::Email])
    .build();

let tokens = client.run_authorization_flow().await?;
```

## HTTPS callbacks

Some OAuth providers (notably Slack) require `https://` redirect URIs, even for
localhost. loopauth supports HTTPS callbacks using locally-trusted TLS
certificates.

### How it works

By default, loopauth serves the callback over plain HTTP on `127.0.0.1`, which
is permitted by [RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3)
and accepted by most providers. When a provider requires HTTPS, call
`.use_https_with(cert)` on the builder to serve over TLS with a trusted
certificate, or `.use_https()` for a self-signed fallback (development only).

The recommended approach uses [mkcert](https://github.com/FiloSottile/mkcert) to
create a locally-trusted certificate authority. Certificates signed by this CA
are trusted by all browsers on the machine, so the OAuth redirect completes
seamlessly with no certificate warnings.

### Who does what

There are three roles in the chain:

| Role | Responsibility |
|------|----------------|
| **loopauth** (this crate) | Generates/loads certs, serves HTTPS, provides setup guide text |
| **CLI author** (your code) | Provides a config directory path, calls `ensure_localhost()` or `from_pem_files()` |
| **End user** (runs the CLI) | One-time: installs `mkcert` and runs `mkcert -install` |

### End-user setup (one-time)

The end user needs to do this once per machine. Both commands can be run from
any directory; they are global operations:

```sh
# 1. Install mkcert (https://github.com/FiloSottile/mkcert#installation)
#    macOS: brew install mkcert
#    Other platforms: see the link above

# 2. Create and install a local CA (may prompt for password).
#    This adds a root certificate to the system trust store so browsers
#    accept localhost certificates signed by it. It does not affect other
#    machines or network traffic.
mkcert -install
```

That's it; there is no step 3. The end user does **not** need to run `mkcert`
to generate certificate files. `TlsCertificate::ensure_localhost()` handles
certificate generation automatically on first run, storing the files in your
app's config directory.

If `mkcert -install` has already been run (e.g. for another tool), the end user
only needs step 1 (installing the `mkcert` binary). Generating multiple
localhost certificates is fine; each is independently valid, all signed by the
same local CA.

### CLI author integration

Point `ensure_localhost` at your app's config directory. It handles everything:

- **First run:** creates the directory (if needed), shells out to `mkcert` to
  generate `localhost-cert.pem` and `localhost-key.pem`, sets file permissions,
  and loads the result.
- **Subsequent runs:** loads the existing cert files from disk. No `mkcert`
  invocation occurs.

The cert files are self-contained and not tied to the directory where `mkcert`
was invoked; `ensure_localhost` manages the paths internally.

```rust
use loopauth::{CliTokenClient, TlsCertificate};

let cert = TlsCertificate::ensure_localhost(
    config_dir.join("tls"),
)?;

let client = CliTokenClient::builder()
    .client_id("my-client-id")
    .auth_url(auth_url)
    .token_url(token_url)
    .use_https_with(cert)
    .build();

let tokens = client.run_authorization_flow().await?;
```

If the end user hasn't installed `mkcert`, `ensure_localhost` returns
`TlsCertificateError::MkcertNotFound`. If the local CA isn't set up
(`mkcert -install` was never run), `TlsCertificateError::MkcertFailed` tells
them what to do.

For full control over cert loading (e.g. custom file paths or embedding certs),
use `TlsCertificate::from_pem_files()` or `TlsCertificate::from_pem()` instead.

### Providing setup instructions to end users

Two `&'static str` constants provide ready-made `mkcert` instructions for end
users:

- `TlsCertificate::SETUP_GUIDE_MANAGED`: covers only `mkcert` installation and
  CA trust (steps 1-2). **Use this when your CLI manages cert generation
  automatically via `ensure_localhost`.**
- `TlsCertificate::SETUP_GUIDE`: full four-step guide including manual cert
  generation and file handoff.

```rust
// When using ensure_localhost (recommended):
println!("{}", loopauth::TlsCertificate::SETUP_GUIDE_MANAGED);

// When using from_pem_files (manual mode):
println!("{}", loopauth::TlsCertificate::SETUP_GUIDE);
```

### Self-signed fallback

For development or testing, `.use_https()` (without a certificate) generates an
ephemeral self-signed certificate. Browsers will display a certificate warning
that the user must click through for the callback to complete. This is not
recommended for end-user-facing flows.

### Provider-specific notes

**Slack**: Requires HTTPS redirect URIs. Register
`https://127.0.0.1:<port>/callback` in your Slack app's Redirect URLs. Use
`.require_port(8443)` on the builder to pin the port so it matches the
registered URL. The callback path `/callback` is not configurable.

## Features

- PKCE ([RFC 7636])
- OIDC discovery
- JWKS validation
- Token refresh
- HTTPS callbacks with locally-trusted certificates
- Configurable token storage
- Configurable browser open behavior
- Configurable HTML success/error pages

[RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636

## Examples

The `examples/` directory contains runnable demos. Each example's source file documents its required and optional environment variables.

| Example | Description |
|---------|-------------|
| [`auth.rs`](examples/auth.rs) | Manual configuration (explicit auth + token URLs) |
| [`auth_discovery.rs`](examples/auth_discovery.rs) | OIDC discovery-based setup |
| [`auth_https.rs`](examples/auth_https.rs) | HTTPS callback with `mkcert` certificates (e.g. for Slack) |
| [`jwks_demo.rs`](examples/jwks_demo.rs) | JWKS JWT validation demo |
| [`refresh_demo.rs`](examples/refresh_demo.rs) | Token refresh flow |

Some examples require environment variables (provider credentials, URLs). Review the source file for each example before running it.

```sh
cargo run --example auth
cargo run --example auth_discovery
cargo run --example auth_https                   # set LOOPAUTH_TLS_DIR or LOOPAUTH_CERT_FILE + KEY_FILE
cargo run --example auth_https -- --setup-guide  # print mkcert setup instructions
cargo run --example jwks_demo
cargo run --example refresh_demo
```

## Local development

You'll need to install [just](https://just.systems/).

```sh
just setup # install required tools (cargo-nextest, cargo-watch, cargo-llvm-cov)
just test  # full test suite
just docs  # open API docs in browser
```

## License

This crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
