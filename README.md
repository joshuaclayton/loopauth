[![crates.io](https://img.shields.io/crates/v/loopauth.svg)](https://crates.io/crates/loopauth)
[![docs.rs](https://docs.rs/loopauth/badge.svg)](https://docs.rs/loopauth)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

# loopauth

OAuth 2.0 Authorization Code + PKCE flow for CLI applications.

`loopauth` opens the user's browser to the authorization URL, spins up a short-lived loopback HTTP server to receive the redirect callback, exchanges the authorization code for tokens, and returns a `TokenSet` containing access and refresh tokens. Your application can then use those tokens (e.g., the ID token) to authenticate users against your own backend.

It is not a full OAuth 2.0 or OIDC library. Other grant types (client credentials, device flow, etc.), token introspection, and app-level authentication are out of scope.

Token storage and downstream identity consumption are intentionally out of scope; implement the `TokenStore` trait to provide your own persistence.

## Quick start

### OIDC auto-discovery

Provider URLs are fetched automatically via `.well-known/openid-configuration`:

```rust
use loopauth::{CliTokenClientBuilder, OAuth2Scope, OpenIdConfiguration};
use url::Url;

let open_id_configuration = OpenIdConfiguration::fetch(
    Url::parse("https://provider.example.com")?,
).await?;

// from_open_id_configuration automatically includes the openid scope
let client = CliTokenClientBuilder::from_open_id_configuration(&open_id_configuration)
    .client_id("my-client-id")
    .extend_scopes([OAuth2Scope::Email])
    .build();

let tokens = client.run_authorization_flow().await?;
```

### Explicit URLs

```rust
use loopauth::{CliTokenClient, OAuth2Scope};
use url::Url;

let client = CliTokenClient::builder()
    .client_id("my-client-id")
    .auth_url(Url::parse("https://provider.example.com/authorize")?)
    .token_url(Url::parse("https://provider.example.com/token")?)
    .with_openid_scope()
    .extend_scopes([OAuth2Scope::Email])
    .build();

let tokens = client.run_authorization_flow().await?;
```

## Features

- PKCE ([RFC 7636])
- OIDC discovery
- JWKS validation
- Token refresh
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
| [`jwks_demo.rs`](examples/jwks_demo.rs) | JWKS JWT validation demo |
| [`refresh_demo.rs`](examples/refresh_demo.rs) | Token refresh flow |

Some examples require environment variables (provider credentials, URLs). Review the source file for each example before running it.

```sh
cargo run --example auth
cargo run --example auth_discovery
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
