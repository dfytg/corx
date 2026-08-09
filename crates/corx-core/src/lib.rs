//! `corx-core` — framework-agnostic CORS forwarding proxy engine.
//!
//! This crate contains the entire hot path of the proxy: URL extraction,
//! CORS shaping, SSRF protection, header filtering, redirect handling and
//! the upstream HTTP client. It does not depend on any specific HTTP server
//! framework, so it can be embedded in `axum`, `actix-web`, `poem`, raw
//! `hyper` services or any custom stack.
//!
//! Prefer the umbrella crate [`corx`](https://docs.rs/corx) for embedding.
//! For a narrower dependency graph, [`corx-server`](https://docs.rs/corx-server)
//! provides the production `axum` + `tower` binding (middleware, TLS,
//! lifecycle). The `corx` CLI is published as package `corx-cli`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// `criterion` is a dev-dependency consumed only by the benches under
// `benches/`. Without this anchoring import the workspace lint
// `unused_crate_dependencies` flags the crate against `lib.rs`.
#[cfg(test)]
use criterion as _;

pub mod config;
pub mod error;
pub mod observability;
pub mod policy;
pub mod proxy;
pub mod util;
