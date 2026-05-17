//! `corx-core` — framework-agnostic CORS forwarding proxy engine.
//!
//! This crate contains the entire hot path of the proxy: URL extraction,
//! CORS shaping, SSRF protection, header filtering, redirect handling and
//! the upstream HTTP client. It does not depend on any specific HTTP server
//! framework, so it can be embedded in `axum`, `actix-web`, `poem`, raw
//! `hyper` services or any custom stack.
//!
//! The companion crate [`corx-server`](https://docs.rs/corx-server) provides
//! the production-grade `axum` + `tower` bindings, middleware (rate limiting,
//! origin guard, access log, OpenTelemetry…), TLS termination and graceful
//! lifecycle management.

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
pub mod proxy;
pub mod util;
