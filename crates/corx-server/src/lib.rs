//! `corx-server` — production-grade `axum` + `tower` bindings on top of the
//! framework-agnostic [`corx_core`] proxy engine.
//!
//! This crate owns:
//!
//! * Inbound middleware (origin guard, multi-dimensional rate limiting,
//!   load shedding, access log, request ID injection).
//! * The router that wires `/` (proxy), `/livez`, `/readyz`, `/healthz`,
//!   and `/metrics`.
//! * TLS / mTLS / FIPS variants, gated by Cargo features.
//! * Telemetry initialisation: structured `tracing`, Prometheus exposition
//!   and the optional OpenTelemetry / OTLP pipeline.
//! * Server lifecycle: bind, serve, graceful shutdown, configuration hot
//!   reload via `arc-swap`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    unused_crate_dependencies,
    reason = "Workspace deps shared across optional features (tls/otel) \
              and integration tests; lib target alone would false-positive."
)]

pub mod config_loader;
pub mod error;
pub mod handlers;
pub mod hot_reload;
pub mod middleware;
pub mod observability;
pub mod router;
pub mod shutdown;
pub mod state;
#[cfg(feature = "tls")]
pub mod tls;

pub use self::error::ServerError;
pub use self::hot_reload::ReloadHandle;
pub use self::router::{AppState, build_router};
pub use self::shutdown::run;
pub use self::state::ServerBuild;
