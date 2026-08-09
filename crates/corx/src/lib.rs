//! `corx` — umbrella library for the CORS forwarding proxy stack.
//!
//! This crate is the **recommended dependency** for embedding corx in another
//! binary or service. It re-exports the engine ([`core`]) and the production
//! HTTP binding ([`server`]), and forwards Cargo features (`tls`, `mtls`,
//! `fips`, `otel`) to the underlying crates.
//!
//! # Crate layout
//!
//! | Crate | Role |
//! |-------|------|
//! | [`corx`](crate) | Public facade (this crate) |
//! | [`corx_core`] | Framework-agnostic proxy engine |
//! | [`corx_server`] | axum / tower production server |
//! | `corx-cli` | Binary (`corx` command) |
//!
//! Advanced embedders may depend on `corx-core` or `corx-server` directly
//! when they need a narrower dependency graph.
//!
//! # Example
//!
//! ```ignore
//! use corx::{AppState, Config, ServerBuild, build_router, run};
//! use corx::server::config_loader;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let config = config_loader::load(None)?;
//! let metrics = corx::server::observability::init_metrics()?;
//! let build = ServerBuild::from_config(config.clone(), metrics)?;
//! let ready = std::sync::Arc::clone(&build.ready);
//! let router = build_router(AppState::new(build));
//! run(&config.server, router, ready).await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Framework-agnostic engine: config, policy, proxy, errors.
pub use corx_core as core;
// ── Convenience re-exports (root surface) ─────────────────────────────────
pub use corx_core::config::{
    AuthConfig, AuthMode, CircuitBreakerConfig, Config, ConfigError, CorsConfig, CorsPolicyKind,
    ForwardedConfig, LimitsConfig, ObservabilityConfig, PreflightConfig, PreflightMode,
    RateLimitConfig, RedirectPolicy, SecurityConfig, ServerConfig, SsrfConfig, SsrfMode,
    TargetConfig, TargetMode, TlsConfig, UpstreamConfig, ValidationReport,
};
pub use corx_core::error::{ErrorKind, ErrorPayload, ProxyError, STATUS_HEADER};
pub use corx_core::policy::{CircuitBreaker, CircuitHop, TargetPolicy};
pub use corx_core::proxy::{
    ClientConfig, CorsPolicy, HeaderFilter, SsrfGuard, TargetUrl, Upstream, UpstreamBody,
    apply_to_response, build_preflight_response, extract_target, is_preflight,
};
/// Production axum/tower server binding, middleware, and lifecycle.
pub use corx_server as server;
pub use corx_server::{AppState, ServerBuild, build_router, run};
