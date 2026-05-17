//! Configuration domain types and built-in defaults.
//!
//! This module contains *only* the data types and their default values. The
//! actual layered loader (TOML + environment + CLI overrides) lives in the
//! `corx-server` crate so that `corx-core` stays free of side-effecting
//! dependencies and is suitable for embedding into custom hosts.
//!
//! Each configuration domain lives in its own submodule and provides its own
//! [`Default`] implementation, so [`Config::default`] is a straightforward
//! aggregation rather than an inherent factory method.

mod cors;
mod forwarded;
mod limits;
mod observability;
mod rate_limit;
mod security;
mod server;
mod ssrf;
mod tls;
mod upstream;
mod validate;

use serde::{Deserialize, Serialize};

pub use self::cors::{CorsConfig, CorsPolicyKind};
pub use self::forwarded::ForwardedConfig;
pub use self::limits::LimitsConfig;
pub use self::observability::{LogFormat, ObservabilityConfig, OtelConfig, OtelProtocol};
pub use self::rate_limit::{
    GlobalLimitConfig, HostLimitConfig, IpLimitConfig, OriginLimitConfig, RateLimitConfig,
};
pub use self::security::SecurityConfig;
pub use self::server::ServerConfig;
pub use self::ssrf::{SsrfConfig, SsrfMode};
pub use self::tls::TlsConfig;
pub use self::upstream::UpstreamConfig;
pub use self::validate::{ConfigError, ValidationReport};

/// Shared serde helper: literal `true` for `#[serde(default = ...)]` slots.
pub(crate) const fn default_true() -> bool {
    true
}

/// Top-level configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Request/response size, timeout and redirect limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// CORS policy applied to outgoing responses.
    #[serde(default)]
    pub cors: CorsConfig,
    /// Inbound request guards (origin lists, required headers).
    #[serde(default)]
    pub security: SecurityConfig,
    /// SSRF protection settings.
    #[serde(default)]
    pub ssrf: SsrfConfig,
    /// Forwarded / X-Request-Id injection.
    #[serde(default)]
    pub forwarded: ForwardedConfig,
    /// Rate limiting.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Upstream HTTP client tuning.
    #[serde(default)]
    pub upstream: UpstreamConfig,
    /// Telemetry (logs, metrics).
    #[serde(default)]
    pub observability: ObservabilityConfig,
}
