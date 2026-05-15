//! Configuration domain types and built-in defaults.
//!
//! This module contains *only* the data types and their default values. The
//! actual layered loader (TOML + environment + CLI overrides) lives in the
//! `corx-server` crate so that `corx-core` stays free of side-effecting
//! dependencies and is suitable for embedding into custom hosts.

mod defaults;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// Request/response size, timeout and redirect limits.
    pub limits: LimitsConfig,
    /// CORS policy applied to outgoing responses.
    pub cors: CorsConfig,
    /// Inbound request guards (origin lists, required headers).
    pub security: SecurityConfig,
    /// SSRF protection settings.
    pub ssrf: SsrfConfig,
    /// Rate limiting.
    pub rate_limit: RateLimitConfig,
    /// Upstream HTTP client tuning.
    pub upstream: UpstreamConfig,
    /// Telemetry (logs, metrics).
    pub observability: ObservabilityConfig,
}

/// HTTP listener configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind the HTTP listener to.
    pub bind: SocketAddr,
    /// Number of Tokio worker threads. `0` selects `num_cpus::get()`.
    pub workers: usize,
    /// How long to wait for in-flight requests during shutdown.
    #[serde(with = "humantime_serde")]
    pub graceful_shutdown: Duration,
    /// Enable HTTP/2 on the inbound listener.
    pub http2: bool,
    /// Optional TLS settings (requires the `tls` cargo feature at compile time).
    pub tls: Option<TlsConfig>,
}

/// TLS configuration for the inbound listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: PathBuf,
}

/// Size- and time-based limits applied to every request.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum inbound request body size, in bytes.
    pub max_request_body_bytes: u64,
    /// Maximum inbound header size, in bytes.
    pub max_request_header_bytes: u32,
    /// Total allowable duration of a single proxied request, end-to-end.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// Timeout for establishing a TCP connection to the upstream.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Maximum number of redirects followed per request.
    pub max_redirects: u8,
}

/// CORS policy discriminant.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CorsPolicyKind {
    /// Return `Access-Control-Allow-Origin: *`.
    Wildcard,
    /// Reflect the request `Origin`, optionally gated by `allowlist`.
    Reflect,
    /// Reflect `Origin` only if it matches one of the explicitly listed values.
    Explicit,
}

/// CORS response-shaping policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Which CORS policy to apply.
    pub policy: CorsPolicyKind,
    /// Used by [`CorsPolicyKind::Reflect`]; empty means “allow any origin”.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Used by [`CorsPolicyKind::Explicit`].
    #[serde(default)]
    pub explicit: Vec<String>,
    /// Value sent for `Access-Control-Max-Age` on preflight responses.
    #[serde(with = "humantime_serde")]
    pub max_age: Duration,
    /// Whether to emit `Access-Control-Allow-Credentials: true`.
    pub allow_credentials: bool,
}

/// Inbound guards.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// At least one of these request headers must be present; empty disables the check.
    #[serde(default)]
    pub require_header: Vec<String>,
    /// Request methods that are explicitly blocked.
    #[serde(default)]
    pub block_methods: Vec<String>,
    /// Request headers stripped before forwarding.
    #[serde(default)]
    pub remove_request_headers: Vec<String>,
    /// Response headers stripped before returning to the client.
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
    /// Origins denied outright (regex-free, exact match).
    #[serde(default)]
    pub origin_blacklist: Vec<String>,
    /// When non-empty, only origins in this list are allowed.
    #[serde(default)]
    pub origin_whitelist: Vec<String>,
}

/// SSRF protection.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SsrfConfig {
    /// Enable SSRF protection; when disabled, resolved IPs are not validated.
    pub enabled: bool,
    /// Extra CIDR ranges to block, on top of the built-in defaults (RFC 1918,
    /// loopback, link-local, unique-local, multicast, reserved).
    #[serde(default)]
    pub extra_blocked_cidrs: Vec<IpNet>,
    /// Allow DNS resolution to return IPv6 addresses.
    pub allow_ipv6: bool,
}

/// Rate-limit configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Globally enable or disable rate limiting.
    pub enabled: bool,
    /// Requests per second permitted per origin.
    pub per_origin_rps: u32,
    /// Additional burst budget on top of the steady-state RPS.
    pub burst: u32,
    /// Regular expressions that match origins exempt from rate limiting.
    #[serde(default)]
    pub unlimited_hosts: Vec<String>,
}

/// Upstream HTTP client tuning.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Max idle connections retained per host in the connection pool.
    pub pool_max_idle_per_host: usize,
    /// Idle connection timeout before eviction.
    #[serde(with = "humantime_serde")]
    pub pool_idle_timeout: Duration,
    /// User-Agent sent on forwarded requests when the client did not set one.
    pub user_agent: String,
}

/// Observability configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Log formatter.
    pub log_format: LogFormat,
    /// `tracing` env-filter directive.
    pub log_level: String,
    /// Path where Prometheus metrics are served.
    pub metrics_endpoint: String,
}

/// Supported log output formats.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable formatter with ANSI colours.
    Pretty,
    /// Structured single-line JSON, one object per event.
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self::defaults()
    }
}
