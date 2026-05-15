//! Configuration domain types and built-in defaults.
//!
//! This module contains *only* the data types and their default values. The
//! actual layered loader (TOML + environment + CLI overrides) lives in the
//! `corx-server` crate so that `corx-core` stays free of side-effecting
//! dependencies and is suitable for embedding into custom hosts.

mod defaults;
mod validate;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub use self::validate::{ConfigError, ValidationReport};

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
    /// Forwarded / X-Request-Id injection.
    #[serde(default = "ForwardedConfig::default")]
    pub forwarded: ForwardedConfig,
    /// Rate limiting.
    pub rate_limit: RateLimitConfig,
    /// Upstream HTTP client tuning.
    pub upstream: UpstreamConfig,
    /// Telemetry (logs, metrics).
    pub observability: ObservabilityConfig,
}

/// Configures `Forwarded` / `X-Forwarded-*` / `X-Request-Id` injection.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedConfig {
    /// Stamp `X-Forwarded-*` and RFC 7239 `Forwarded` on outbound requests.
    #[serde(default = "default_true")]
    pub inject: bool,
    /// Trust an inbound `X-Forwarded-For` chain and append our peer IP.
    /// Defaults to `false`: an internet-facing deployment must not let a
    /// client poison logs by forging upstream forwarders.
    #[serde(default)]
    pub trust_inbound_xff: bool,
    /// Generate a UUID v7 `X-Request-Id` when the client did not supply one.
    #[serde(default = "default_true")]
    pub inject_request_id: bool,
}

impl Default for ForwardedConfig {
    fn default() -> Self {
        Self {
            inject: true,
            trust_inbound_xff: false,
            inject_request_id: true,
        }
    }
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
    /// Path to the PEM-encoded private key (PKCS#8 or RSA).
    pub key_path: PathBuf,
    /// Path to the PEM-encoded trust anchors used to validate client
    /// certificates. When set, the server will require mTLS. Requires the
    /// `mtls` Cargo feature on the binary.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    /// ALPN protocols to advertise, in preference order. Defaults to
    /// `["h2", "http/1.1"]`.
    #[serde(default = "default_alpn_protocols")]
    pub alpn_protocols: Vec<String>,
}

fn default_alpn_protocols() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
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
    /// Allow `https → http` redirect downgrades. Defaults to `false` to keep
    /// transport security from silently weakening across hops.
    #[serde(default)]
    pub allow_https_to_http_downgrade: bool,
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
    /// Methods advertised in `Access-Control-Allow-Methods` for preflight
    /// responses. Empty falls back to echoing the request's
    /// `Access-Control-Request-Method`.
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    /// Headers advertised in `Access-Control-Allow-Headers` for preflight
    /// responses. Empty falls back to echoing the request's
    /// `Access-Control-Request-Headers`.
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,
    /// Headers advertised in `Access-Control-Expose-Headers`. The
    /// machine-readable `x-corx-status` and `x-request-id` are always exposed
    /// in addition to whatever the operator configures here.
    #[serde(default = "default_exposed_headers")]
    pub exposed_headers: Vec<String>,
    /// Value sent for `Access-Control-Max-Age` on preflight responses.
    #[serde(with = "humantime_serde")]
    pub max_age: Duration,
    /// Whether to emit `Access-Control-Allow-Credentials: true`.
    pub allow_credentials: bool,
    /// Honour the Private Network Access (PNA) preflight by emitting
    /// `Access-Control-Allow-Private-Network: true` when requested. Required
    /// for browsers that target a public origin from a private/local network.
    #[serde(default)]
    pub allow_private_network: bool,
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "HEAD".into(),
        "POST".into(),
        "PUT".into(),
        "DELETE".into(),
        "PATCH".into(),
        "OPTIONS".into(),
    ]
}

fn default_allowed_headers() -> Vec<String> {
    vec![
        "accept".into(),
        "accept-language".into(),
        "authorization".into(),
        "content-language".into(),
        "content-type".into(),
        "x-requested-with".into(),
        "x-request-id".into(),
    ]
}

fn default_exposed_headers() -> Vec<String> {
    vec![
        "x-corx-status".into(),
        "x-corx-target-url".into(),
        "x-request-id".into(),
    ]
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

/// SSRF protection mode.
///
/// **Strict** is the only fail-closed posture and the only mode an operator
/// should run in production unless they have explicitly threat-modelled the
/// risk of reaching private address space. Switching to **Permissive** must
/// be a deliberate, documented decision.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum SsrfMode {
    /// Reject every IP that falls into a blocked CIDR after standardisation.
    /// Recommended default for any production deployment.
    Strict,
    /// Allow private / RFC 1918 / loopback / link-local destinations. **Only**
    /// use this for trusted-environment deployments (internal API gateways,
    /// CI runners). When `allow_private = false` the proxy still rejects
    /// loopback / link-local / IPv4-mapped IPv6 of the same.
    Permissive {
        /// When `true` the operator opts out of every default block range.
        /// When `false` only RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`,
        /// `192.168.0.0/16`) and unique-local IPv6 are admitted.
        #[serde(default)]
        allow_private: bool,
    },
}

impl SsrfMode {
    /// Returns `true` when the policy is allowed to admit private IPs.
    #[must_use]
    pub const fn admits_private(&self) -> bool {
        matches!(
            self,
            Self::Permissive {
                allow_private: true
            }
        )
    }
}

/// SSRF protection.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SsrfConfig {
    /// Operating mode. **Strict** is the production default.
    pub mode: SsrfMode,
    /// Allow DNS resolution to return IPv6 addresses.
    pub allow_ipv6: bool,
    /// Extra CIDR ranges to block, on top of the built-in defaults (RFC 1918,
    /// loopback, link-local, unique-local, multicast, reserved).
    #[serde(default)]
    pub extra_blocked_cidrs: Vec<IpNet>,
    /// CIDR ranges that override the built-in block list. Useful in `strict`
    /// mode to whitelist a single internal API gateway while keeping every
    /// other private range blocked.
    #[serde(default)]
    pub extra_allowed_cidrs: Vec<IpNet>,
    /// Apply the SSRF guard on every redirect hop, not only the initial
    /// request. When `true`, an external-to-internal redirect is rejected
    /// even if the proxy was reached over the public internet originally.
    #[serde(default = "default_true")]
    pub deny_redirect_to_private: bool,
}

const fn default_true() -> bool {
    true
}

/// Rate-limit configuration covering four orthogonal dimensions.
///
/// Each sub-limiter is independent: setting any of `origin.rps`, `ip.rps`,
/// `target_host.rps` or `global.rps` to `0` disables that dimension while
/// leaving the others active. Setting [`RateLimitConfig::enabled`] to
/// `false` disables every dimension at once.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Master switch. When `false`, every dimension below is bypassed.
    pub enabled: bool,
    /// Per-`Origin`-header limiting.
    #[serde(default)]
    pub origin: OriginLimitConfig,
    /// Per-client-IP limiting.
    #[serde(default)]
    pub ip: IpLimitConfig,
    /// Per-target-host limiting (protects upstreams from a single misbehaving
    /// caller targeting a popular destination).
    #[serde(default)]
    pub target_host: HostLimitConfig,
    /// Process-wide concurrency limiter that drives the load-shed layer.
    #[serde(default)]
    pub global: GlobalLimitConfig,
}

/// Per-`Origin` rate-limit configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginLimitConfig {
    /// Steady-state requests-per-second; `0` disables this dimension.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
    /// Regex patterns matched against the request `Origin` header. Matching
    /// origins bypass the limiter entirely.
    #[serde(default)]
    pub unlimited_patterns: Vec<String>,
}

impl Default for OriginLimitConfig {
    fn default() -> Self {
        Self {
            rps: 0,
            burst: 0,
            unlimited_patterns: Vec::new(),
        }
    }
}

/// Per-client-IP rate-limit configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpLimitConfig {
    /// Steady-state requests-per-second; `0` disables this dimension.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
    /// CIDR ranges whose source IPs are exempt from rate limiting (operator
    /// healthchecks, internal load-balancers, etc.).
    #[serde(default)]
    pub trusted_cidrs: Vec<IpNet>,
}

impl Default for IpLimitConfig {
    fn default() -> Self {
        Self {
            rps: 0,
            burst: 0,
            trusted_cidrs: Vec::new(),
        }
    }
}

/// Per-target-host rate-limit configuration.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimitConfig {
    /// Steady-state requests-per-second; `0` disables this dimension.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
}

impl Default for HostLimitConfig {
    fn default() -> Self {
        Self { rps: 0, burst: 0 }
    }
}

/// Process-wide global limits that drive the load-shed layer.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalLimitConfig {
    /// Steady-state requests-per-second across the entire proxy. `0`
    /// disables the global token bucket.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
    /// Maximum number of in-flight requests. Exceeding this triggers the
    /// load-shed layer which immediately answers `503 Service Unavailable`
    /// with a `Retry-After` header. `0` disables the load-shed layer.
    #[serde(default)]
    pub inflight_max: u32,
}

impl Default for GlobalLimitConfig {
    fn default() -> Self {
        Self {
            rps: 0,
            burst: 0,
            inflight_max: 0,
        }
    }
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
