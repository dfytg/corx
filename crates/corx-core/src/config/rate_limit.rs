//! Multi-dimensional rate-limit configuration.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::default_true;

/// Rate-limit configuration covering four orthogonal GCRA dimensions.
///
/// Each sub-limiter is independent: setting any of `origin.rps`, `ip.rps`,
/// `target_host.rps` or `global.rps` to `0` disables that dimension while
/// leaving the others active. Setting [`RateLimitConfig::enabled`] to
/// `false` disables every GCRA dimension at once.
///
/// Process-wide **inflight** concurrency is configured under
/// [`crate::config::LimitsConfig::inflight_max`], not here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Master switch for GCRA dimensions. Default: enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Soft cap on distinct keys per keyed dimension (origin / ip / host).
    /// New keys are rejected with 429 when the map is full.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
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
    /// Process-wide GCRA token bucket.
    #[serde(default)]
    pub global: GlobalLimitConfig,
}

const fn default_max_keys() -> usize {
    16_384
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_keys: default_max_keys(),
            origin: OriginLimitConfig {
                rps: 50,
                burst: 100,
                unlimited_patterns: Vec::new(),
            },
            ip: IpLimitConfig {
                rps: 30,
                burst: 60,
                trusted_cidrs: Vec::new(),
            },
            target_host: HostLimitConfig {
                rps: 100,
                burst: 200,
            },
            global: GlobalLimitConfig {
                rps: 5_000,
                burst: 10_000,
            },
        }
    }
}

/// Per-`Origin` rate-limit configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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

/// Per-client-IP rate-limit configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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

/// Per-target-host rate-limit configuration.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostLimitConfig {
    /// Steady-state requests-per-second; `0` disables this dimension.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
}

/// Process-wide GCRA token bucket (not inflight concurrency).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GlobalLimitConfig {
    /// Steady-state requests-per-second across the entire proxy. `0`
    /// disables the global token bucket.
    #[serde(default)]
    pub rps: u32,
    /// Token-bucket burst budget on top of `rps`.
    #[serde(default)]
    pub burst: u32,
}
