//! Per-host circuit breaker configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::default_true;

/// Process-local per-upstream-host circuit breaker.
///
/// State is not shared across replicas; pair with external rate limiting when
/// multi-instance consistency is required.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Master switch. Default: enabled with conservative thresholds.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Consecutive failures in the rolling window that trip `Open`.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Rolling window used to count failures toward the threshold.
    #[serde(default = "default_window", with = "humantime_serde")]
    pub window: Duration,
    /// How long the breaker stays `Open` before `HalfOpen` probes.
    #[serde(default = "default_open_duration", with = "humantime_serde")]
    pub open_duration: Duration,
    /// Concurrent `HalfOpen` probe budget per host.
    #[serde(default = "default_half_open_max")]
    pub half_open_max: u32,
    /// Count upstream HTTP 5xx as failures (in addition to connect/timeout).
    #[serde(default = "default_true")]
    pub count_5xx: bool,
    /// Soft cap on tracked host keys. Idle closed entries are evicted when
    /// the map exceeds this size (cardinality / abuse defence).
    #[serde(default = "default_max_hosts")]
    pub max_hosts: usize,
}

const fn default_failure_threshold() -> u32 {
    5
}

const fn default_half_open_max() -> u32 {
    1
}

const fn default_window() -> Duration {
    Duration::from_secs(30)
}

const fn default_open_duration() -> Duration {
    Duration::from_secs(30)
}

const fn default_max_hosts() -> usize {
    8192
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: default_failure_threshold(),
            window: default_window(),
            open_duration: default_open_duration(),
            half_open_max: default_half_open_max(),
            count_5xx: true,
            max_hosts: default_max_hosts(),
        }
    }
}
