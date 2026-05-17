//! Upstream HTTP client tuning configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

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

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 32,
            pool_idle_timeout: Duration::from_secs(90),
            user_agent: format!("corx/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}
