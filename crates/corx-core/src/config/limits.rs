//! Size- and time-based limits applied to every request.

use std::time::Duration;

use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;

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

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 10 * MIB,
            max_request_header_bytes: 32 * 1024,
            request_timeout: Duration::from_mins(1),
            connect_timeout: Duration::from_secs(10),
            max_redirects: 5,
            allow_https_to_http_downgrade: false,
        }
    }
}
