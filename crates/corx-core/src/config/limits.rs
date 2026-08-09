//! Size- and time-based limits applied to every request.

use std::time::Duration;

use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;

/// How upstream 3xx responses are handled.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RedirectPolicy {
    /// Follow redirects in-proxy (up to [`LimitsConfig::max_redirects`]),
    /// re-validating SSRF on every hop. **Default.**
    #[default]
    Follow,
    /// Do not follow; surface a proxy error instead of leaking Location.
    Block,
    /// Return the 3xx to the client with `Location` rewritten to the proxy
    /// path-prefix form (cors-anywhere style). Does not follow.
    Rewrite,
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
    /// Maximum number of redirects followed per request (`follow` policy).
    pub max_redirects: u8,
    /// Allow `https → http` redirect downgrades. Defaults to `false`.
    #[serde(default)]
    pub allow_https_to_http_downgrade: bool,
    /// Redirect handling policy.
    #[serde(default)]
    pub redirect_policy: RedirectPolicy,
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
            redirect_policy: RedirectPolicy::Follow,
        }
    }
}
