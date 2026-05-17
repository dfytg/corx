//! Inbound request guards: origin lists, blocked methods, required headers.

use serde::{Deserialize, Serialize};

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

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_header: vec!["origin".into()],
            block_methods: vec!["CONNECT".into(), "TRACE".into()],
            remove_request_headers: vec!["cookie".into(), "cookie2".into()],
            remove_response_headers: vec!["set-cookie".into(), "set-cookie2".into()],
            origin_blacklist: Vec::new(),
            origin_whitelist: Vec::new(),
        }
    }
}
