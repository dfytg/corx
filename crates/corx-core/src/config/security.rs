//! Inbound request guards: origin lists, blocked methods, required headers,
//! preflight gating, and optional bearer authentication.

use serde::{Deserialize, Serialize};

use super::default_true;

/// How CORS preflight (`OPTIONS`) requests are gated.
///
/// * [`Enforce`](PreflightMode::Enforce) — preflights run the same origin
///   (and optionally rate-limit) guards as normal requests. **Default.**
/// * [`Open`](PreflightMode::Open) — preflights short-circuit before guards,
///   matching classic cors-anywhere behaviour. Opt-in only.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PreflightMode {
    /// Apply origin / method / required-header guards (and optional rate limit).
    #[default]
    Enforce,
    /// Skip inbound guards; answer 204 immediately.
    Open,
}

/// Preflight-specific security knobs.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreflightConfig {
    /// Guard mode for `OPTIONS` preflights.
    #[serde(default)]
    pub mode: PreflightMode,
    /// When `mode = enforce`, also charge the multi-dimensional rate limiter.
    /// Host dimension is applied only when the path yields a parseable target.
    #[serde(default = "default_true")]
    pub rate_limit: bool,
}

impl Default for PreflightConfig {
    fn default() -> Self {
        Self {
            mode: PreflightMode::Enforce,
            rate_limit: true,
        }
    }
}

/// Client authentication mode for proxy traffic (ops routes remain open).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No shared-secret check (default).
    #[default]
    None,
    /// Require `Authorization: Bearer <token>` matching one of the configured tokens.
    Bearer,
}

/// Optional shared-secret authentication.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication mode.
    #[serde(default)]
    pub mode: AuthMode,
    /// Accepted bearer tokens (constant-time compared). Never log these.
    #[serde(default)]
    pub bearer_tokens: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::None,
            bearer_tokens: Vec::new(),
        }
    }
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
    /// CORS preflight gating (default: enforce origin + rate limit).
    #[serde(default)]
    pub preflight: PreflightConfig,
    /// Optional bearer-token authentication for proxy traffic.
    #[serde(default)]
    pub auth: AuthConfig,
    /// When `true`, startup fails unless at least one of: non-empty origin
    /// whitelist, bearer auth, or mTLS (TLS client CA) is configured.
    #[serde(default)]
    pub require_client_binding: bool,
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
            preflight: PreflightConfig::default(),
            auth: AuthConfig::default(),
            require_client_binding: false,
        }
    }
}
