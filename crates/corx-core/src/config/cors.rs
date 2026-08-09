//! CORS response-shaping policy configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// CORS policy discriminant.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CorsPolicyKind {
    /// Return `Access-Control-Allow-Origin: *`.
    Wildcard,
    /// Reflect the request `Origin`, gated by [`CorsConfig::origins`] unless
    /// [`CorsConfig::allow_any_origin`] is set.
    #[default]
    Reflect,
    /// Reflect `Origin` only if it is listed in [`CorsConfig::origins`].
    Explicit,
}

/// CORS response-shaping policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Which CORS policy to apply.
    #[serde(default)]
    pub policy: CorsPolicyKind,
    /// Origins used by `reflect` (as an allow-gate) and by `explicit`
    /// (as the exclusive list). Exact-match strings.
    #[serde(default)]
    pub origins: Vec<String>,
    /// When `policy = reflect` and `origins` is empty, echo any request
    /// `Origin` only if this flag is `true`. Default `false` (fail-closed).
    #[serde(default)]
    pub allow_any_origin: bool,
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
    /// `Access-Control-Allow-Private-Network: true` when requested.
    #[serde(default)]
    pub allow_private_network: bool,
}

fn default_allowed_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn default_allowed_headers() -> Vec<String> {
    [
        "accept",
        "accept-language",
        "authorization",
        "content-language",
        "content-type",
        "x-requested-with",
        "x-request-id",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn default_exposed_headers() -> Vec<String> {
    ["x-corx-status", "x-corx-target-url", "x-request-id"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            policy: CorsPolicyKind::Reflect,
            origins: Vec::new(),
            // Fail-closed: operators must set `allow_any_origin = true` or
            // populate `origins` for cross-origin reflection.
            allow_any_origin: false,
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            exposed_headers: default_exposed_headers(),
            max_age: Duration::from_mins(10),
            allow_credentials: false,
            allow_private_network: false,
        }
    }
}
