//! Upstream target host / scheme admission policy.

use serde::{Deserialize, Serialize};

/// How host names are filtered before SSRF / DNS.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetMode {
    /// Any host is admitted; SSRF still applies to resolved addresses.
    #[default]
    AnyPublic,
    /// Only hosts matching [`TargetConfig::hosts`] are admitted.
    Allowlist,
    /// Hosts matching [`TargetConfig::hosts`] are rejected; all others admitted.
    Denylist,
}

/// Target URL admission (host + scheme) applied after path extraction and
/// before rate limiting / upstream connect.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Host admission mode.
    #[serde(default)]
    pub mode: TargetMode,
    /// Host patterns. Exact match (`api.example.com`) or DNS suffix
    /// (`.example.com` matches `a.example.com` and `example.com`).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Allowed URI schemes (lowercase). Empty falls back to `http` + `https`.
    #[serde(default = "default_schemes")]
    pub schemes: Vec<String>,
    /// When `true`, reject non-`https` targets regardless of `schemes`.
    #[serde(default)]
    pub https_only: bool,
}

fn default_schemes() -> Vec<String> {
    vec!["https".into(), "http".into()]
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            mode: TargetMode::AnyPublic,
            hosts: Vec::new(),
            schemes: default_schemes(),
            https_only: false,
        }
    }
}
