//! SSRF protection configuration.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

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
    pub const fn admits_private(self) -> bool {
        matches!(
            self,
            Self::Permissive {
                allow_private: true
            }
        )
    }
}

/// SSRF protection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            mode: SsrfMode::Strict,
            allow_ipv6: true,
            extra_blocked_cidrs: Vec::new(),
            extra_allowed_cidrs: Vec::new(),
        }
    }
}
