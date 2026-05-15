//! SSRF protection (v2).
//!
//! DNS resolution is performed inside the proxy using [`hickory_resolver`],
//! giving the operator fine-grained control over address policy. Every
//! resolved IP is:
//!
//! 1. **Standardised** — IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is folded back to
//!    its IPv4 representation, so `::ffff:127.0.0.1` cannot bypass
//!    `127.0.0.0/8`.
//! 2. **Validated** against a curated list of RFC-reserved ranges, the
//!    operator's `extra_blocked_cidrs`, and an `extra_allowed_cidrs` override
//!    list that can punch deliberate holes for internal API gateways.
//! 3. **Recorded** — a `corx_ssrf_blocks_total{cidr}` counter is incremented
//!    on every interception, keyed by the matching CIDR (a finite, low-
//!    cardinality set safe for Prometheus).
//!
//! This guard is deliberately placed *before* the hyper connector to make
//! bypass impossible: `HttpConnector` never sees a hostname, it is handed a
//! pre-validated [`SocketAddr`]. To support hyper happy-eyeballs the
//! resolver returns *every* admissible address from a single DNS lookup, so
//! IPv6/IPv4 fallback works naturally.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use ipnet::IpNet;

use crate::config::{SsrfConfig, SsrfMode};
use crate::error::ProxyError;
use crate::observability;

/// The list of IP ranges that should never be reachable via the proxy unless
/// the operator explicitly opts-in via [`SsrfMode::Permissive`] or punches a
/// hole through `extra_allowed_cidrs`.
///
/// Rationale for each range is intentionally explicit; do not remove entries
/// without threat-modelling the impact on the deployment environment.
const DEFAULT_BLOCKED_CIDRS: &[&str] = &[
    // --- IPv4 -----------------------------------------------------------
    "0.0.0.0/8",          // "this network" (RFC 1122)
    "10.0.0.0/8",         // RFC 1918 private
    "100.64.0.0/10",      // Carrier-grade NAT (RFC 6598)
    "127.0.0.0/8",        // Loopback (RFC 1122)
    "169.254.0.0/16",     // Link-local incl. AWS / Azure / GCP metadata (RFC 3927)
    "172.16.0.0/12",      // RFC 1918 private
    "192.0.0.0/24",       // IETF protocol assignments (RFC 6890)
    "192.0.2.0/24",       // TEST-NET-1 (RFC 5737)
    "192.168.0.0/16",     // RFC 1918 private
    "198.18.0.0/15",      // Benchmarking (RFC 2544)
    "198.51.100.0/24",    // TEST-NET-2 (RFC 5737)
    "203.0.113.0/24",     // TEST-NET-3 (RFC 5737)
    "224.0.0.0/4",        // Multicast (RFC 5771)
    "240.0.0.0/4",        // Reserved future use (RFC 1112)
    "255.255.255.255/32", // Limited broadcast
    // --- IPv6 -----------------------------------------------------------
    "::/128",        // Unspecified (RFC 4291)
    "::1/128",       // Loopback (RFC 4291)
    "::ffff:0:0/96", // IPv4-mapped — redundant after canonicalisation but kept
    // for defence in depth.
    "64:ff9b::/96",   // IPv4/IPv6 translation (RFC 6052)
    "64:ff9b:1::/48", // Local IPv4/IPv6 translation (RFC 8215)
    "100::/64",       // Discard prefix (RFC 6666)
    "2001:db8::/32",  // Documentation (RFC 3849)
    "2002::/16",      // 6to4 (largely deprecated, kept fail-closed)
    "fc00::/7",       // Unique local (RFC 4193)
    "fe80::/10",      // Link-local (RFC 4291)
    "ff00::/8",       // Multicast (RFC 4291)
];

/// CIDR ranges that, when admitted, indicate the address is private. Used
/// when [`SsrfMode::Permissive`] is selected with `allow_private = false`.
const PRIVATE_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Compiled SSRF guard.
#[derive(Clone)]
pub struct SsrfGuard {
    mode: SsrfMode,
    allow_ipv6: bool,
    blocked: Arc<[IpNet]>,
    allowed: Arc<[IpNet]>,
    private: Arc<[IpNet]>,
    resolver: TokioAsyncResolver,
}

impl std::fmt::Debug for SsrfGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsrfGuard")
            .field("mode", &self.mode)
            .field("allow_ipv6", &self.allow_ipv6)
            .field("blocked_count", &self.blocked.len())
            .field("allowed_count", &self.allowed.len())
            .finish_non_exhaustive()
    }
}

impl SsrfGuard {
    /// Creates a new guard backed by the supplied resolver and configuration.
    #[must_use]
    pub fn new(cfg: &SsrfConfig, resolver: TokioAsyncResolver) -> Self {
        let blocked = compile_cidr_list(DEFAULT_BLOCKED_CIDRS, &cfg.extra_blocked_cidrs);
        let allowed = compile_cidr_list(&[], &cfg.extra_allowed_cidrs);
        let private = compile_cidr_list(PRIVATE_RANGES, &[]);
        Self {
            mode: cfg.mode,
            allow_ipv6: cfg.allow_ipv6,
            blocked: Arc::from(blocked),
            allowed: Arc::from(allowed),
            private: Arc::from(private),
            resolver,
        }
    }

    /// Standardises an IP into its canonical form. IPv4-mapped IPv6 addresses
    /// are folded back to plain IPv4 so that policy checks compare the same
    /// underlying value regardless of how the upstream announced it.
    #[must_use]
    pub fn canonicalise(addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V6(v6) => {
                let canonical = v6.to_canonical();
                IpAddr::from(canonical)
            }
            IpAddr::V4(_) => addr,
        }
    }

    /// Resolves `host` and returns *every* address admissible by policy.
    ///
    /// Returning multiple addresses lets the caller (typically the hyper
    /// connector) perform happy-eyeballs IPv4/IPv6 fallback. The returned
    /// vector is never empty: an error surfaces instead.
    ///
    /// # Errors
    ///
    /// Returns an error if DNS resolution fails, or when every resolved IP
    /// is blocked by policy.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        // Accept bare IP literals without consulting DNS.
        if let Ok(ip) = host.parse::<IpAddr>() {
            metrics::counter!(observability::DNS_LOOKUPS, "result" => "literal").increment(1);
            let canonical = self.check_ip(ip)?;
            return Ok(vec![SocketAddr::new(canonical, port)]);
        }

        let lookup = match self.resolver.lookup_ip(host).await {
            Ok(lookup) => {
                metrics::counter!(observability::DNS_LOOKUPS, "result" => "ok").increment(1);
                lookup
            }
            Err(err) => {
                metrics::counter!(observability::DNS_LOOKUPS, "result" => "error").increment(1);
                return Err(ProxyError::Dns {
                    host: host.to_owned(),
                    source: Box::new(err),
                });
            }
        };

        let mut admissible: Vec<SocketAddr> = Vec::new();
        let mut last_violation: Option<ProxyError> = None;

        for raw in lookup.iter() {
            let canonical = Self::canonicalise(raw);
            if !self.allow_ipv6 && canonical.is_ipv6() {
                continue;
            }
            match self.evaluate(canonical) {
                Ok(()) => admissible.push(SocketAddr::new(canonical, port)),
                Err(err) => last_violation = Some(err),
            }
        }

        if !admissible.is_empty() {
            return Ok(admissible);
        }

        Err(last_violation.unwrap_or_else(|| ProxyError::Dns {
            host: host.to_owned(),
            source: "no usable address returned by resolver".into(),
        }))
    }

    /// Validates a literal IP address. Returns the standardised form so the
    /// caller can use it consistently downstream.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::SsrfBlocked`] when the IP is blocked.
    pub fn check_ip(&self, raw: IpAddr) -> Result<IpAddr, ProxyError> {
        let canonical = Self::canonicalise(raw);
        if !self.allow_ipv6 && canonical.is_ipv6() {
            return Err(ProxyError::SsrfBlocked(canonical));
        }
        self.evaluate(canonical)?;
        Ok(canonical)
    }

    fn evaluate(&self, ip: IpAddr) -> Result<(), ProxyError> {
        // Allowlist always wins to support deliberate carve-outs.
        if self.allowed.iter().any(|net| net.contains(&ip)) {
            return Ok(());
        }

        match self.mode {
            SsrfMode::Strict => {
                if let Some(net) = self.blocked.iter().find(|net| net.contains(&ip)) {
                    record_block(net);
                    return Err(ProxyError::SsrfBlocked(ip));
                }
                Ok(())
            }
            SsrfMode::Permissive { allow_private } => {
                if allow_private {
                    return Ok(());
                }
                if let Some(net) = self.private.iter().find(|net| net.contains(&ip)) {
                    record_block(net);
                    return Err(ProxyError::SsrfBlocked(ip));
                }
                Ok(())
            }
        }
    }
}

fn record_block(net: &IpNet) {
    let cidr = net.to_string();
    metrics::counter!(observability::SSRF_BLOCKS, "cidr" => cidr).increment(1);
}

fn compile_cidr_list(builtin: &[&str], extras: &[IpNet]) -> Vec<IpNet> {
    let mut list = Vec::with_capacity(builtin.len() + extras.len());
    for raw in builtin {
        if let Ok(net) = raw.parse::<IpNet>() {
            list.push(net);
        } else {
            tracing::warn!(cidr = raw, "hard-coded SSRF CIDR failed to parse");
        }
    }
    list.extend(extras.iter().copied());
    list
}

/// Builds the default async DNS resolver used by the proxy.
///
/// Tries the system resolver configuration first and falls back to Google
/// Public DNS when it cannot be loaded (useful in container environments
/// with no `/etc/resolv.conf`).
#[must_use]
pub fn build_resolver() -> TokioAsyncResolver {
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, opts)) => TokioAsyncResolver::tokio(config, opts),
        Err(_) => TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr as _;

    use ipnet::IpNet;

    use super::{DEFAULT_BLOCKED_CIDRS, SsrfGuard, SsrfMode, compile_cidr_list};
    use crate::config::SsrfConfig;

    fn guard(mode: SsrfMode, extras_block: Vec<IpNet>, extras_allow: Vec<IpNet>) -> SsrfGuard {
        let cfg = SsrfConfig {
            mode,
            allow_ipv6: true,
            extra_blocked_cidrs: extras_block,
            extra_allowed_cidrs: extras_allow,
            deny_redirect_to_private: true,
        };
        let resolver = super::build_resolver();
        SsrfGuard::new(&cfg, resolver)
    }

    #[test]
    fn default_list_blocks_loopback() {
        let list = compile_cidr_list(DEFAULT_BLOCKED_CIDRS, &[]);
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(list.iter().any(|net| net.contains(&loopback)));
    }

    #[test]
    fn default_list_blocks_ipv6_loopback() {
        let list = compile_cidr_list(DEFAULT_BLOCKED_CIDRS, &[]);
        let loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(list.iter().any(|net| net.contains(&loopback)));
    }

    #[test]
    fn default_list_blocks_link_local() {
        let list = compile_cidr_list(DEFAULT_BLOCKED_CIDRS, &[]);
        let aws_metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert!(list.iter().any(|net| net.contains(&aws_metadata)));
    }

    #[test]
    fn public_ip_is_not_blocked() {
        let list = compile_cidr_list(DEFAULT_BLOCKED_CIDRS, &[]);
        let public = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert!(!list.iter().any(|net| net.contains(&public)));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_canonicalised() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let canonical = SsrfGuard::canonicalise(mapped);
        assert_eq!(canonical, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn strict_mode_rejects_loopback() {
        let g = guard(SsrfMode::Strict, vec![], vec![]);
        assert!(g.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err());
    }

    #[test]
    fn strict_mode_rejects_ipv4_mapped_loopback() {
        let g = guard(SsrfMode::Strict, vec![], vec![]);
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(g.check_ip(mapped).is_err());
    }

    #[test]
    fn permissive_allow_private_admits_loopback() {
        let g = guard(
            SsrfMode::Permissive {
                allow_private: true,
            },
            vec![],
            vec![],
        );
        assert!(g.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    }

    #[test]
    fn permissive_no_private_still_rejects_loopback() {
        let g = guard(
            SsrfMode::Permissive {
                allow_private: false,
            },
            vec![],
            vec![],
        );
        assert!(g.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err());
    }

    #[test]
    fn allowlist_overrides_default_block() {
        let net = IpNet::from_str("10.0.0.0/24").unwrap();
        let g = guard(SsrfMode::Strict, vec![], vec![net]);
        assert!(g.check_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))).is_ok());
        assert!(
            g.check_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))).is_err(),
            "only the carved-out range should be admitted"
        );
    }

    #[test]
    fn extra_block_extends_default() {
        let net = IpNet::from_str("203.0.113.0/24").unwrap();
        let g = guard(SsrfMode::Strict, vec![net], vec![]);
        assert!(
            g.check_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
                .is_err()
        );
    }
}
