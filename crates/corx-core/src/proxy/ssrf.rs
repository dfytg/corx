//! SSRF protection.
//!
//! DNS resolution is performed inside the proxy using [`hickory_resolver`],
//! giving the operator fine-grained control over address policy. Every
//! resolved IP is validated against a compile-time list of RFC-reserved
//! ranges plus any operator-defined CIDRs before an upstream connection is
//! attempted.
//!
//! This guard is deliberately placed *before* the hyper connector to make
//! bypass impossible: `HttpConnector` never sees a hostname, it is handed a
//! pre-validated [`SocketAddr`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use ipnet::IpNet;

use crate::config::SsrfConfig;
use crate::error::ProxyError;

/// The list of IP ranges that should never be reachable via the proxy unless
/// the operator explicitly opts-in by disabling SSRF protection.
///
/// Rationale for each range is intentionally explicit; do not remove entries
/// without threat-modelling the impact on the deployment environment.
const DEFAULT_BLOCKED_CIDRS: &[&str] = &[
    // --- IPv4 -----------------------------------------------------------
    "0.0.0.0/8",          // "this network"
    "10.0.0.0/8",         // RFC 1918 private
    "100.64.0.0/10",      // Carrier-grade NAT
    "127.0.0.0/8",        // Loopback
    "169.254.0.0/16",     // Link-local (AWS metadata etc.)
    "172.16.0.0/12",      // RFC 1918 private
    "192.0.0.0/24",       // IETF protocol assignments
    "192.0.2.0/24",       // TEST-NET-1
    "192.168.0.0/16",     // RFC 1918 private
    "198.18.0.0/15",      // Benchmarking
    "198.51.100.0/24",    // TEST-NET-2
    "203.0.113.0/24",     // TEST-NET-3
    "224.0.0.0/4",        // Multicast
    "240.0.0.0/4",        // Reserved
    "255.255.255.255/32", // Broadcast
    // --- IPv6 -----------------------------------------------------------
    "::/128",        // Unspecified
    "::1/128",       // Loopback
    "::ffff:0:0/96", // IPv4-mapped
    "64:ff9b::/96",  // IPv4/IPv6 translation
    "100::/64",      // Discard
    "fc00::/7",      // Unique local
    "fe80::/10",     // Link-local
    "ff00::/8",      // Multicast
];

/// Compiled SSRF guard.
#[derive(Clone)]
pub struct SsrfGuard {
    enabled: bool,
    allow_ipv6: bool,
    blocked: Arc<[IpNet]>,
    resolver: TokioAsyncResolver,
}

impl std::fmt::Debug for SsrfGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsrfGuard")
            .field("enabled", &self.enabled)
            .field("allow_ipv6", &self.allow_ipv6)
            .field("blocked_count", &self.blocked.len())
            .finish_non_exhaustive()
    }
}

impl SsrfGuard {
    /// Creates a new guard backed by the supplied resolver and configuration.
    #[must_use]
    pub fn new(cfg: &SsrfConfig, resolver: TokioAsyncResolver) -> Self {
        let blocked = compile_cidr_list(&cfg.extra_blocked_cidrs);
        Self {
            enabled: cfg.enabled,
            allow_ipv6: cfg.allow_ipv6,
            blocked: Arc::from(blocked),
            resolver,
        }
    }

    /// Resolves `host` and returns the first address that passes the policy.
    ///
    /// # Errors
    ///
    /// Returns an error if DNS resolution fails, or when every resolved IP is
    /// blocked by policy.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ProxyError> {
        // Accept bare IP literals without consulting DNS.
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.check_ip(ip)?;
            return Ok(SocketAddr::new(ip, port));
        }

        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|err| ProxyError::Dns {
                host: host.to_owned(),
                source: Box::new(err),
            })?;

        for ip in lookup.iter() {
            if !self.allow_ipv6 && ip.is_ipv6() {
                continue;
            }
            if self.is_blocked(ip) {
                if self.enabled {
                    return Err(ProxyError::SsrfBlocked(ip));
                }
                continue;
            }
            return Ok(SocketAddr::new(ip, port));
        }

        Err(ProxyError::Dns {
            host: host.to_owned(),
            source: "no usable address returned by resolver".into(),
        })
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), ProxyError> {
        if !self.enabled {
            return Ok(());
        }
        if self.is_blocked(ip) {
            Err(ProxyError::SsrfBlocked(ip))
        } else {
            Ok(())
        }
    }

    fn is_blocked(&self, ip: IpAddr) -> bool {
        self.blocked.iter().any(|net| net.contains(&ip))
    }
}

fn compile_cidr_list(extras: &[IpNet]) -> Vec<IpNet> {
    let mut list = Vec::with_capacity(DEFAULT_BLOCKED_CIDRS.len() + extras.len());
    for raw in DEFAULT_BLOCKED_CIDRS {
        if let Ok(net) = raw.parse::<IpNet>() {
            list.push(net);
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

    use super::compile_cidr_list;

    #[test]
    fn default_list_blocks_loopback() {
        let list = compile_cidr_list(&[]);
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(list.iter().any(|net| net.contains(&loopback)));
    }

    #[test]
    fn default_list_blocks_ipv6_loopback() {
        let list = compile_cidr_list(&[]);
        let loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(list.iter().any(|net| net.contains(&loopback)));
    }

    #[test]
    fn default_list_blocks_link_local() {
        let list = compile_cidr_list(&[]);
        let aws_metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert!(list.iter().any(|net| net.contains(&aws_metadata)));
    }

    #[test]
    fn public_ip_is_not_blocked() {
        let list = compile_cidr_list(&[]);
        let public = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert!(!list.iter().any(|net| net.contains(&public)));
    }
}
