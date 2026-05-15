//! Multi-dimensional rate limiter (per-Origin / per-IP / per-Target-Host /
//! Global) backed by `governor`'s GCRA token bucket.
//!
//! All four dimensions are independent and can be enabled \u00e0 la carte. The
//! hot path is lock-free: keyed limiters use `dashmap`, the global limiter is
//! a single atomic. When a dimension trips, the
//! `corx_rate_limited_total{dimension}` counter is incremented before the
//! request is rejected so operators can see *which* dimension is shedding
//! load.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::QuantaClock;
use governor::state::keyed::DashMapStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovRateLimiter};
use ipnet::IpNet;
use regex::RegexSet;

use corx_core::config::{
    GlobalLimitConfig, HostLimitConfig, IpLimitConfig, OriginLimitConfig, RateLimitConfig,
};
use corx_core::error::ProxyError;
use corx_core::observability;

type KeyedLimiter<K> = GovRateLimiter<K, DashMapStateStore<K>, QuantaClock>;
type DirectLimiter = GovRateLimiter<NotKeyed, InMemoryState, QuantaClock>;

/// Inputs supplied by the inbound stack on every request.
#[derive(Debug, Clone)]
pub struct RateContext<'a> {
    /// Value of the `Origin` request header, if present.
    pub origin: Option<&'a str>,
    /// Client IP as observed by the listener.
    pub client_ip: IpAddr,
    /// Validated upstream target host.
    pub target_host: &'a str,
}

/// Compiled, four-dimensional rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    enabled: bool,
    origin: Option<OriginDimension>,
    ip: Option<IpDimension>,
    host: Option<HostDimension>,
    global: Option<DirectLimiter>,
}

struct OriginDimension {
    limiter: KeyedLimiter<String>,
    unlimited: RegexSet,
}

struct IpDimension {
    limiter: KeyedLimiter<IpAddr>,
    trusted: Vec<IpNet>,
}

struct HostDimension {
    limiter: KeyedLimiter<String>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("enabled", &self.inner.enabled)
            .field("origin_enabled", &self.inner.origin.is_some())
            .field("ip_enabled", &self.inner.ip.is_some())
            .field("target_host_enabled", &self.inner.host.is_some())
            .field("global_enabled", &self.inner.global.is_some())
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Compile every dimension declared in the configuration.
    ///
    /// # Errors
    ///
    /// Fails if any rps/burst pair is malformed, or if any regex in
    /// `origin.unlimited_patterns` cannot be compiled.
    pub fn from_config(cfg: &RateLimitConfig) -> anyhow::Result<Self> {
        if !cfg.enabled {
            return Ok(Self {
                inner: Arc::new(Inner {
                    enabled: false,
                    origin: None,
                    ip: None,
                    host: None,
                    global: None,
                }),
            });
        }

        let origin = build_origin(&cfg.origin)?;
        let ip = build_ip(&cfg.ip)?;
        let host = build_host(&cfg.target_host)?;
        let global = build_global(&cfg.global)?;

        Ok(Self {
            inner: Arc::new(Inner {
                enabled: true,
                origin,
                ip,
                host,
                global,
            }),
        })
    }

    /// Enforce every enabled dimension on the supplied request context. Each
    /// dimension is checked in turn; the *first* dimension that rejects the
    /// request short-circuits the rest so we attribute the rejection to the
    /// most specific cause.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::RateLimited`] when any dimension is exhausted.
    pub fn check(&self, ctx: &RateContext<'_>) -> Result<(), ProxyError> {
        if !self.inner.enabled {
            return Ok(());
        }

        if let Some(dim) = self.inner.origin.as_ref()
            && let Some(origin) = ctx.origin
            && !dim.unlimited.is_match(origin)
            && dim.limiter.check_key(&origin.to_owned()).is_err()
        {
            return reject("origin");
        }

        if let Some(dim) = self.inner.ip.as_ref()
            && !is_trusted(&dim.trusted, ctx.client_ip)
            && dim.limiter.check_key(&ctx.client_ip).is_err()
        {
            return reject("ip");
        }

        if let Some(dim) = self.inner.host.as_ref()
            && dim.limiter.check_key(&ctx.target_host.to_owned()).is_err()
        {
            return reject("target_host");
        }

        if let Some(global) = self.inner.global.as_ref()
            && global.check().is_err()
        {
            return reject("global");
        }

        Ok(())
    }
}

fn reject(dimension: &'static str) -> Result<(), ProxyError> {
    metrics::counter!(observability::RATE_LIMITED, "dimension" => dimension).increment(1);
    Err(ProxyError::RateLimited)
}

fn quota(rps: u32, burst: u32) -> anyhow::Result<Quota> {
    let rps = NonZeroU32::new(rps).ok_or_else(|| anyhow::anyhow!("rps must be > 0"))?;
    let burst = NonZeroU32::new(burst.max(rps.get()))
        .ok_or_else(|| anyhow::anyhow!("burst must be > 0"))?;
    Ok(Quota::per_second(rps).allow_burst(burst))
}

fn build_origin(cfg: &OriginLimitConfig) -> anyhow::Result<Option<OriginDimension>> {
    if cfg.rps == 0 {
        return Ok(None);
    }
    let q = quota(cfg.rps, cfg.burst)?;
    let limiter: KeyedLimiter<String> =
        GovRateLimiter::dashmap_with_clock(q, QuantaClock::default());
    let unlimited = RegexSet::new(&cfg.unlimited_patterns)
        .map_err(|err| anyhow::anyhow!("invalid origin.unlimited_patterns regex: {err}"))?;
    Ok(Some(OriginDimension { limiter, unlimited }))
}

fn build_ip(cfg: &IpLimitConfig) -> anyhow::Result<Option<IpDimension>> {
    if cfg.rps == 0 {
        return Ok(None);
    }
    let q = quota(cfg.rps, cfg.burst)?;
    let limiter: KeyedLimiter<IpAddr> =
        GovRateLimiter::dashmap_with_clock(q, QuantaClock::default());
    Ok(Some(IpDimension {
        limiter,
        trusted: cfg.trusted_cidrs.clone(),
    }))
}

fn build_host(cfg: &HostLimitConfig) -> anyhow::Result<Option<HostDimension>> {
    if cfg.rps == 0 {
        return Ok(None);
    }
    let q = quota(cfg.rps, cfg.burst)?;
    let limiter: KeyedLimiter<String> =
        GovRateLimiter::dashmap_with_clock(q, QuantaClock::default());
    Ok(Some(HostDimension { limiter }))
}

fn build_global(cfg: &GlobalLimitConfig) -> anyhow::Result<Option<DirectLimiter>> {
    if cfg.rps == 0 {
        return Ok(None);
    }
    let q = quota(cfg.rps, cfg.burst)?;
    Ok(Some(GovRateLimiter::direct_with_clock(
        q,
        QuantaClock::default(),
    )))
}

fn is_trusted(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use corx_core::config::{
        GlobalLimitConfig, HostLimitConfig, IpLimitConfig, OriginLimitConfig, RateLimitConfig,
    };

    use super::{RateContext, RateLimiter};

    fn cfg() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            origin: OriginLimitConfig {
                rps: 0,
                burst: 0,
                unlimited_patterns: vec![],
            },
            ip: IpLimitConfig {
                rps: 0,
                burst: 0,
                trusted_cidrs: vec![],
            },
            target_host: HostLimitConfig { rps: 0, burst: 0 },
            global: GlobalLimitConfig {
                rps: 0,
                burst: 0,
                inflight_max: 0,
            },
        }
    }

    fn ctx<'a>(origin: Option<&'a str>, ip: &'a str, host: &'a str) -> RateContext<'a> {
        RateContext {
            origin,
            client_ip: ip.parse().unwrap(),
            target_host: host,
        }
    }

    #[test]
    fn disabled_admits_everything() {
        let mut c = cfg();
        c.enabled = false;
        let lim = RateLimiter::from_config(&c).unwrap();
        for _ in 0..100 {
            assert!(lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test")).is_ok());
        }
    }

    #[test]
    fn origin_dimension_rejects_after_burst() {
        let mut c = cfg();
        c.origin.rps = 1;
        c.origin.burst = 2;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test")).is_ok());
        assert!(lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test")).is_ok());
        assert!(lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test")).is_err());
    }

    #[test]
    fn origin_unlimited_pattern_bypasses() {
        let mut c = cfg();
        c.origin.rps = 1;
        c.origin.burst = 1;
        c.origin.unlimited_patterns = vec![r"^https://whitelisted\.test$".into()];
        let lim = RateLimiter::from_config(&c).unwrap();
        for _ in 0..10 {
            assert!(
                lim.check(&ctx(Some("https://whitelisted.test"), "1.2.3.4", "x.test"))
                    .is_ok()
            );
        }
    }

    #[test]
    fn ip_dimension_independent_of_origin() {
        let mut c = cfg();
        c.ip.rps = 1;
        c.ip.burst = 1;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(None, "1.2.3.4", "x.test")).is_ok());
        assert!(lim.check(&ctx(None, "1.2.3.4", "x.test")).is_err());
        // Different IP has its own bucket.
        assert!(lim.check(&ctx(None, "1.2.3.5", "x.test")).is_ok());
    }

    #[test]
    fn ip_trusted_cidr_bypasses() {
        let mut c = cfg();
        c.ip.rps = 1;
        c.ip.burst = 1;
        c.ip.trusted_cidrs = vec![ipnet::IpNet::from_str("10.0.0.0/8").unwrap()];
        let lim = RateLimiter::from_config(&c).unwrap();
        for _ in 0..10 {
            assert!(lim.check(&ctx(None, "10.1.2.3", "x.test")).is_ok());
        }
    }

    #[test]
    fn target_host_dimension_buckets_per_host() {
        let mut c = cfg();
        c.target_host.rps = 1;
        c.target_host.burst = 1;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(None, "1.1.1.1", "popular.test")).is_ok());
        assert!(lim.check(&ctx(None, "2.2.2.2", "popular.test")).is_err());
        // Different upstream uses an independent bucket.
        assert!(lim.check(&ctx(None, "3.3.3.3", "rare.test")).is_ok());
    }

    #[test]
    fn global_dimension_caps_total_throughput() {
        let mut c = cfg();
        c.global.rps = 1;
        c.global.burst = 1;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(None, "1.1.1.1", "a.test")).is_ok());
        assert!(lim.check(&ctx(None, "9.9.9.9", "z.test")).is_err());
    }

    #[test]
    fn first_failing_dimension_wins() {
        let mut c = cfg();
        // Origin is the most specific; an over-quota origin must not consume
        // a token from the more permissive dimensions below.
        c.origin.rps = 1;
        c.origin.burst = 1;
        c.global.rps = 1_000;
        c.global.burst = 1_000;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(Some("o"), "1.1.1.1", "a.test")).is_ok());
        assert!(lim.check(&ctx(Some("o"), "1.1.1.1", "a.test")).is_err());
    }
}
