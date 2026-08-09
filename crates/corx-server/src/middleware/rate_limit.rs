//! Multi-dimensional rate limiter (per-Origin / per-IP / per-Target-Host /
//! Global) backed by `governor`'s GCRA token bucket.
//!
//! All four dimensions are independent and can be enabled à la carte. The
//! hot path is lock-free: keyed limiters use `dashmap`, the global limiter is
//! a single atomic. When a dimension trips, the
//! `corx_rate_limited_total{dimension}` counter is incremented before the
//! request is rejected so operators can see *which* dimension is shedding
//! load.
//!
//! Keyed dimensions enforce [`RateLimitConfig::max_keys`]: when the key
//! registry is full, unknown keys are rejected fail-closed rather than
//! growing without bound.

use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use corx_core::config::{
    GlobalLimitConfig, HostLimitConfig, IpLimitConfig, OriginLimitConfig, RateLimitConfig,
};
use corx_core::error::ProxyError;
use corx_core::observability;
use dashmap::DashMap;
use foldhash::fast::RandomState;
use governor::clock::QuantaClock;
use governor::state::keyed::DashMapStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovRateLimiter};
use ipnet::IpNet;
use regex::RegexSet;

type KeyedLimiter<K> = GovRateLimiter<K, DashMapStateStore<K>, QuantaClock>;
type DirectLimiter = GovRateLimiter<NotKeyed, InMemoryState, QuantaClock>;

/// Inputs supplied by the inbound stack on every request.
#[derive(Debug, Clone)]
pub struct RateContext<'a> {
    /// Value of the `Origin` request header, if present.
    pub origin: Option<&'a str>,
    /// Client IP as observed by the listener.
    pub client_ip: IpAddr,
    /// Validated upstream target host. `None` skips the host dimension
    /// (used for preflights whose path is not a parseable target URL).
    pub target_host: Option<&'a str>,
}

/// Compiled, four-dimensional rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    enabled: bool,
    max_keys: usize,
    origin: Option<OriginDimension>,
    ip: Option<IpDimension>,
    host: Option<HostDimension>,
    global: Option<DirectLimiter>,
}

struct OriginDimension {
    limiter: KeyedLimiter<String>,
    keys: DashMap<String, (), RandomState>,
    unlimited: RegexSet,
}

struct IpDimension {
    limiter: KeyedLimiter<IpAddr>,
    keys: DashMap<IpAddr, (), RandomState>,
    trusted: Vec<IpNet>,
}

struct HostDimension {
    limiter: KeyedLimiter<String>,
    keys: DashMap<String, (), RandomState>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("enabled", &self.inner.enabled)
            .field("max_keys", &self.inner.max_keys)
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
                    max_keys: cfg.max_keys.max(1),
                    origin: None,
                    ip: None,
                    host: None,
                    global: None,
                }),
            });
        }

        let origin = build_origin(&cfg.origin)?;
        let ip = build_ip(&cfg.ip)?;
        let host = build_host(cfg.target_host)?;
        let global = build_global(cfg.global)?;

        Ok(Self {
            inner: Arc::new(Inner {
                enabled: true,
                max_keys: cfg.max_keys.max(1),
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
    /// Returns [`ProxyError::RateLimited`] when any dimension is exhausted
    /// or when a keyed store is full and the key is new.
    pub fn check(&self, ctx: &RateContext<'_>) -> Result<(), ProxyError> {
        if !self.inner.enabled {
            return Ok(());
        }

        let max_keys = self.inner.max_keys;

        if let Some(dim) = self.inner.origin.as_ref()
            && let Some(origin) = ctx.origin
            && !dim.unlimited.is_match(origin)
        {
            admit_and_check_str(&dim.limiter, &dim.keys, origin, max_keys, "origin")?;
        }

        if let Some(dim) = self.inner.ip.as_ref()
            && !is_trusted(&dim.trusted, ctx.client_ip)
        {
            admit_and_check(&dim.limiter, &dim.keys, &ctx.client_ip, max_keys, "ip")?;
        }

        if let Some(dim) = self.inner.host.as_ref()
            && let Some(host) = ctx.target_host
        {
            admit_and_check_str(&dim.limiter, &dim.keys, host, max_keys, "target_host")?;
        }

        if let Some(global) = self.inner.global.as_ref()
            && global.check().is_err()
        {
            return reject("global");
        }

        Ok(())
    }
}

fn admit_and_check_str(
    limiter: &KeyedLimiter<String>,
    keys: &DashMap<String, (), RandomState>,
    key: &str,
    max_keys: usize,
    dimension: &'static str,
) -> Result<(), ProxyError> {
    let owned = key.to_owned();
    admit_key(keys, &owned, max_keys, dimension)?;
    if limiter.check_key(&owned).is_err() {
        return reject(dimension);
    }
    Ok(())
}

fn admit_and_check<K>(
    limiter: &KeyedLimiter<K>,
    keys: &DashMap<K, (), RandomState>,
    key: &K,
    max_keys: usize,
    dimension: &'static str,
) -> Result<(), ProxyError>
where
    K: Clone + Eq + Hash,
{
    admit_key(keys, key, max_keys, dimension)?;
    if limiter.check_key(key).is_err() {
        return reject(dimension);
    }
    Ok(())
}

/// Register a new key if needed. On concurrent overshoot past `max_keys`,
/// remove the insertion and reject (fail-closed).
fn admit_key<K>(
    keys: &DashMap<K, (), RandomState>,
    key: &K,
    max_keys: usize,
    dimension: &'static str,
) -> Result<(), ProxyError>
where
    K: Clone + Eq + Hash,
{
    if keys.contains_key(key) {
        return Ok(());
    }
    if keys.len() >= max_keys {
        return reject(dimension);
    }
    keys.insert(key.clone(), ());
    if keys.len() > max_keys {
        keys.remove(key);
        return reject(dimension);
    }
    Ok(())
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

fn empty_key_map<K: Eq + Hash>() -> DashMap<K, (), RandomState> {
    DashMap::with_hasher(RandomState::default())
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
    Ok(Some(OriginDimension {
        limiter,
        keys: empty_key_map(),
        unlimited,
    }))
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
        keys: empty_key_map(),
        trusted: cfg.trusted_cidrs.clone(),
    }))
}

fn build_host(cfg: HostLimitConfig) -> anyhow::Result<Option<HostDimension>> {
    if cfg.rps == 0 {
        return Ok(None);
    }
    let q = quota(cfg.rps, cfg.burst)?;
    let limiter: KeyedLimiter<String> =
        GovRateLimiter::dashmap_with_clock(q, QuantaClock::default());
    Ok(Some(HostDimension {
        limiter,
        keys: empty_key_map(),
    }))
}

fn build_global(cfg: GlobalLimitConfig) -> anyhow::Result<Option<DirectLimiter>> {
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
            max_keys: 16_384,
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
            global: GlobalLimitConfig { rps: 0, burst: 0 },
        }
    }

    fn ctx<'a>(origin: Option<&'a str>, ip: &'a str, host: &'a str) -> RateContext<'a> {
        RateContext {
            origin,
            client_ip: ip.parse().unwrap(),
            target_host: Some(host),
        }
    }

    #[test]
    fn disabled_admits_everything() {
        let mut c = cfg();
        c.enabled = false;
        let lim = RateLimiter::from_config(&c).unwrap();
        for _ in 0..100 {
            assert!(
                lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test"))
                    .is_ok()
            );
        }
    }

    #[test]
    fn origin_dimension_rejects_after_burst() {
        let mut c = cfg();
        c.origin.rps = 1;
        c.origin.burst = 2;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(
            lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test"))
                .is_ok()
        );
        assert!(
            lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test"))
                .is_ok()
        );
        assert!(
            lim.check(&ctx(Some("https://a.test"), "1.2.3.4", "x.test"))
                .is_err()
        );
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
        c.origin.rps = 1;
        c.origin.burst = 1;
        c.global.rps = 1_000;
        c.global.burst = 1_000;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(lim.check(&ctx(Some("o"), "1.1.1.1", "a.test")).is_ok());
        assert!(lim.check(&ctx(Some("o"), "1.1.1.1", "a.test")).is_err());
    }

    #[test]
    fn max_keys_rejects_new_keys_when_full() {
        let mut c = cfg();
        c.max_keys = 1;
        c.origin.rps = 100;
        c.origin.burst = 100;
        let lim = RateLimiter::from_config(&c).unwrap();
        assert!(
            lim.check(&ctx(Some("https://a.test"), "1.1.1.1", "h"))
                .is_ok()
        );
        assert!(
            lim.check(&ctx(Some("https://b.test"), "1.1.1.1", "h"))
                .is_err(),
            "second distinct origin must be rejected when max_keys=1"
        );
        assert!(
            lim.check(&ctx(Some("https://a.test"), "1.1.1.1", "h"))
                .is_ok(),
            "existing key remains admissible"
        );
    }
}
