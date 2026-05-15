//! Per-origin rate limiting using a GCRA (generic cell rate algorithm) token
//! bucket. The `governor` crate provides a lock-free keyed limiter backed by
//! a concurrent `dashmap`, making this a zero-contention check on the hot
//! path.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::{Clock as _, QuantaClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter as GovRateLimiter};
use regex::RegexSet;

use corx_core::config::RateLimitConfig;
use corx_core::error::ProxyError;

type Limiter = GovRateLimiter<String, DashMapStateStore<String>, QuantaClock>;

/// Compiled rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    limiter: Option<Limiter>,
    clock: QuantaClock,
    unlimited: RegexSet,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("enabled", &self.inner.limiter.is_some())
            .field("unlimited_patterns", &self.inner.unlimited.len())
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Compile a limiter from the configuration.
    ///
    /// # Errors
    ///
    /// Fails if the configured RPS is zero, or if the regex set cannot be
    /// compiled.
    pub fn from_config(cfg: &RateLimitConfig) -> anyhow::Result<Self> {
        if !cfg.enabled {
            return Ok(Self {
                inner: Arc::new(Inner {
                    limiter: None,
                    clock: QuantaClock::default(),
                    unlimited: RegexSet::empty(),
                }),
            });
        }

        let rps = NonZeroU32::new(cfg.per_origin_rps)
            .ok_or_else(|| anyhow::anyhow!("per_origin_rps must be > 0"))?;
        let burst = NonZeroU32::new(cfg.burst.max(cfg.per_origin_rps))
            .ok_or_else(|| anyhow::anyhow!("burst must be > 0"))?;

        let quota = Quota::per_second(rps).allow_burst(burst);
        let clock = QuantaClock::default();
        let limiter: Limiter = GovRateLimiter::dashmap_with_clock(quota, clock.clone());

        let unlimited = RegexSet::new(&cfg.unlimited_hosts)
            .map_err(|err| anyhow::anyhow!("invalid unlimited_hosts regex: {err}"))?;

        Ok(Self {
            inner: Arc::new(Inner {
                limiter: Some(limiter),
                clock,
                unlimited,
            }),
        })
    }

    /// Checks whether a request from `origin` should be admitted.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::RateLimited`] when the caller has exhausted its
    /// budget.
    pub fn check(&self, origin: &str) -> Result<(), ProxyError> {
        let Some(limiter) = self.inner.limiter.as_ref() else {
            return Ok(());
        };

        if self.inner.unlimited.is_match(origin) {
            return Ok(());
        }

        // Touch the clock to keep it live; governor reads it internally too.
        let _ = self.inner.clock.now();
        let key = origin.to_owned();
        limiter.check_key(&key).map_err(|_| ProxyError::RateLimited)
    }
}

#[cfg(test)]
mod tests {
    use corx_core::config::RateLimitConfig;

    use super::RateLimiter;

    fn cfg(enabled: bool, rps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            enabled,
            per_origin_rps: rps,
            burst,
            unlimited_hosts: vec![],
        }
    }

    #[test]
    fn disabled_limiter_always_admits() {
        let limiter = RateLimiter::from_config(&cfg(false, 1, 1)).unwrap();
        for _ in 0..100 {
            assert!(limiter.check("https://a.test").is_ok());
        }
    }

    #[test]
    fn enabled_limiter_enforces_burst_budget() {
        let limiter = RateLimiter::from_config(&cfg(true, 1, 2)).unwrap();
        assert!(limiter.check("https://a.test").is_ok());
        assert!(limiter.check("https://a.test").is_ok());
        assert!(limiter.check("https://a.test").is_err());
    }

    #[test]
    fn unlimited_hosts_bypass_limiter() {
        let mut config = cfg(true, 1, 1);
        config.unlimited_hosts = vec![r"^https://whitelisted\.test$".into()];
        let limiter = RateLimiter::from_config(&config).unwrap();
        for _ in 0..10 {
            assert!(limiter.check("https://whitelisted.test").is_ok());
        }
    }
}
