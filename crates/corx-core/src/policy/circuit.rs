//! Process-local per-host circuit breaker.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use foldhash::fast::RandomState;

use crate::config::CircuitBreakerConfig;
use crate::error::ProxyError;
use crate::observability;

/// Outcome of a circuit check before dispatching upstream.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CircuitDecision {
    /// Proceed with the request.
    Closed,
    /// Proceed as a limited half-open probe.
    HalfOpenProbe,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Closed,
    Open { until: Instant },
    HalfOpen { probes: u32 },
}

struct HostCircuit {
    state: State,
    /// Failure timestamps inside the rolling window (oldest first).
    failures: Vec<Instant>,
}

impl HostCircuit {
    const fn new() -> Self {
        Self {
            state: State::Closed,
            failures: Vec::new(),
        }
    }
}

/// Per-host circuit breaker shared across requests.
#[derive(Clone)]
pub struct CircuitBreaker {
    inner: Arc<Inner>,
}

struct Inner {
    enabled: bool,
    failure_threshold: u32,
    window: Duration,
    open_duration: Duration,
    half_open_max: u32,
    count_5xx: bool,
    hosts: DashMap<String, HostCircuit, RandomState>,
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("enabled", &self.inner.enabled)
            .field("hosts", &self.inner.hosts.len())
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    /// Compile from configuration.
    #[must_use]
    pub fn from_config(cfg: &CircuitBreakerConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                enabled: cfg.enabled,
                failure_threshold: cfg.failure_threshold.max(1),
                window: cfg.window,
                open_duration: cfg.open_duration,
                half_open_max: cfg.half_open_max.max(1),
                count_5xx: cfg.count_5xx,
                hosts: DashMap::with_hasher(RandomState::default()),
            }),
        }
    }

    /// Whether upstream HTTP 5xx should be recorded as failures.
    #[must_use]
    pub fn count_5xx(&self) -> bool {
        self.inner.count_5xx
    }

    /// Check whether a request to `host` may proceed.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::CircuitOpen`] when the breaker is open.
    pub fn check(&self, host: &str) -> Result<CircuitDecision, ProxyError> {
        if !self.inner.enabled {
            return Ok(CircuitDecision::Closed);
        }
        let now = Instant::now();
        let half_open_max = self.inner.half_open_max;
        let mut entry = self
            .inner
            .hosts
            .entry(host.to_owned())
            .or_insert_with(HostCircuit::new);
        let decision = transition_on_check(&mut entry, now, half_open_max);
        drop(entry);
        decision.ok_or_else(|| {
            metrics::counter!(observability::CIRCUIT_REJECTS).increment(1);
            ProxyError::CircuitOpen(host.to_owned())
        })
    }

    /// Record a successful upstream response (or client-error that is not a
    /// failure signal). Resets the host to closed.
    pub fn record_success(&self, host: &str) {
        if !self.inner.enabled {
            return;
        }
        if let Some(mut entry) = self.inner.hosts.get_mut(host) {
            entry.failures.clear();
            entry.state = State::Closed;
        }
    }

    /// Record a transport / policy failure that should trip the breaker.
    pub fn record_failure(&self, host: &str) {
        if !self.inner.enabled {
            return;
        }
        let now = Instant::now();
        let window = self.inner.window;
        let threshold = self.inner.failure_threshold;
        let open_duration = self.inner.open_duration;
        let mut entry = self
            .inner
            .hosts
            .entry(host.to_owned())
            .or_insert_with(HostCircuit::new);
        let opened = record_failure_on(&mut entry, now, window, threshold, open_duration);
        drop(entry);
        if opened {
            metrics::counter!(observability::CIRCUIT_OPENS).increment(1);
            tracing::warn!(host, "circuit breaker opened");
        }
    }
}

fn transition_on_check(
    entry: &mut HostCircuit,
    now: Instant,
    half_open_max: u32,
) -> Option<CircuitDecision> {
    match entry.state {
        State::Closed => Some(CircuitDecision::Closed),
        State::Open { until } if now >= until => {
            entry.state = State::HalfOpen { probes: 1 };
            Some(CircuitDecision::HalfOpenProbe)
        }
        State::HalfOpen { probes } if probes < half_open_max => {
            entry.state = State::HalfOpen {
                probes: probes.saturating_add(1),
            };
            Some(CircuitDecision::HalfOpenProbe)
        }
        State::Open { .. } | State::HalfOpen { .. } => None,
    }
}

fn record_failure_on(
    entry: &mut HostCircuit,
    now: Instant,
    window: Duration,
    threshold: u32,
    open_duration: Duration,
) -> bool {
    entry.failures.retain(|t| now.duration_since(*t) <= window);
    entry.failures.push(now);

    let failure_count = u32::try_from(entry.failures.len()).unwrap_or(u32::MAX);
    let should_open = matches!(entry.state, State::HalfOpen { .. }) || failure_count >= threshold;
    if !should_open {
        return false;
    }
    entry.state = State::Open {
        until: now + open_duration,
    };
    entry.failures.clear();
    true
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::CircuitBreakerConfig;

    fn cfg(threshold: u32) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: true,
            failure_threshold: threshold,
            window: Duration::from_mins(1),
            open_duration: Duration::from_millis(50),
            half_open_max: 1,
            count_5xx: true,
        }
    }

    #[test]
    fn trips_after_threshold_failures() {
        let cb = CircuitBreaker::from_config(&cfg(3));
        assert!(cb.check("h.test").is_ok());
        cb.record_failure("h.test");
        cb.record_failure("h.test");
        assert!(cb.check("h.test").is_ok());
        cb.record_failure("h.test");
        assert!(cb.check("h.test").is_err());
    }

    #[test]
    fn success_resets() {
        let cb = CircuitBreaker::from_config(&cfg(2));
        cb.record_failure("h.test");
        cb.record_success("h.test");
        cb.record_failure("h.test");
        assert!(cb.check("h.test").is_ok());
    }

    #[test]
    fn disabled_never_trips() {
        let mut c = cfg(1);
        c.enabled = false;
        let cb = CircuitBreaker::from_config(&c);
        cb.record_failure("h.test");
        cb.record_failure("h.test");
        assert!(cb.check("h.test").is_ok());
    }
}
