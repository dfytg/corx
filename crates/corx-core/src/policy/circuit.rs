//! Process-local per-host circuit breaker.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use foldhash::fast::RandomState;

use crate::config::CircuitBreakerConfig;
use crate::error::ProxyError;
use crate::observability;

#[derive(Debug, Clone, Copy)]
enum State {
    Closed,
    Open { until: Instant },
    /// `since` bounds half-open so cancelled probes cannot lock a host forever.
    HalfOpen { probes: u32, since: Instant },
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

    const fn is_idle_closed(&self) -> bool {
        matches!(self.state, State::Closed) && self.failures.is_empty()
    }

    const fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    fn is_expired_open(&self, now: Instant) -> bool {
        matches!(self.state, State::Open { until } if now >= until)
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
    max_hosts: usize,
    hosts: DashMap<String, HostCircuit, RandomState>,
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("enabled", &self.inner.enabled)
            .field("hosts", &self.inner.hosts.len())
            .field("max_hosts", &self.inner.max_hosts)
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
                max_hosts: cfg.max_hosts.max(1),
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
    /// Half-open probe budgeting is enforced inside this method. Callers must
    /// always pair a successful `check` with [`Self::record_success`] or
    /// [`Self::record_failure`] (or a drop-guard that records failure) so a
    /// cancelled probe cannot leave the host stuck in half-open forever.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::CircuitOpen`] when the breaker is open.
    pub fn check(&self, host: &str) -> Result<(), ProxyError> {
        if !self.inner.enabled {
            return Ok(());
        }
        let now = Instant::now();
        let half_open_max = self.inner.half_open_max;
        let open_duration = self.inner.open_duration;
        let mut entry = self
            .inner
            .hosts
            .entry(host.to_owned())
            .or_insert_with(HostCircuit::new);
        let allowed = transition_on_check(&mut entry, now, half_open_max, open_duration);
        drop(entry);
        if allowed {
            self.evict_if_needed(now);
            Ok(())
        } else {
            metrics::counter!(observability::CIRCUIT_REJECTS).increment(1);
            Err(ProxyError::CircuitOpen(host.to_owned()))
        }
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
        self.evict_if_needed(now);
    }

    /// Number of tracked hosts (test / ops helper).
    #[must_use]
    pub fn tracked_hosts(&self) -> usize {
        self.inner.hosts.len()
    }

    fn evict_if_needed(&self, now: Instant) {
        let max = self.inner.max_hosts;
        if self.inner.hosts.len() <= max {
            return;
        }
        // Prefer reclaiming entries that no longer need protection state.
        self.evict_matching(max, HostCircuit::is_idle_closed);
        if self.inner.hosts.len() > max {
            self.evict_matching(max, |c| c.is_expired_open(now));
        }
        if self.inner.hosts.len() > max {
            self.evict_matching(max, HostCircuit::is_closed);
        }
    }

    fn evict_matching(&self, max: usize, pred: impl Fn(&HostCircuit) -> bool) {
        let excess = self.inner.hosts.len().saturating_sub(max);
        if excess == 0 {
            return;
        }
        let mut removed = 0usize;
        self.inner.hosts.retain(|_, circuit| {
            if removed >= excess || !pred(circuit) {
                return true;
            }
            removed = removed.saturating_add(1);
            false
        });
    }
}

fn transition_on_check(
    entry: &mut HostCircuit,
    now: Instant,
    half_open_max: u32,
    open_duration: Duration,
) -> bool {
    match entry.state {
        State::Closed => true,
        State::Open { until } if now >= until => {
            entry.state = State::HalfOpen {
                probes: 1,
                since: now,
            };
            true
        }
        State::HalfOpen { probes, since } if probes < half_open_max => {
            entry.state = State::HalfOpen {
                probes: probes.saturating_add(1),
                since,
            };
            true
        }
        // Probe budget exhausted: if the half-open window elapsed (cancelled
        // probes never settled), open a new probe window instead of locking
        // the host permanently.
        State::HalfOpen { since, .. } if now.duration_since(since) >= open_duration => {
            entry.state = State::HalfOpen {
                probes: 1,
                since: now,
            };
            true
        }
        State::Open { .. } | State::HalfOpen { .. } => false,
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

/// RAII guard: records a failure if the hop is abandoned (cancel / panic)
/// without an explicit success or failure settlement.
#[derive(Debug)]
pub struct CircuitHop<'a> {
    circuit: &'a CircuitBreaker,
    host: String,
    settled: bool,
}

impl<'a> CircuitHop<'a> {
    /// Admit `host` and return a guard that must be settled.
    ///
    /// # Errors
    ///
    /// Propagates [`CircuitBreaker::check`].
    pub fn admit(circuit: &'a CircuitBreaker, host: impl Into<String>) -> Result<Self, ProxyError> {
        let host = host.into();
        circuit.check(&host)?;
        Ok(Self {
            circuit,
            host,
            settled: false,
        })
    }

    /// Host this hop was admitted for.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Mark the hop successful (disarms drop-failure).
    pub fn success(mut self) {
        self.circuit.record_success(&self.host);
        self.settled = true;
    }

    /// Mark the hop failed (disarms drop-failure).
    pub fn failure(mut self) {
        self.circuit.record_failure(&self.host);
        self.settled = true;
    }
}

impl Drop for CircuitHop<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.circuit.record_failure(&self.host);
        }
    }
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
            max_hosts: 8192,
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

    #[test]
    fn max_hosts_evicts_idle_closed() {
        let mut c = cfg(10);
        c.max_hosts = 2;
        let cb = CircuitBreaker::from_config(&c);
        assert!(cb.check("a.test").is_ok());
        assert!(cb.check("b.test").is_ok());
        assert!(cb.check("c.test").is_ok());
        assert!(cb.tracked_hosts() <= 2);
    }

    #[test]
    fn hop_guard_records_failure_on_drop() {
        let cb = CircuitBreaker::from_config(&cfg(1));
        {
            let hop = CircuitHop::admit(&cb, "h.test").expect("admit");
            assert_eq!(hop.host(), "h.test");
            // drop without settle
        }
        assert!(
            cb.check("h.test").is_err(),
            "unsettled hop must count as failure and trip threshold=1"
        );
    }

    #[test]
    fn hop_guard_success_disarms_drop() {
        let cb = CircuitBreaker::from_config(&cfg(1));
        {
            let hop = CircuitHop::admit(&cb, "h.test").expect("admit");
            hop.success();
        }
        assert!(cb.check("h.test").is_ok());
    }
}
