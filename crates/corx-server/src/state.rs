//! Assembled dependencies ready to be injected into the `axum` router.
//!
//! ## Hot-reload model
//!
//! Fields fall into two camps:
//!
//! * **Hot-swappable** — CORS, header filters, request guards (origin lists +
//!   rate limiter), the upstream HTTP client and the source [`Config`] are
//!   bundled into [`LivePolicies`] and stored behind an
//!   [`ArcSwap`](arc_swap::ArcSwap). Each request loads a single snapshot so
//!   the policy view is consistent for the whole handler chain even if a
//!   reload races in mid-request.
//! * **Process state retained across reload when config is unchanged** —
//!   `circuit` and `rate` (`RateLimiter`) keep their in-memory maps so a
//!   SIGHUP that only tweaks CORS does not reset open breakers or GCRA
//!   budgets. `upstream` (connection pool + SSRF + target policy) is rebuilt
//!   when ssrf / target / upstream / connect / redirect settings change.
//! * **Frozen-at-startup** — the listener (bind address, TLS, HTTP/2 toggle),
//!   request body limits and timeouts that are baked into the `axum::Router`,
//!   and the metrics endpoint path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use arc_swap::{ArcSwap, Guard};
use corx_core::config::{Config, LimitsConfig, ServerConfig};
use corx_core::policy::{CircuitBreaker, TargetPolicy};
use corx_core::proxy::{CorsPolicy, HeaderFilter, SsrfGuard, Upstream};

use crate::middleware::{OriginPolicy, RateLimiter, RequestGuard};
use crate::observability::MetricsHandle;

/// Atomically-replaceable bundle of policy state.
#[derive(Debug)]
pub struct LivePolicies {
    /// Source configuration this snapshot was built from.
    pub config: Arc<Config>,
    /// Compiled CORS policy.
    pub cors: Arc<CorsPolicy>,
    /// Inbound request filter.
    pub request_filter: Arc<HeaderFilter>,
    /// Outbound response filter.
    pub response_filter: Arc<HeaderFilter>,
    /// Inbound guards (origin allow/deny, multi-dimensional rate limiter,
    /// required-header check).
    pub guard: RequestGuard,
    /// Target host / scheme admission (also enforced inside `upstream` on
    /// every redirect hop).
    pub target_policy: TargetPolicy,
    /// Per-host circuit breaker (process-local; retained across reload when
    /// circuit config is unchanged).
    pub circuit: CircuitBreaker,
    /// Upstream HTTP client (pool + SSRF + hop target policy).
    pub upstream: Upstream,
}

impl LivePolicies {
    /// Compile every hot-swappable component from the operator's config.
    ///
    /// # Errors
    ///
    /// Returns an error when any component fails to compile (invalid
    /// regex, malformed CIDR, missing TLS material, etc.).
    pub fn build(config: Config) -> anyhow::Result<Self> {
        Self::build_from(config, None)
    }

    /// Build a new snapshot, reusing process state from `previous` when the
    /// corresponding config sections are unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when any component fails to compile.
    pub fn build_from(config: Config, previous: Option<&Self>) -> anyhow::Result<Self> {
        let cors = CorsPolicy::from_config(&config.cors);
        let request_filter = HeaderFilter::try_new(&config.security.remove_request_headers)
            .map_err(|err| anyhow::anyhow!("security.remove_request_headers: {err}"))?;
        let response_filter = HeaderFilter::try_new(&config.security.remove_response_headers)
            .map_err(|err| anyhow::anyhow!("security.remove_response_headers: {err}"))?;

        let target_policy = TargetPolicy::from_config(&config.target);

        let rate_limiter = match previous {
            Some(prev) if prev.config.rate_limit == config.rate_limit => prev.guard.rate_limiter(),
            _ => RateLimiter::from_config(&config.rate_limit)?,
        };

        let origin_policy = OriginPolicy::from_config(&config.security);
        let guard = RequestGuard::new(origin_policy, rate_limiter);

        let circuit = match previous {
            Some(prev) if prev.config.circuit_breaker == config.circuit_breaker => {
                prev.circuit.clone()
            }
            _ => CircuitBreaker::from_config(&config.circuit_breaker),
        };

        let upstream = match previous {
            Some(prev) if upstream_config_eq(&prev.config, &config) => prev.upstream.clone(),
            _ => {
                let resolver = corx_core::proxy::build_resolver();
                let ssrf = SsrfGuard::new(&config.ssrf, resolver);
                let client_config = corx_core::proxy::ClientConfig {
                    pool_max_idle_per_host: config.upstream.pool_max_idle_per_host,
                    pool_idle_timeout: config.upstream.pool_idle_timeout,
                    connect_timeout: config.limits.connect_timeout,
                    max_redirects: config.limits.max_redirects,
                    allow_https_to_http_downgrade: config.limits.allow_https_to_http_downgrade,
                    redirect_policy: config.limits.redirect_policy,
                    user_agent: config.upstream.user_agent.clone(),
                };
                Upstream::new(client_config, ssrf, target_policy.clone())
                    .map_err(|err| anyhow::anyhow!("upstream client: {err}"))?
            }
        };

        Ok(Self {
            config: Arc::new(config),
            cors: Arc::new(cors),
            request_filter: Arc::new(request_filter),
            response_filter: Arc::new(response_filter),
            guard,
            target_policy,
            circuit,
            upstream,
        })
    }
}

/// Fields that force a full upstream client rebuild (pool + SSRF + hop policy).
fn upstream_config_eq(a: &Config, b: &Config) -> bool {
    a.ssrf == b.ssrf
        && a.target == b.target
        && a.upstream == b.upstream
        && a.limits.connect_timeout == b.limits.connect_timeout
        && a.limits.max_redirects == b.limits.max_redirects
        && a.limits.allow_https_to_http_downgrade == b.limits.allow_https_to_http_downgrade
        && a.limits.redirect_policy == b.limits.redirect_policy
}

/// All dependencies required by the server.
#[derive(Clone, Debug)]
pub struct ServerBuild {
    /// Hot-swappable policy snapshot.
    pub policies: Arc<ArcSwap<LivePolicies>>,
    /// Live in-flight counter feeding the load-shed layer. Independent of
    /// the Prometheus gauge so the hot path stays free of metrics overhead.
    pub inflight: Arc<AtomicU64>,
    /// Liveness flag. Flipped to `false` once a shutdown signal arrives so
    /// `/readyz` can announce that the listener is draining and load
    /// balancers should remove the pod from rotation.
    pub ready: Arc<AtomicBool>,
    /// Prometheus exposition handle.
    pub metrics: MetricsHandle,
    /// Listener configuration captured at startup. Compared against incoming
    /// reloads to reject attempts to change immutable fields.
    pub immutable_server: Arc<ServerConfig>,
    /// Body / timeout limits baked into the `axum::Router` at startup.
    pub immutable_limits: LimitsConfig,
    /// Path under which Prometheus metrics are exposed; locked at startup
    /// because changing it would require re-registering routes.
    pub immutable_metrics_endpoint: String,
}

impl ServerBuild {
    /// Assembles the server components from the operator-provided
    /// configuration and the previously-installed metrics handle.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the underlying components fail to compile
    /// (invalid regex, missing TLS verifier, etc.).
    pub fn from_config(config: Config, metrics: MetricsHandle) -> anyhow::Result<Self> {
        let immutable_server = Arc::new(config.server.clone());
        let immutable_limits = config.limits;
        let immutable_metrics_endpoint = config.observability.metrics_endpoint.clone();

        let policies = LivePolicies::build(config)?;

        Ok(Self {
            policies: Arc::new(ArcSwap::from_pointee(policies)),
            inflight: Arc::new(AtomicU64::new(0)),
            ready: Arc::new(AtomicBool::new(true)),
            metrics,
            immutable_server,
            immutable_limits,
            immutable_metrics_endpoint,
        })
    }

    /// Borrow the current policy snapshot. Cheap (single atomic load); the
    /// returned guard pins the snapshot for the rest of the handler.
    #[must_use]
    pub fn policies(&self) -> Guard<Arc<LivePolicies>> {
        self.policies.load()
    }
}
