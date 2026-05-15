//! Assembled dependencies ready to be injected into the `axum` router.
//!
//! ## Hot-reload model
//!
//! Fields fall into two camps:
//!
//! * **Hot-swappable** \u2014 CORS, header filters, request guards (origin lists +
//!   rate limiter), the upstream HTTP client and the source [`Config`] are
//!   bundled into [`LivePolicies`] and stored behind an
//!   [`ArcSwap`](arc_swap::ArcSwap). Each request loads a single snapshot so
//!   the policy view is consistent for the whole handler chain even if a
//!   reload races in mid-request.
//! * **Frozen-at-startup** \u2014 the listener (bind address, TLS, HTTP/2 toggle),
//!   request body limits and timeouts that are baked into the `axum::Router`,
//!   and the metrics endpoint path. These are recorded under `immutable_*`
//!   so a reload can detect attempts to change them and reject the new
//!   configuration with a clear log message.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use arc_swap::{ArcSwap, Guard};
use corx_core::config::{Config, LimitsConfig, ServerConfig};
use corx_core::proxy::{CorsPolicy, RequestFilter, ResponseFilter, SsrfGuard, Upstream};

use crate::middleware::{OriginPolicy, RateLimiter, RequestGuard};
use crate::observability::MetricsHandle;

/// Atomically-replaceable bundle of policy state.
///
/// Every request handler dereferences exactly one snapshot so views are
/// internally consistent even while a SIGHUP-driven reload swaps the
/// pointer underneath.
#[derive(Debug)]
pub struct LivePolicies {
    /// Source configuration this snapshot was built from.
    pub config: Arc<Config>,
    /// Compiled CORS policy.
    pub cors: Arc<CorsPolicy>,
    /// Inbound request filter.
    pub request_filter: Arc<RequestFilter>,
    /// Outbound response filter.
    pub response_filter: Arc<ResponseFilter>,
    /// Inbound guards (origin allow/deny, multi-dimensional rate limiter,
    /// required-header check).
    pub guard: RequestGuard,
    /// Upstream HTTP client. Rebuilt on reload, so SIGHUP discards the
    /// existing connection pool. Reloads are deliberate and rare, so this
    /// trade-off is acceptable in exchange for picking up fresh SSRF,
    /// timeout and pool-tuning settings without process restart.
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
        let cors = CorsPolicy::from_config(&config.cors);
        let request_filter = RequestFilter::new(&config.security.remove_request_headers);
        let response_filter = ResponseFilter::new(&config.security.remove_response_headers);

        let resolver = corx_core::proxy::build_resolver();
        let ssrf = SsrfGuard::new(&config.ssrf, resolver);

        let upstream_config = corx_core::proxy::UpstreamConfig {
            pool_max_idle_per_host: config.upstream.pool_max_idle_per_host,
            pool_idle_timeout: config.upstream.pool_idle_timeout,
            connect_timeout: config.limits.connect_timeout,
            max_redirects: config.limits.max_redirects,
            allow_https_to_http_downgrade: config.limits.allow_https_to_http_downgrade,
            user_agent: config.upstream.user_agent.clone(),
        };
        let upstream = Upstream::new(upstream_config, ssrf);

        let origin_policy = OriginPolicy::from_config(&config.security);
        let rate_limiter = RateLimiter::from_config(&config.rate_limit)?;
        let guard = RequestGuard::new(origin_policy, rate_limiter);

        Ok(Self {
            config: Arc::new(config),
            cors: Arc::new(cors),
            request_filter: Arc::new(request_filter),
            response_filter: Arc::new(response_filter),
            guard,
            upstream,
        })
    }
}

/// All dependencies required by the server.
///
/// Cheap to clone (everything is `Arc`-shared); cloned once per request via
/// the `axum` extractor so the hot path is wait-free.
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
