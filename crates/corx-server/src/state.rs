//! Assembled dependencies ready to be injected into the `axum` router.

use std::sync::Arc;

use corx_core::config::Config;
use corx_core::proxy::{CorsPolicy, RequestFilter, ResponseFilter, SsrfGuard, Upstream};

use crate::middleware::{OriginPolicy, RateLimiter, RequestGuard};
use crate::observability::MetricsHandle;

/// All dependencies required by the server, assembled at startup.
#[derive(Clone, Debug)]
pub struct ServerBuild {
    /// Loaded operator configuration.
    pub config: Arc<Config>,
    /// Compiled CORS policy.
    pub cors: Arc<CorsPolicy>,
    /// Inbound request filter.
    pub request_filter: Arc<RequestFilter>,
    /// Outbound response filter.
    pub response_filter: Arc<ResponseFilter>,
    /// Inbound guards (origin, rate-limit, required headers).
    pub guard: RequestGuard,
    /// Upstream HTTP client.
    pub upstream: Upstream,
    /// Prometheus exposition handle.
    pub metrics: MetricsHandle,
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
            user_agent: config.upstream.user_agent.clone(),
        };
        let upstream = Upstream::new(upstream_config, ssrf)?;

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
            metrics,
        })
    }
}
