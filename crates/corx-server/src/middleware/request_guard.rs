//! Combined inbound request guard used by the `axum` router layer.

use std::net::IpAddr;
use std::sync::Arc;

use corx_core::error::ProxyError;
use http::Request;

use crate::middleware::rate_limit::RateContext;
use crate::middleware::{OriginPolicy, RateLimiter};

/// Bundles all synchronous inbound checks into a single entry point so that
/// handlers can stay focused on forwarding logic.
#[derive(Debug, Clone)]
pub struct RequestGuard {
    origin: Arc<OriginPolicy>,
    rate_limit: RateLimiter,
}

impl RequestGuard {
    /// Wraps the supplied policies into a single guard.
    #[must_use]
    pub fn new(origin: OriginPolicy, rate_limit: RateLimiter) -> Self {
        Self {
            origin: Arc::new(origin),
            rate_limit,
        }
    }

    /// Origin policy / required headers / blocked methods. Cheap, runs
    /// before URL extraction so that obviously-bad requests never reach the
    /// parser.
    ///
    /// # Errors
    ///
    /// Forwards [`OriginPolicy::evaluate`] failures.
    pub fn check_origin<B>(&self, request: &Request<B>) -> Result<(), ProxyError> {
        self.origin.evaluate(request.method(), request.headers())
    }

    /// Multi-dimensional rate limiting. Run *after* URL extraction so the
    /// `target_host` dimension can use the validated punycode hostname.
    /// Pass `target_host = None` to skip the host dimension (preflight
    /// paths that are not a parseable target).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::RateLimited`] when any dimension exhausts.
    pub fn check_rate<B>(
        &self,
        request: &Request<B>,
        client_ip: IpAddr,
        target_host: Option<&str>,
    ) -> Result<(), ProxyError> {
        let origin = request
            .headers()
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok());
        let ctx = RateContext {
            origin,
            client_ip,
            target_host,
        };
        self.rate_limit.check(&ctx)
    }
}
