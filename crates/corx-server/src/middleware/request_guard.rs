//! Combined inbound request guard used by the `axum` router layer.

use std::sync::Arc;

use http::Method;
use http::Request;

use corx_core::error::ProxyError;

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

    /// Evaluates all inbound guards for `request` and returns the origin
    /// string that was used for the decision, when present.
    ///
    /// # Errors
    ///
    /// Surfaces the first failing guard. Ordering is:
    ///
    /// 1. origin blacklist / whitelist / required headers / blocked methods,
    /// 2. rate limiting.
    pub fn evaluate<B>(&self, request: &Request<B>) -> Result<Option<&'static str>, ProxyError> {
        self.origin.evaluate(request.method(), request.headers())?;
        if let Some(origin) = request
            .headers()
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            self.rate_limit.check(origin)?;
        }
        Ok(None)
    }

    /// Short-circuits CORS preflights to avoid rate-limiting them away.
    #[must_use]
    pub fn should_skip_for_preflight(method: &Method) -> bool {
        method == Method::OPTIONS
    }
}
