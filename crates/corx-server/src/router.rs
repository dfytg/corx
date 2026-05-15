//! `axum` router wiring.

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get};
use http::StatusCode;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::ServerBuild;

/// Shared application state injected into every handler.
#[derive(Clone, Debug)]
pub struct AppState {
    /// Pre-assembled dependencies.
    pub build: Arc<ServerBuild>,
}

impl AppState {
    /// Wraps the shared [`ServerBuild`] into an `axum`-compatible state.
    #[must_use]
    pub fn new(build: ServerBuild) -> Self {
        Self {
            build: Arc::new(build),
        }
    }
}

/// Builds the `axum` router with every middleware layer registered.
#[must_use]
pub fn build_router(state: AppState) -> Router<()> {
    let max_body = state.build.config.limits.max_request_body_bytes;
    let request_timeout = state.build.config.limits.request_timeout;
    let metrics_path = state.build.config.observability.metrics_endpoint.clone();
    let body_limit = usize::try_from(max_body).unwrap_or(usize::MAX);

    let mut router = Router::new()
        .route("/", get(handlers::usage))
        .route("/healthz", get(handlers::healthz))
        .route("/iscorsneeded", get(handlers::is_cors_needed));

    if !metrics_path.is_empty() {
        router = router.route(&metrics_path, get(handlers::prometheus_metrics));
    }

    router
        .fallback(any(handlers::proxy))
        .method_not_allowed_fallback(handlers::not_found)
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        .layer(TraceLayer::new_for_http())
}
