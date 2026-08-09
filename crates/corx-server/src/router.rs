//! `axum` router wiring.

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{any, get};
use http::StatusCode;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware::{
    access_log_layer, auth_layer, cors_layer, header_limit_layer, load_shed_layer,
};
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
///
/// Layer order (outer → inner):
///
/// ```text
/// Trace → access_log → cors → Timeout → BodyLimit → CatchPanic
///   → header_limit → load_shed → auth → handler
/// ```
///
/// CORS sits outside timeout / body-limit / auth / load-shed so 401/503/431/
/// 504/413 responses still carry browser-readable ACAO headers.
pub fn build_router(state: AppState) -> Router<()> {
    let max_body = state.build.immutable_limits.max_request_body_bytes;
    let request_timeout = state.build.immutable_limits.request_timeout;
    let metrics_path = state.build.immutable_metrics_endpoint.clone();
    let body_limit = usize::try_from(max_body).unwrap_or_else(|_| {
        tracing::warn!(
            configured = max_body,
            used = usize::MAX,
            "limits.max_request_body_bytes exceeds usize::MAX on this target; clamping to usize::MAX",
        );
        usize::MAX
    });

    let mut router = Router::new()
        .route("/", get(handlers::usage))
        .route("/livez", get(handlers::livez))
        .route("/readyz", get(handlers::readyz))
        .route("/healthz", get(handlers::healthz))
        .route("/iscorsneeded", get(handlers::is_cors_needed));

    if !metrics_path.is_empty() {
        router = router.route(&metrics_path, get(handlers::prometheus_metrics));
    }

    let cors_state = state.clone();

    router
        .fallback(any(handlers::proxy))
        .method_not_allowed_fallback(handlers::not_found)
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            load_shed_layer,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            header_limit_layer,
        ))
        .with_state(state)
        .layer(CatchPanicLayer::new())
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        // Outside timeout/body so 504/413 also get CORS headers.
        .layer(middleware::from_fn_with_state(cors_state, cors_layer))
        .layer(middleware::from_fn(access_log_layer))
        .layer(TraceLayer::new_for_http())
}
