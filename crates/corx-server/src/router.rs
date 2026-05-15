//! `axum` router wiring.

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{any, get};
use http::StatusCode;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware::{access_log_layer, cors_layer, load_shed_layer};
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
    // Body size and timeout are baked into the router at startup; they
    // come from the immutable snapshot for the same reason a SIGHUP reload
    // cannot change them mid-flight.
    let max_body = state.build.immutable_limits.max_request_body_bytes;
    let request_timeout = state.build.immutable_limits.request_timeout;
    let metrics_path = state.build.immutable_metrics_endpoint.clone();
    let body_limit = usize::try_from(max_body).unwrap_or(usize::MAX);

    let mut router = Router::new()
        .route("/", get(handlers::usage))
        .route("/livez", get(handlers::livez))
        .route("/readyz", get(handlers::readyz))
        .route("/healthz", get(handlers::healthz))
        .route("/iscorsneeded", get(handlers::is_cors_needed));

    if !metrics_path.is_empty() {
        router = router.route(&metrics_path, get(handlers::prometheus_metrics));
    }

    router
        .fallback(any(handlers::proxy))
        .method_not_allowed_fallback(handlers::not_found)
        // CORS runs first (innermost), so even responses from later layers
        // gain the headers; load-shed sits just outside it so 503s also
        // leave with valid CORS metadata.
        .layer(middleware::from_fn_with_state(state.clone(), cors_layer))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            load_shed_layer,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        // Access log sits at the outermost level so it observes the *final*
        // status (including timeouts and load-shed responses) and the wall
        // clock duration the client actually saw.
        .layer(middleware::from_fn(access_log_layer))
        .layer(TraceLayer::new_for_http())
}
