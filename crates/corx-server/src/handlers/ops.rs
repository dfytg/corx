//! Operational HTTP endpoints: liveness, readiness, metrics, fallback.

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use http::{StatusCode, header};

use crate::router::AppState;

const USAGE_TEXT: &str = "corx \u{2014} a CORS forwarding proxy\n\n\
Usage:\n    \
GET /https://target.example.com/path\n    \
GET /target.example.com/path\n    \
GET /?url=<percent-encoded-url>\n\n\
Operational endpoints:\n    \
GET /healthz           liveness probe\n    \
GET /iscorsneeded      cors-anywhere compatibility shim\n    \
GET /metrics           Prometheus exposition\n";

/// Landing page describing how to use the proxy.
pub(crate) async fn usage() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        USAGE_TEXT,
    )
        .into_response()
}

/// `GET /livez` — process liveness. Returns `200 OK` until the process
/// panics; load balancers should *not* drain on this signal.
pub(crate) async fn livez() -> Response {
    (StatusCode::OK, "live").into_response()
}

/// `GET /readyz` — readiness for traffic. Returns `503 Service Unavailable`
/// while the server is draining so load balancers stop sending new
/// requests.
pub(crate) async fn readyz(State(state): State<AppState>) -> Response {
    if state.build.ready.load(std::sync::atomic::Ordering::Acquire) {
        let body = serde_json::json!({"status": "ready"});
        (StatusCode::OK, Json(body)).into_response()
    } else {
        let body = serde_json::json!({
            "status": "draining",
            "reason": "shutdown signal received",
        });
        (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
    }
}

/// `GET /healthz` — backwards-compatible alias kept for Kubernetes default
/// probes. Mirrors `/readyz` so behaviour stays consistent.
pub(crate) async fn healthz(state: State<AppState>) -> Response {
    readyz(state).await
}

/// `GET /iscorsneeded` — cors-anywhere compatibility endpoint.
pub(crate) async fn is_cors_needed() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "no",
    )
        .into_response()
}

/// `GET /metrics` — Prometheus text exposition.
pub(crate) async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    let body = state.build.metrics.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Fallback handler used when the router cannot match a path.
pub(crate) async fn not_found() -> Response {
    let body = serde_json::json!({
        "error": "not_found",
        "message": "resource not found",
    });
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}
