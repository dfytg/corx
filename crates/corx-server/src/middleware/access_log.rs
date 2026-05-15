//! Per-request structured access log.
//!
//! Emits one `INFO`-level event per completed request with the canonical
//! fields operators need for debugging and SLO dashboards. Running as a
//! `tower::Layer` (rather than reusing `tower_http::trace::TraceLayer`)
//! lets us emit a single line at completion with the correct duration and
//! the `X-Request-Id` we injected via [`crate::middleware::request_id`].

use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use http::header;

/// Record one `corx::access` tracing event per request, regardless of
/// whether the proxy succeeded or returned an error response.
pub async fn access_log_layer(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let uri_path = request.uri().path().to_owned();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let response = next.run(request).await;
    let status = response.status();
    let error_kind = response
        .headers()
        .get(corx_core::error::STATUS_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    tracing::info!(
        target: "corx::access",
        kind = "access",
        method = %method,
        path = %uri_path,
        status = status.as_u16(),
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        client_ip = %peer.ip(),
        origin = origin.as_deref().unwrap_or(""),
        request_id = request_id.as_deref().unwrap_or(""),
        error_kind = error_kind.as_deref().unwrap_or(""),
    );

    response
}
