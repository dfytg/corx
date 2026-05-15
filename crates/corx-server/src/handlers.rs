//! HTTP handlers: the proxy endpoint and the operational endpoints.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::Json;
use axum::body::Body as AxumBody;
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse as _, Response};
use corx_core::error::ProxyError;
use corx_core::proxy::{self, InboundContext, TargetUrl, UpstreamBody, is_preflight};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use http_body_util::BodyExt as _;

use crate::error::ServerError;
use crate::observability::CountingBody;
use crate::observability::metrics as stats;
use crate::router::AppState;

const EXPOSE_URL_HEADER: HeaderName = HeaderName::from_static("x-corx-target-url");
const VIA_HEADER_VALUE: &str = "1.1 corx";

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

/// Primary proxy handler, bound to any path matching `/*path`.
pub(crate) async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<AxumBody>,
) -> Result<Response, ServerError> {
    let started = Instant::now();
    metrics::counter!(stats::REQUESTS_TOTAL).increment(1);
    metrics::gauge!(stats::INFLIGHT_REQUESTS).increment(1.0);

    let decrement_inflight = InflightGuard;

    let outcome = serve(state, request, peer.ip()).await;

    match &outcome {
        Ok(response) => {
            let status = response.status();
            metrics::histogram!(
                stats::REQUEST_DURATION,
                "status" => status.as_u16().to_string()
            )
            .record(started.elapsed().as_secs_f64());
        }
        Err(error) => {
            let kind = error.0.kind();
            metrics::counter!(stats::UPSTREAM_ERRORS, "kind" => kind.as_str()).increment(1);
            metrics::histogram!(
                stats::REQUEST_DURATION,
                "status" => kind.status().as_u16().to_string()
            )
            .record(started.elapsed().as_secs_f64());
        }
    }

    drop(decrement_inflight);
    outcome
}

struct InflightGuard;

impl Drop for InflightGuard {
    fn drop(&mut self) {
        metrics::gauge!(stats::INFLIGHT_REQUESTS).decrement(1.0);
    }
}

async fn serve(
    state: AppState,
    request: Request<AxumBody>,
    client_ip: IpAddr,
) -> Result<Response, ServerError> {
    let policies = state.build.policies();

    // CORS preflight short-circuit (no guards: preflights cannot carry the
    // information the guards need and browsers cache them via max-age).
    if is_preflight(&request) {
        let response = proxy::build_preflight_response(&request, policies.cors.as_ref());
        let (parts, body) = response.into_parts();
        let axum_body = AxumBody::new(body.map_err(|never| match never {}));
        return Ok(Response::from_parts(parts, axum_body));
    }

    // Stage 1: cheap origin / method / required-header guards.
    policies.guard.check_origin(&request)?;

    // Extract and validate the upstream target URL.
    let target = proxy::extract_target(request.uri())?;

    // Stage 2: multi-dimensional rate limiting now that we know the target.
    policies
        .guard
        .check_rate(&request, client_ip, &target.host)?;

    drop(policies);
    execute_proxy(state, request, target, client_ip).await
}

async fn execute_proxy(
    state: AppState,
    request: Request<AxumBody>,
    target: TargetUrl,
    client_ip: IpAddr,
) -> Result<Response, ServerError> {
    // The listener (and therefore the inbound scheme/port) is locked at
    // startup; pull it from the immutable snapshot so a SIGHUP-triggered
    // reload mid-request cannot change it underneath us.
    let tls_on = state.build.immutable_server.tls.is_some();
    let local_port = state.build.immutable_server.bind.port();

    let inbound_scheme = request
        .uri()
        .scheme_str()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || if tls_on { "https" } else { "http" }.to_owned(),
            str::to_owned,
        );
    let inbound_host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let policies = state.build.policies();

    let (mut parts, body) = request.into_parts();
    // Preserve inbound headers so that CORS can still reflect the original
    // Origin after the request has been consumed by the upstream client.
    let inbound_headers = parts.headers.clone();

    policies.request_filter.apply(&mut parts.headers);

    let inbound = InboundContext {
        client_ip: Some(client_ip),
        scheme: inbound_scheme.as_str(),
        host: inbound_host.as_deref(),
        local_port,
    };
    let forwarded_cfg = policies.config.forwarded;
    proxy::inject_forwarded(&mut parts.headers, inbound, &target, forwarded_cfg);

    inject_default_user_agent(&mut parts.headers, policies.upstream.user_agent());
    set_host_from_target(&mut parts.headers, &target);

    let upstream_uri = target.to_uri()?;
    parts.uri = upstream_uri;

    let body: UpstreamBody = axum_to_upstream_body(body);
    let outbound = Request::from_parts(parts, body);

    let upstream_started = Instant::now();
    let upstream_response = policies.upstream.execute(outbound).await;
    let upstream_elapsed = upstream_started.elapsed().as_secs_f64();

    let response = upstream_response.inspect_err(|error| {
        let kind = error.kind();
        metrics::histogram!(stats::UPSTREAM_DURATION, "status" => kind.as_str())
            .record(upstream_elapsed);
    })?;

    metrics::histogram!(
        stats::UPSTREAM_DURATION,
        "status" => response.status().as_u16().to_string()
    )
    .record(upstream_elapsed);

    Ok(shape_response(response, &state, &target, &inbound_headers))
}

fn shape_response(
    response: hyper::Response<hyper::body::Incoming>,
    state: &AppState,
    target: &TargetUrl,
    request_headers: &HeaderMap,
) -> Response {
    let policies = state.build.policies();

    let (mut response_parts, response_body) = response.into_parts();
    policies.response_filter.apply(&mut response_parts.headers);

    // Advertise the final URL and our presence in the via chain.
    if let Ok(value) = HeaderValue::from_str(target.url.as_str()) {
        response_parts.headers.insert(EXPOSE_URL_HEADER, value);
    }
    append_via_header(&mut response_parts.headers);

    let mut reassembled = hyper::Response::from_parts(response_parts, response_body);

    // Apply CORS last so its headers win on collisions.
    proxy::apply_to_response(&mut reassembled, request_headers, policies.cors.as_ref());

    let (final_parts, final_body) = reassembled.into_parts();
    let counted = CountingBody::new(final_body, "response");
    let axum_body = AxumBody::new(counted.map_err(axum::Error::new));
    Response::from_parts(final_parts, axum_body)
}

fn inject_default_user_agent(headers: &mut HeaderMap, default_ua: &str) {
    if headers.contains_key(header::USER_AGENT) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(default_ua) {
        headers.insert(header::USER_AGENT, value);
    }
}

fn set_host_from_target(headers: &mut HeaderMap, target: &TargetUrl) {
    let authority = target.url.port().map_or_else(
        || target.host.clone(),
        |port| format!("{}:{port}", target.host),
    );
    if let Ok(value) = HeaderValue::from_str(&authority) {
        headers.insert(header::HOST, value);
    }
}

fn append_via_header(headers: &mut HeaderMap) {
    let header_name = header::VIA;
    let new_value = headers.get(&header_name).map_or_else(
        || VIA_HEADER_VALUE.to_owned(),
        |existing| {
            existing.to_str().map_or_else(
                |_| VIA_HEADER_VALUE.to_owned(),
                |s| format!("{s}, {VIA_HEADER_VALUE}"),
            )
        },
    );
    if let Ok(value) = HeaderValue::from_str(&new_value) {
        headers.insert(header_name, value);
    }
}

fn axum_to_upstream_body(body: AxumBody) -> UpstreamBody {
    let counted = CountingBody::new(body, "request");
    counted
        .map_err(|err| ProxyError::Internal(anyhow::Error::new(err)))
        .boxed_unsync()
}

/// Fallback handler used when the router cannot match a path.
pub(crate) async fn not_found() -> Response {
    let body = serde_json::json!({
        "error": "not_found",
        "message": "resource not found",
    });
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}
