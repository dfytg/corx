//! Primary proxy handler: drives the full inbound → upstream → outbound
//! lifecycle for every non-operational request.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::body::Body as AxumBody;
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use corx_core::proxy::{self, InboundContext, TargetUrl, is_preflight};
use http::{HeaderMap, HeaderValue, Request, header};
use http_body_util::BodyExt as _;

use super::outbound::{
    EXPOSE_URL_HEADER, append_via_header, axum_to_upstream_body, inject_default_user_agent,
    set_host_from_target,
};
use crate::error::ServerError;
use crate::observability::CountingBody;
use crate::observability::metrics as stats;
use crate::router::AppState;

/// Primary proxy handler, bound to any path matching `/*path`.
pub(crate) async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<AxumBody>,
) -> Result<Response, ServerError> {
    let started = Instant::now();
    metrics::counter!(stats::REQUESTS_TOTAL).increment(1);
    metrics::gauge!(stats::INFLIGHT_REQUESTS).increment(1.0);

    let _decrement_inflight = InflightGuard;
    let outcome = serve(state, request, peer.ip()).await;

    let elapsed = started.elapsed().as_secs_f64();
    match &outcome {
        Ok(response) => {
            metrics::histogram!(
                stats::REQUEST_DURATION,
                "status" => response.status().as_u16().to_string()
            )
            .record(elapsed);
        }
        Err(error) => {
            let kind = error.0.kind();
            metrics::counter!(stats::UPSTREAM_ERRORS, "kind" => kind.as_str()).increment(1);
            metrics::histogram!(
                stats::REQUEST_DURATION,
                "status" => kind.status().as_u16().to_string()
            )
            .record(elapsed);
        }
    }

    outcome
}

/// RAII guard that decrements the in-flight gauge on drop, even on panic.
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

    parts.uri = target.to_uri()?;
    let outbound = Request::from_parts(parts, axum_to_upstream_body(body));

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

    if let Ok(value) = HeaderValue::from_str(target.url.as_str()) {
        response_parts.headers.insert(EXPOSE_URL_HEADER, value);
    }
    append_via_header(&mut response_parts.headers);

    let mut reassembled = hyper::Response::from_parts(response_parts, response_body);
    proxy::apply_to_response(&mut reassembled, request_headers, policies.cors.as_ref());

    let (final_parts, final_body) = reassembled.into_parts();
    let counted = CountingBody::new(final_body, "response");
    let axum_body = AxumBody::new(counted.map_err(axum::Error::new));
    Response::from_parts(final_parts, axum_body)
}
