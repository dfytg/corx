//! Primary proxy handler: drives the full inbound → upstream → outbound
//! lifecycle for every non-operational request.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::body::Body as AxumBody;
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use corx_core::config::{PreflightMode, RedirectPolicy};
use corx_core::proxy::{self, InboundContext, TargetUrl, is_preflight};
use http::{HeaderMap, HeaderValue, Request, header};
use http_body_util::BodyExt as _;

use super::outbound::{
    EXPOSE_URL_HEADER, append_via_header, axum_to_upstream_body, inject_default_user_agent,
    set_host_from_target,
};
use crate::error::ServerError;
use crate::observability::{CountingBody, LimitingBody};
use crate::router::AppState;

/// Primary proxy handler, bound to any path matching `/*path`.
pub(crate) async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<AxumBody>,
) -> Result<Response, ServerError> {
    let started = Instant::now();
    metrics::counter!(crate::observability::metrics::REQUESTS_TOTAL).increment(1);
    metrics::gauge!(crate::observability::metrics::INFLIGHT_REQUESTS).increment(1.0);

    let _decrement_inflight = InflightGuard;
    let outcome = serve(state, request, peer.ip()).await;

    let elapsed = started.elapsed().as_secs_f64();
    match &outcome {
        Ok(response) => {
            metrics::histogram!(
                crate::observability::metrics::REQUEST_DURATION,
                "status" => response.status().as_u16().to_string()
            )
            .record(elapsed);
        }
        Err(error) => {
            let kind = error.kind();
            metrics::counter!(
                crate::observability::metrics::UPSTREAM_ERRORS,
                "kind" => kind.as_str()
            )
            .increment(1);
            metrics::histogram!(
                crate::observability::metrics::REQUEST_DURATION,
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
        metrics::gauge!(crate::observability::metrics::INFLIGHT_REQUESTS).decrement(1.0);
    }
}

async fn serve(
    state: AppState,
    request: Request<AxumBody>,
    client_ip: IpAddr,
) -> Result<Response, ServerError> {
    let policies = state.build.policies();

    // CORS preflight: by default runs the same origin (and optional rate)
    // guards as real traffic so blacklisted origins cannot harvest 204s
    // and OPTIONS cannot bypass the limiter.
    if is_preflight(&request) {
        let preflight = &policies.config.security.preflight;
        if preflight.mode == PreflightMode::Enforce {
            policies.guard.check_origin(&request)?;
            if preflight.rate_limit {
                let target_host = proxy::extract_target(request.uri()).ok().map(|t| t.host);
                policies
                    .guard
                    .check_rate(&request, client_ip, target_host.as_deref())?;
            }
        }
        let response = proxy::build_preflight_response(&request, policies.cors.as_ref());
        let (parts, body) = response.into_parts();
        let axum_body = AxumBody::new(body.map_err(|never| match never {}));
        return Ok(Response::from_parts(parts, axum_body));
    }

    policies.guard.check_origin(&request)?;

    let target = proxy::extract_target(request.uri())?;
    // First-hop admission (redirect hops re-check inside Upstream::execute).
    policies.target_policy.check(&target)?;

    policies
        .guard
        .check_rate(&request, client_ip, Some(target.host.as_str()))?;

    drop(policies);
    execute_proxy(state, request, target, client_ip).await
}

async fn execute_proxy(
    state: AppState,
    request: Request<AxumBody>,
    target: TargetUrl,
    client_ip: IpAddr,
) -> Result<Response, ServerError> {
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
    let upstream_response = policies
        .upstream
        .execute(outbound, &policies.circuit)
        .await;
    let upstream_elapsed = upstream_started.elapsed().as_secs_f64();

    let response = match upstream_response {
        Ok(response) => {
            metrics::histogram!(
                crate::observability::metrics::UPSTREAM_DURATION,
                "status" => response.status().as_u16().to_string()
            )
            .record(upstream_elapsed);
            response
        }
        Err(error) => {
            let kind = error.kind();
            metrics::histogram!(
                crate::observability::metrics::UPSTREAM_DURATION,
                "status" => kind.as_str()
            )
            .record(upstream_elapsed);
            return Err(error.into());
        }
    };

    let redirect_policy = policies.config.limits.redirect_policy;
    Ok(shape_response(
        response,
        &state,
        &target,
        &inbound_headers,
        redirect_policy,
    ))
}

fn shape_response(
    response: hyper::Response<hyper::body::Incoming>,
    state: &AppState,
    target: &TargetUrl,
    _request_headers: &HeaderMap,
    redirect_policy: RedirectPolicy,
) -> Response {
    let policies = state.build.policies();

    let (mut response_parts, response_body) = response.into_parts();
    policies.response_filter.apply(&mut response_parts.headers);

    if let Ok(value) = HeaderValue::from_str(target.url.as_str()) {
        response_parts.headers.insert(EXPOSE_URL_HEADER, value);
    }
    append_via_header(&mut response_parts.headers);

    if redirect_policy == RedirectPolicy::Rewrite {
        rewrite_location_header(&mut response_parts.headers);
    }

    // CORS is applied solely by `cors_layer` so every response path (errors,
    // load-shed, success) shares one owner.

    let max_response = state.build.immutable_limits.max_response_body_bytes;
    let counted = CountingBody::new(response_body, "response");
    let limited = LimitingBody::new(counted, max_response);
    let axum_body = AxumBody::new(limited.map_err(axum::Error::new));
    Response::from_parts(response_parts, axum_body)
}

/// Rewrite absolute `Location` values into the cors-anywhere path-prefix form
/// so the browser stays on the proxy for the next hop.
fn rewrite_location_header(headers: &mut HeaderMap) {
    let Some(location) = headers.get(header::LOCATION) else {
        return;
    };
    let Ok(raw) = location.to_str() else {
        return;
    };
    if !(raw.starts_with("http://") || raw.starts_with("https://")) {
        return;
    }
    let rewritten = format!("/{raw}");
    if let Ok(value) = HeaderValue::from_str(&rewritten) {
        headers.insert(header::LOCATION, value);
    }
}
