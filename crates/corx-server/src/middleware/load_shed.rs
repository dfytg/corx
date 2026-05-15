//! Process-wide load shedding.
//!
//! When [`GlobalLimitConfig::inflight_max`] is non-zero, this layer rejects
//! every additional request with `503 Service Unavailable` once the
//! configured concurrency cap is reached. Rejections carry a `Retry-After`
//! hint and bump the `corx_rate_limited_total{dimension="global"}` counter
//! so existing dashboards light up identically to other shed paths.
//!
//! `inflight_max = 0` keeps the layer on the request path but as a no-op,
//! avoiding the cost of swapping layer stacks on configuration reload.
//!
//! [`GlobalLimitConfig::inflight_max`]: corx_core::config::GlobalLimitConfig::inflight_max

use std::sync::atomic::Ordering;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use corx_core::observability;
use http::{HeaderValue, StatusCode, header};

use crate::router::AppState;

/// `axum::middleware::from_fn_with_state` adapter for the load-shed layer.
pub async fn load_shed_layer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let max = u64::from(state.build.policies().config.rate_limit.global.inflight_max);
    if max == 0 {
        return next.run(request).await;
    }

    let counter = &state.build.inflight;
    let prev = counter.fetch_add(1, Ordering::AcqRel);
    if prev >= max {
        // Restore the counter; we never actually entered service.
        counter.fetch_sub(1, Ordering::AcqRel);
        metrics::counter!(observability::RATE_LIMITED, "dimension" => "global").increment(1);
        return shed_response();
    }

    let response = next.run(request).await;
    counter.fetch_sub(1, Ordering::AcqRel);
    response
}

fn shed_response() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        "load shed: inflight cap reached",
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}
