//! `axum` middleware that stamps CORS headers onto every response leaving
//! the proxy.
//!
//! Running as a layer rather than ad-hoc inside each handler ensures that:
//!
//! * **Success responses** \u2014 the upstream-shaped response receives the
//!   policy-derived `Access-Control-*` headers.
//! * **Error responses** \u2014 [`crate::error::ServerError`] is rendered into a
//!   JSON body which then flows through this layer, so cross-origin error
//!   payloads remain readable to the calling browser.
//! * **Preflight short-circuits** \u2014 `build_preflight_response` already emits
//!   CORS headers; this layer is idempotent so it overwrites them with the
//!   same values without harm.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use corx_core::proxy::apply_to_response;

use crate::router::AppState;

/// Captures the inbound request headers, runs the rest of the stack, then
/// stamps CORS onto whatever response comes back.
pub async fn cors_layer(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let request_headers = request.headers().clone();
    let mut response = next.run(request).await;
    apply_to_response(
        &mut response,
        &request_headers,
        state.build.policies().cors.as_ref(),
    );
    response
}
