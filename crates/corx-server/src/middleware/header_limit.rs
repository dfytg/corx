//! Enforce `limits.max_request_header_bytes` before handlers run.
//!
//! Hyper/axum do not expose a portable knobs for max header size on every
//! listener path, so we measure the decoded header map (name + value bytes)
//! and reject oversized requests with `431 Request Header Fields Too Large`.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

use crate::router::AppState;

/// Rejects requests whose combined header name+value size exceeds the
/// configured ceiling.
pub async fn header_limit_layer(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let max = state.build.immutable_limits.max_request_header_bytes;
    let size = header_map_bytes(request.headers());
    if size > u64::from(max) {
        tracing::debug!(
            header_bytes = size,
            max_bytes = max,
            "request headers exceed configured limit"
        );
        return (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request header fields too large",
        )
            .into_response();
    }
    next.run(request).await
}

/// Sum of header name lengths plus value lengths (decoded, not wire framing).
fn header_map_bytes(headers: &http::HeaderMap) -> u64 {
    let mut total: u64 = 0;
    for (name, value) in headers {
        total = total.saturating_add(name.as_str().len() as u64);
        total = total.saturating_add(value.as_bytes().len() as u64);
    }
    total
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::header_map_bytes;

    #[test]
    fn empty_map_is_zero() {
        assert_eq!(header_map_bytes(&HeaderMap::new()), 0);
    }

    #[test]
    fn counts_name_and_value() {
        let mut map = HeaderMap::new();
        map.insert("x-a", HeaderValue::from_static("bb"));
        // "x-a" = 3, "bb" = 2
        assert_eq!(header_map_bytes(&map), 5);
    }
}
