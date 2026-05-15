//! `axum` adapter that turns a [`corx_core::error::ProxyError`] into a
//! browser-friendly HTTP response.
//!
//! The adapter:
//!
//! 1. Derives the HTTP status from [`ErrorKind::status`].
//! 2. Sets `X-Corx-Status` to the stable machine-readable identifier.
//! 3. Serialises the [`ErrorPayload`] as JSON.
//!
//! CORS headers are appended afterwards by a dedicated middleware so that
//! cross-origin error responses remain visible to browser callers.

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::HeaderValue;

use corx_core::error::{ProxyError, STATUS_HEADER};

/// Newtype wrapper that lifts a [`ProxyError`] into an `axum::IntoResponse`.
///
/// Handlers should return `Result<Response, ServerError>` and rely on the
/// blanket `From<ProxyError>` conversion so that `?` works transparently:
///
/// ```ignore
/// async fn proxy(...) -> Result<Response, ServerError> {
///     do_work().await?; // do_work returns Result<_, ProxyError>
///     Ok(response)
/// }
/// ```
#[derive(Debug)]
pub struct ServerError(pub ProxyError);

impl<E: Into<ProxyError>> From<E> for ServerError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, payload) = self.0.to_payload();
        tracing::debug!(
            error.kind = payload.error,
            error.detail = %self.0,
            "request failed"
        );

        let mut response = (status, Json(payload)).into_response();
        if let Ok(value) = HeaderValue::from_str(self.0.kind().as_str()) {
            response.headers_mut().insert(STATUS_HEADER, value);
        }
        response
    }
}
