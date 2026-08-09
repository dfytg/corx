//! Optional bearer-token authentication for proxy traffic.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use corx_core::config::AuthMode;
use corx_core::error::ProxyError;
use http::Method;
use http::header::{AUTHORIZATION, HeaderMap};

use crate::error::ServerError;
use crate::router::AppState;

/// Enforce `security.auth` when mode is Bearer.
///
/// Skips: operational endpoints, CORS preflight (`OPTIONS`), and when mode is
/// `none`. Browsers do not attach `Authorization` to preflights by default.
pub async fn auth_layer(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS || is_ops_path(request.uri().path(), &state) {
        return next.run(request).await;
    }

    let policies = state.build.policies();
    let auth = &policies.config.security.auth;
    if auth.mode != AuthMode::Bearer {
        drop(policies);
        return next.run(request).await;
    }

    match check_bearer(request.headers(), &auth.bearer_tokens) {
        Ok(()) => {
            drop(policies);
            next.run(request).await
        }
        Err(err) => ServerError::from(err).into_response(),
    }
}

fn is_ops_path(path: &str, state: &AppState) -> bool {
    matches!(
        path,
        "/" | "/livez" | "/readyz" | "/healthz" | "/iscorsneeded"
    ) || {
        let metrics = state.build.immutable_metrics_endpoint.as_str();
        !metrics.is_empty() && path == metrics
    }
}

fn check_bearer(headers: &HeaderMap, tokens: &[String]) -> Result<(), ProxyError> {
    let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return Err(ProxyError::Unauthorized("missing Authorization header"));
    };
    let Some(presented) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return Err(ProxyError::Unauthorized("expected Bearer scheme"));
    };

    // Constant-time-ish compare across all tokens to avoid early exit leaks.
    let presented = presented.as_bytes();
    let mut matched = false;
    for token in tokens {
        if ct_eq(presented, token.as_bytes()) {
            matched = true;
        }
    }
    if matched {
        Ok(())
    } else {
        Err(ProxyError::Unauthorized("invalid bearer token"))
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn accepts_matching_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        assert!(check_bearer(&headers, &["secret".into()]).is_ok());
    }

    #[test]
    fn rejects_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer nope"));
        assert!(check_bearer(&headers, &["secret".into()]).is_err());
    }

    #[test]
    fn rejects_missing() {
        assert!(check_bearer(&HeaderMap::new(), &["secret".into()]).is_err());
    }
}
