//! Manual redirect handling.
//!
//! Following redirects inside the proxy (rather than propagating them to the
//! client) preserves the CORS invariant: a cross-origin redirect response
//! cannot bypass the allowlist of the initial hop. It also lets us reset
//! sensitive per-origin state (cookies, authorization) on cross-host hops.
//!
//! [`RedirectState`] captures everything needed to synthesise the next hop
//! from an upstream `Location` header without needing access to the already-
//! consumed request body.

use http::header::{self, HeaderMap, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri};
use hyper::body::Incoming;

use crate::error::ProxyError;
use crate::proxy::upstream::{UpstreamBody, empty_upstream_body};

/// Headers that must never survive a cross-host redirect.
const SENSITIVE_HEADERS: &[HeaderName] = &[header::AUTHORIZATION, header::COOKIE];

/// Captured state from the initial request, used to rebuild follow-up
/// requests after each redirect hop.
#[derive(Debug, Clone)]
pub struct RedirectState {
    /// The original HTTP method (before any downgrade).
    pub method: Method,
    /// Headers that should be inherited by every hop until stripped.
    pub headers: HeaderMap,
    /// Current URI for the next hop.
    pub uri: Uri,
}

impl RedirectState {
    /// Constructs state from the initial request. Cloning the header map is
    /// unavoidable because the original request will be consumed by hyper on
    /// the first call.
    #[must_use]
    pub const fn from_initial(method: Method, uri: Uri, headers: HeaderMap) -> Self {
        Self {
            method,
            headers,
            uri,
        }
    }
}

/// Returns `true` for 3xx status codes we are willing to follow.
#[must_use]
pub const fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// Given a redirect `response`, compute the next request to dispatch.
///
/// Returns `Ok(None)` when the response does not carry a usable `Location`,
/// or when the follow-up would require a request body that we have already
/// discarded (307/308 after a `POST`/`PUT`/`PATCH`).
///
/// # Errors
///
/// Returns an error when the `Location` header resolves to a malformed URI.
pub fn prepare_next(
    state: &mut RedirectState,
    response: &Response<Incoming>,
) -> Result<Option<Request<UpstreamBody>>, ProxyError> {
    let Some(location) = response.headers().get(header::LOCATION) else {
        return Ok(None);
    };
    let Ok(location_str) = location.to_str() else {
        return Ok(None);
    };

    let next_uri = resolve_location(&state.uri, location_str)?;
    let cross_host = authority_differs(&state.uri, &next_uri);

    let (next_method, drop_body) = classify_transition(&state.method, response.status());

    // 307/308 with a body-carrying method: cannot safely replay because the
    // original body has already been consumed by hyper::Client::request.
    if !drop_body && body_bearing(&next_method) {
        return Ok(None);
    }

    state.method = next_method.clone();
    state.uri = next_uri.clone();

    if cross_host {
        for name in SENSITIVE_HEADERS {
            state.headers.remove(name);
        }
        // Host will be recomputed by hyper from the URI authority.
        state.headers.remove(header::HOST);
    }

    let mut builder = Request::builder().method(next_method).uri(next_uri);
    if let Some(headers) = builder.headers_mut() {
        headers.extend(state.headers.clone());
    }

    let body = empty_upstream_body();

    builder
        .body(body)
        .map(Some)
        .map_err(|err| ProxyError::InvalidUrl(format!("cannot build redirect request: {err}")))
}

fn resolve_location(base: &Uri, location: &str) -> Result<Uri, ProxyError> {
    if location.contains("://") {
        return location
            .parse()
            .map_err(|err| ProxyError::InvalidUrl(format!("invalid redirect target: {err}")));
    }

    let base_url = uri_to_url(base)?;
    let resolved = base_url
        .join(location)
        .map_err(|err| ProxyError::InvalidUrl(format!("cannot resolve redirect: {err}")))?;
    resolved
        .as_str()
        .parse()
        .map_err(|err| ProxyError::InvalidUrl(format!("invalid resolved redirect: {err}")))
}

fn uri_to_url(uri: &Uri) -> Result<url::Url, ProxyError> {
    url::Url::parse(&uri.to_string())
        .map_err(|err| ProxyError::InvalidUrl(format!("uri-to-url failed: {err}")))
}

fn classify_transition(method: &Method, status: StatusCode) -> (Method, bool) {
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
            if body_bearing(method) {
                (Method::GET, true)
            } else {
                (method.clone(), false)
            }
        }
        _ => (method.clone(), false),
    }
}

const fn body_bearing(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH)
}

fn authority_differs(a: &Uri, b: &Uri) -> bool {
    match (a.authority(), b.authority()) {
        (Some(x), Some(y)) => !x.as_str().eq_ignore_ascii_case(y.as_str()),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method, StatusCode, Uri};

    use super::{
        RedirectState, authority_differs, classify_transition, is_redirect, resolve_location,
    };

    #[test]
    fn is_redirect_matches_expected_statuses() {
        assert!(is_redirect(StatusCode::MOVED_PERMANENTLY));
        assert!(is_redirect(StatusCode::FOUND));
        assert!(is_redirect(StatusCode::SEE_OTHER));
        assert!(is_redirect(StatusCode::TEMPORARY_REDIRECT));
        assert!(is_redirect(StatusCode::PERMANENT_REDIRECT));
        assert!(!is_redirect(StatusCode::OK));
        assert!(!is_redirect(StatusCode::NOT_MODIFIED));
    }

    #[test]
    fn post_downgrades_to_get_on_303() {
        let (method, drop_body) = classify_transition(&Method::POST, StatusCode::SEE_OTHER);
        assert_eq!(method, Method::GET);
        assert!(drop_body);
    }

    #[test]
    fn get_stays_get_on_308() {
        let (method, drop_body) = classify_transition(&Method::GET, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(method, Method::GET);
        assert!(!drop_body);
    }

    #[test]
    fn relative_redirect_is_resolved_against_base() {
        let base: Uri = "http://a.test/foo/bar".parse().unwrap();
        let next = resolve_location(&base, "/baz").unwrap();
        assert_eq!(next.to_string(), "http://a.test/baz");
    }

    #[test]
    fn absolute_redirect_is_returned_verbatim() {
        let base: Uri = "http://a.test/".parse().unwrap();
        let next = resolve_location(&base, "https://b.test/path").unwrap();
        assert_eq!(next.to_string(), "https://b.test/path");
    }

    #[test]
    fn authority_comparison_is_case_insensitive() {
        let a: Uri = "http://A.Test/".parse().unwrap();
        let b: Uri = "http://a.test/".parse().unwrap();
        assert!(!authority_differs(&a, &b));
    }

    #[test]
    fn state_constructor_preserves_inputs() {
        let state = RedirectState::from_initial(
            Method::POST,
            Uri::from_static("http://a.test/"),
            HeaderMap::new(),
        );
        assert_eq!(state.method, Method::POST);
        assert_eq!(state.uri.to_string(), "http://a.test/");
        assert!(state.headers.is_empty());
    }
}
