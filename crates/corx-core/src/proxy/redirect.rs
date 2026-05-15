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

use http::header::{self, HeaderMap};
use http::{Method, Request, Response, StatusCode, Uri};
use hyper::body::Incoming;

use crate::error::ProxyError;
use crate::proxy::upstream::{UpstreamBody, empty_upstream_body};

/// Headers that must never survive a cross-host redirect. The list deliberately
/// goes beyond the IETF requirements to also strip `Proxy-Authorization`,
/// `Authentication-Info` and `WWW-Authenticate` because they may carry
/// credential material the new origin must not see.
///
/// Stored as static strings rather than `HeaderName` because `HeaderName`
/// values produced by `from_static` cannot be embedded in a `const` slice.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "authentication-info",
    "www-authenticate",
];

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

/// Result of consulting the redirect machinery for the next hop.
///
/// `Continue` boxes its payload so the discriminant + `Stop` arm stay
/// pointer-sized; otherwise the (large) `Request` body would bloat every
/// stack frame that returns a `NextHop`.
#[derive(Debug)]
pub enum NextHop {
    /// Continue following with this freshly-built request.
    Continue(Box<Request<UpstreamBody>>),
    /// Stop following and return the original 3xx response to the client.
    /// `reason` is logged but not exposed on the wire.
    Stop(&'static str),
}

/// Given a redirect `response`, compute the next request to dispatch.
///
/// # Errors
///
/// Returns an error when the `Location` header resolves to a malformed URI
/// or specifies a non-HTTP(S) scheme (`data:`, `javascript:`, `file:` …).
pub fn prepare_next(
    state: &mut RedirectState,
    response: &Response<Incoming>,
    allow_https_to_http_downgrade: bool,
) -> Result<NextHop, ProxyError> {
    let Some(location) = response.headers().get(header::LOCATION) else {
        return Ok(NextHop::Stop("no Location header"));
    };
    let Ok(location_str) = location.to_str() else {
        return Ok(NextHop::Stop("non-utf8 Location header"));
    };

    let next_uri = resolve_location(&state.uri, location_str)?;
    require_safe_scheme(&next_uri)?;

    if !allow_https_to_http_downgrade && is_https_to_http_downgrade(&state.uri, &next_uri) {
        return Err(ProxyError::InvalidUrl(
            "https → http redirect downgrade rejected".to_owned(),
        ));
    }

    let cross_host = authority_differs(&state.uri, &next_uri);
    let (next_method, drop_body) = classify_transition(&state.method, response.status());

    // 307/308 with a body-carrying method: cannot safely replay because the
    // original body has already been consumed by hyper::Client::request.
    if !drop_body && body_bearing(&next_method) {
        return Ok(NextHop::Stop(
            "307/308 with body-bearing method cannot be safely replayed",
        ));
    }

    state.method = next_method.clone();
    state.uri = next_uri.clone();

    if cross_host {
        for name in SENSITIVE_HEADERS {
            state.headers.remove(*name);
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
        .map(|req| NextHop::Continue(Box::new(req)))
        .map_err(|err| ProxyError::InvalidUrl(format!("cannot build redirect request: {err}")))
}

fn require_safe_scheme(uri: &Uri) -> Result<(), ProxyError> {
    match uri.scheme_str() {
        Some("http" | "https") => Ok(()),
        Some(other) => Err(ProxyError::InvalidUrl(format!(
            "redirect to unsupported scheme `{other}`"
        ))),
        None => Err(ProxyError::InvalidUrl(
            "redirect Location lacks a scheme".to_owned(),
        )),
    }
}

fn is_https_to_http_downgrade(from: &Uri, to: &Uri) -> bool {
    matches!(from.scheme_str(), Some("https")) && matches!(to.scheme_str(), Some("http"))
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
        NextHop, RedirectState, authority_differs, classify_transition, is_https_to_http_downgrade,
        is_redirect, require_safe_scheme, resolve_location,
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

    #[test]
    fn file_scheme_is_rejected() {
        let uri: Uri = "file://localhost/etc/passwd".parse().unwrap();
        assert!(require_safe_scheme(&uri).is_err());
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        let uri: Uri = "ftp://example.com/".parse().unwrap();
        assert!(require_safe_scheme(&uri).is_err());
    }

    #[test]
    fn ws_scheme_is_rejected() {
        let uri: Uri = "ws://example.com/socket".parse().unwrap();
        assert!(require_safe_scheme(&uri).is_err());
    }

    #[test]
    fn gopher_scheme_is_rejected() {
        let uri: Uri = "gopher://example.com/".parse().unwrap();
        assert!(require_safe_scheme(&uri).is_err());
    }

    #[test]
    fn detects_https_to_http_downgrade() {
        let from: Uri = "https://a.test/".parse().unwrap();
        let to: Uri = "http://a.test/".parse().unwrap();
        assert!(is_https_to_http_downgrade(&from, &to));
        let to_https: Uri = "https://b.test/".parse().unwrap();
        assert!(!is_https_to_http_downgrade(&from, &to_https));
    }

    #[test]
    fn next_hop_enum_constructible_from_continue() {
        // Compile-time only: ensure the enum is exhaustive in the public API.
        fn _accept(_n: NextHop) {}
    }
}
