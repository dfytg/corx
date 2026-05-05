//! CORS policy implementation.
//!
//! This module produces the response headers required to satisfy the CORS
//! protocol on both preflight (`OPTIONS`) and actual responses. The set of
//! admitted origins is driven by [`CorsPolicy`], a compiled representation of
//! the operator-supplied configuration.

use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use foldhash::fast::RandomState;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Empty;

use crate::config::{CorsConfig, CorsPolicyKind};

type OriginSet = HashSet<String, RandomState>;

/// Response body type used for short-lived responses constructed inside this module.
pub type StaticBody = Empty<Bytes>;

/// Compiled CORS policy ready to be applied to responses.
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    mode: PolicyMode,
    max_age: Duration,
    allow_credentials: bool,
}

#[derive(Debug, Clone)]
enum PolicyMode {
    Wildcard,
    Reflect(Option<OriginSet>),
    Explicit(OriginSet),
}

impl CorsPolicy {
    /// Compiles the operator-provided [`CorsConfig`] into a dispatch-ready policy.
    #[must_use]
    pub fn from_config(cfg: &CorsConfig) -> Self {
        let mode = match cfg.policy {
            CorsPolicyKind::Wildcard => PolicyMode::Wildcard,
            CorsPolicyKind::Reflect => {
                let set = if cfg.allowlist.is_empty() {
                    None
                } else {
                    Some(to_origin_set(&cfg.allowlist))
                };
                PolicyMode::Reflect(set)
            }
            CorsPolicyKind::Explicit => PolicyMode::Explicit(to_origin_set(&cfg.explicit)),
        };

        Self {
            mode,
            max_age: cfg.max_age,
            allow_credentials: cfg.allow_credentials,
        }
    }

    /// Resolves the `Access-Control-Allow-Origin` value to use for a given
    /// request. Returns `None` when the request origin is not permitted.
    fn resolve_allow_origin(&self, request_origin: Option<&HeaderValue>) -> Option<HeaderValue> {
        match &self.mode {
            PolicyMode::Wildcard => Some(HeaderValue::from_static("*")),
            PolicyMode::Reflect(allow) => {
                let origin = request_origin?.to_str().ok()?;
                match allow {
                    Some(set) if set.contains(origin) => HeaderValue::from_str(origin).ok(),
                    Some(_) => None,
                    None => HeaderValue::from_str(origin).ok(),
                }
            }
            PolicyMode::Explicit(set) => {
                let origin = request_origin?.to_str().ok()?;
                if set.contains(origin) {
                    HeaderValue::from_str(origin).ok()
                } else {
                    None
                }
            }
        }
    }
}

fn to_origin_set(values: &[String]) -> OriginSet {
    let mut set = OriginSet::with_capacity_and_hasher(values.len(), RandomState::default());
    for value in values {
        set.insert(value.clone());
    }
    set
}

/// Build a `204 No Content` response to a CORS preflight request.
#[must_use]
pub fn build_preflight_response<B>(req: &Request<B>, policy: &CorsPolicy) -> Response<StaticBody> {
    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|_| Response::new(Empty::<Bytes>::new()));

    apply_cors_base(response.headers_mut(), req.headers(), policy);

    let request_headers = req.headers();

    if let Some(acrm) = request_headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)
        && let Ok(value) = HeaderValue::from_bytes(acrm.as_bytes())
    {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
    }

    if let Some(acrh) = request_headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        && let Ok(value) = HeaderValue::from_bytes(acrh.as_bytes())
    {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
    }

    if let Ok(value) = HeaderValue::from_str(&policy.max_age.as_secs().to_string()) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_MAX_AGE, value);
    }

    response
}

/// Apply CORS headers to a non-preflight upstream response.
///
/// Existing CORS headers produced by the upstream are replaced with values
/// derived from the configured policy, preventing conflicts that browsers
/// reject.
pub fn apply_response_headers<B>(
    response: &mut Response<B>,
    request: &Request<impl Sized>,
    policy: &CorsPolicy,
) {
    apply_cors_base(response.headers_mut(), request.headers(), policy);
    response.headers_mut().insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("*"),
    );
}

/// Determine whether the request is a CORS preflight.
#[must_use]
pub fn is_preflight<B>(request: &Request<B>) -> bool {
    request.method() == Method::OPTIONS
        && request.headers().contains_key(header::ORIGIN)
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn apply_cors_base(
    response_headers: &mut HeaderMap,
    request_headers: &HeaderMap,
    policy: &CorsPolicy,
) {
    let origin = request_headers.get(header::ORIGIN);
    let Some(allow_origin) = policy.resolve_allow_origin(origin) else {
        return;
    };

    response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);

    if policy.allow_credentials {
        response_headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    // Vary on Origin whenever the response depends on it so caches behave correctly.
    match &policy.mode {
        PolicyMode::Wildcard => {}
        PolicyMode::Reflect(_) | PolicyMode::Explicit(_) => {
            append_vary(response_headers, "origin");
        }
    }
}

fn append_vary(headers: &mut HeaderMap, value: &'static str) {
    let header_name: HeaderName = header::VARY;
    match headers.get(&header_name) {
        Some(existing) => {
            let Ok(existing) = existing.to_str() else {
                return;
            };
            if existing
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case(value))
            {
                return;
            }
            let combined = format!("{existing}, {value}");
            if let Ok(header_value) = HeaderValue::from_str(&combined) {
                headers.insert(header_name, header_value);
            }
        }
        None => {
            headers.insert(header_name, HeaderValue::from_static(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{Method, Request};

    use super::{CorsPolicy, apply_response_headers, build_preflight_response, is_preflight};
    use crate::config::{CorsConfig, CorsPolicyKind};

    fn policy(kind: CorsPolicyKind, allowlist: Vec<String>, explicit: Vec<String>) -> CorsPolicy {
        CorsPolicy::from_config(&CorsConfig {
            policy: kind,
            allowlist,
            explicit,
            max_age: std::time::Duration::from_mins(10),
            allow_credentials: false,
        })
    }

    fn request(
        method: Method,
        origin: Option<&str>,
        preflight_method: Option<&str>,
    ) -> Request<()> {
        let mut builder = Request::builder().method(method).uri("/");
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(method) = preflight_method {
            builder = builder.header("access-control-request-method", method);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn wildcard_returns_star() {
        let pol = policy(CorsPolicyKind::Wildcard, vec![], vec![]);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_response_headers(&mut resp, &req, &pol);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[test]
    fn reflect_without_allowlist_echoes_origin() {
        let pol = policy(CorsPolicyKind::Reflect, vec![], vec![]);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_response_headers(&mut resp, &req, &pol);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://app.test"
        );
        assert_eq!(resp.headers().get("vary").unwrap(), "origin");
    }

    #[test]
    fn reflect_with_allowlist_gates_origins() {
        let pol = policy(
            CorsPolicyKind::Reflect,
            vec!["https://good.test".into()],
            vec![],
        );
        let req = request(Method::GET, Some("https://bad.test"), None);
        let mut resp = http::Response::new(());
        apply_response_headers(&mut resp, &req, &pol);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[test]
    fn explicit_only_matches_configured() {
        let pol = policy(
            CorsPolicyKind::Explicit,
            vec![],
            vec!["https://ok.test".into()],
        );
        let req_ok = request(Method::GET, Some("https://ok.test"), None);
        let mut resp_ok = http::Response::new(());
        apply_response_headers(&mut resp_ok, &req_ok, &pol);
        assert_eq!(
            resp_ok
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://ok.test"
        );

        let req_bad = request(Method::GET, Some("https://x.test"), None);
        let mut resp_bad = http::Response::new(());
        apply_response_headers(&mut resp_bad, &req_bad, &pol);
        assert!(
            resp_bad
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[test]
    fn preflight_mirrors_method_and_max_age() {
        let pol = policy(CorsPolicyKind::Wildcard, vec![], vec![]);
        let req = request(Method::OPTIONS, Some("https://a.test"), Some("POST"));
        assert!(is_preflight(&req));
        let resp = build_preflight_response(&req, &pol);
        assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("access-control-allow-methods").unwrap(),
            "POST"
        );
        assert_eq!(resp.headers().get("access-control-max-age").unwrap(), "600");
    }
}
