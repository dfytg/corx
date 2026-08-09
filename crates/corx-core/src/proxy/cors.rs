//! CORS policy implementation (v2).
//!
//! This module produces the response headers required to satisfy the CORS
//! protocol on every reply leaving the proxy:
//!
//! * **Preflights** — a synthetic `204 No Content` response with the full
//!   `Access-Control-Allow-{Origin,Methods,Headers}` triple, the configured
//!   `Access-Control-Max-Age`, and — when [`CorsConfig::allow_private_network`]
//!   is on — the Private Network Access (PNA) handshake.
//! * **Real responses** — the upstream's headers are replaced by the
//!   policy-derived values so browsers cannot be confused by conflicting
//!   instructions from the upstream.
//! * **Error responses** — the same headers are stamped onto the JSON error
//!   payloads constructed in [`crate::error`] so cross-origin failures stay
//!   readable to the calling browser.
//!
//! All three paths route through [`apply_to_response`] to keep the policy
//! in one place.

use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Empty;

use crate::config::{CorsConfig, CorsPolicyKind};
use crate::util::OriginSet;

/// Header used by browsers to opt into Private Network Access preflights
/// when the page origin is on a more-private network than the target.
const ACR_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-request-private-network");
const ACA_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-allow-private-network");

/// Response body type used for short-lived responses constructed inside this module.
pub type StaticBody = Empty<Bytes>;

/// Compiled CORS policy ready to be applied to responses.
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    mode: PolicyMode,
    allowed_methods: Option<HeaderValue>,
    allowed_headers: Option<HeaderValue>,
    exposed_headers: Option<HeaderValue>,
    max_age_value: Option<HeaderValue>,
    allow_credentials: bool,
    allow_private_network: bool,
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
                if !cfg.origins.is_empty() {
                    PolicyMode::Reflect(Some(to_origin_set(&cfg.origins)))
                } else if cfg.allow_any_origin {
                    // Empty origins + allow_any_origin: echo any Origin.
                    PolicyMode::Reflect(None)
                } else {
                    // Fail-closed: empty gate rejects every Origin.
                    PolicyMode::Reflect(Some(to_origin_set(&[])))
                }
            }
            CorsPolicyKind::Explicit => PolicyMode::Explicit(to_origin_set(&cfg.origins)),
        };

        Self {
            mode,
            allowed_methods: encode_token_list(&cfg.allowed_methods),
            allowed_headers: encode_token_list(&cfg.allowed_headers),
            exposed_headers: encode_token_list(&cfg.exposed_headers),
            max_age_value: encode_max_age(cfg.max_age),
            allow_credentials: cfg.allow_credentials,
            allow_private_network: cfg.allow_private_network,
        }
    }

    /// Returns `true` when the policy is willing to emit credentials for
    /// cross-origin requests. Used by handlers to mirror state into other
    /// response paths.
    #[must_use]
    pub const fn allow_credentials(&self) -> bool {
        self.allow_credentials
    }

    /// Resolves the `Access-Control-Allow-Origin` value to use for a given
    /// request. Returns `None` when the request origin is not permitted.
    ///
    /// Browsers reject `Access-Control-Allow-Origin: *` together with
    /// `Access-Control-Allow-Credentials: true`; whenever credentials are on
    /// we therefore reflect the request origin (degraded wildcard) so that
    /// the response remains semantically valid.
    fn resolve_allow_origin(&self, request_origin: Option<&HeaderValue>) -> Option<HeaderValue> {
        match &self.mode {
            PolicyMode::Wildcard => {
                if self.allow_credentials {
                    request_origin
                        .and_then(|value| value.to_str().ok())
                        .and_then(|s| HeaderValue::from_str(s).ok())
                } else {
                    Some(HeaderValue::from_static("*"))
                }
            }
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
    values.iter().cloned().collect()
}

/// Build a `204 No Content` response to a CORS preflight request.
#[must_use]
pub fn build_preflight_response<B>(req: &Request<B>, policy: &CorsPolicy) -> Response<StaticBody> {
    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|_| Response::new(Empty::<Bytes>::new()));

    let request_headers = req.headers();
    let response_headers = response.headers_mut();

    apply_cors_base(response_headers, request_headers, policy);

    // Allowed methods: the configured allowlist takes precedence over echoing
    // the request method. Echoing only happens when the operator left the
    // list empty (a deliberate "trust the upstream" stance).
    if let Some(value) = policy.allowed_methods.as_ref() {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value.clone());
    } else if let Some(acrm) = request_headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)
        && let Ok(value) = HeaderValue::from_bytes(acrm.as_bytes())
    {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
    }

    // Allowed headers follow the same logic.
    if let Some(value) = policy.allowed_headers.as_ref() {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value.clone());
    } else if let Some(acrh) = request_headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        && let Ok(value) = HeaderValue::from_bytes(acrh.as_bytes())
    {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
    }

    if let Some(value) = policy.max_age_value.as_ref() {
        response_headers.insert(header::ACCESS_CONTROL_MAX_AGE, value.clone());
    }

    // Private Network Access handshake (Chromium et al.).
    if policy.allow_private_network && request_headers.get(&ACR_PRIVATE_NETWORK).is_some() {
        response_headers.insert(ACA_PRIVATE_NETWORK, HeaderValue::from_static("true"));
    }

    // Preflights vary on the request method and headers in addition to origin.
    append_vary(response_headers, "access-control-request-method");
    append_vary(response_headers, "access-control-request-headers");

    response
}

/// Apply CORS headers to a non-preflight upstream response.
///
/// Existing CORS headers produced by the upstream are replaced with values
/// derived from the configured policy, preventing conflicts that browsers
/// reject.
pub fn apply_to_response<B>(
    response: &mut Response<B>,
    request_headers: &HeaderMap,
    policy: &CorsPolicy,
) {
    let response_headers = response.headers_mut();
    apply_cors_base(response_headers, request_headers, policy);
    if let Some(value) = policy.exposed_headers.as_ref() {
        response_headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value.clone());
    }
}

/// Apply CORS headers to a synthesised error response.
///
/// Keeps cross-origin error payloads visible to the browser. Mirrors
/// [`apply_to_response`] but is exposed under a distinct name so call
/// sites read clearly.
pub fn apply_to_error_response<B>(
    response: &mut Response<B>,
    request_headers: &HeaderMap,
    policy: &CorsPolicy,
) {
    apply_to_response(response, request_headers, policy);
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
        // Origin not admitted — still record `Vary: origin` so caches do not
        // serve a stale allow-origin response to a different caller.
        append_vary(response_headers, "origin");
        return;
    };

    response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);

    if policy.allow_credentials {
        response_headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    // Always Vary on Origin so caches behave correctly. The previous
    // wildcard-only fast path leaked behaviour when a future config reload
    // narrowed the policy.
    append_vary(response_headers, "origin");
}

fn encode_token_list(values: &[String]) -> Option<HeaderValue> {
    if values.is_empty() {
        return None;
    }
    let joined = values.join(", ");
    HeaderValue::from_str(&joined).ok()
}

fn encode_max_age(duration: Duration) -> Option<HeaderValue> {
    let secs = duration.as_secs();
    HeaderValue::from_str(&secs.to_string()).ok()
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

    use super::{CorsPolicy, apply_to_response, build_preflight_response, is_preflight};
    use crate::config::{CorsConfig, CorsPolicyKind};

    fn policy(kind: CorsPolicyKind, origins: Vec<String>, allow_any_origin: bool) -> CorsPolicy {
        CorsPolicy::from_config(&CorsConfig {
            policy: kind,
            origins,
            allow_any_origin,
            allowed_methods: vec!["GET".into(), "POST".into(), "OPTIONS".into()],
            allowed_headers: vec!["content-type".into()],
            exposed_headers: vec!["x-corx-status".into()],
            max_age: std::time::Duration::from_mins(10),
            allow_credentials: false,
            allow_private_network: false,
        })
    }

    fn request(
        http_method: Method,
        origin: Option<&str>,
        preflight_method: Option<&str>,
    ) -> Request<()> {
        let mut builder = Request::builder().method(http_method).uri("/");
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(preflight) = preflight_method {
            builder = builder.header("access-control-request-method", preflight);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn wildcard_returns_star() {
        let pol = policy(CorsPolicyKind::Wildcard, vec![], false);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[test]
    fn reflect_with_allow_any_origin_echoes() {
        let pol = policy(CorsPolicyKind::Reflect, vec![], true);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://app.test"
        );
        assert_eq!(resp.headers().get("vary").unwrap(), "origin");
    }

    #[test]
    fn reflect_fail_closed_without_origins_or_flag() {
        let pol = policy(CorsPolicyKind::Reflect, vec![], false);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[test]
    fn reflect_with_origins_gates() {
        let pol = policy(
            CorsPolicyKind::Reflect,
            vec!["https://good.test".into()],
            false,
        );
        let req = request(Method::GET, Some("https://bad.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[test]
    fn explicit_only_matches_configured() {
        let pol = policy(
            CorsPolicyKind::Explicit,
            vec!["https://ok.test".into()],
            false,
        );
        let req_ok = request(Method::GET, Some("https://ok.test"), None);
        let mut resp_ok = http::Response::new(());
        apply_to_response(&mut resp_ok, req_ok.headers(), &pol);
        assert_eq!(
            resp_ok
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://ok.test"
        );

        let req_bad = request(Method::GET, Some("https://x.test"), None);
        let mut resp_bad = http::Response::new(());
        apply_to_response(&mut resp_bad, req_bad.headers(), &pol);
        assert!(
            resp_bad
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[test]
    fn preflight_uses_configured_allowed_methods() {
        let pol = policy(CorsPolicyKind::Wildcard, vec![], false);
        let req = request(Method::OPTIONS, Some("https://a.test"), Some("POST"));
        assert!(is_preflight(&req));
        let resp = build_preflight_response(&req, &pol);
        assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("access-control-allow-methods").unwrap(),
            "GET, POST, OPTIONS"
        );
        assert_eq!(
            resp.headers().get("access-control-allow-headers").unwrap(),
            "content-type"
        );
        assert_eq!(resp.headers().get("access-control-max-age").unwrap(), "600");
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(vary.contains("origin"), "vary must contain origin: {vary}");
        assert!(
            vary.contains("access-control-request-method"),
            "vary must contain ACR-Method: {vary}"
        );
    }

    #[test]
    fn exposed_headers_are_emitted_on_real_response() {
        let pol = policy(CorsPolicyKind::Reflect, vec![], true);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert_eq!(
            resp.headers().get("access-control-expose-headers").unwrap(),
            "x-corx-status"
        );
    }

    #[test]
    fn pna_handshake_replies_when_enabled() {
        let mut cfg = CorsConfig {
            policy: CorsPolicyKind::Wildcard,
            origins: vec![],
            allow_any_origin: false,
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["content-type".into()],
            exposed_headers: vec![],
            max_age: std::time::Duration::from_mins(1),
            allow_credentials: false,
            allow_private_network: true,
        };
        let pol = CorsPolicy::from_config(&cfg);
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header("origin", "https://app.test")
            .header("access-control-request-method", "GET")
            .header("access-control-request-private-network", "true")
            .body(())
            .unwrap();
        let resp = build_preflight_response(&req, &pol);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-private-network")
                .unwrap(),
            "true"
        );

        // PNA defaults to off.
        cfg.allow_private_network = false;
        let pol_off = CorsPolicy::from_config(&cfg);
        let resp_off = build_preflight_response(&req, &pol_off);
        assert!(
            resp_off
                .headers()
                .get("access-control-allow-private-network")
                .is_none()
        );
    }

    #[test]
    fn wildcard_with_credentials_falls_back_to_origin_echo() {
        let mut cfg = CorsConfig {
            policy: CorsPolicyKind::Wildcard,
            origins: vec![],
            allow_any_origin: false,
            allowed_methods: vec![],
            allowed_headers: vec![],
            exposed_headers: vec![],
            max_age: std::time::Duration::from_mins(1),
            allow_credentials: true,
            allow_private_network: false,
        };
        let pol = CorsPolicy::from_config(&cfg);
        let req = request(Method::GET, Some("https://app.test"), None);
        let mut resp = http::Response::new(());
        apply_to_response(&mut resp, req.headers(), &pol);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://app.test"
        );
        assert_eq!(
            resp.headers()
                .get("access-control-allow-credentials")
                .unwrap(),
            "true"
        );
        // sanity: the wildcard branch still hits when credentials are off
        cfg.allow_credentials = false;
        let pol_no_creds = CorsPolicy::from_config(&cfg);
        let mut resp2 = http::Response::new(());
        apply_to_response(&mut resp2, req.headers(), &pol_no_creds);
        assert_eq!(
            resp2.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }
}
