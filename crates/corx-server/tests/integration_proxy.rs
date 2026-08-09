#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    reason = "Integration-test binaries see every dev-dep of `corx-server` \
              but only use a handful; cargo's integration test convention \
              places #[test] functions at the module root rather than \
              under #[cfg(test)]; unwrap/expect are acceptable test wiring."
)]

//! End-to-end integration tests for the corx proxy, exercising the full
//! axum router stack.
//!
//! These tests stand up:
//!
//! * a `wiremock` upstream so we can assert what corx forwarded;
//! * a fully assembled corx [`AppState`] / [`build_router`] stack with a
//!   tweaked configuration;
//! * `tower::ServiceExt::oneshot` to drive requests through the router as
//!   if they came from a real client.
//!
//! Hot-path semantics covered here:
//!
//! 1. CORS preflight short-circuit returns 204 with the expected headers.
//! 2. Simple proxy forwards the body and reflects the upstream response.
//! 3. SSRF guard blocks loopback by default and allows it via
//!    `extra_allowed_cidrs`.
//! 4. Origin guard 403s requests whose Origin is on the blacklist.
//! 5. Forwarded / X-Forwarded-* / X-Request-Id are stamped onto the
//!    outbound request.
//! 6. `/livez` and `/readyz` follow the readiness contract.

use std::net::SocketAddr;
use std::sync::Once;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, StatusCode, header};
use corx_core::config::{Config, SsrfMode};
use corx_server::observability::MetricsHandle;
use corx_server::{AppState, ServerBuild, build_router};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `oneshot` does not run the listener, so we have to fabricate the
/// `ConnectInfo<SocketAddr>` extension ourselves. The access-log layer (and
/// the proxy handler) extract it; without one they would 500 with a
/// "missing extension" error before any of our assertions ran.
///
/// We also stamp a default `Origin` header because the production default
/// configuration sets `security.require_header = ["origin"]` to refuse
/// being addressed as a generic open proxy. Tests that exercise the
/// require-header policy itself should override the header explicitly.
fn with_peer(builder: http::request::Builder) -> Request<Body> {
    let already_has_origin = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key(header::ORIGIN));
    let builder = if already_has_origin {
        builder
    } else {
        builder.header(header::ORIGIN, "https://test.local")
    };
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:54321".parse().unwrap(),
    ));
    request
}

fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a router fronted by a default-ish config plus the supplied
/// mutator. Returning the [`MockServer`] lets each test assert on the
/// upstream side.
fn make_stack(mutator: impl FnOnce(&mut Config)) -> (axum::Router, MockServer) {
    ensure_crypto_provider();
    // Synchronous mock-server bootstrap is fine because tokio is already
    // running under `#[tokio::test]`.
    let mock = futures::executor::block_on(MockServer::start());

    let mut config = Config::default();
    // Allow the loopback the mock binds to; SSRF default rejects 127/8.
    config.ssrf.mode = SsrfMode::Strict;
    config
        .ssrf
        .extra_allowed_cidrs
        .push("127.0.0.0/8".parse().unwrap());
    // Tests expect reflect-any CORS (cors-anywhere style); production
    // defaults are fail-closed (`allow_any_origin = false`).
    config.cors.allow_any_origin = true;
    // Circuit breaker would trip under tight unit failure bursts; keep on
    // but with a high threshold so happy-path tests are not flaky.
    config.circuit_breaker.failure_threshold = 10_000;
    // Isolation: disable GCRA so concurrent tests do not share process
    // budgets (limiter state is per ServerBuild, but keep headroom clear).
    config.rate_limit.enabled = false;

    mutator(&mut config);

    let metrics = MetricsHandle::for_test();
    let build = ServerBuild::from_config(config, metrics).expect("build server");
    let router = build_router(AppState::new(build));
    (router, mock)
}

fn upstream_url(mock: &MockServer, path_and_query: &str) -> String {
    format!(
        "/{base}{rest}",
        base = mock.uri().trim_end_matches('/'),
        rest = path_and_query
    )
}

#[tokio::test]
async fn livez_always_reports_healthy() {
    let (router, _mock) = make_stack(|_| {});
    let response = router
        .oneshot(with_peer(Request::builder().uri("/livez")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_starts_ready() {
    let (router, _mock) = make_stack(|_| {});
    let response = router
        .oneshot(with_peer(Request::builder().uri("/readyz")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_returns_204_with_allow_headers() {
    let (router, mock) = make_stack(|_| {});
    let request = with_peer(
        Request::builder()
            .method("OPTIONS")
            .uri(upstream_url(&mock, "/foo"))
            .header(header::ORIGIN, "https://app.example.com")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-custom"),
    );
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let allow_origin = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("allow-origin");
    // Default policy is `reflect`, so the preflight echoes the request
    // origin back rather than emitting `*`.
    assert_eq!(
        allow_origin,
        &HeaderValue::from_static("https://app.example.com")
    );
    // The preflight should also tell the client which methods and headers
    // are negotiable.
    assert!(
        response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
    );
    assert!(
        response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_HEADERS)
    );
}

#[tokio::test]
async fn simple_proxy_forwards_response_body() {
    let (router, mock) = make_stack(|_| {});
    Mock::given(method("GET"))
        .and(path("/payload"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock)
        .await;

    let uri = upstream_url(&mock, "/payload");
    let response = router
        .oneshot(with_peer(Request::builder().uri(&uri)))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"pong");
}

#[tokio::test]
async fn ssrf_blocks_loopback_hostname_when_not_allow_listed() {
    // Drop the test-only loopback allow-list so the production-grade
    // strict guard takes over.
    let (router, mock) = make_stack(|cfg| {
        cfg.ssrf.extra_allowed_cidrs.clear();
    });
    // Target the mock by hostname rather than by IP literal so the
    // request flows through corx's GuardedResolver. A DNS-resolved
    // `localhost` lands in `127.0.0.1` which the default block-list
    // refuses.
    let mock_uri = mock.uri();
    let mock_port = mock_uri.rsplit_once(':').map_or("", |(_, p)| p);
    let target = format!("/http://localhost:{mock_port}/x");
    let response = router
        .oneshot(with_peer(Request::builder().uri(target)))
        .await
        .unwrap();
    let status = response.status();
    // Either the SSRF guard intercepted the resolver result (HTTP 403) or
    // the upstream connection failed because no admissible address
    // remained (HTTP 502). Both outcomes mean the proxy refused to
    // contact the loopback target, which is what the test verifies.
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::BAD_GATEWAY,),
        "expected 403/502 for blocked loopback hostname, got {status}",
    );
}

#[tokio::test]
async fn origin_blacklist_rejects_listed_origin() {
    let (router, mock) = make_stack(|cfg| {
        cfg.security
            .origin_blacklist
            .push("https://blocked.example.com".into());
    });
    let response = router
        .oneshot(with_peer(
            Request::builder()
                .uri(upstream_url(&mock, "/x"))
                .header(header::ORIGIN, "https://blocked.example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn origin_blacklist_rejects_preflight_by_default() {
    let (router, mock) = make_stack(|cfg| {
        cfg.security
            .origin_blacklist
            .push("https://blocked.example.com".into());
    });
    let response = router
        .oneshot(with_peer(
            Request::builder()
                .method("OPTIONS")
                .uri(upstream_url(&mock, "/x"))
                .header(header::ORIGIN, "https://blocked.example.com")
                .header("access-control-request-method", "GET"),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "preflight must not bypass origin guards when security.preflight.mode=enforce"
    );
}

#[tokio::test]
async fn preflight_open_mode_skips_origin_guard() {
    use corx_core::config::PreflightMode;
    let (router, mock) = make_stack(|cfg| {
        cfg.security
            .origin_blacklist
            .push("https://blocked.example.com".into());
        cfg.security.preflight.mode = PreflightMode::Open;
    });
    let response = router
        .oneshot(with_peer(
            Request::builder()
                .method("OPTIONS")
                .uri(upstream_url(&mock, "/x"))
                .header(header::ORIGIN, "https://blocked.example.com")
                .header("access-control-request-method", "GET"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn oversized_headers_return_431() {
    let (router, mock) = make_stack(|cfg| {
        cfg.limits.max_request_header_bytes = 64;
    });
    let huge = "x".repeat(200);
    let response = router
        .oneshot(with_peer(
            Request::builder()
                .uri(upstream_url(&mock, "/x"))
                .header("x-big", huge),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
}

#[tokio::test]
async fn target_allowlist_rejects_other_hosts() {
    use corx_core::config::TargetMode;
    let (router, mock) = make_stack(|cfg| {
        cfg.target.mode = TargetMode::Allowlist;
        cfg.target.hosts = vec!["allowed.example".into()];
    });
    let response = router
        .oneshot(with_peer(Request::builder().uri(upstream_url(&mock, "/x"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bearer_auth_rejects_without_token() {
    use corx_core::config::AuthMode;
    let (router, mock) = make_stack(|cfg| {
        cfg.security.auth.mode = AuthMode::Bearer;
        cfg.security.auth.bearer_tokens = vec!["s3cret".into()];
    });
    let response = router
        .oneshot(with_peer(Request::builder().uri(upstream_url(&mock, "/x"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_auth_accepts_valid_token() {
    use corx_core::config::AuthMode;
    let (router, mock) = make_stack(|cfg| {
        cfg.security.auth.mode = AuthMode::Bearer;
        cfg.security.auth.bearer_tokens = vec!["s3cret".into()];
    });
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;
    let response = router
        .oneshot(with_peer(
            Request::builder()
                .uri(upstream_url(&mock, "/ok"))
                .header(header::AUTHORIZATION, "Bearer s3cret"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn redirect_follow_rejects_hop_outside_allowlist() {
    use corx_core::config::TargetMode;
    // Two-phase setup so the allowlist can include the mock's host.
    ensure_crypto_provider();
    let mock = MockServer::start().await;
    let host = mock_host(&mock);

    let mut config = Config::default();
    config.ssrf.mode = SsrfMode::Strict;
    config
        .ssrf
        .extra_allowed_cidrs
        .push("127.0.0.0/8".parse().unwrap());
    config.cors.allow_any_origin = true;
    config.circuit_breaker.failure_threshold = 10_000;
    config.rate_limit.enabled = false;
    config.target.mode = TargetMode::Allowlist;
    config.target.hosts = vec![host];
    config.limits.redirect_policy = corx_core::config::RedirectPolicy::Follow;

    let metrics = MetricsHandle::for_test();
    let build = ServerBuild::from_config(config, metrics).expect("build server");
    let router = build_router(AppState::new(build));

    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example/secret"),
        )
        .mount(&mock)
        .await;

    let response = router
        .oneshot(with_peer(
            Request::builder().uri(upstream_url(&mock, "/start")),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "redirect hop outside allowlist must be rejected"
    );
}

#[tokio::test]
async fn redirect_follow_admits_hop_on_allowlist() {
    use corx_core::config::TargetMode;
    // Two mock servers on loopback — both allowlisted by suffix.
    let mock_b = futures::executor::block_on(MockServer::start());
    let (router, mock_a) = make_stack(|cfg| {
        cfg.target.mode = TargetMode::Allowlist;
        cfg.target.hosts = vec!["127.0.0.1".into()];
        cfg.limits.redirect_policy = corx_core::config::RedirectPolicy::Follow;
        cfg.ssrf
            .extra_allowed_cidrs
            .push("127.0.0.0/8".parse().unwrap());
    });

    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("landed"))
        .mount(&mock_b)
        .await;

    let location = format!("{}/final", mock_b.uri().trim_end_matches('/'));
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", location.as_str()))
        .mount(&mock_a)
        .await;

    let response = router
        .oneshot(with_peer(
            Request::builder().uri(upstream_url(&mock_a, "/start")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"landed");
}

fn mock_host(mock: &MockServer) -> String {
    // mock.uri() is like http://127.0.0.1:PORT
    let uri = mock.uri();
    let without_scheme = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(&uri);
    without_scheme
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .to_owned()
}

#[tokio::test]
async fn error_payload_is_client_safe() {
    let (router, _mock) = make_stack(|cfg| {
        cfg.ssrf.extra_allowed_cidrs.clear();
    });
    let response = router
        .oneshot(with_peer(
            Request::builder().uri("/http://localhost/private"),
        ))
        .await
        .unwrap();
    // Forbidden (SSRF) or bad gateway depending on resolution path.
    assert!(
        matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::BAD_GATEWAY
        ),
        "unexpected status {}",
        response.status()
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    // Client payload must not echo raw resolver / OS error strings.
    assert!(
        !text.contains("os error") && !text.contains("ConnectError"),
        "leaked internal detail: {text}"
    );
}

#[tokio::test]
async fn redirect_rewrite_rewrites_location_to_proxy_path() {
    let (router, mock) = make_stack(|cfg| {
        cfg.limits.redirect_policy = corx_core::config::RedirectPolicy::Rewrite;
    });
    Mock::given(method("GET"))
        .and(path("/bounce"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "https://next.example/path?q=1"),
        )
        .mount(&mock)
        .await;

    let response = router
        .oneshot(with_peer(
            Request::builder().uri(upstream_url(&mock, "/bounce")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .unwrap();
    assert_eq!(
        location, "/https://next.example/path?q=1",
        "rewrite policy must prefix absolute Location with /"
    );
}

#[tokio::test]
async fn proxy_injects_forwarded_and_request_id_headers() {
    let (router, mock) = make_stack(|_| {});
    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock)
        .await;

    let response = router
        .oneshot(with_peer(
            Request::builder().uri(upstream_url(&mock, "/echo")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The mock recorded the upstream request; assert it carries the
    // headers corx is supposed to inject. wiremock exposes them via
    // `received_requests`.
    let requests = mock.received_requests().await.expect("recorded");
    let upstream = requests.into_iter().next().expect("one upstream");
    assert!(
        upstream.headers.contains_key("forwarded"),
        "Forwarded header must be injected"
    );
    assert!(
        upstream.headers.contains_key("x-forwarded-for"),
        "X-Forwarded-For header must be injected"
    );
    assert!(
        upstream.headers.contains_key("x-request-id"),
        "X-Request-Id must be injected when forwarded.inject_request_id is on"
    );
}
