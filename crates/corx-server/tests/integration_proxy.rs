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
