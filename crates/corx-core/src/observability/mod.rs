//! Observability constants exposed by the proxy engine.
//!
//! Metric names live here so that both the engine (when it records values)
//! and the HTTP layer (when it installs a recorder and labels) agree on the
//! exact identifiers. Recorder installation itself is framework-specific and
//! lives in `corx-server`.

/// Counter: total inbound requests handled.
pub const REQUESTS_TOTAL: &str = "corx_requests_total";
/// Histogram: end-to-end inbound request duration in seconds.
pub const REQUEST_DURATION: &str = "corx_request_duration_seconds";
/// Histogram: upstream request duration in seconds.
pub const UPSTREAM_DURATION: &str = "corx_upstream_duration_seconds";
/// Counter: number of upstream failures broken down by reason.
pub const UPSTREAM_ERRORS: &str = "corx_upstream_errors_total";
/// Gauge: currently in-flight proxied requests.
pub const INFLIGHT_REQUESTS: &str = "corx_inflight_requests";
/// Counter: bytes transferred through the proxy, keyed by `direction`.
pub const BYTES_TRANSFERRED: &str = "corx_bytes_transferred_total";
/// Counter: requests denied by the rate limiter, keyed by `dimension`.
pub const RATE_LIMITED: &str = "corx_rate_limited_total";
/// Counter: SSRF policy interceptions, keyed by `cidr`.
pub const SSRF_BLOCKS: &str = "corx_ssrf_blocks_total";
/// Counter: DNS lookup outcomes, keyed by `result`.
pub const DNS_LOOKUPS: &str = "corx_dns_lookups_total";
/// Histogram: number of redirect hops per request, keyed by `target_host`.
pub const REDIRECT_HOPS: &str = "corx_redirect_hops";
/// Gauge: number of active WebSocket connections.
pub const WEBSOCKET_ACTIVE: &str = "corx_websocket_connections_active";
/// Counter: WebSocket handshake outcomes, keyed by `status`.
pub const WEBSOCKET_HANDSHAKES: &str = "corx_websocket_handshakes_total";
/// Counter: configuration reload outcomes, keyed by `result`.
pub const CONFIG_RELOAD: &str = "corx_config_reload_total";
/// Gauge: build information watermark; always reported as 1.
pub const BUILD_INFO: &str = "corx_build_info";
