//! Prometheus metrics recorder.
//!
//! Metric **names** live in [`corx_core::observability`] so they can be
//! referenced from the framework-agnostic engine. This module re-exports them
//! and additionally owns the recorder installation — which is HTTP-stack
//! specific and therefore lives outside of `corx-core`.

use std::sync::OnceLock;

pub use corx_core::observability::{
    BUILD_INFO, BYTES_TRANSFERRED, CIRCUIT_OPENS, CIRCUIT_REJECTS, CONFIG_RELOAD, DNS_LOOKUPS,
    INFLIGHT_REQUESTS, RATE_LIMITED, REDIRECT_HOPS, REQUEST_DURATION, REQUESTS_TOTAL, SSRF_BLOCKS,
    UPSTREAM_DURATION, UPSTREAM_ERRORS,
};
use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Handle used to render the Prometheus text exposition on demand.
///
/// Wraps an `Option<PrometheusHandle>` so integration tests can opt out of
/// registering the global recorder (which can only be installed once per
/// process). In production code paths the `Option` is always `Some`.
#[derive(Clone)]
pub struct MetricsHandle {
    inner: Option<PrometheusHandle>,
}

impl std::fmt::Debug for MetricsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsHandle").finish()
    }
}

impl MetricsHandle {
    /// Renders the current metric values as a Prometheus text exposition.
    /// Returns the empty string when running under the test-only stub.
    #[must_use]
    pub fn render(&self) -> String {
        self.inner
            .as_ref()
            .map(PrometheusHandle::render)
            .unwrap_or_default()
    }

    /// Test-only constructor that skips global recorder registration so
    /// multiple integration-test cases can each spin up a fresh
    /// [`crate::ServerBuild`] without conflicting on the
    /// process-wide `metrics` recorder slot.
    #[must_use]
    pub const fn for_test() -> Self {
        Self { inner: None }
    }
}

/// Latency histogram bucket layout shared by every duration metric. Spans
/// 1 ms → 10 s on a near-logarithmic scale, matching the SLO ranges most
/// API gateways care about.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Bucket layout for redirect-hop counts.
const REDIRECT_HOP_BUCKETS: &[f64] = &[0.0, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0];

/// Initialises the Prometheus recorder and registers metric descriptions.
///
/// # Errors
///
/// Fails if another `metrics` recorder has already been installed process-wide.
pub fn init_metrics() -> anyhow::Result<MetricsHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(REQUEST_DURATION.into()),
            LATENCY_BUCKETS,
        )?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(UPSTREAM_DURATION.into()),
            LATENCY_BUCKETS,
        )?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(REDIRECT_HOPS.into()),
            REDIRECT_HOP_BUCKETS,
        )?
        .install_recorder()?;

    describe_counter!(
        REQUESTS_TOTAL,
        Unit::Count,
        "Total inbound requests handled"
    );
    describe_histogram!(
        REQUEST_DURATION,
        Unit::Seconds,
        "End-to-end request duration as measured at the inbound listener",
    );
    describe_histogram!(
        UPSTREAM_DURATION,
        Unit::Seconds,
        "Duration of the upstream request leg only",
    );
    describe_counter!(
        UPSTREAM_ERRORS,
        Unit::Count,
        "Upstream failures, broken down by error kind",
    );
    describe_gauge!(
        INFLIGHT_REQUESTS,
        Unit::Count,
        "Currently in-flight requests"
    );
    describe_counter!(
        BYTES_TRANSFERRED,
        Unit::Bytes,
        "Bytes transferred through the proxy, keyed by direction"
    );
    describe_counter!(
        RATE_LIMITED,
        Unit::Count,
        "Rate-limited request rejections, keyed by dimension",
    );
    describe_counter!(
        SSRF_BLOCKS,
        Unit::Count,
        "SSRF policy interceptions, keyed by the matching CIDR",
    );
    describe_counter!(
        DNS_LOOKUPS,
        Unit::Count,
        "DNS lookup outcomes, keyed by result",
    );
    describe_histogram!(
        REDIRECT_HOPS,
        Unit::Count,
        "Number of redirect hops followed per request, keyed by target host",
    );
    describe_counter!(
        CONFIG_RELOAD,
        Unit::Count,
        "Configuration reload attempts, keyed by result",
    );
    describe_counter!(
        CIRCUIT_OPENS,
        Unit::Count,
        "Circuit breaker transitions to Open",
    );
    describe_counter!(
        CIRCUIT_REJECTS,
        Unit::Count,
        "Requests rejected because a circuit is open",
    );
    describe_gauge!(
        BUILD_INFO,
        Unit::Count,
        "Build information watermark; always reported as 1",
    );

    // Stamp build_info exactly once with the binary's identity. The label
    // set is small and deterministic so this never causes cardinality
    // explosions.
    metrics::gauge!(
        BUILD_INFO,
        "version" => env!("CARGO_PKG_VERSION"),
        "rust_version" => env!("CARGO_PKG_RUST_VERSION"),
        "features" => active_features(),
    )
    .set(1.0);

    Ok(MetricsHandle {
        inner: Some(handle),
    })
}

/// Comma-separated list of Cargo features the binary was compiled with, or
/// `"none"` when every optional feature is off.
///
/// Memoised in a `OnceLock` so the `build_info` metric and the `--version`
/// CLI subcommand share a single allocation.
#[must_use]
pub fn active_features() -> &'static str {
    static FEATURES: OnceLock<String> = OnceLock::new();
    FEATURES
        .get_or_init(|| {
            let candidates: &[(bool, &str)] = &[
                (cfg!(feature = "tls"), "tls"),
                (cfg!(feature = "mtls"), "mtls"),
                (cfg!(feature = "fips"), "fips"),
                (cfg!(feature = "otel"), "otel"),
            ];
            let active: Vec<&str> = candidates
                .iter()
                .filter_map(|(on, name)| on.then_some(*name))
                .collect();
            if active.is_empty() {
                "none".to_owned()
            } else {
                active.join(",")
            }
        })
        .as_str()
}
