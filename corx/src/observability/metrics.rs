//! Prometheus metrics recorder.

use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Handle used to render the Prometheus text exposition on demand.
#[derive(Clone)]
pub struct MetricsHandle {
    inner: PrometheusHandle,
}

impl std::fmt::Debug for MetricsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsHandle").finish_non_exhaustive()
    }
}

impl MetricsHandle {
    /// Renders the current metric values as a Prometheus text exposition.
    #[must_use]
    pub fn render(&self) -> String {
        self.inner.render()
    }
}

/// Counter: total inbound requests handled.
pub const REQUESTS_TOTAL: &str = "corx_requests_total";
/// Histogram: inbound request duration in seconds.
pub const REQUEST_DURATION: &str = "corx_request_duration_seconds";
/// Histogram: upstream request duration in seconds.
pub const UPSTREAM_DURATION: &str = "corx_upstream_duration_seconds";
/// Counter: number of upstream failures broken down by reason.
pub const UPSTREAM_ERRORS: &str = "corx_upstream_errors_total";
/// Gauge: currently in-flight proxied requests.
pub const INFLIGHT_REQUESTS: &str = "corx_inflight_requests";
/// Counter: bytes transferred, keyed by `direction=request|response`.
pub const BYTES_TRANSFERRED: &str = "corx_bytes_transferred_total";
/// Counter: requests denied by the rate limiter, keyed by `reason`.
pub const RATE_LIMITED: &str = "corx_rate_limited_total";

/// Initialises the Prometheus recorder and registers metric descriptions.
///
/// # Errors
///
/// Fails if another `metrics` recorder has already been installed process-wide.
pub fn init_metrics() -> anyhow::Result<MetricsHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(REQUEST_DURATION.into()),
            &[
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(UPSTREAM_DURATION.into()),
            &[
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
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
        "Bytes transferred through the proxy"
    );
    describe_counter!(RATE_LIMITED, Unit::Count, "Rate limited request rejections");

    Ok(MetricsHandle { inner: handle })
}
