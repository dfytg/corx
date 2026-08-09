//! Telemetry wiring: structured logging, Prometheus metrics, OpenTelemetry
//! traces (feature `otel`), and streaming-body byte counters.

pub mod metering;
pub mod metrics;
#[cfg(feature = "otel")]
pub mod otel;
mod tracing;

pub use self::metering::{CountingBody, LimitingBody};
pub use self::metrics::{MetricsHandle, active_features, init_metrics};
pub use self::tracing::init_tracing;
