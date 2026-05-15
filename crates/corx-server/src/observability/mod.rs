//! Telemetry wiring: structured logging, Prometheus metrics, OpenTelemetry
//! traces (feature `otel`), and streaming-body byte counters.

pub mod metering;
pub mod metrics;
#[cfg(feature = "otel")]
pub mod otel;
mod tracing;

pub use self::metering::CountingBody;
pub use self::metrics::{MetricsHandle, init_metrics};
pub use self::tracing::init_tracing;
