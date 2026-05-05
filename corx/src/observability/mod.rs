//! Telemetry wiring: structured logging and Prometheus metrics.

pub mod metrics;
mod tracing;

pub use self::metrics::{MetricsHandle, init_metrics};
pub use self::tracing::init_tracing;
