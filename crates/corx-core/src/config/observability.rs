//! Telemetry configuration: logging, metrics, and tracing.

use serde::{Deserialize, Serialize};

/// Observability configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Log formatter.
    pub log_format: LogFormat,
    /// `tracing` env-filter directive.
    pub log_level: String,
    /// Path where Prometheus metrics are served.
    pub metrics_endpoint: String,
    /// OpenTelemetry / OTLP trace export. Disabled by default. Compiled in
    /// only when the `otel` Cargo feature is enabled on the binary.
    #[serde(default)]
    pub otel: OtelConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Json,
            log_level: "info".into(),
            metrics_endpoint: "/metrics".into(),
            otel: OtelConfig::default(),
        }
    }
}

/// Supported log output formats.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable formatter with ANSI colours.
    Pretty,
    /// Structured single-line JSON, one object per event.
    Json,
}

/// OpenTelemetry / OTLP exporter configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OtelConfig {
    /// Master switch.
    #[serde(default)]
    pub enabled: bool,
    /// Collector endpoint (e.g. `http://otel-collector:4317`).
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    /// Wire protocol used to talk to the collector.
    #[serde(default)]
    pub protocol: OtelProtocol,
    /// `service.name` resource attribute.
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
    /// `service.namespace` resource attribute.
    #[serde(default)]
    pub service_namespace: String,
    /// Free-form `key=value` resource attributes; merged into the resource.
    #[serde(default)]
    pub resource_attributes: Vec<String>,
    /// Sampling ratio in `[0.0, 1.0]`. `1.0` keeps every span; `0.1` keeps
    /// 10 %.
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            protocol: OtelProtocol::default(),
            service_name: default_otel_service_name(),
            service_namespace: String::new(),
            resource_attributes: Vec::new(),
            sample_ratio: default_sample_ratio(),
        }
    }
}

fn default_otel_endpoint() -> String {
    "http://localhost:4317".into()
}

fn default_otel_service_name() -> String {
    "corx".into()
}

const fn default_sample_ratio() -> f64 {
    0.1
}

/// OTLP wire protocol.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OtelProtocol {
    /// gRPC over HTTP/2 (port 4317 by default). Recommended for collector
    /// deployments inside the same trust boundary.
    #[default]
    Grpc,
    /// `application/x-protobuf` over HTTP/1.1 (port 4318 by default).
    Http,
}
