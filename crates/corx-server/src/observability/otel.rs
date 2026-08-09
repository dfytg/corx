//! OpenTelemetry / OTLP trace export.
//!
//! Compiled only when the `otel` Cargo feature is on. Provides
//! [`build_tracer`] which yields an SDK tracer that can be plugged into the
//! [`crate::observability::init_tracing`] pipeline via
//! `tracing-opentelemetry`.

use anyhow::Context as _;
use corx_core::config::{OtelConfig, OtelProtocol};
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracer, SdkTracerProvider};

/// Build the SDK tracer that backs `tracing-opentelemetry`'s layer.
///
/// Returning the bare tracer (instead of a fully wrapped subscriber layer)
/// keeps the layer's `S` type parameter free for the caller's registry to
/// infer at the `with(...)` site.
///
/// Returns `Ok(None)` when `cfg.enabled = false` so the caller can plug an
/// `Option<L>` straight into `Subscriber::with`.
///
/// # Errors
///
/// Returns an error when the OTLP exporter cannot be constructed (typically
/// invalid endpoint or unreachable collector at startup).
pub fn build_tracer(cfg: &OtelConfig) -> anyhow::Result<Option<SdkTracer>> {
    if !cfg.enabled {
        return Ok(None);
    }

    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = match cfg.protocol {
        OtelProtocol::Grpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&cfg.endpoint)
            .with_protocol(Protocol::Grpc)
            .build()
            .context("building OTLP gRPC span exporter")?,
        OtelProtocol::Http => SpanExporter::builder()
            .with_http()
            .with_endpoint(&cfg.endpoint)
            .with_protocol(Protocol::HttpBinary)
            .build()
            .context("building OTLP HTTP span exporter")?,
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(build_resource(cfg))
        .with_sampler(Sampler::TraceIdRatioBased(cfg.sample_ratio.clamp(0.0, 1.0)))
        .build();

    let tracer = provider.tracer("corx");
    global::set_tracer_provider(provider);

    Ok(Some(tracer))
}

fn build_resource(cfg: &OtelConfig) -> Resource {
    let mut kvs: Vec<KeyValue> = vec![
        KeyValue::new("service.name", cfg.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ];
    if !cfg.service_namespace.is_empty() {
        kvs.push(KeyValue::new(
            "service.namespace",
            cfg.service_namespace.clone(),
        ));
    }
    for entry in &cfg.resource_attributes {
        if let Some((k, v)) = entry.split_once('=') {
            kvs.push(KeyValue::new(k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    Resource::builder_empty().with_attributes(kvs).build()
}
