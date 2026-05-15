//! OpenTelemetry / OTLP trace export.
//!
//! Compiled only when the `otel` Cargo feature is on. Provides
//! [`build_layer`] which yields a `tracing_subscriber::Layer` that can be
//! plugged into the [`crate::observability::init_tracing`] pipeline.
//!
//! Spans naturally form a tree because every async function instrumented
//! with `#[tracing::instrument]` spawns a child span; the OpenTelemetry
//! layer propagates the resulting trace context onto the configured OTLP
//! endpoint.

use anyhow::Context as _;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{Sampler, Tracer, TracerProvider};

use corx_core::config::{OtelConfig, OtelProtocol};

/// Build the SDK tracer that backs `tracing-opentelemetry`'s layer.
///
/// Returning the bare tracer (instead of a fully wrapped subscriber layer)
/// keeps the layer's `S` type parameter free for the caller's registry to
/// infer at the `with(...)` site \u2014 trait-object dispatch over `Layer<S>`
/// would otherwise force `S` to be specified at this boundary, which is
/// not possible without naming the concrete `Layered<...>` chain.
///
/// Returns `Ok(None)` when `cfg.enabled = false` so the caller can plug an
/// `Option<L>` straight into `Subscriber::with`.
///
/// # Errors
///
/// Returns an error when the OTLP exporter cannot be constructed (typically
/// invalid endpoint or unreachable collector at startup).
pub fn build_tracer(cfg: &OtelConfig) -> anyhow::Result<Option<Tracer>> {
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

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, Tokio)
        .with_resource(build_resource(cfg))
        .with_sampler(Sampler::TraceIdRatioBased(
            cfg.sample_ratio.clamp(0.0, 1.0),
        ))
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
    Resource::new(kvs)
}
