use std::env;

use tracing::Subscriber;
use tracing_opentelemetry::{OpenTelemetryLayer, PreSampledTracer};
use tracing_subscriber::{EnvFilter, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::formatter::DatadogFormatter;
use crate::shutdown::TracerShutdown;
use crate::tracer::build_tracer;

pub struct DatadogLayers<S, T>
    where
        S: Subscriber + for<'span> LookupSpan<'span>,
        T: opentelemetry::trace::Tracer + PreSampledTracer + 'static,
{
    pub log_layer: Box<dyn Layer<S> + Send + Sync>,
    pub telemetry_layer: Option<OpenTelemetryLayer<S, T>>,
    pub loglevel_layer: EnvFilter,
    pub guard: tracing_appender::non_blocking::WorkerGuard,
    pub trace_shutdown: TracerShutdown,
}

pub fn init<S>() -> anyhow::Result<DatadogLayers<S, opentelemetry_sdk::trace::Tracer>>
    where
        S: Subscriber + for<'span> LookupSpan<'span>,
{
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let dd_enabled = env::var("DD_ENABLED").map(|s| s == "true").unwrap_or_else(|_| false);
    let log_layer = Box::new(tracing_subscriber::fmt::layer()
        .json()
        .event_format(DatadogFormatter)
        .with_writer(non_blocking));
    let loglevel_layer = loglevel_filter_layer(dd_enabled);
    if dd_enabled {
        let tracer = build_tracer()?;
        let telemetry_layer: OpenTelemetryLayer<S, _> = tracing_opentelemetry::layer().with_tracer(tracer);
        let telemetry_layer = Some(telemetry_layer);
        let t: DatadogLayers<S, _> = DatadogLayers {
            log_layer,
            telemetry_layer,
            loglevel_layer,
            guard,
            trace_shutdown: TracerShutdown {},
        };
        Ok(t)
    } else {
        let telemetry_layer = None;
        Ok(DatadogLayers {
            log_layer,
            telemetry_layer,
            loglevel_layer,
            guard,
            trace_shutdown: TracerShutdown {},
        })
    }
}

fn loglevel_filter_layer(dd_enabled: bool) -> EnvFilter {
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let axum_tracing_log_level = env::var("AXUM_TRACING_LOG_LEVEL")
        .unwrap_or_else(|_| if dd_enabled { "info".to_string() } else { "off".to_string() });
    let otel_log_level = env::var("OTEL_LOG_LEVEL").unwrap_or_else(|_| "debug".to_string());
    env::set_var(
        "RUST_LOG",
        format!("{log_level},axum_tracing_opentelemetry={axum_tracing_log_level},otel={otel_log_level}"),
    );
    EnvFilter::from_default_env()
}
