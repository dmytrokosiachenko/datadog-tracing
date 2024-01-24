use std::env;

use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, registry};

use crate::formatter::DatadogFormatter;
use crate::shutdown::TracerShutdown;
use crate::tracer::build_tracer;

pub struct DatadogLayers<S> {
    pub loglevel_layer: EnvFilter,
    pub guard: WorkerGuard,
    pub trace_shutdown: TracerShutdown,
    pub telemetry_layer: Box<dyn Layer<S>>,
    pub log_layer: Box<dyn Layer<S>>,
}

pub fn init<S>() -> Box<DatadogLayers<S>> where S: Subscriber + for<'a> registry::LookupSpan<'a> {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let dd_enabled = env::var("DD_ENABLED").map(|s| s == "true").unwrap_or_else(|_| false);
    let log_layer = Box::new(tracing_subscriber::fmt::layer()
        .json()
        .event_format(DatadogFormatter)
        .with_writer(non_blocking));
    let loglevel_layer = loglevel_filter_layer(dd_enabled);
    if dd_enabled {
        let tracer = build_tracer().unwrap_or_else(|e| panic!("Could not init datadog tracer: {}", e));
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let telemetry_layer = Box::new(telemetry_layer);
        let t = DatadogLayers {
            log_layer,
            telemetry_layer,
            loglevel_layer,
            guard,
            trace_shutdown: TracerShutdown {},
        };
        Box::new(t)
    } else {
        Box::new(DatadogLayers {
            log_layer,
            telemetry_layer: Box::new(tracing_subscriber::fmt::layer()),
            loglevel_layer: loglevel_layer,
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
