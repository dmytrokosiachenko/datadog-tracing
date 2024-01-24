use std::env;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{EnvFilter, Layer, Registry};
use tracing_subscriber::fmt::format::JsonFields;
use tracing_subscriber::layer::{Layered, SubscriberExt};

use crate::formatter::DatadogFormatter;
use crate::shutdown::TracerShutdown;
use crate::tracer::build_tracer;

type RegistryLayer = Layered<Box<dyn Layer<Registry> + Send + Sync>, Registry>;
type FormatterLayer = Layered<Box<tracing_subscriber::fmt::Layer<RegistryLayer, JsonFields, DatadogFormatter, NonBlocking>>, RegistryLayer>;
type EnvFilterLayer = Layered<EnvFilter, FormatterLayer>;

pub type RegisterType = Box<EnvFilterLayer>;

pub fn init() -> anyhow::Result<(RegisterType, WorkerGuard, TracerShutdown)> {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let dd_enabled = env::var("DD_ENABLED").map(|s| s == "true").unwrap_or_else(|_| false);
    let log_layer = Box::new(tracing_subscriber::fmt::layer()
        .json()
        .event_format(DatadogFormatter)
        .with_writer(non_blocking));
    let loglevel_layer = loglevel_filter_layer(dd_enabled);
    if dd_enabled {
        let tracer = build_tracer()?;
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
        let registry = Box::new(Registry::default()
            .with(telemetry_layer)
            .with(log_layer)
            .with(loglevel_layer));
        Ok((registry, guard, TracerShutdown {}))
    } else {
        return Err(anyhow::anyhow!("DD_ENABLED is not set"));
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
