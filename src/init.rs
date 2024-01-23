use std::env;
use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;

use tracing_subscriber::{EnvFilter, Layer};
use tracing_subscriber::registry::LookupSpan;


use crate::formatter::DatadogFormatter;
use crate::shutdown::TracerShutdown;

pub fn init<S>() -> (EnvFilter, Box<dyn Layer<S> + Send + Sync + 'static>, WorkerGuard, TracerShutdown) where S: Subscriber + for<'a> LookupSpan<'a> {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let dd_enabled = env::var("DD_ENABLED").map(|s| s == "true").unwrap_or(false);
    if dd_enabled {
        let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        let axum_tracing_log_level = env::var("AXUM_TRACING_LOG_LEVEL").unwrap_or_else(|_| if dd_enabled { "info".to_string() } else { "off".to_string() });
        let otel_log_level = env::var("OTEL_LOG_LEVEL").unwrap_or_else(|_| "debug".to_string());
        env::set_var(
            "RUST_LOG",
            format!("{log_level},axum_tracing_opentelemetry={axum_tracing_log_level},otel={otel_log_level}"),
        );
        let filter = EnvFilter::from_default_env();
        let layer = Box::new(tracing_subscriber::fmt::layer()
            .json()
            .event_format(DatadogFormatter)
            .with_writer(non_blocking));
        (filter, layer, guard, TracerShutdown {})
    } else {
        let filter = EnvFilter::from_default_env();
        let layer = Box::new(tracing_subscriber::fmt::layer().with_writer(non_blocking));
        (filter, layer, guard, TracerShutdown {})
    }
}