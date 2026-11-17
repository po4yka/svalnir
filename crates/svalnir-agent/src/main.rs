//! Svalnir user agent.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies.
//!
//! This build is a skeleton. The process runs the main run loop until it
//! gets `SIGINT` or `SIGTERM`, so that a collector on another thread can
//! read `AppKit` state that is current. It starts no collector, registers no
//! service, and changes no other process.

use std::process::ExitCode;

use svalnir_agent::platform::run_loop::run_main_run_loop_until_stop;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "svalnir-agent skeleton"
    );
    match run_main_run_loop_until_stop() {
        Ok(signal) => {
            tracing::info!(?signal, "svalnir-agent stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "the main run loop did not run");
            ExitCode::FAILURE
        }
    }
}
