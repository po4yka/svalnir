//! Svalnir user agent.
//!
//! Owns collection, lifecycle, the action coordinator, application adapters,
//! and the local client API. It has no rendering dependencies.

use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "svalnir-agent skeleton"
    );
}
