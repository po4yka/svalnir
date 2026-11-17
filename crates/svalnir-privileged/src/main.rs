//! Svalnir privileged helper.
//!
//! The library `svalnir_privileged` has the typed operations and their
//! validation. This binary runs no operation: this build has no transport
//! and no executor, and nothing installs the helper.

use std::process::ExitCode;

use svalnir_privileged as _;

fn main() -> ExitCode {
    eprintln!(
        "svalnir-privileged: the privileged helper is not installed in this build. It accepts no request and runs no operation."
    );
    ExitCode::FAILURE
}
