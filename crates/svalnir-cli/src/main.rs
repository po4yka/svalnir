//! Entry point of the `svalnir` binary. The library crate has the behavior.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    svalnir_cli::run(std::env::args_os(), &mut stdout, &mut stderr).into()
}
