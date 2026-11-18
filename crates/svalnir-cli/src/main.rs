//! Entry point of the `svalnir` binary. The library crate has the behavior.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::process::ExitCode;

/// Standard output with no buffer.
///
/// A buffer of lines hides a short write and retries after `EINTR`, so Ctrl+C
/// could not end a write to a full pipe. A `File` over a duplicate of the
/// descriptor returns both to the caller. Each command writes a result in
/// one call, so the content of the output is the same. If the duplicate is
/// not available, the locked standard output is the fallback.
fn unbuffered_stdout() -> Box<dyn Write> {
    match io::stdout().as_fd().try_clone_to_owned() {
        Ok(descriptor) => Box::new(File::from(descriptor)),
        Err(_) => Box::new(io::stdout().lock()),
    }
}

fn main() -> ExitCode {
    let mut stdout: Box<dyn Write> = unbuffered_stdout();
    let mut stderr = io::stderr().lock();
    svalnir_cli::run(std::env::args_os(), &mut stdout, &mut stderr).into()
}
