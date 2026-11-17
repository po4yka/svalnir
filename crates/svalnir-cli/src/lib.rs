//! Svalnir command-line client.
//!
//! Parses arguments, renders output, and sends requests to the shared
//! application services. It has no independent destructive execution path.
//!
//! This build implements the argument contract, the machine-output envelope,
//! the exit status, and the commands that need no agent (`completions` and
//! `license`). Each other command reports `not_implemented` with exit
//! status 3 and makes no change.

use std::ffi::OsString;
use std::io::{self, Write};

use clap::Parser;

pub mod cli;
mod commands;
pub mod output;

// The read-only commands of Milestone 1 will run in this process through the
// agent library.
// TODO(npochaev): remove this line when a command uses the crate.
use svalnir_agent as _;

#[cfg(test)]
mod tests;

use cli::{Cli, Format};
use commands::CommandFailure;
use output::{Envelope, ErrorBody, ExitStatus, RequestId};

/// Runs one invocation and returns its exit status.
///
/// `arguments` includes the program name. Results go to `stdout`; diagnostics
/// go to `stderr`. In a machine format, `stdout` receives only JSON.
pub fn run<I, T>(arguments: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitStatus
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with_request_id(arguments, output::generate_request_id(), stdout, stderr)
}

fn run_with_request_id<I, T>(
    arguments: I,
    request_id: RequestId,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitStatus
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let cli: Cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let rendered = error.render();
            if !error.use_stderr() {
                // Help and version.
                return finish(write!(stdout, "{rendered}"), ExitStatus::Success, stderr);
            }
            let mut written: io::Result<()> = write!(stderr, "{rendered}");
            if written.is_ok() && requests_machine_format(&arguments) {
                let body: ErrorBody = commands::invalid_arguments(error.kind().as_str());
                written = commands::write_json(stdout, &Envelope::error(request_id, body))
                    .and_then(|()| stdout.flush());
            }
            return finish(written, ExitStatus::Usage, stderr);
        }
    };
    match commands::execute(&cli, &request_id, stdout) {
        Ok(()) => finish(stdout.flush(), ExitStatus::Success, stderr),
        // A closed pipe keeps the success status; another write error does not.
        Err(CommandFailure::Output(error)) => finish(Err(error), ExitStatus::Success, stderr),
        Err(CommandFailure::Rejected(error)) => {
            let status: ExitStatus = error.family.exit_status();
            let written = report_error(cli.common.format, request_id, error, stdout, stderr);
            finish(written, status, stderr)
        }
    }
}

fn report_error(
    format: Format,
    request_id: RequestId,
    error: ErrorBody,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => writeln!(stderr, "error: {}", error.message),
        Format::Json | Format::Ndjson => {
            commands::write_json(stdout, &Envelope::error(request_id, error))?;
            stdout.flush()
        }
    }
}

/// Whether rejected arguments select a machine format.
///
/// The parser gives no result for rejected arguments, so this function reads
/// the `--format` value directly. The value of another option is not read as
/// the format, because `--format` must be an argument of its own.
fn requests_machine_format(arguments: &[OsString]) -> bool {
    let mut texts = arguments.iter().map(|argument| argument.to_str());
    while let Some(text) = texts.next() {
        let value: Option<&str> = match text {
            Some("--") => return false,
            Some("--format") => texts.next().flatten(),
            Some(other) => other.strip_prefix("--format="),
            None => None,
        };
        if matches!(value, Some("json" | "ndjson")) {
            return true;
        }
    }
    false
}

/// Selects the exit status after the last write.
///
/// A closed pipe is the decision of the reader, for example `svalnir license
/// | head`. It keeps the status and prints nothing.
fn finish(written: io::Result<()>, status: ExitStatus, stderr: &mut dyn Write) -> ExitStatus {
    match written {
        Ok(()) => status,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => status,
        Err(error) => {
            // No other stream is available if this write fails.
            drop(writeln!(stderr, "error: cannot write the output: {error}"));
            ExitStatus::Failure
        }
    }
}
