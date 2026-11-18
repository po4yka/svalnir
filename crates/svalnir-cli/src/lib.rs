//! Svalnir command-line client.
//!
//! Parses arguments, renders output, runs the read-only commands in its own
//! process, and wires the commands that change state to the libraries:
//! the plan builder and the grant logic of `svalnir-core`, and the journal,
//! the coordinator, and the executors of `svalnir-agent`.
//!
//! Milestone 2 has no socket. A command reads and writes the operation
//! journal in the state directory. A plan is applied by the process that
//! holds the coordinator lock of the journal: the agent when one runs, and
//! otherwise this process, as a transient coordinator that evaluates no
//! guard. `docs/INTERFACES.md` owns the contract.
//!
//! No command acts without a plan that the journal has and an approval of
//! that plan. `agent install` and `agent uninstall` change the registered
//! services of the host only through `seams::ServiceHost`.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`cli`] | The argument definitions |
//! | [`output`] | The JSON envelope, the structured error, and the exit status |
//! | `commands` | The dispatcher and one module for each command family |
//! | `environment` | The state directory, the home directory, and the invocation directory |
//! | `host` | The collection context of this process |
//! | `interrupt` | The Ctrl+C flag of `scan`, `monitor`, and a wait for an operation |
//! | `seams` | The terminal question, the Trash operation, and the service manager, which a test replaces |
//! | `text` | Escaping and formatting of the human-readable output |

use std::ffi::OsString;
use std::io::{self, Write};

use clap::Parser;

pub mod cli;
mod commands;
mod environment;
mod host;
mod interrupt;
pub mod output;
mod seams;
mod text;

#[cfg(test)]
#[cfg(target_os = "macos")]
mod intervention_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use cli::{Cli, Format};
use commands::CommandFailure;
use environment::Environment;
use output::{Envelope, ErrorBody, ExitStatus, RequestId, Warning};

/// Runs one invocation and returns its exit status.
///
/// `arguments` includes the program name. Results go to `stdout`; diagnostics
/// go to `stderr`. In a machine format, `stdout` receives only JSON.
pub fn run<I, T>(arguments: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitStatus
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_in(
        arguments,
        output::generate_request_id(),
        &Environment::from_process(),
        stdout,
        stderr,
    )
}

fn run_in<I, T>(
    arguments: I,
    request_id: RequestId,
    environment: &Environment,
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
    match commands::execute(&cli, &request_id, environment, stdout, stderr) {
        Ok(status) => finish(stdout.flush(), status, stderr),
        // A closed pipe keeps the success status; another write error does not.
        Err(CommandFailure::Output(error)) => finish(Err(error), ExitStatus::Success, stderr),
        // The result of an operation has its own status. A closed pipe
        // does not change it.
        Err(CommandFailure::OutputAfter { error, status }) => finish(Err(error), status, stderr),
        Err(CommandFailure::Rejected(error)) => {
            let status: ExitStatus = error.exit_status();
            let written = report_error(
                cli.common.format,
                request_id,
                error,
                Vec::new(),
                stdout,
                stderr,
            );
            finish(written, status, stderr)
        }
        Err(CommandFailure::RejectedWithWarnings(boxed)) => {
            let (error, warnings): (ErrorBody, Vec<Warning>) = *boxed;
            let status: ExitStatus = error.exit_status();
            let written = report_error(
                cli.common.format,
                request_id,
                error,
                warnings,
                stdout,
                stderr,
            );
            finish(written, status, stderr)
        }
    }
}

fn report_error(
    format: Format,
    request_id: RequestId,
    error: ErrorBody,
    warnings: Vec<Warning>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for warning in &warnings {
                writeln!(stderr, "warning: {}", warning.message)?;
            }
            writeln!(stderr, "error: {}", error.message)
        }
        Format::Json | Format::Ndjson => {
            commands::write_json(
                stdout,
                &Envelope::error(request_id, error).with_warnings(warnings),
            )?;
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
