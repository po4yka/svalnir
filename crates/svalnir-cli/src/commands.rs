//! Command dispatch.
//!
//! This module selects the function that runs a command. Each command
//! family is a module of its own, with the collection of the data separate
//! from the rendering.
//!
//! | Module | Commands |
//! | --- | --- |
//! | `resources`, `monitor`, `processes`, `scan`, `doctor`, `policy` | The read-only commands, which read the host in this process |
//! | `config` | `config validate` and `config show`, with `--effective` |
//! | `authority` | `config apply`, `policy enable`, `policy disable`, `policy rearm`, `agent pause`, and `agent resume` |
//! | `clean`, `stop` | `clean plan`, `clean show`, `clean apply`, and `processes stop` |
//! | `apply`, `execution` | The apply flow: the approval, the transient coordinator or the request queue, and the wait |
//! | `operations`, `history` | `operations show`, `operations wait`, `operations cancel`, `operations acknowledge`, and `history` |
//! | `agent` | `agent status`, `agent install`, and `agent uninstall` |
//! | `session`, `plan_store`, `plan_view`, `operation_view` | The journal connection and the authority record, the plan documents, and the shared views |
//!
//! Milestone 2 has no socket. A command reads and writes the operation
//! journal in the state directory, which the agent also uses
//! (`docs/INTERFACES.md` section 4).

use std::io::{self, Write};

use clap::CommandFactory;
use serde::Serialize;

use crate::cli::{
    AgentCommand, CleanCommand, CleanMode, Cli, Command, ConfigCommand, Format, MemoryCommand,
    OperationsCommand, PolicyCommand, ProcessesCommand, SwapCommand,
};
use crate::environment::Environment;
use crate::interrupt::Interrupt;
use crate::output::{
    Envelope, ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction, RequestId, Warning,
};

pub(crate) mod agent;
pub(crate) mod apply;
pub(crate) mod authority;
pub(crate) mod capacity;
#[cfg(unix)]
pub(crate) mod clean;
pub(crate) mod config;
pub(crate) mod doctor;
pub(crate) mod evict;
#[cfg(target_os = "macos")]
pub(crate) mod execution;
pub(crate) mod history;
mod home;
#[cfg(unix)]
pub(crate) mod inspect;
pub(crate) mod monitor;
pub(crate) mod operation_view;
pub(crate) mod operations;
pub(crate) mod plan_store;
pub(crate) mod plan_view;
pub(crate) mod policy;
pub(crate) mod processes;
pub(crate) mod resources;
pub(crate) mod scan;
#[cfg(unix)]
pub(crate) mod selection;
pub(crate) mod session;
mod start_failure;
#[cfg(target_os = "macos")]
pub(crate) mod stop;

const LICENSE_SPDX_ID: &str = "GPL-3.0-only";
const LICENSE_TEXT: &str = include_str!("../../../LICENSE");
const LICENSE_NOTICE: &str = "\
Svalnir is licensed under the GNU General Public License, version 3 (GPL-3.0-only).
Svalnir is provided without warranty, as the license describes.
The notices for imported material are in THIRD_PARTY_NOTICES.md of the source.
";

/// The reason a command did not complete.
#[derive(Debug)]
pub(crate) enum CommandFailure {
    /// The output stream rejected a write.
    Output(io::Error),
    /// The output stream rejected the write of a result whose exit status
    /// is known. The status reports an operation, so a reader that closed
    /// the pipe does not change it.
    OutputAfter {
        /// The write error.
        error: io::Error,
        /// The exit status of the result that was not written.
        status: ExitStatus,
    },
    /// The command returned a structured error.
    Rejected(ErrorBody),
    /// The command returned a structured error after the invocation had
    /// collected advisory findings. The findings are not lost.
    RejectedWithWarnings(Box<(ErrorBody, Vec<Warning>)>),
}

impl From<io::Error> for CommandFailure {
    fn from(error: io::Error) -> Self {
        Self::Output(error)
    }
}

impl From<ErrorBody> for CommandFailure {
    fn from(error: ErrorBody) -> Self {
        Self::Rejected(error)
    }
}

/// The streams and the shared inputs of one command.
pub(crate) struct Invocation<'a> {
    pub(crate) format: Format,
    pub(crate) request_id: &'a RequestId,
    pub(crate) environment: &'a Environment,
    pub(crate) stdout: &'a mut dyn Write,
    pub(crate) stderr: &'a mut dyn Write,
    /// The longest client wait of `--timeout`. It cancels no admitted work.
    pub(crate) timeout: Option<std::time::Duration>,
    /// Advisory findings. In a machine format they are in the envelope; in
    /// the text format they go to stderr.
    pub(crate) warnings: Vec<Warning>,
}

impl Invocation<'_> {
    /// Writes one result: the envelope in a machine format, or `text`.
    pub(crate) fn emit<T: Serialize>(
        &mut self,
        kind: Kind,
        view: &T,
        text: impl FnOnce(&T) -> String,
    ) -> io::Result<()> {
        let warnings: Vec<Warning> = std::mem::take(&mut self.warnings);
        match self.format {
            Format::Text => {
                for warning in &warnings {
                    writeln!(self.stderr, "warning: {}", warning.message)?;
                }
                write_interruptible(
                    self.stdout,
                    text(view).as_bytes(),
                    &self.environment.interrupt,
                )
            }
            Format::Json | Format::Ndjson => {
                let envelope =
                    Envelope::result(self.request_id.clone(), kind, view).with_warnings(warnings);
                write_interruptible(
                    self.stdout,
                    &json_line(&envelope)?,
                    &self.environment.interrupt,
                )
            }
        }
    }

    /// Writes one result whose exit status is `status`, and returns the
    /// status. A failed write keeps the status: the result reports an
    /// operation that this command executed or read, and a closed pipe
    /// must not turn its failure into success.
    pub(crate) fn emit_with_status<T: Serialize>(
        &mut self,
        kind: Kind,
        view: &T,
        text: impl FnOnce(&T) -> String,
        status: ExitStatus,
    ) -> Result<ExitStatus, CommandFailure> {
        match self.emit(kind, view, text) {
            Ok(()) => Ok(status),
            Err(error) => Err(CommandFailure::OutputAfter { error, status }),
        }
    }
}

#[derive(Debug, Serialize)]
struct LicenseReport {
    spdx_id: &'static str,
    text: &'static str,
}

pub(crate) fn execute(
    cli: &Cli,
    request_id: &RequestId,
    environment: &Environment,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitStatus, CommandFailure> {
    let format: Format = cli.common.format;
    check_format(&cli.command, format)?;
    check_rule_selection(&cli.command)?;
    let mut invocation = Invocation {
        format,
        request_id,
        environment,
        stdout,
        stderr,
        timeout: cli.common.timeout,
        warnings: Vec::new(),
    };
    if cli.common.timeout.is_some() && !waits_for_an_operation(&cli.command) {
        invocation.warnings.push(Warning {
            code: "timeout_not_applied".into(),
            message: format!(
                "`svalnir {}` has no wait that `--timeout` can bound; the option has no effect",
                cli.command.path()
            ),
        });
    }
    let result: Result<ExitStatus, CommandFailure> = dispatch(cli, &mut invocation);
    match result {
        Err(CommandFailure::Rejected(error)) if !invocation.warnings.is_empty() => {
            Err(CommandFailure::RejectedWithWarnings(Box::new((
                error,
                std::mem::take(&mut invocation.warnings),
            ))))
        }
        other => other,
    }
}

fn completions(
    arguments: &crate::cli::CompletionsArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    // `generate` panics on a write error, so it writes to memory first.
    let mut script: Vec<u8> = Vec::new();
    clap_complete::generate(arguments.shell, &mut Cli::command(), "svalnir", &mut script);
    // The script has no envelope, so each finding goes to stderr.
    for warning in std::mem::take(&mut invocation.warnings) {
        writeln!(invocation.stderr, "warning: {}", warning.message)?;
    }
    invocation.stdout.write_all(&script)?;
    Ok(ExitStatus::Success)
}

/// The commands that change no state of Svalnir.
fn dispatch_read_only(
    command: &Command,
    invocation: &mut Invocation<'_>,
) -> Option<Result<ExitStatus, CommandFailure>> {
    Some(match command {
        Command::Status => resources::status(invocation),
        Command::Memory {
            command: MemoryCommand::Status,
        } => resources::memory_status(invocation),
        Command::Swap {
            command: SwapCommand::Status,
        } => resources::swap_status(invocation),
        Command::Monitor(arguments) => monitor::run(arguments, invocation),
        Command::Processes {
            command: ProcessesCommand::Top(arguments),
        } => processes::top(arguments, invocation),
        Command::Processes {
            command: ProcessesCommand::Show(arguments),
        } => processes::show(arguments, invocation),
        Command::Scan(arguments) => scan::scan(arguments, invocation),
        Command::Report(arguments) => scan::report(arguments, invocation),
        Command::Doctor => doctor::run(invocation),
        Command::Config {
            command: ConfigCommand::Validate(arguments),
        } => config::validate(arguments, invocation),
        Command::Config {
            command: ConfigCommand::Show(arguments),
        } => config::show(arguments, invocation),
        Command::Policy {
            command: PolicyCommand::List,
        } => policy::list(invocation),
        Command::Policy {
            command: PolicyCommand::Show(arguments),
        } => policy::show(arguments, invocation),
        Command::Policy {
            command: PolicyCommand::Simulate(arguments),
        } => policy::simulate(arguments, invocation),
        _ => return None,
    })
}

fn dispatch(cli: &Cli, invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    if let Some(result) = dispatch_read_only(&cli.command, invocation) {
        return result;
    }
    home::check(&cli.command, invocation.environment)?;
    match &cli.command {
        Command::Completions(arguments) => completions(arguments, invocation),
        Command::License => {
            let report = LicenseReport {
                spdx_id: LICENSE_SPDX_ID,
                text: LICENSE_TEXT,
            };
            invocation.emit(Kind::Report, &report, |report| {
                format!("{LICENSE_NOTICE}\n{}", report.text)
            })?;
            Ok(ExitStatus::Success)
        }
        #[cfg(unix)]
        Command::Clean {
            command: CleanCommand::Inspect(arguments),
        } => inspect::inspect(arguments, invocation),
        #[cfg(unix)]
        Command::Clean {
            command: CleanCommand::Plan(arguments),
        } => clean::plan(arguments, invocation),
        #[cfg(unix)]
        Command::Clean {
            command: CleanCommand::Show(arguments),
        } => clean::show(arguments, invocation),
        #[cfg(unix)]
        Command::Clean {
            command: CleanCommand::Apply(arguments),
        } => clean::apply(arguments, invocation),
        #[cfg(target_os = "macos")]
        Command::Processes {
            command: ProcessesCommand::Stop(arguments),
        } => stop::stop(arguments, invocation),
        Command::Config {
            command: ConfigCommand::Apply(arguments),
        } => authority::config_apply(arguments, invocation),
        Command::Policy {
            command: PolicyCommand::Enable(arguments),
        } => authority::policy_enable(arguments, invocation),
        Command::Policy {
            command: PolicyCommand::Disable(arguments),
        } => authority::policy_disable(arguments, invocation),
        Command::Policy {
            command: PolicyCommand::Rearm(arguments),
        } => authority::policy_rearm(arguments, invocation),
        Command::Operations {
            command: OperationsCommand::Show(arguments),
        } => operations::show(arguments, invocation),
        Command::Operations {
            command: OperationsCommand::Wait(arguments),
        } => operations::wait(arguments, invocation),
        Command::Operations {
            command: OperationsCommand::Cancel(arguments),
        } => operations::cancel(arguments, invocation),
        Command::Operations {
            command: OperationsCommand::Acknowledge(arguments),
        } => operations::acknowledge(arguments, invocation),
        Command::History(arguments) => history::history(arguments, invocation),
        Command::Agent {
            command: AgentCommand::Status,
        } => agent::status(invocation),
        Command::Agent {
            command: AgentCommand::Install(arguments),
        } => agent::install(arguments, invocation),
        Command::Agent {
            command: AgentCommand::Uninstall(arguments),
        } => agent::uninstall(arguments, invocation),
        Command::Agent {
            command: AgentCommand::Pause(arguments),
        } => authority::agent_pause(arguments, invocation),
        Command::Agent {
            command: AgentCommand::Resume,
        } => authority::agent_resume(invocation),
        // A command whose executor does not exist for this platform.
        command => Err(not_implemented(command).into()),
    }
}

/// Whether `--timeout` bounds a wait of the command. Each other command
/// has no wait that the option can bound.
fn waits_for_an_operation(command: &Command) -> bool {
    matches!(
        command,
        Command::Clean {
            command: CleanCommand::Apply(_)
        } | Command::Operations {
            command: OperationsCommand::Wait(_)
                | OperationsCommand::Cancel(_)
                | OperationsCommand::Acknowledge(_)
        } | Command::Processes {
            command: ProcessesCommand::Stop(_)
        } | Command::Policy {
            command: PolicyCommand::Rearm(_)
        }
    )
}

/// Writes all of `bytes`. The user can interrupt a write that blocks.
///
/// `write_all` retries a write that `EINTR` ended, so a blocked write to a
/// full pipe would never return after Ctrl+C. A write that the signal cut
/// short returns the count of the bytes that it took, with no error. This
/// function reads the flag after such a write and at each `EINTR`, and ends
/// with `ErrorKind::Interrupted` when the flag is set. The flag is never set
/// in a command that did not arm it, so there the behavior is that of
/// `write_all`.
pub(crate) fn write_interruptible(
    stdout: &mut dyn Write,
    mut bytes: &[u8],
    interrupt: &Interrupt,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match stdout.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => {
                bytes = &bytes[written..];
                if !bytes.is_empty() && interrupt.is_requested() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if interrupt.is_requested() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// The bytes of one JSON value and a newline.
pub(crate) fn json_line<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes: Vec<u8> = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn check_format(command: &Command, format: Format) -> Result<(), ErrorBody> {
    let message: String = match (command, format) {
        (Command::Completions(_), Format::Json | Format::Ndjson) => {
            "`svalnir completions` writes a shell script; use `--format text`".to_owned()
        }
        (command, Format::Ndjson) if !command.is_streaming() => format!(
            "`svalnir {}` is not a streaming command; use `--format json`",
            command.path()
        ),
        (command, Format::Json) if command.is_streaming() => format!(
            "`svalnir {}` is a streaming command; use `--format ndjson`",
            command.path()
        ),
        _ => return Ok(()),
    };
    Err(ErrorBody {
        code: "unsupported_format".into(),
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message,
        fields: &["format"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    })
}

/// A rule selects the candidates of the `evict` mode only.
fn check_rule_selection(command: &Command) -> Result<(), ErrorBody> {
    let Command::Clean {
        command: CleanCommand::Plan(plan),
    } = command
    else {
        return Ok(());
    };
    if plan.rule.is_none() || plan.mode == CleanMode::Evict {
        return Ok(());
    }
    Err(ErrorBody {
        code: "unsupported_rule_selection".into(),
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: "`--rule` applies only to `--mode evict`".to_owned(),
        fields: &["rule", "mode"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    })
}

/// The error for arguments that the parser rejected.
pub(crate) fn invalid_arguments(reason: Option<&str>) -> ErrorBody {
    ErrorBody {
        code: "invalid_arguments".into(),
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: format!(
            "the arguments are not valid: {}; stderr has the details",
            reason.unwrap_or("the parser rejected them")
        ),
        fields: &[],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    }
}

fn not_implemented(command: &Command) -> ErrorBody {
    ErrorBody {
        code: "not_implemented".into(),
        family: ErrorFamily::Native,
        stage: ErrorStage::Dispatch,
        message: format!(
            "`svalnir {}` is not implemented in this build; the command made no change",
            command.path()
        ),
        fields: &[],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    }
}
