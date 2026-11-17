//! Command dispatch.
//!
//! This module selects the function that runs a command. Each command
//! family is a module of its own, with the collection of the data separate
//! from the rendering. The read-only commands run in this process through
//! the agent library. Each command that changes the host, a policy, or the
//! agent reports `not_implemented`. No command of this build deletes a file,
//! moves a file to Trash, signals a process, registers a service, or
//! activates a policy.

use std::io::{self, Write};

use clap::CommandFactory;
use serde::Serialize;

use crate::cli::{
    CleanCommand, CleanMode, Cli, Command, ConfigCommand, Format, MemoryCommand, PolicyCommand,
    ProcessesCommand, SwapCommand,
};
use crate::environment::Environment;
use crate::output::{
    Envelope, ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction, RequestId, Warning,
};

pub(crate) mod config;
pub(crate) mod doctor;
pub(crate) mod monitor;
pub(crate) mod policy;
pub(crate) mod processes;
pub(crate) mod resources;
pub(crate) mod scan;

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
                self.stdout.write_all(text(view).as_bytes())
            }
            Format::Json | Format::Ndjson => write_json(
                self.stdout,
                &Envelope::result(self.request_id.clone(), kind, view).with_warnings(warnings),
            ),
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
        warnings: Vec::new(),
    };
    if cli.common.timeout.is_some() && runs_in_process(&cli.command) {
        invocation.warnings.push(Warning {
            code: "timeout_not_applied",
            message: format!(
                "`svalnir {}` runs in this process and has no transport wait; `--timeout` has no effect",
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

fn dispatch(cli: &Cli, invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    match &cli.command {
        Command::Completions(arguments) => {
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
        command => Err(not_implemented(command).into()),
    }
}

/// Whether this build runs the command in the client process.
fn runs_in_process(command: &Command) -> bool {
    !matches!(
        command,
        Command::Clean { .. }
            | Command::Operations { .. }
            | Command::Agent { .. }
            | Command::History(_)
            | Command::Processes {
                command: ProcessesCommand::Stop(_)
            }
            | Command::Policy {
                command: PolicyCommand::Enable(_)
                    | PolicyCommand::Disable(_)
                    | PolicyCommand::Rearm(_)
            }
            | Command::Config {
                command: ConfigCommand::Apply(_)
            }
    )
}

/// Writes one JSON value and a newline.
///
/// The value is serialized to memory first, so a serialization failure
/// leaves no partial line in `stdout`.
pub(crate) fn write_json<T: Serialize>(stdout: &mut dyn Write, value: &T) -> io::Result<()> {
    stdout.write_all(&json_line(value)?)
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
        code: "unsupported_format",
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message,
        fields: vec!["format"],
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
        code: "unsupported_rule_selection",
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: "`--rule` applies only to `--mode evict`".to_owned(),
        fields: vec!["rule", "mode"],
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    })
}

/// The error for arguments that the parser rejected.
pub(crate) fn invalid_arguments(reason: Option<&str>) -> ErrorBody {
    ErrorBody {
        code: "invalid_arguments",
        family: ErrorFamily::Request,
        stage: ErrorStage::Arguments,
        message: format!(
            "the arguments are not valid: {}; stderr has the details",
            reason.unwrap_or("the parser rejected them")
        ),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::CorrectRequest,
    }
}

/// The error for a value that needs the background agent.
pub(crate) fn agent_unavailable(what: &str) -> ErrorBody {
    ErrorBody {
        code: "agent_unavailable",
        family: ErrorFamily::Native,
        stage: ErrorStage::Dispatch,
        message: format!(
            "{what} needs the background agent, and this build has no agent; the command made no change"
        ),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    }
}

fn not_implemented(command: &Command) -> ErrorBody {
    ErrorBody {
        code: "not_implemented",
        family: ErrorFamily::Native,
        stage: ErrorStage::Dispatch,
        message: format!(
            "`svalnir {}` is not implemented in this build; the command made no change",
            command.path()
        ),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::None,
    }
}
