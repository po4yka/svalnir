//! Command execution.
//!
//! The commands that need no agent run here. Each other command reports that
//! this build does not implement it. No command in this module deletes a
//! file or signals a process.

use std::io::{self, Write};

use clap::CommandFactory;
use serde::Serialize;

use crate::cli::{Cli, Command, Format};
use crate::output::{Envelope, ErrorBody, ErrorFamily, ErrorStage, Kind, NextAction, RequestId};

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

#[derive(Debug, Serialize)]
struct LicenseReport {
    spdx_id: &'static str,
    text: &'static str,
}

pub(crate) fn execute(
    cli: &Cli,
    request_id: &RequestId,
    stdout: &mut dyn Write,
) -> Result<(), CommandFailure> {
    let format: Format = cli.common.format;
    check_format(&cli.command, format)?;
    match &cli.command {
        Command::Completions(arguments) => {
            // `generate` panics on a write error, so it writes to memory first.
            let mut script: Vec<u8> = Vec::new();
            clap_complete::generate(arguments.shell, &mut Cli::command(), "svalnir", &mut script);
            stdout.write_all(&script)?;
        }
        Command::License => match format {
            Format::Text => {
                stdout.write_all(LICENSE_NOTICE.as_bytes())?;
                stdout.write_all(b"\n")?;
                stdout.write_all(LICENSE_TEXT.as_bytes())?;
            }
            Format::Json | Format::Ndjson => {
                let report = LicenseReport {
                    spdx_id: LICENSE_SPDX_ID,
                    text: LICENSE_TEXT,
                };
                write_json(
                    stdout,
                    &Envelope::result(request_id.clone(), Kind::Report, report),
                )?;
            }
        },
        command => return Err(not_implemented(command).into()),
    }
    Ok(())
}

/// Writes one JSON value and a newline.
pub(crate) fn write_json<T: Serialize>(stdout: &mut dyn Write, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *stdout, value)?;
    stdout.write_all(b"\n")
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
