//! The `HOME` check of the commands that change state.
//!
//! A command that changes state uses the home directory for the default
//! state directory, the home protections, and the Trash. Before it changes
//! anything, it compares `HOME` with the home directory of the account
//! record of the effective user, with the check of `svalnir-agent`, and
//! refuses a difference (`docs/INTERFACES.md` section 4). A read-only
//! command has no check.

use svalnir_agent::platform::account::{AccountSource, HomeError, verify_home};

use crate::cli::{AgentCommand, CleanCommand, Command, OperationsCommand, PolicyCommand};
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};

/// Whether `command` changes state. `scan` writes a scan record to the
/// rebuildable catalog store only, and is a read-only command.
fn changes_state(command: &Command) -> bool {
    matches!(
        command,
        Command::Clean {
            command: CleanCommand::Plan(_) | CleanCommand::Apply(_),
        } | Command::Processes {
            command: crate::cli::ProcessesCommand::Stop(_),
        } | Command::Operations {
            command: OperationsCommand::Cancel(_) | OperationsCommand::Acknowledge(_),
        } | Command::Config {
            command: crate::cli::ConfigCommand::Apply(_),
        } | Command::Policy {
            command: PolicyCommand::Enable(_) | PolicyCommand::Disable(_) | PolicyCommand::Rearm(_),
        } | Command::Agent {
            command: AgentCommand::Pause(_)
                | AgentCommand::Resume
                | AgentCommand::Install(_)
                | AgentCommand::Uninstall(_),
        }
    )
}

/// Refuses a command that changes state when `HOME` is not the home
/// directory of the account record of the effective user. Each other
/// command passes.
///
/// # Errors
///
/// Returns the error of the check, with the family `native` (exit `3`).
pub(crate) fn check(command: &Command, environment: &Environment) -> Result<(), ErrorBody> {
    if !changes_state(command) {
        return Ok(());
    }
    let account: Box<dyn AccountSource> = environment.seams.account_source();
    verify_home(environment.home.as_deref(), account.as_ref())
        .map(drop)
        .map_err(|error| home_error(&error))
}

fn home_error(error: &HomeError) -> ErrorBody {
    let message: &'static str = match error {
        HomeError::NotSet => "`HOME` is not set; the command made no change",
        HomeError::NoAccountRecord | HomeError::AccountLookup(_) => {
            "the account record of the effective user has no home directory or cannot be read; the command made no change"
        }
        HomeError::NotResolvable(_) => {
            "`HOME` or the home directory of the account record does not exist or is not accessible; the command made no change"
        }
        HomeError::Mismatch => {
            "`HOME` is not the home directory of the account record of the effective user; start the command with the `HOME` of this user; the command made no change"
        }
    };
    ErrorBody::new(
        error.code(),
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        message,
    )
    .with_next_action(NextAction::None)
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::changes_state;
    use crate::cli::Cli;

    fn command(arguments: &[&str]) -> crate::cli::Command {
        let mut all: Vec<&str> = vec!["svalnir"];
        all.extend_from_slice(arguments);
        Cli::try_parse_from(all).unwrap().command
    }

    #[test]
    fn each_command_that_changes_state_has_the_check() {
        for arguments in [
            &["clean", "plan", "--scan", "s"][..],
            &["clean", "apply", "--plan", "p"],
            &["processes", "stop", "--target", "t"],
            &["operations", "cancel", "--operation", "o"],
            &["operations", "acknowledge", "--operation", "o"],
            &[
                "config",
                "apply",
                "--config",
                "/c.toml",
                "--expected-revision",
                "none",
            ],
            &["policy", "enable", "memory-guard"],
            &["policy", "disable", "memory-guard"],
            &[
                "policy",
                "rearm",
                "memory-guard",
                "--incident",
                "i",
                "--generation",
                "1",
            ],
            &["agent", "pause", "--for", "1h"],
            &["agent", "resume"],
            &["agent", "install"],
            &["agent", "uninstall"],
        ] {
            assert!(changes_state(&command(arguments)), "{arguments:?}");
        }
    }

    #[test]
    fn a_read_only_command_has_no_check() {
        for arguments in [
            &["status"][..],
            &["doctor"],
            &["scan", "/tmp"],
            &["report", "--scan", "s"],
            &["clean", "show", "--plan", "p"],
            &["operations", "show", "--operation", "o"],
            &["operations", "wait", "--operation", "o"],
            &["history"],
            &["agent", "status"],
            &["config", "show"],
            &["policy", "list"],
            &["license"],
        ] {
            assert!(!changes_state(&command(arguments)), "{arguments:?}");
        }
    }
}
