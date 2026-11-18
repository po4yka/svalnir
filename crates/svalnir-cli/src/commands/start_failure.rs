//! The start-failure record of the agent in `agent status` and `doctor`.
//!
//! The agent writes the record at a permanent start error and removes it
//! at its next successful start. The view reads it from the state
//! directory, also when no agent runs. The read makes no state directory.

use serde::Serialize;
use svalnir_agent::runtime::start_failure::{StartFailure, StartFailureReason, read_start_failure};
use svalnir_core::time::WallTime;

use crate::environment::Environment;
use crate::text::{escape, put_line};

/// The latest permanent start error of the agent.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum StartFailureView {
    /// The state directory has no record: the latest start of the agent
    /// had no permanent error, or no agent started on it.
    None,
    /// The record of the latest permanent start error.
    Recorded {
        reason: StartFailureReason,
        message: String,
        failed_at: Option<WallTime>,
        agent_version: String,
    },
    /// The record exists and this build cannot read it.
    NotReadable,
    /// The state directory is not known.
    StateDirectoryUnknown,
}

impl StartFailureView {
    /// Reads the record of the state directory of `environment`.
    pub(crate) fn read(environment: &Environment) -> Self {
        let Ok(state) = environment.state_directory() else {
            return Self::StateDirectoryUnknown;
        };
        match read_start_failure(&state) {
            Ok(None) => Self::None,
            Ok(Some(StartFailure {
                reason,
                message,
                failed_at,
                agent_version,
                ..
            })) => Self::Recorded {
                reason,
                message,
                failed_at,
                agent_version,
            },
            Err(_) => Self::NotReadable,
        }
    }

    /// Adds one line, and a second line for a record, to `out`.
    pub(crate) fn render(&self, out: &mut String) {
        match self {
            Self::None => out.push_str("Agent start failure: none recorded\n"),
            Self::Recorded {
                reason,
                message,
                failed_at,
                agent_version,
            } => {
                let at: String =
                    failed_at.map_or_else(|| "an unknown time".to_owned(), |at| at.to_string());
                put_line!(
                    out,
                    "Agent start failure: {} at {at}, agent {}",
                    reason.code(),
                    escape(agent_version)
                );
                put_line!(
                    out,
                    "  {}; the agent stays stopped until the cause is corrected and it is started again",
                    escape(message)
                );
            }
            Self::NotReadable => out
                .push_str("Agent start failure: a record exists, and this build cannot read it\n"),
            Self::StateDirectoryUnknown => {
                out.push_str("Agent start failure: the state directory is not known\n");
            }
        }
    }
}
