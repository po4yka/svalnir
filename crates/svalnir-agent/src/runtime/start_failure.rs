//! The start-failure record of the agent and the classes of start errors.
//!
//! A start error is **permanent** when a new start with the same inputs
//! gives the same error: an invalid configuration, a `HOME` that is not
//! the home directory of the effective user, a refused state directory, or
//! a journal of a different version or that is not a journal. The agent
//! then writes one [`StartFailure`] record in its state directory and exits
//! with [`PERMANENT_START_ERROR_STATUS`], which the `KeepAlive` condition of
//! the `LaunchAgent` definition does not restart
//! ([`launch_agent::render`](super::launch_agent::render)). Each other start
//! error is **transient**: the agent exits with failure, and `launchd`
//! starts it again after its throttle interval.
//!
//! The record is one file, [`START_FAILURE_FILE_NAME`], with mode `0600`. A
//! new record replaces the earlier one with an atomic rename, and the next
//! successful start removes it. The record needs neither a valid
//! configuration nor a usable journal. When the state directory itself is
//! refused, the agent writes no record, and the standard error stream has
//! the one line of the failure. The record has a reason code, a fixed
//! message, the time, and the version of the agent: no path, no secret, and
//! no value of the environment.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svalnir_core::time::WallTime;

use super::DriverError;
use crate::coordinator::StartError;
use crate::journal::OperationJournalError;
use crate::platform::account::HomeError;

/// The file name of the start-failure record in the state directory.
pub const START_FAILURE_FILE_NAME: &str = "agent-start-failure.json";

/// The version of the [`StartFailure`] record.
pub const START_FAILURE_VERSION: u32 = 1;

/// The exit status of a permanent start error. The `LaunchAgent` definition
/// has `KeepAlive` with `SuccessfulExit` false: `launchd` starts the job
/// again only after an exit status that is not zero, so this status keeps
/// the agent stopped until the user corrects the cause.
pub const PERMANENT_START_ERROR_STATUS: u8 = 0;

/// The largest record that a read accepts, in bytes.
const MAX_RECORD_BYTES: u64 = 16 * 1024;

/// The name of the temporary file of a write, in the state directory.
const TEMPORARY_FILE_NAME: &str = "agent-start-failure.json.tmp";

/// The reason of a permanent start error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartFailureReason {
    /// The configuration file cannot be read, is not a regular file, or is
    /// too large.
    ConfigurationNotReadable,
    /// The configuration is not valid.
    ConfigurationInvalid,
    /// `HOME` is not set.
    HomeNotSet,
    /// The effective user has no account record with a home directory, or
    /// the record cannot be read.
    HomeAccountUnknown,
    /// `HOME` or the home directory of the account record cannot be
    /// resolved.
    HomeNotResolvable,
    /// `HOME` is not the home directory of the account record.
    HomeMismatch,
    /// The state directory is refused. No record is written for this
    /// reason: the record would be in the refused directory.
    StateDirectoryRefused,
    /// The journal is of an earlier version and has no migration.
    JournalOlderVersion,
    /// The journal is of a later version.
    JournalNewerVersion,
    /// The file at the journal path is not an operation journal.
    JournalNotRecognized,
    /// The journal file is corrupt.
    JournalCorrupt,
}

impl StartFailureReason {
    /// The stable code of the reason.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConfigurationNotReadable => "configuration_not_readable",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::HomeNotSet => "home_not_set",
            Self::HomeAccountUnknown => "home_account_unknown",
            Self::HomeNotResolvable => "home_not_resolvable",
            Self::HomeMismatch => "home_mismatch",
            Self::StateDirectoryRefused => "state_directory_refused",
            Self::JournalOlderVersion => "journal_older_version",
            Self::JournalNewerVersion => "journal_newer_version",
            Self::JournalNotRecognized => "journal_not_recognized",
            Self::JournalCorrupt => "journal_corrupt",
        }
    }

    /// A fixed message with the correction. It has no path.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ConfigurationNotReadable => {
                "the configuration file is not readable, is not a regular file, or is too large"
            }
            Self::ConfigurationInvalid => {
                "the configuration is not valid; `svalnir config validate` shows the findings"
            }
            Self::HomeNotSet => "`HOME` is not set",
            Self::HomeAccountUnknown => {
                "the account record of the effective user has no home directory or cannot be read"
            }
            Self::HomeNotResolvable => "the home directory does not exist or is not accessible",
            Self::HomeMismatch => {
                "`HOME` is not the home directory of the account record of the effective user"
            }
            Self::StateDirectoryRefused => {
                "the state directory is a symbolic link, is not a directory, has a different owner, or permits access to the group or to other users"
            }
            Self::JournalOlderVersion => {
                "the operation journal is of an earlier build and has no migration"
            }
            Self::JournalNewerVersion => "the operation journal is of a newer build",
            Self::JournalNotRecognized => {
                "the file at the journal path is not an operation journal"
            }
            Self::JournalCorrupt => "the operation journal file is corrupt",
        }
    }

    /// The reason of a `HOME` error that is permanent. `None`: the error
    /// is transient. A lookup of the account record that failed, for
    /// example because the directory service is not ready at login, can
    /// pass at a later start; an account with no record cannot.
    #[must_use]
    pub const fn of_home(error: &HomeError) -> Option<Self> {
        match error {
            HomeError::NotSet => Some(Self::HomeNotSet),
            HomeError::NoAccountRecord => Some(Self::HomeAccountUnknown),
            HomeError::AccountLookup(_) => None,
            HomeError::NotResolvable(_) => Some(Self::HomeNotResolvable),
            HomeError::Mismatch => Some(Self::HomeMismatch),
        }
    }

    /// The reason of a journal error that is permanent. `None`: the error
    /// is transient, for example a busy journal or an input or output
    /// error.
    #[must_use]
    pub const fn of_journal(error: &OperationJournalError) -> Option<Self> {
        match error {
            OperationJournalError::OlderVersion { .. } => Some(Self::JournalOlderVersion),
            OperationJournalError::NewerVersion { .. } => Some(Self::JournalNewerVersion),
            OperationJournalError::NotAJournal => Some(Self::JournalNotRecognized),
            OperationJournalError::Corrupt(_) => Some(Self::JournalCorrupt),
            _ => None,
        }
    }

    /// The reason of a start error of the driver that is permanent.
    /// `None`: the error is transient. A held coordinator lock is not an
    /// error of the driver ([`DriverStart::Busy`](super::DriverStart)).
    #[must_use]
    pub const fn of_driver(error: &DriverError) -> Option<Self> {
        match error {
            DriverError::Journal(error) | DriverError::Coordinator(StartError::Journal(error)) => {
                Self::of_journal(error)
            }
            DriverError::Coordinator(StartError::Lock(_) | StartError::Clock)
            | DriverError::Clock
            | DriverError::Reconciliation => None,
        }
    }
}

/// The record of the latest permanent start error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartFailure {
    /// [`START_FAILURE_VERSION`].
    pub schema_version: u32,
    /// The reason.
    pub reason: StartFailureReason,
    /// The fixed message of the reason.
    pub message: String,
    /// The wall-clock time of the failure. `None` when the clock gave no
    /// time.
    pub failed_at: Option<WallTime>,
    /// The version of the agent that failed.
    pub agent_version: String,
}

impl StartFailure {
    /// The record of `reason` at `failed_at`.
    #[must_use]
    pub fn new(reason: StartFailureReason, failed_at: Option<WallTime>) -> Self {
        Self {
            schema_version: START_FAILURE_VERSION,
            reason,
            message: reason.message().to_owned(),
            failed_at,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// Why a start-failure record cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum StartFailureReadError {
    /// The file cannot be read, is not a regular file, or is too large.
    #[error("the start-failure record cannot be read")]
    File(#[source] std::io::Error),
    /// The file is not a record of this version.
    #[error("the start-failure record cannot be decoded")]
    Decode(#[source] serde_json::Error),
}

/// The path of the record in `state_directory`.
#[must_use]
pub fn start_failure_path(state_directory: &Path) -> PathBuf {
    state_directory.join(START_FAILURE_FILE_NAME)
}

/// Writes `record` to `state_directory`, in place of an earlier record.
///
/// The record goes to a temporary file with mode `0600`, which is synced
/// and then renamed to [`START_FAILURE_FILE_NAME`]; then the directory is
/// synced. A reader sees the earlier record or the new one.
///
/// # Errors
///
/// Returns the error of a file operation. The earlier record then stays.
pub fn write_start_failure(state_directory: &Path, record: &StartFailure) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let text: Vec<u8> = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let temporary: PathBuf = state_directory.join(TEMPORARY_FILE_NAME);
    // A temporary file of a write that did not complete.
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(&text)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, start_failure_path(state_directory))?;
    std::fs::File::open(state_directory)?.sync_all()
}

/// Reads the record of `state_directory`. `Ok(None)`: there is none.
///
/// # Errors
///
/// Returns a [`StartFailureReadError`] when the file exists and cannot be
/// read or decoded.
pub fn read_start_failure(
    state_directory: &Path,
) -> Result<Option<StartFailure>, StartFailureReadError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file: std::fs::File = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(start_failure_path(state_directory))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StartFailureReadError::File(error)),
    };
    if !file
        .metadata()
        .map_err(StartFailureReadError::File)?
        .is_file()
    {
        return Err(StartFailureReadError::File(
            std::io::ErrorKind::InvalidInput.into(),
        ));
    }
    let mut text: Vec<u8> = Vec::new();
    file.take(MAX_RECORD_BYTES.saturating_add(1))
        .read_to_end(&mut text)
        .map_err(StartFailureReadError::File)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
        return Err(StartFailureReadError::File(
            std::io::ErrorKind::FileTooLarge.into(),
        ));
    }
    serde_json::from_slice(&text)
        .map(Some)
        .map_err(StartFailureReadError::Decode)
}

/// Removes the record of `state_directory`. A record that does not exist
/// is not an error.
///
/// # Errors
///
/// Returns the error of the removal.
pub fn remove_start_failure(state_directory: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(start_failure_path(state_directory)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use svalnir_core::time::WallTime;

    use super::{
        START_FAILURE_FILE_NAME, StartFailure, StartFailureReadError, StartFailureReason,
        read_start_failure, remove_start_failure, start_failure_path, write_start_failure,
    };
    use crate::coordinator::StartError;
    use crate::journal::OperationJournalError;
    use crate::platform::account::HomeError;
    use crate::runtime::DriverError;

    fn sqlite_error() -> rusqlite::Error {
        rusqlite::Error::InvalidQuery
    }

    #[test]
    fn each_home_error_but_a_failed_account_lookup_is_permanent() {
        for (error, code) in [
            (HomeError::NotSet, "home_not_set"),
            (HomeError::NoAccountRecord, "home_account_unknown"),
            (
                HomeError::NotResolvable(std::io::ErrorKind::NotFound.into()),
                "home_not_resolvable",
            ),
            (HomeError::Mismatch, "home_mismatch"),
        ] {
            assert_eq!(
                StartFailureReason::of_home(&error).map(StartFailureReason::code),
                Some(code)
            );
            assert_eq!(error.code(), code);
        }
        // A lookup that failed, for example because the directory service
        // is not ready at login, can pass at a later start.
        let lookup = HomeError::AccountLookup(std::io::ErrorKind::Other.into());
        assert_eq!(StartFailureReason::of_home(&lookup), None);
        assert_eq!(lookup.code(), "home_account_unknown");
    }

    #[test]
    fn a_journal_of_a_different_version_or_that_is_not_a_journal_is_permanent() {
        let permanent = [
            (
                OperationJournalError::OlderVersion {
                    found: 3,
                    supported: 4,
                },
                StartFailureReason::JournalOlderVersion,
            ),
            (
                OperationJournalError::NewerVersion {
                    found: 5,
                    supported: 4,
                },
                StartFailureReason::JournalNewerVersion,
            ),
            (
                OperationJournalError::NotAJournal,
                StartFailureReason::JournalNotRecognized,
            ),
            (
                OperationJournalError::Corrupt(sqlite_error()),
                StartFailureReason::JournalCorrupt,
            ),
        ];
        for (error, reason) in permanent {
            assert_eq!(StartFailureReason::of_journal(&error), Some(reason));
            assert_eq!(
                StartFailureReason::of_driver(&DriverError::Journal(error)),
                Some(reason)
            );
        }
        // The same error through the start of the coordinator.
        assert_eq!(
            StartFailureReason::of_driver(&DriverError::Coordinator(StartError::Journal(
                OperationJournalError::NotAJournal
            ))),
            Some(StartFailureReason::JournalNotRecognized)
        );
    }

    #[test]
    fn a_busy_journal_a_lock_error_and_an_io_error_are_transient() {
        for error in [
            DriverError::Journal(OperationJournalError::Busy(sqlite_error())),
            DriverError::Journal(OperationJournalError::Io(sqlite_error())),
            DriverError::Journal(OperationJournalError::File(
                std::io::ErrorKind::Interrupted.into(),
            )),
            DriverError::Coordinator(StartError::Lock(std::io::ErrorKind::WouldBlock.into())),
            DriverError::Coordinator(StartError::Clock),
            DriverError::Coordinator(StartError::Journal(OperationJournalError::Busy(
                sqlite_error(),
            ))),
            DriverError::Clock,
            DriverError::Reconciliation,
        ] {
            assert_eq!(StartFailureReason::of_driver(&error), None, "{error:?}");
        }
    }

    fn record(reason: StartFailureReason) -> StartFailure {
        StartFailure::new(reason, Some(WallTime::from_unix(1_800_000_000, 0).unwrap()))
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_record_is_private_replaces_the_earlier_one_and_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let state: &Path = temp.path();
        assert!(read_start_failure(state).unwrap().is_none());
        let first: StartFailure = record(StartFailureReason::ConfigurationInvalid);
        write_start_failure(state, &first).unwrap();
        assert_eq!(read_start_failure(state).unwrap(), Some(first));
        assert_eq!(mode(&start_failure_path(state)), 0o600);
        let second: StartFailure = record(StartFailureReason::HomeMismatch);
        write_start_failure(state, &second).unwrap();
        assert_eq!(read_start_failure(state).unwrap(), Some(second));
        // One record, and no temporary file.
        let names: Vec<String> = std::fs::read_dir(state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, [START_FAILURE_FILE_NAME]);
        remove_start_failure(state).unwrap();
        assert!(read_start_failure(state).unwrap().is_none());
        // A removal with no record is not an error.
        remove_start_failure(state).unwrap();
    }

    #[test]
    fn a_record_has_the_code_a_fixed_message_and_the_version() {
        let json: serde_json::Value =
            serde_json::to_value(record(StartFailureReason::HomeMismatch)).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["reason"], "home_mismatch");
        assert_eq!(json["message"], StartFailureReason::HomeMismatch.message());
        assert_eq!(json["agent_version"], env!("CARGO_PKG_VERSION"));
        assert!(json["failed_at"].is_string());
    }

    #[test]
    fn a_record_that_is_not_a_record_or_is_a_link_is_not_readable() {
        let temp = tempfile::tempdir().unwrap();
        let state: &Path = temp.path();
        std::fs::write(start_failure_path(state), b"{\"reason\":1}").unwrap();
        assert!(matches!(
            read_start_failure(state),
            Err(StartFailureReadError::Decode(_))
        ));
        std::fs::remove_file(start_failure_path(state)).unwrap();
        let target = state.join("target");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, start_failure_path(state)).unwrap();
        assert!(matches!(
            read_start_failure(state),
            Err(StartFailureReadError::File(_))
        ));
    }
}
