//! The shared inputs of the commands that read or write the operation
//! journal: the principal, the journal connection, the times, the authority
//! record, and the conversion of library errors to structured errors.
//!
//! Milestone 2 has no socket. A client and the agent share state through
//! the journal in the state directory (`docs/INTERFACES.md` section 4).

use std::path::PathBuf;
use std::time::SystemTime;

use svalnir_agent::journal::{JournalOptions, OperationJournal, OperationJournalError};
use svalnir_core::action::{ActionError, ClientRole, Principal};
use svalnir_core::grant::{AuthorityState, ControlClock};
use svalnir_core::policy::EvaluationClock;
use svalnir_core::process::Uid;
use svalnir_core::time::WallTime;

use svalnir_agent::observe;
pub(crate) use svalnir_agent::observe::{
    AuthorityReadError, CoordinatorPresence, ExistingJournalError, StoredAuthority,
    coordinator_presence,
};

use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};

/// The user of this process.
pub(crate) fn current_uid() -> Uid {
    observe::current_uid()
}

/// The principal of a request of this client. The journal is same-user
/// state: the principal is a record, not an authentication.
pub(crate) fn principal() -> Principal {
    svalnir_agent::client::principal(ClientRole::Cli)
}

/// A new identity text: the prefix, the wall-clock time, the process ID,
/// and a counter of this process.
pub(crate) fn new_id(prefix: &str) -> String {
    svalnir_agent::client::new_id(prefix)
}

/// The error for an identity that could not be made.
pub(crate) fn identity_error() -> ErrorBody {
    ErrorBody::new(
        "identity_unavailable",
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        "an identity of the request cannot be made; the command made no change",
    )
}

/// The times of one invocation.
#[derive(Debug, Clone)]
pub(crate) struct Now {
    /// The monotonic time, with its clock domain and boot.
    pub(crate) clock: EvaluationClock,
    /// The wall-clock time.
    pub(crate) wall: WallTime,
}

impl Now {
    /// Reads the clocks of the collection context.
    pub(crate) fn read(host: &Host) -> Result<Self, ErrorBody> {
        let (clock, wall) = svalnir_agent::client::control_time(host.context()).map_err(|_| {
            ErrorBody::new(
                "clock_unavailable",
                ErrorFamily::Native,
                ErrorStage::Collection,
                "a clock of this host gave no value; the command made no change",
            )
        })?;
        Ok(Self { clock, wall })
    }

    /// The clock of a control request.
    pub(crate) fn control(&self) -> ControlClock<'_> {
        ControlClock {
            clock: &self.clock,
            wall: self.wall,
        }
    }
}

/// The wall-clock time of the system clock, for a time that is display
/// data. A clock with no value gives the epoch.
pub(crate) fn wall_now() -> WallTime {
    WallTime::try_from(SystemTime::now()).unwrap_or(WallTime::UNIX_EPOCH)
}

/// The wall-clock time of the system clock, for the time of an authority
/// record.
///
/// # Errors
///
/// Returns `clock_unavailable` when the clock has no value that a record
/// can hold: a record must not get the epoch as its time.
pub(crate) fn record_time() -> Result<WallTime, ErrorBody> {
    record_time_of(SystemTime::now())
}

/// The record time of `time`. See [`record_time`].
fn record_time_of(time: SystemTime) -> Result<WallTime, ErrorBody> {
    WallTime::try_from(time).map_err(|_| {
        ErrorBody::new(
            "clock_unavailable",
            ErrorFamily::Native,
            ErrorStage::Collection,
            "the system clock has no value that a record can hold; the command made no change",
        )
    })
}

/// The settings of a journal connection of the client.
fn journal_options() -> JournalOptions {
    JournalOptions::default()
}

/// Converts a journal failure. The message has no path and no record
/// content.
pub(crate) fn journal_error(error: &OperationJournalError) -> ErrorBody {
    let (code, family, message): (&'static str, ErrorFamily, &'static str) = match error {
        OperationJournalError::Busy(_) => (
            "journal_busy",
            ErrorFamily::Recording,
            "the operation journal is locked by a different process; try the command again",
        ),
        OperationJournalError::QueueFull { .. } => (
            "queue_full",
            ErrorFamily::Limits,
            "the request queue of the journal is full; wait for the coordinator to serve it",
        ),
        OperationJournalError::AdmissionStopped(_) | OperationJournalError::Full(_) => (
            "journal_full",
            ErrorFamily::Recording,
            "the operation journal has no space for new work",
        ),
        OperationJournalError::NewerVersion { .. } => (
            "journal_newer_version",
            ErrorFamily::Recording,
            "the operation journal is of a newer build of Svalnir; this build does not change it",
        ),
        OperationJournalError::OlderVersion { .. } => (
            "journal_older_version",
            ErrorFamily::Recording,
            "the operation journal is of an earlier build of Svalnir and has no migration; this build does not change it",
        ),
        OperationJournalError::SchemaNotCurrent { .. } => (
            "journal_not_current",
            ErrorFamily::Recording,
            "the operation journal is not of the current version; this build does not change it",
        ),
        OperationJournalError::NotAJournal => (
            "journal_not_recognized",
            ErrorFamily::Recording,
            "the file at the journal path is not an operation journal; this build does not change it",
        ),
        OperationJournalError::Conflict => (
            "journal_conflict",
            ErrorFamily::Evidence,
            "a different process changed the record at the same time; read the state again and decide again",
        ),
        OperationJournalError::NotFound => (
            "record_not_found",
            ErrorFamily::Evidence,
            "the journal has no such record",
        ),
        OperationJournalError::PlanVersion { .. } => {
            return super::plan_store::plan_version_not_supported("stored plan");
        }
        _ => (
            "journal_unavailable",
            ErrorFamily::Recording,
            "the operation journal cannot be used",
        ),
    };
    let next_action: NextAction = match family {
        ErrorFamily::Evidence => NextAction::RefreshObservation,
        ErrorFamily::Limits => NextAction::RespectLimits,
        _ => NextAction::None,
    };
    ErrorBody::new(code, family, ErrorStage::Storage, message).with_next_action(next_action)
}

/// Opens the journal when its file exists. A query does not make the
/// state directory or the journal.
pub(crate) fn open_existing_journal(
    environment: &Environment,
) -> Result<Option<OperationJournal>, ErrorBody> {
    let path: PathBuf = environment.journal_path()?;
    observe::open_existing_journal(&path, &journal_options()).map_err(|error| match error {
        ExistingJournalError::NotAJournal => journal_error(&OperationJournalError::NotAJournal),
        ExistingJournalError::Inspect => ErrorBody::new(
            "journal_unavailable",
            ErrorFamily::Recording,
            ErrorStage::Storage,
            "the operation journal cannot be inspected",
        ),
        ExistingJournalError::Open(error) => journal_error(&error),
    })
}

/// Opens the journal for a command that writes. Makes the state directory
/// and the journal when they do not exist.
pub(crate) fn open_journal(environment: &Environment) -> Result<OperationJournal, ErrorBody> {
    environment.create_state_directory()?;
    OperationJournal::open(&environment.journal_path()?, &journal_options())
        .map_err(|error| journal_error(&error))
}

/// Reads the authority record.
///
/// # Errors
///
/// Returns an authority error for a record of a different user, and a
/// recording error for a record that cannot be read. A record that this
/// build cannot decode, for example a record of an earlier build, gives
/// `authority_record_not_readable` and no authority.
pub(crate) fn read_authority(journal: &OperationJournal) -> Result<StoredAuthority, ErrorBody> {
    observe::read_authority(journal, current_uid()).map_err(|error| match error {
        AuthorityReadError::Journal(OperationJournalError::Decode { .. }) => ErrorBody::new(
            "authority_record_not_readable",
            ErrorFamily::Recording,
            ErrorStage::Storage,
            "the authority record of the journal has a format that this build cannot read, for example the format of an earlier build; it gives no authority, and the command made no change; stop the agent and remove the operation journal `operations.sqlite` of the state directory to start with no authority record",
        ),
        AuthorityReadError::Journal(error) => journal_error(&error),
        AuthorityReadError::DifferentUser => ErrorBody::new(
            "authority_record_of_a_different_user",
            ErrorFamily::Authority,
            ErrorStage::Storage,
            "the authority record of the journal is of a different user; the command made no change",
        ),
    })
}

/// The error for a command that needs a policy revision in effect.
pub(crate) fn no_active_revision() -> ErrorBody {
    ErrorBody::new(
        "no_active_policy_revision",
        ErrorFamily::Authority,
        ErrorStage::Admission,
        "no configuration revision is in effect; activate one with `svalnir config apply --config PATH --expected-revision none`; the command made no change",
    )
}

/// The configuration of the revision in effect.
pub(crate) use svalnir_agent::client::ActiveConfig;

/// Reads the configuration text of the revision in effect and validates it
/// against the content digest of the revision, as the agent does.
///
/// # Errors
///
/// Returns `no_active_policy_revision` with no revision, and
/// `policy_revision_source_not_usable` when the journal does not have the
/// text of the revision or the text does not agree with the revision.
pub(crate) fn active_config(
    journal: &OperationJournal,
    state: &AuthorityState,
) -> Result<ActiveConfig, ErrorBody> {
    use svalnir_agent::client::ActiveConfigError;
    svalnir_agent::client::active_config(journal, state).map_err(|error| match error {
        ActiveConfigError::NoActiveRevision => no_active_revision(),
        ActiveConfigError::Journal(error) => journal_error(&error),
        ActiveConfigError::SourceNotUsable => ErrorBody::new(
            "policy_revision_source_not_usable",
            ErrorFamily::Recording,
            ErrorStage::Storage,
            "the journal does not have a usable configuration text for the revision in effect; activate the configuration again",
        ),
    })
}

/// A sentence for an error code of the coordinator or of the
/// authorization, when this client has one.
fn explanation(code: &str) -> Option<&'static str> {
    Some(match code {
        "plan_expired" => "the plan is expired; prepare a new plan",
        "plan_not_found" => "the journal has no plan with this ID",
        "approval_mismatch" | "manual_approval_mismatch" => {
            "the approval does not agree with the stored plan"
        }
        "policy_revision_changed" | "policy_revision_mismatch" => {
            "the configuration revision changed after the plan was prepared; prepare a new plan"
        }
        "no_active_policy_revision" => {
            "no configuration revision is in effect; activate one with `svalnir config apply`"
        }
        "target_protected" => "a hard protection applies to the target",
        "lease_unavailable" => {
            "a different operation uses the same root, volume, or process; wait for it"
        }
        "queue_full" => "too many operations wait; wait for one to end",
        "reconciliation_pending" => {
            "an earlier operation has an unknown effect; reconcile it before new work"
        }
        "rule_mode_not_validated" => {
            "the rule has no recorded validation for this mode, so the mode is not permitted"
        }
        "wrong_principal" | "plan_conflict" => "the plan is of a different user or request",
        "helper_not_available" => {
            "the plan needs the privileged helper, which this build does not call"
        }
        "operation_not_found" => "the journal has no operation with this ID",
        _ => return None,
    })
}

/// Converts an error record of the coordinator. `what` names the request
/// that was refused.
pub(crate) fn action_error(error: &ActionError, what: &str) -> ErrorBody {
    let code: &str = error.code.as_str();
    let detail: String = explanation(code).map_or_else(
        || format!("{what} was refused: {code}"),
        |sentence| format!("{what} was refused: {sentence} ({code})"),
    );
    let submitted: bool = error.dispatch.is_possibly_submitted();
    let next_action: NextAction = if submitted {
        NextAction::Reconcile
    } else if matches!(
        code,
        "plan_expired" | "policy_revision_changed" | "policy_revision_mismatch"
    ) {
        NextAction::PrepareNewPlan
    } else {
        match &error.family {
            ErrorFamily::Request => NextAction::CorrectRequest,
            ErrorFamily::Authority => NextAction::ResolveAuthority,
            ErrorFamily::Evidence => NextAction::RefreshObservation,
            ErrorFamily::Limits => NextAction::RespectLimits,
            ErrorFamily::Outcome | ErrorFamily::Unrecognized(_) => NextAction::Reconcile,
            ErrorFamily::Eligibility | ErrorFamily::Recording | ErrorFamily::Native => {
                NextAction::None
            }
        }
    };
    let message: String = if submitted {
        format!("{detail}; a call was possibly issued, so the effect is not known")
    } else {
        format!("{detail}; the request made no change")
    };
    ErrorBody {
        code: code.into(),
        family: error.family.clone(),
        stage: ErrorStage::Admission,
        message,
        fields: &[],
        operation_id: error
            .operation_id
            .as_ref()
            .map(|operation_id| operation_id.as_str().into()),
        plan_id: error
            .plan_id
            .as_ref()
            .map(|plan_id| plan_id.as_str().into()),
        next_action,
    }
}

/// The error for an identifier argument that is not valid.
pub(crate) fn invalid_identifier(
    code: &'static str,
    what: &str,
    fields: &'static [&'static str],
) -> ErrorBody {
    ErrorBody::new(
        code,
        ErrorFamily::Request,
        ErrorStage::Arguments,
        format!("the {what} is not valid; use the ID that Svalnir printed"),
    )
    .with_fields(fields)
}

#[cfg(test)]
mod record_time_tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::record_time_of;

    #[test]
    fn a_clock_value_that_a_record_cannot_hold_is_an_error_and_not_the_epoch() {
        let far: SystemTime = UNIX_EPOCH
            .checked_add(Duration::from_secs(300_000_000_001))
            .unwrap();
        let error = record_time_of(far).unwrap_err();
        assert_eq!(&*error.code, "clock_unavailable");
        assert!(record_time_of(UNIX_EPOCH + Duration::from_secs(1)).is_ok());
    }
}
