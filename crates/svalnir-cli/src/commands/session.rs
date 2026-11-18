//! The shared inputs of the commands that read or write the operation
//! journal: the principal, the journal connection, the times, the authority
//! record, and the conversion of library errors to structured errors.
//!
//! Milestone 2 has no socket. A client and the agent share state through
//! the journal in the state directory (`docs/INTERFACES.md` section 4).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use svalnir_agent::journal::{
    AgentRecord, JournalOptions, OperationJournal, OperationJournalError,
};
use svalnir_core::action::{ActionError, ClientRole, Principal};
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::grant::{ActiveRevision, AuthorityState, ControlClock};
use svalnir_core::policy::{ContinuityGeneration, EvaluationClock};
use svalnir_core::process::Uid;
use svalnir_core::time::WallTime;

pub(crate) use svalnir_agent::observe::{CoordinatorPresence, coordinator_presence};

use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, NextAction};

/// The user of this process.
pub(crate) fn current_uid() -> Uid {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no argument, changes nothing, and does not
        // fail.
        Uid::new(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        Uid::new(0)
    }
}

/// The principal of a request of this client. The journal is same-user
/// state: the principal is a record, not an authentication.
pub(crate) fn principal() -> Principal {
    Principal {
        uid: current_uid(),
        session: None,
        role: ClientRole::Cli,
    }
}

/// A new identity text: the prefix, the wall-clock time, the process ID,
/// and a counter of this process.
pub(crate) fn new_id(prefix: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanoseconds: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "{prefix}_{nanoseconds:x}_{:x}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
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
        let context = host.context();
        let identity = context.identity();
        let unavailable = |_| {
            ErrorBody::new(
                "clock_unavailable",
                ErrorFamily::Native,
                ErrorStage::Collection,
                "a clock of this host gave no value; the command made no change",
            )
        };
        Ok(Self {
            clock: EvaluationClock {
                now: context.clock().monotonic_now().map_err(unavailable)?,
                clock_domain: identity.clock_domain.clone(),
                boot_id: identity.boot_id.clone(),
                continuity: ContinuityGeneration::new(0),
                last_discontinuity: None,
            },
            wall: context.clock().wall_now().map_err(unavailable)?,
        })
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
    WallTime::try_from(SystemTime::now()).map_err(|_| {
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
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(journal_error(&OperationJournalError::NotAJournal)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(ErrorBody::new(
                "journal_unavailable",
                ErrorFamily::Recording,
                ErrorStage::Storage,
                "the operation journal cannot be inspected",
            ));
        }
    }
    OperationJournal::open(&path, &journal_options())
        .map(Some)
        .map_err(|error| journal_error(&error))
}

/// Opens the journal for a command that writes. Makes the state directory
/// and the journal when they do not exist.
pub(crate) fn open_journal(environment: &Environment) -> Result<OperationJournal, ErrorBody> {
    environment.create_state_directory()?;
    OperationJournal::open(&environment.journal_path()?, &journal_options())
        .map_err(|error| journal_error(&error))
}

/// The authority record of the journal with its record revision.
#[derive(Debug, Clone)]
pub(crate) struct StoredAuthority {
    /// The record. With no record, the state of a user with no activation.
    pub(crate) state: AuthorityState,
    /// The revision of the record, or 0 with no record.
    pub(crate) revision: u64,
}

/// Reads the authority record.
///
/// # Errors
///
/// Returns an authority error for a record of a different user, and a
/// recording error for a record that cannot be read.
pub(crate) fn read_authority(journal: &OperationJournal) -> Result<StoredAuthority, ErrorBody> {
    let uid: Uid = current_uid();
    match journal
        .agent_record::<AuthorityState>(AgentRecord::Authority)
        .map_err(|error| journal_error(&error))?
    {
        None => Ok(StoredAuthority {
            state: AuthorityState::new(uid),
            revision: 0,
        }),
        Some(stored) if stored.record.principal != uid => Err(ErrorBody::new(
            "authority_record_of_a_different_user",
            ErrorFamily::Authority,
            ErrorStage::Storage,
            "the authority record of the journal is of a different user; the command made no change",
        )),
        Some(stored) => Ok(StoredAuthority {
            state: stored.record,
            revision: stored.revision,
        }),
    }
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
#[derive(Debug, Clone)]
pub(crate) struct ActiveConfig {
    /// The revision and its scope.
    pub(crate) active: ActiveRevision,
    /// The validated configuration of the revision.
    pub(crate) config: ValidatedConfig,
}

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
    let active: &ActiveRevision = state.active.as_ref().ok_or_else(no_active_revision)?;
    let not_usable = || {
        ErrorBody::new(
            "policy_revision_source_not_usable",
            ErrorFamily::Recording,
            ErrorStage::Storage,
            "the journal does not have a usable configuration text for the revision in effect; activate the configuration again",
        )
    };
    let source: String = journal
        .policy_revision_source(&active.revision.revision_id)
        .map_err(|error| journal_error(&error))?
        .ok_or_else(not_usable)?;
    if ContentDigest::of_bytes(source.as_bytes()) != active.revision.content {
        return Err(not_usable());
    }
    let config: ValidatedConfig = parse_and_validate(&source)
        .config()
        .cloned()
        .ok_or_else(not_usable)?;
    Ok(ActiveConfig {
        active: active.clone(),
        config,
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
