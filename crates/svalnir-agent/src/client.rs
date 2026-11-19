//! The client side of the request queue and of the authority record.
//!
//! This build has no socket and no XPC service. A client process (the CLI
//! or the GPUI client) reaches the agent through the operation journal: it
//! writes a request to the queue of the journal and reads its completion,
//! or it writes a new authority record with a compare-and-set on the record
//! revision. The functions here are that shared path, so that each client
//! uses the same identities, the same wait, and the same write.
//!
//! No function here admits a plan, executes a step, or takes the
//! coordinator lock. The coordinator of the agent decides each request.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use svalnir_core::action::{ClientRole, Principal};
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::grant::{
    Acknowledged, ActiveRevision, AuthorityState, Change, InstanceInhibition, Persistence,
};
use svalnir_core::id::RequestId;
use svalnir_core::plan::{StopLimits, StopStrategy};
use svalnir_core::policy::{ContinuityGeneration, EvaluationClock};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::WallTime;

use crate::journal::{
    AgentRecord, CoordinatorLock, CoordinatorRole, LockState, OperationJournal,
    OperationJournalError, RequestCompletion, RequestStatus,
};
use crate::observe::{self, CoordinatorPresence, StoredAuthority};
use crate::platform::memory::{ClockError, CollectionContext};

/// Which process holds the coordinator lock of a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPresence {
    /// The agent holds the lock, so a request in the queue is served.
    Agent,
    /// A client process holds the lock as a transient coordinator. It can
    /// stop before it serves a request of a different client.
    OtherCoordinator,
    /// No process holds the lock.
    Absent,
    /// The lock file cannot be read, so the holder is not known.
    Unknown,
}

/// Reads which process holds the coordinator lock of the journal at
/// `journal_path`. The reading takes no lock and makes no file
/// ([`CoordinatorLock::probe`]).
#[must_use]
pub fn agent_presence(journal_path: &Path) -> AgentPresence {
    match CoordinatorLock::probe(journal_path) {
        Ok(LockState::Held(CoordinatorRole::Agent)) => AgentPresence::Agent,
        Ok(LockState::Held(CoordinatorRole::Client)) => AgentPresence::OtherCoordinator,
        Ok(LockState::Free) => AgentPresence::Absent,
        Err(_) => AgentPresence::Unknown,
    }
}

/// The principal of a request of a client with the role `role`. The journal
/// is same-user state: the principal is a record, not an authentication.
#[must_use]
pub fn principal(role: ClientRole) -> Principal {
    Principal {
        uid: observe::current_uid(),
        session: None,
        role,
    }
}

/// A new identity text: the prefix, the wall-clock time, the process ID,
/// and a counter of this process.
#[must_use]
pub fn new_id(prefix: &str) -> String {
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

/// The number of reads in sequence that a wait tries again when the
/// journal is busy.
pub const BUSY_READS: u32 = 40;

/// The count of the failed reads in sequence of a wait on the journal.
///
/// A busy journal is read again, because a different process writes to it
/// and a read changes nothing. The wait does not go on without a bound:
/// after [`BUSY_READS`] busy reads in sequence the error of the read is
/// the result. A read that succeeds starts the count again, and an error
/// that is not "busy" is never tried again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BusyReads(u32);

impl BusyReads {
    /// Records a read that succeeded.
    pub const fn succeeded(&mut self) {
        self.0 = 0;
    }

    /// Records a read that failed. Returns `true` when the wait reads the
    /// journal again: the failure is a busy journal, and fewer than
    /// [`BUSY_READS`] busy reads came before it in sequence.
    pub const fn reads_again(&mut self, is_busy: bool) -> bool {
        if is_busy && self.0 < BUSY_READS {
            self.0 = self.0.saturating_add(1);
            true
        } else {
            false
        }
    }
}

/// The time between two reads of the queue while the coordinator serves a
/// request.
pub const QUEUE_POLL: Duration = Duration::from_millis(100);

/// The number of queue reads between two reads of the coordinator lock.
pub const PRESENCE_CHECK_INTERVAL: u32 = 10;

/// Why a wait for the completion of a request ended with no completion.
#[derive(Debug, thiserror::Error)]
pub enum WaitError {
    /// The wait ended first. The request stays in the queue, and the
    /// coordinator can serve it later.
    #[error("the coordinator did not serve the request before the end of the wait")]
    Pending,
    /// No process holds the coordinator lock now: the coordinator stopped
    /// before it served the request. The request stays in the queue.
    #[error("the coordinator stopped before it served the request")]
    CoordinatorStopped,
    /// The journal gave no answer.
    #[error("the request queue cannot be read: {0}")]
    Journal(OperationJournalError),
}

/// Reads the queue of `journal` until the coordinator completes the
/// request `request_id`, and returns its completion.
///
/// The wait reads the queue every [`QUEUE_POLL`], and the coordinator lock
/// of `journal_path` every [`PRESENCE_CHECK_INTERVAL`] reads.
///
/// # Errors
///
/// Returns [`WaitError::Pending`] when `timeout` ends first,
/// [`WaitError::CoordinatorStopped`] when no process holds the lock, and
/// [`WaitError::Journal`] for a read that failed and is not a busy journal,
/// or after [`BUSY_READS`] busy reads in sequence.
pub fn wait_for_completion(
    journal: &OperationJournal,
    journal_path: &Path,
    request_id: &RequestId,
    timeout: Duration,
) -> Result<RequestCompletion, WaitError> {
    let started: Instant = Instant::now();
    let mut reads: u32 = 0;
    let mut busy: BusyReads = BusyReads::default();
    loop {
        reads = reads.wrapping_add(1);
        match journal.request_status(request_id) {
            Ok(Some(RequestStatus::Completed { completion })) => return Ok(completion),
            Ok(_) => busy.succeeded(),
            // A busy journal is read again: a different process writes to
            // it.
            Err(error) => {
                let is_busy: bool = matches!(error, OperationJournalError::Busy(_));
                if !busy.reads_again(is_busy) {
                    return Err(WaitError::Journal(error));
                }
            }
        }
        if reads.is_multiple_of(PRESENCE_CHECK_INTERVAL)
            && observe::coordinator_presence(journal_path) == CoordinatorPresence::NotRunning
        {
            return Err(WaitError::CoordinatorStopped);
        }
        if started.elapsed() >= timeout {
            return Err(WaitError::Pending);
        }
        std::thread::sleep(QUEUE_POLL);
    }
}

/// Writes the new authority record of `change` and gives the
/// acknowledgement. The write is a compare-and-set on the revision of
/// `stored`, so a record that a different process changed after the read
/// is not replaced. A change that needs no write writes nothing.
///
/// The second value is `true` when the journal has a new record.
///
/// # Errors
///
/// Returns [`OperationJournalError::Conflict`] when the record changed
/// after the read, or a different journal error. On an error the record is
/// not changed, so the change is not in effect.
pub fn write_authority<R>(
    journal: &mut OperationJournal,
    stored: &StoredAuthority,
    change: Change<R>,
    now: WallTime,
) -> Result<(Acknowledged<R>, bool), OperationJournalError> {
    let inhibition = InstanceInhibition::default();
    if !change.needs_persistence() {
        return Ok((change.acknowledge(&inhibition, Persistence::Durable), false));
    }
    journal.put_agent_record(
        AgentRecord::Authority,
        &change.next,
        Some(stored.revision),
        now,
    )?;
    Ok((change.acknowledge(&inhibition, Persistence::Durable), true))
}

/// Reads the clocks of a control request from `context`: the monotonic
/// time with its clock domain and boot, and the wall-clock time.
///
/// # Errors
///
/// Returns the [`ClockError`] of a clock that gave no value.
pub fn control_time(
    context: &CollectionContext,
) -> Result<(EvaluationClock, WallTime), ClockError> {
    let identity = context.identity();
    let clock = EvaluationClock {
        now: context.clock().monotonic_now()?,
        clock_domain: identity.clock_domain.clone(),
        boot_id: identity.boot_id.clone(),
        continuity: ContinuityGeneration::new(0),
        last_discontinuity: None,
    };
    Ok((clock, context.clock().wall_now()?))
}

/// The grace period of a manual stop when the user gives none.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(10);

/// The longest grace period of a manual stop.
pub const MAX_STOP_GRACE: Nanoseconds = Nanoseconds::new(5 * 60 * 1_000_000_000);

/// The time in which the executor observes the exit after a force signal.
const FORCE_VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

/// The time that the deadline of a stop has in addition to its steps.
const STOP_DEADLINE_MARGIN: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

/// How a manual stop ends the processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// A request to exit. The grace period is the time in which the
    /// executor observes the exit.
    Graceful,
    /// A request to exit, then a force quit after the grace period.
    ForceAfterGrace,
    /// A force quit at once.
    ImmediateForce,
}

/// The strategy and the durations of a manual stop with the grace period
/// `grace`, for [`svalnir_core::plan::StopRequest`]. The caller checks that
/// `grace` is at most [`MAX_STOP_GRACE`].
#[must_use]
pub fn manual_stop(mode: StopMode, grace: Nanoseconds) -> (StopStrategy, StopLimits) {
    let (strategy, window): (StopStrategy, Nanoseconds) = match mode {
        StopMode::ImmediateForce => (StopStrategy::ImmediateForce, FORCE_VERIFICATION_WINDOW),
        StopMode::ForceAfterGrace => (
            StopStrategy::ForceAfterGrace { grace },
            FORCE_VERIFICATION_WINDOW,
        ),
        StopMode::Graceful => (StopStrategy::Graceful, grace),
    };
    let steps: u64 = window.get().saturating_mul(2);
    let deadline: Nanoseconds = Nanoseconds::new(
        strategy
            .grace()
            .map_or(0, Nanoseconds::get)
            .saturating_add(steps)
            .saturating_add(STOP_DEADLINE_MARGIN.get()),
    );
    (
        strategy,
        StopLimits {
            execution_deadline: deadline,
            verification_window: window,
            max_grace: MAX_STOP_GRACE,
            max_verification_window: MAX_STOP_GRACE,
            max_execution_deadline: deadline,
        },
    )
}

/// Why the configuration of the revision in effect is not usable.
#[derive(Debug, thiserror::Error)]
pub enum ActiveConfigError {
    /// No policy revision is in effect.
    #[error("no policy revision is in effect")]
    NoActiveRevision,
    /// The journal could not give the configuration text.
    #[error("the configuration text cannot be read: {0}")]
    Journal(OperationJournalError),
    /// The journal has no configuration text for the revision, or the text
    /// does not agree with the revision.
    #[error("the journal has no usable configuration text for the revision in effect")]
    SourceNotUsable,
}

/// The revision in effect and its validated configuration.
#[derive(Debug, Clone)]
pub struct ActiveConfig {
    /// The revision and its scope.
    pub active: ActiveRevision,
    /// The validated configuration of the revision.
    pub config: ValidatedConfig,
}

/// Reads the configuration text of the revision in effect of `state` and
/// validates it against the content digest of the revision, as the agent
/// does.
///
/// # Errors
///
/// Returns [`ActiveConfigError::NoActiveRevision`] with no revision,
/// [`ActiveConfigError::Journal`] for a read that failed, and
/// [`ActiveConfigError::SourceNotUsable`] when the text is absent or does
/// not agree with the revision.
pub fn active_config(
    journal: &OperationJournal,
    state: &AuthorityState,
) -> Result<ActiveConfig, ActiveConfigError> {
    let active: &ActiveRevision = state
        .active
        .as_ref()
        .ok_or(ActiveConfigError::NoActiveRevision)?;
    let source: String = journal
        .policy_revision_source(&active.revision.revision_id)
        .map_err(ActiveConfigError::Journal)?
        .ok_or(ActiveConfigError::SourceNotUsable)?;
    if ContentDigest::of_bytes(source.as_bytes()) != active.revision.content {
        return Err(ActiveConfigError::SourceNotUsable);
    }
    let config: ValidatedConfig = parse_and_validate(&source)
        .config()
        .cloned()
        .ok_or(ActiveConfigError::SourceNotUsable)?;
    Ok(ActiveConfig {
        active: active.clone(),
        config,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use svalnir_core::action::{ActionError, ActionStage, DispatchState, ErrorCode, ErrorFamily};
    use svalnir_core::grant::{ResumeRequest, resume};
    use svalnir_core::id::{ExecutorEpochId, OperationId};

    use super::*;
    use crate::journal::{JournalOptions, QueuedRequest, RequestBody};

    fn journal_in(directory: &tempfile::TempDir) -> (OperationJournal, PathBuf) {
        let path: PathBuf = directory.path().join("operations.sqlite");
        let journal = OperationJournal::open(&path, &JournalOptions::default())
            .unwrap_or_else(|error| panic!("journal: {error}"));
        (journal, path)
    }

    fn request(id: &str) -> QueuedRequest {
        QueuedRequest {
            request_id: RequestId::new(id).unwrap_or_else(|error| panic!("{error}")),
            principal: principal(ClientRole::Gui),
            body: RequestBody::Acknowledge {
                operation_id: OperationId::new("op-1").unwrap_or_else(|error| panic!("{error}")),
            },
            enqueued_at: WallTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn presence_follows_the_role_of_the_holder() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (_journal, path) = journal_in(&directory);
        assert_eq!(agent_presence(&path), AgentPresence::Absent);
        let agent = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(agent_presence(&path), AgentPresence::Agent);
        drop(agent);
        let client = CoordinatorLock::try_acquire(&path, CoordinatorRole::Client)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(agent_presence(&path), AgentPresence::OtherCoordinator);
        drop(client);
        assert_eq!(agent_presence(&path), AgentPresence::Absent);
    }

    #[test]
    fn the_principal_has_the_role_of_the_client() {
        assert_eq!(principal(ClientRole::Gui).role, ClientRole::Gui);
        assert_eq!(principal(ClientRole::Cli).uid, observe::current_uid());
    }

    #[test]
    fn identities_are_distinct() {
        assert_ne!(new_id("request"), new_id("request"));
        assert!(new_id("plan").starts_with("plan_"));
    }

    #[test]
    fn a_busy_journal_is_read_again_for_a_bounded_number_of_reads_in_sequence() {
        let mut busy = BusyReads::default();
        // An error that is not a busy journal is never tried again, and it
        // does not use a place of the bound.
        assert!(!busy.reads_again(false));
        for _ in 0..BUSY_READS {
            assert!(busy.reads_again(true));
        }
        // The bound is reached: the error of the read is the result.
        assert!(!busy.reads_again(true));
        assert!(!busy.reads_again(true));
        // A read that succeeds starts the count again.
        busy.succeeded();
        for _ in 0..BUSY_READS {
            assert!(busy.reads_again(true));
            assert!(!busy.reads_again(false));
        }
        assert!(!busy.reads_again(true));
    }

    #[test]
    fn the_wait_gives_the_completion_of_the_coordinator() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (mut journal, path) = journal_in(&directory);
        let lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let epoch = ExecutorEpochId::new("agent-1").unwrap_or_else(|error| panic!("{error}"));
        journal
            .begin_coordination(&lock, &epoch, WallTime::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"));
        let queued = request("request-1");
        journal
            .enqueue_request(&queued)
            .unwrap_or_else(|error| panic!("{error}"));
        let claimed = journal
            .claim_next_request(&epoch)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(claimed.is_some());
        let rejected = RequestCompletion::Rejected {
            error: ActionError {
                code: ErrorCode::new("operation_not_found")
                    .unwrap_or_else(|error| panic!("{error}")),
                family: ErrorFamily::Request,
                stage: ActionStage::Admission,
                dispatch: DispatchState::NotSubmitted,
                plan_id: None,
                operation_id: None,
                step_id: None,
            },
        };
        journal
            .complete_request(&queued.request_id, &epoch, &rejected)
            .unwrap_or_else(|error| panic!("{error}"));
        let completion =
            wait_for_completion(&journal, &path, &queued.request_id, Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completion, rejected);
    }

    #[test]
    fn the_wait_ends_when_the_time_ends() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (mut journal, path) = journal_in(&directory);
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let queued = request("request-2");
        journal
            .enqueue_request(&queued)
            .unwrap_or_else(|error| panic!("{error}"));
        let result = wait_for_completion(&journal, &path, &queued.request_id, Duration::ZERO);
        assert!(matches!(result, Err(WaitError::Pending)));
    }

    #[test]
    fn the_wait_ends_when_no_coordinator_holds_the_lock() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (mut journal, path) = journal_in(&directory);
        let queued = request("request-3");
        journal
            .enqueue_request(&queued)
            .unwrap_or_else(|error| panic!("{error}"));
        let result =
            wait_for_completion(&journal, &path, &queued.request_id, Duration::from_secs(10));
        assert!(matches!(result, Err(WaitError::CoordinatorStopped)));
    }

    #[test]
    fn no_revision_has_no_configuration() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (journal, _path) = journal_in(&directory);
        let state = AuthorityState::new(observe::current_uid());
        assert!(matches!(
            active_config(&journal, &state),
            Err(ActiveConfigError::NoActiveRevision)
        ));
    }

    #[test]
    fn a_changed_record_is_not_replaced() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let (mut journal, _path) = journal_in(&directory);
        let uid = observe::current_uid();
        let state = AuthorityState::new(uid);
        // A different process wrote a record after the read of revision 0.
        journal
            .put_agent_record(AgentRecord::Authority, &state, None, WallTime::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"));
        let earlier_read = StoredAuthority {
            state: state.clone(),
            revision: 0,
        };
        let clock = EvaluationClock {
            now: svalnir_core::time::MonotonicNanos::new(1),
            clock_domain: svalnir_core::id::ClockDomainId::new("domain")
                .unwrap_or_else(|error| panic!("{error}")),
            boot_id: svalnir_core::id::BootId::new("boot")
                .unwrap_or_else(|error| panic!("{error}")),
            continuity: ContinuityGeneration::new(0),
            last_discontinuity: None,
        };
        let paused = svalnir_core::grant::pause(
            &state,
            &svalnir_core::grant::PauseRequest {
                principal: uid,
                duration: None,
            },
            &svalnir_core::grant::ControlClock {
                clock: &clock,
                wall: WallTime::UNIX_EPOCH,
            },
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        let result = write_authority(&mut journal, &earlier_read, paused, WallTime::UNIX_EPOCH);
        assert!(matches!(result, Err(OperationJournalError::Conflict)));
        // A change that needs no write writes nothing.
        let unchanged = resume(
            &state,
            &InstanceInhibition::default(),
            &ResumeRequest { principal: uid },
            &svalnir_core::grant::ControlClock {
                clock: &clock,
                wall: WallTime::UNIX_EPOCH,
            },
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        let (_, written) =
            write_authority(&mut journal, &earlier_read, unchanged, WallTime::UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(!written);
    }
}
