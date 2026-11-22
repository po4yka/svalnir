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
//!
//! [`cleanup`] has the rule checks, the discoveries, the inspections, and
//! the plan builder calls of the manual cleanup plans that the clients
//! share.

#[cfg(unix)]
pub mod cleanup;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use svalnir_core::action::{ClientRole, Principal};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::config::{ValidatedConfig, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::{
    Acknowledged, ActiveRevision, AuthorityState, Change, InstanceInhibition, Persistence,
};
use svalnir_core::id::{ApplicationInstanceId, PlanId, RequestId, StepId, TargetId};
use svalnir_core::plan::{
    PlanBuildError, PlanContext, PlanOutcome, StopLimits, StopRequest, StopStepIds, StopStrategy,
    build_stop_plan, manual_plan_lifetime,
};
use svalnir_core::policy::{
    ApplicationCandidate, ContinuityGeneration, EvaluationClock, ProtectionContext,
};
use svalnir_core::process::VerifiedMembership;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::WallTime;

use crate::journal::{
    AgentRecord, CoordinatorLock, CoordinatorRole, LockState, OperationJournal,
    OperationJournalError, RequestCompletion, RequestStatus,
};
use crate::observe::{self, CoordinatorPresence, StoredAuthority};
use crate::platform::memory::{ClockError, CollectionContext};
use crate::platform::process::{ProcessSnapshot, application_candidates};

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

/// Why [`create_state_directory`] gives no state directory. The function
/// made no record in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateDirectoryError {
    /// The directory cannot be made.
    #[error("the state directory cannot be created: {0}")]
    NotWritable(std::io::ErrorKind),
    /// The path is a symbolic link or not a directory, has a different
    /// owner, or permits access to the group or to other users.
    #[error("the state directory is not a private directory of this user")]
    NotPrivate,
}

/// Makes the state directory `directory` and its parents when they do not
/// exist, for a client that must write a record in it.
///
/// The CLI and the GPUI client call this one function, so that both make
/// the directory with the same mode and refuse the same directory. A new
/// directory is readable only by its owner (mode `0700`), because the
/// records can name private paths. A directory that exists must also be
/// private ([`is_private_directory`]). The function makes no journal and
/// takes no lock. The caller checks that `HOME` is the home directory of
/// the account record before it calls this function.
///
/// # Errors
///
/// Returns [`StateDirectoryError::NotWritable`] when the directory cannot
/// be made, and [`StateDirectoryError::NotPrivate`] when the path is not a
/// private directory of this user.
pub fn create_state_directory(directory: &Path) -> Result<(), StateDirectoryError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|error| StateDirectoryError::NotWritable(error.kind()))?;
    // The builder sets the mode only of a directory that it makes. A
    // directory that exists must also be private.
    if is_private_directory(directory) {
        Ok(())
    } else {
        Err(StateDirectoryError::NotPrivate)
    }
}

/// Whether `path` is a directory, not a symbolic link, that the user of
/// this process owns and that gives no access to the group or to other
/// users.
#[must_use]
pub fn is_private_directory(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // The six low bits of the mode are the permissions of the group
        // and of each other user. A private directory has none of them.
        metadata.uid() == observe::current_uid().get() && metadata.mode().trailing_zeros() >= 6
    }
    #[cfg(not(unix))]
    {
        true
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

/// The application or managed-job instance of `candidate`: the instance
/// of the verified membership of its members. `None` for a candidate with
/// no member that has a verified membership.
#[must_use]
pub fn candidate_instance(candidate: &ApplicationCandidate) -> Option<&ApplicationInstanceId> {
    match candidate
        .processes
        .first()?
        .association
        .verified_membership()?
    {
        VerifiedMembership::Application { instance_id, .. }
        | VerifiedMembership::ManagedJob { instance_id, .. } => Some(instance_id),
    }
}

/// The candidate of the application or managed-job instance `instance` in
/// `snapshot`, from [`application_candidates`]: only the processes with a
/// verified membership in the instance are its members, never the
/// processes that have the same name.
///
/// `None` when the snapshot has no verified member of the instance, or
/// when the instance has no candidate because no membership identity or
/// footprint observation can be made for it.
#[must_use]
pub fn group_candidate(
    snapshot: &ProcessSnapshot,
    protection: &ProtectionContext<'_>,
    instance: &ApplicationInstanceId,
) -> Option<ApplicationCandidate> {
    application_candidates(snapshot, protection)
        .into_iter()
        .find(|candidate| candidate_instance(candidate) == Some(instance))
}

/// The inputs of the plan of a manual stop.
#[derive(Debug, Clone, Copy)]
pub struct ManualStopPlan<'a> {
    /// The identity text of the plan, from [`new_id`]. The target and the
    /// steps have identities that start with it.
    pub plan_id: &'a str,
    /// The principal of the plan.
    pub principal: &'a Principal,
    /// The revision in effect, which the plan binds.
    pub active: &'a ActiveRevision,
    /// The validated configuration of the revision.
    pub config: &'a ValidatedConfig,
    /// The clock of the plan.
    pub clock: &'a EvaluationClock,
    /// The wall-clock time of the plan.
    pub created_wall: WallTime,
    /// The canonical home directory, for the protections of the
    /// configuration.
    pub home_directory: Option<&'a LosslessPath>,
    /// The processes to stop: one process, or the verified members of one
    /// instance.
    pub candidate: &'a ApplicationCandidate,
    /// The protection context of the client.
    pub protection: &'a ProtectionContext<'a>,
    /// The strategy and the durations, from [`manual_stop`].
    pub strategy: StopStrategy,
    /// The durations of the stop, from [`manual_stop`].
    pub limits: StopLimits,
}

/// Why the plan of a manual stop was not built.
#[derive(Debug, thiserror::Error)]
pub enum ManualStopError {
    /// An identity of the plan, of its target, or of a step is not valid.
    #[error("an identity of the plan is not valid")]
    Identity,
    /// The plan builder refused the request.
    #[error("{0}")]
    Build(PlanBuildError),
}

/// Builds the plan of a manual stop with [`build_stop_plan`], as each
/// client does: the plan binds the revision in effect and no grant, and it
/// has the lifetime of a manual plan of the configuration.
///
/// The result has no plan when the builder left the candidate out, for
/// example for a protection; its preview has the reasons.
///
/// # Errors
///
/// Returns [`ManualStopError::Identity`] for an identity that is not valid,
/// and [`ManualStopError::Build`] when the builder refuses the request or
/// the configuration has no usable lifetime of a manual plan
/// ([`PlanBuildError::Lifetime`]).
pub fn build_manual_stop(input: &ManualStopPlan<'_>) -> Result<PlanOutcome, ManualStopError> {
    let identity = |suffix: &str| format!("{}-{suffix}", input.plan_id);
    let lifetime: Nanoseconds = manual_plan_lifetime(input.config)
        .ok_or(ManualStopError::Build(PlanBuildError::Lifetime))?;
    let context = PlanContext {
        plan_id: PlanId::new(input.plan_id).map_err(|_| ManualStopError::Identity)?,
        principal: input.principal.clone(),
        authority: AuthorityBinding {
            policy_revision: input.active.revision.revision_id.clone(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: input.clock,
        created_wall: input.created_wall,
        lifetime,
        protections: input.config.protections(),
        home_directory: input.home_directory,
    };
    let request = StopRequest {
        target_id: TargetId::new(identity("app")).map_err(|_| ManualStopError::Identity)?,
        candidate: input.candidate,
        protection: input.protection,
        strategy: input.strategy,
        steps: StopStepIds {
            graceful: StepId::new(identity("graceful")).map_err(|_| ManualStopError::Identity)?,
            force: StepId::new(identity("force")).map_err(|_| ManualStopError::Identity)?,
        },
        limits: input.limits,
    };
    build_stop_plan(&context, &request).map_err(ManualStopError::Build)
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

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn an_absent_state_directory_is_made_private_with_its_parents() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let state: PathBuf = directory.path().join("parent").join("state");
        assert_eq!(create_state_directory(&state), Ok(()));
        assert_eq!(mode_of(&state), 0o700);
        assert!(is_private_directory(&state));
        // A second call finds the private directory and changes nothing.
        assert_eq!(create_state_directory(&state), Ok(()));
        assert_eq!(mode_of(&state), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_state_directory_that_others_can_read_is_refused_and_not_changed() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let state: PathBuf = directory.path().join("state");
        std::fs::create_dir(&state).unwrap_or_else(|error| panic!("{error}"));
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o750))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            create_state_directory(&state),
            Err(StateDirectoryError::NotPrivate)
        );
        assert_eq!(mode_of(&state), 0o750);
        assert!(!is_private_directory(&state));
    }

    #[cfg(unix)]
    #[test]
    fn a_state_directory_through_a_symbolic_link_is_refused() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let target: PathBuf = directory.path().join("target");
        assert_eq!(create_state_directory(&target), Ok(()));
        let link: PathBuf = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            create_state_directory(&link),
            Err(StateDirectoryError::NotPrivate)
        );
    }

    #[test]
    fn a_state_directory_below_a_file_cannot_be_made() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let file: PathBuf = directory.path().join("file");
        std::fs::write(&file, b"").unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            create_state_directory(&file.join("state")),
            Err(StateDirectoryError::NotWritable(_))
        ));
        assert!(!is_private_directory(&file));
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
