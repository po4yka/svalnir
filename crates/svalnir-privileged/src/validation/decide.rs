//! The decision on one request.

use serde::Serialize;
use svalnir_core::action::{ClientRole, FileObjectType, StepState, WorkCharge};
use svalnir_core::authority::{PrivilegeGrant, PrivilegeGrantRef};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::FileObjectEvidence;
use svalnir_core::quantity::{EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::path::EntryPath;
use super::record::{ConsumedRequest, RateUsage, RecordError, StepKey, StepStatus};
use super::refusal::{Refusal, RefusalReason};
use super::state::{
    ApprovedRoot, GrantLimits, HelperClock, HelperConfig, HelperGrant, HelperState, RateCeiling,
    SUPPORTED_ACTION_CLASS,
};
use crate::request::{
    CallerIdentity, EvictEntries, HelperOperation, HelperRequest, LoginSessionId,
    MAX_TARGETS_PER_REQUEST, OperationKind, RequestValidity, StepCorrelation,
};

/// One entry of an accepted eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedEntry {
    /// The entry, as checked names below the root. The executor opens each
    /// name relative to the handle of the directory before it and does not
    /// follow a symbolic link.
    pub path: EntryPath,
    /// The type of the object that the agent observed. The executor does
    /// not remove an object of a different type. It removes a directory
    /// only as one empty directory, never with its content.
    pub object_type: FileObjectType,
    /// The native identifiers that the agent observed. The executor does
    /// not remove an object with different identifiers.
    pub object: FileObjectEvidence,
    /// The largest work of this entry.
    pub limit: WorkCharge,
}

/// An accepted eviction: the exact entries, below the root of the helper
/// record, with the limits that the helper decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedEviction {
    /// The deduplication identity of the step.
    pub key: StepKey,
    /// The login session of the caller. The record binds the step to it.
    pub login_session: LoginSessionId,
    /// The plan, the operation, and the step.
    pub correlation: StepCorrelation,
    /// The grant and the generation that cover the step.
    pub grant: PrivilegeGrantRef,
    /// The root, from the record of the helper. The request gave only its
    /// identity.
    pub root: ApprovedRoot,
    /// The rule revision.
    pub rule: RuleRef,
    /// The entries, in the sequence of the request.
    pub entries: Vec<BoundedEntry>,
    /// The largest work of the step: the sum of the entry limits. It is
    /// not larger than a ceiling of the grant.
    pub limit: WorkCharge,
    /// The monotonic time after which the executor submits no call: the
    /// expiry of the request. The helper accepted the request only because
    /// the grant applies until this time. A revocation after the
    /// acceptance is not in this value: the executor calls
    /// [`HelperState::still_covers`] before each call.
    pub deadline: MonotonicNanos,
}

/// The exact bounded operation that the helper accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedOperation {
    /// Permanent removal of listed entries below one approved root.
    EvictEntries(BoundedEviction),
}

impl BoundedOperation {
    /// The deduplication identity of the step.
    pub fn key(&self) -> &StepKey {
        match self {
            Self::EvictEntries(eviction) => &eviction.key,
        }
    }
}

/// The result of [`validate`]: what the helper decides for a request. The
/// function records nothing, so an `Accept` is not permission to act. Only
/// [`HelperState::admit`] gives that permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The helper accepts the request with this bounded operation.
    Accept(Box<BoundedOperation>),
    /// The record has the step with the same content, or the request is a
    /// status query. This is the recorded state. It is not a second
    /// acceptance.
    Known(StepStatus),
    /// The helper refuses the request.
    Refuse(Refusal),
}

/// An accepted and consumed step: the permission to do one bounded
/// operation one time.
///
/// Only [`HelperState::admit`] makes the value, in the same call that
/// records the consumption of the step. The value cannot be cloned.
#[derive(Debug, PartialEq, Eq)]
pub struct Dispatch {
    operation: BoundedOperation,
}

impl Dispatch {
    /// The operation to do.
    pub fn operation(&self) -> &BoundedOperation {
        &self.operation
    }

    /// The deduplication identity of the step.
    pub fn key(&self) -> &StepKey {
        self.operation.key()
    }
}

/// The result of [`HelperState::admit`].
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// The helper accepted the request and recorded the consumption of
    /// the step.
    Dispatch(Box<Dispatch>),
    /// The recorded state of the step. The helper accepted nothing.
    Known(StepStatus),
    /// The helper refused the request and recorded nothing.
    Refused(Refusal),
}

/// The decision with the record that an acceptance adds.
enum Evaluation {
    Accept {
        operation: Box<BoundedOperation>,
        record: Box<ConsumedRequest>,
    },
    Known(StepStatus),
}

/// The part of a request that identifies its effect. The transport
/// identity is not a part: a new transport identity does not make a new
/// request.
#[derive(Serialize)]
struct RequestContent<'request> {
    correlation: &'request StepCorrelation,
    validity: &'request RequestValidity,
    operation: &'request HelperOperation,
}

/// Decides one request against the state of the helper.
///
/// The function is pure: it reads no clock and no file, and it changes
/// nothing. With the same arguments it gives the same result. Use it to
/// examine a decision. It decides against the record as it is:
/// [`HelperState::admit`] first removes each record that can be removed,
/// so the two results can be different for a state that has such a record
/// (a full record, or a settled step whose retention is complete). To act on a request, use [`HelperState::admit`],
/// which also records the consumption.
///
/// The helper uses only its own state and the identity that the transport
/// made. A statement of the request about authority has no effect: the
/// grant reference is compared with the record, the root is found in the
/// record, and the bounds of the entries can only make the operation
/// smaller.
///
/// The checks, in sequence:
///
/// 1. The protocol version.
/// 2. The code-signing identity, the role, and the login session of the
///    caller.
/// 3. For a status query: the validity, then the recorded state of the
///    step of the authenticated user. A step of a different login session
///    gives a refusal.
/// 4. The record of consumed requests: a step of a different login
///    session gives a refusal. The same step with the same content gives
///    its recorded state, and with a different content gives a refusal. A
///    recorded transport identity for a different step gives a refusal.
/// 5. The validity: the timeline, the expiry, and the longest validity.
/// 6. The grant: its user, its generation, its revocation, and its expiry.
///    The grant must apply for the full validity of the request.
/// 7. The root and the rule revision of the root.
/// 8. The entries: their number, their names, and their bounds.
/// 9. The ceilings of one operation, in bytes and in items.
/// 10. The rate ceiling, in requests and in work.
/// 11. The grant again, with `PrivilegeGrant::covers`.
/// 12. The record quota of the user, and the room in the record of
///     consumed requests.
pub fn validate(
    state: &HelperState,
    caller: &CallerIdentity,
    request: &HelperRequest,
    clock: &HelperClock,
) -> Verdict {
    match evaluate(state, caller, request, clock) {
        Ok(Evaluation::Accept { operation, .. }) => Verdict::Accept(operation),
        Ok(Evaluation::Known(status)) => Verdict::Known(status),
        Err(reason) => Verdict::Refuse(refusal(reason, request)),
    }
}

impl HelperState {
    /// Decides one request and, when the helper accepts it, records the
    /// consumption of its step in the same call.
    ///
    /// The function first removes each record that
    /// [`HelperState::remove_expired`] can remove. Then it decides as
    /// [`validate`] does.
    ///
    /// The caller must make the changed record durable before it gives the
    /// [`Dispatch`] to an executor (`docs/ACTION_CONTRACTS.md` section 12).
    /// This crate has no storage. If the write fails, the caller does not
    /// execute the step, and it records `NoAction` for the step with
    /// [`HelperState::record_progress`]. The step stays consumed.
    ///
    /// A refusal consumes no step. The removal of old records at the start
    /// of the call is the only change that a refusal can leave.
    pub fn admit(
        &mut self,
        caller: &CallerIdentity,
        request: &HelperRequest,
        clock: &HelperClock,
    ) -> Admission {
        self.remove_expired(clock);
        match evaluate(self, caller, request, clock) {
            Ok(Evaluation::Accept { operation, record }) => match self.consumed.insert(*record) {
                Ok(()) => Admission::Dispatch(Box::new(Dispatch {
                    operation: *operation,
                })),
                Err(RecordError::Full) => {
                    Admission::Refused(refusal(RefusalReason::RecordFull, request))
                }
                Err(_) => Admission::Refused(refusal(RefusalReason::ConflictingDuplicate, request)),
            },
            Ok(Evaluation::Known(status)) => Admission::Known(status),
            Err(reason) => Admission::Refused(refusal(reason, request)),
        }
    }

    /// Answers whether the record still covers a step in work, at the
    /// clock of the helper.
    ///
    /// The executor asks this before each call. A revocation of the grant
    /// applies at this boundary, as `docs/ACTION_CONTRACTS.md` section 11
    /// states. The function is pure: it reads no clock and no file, and it
    /// changes nothing. The checks, in sequence:
    ///
    /// 1. The record has the step for the login session of the operation,
    ///    and the step is `DispatchConsumed` or `Verifying`.
    /// 2. The clock is on the timeline of the record, and it is before the
    ///    deadline of the operation.
    /// 3. The grant is known for the user of the step, it has the
    ///    generation of the operation, it is not revoked, and it is in
    ///    effect at the wall-clock time.
    /// 4. The record has the root of the operation, as it was accepted, and
    ///    the root has the rule of the operation.
    ///
    /// # Errors
    ///
    /// Returns the [`RefusalReason`] of the first check that fails. The
    /// executor records this reason and submits no call.
    pub fn still_covers(
        &self,
        dispatch: &Dispatch,
        clock: &HelperClock,
    ) -> Result<(), RefusalReason> {
        let BoundedOperation::EvictEntries(eviction) = dispatch.operation();
        let key: &StepKey = dispatch.key();
        let recorded: &ConsumedRequest = self
            .consumed
            .find(key)
            .ok_or(RefusalReason::StepNotRecorded)?;
        if recorded.login_session != eviction.login_session {
            return Err(RefusalReason::LoginSessionMismatch);
        }
        if !matches!(
            recorded.state,
            StepState::DispatchConsumed | StepState::Verifying
        ) {
            return Err(RefusalReason::StepNotRecorded);
        }
        if recorded.clock_domain != clock.clock_domain || recorded.boot_id != clock.boot_id {
            return Err(RefusalReason::ClockNotComparable);
        }
        if clock.monotonic >= eviction.deadline {
            return Err(RefusalReason::RequestExpired);
        }
        let record: &HelperGrant = self
            .grant(&eviction.grant.grant_id)
            .ok_or(RefusalReason::GrantUnknown)?;
        let grant: &PrivilegeGrant = record.grant();
        if grant.principal != key.principal {
            return Err(RefusalReason::GrantUnknown);
        }
        if !grant.matches(&eviction.grant) {
            return Err(RefusalReason::GrantGenerationStale);
        }
        if grant.revoked {
            return Err(RefusalReason::GrantRevoked);
        }
        if !grant.is_in_effect(clock.wall) {
            return Err(RefusalReason::GrantExpired);
        }
        let root: &ApprovedRoot = record
            .root(eviction.root.root_id())
            .filter(|root: &&ApprovedRoot| **root == eviction.root)
            .ok_or(RefusalReason::RootNotGranted)?;
        if !root.rules().contains(&eviction.rule) {
            return Err(RefusalReason::RuleNotSupported);
        }
        Ok(())
    }

    /// Records the next state of a consumed step: `Verifying` when the
    /// executor submitted its call, and then a result state.
    ///
    /// # Errors
    ///
    /// Returns a [`RecordError`] when the record does not have the step or
    /// when the step cannot go from its state to `next`.
    pub fn record_progress(
        &mut self,
        key: &StepKey,
        next: StepState,
    ) -> Result<StepStatus, RecordError> {
        self.consumed.advance(key, next)
    }

    /// Removes each record of a consumed request that can be removed with
    /// no risk of a replay. Returns the number of removed records. A step
    /// that is not settled stays.
    pub fn remove_expired(&mut self, clock: &HelperClock) -> usize {
        self.consumed.remove_expired(clock)
    }
}

fn refusal(reason: RefusalReason, request: &HelperRequest) -> Refusal {
    Refusal {
        reason,
        correlation: request.correlation.clone(),
    }
}

fn evaluate(
    state: &HelperState,
    caller: &CallerIdentity,
    request: &HelperRequest,
    clock: &HelperClock,
) -> Result<Evaluation, RefusalReason> {
    state.config.protocols.check(request.protocol)?;
    let login_session: LoginSessionId =
        check_caller(&state.config, caller, request.operation.kind())?;
    // The user of the key is the audited user of the connection. The
    // request has no field that can replace it.
    let key: StepKey = StepKey {
        principal: caller.audited_uid(),
        operation_id: request.correlation.operation_id.clone(),
        step_id: request.correlation.step_id.clone(),
    };
    match &request.operation {
        HelperOperation::QueryStepStatus(_) => {
            check_validity(&request.validity, clock, state.config.max_validity)?;
            let recorded: &ConsumedRequest = state
                .consumed
                .find(&key)
                .ok_or(RefusalReason::StepNotRecorded)?;
            if recorded.login_session != login_session {
                return Err(RefusalReason::LoginSessionMismatch);
            }
            if recorded.correlation != request.correlation {
                return Err(RefusalReason::ConflictingDuplicate);
            }
            Ok(Evaluation::Known(recorded.status()))
        }
        HelperOperation::EvictEntries(eviction) => {
            evaluate_eviction(state, caller, login_session, request, eviction, key, clock)
        }
    }
}

fn evaluate_eviction(
    state: &HelperState,
    caller: &CallerIdentity,
    login_session: LoginSessionId,
    request: &HelperRequest,
    eviction: &EvictEntries,
    key: StepKey,
    clock: &HelperClock,
) -> Result<Evaluation, RefusalReason> {
    let content: ContentDigest = ContentDigest::of_json(&RequestContent {
        correlation: &request.correlation,
        validity: &request.validity,
        operation: &request.operation,
    })
    .map_err(|_| RefusalReason::ContentNotEncodable)?;

    // Deduplication comes before each check of freshness and authority. A
    // repeated step gets its recorded state, and never a second acceptance,
    // also after its request expired or its grant changed. This is true
    // while the record has the step. The record removes a settled step
    // only after its request is expired and its retention is complete; a
    // later request for the same step identity is then a new step, with
    // each check of freshness, authority, and rate.
    //
    // The login session comes before the content: a step of a different
    // login session gives one reason for a repeat and for a different
    // content, so that session learns nothing about the step.
    if let Some(recorded) = state.consumed.find(&key) {
        return if recorded.login_session != login_session {
            Err(RefusalReason::LoginSessionMismatch)
        } else if recorded.content == content {
            Ok(Evaluation::Known(recorded.status()))
        } else {
            Err(RefusalReason::ConflictingDuplicate)
        };
    }
    if state
        .consumed
        .has_request_id(caller.audited_uid(), &request.request_id)
    {
        return Err(RefusalReason::RequestIdReused);
    }

    check_validity(&request.validity, clock, state.config.max_validity)?;

    let record: &HelperGrant = check_grant(state, caller, &eviction.grant, clock)?;
    check_grant_outlasts(record.grant(), &request.validity, clock)?;
    let root: &ApprovedRoot = record
        .root(&eviction.root_id)
        .ok_or(RefusalReason::RootNotGranted)?;
    if !root.rules().contains(&eviction.rule) {
        return Err(RefusalReason::RuleNotSupported);
    }

    let (entries, total): (Vec<BoundedEntry>, WorkCharge) =
        check_entries(eviction, record.limits())?;
    check_operation_ceiling(record.grant(), total)?;
    check_rate(state, record, total, clock)?;

    // The final check uses the question that the grant answers about
    // itself. The checks before it give the specific reasons.
    if !record.grant().covers(
        caller.audited_uid(),
        &SUPPORTED_ACTION_CLASS,
        &eviction.root_id,
        &total,
        clock.wall,
    ) {
        return Err(RefusalReason::GrantDoesNotCover);
    }

    // Admission fails before an effect when the helper cannot keep the
    // record of the step.
    if state.consumed.count_for(caller.audited_uid()) >= state.config.principal_quota {
        return Err(RefusalReason::RecordQuota);
    }
    if state.consumed.is_full() {
        return Err(RefusalReason::RecordFull);
    }

    let operation: BoundedOperation = BoundedOperation::EvictEntries(BoundedEviction {
        key: key.clone(),
        login_session,
        correlation: request.correlation.clone(),
        grant: record.grant().reference(),
        root: root.clone(),
        rule: eviction.rule.clone(),
        entries,
        limit: total,
        deadline: request.validity.expires_at,
    });
    let consumed: ConsumedRequest = ConsumedRequest {
        key,
        login_session,
        request_id: request.request_id.clone(),
        correlation: request.correlation.clone(),
        content,
        grant_id: record.grant().grant_id.clone(),
        charge: total,
        clock_domain: clock.clock_domain.clone(),
        boot_id: clock.boot_id.clone(),
        accepted_at: clock.monotonic,
        accepted_wall: clock.wall,
        expires_at: request.validity.expires_at,
        state: StepState::DispatchConsumed,
    };
    Ok(Evaluation::Accept {
        operation: Box::new(operation),
        record: Box::new(consumed),
    })
}

/// Checks the code-signing identity, the role, and the login session of the
/// caller. Returns the login session.
///
/// Each operation is for the agent only. The command-line client and the
/// GPUI client use the agent; they do not call the helper. Each request
/// needs a login session, because the record binds each step to one.
fn check_caller(
    config: &HelperConfig,
    caller: &CallerIdentity,
    kind: OperationKind,
) -> Result<LoginSessionId, RefusalReason> {
    if caller.code() != &config.agent {
        return Err(RefusalReason::CallerNotPermitted);
    }
    let permitted: bool = match (kind, caller.role()) {
        (OperationKind::EvictEntries | OperationKind::QueryStepStatus, ClientRole::Agent) => true,
        (
            OperationKind::EvictEntries | OperationKind::QueryStepStatus,
            ClientRole::Cli | ClientRole::Gui | ClientRole::Unrecognized(_),
        ) => false,
    };
    if !permitted {
        return Err(RefusalReason::RoleNotPermitted);
    }
    caller
        .login_session()
        .ok_or(RefusalReason::LoginSessionMissing)
}

/// Checks that the request is current on the clock of the helper.
fn check_validity(
    validity: &RequestValidity,
    clock: &HelperClock,
    max_validity: Nanoseconds,
) -> Result<(), RefusalReason> {
    if validity.clock_domain != clock.clock_domain
        || validity.boot_id != clock.boot_id
        || clock.monotonic < validity.issued_at
    {
        return Err(RefusalReason::ClockNotComparable);
    }
    if validity.expires_at <= validity.issued_at {
        return Err(RefusalReason::ValidityEmpty);
    }
    if clock.monotonic >= validity.expires_at {
        return Err(RefusalReason::RequestExpired);
    }
    let length: Nanoseconds = validity
        .expires_at
        .checked_duration_since(validity.issued_at)
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    if length > max_validity {
        return Err(RefusalReason::ValidityTooLong);
    }
    Ok(())
}

/// Finds the current grant record that the reference names for the
/// authenticated user.
fn check_grant<'state>(
    state: &'state HelperState,
    caller: &CallerIdentity,
    reference: &PrivilegeGrantRef,
    clock: &HelperClock,
) -> Result<&'state HelperGrant, RefusalReason> {
    let record: &HelperGrant = state
        .grant(&reference.grant_id)
        .ok_or(RefusalReason::GrantUnknown)?;
    let grant: &PrivilegeGrant = record.grant();
    // A grant of a different user is not known to this caller. The reason
    // does not show that the grant exists.
    if grant.principal != caller.audited_uid() {
        return Err(RefusalReason::GrantUnknown);
    }
    if reference.generation < grant.generation {
        return Err(RefusalReason::GrantGenerationStale);
    }
    if reference.generation > grant.generation || !grant.matches(reference) {
        return Err(RefusalReason::GrantGenerationUnknown);
    }
    if grant.revoked {
        return Err(RefusalReason::GrantRevoked);
    }
    if !grant.is_in_effect(clock.wall) {
        return Err(RefusalReason::GrantExpired);
    }
    Ok(record)
}

/// Checks that the grant applies for the full validity of the request.
///
/// The executor can submit a call until the expiry of the request, which
/// is a monotonic time. The expiry of the grant is a wall-clock time. The
/// function adds the time that remains of the request to the wall-clock
/// time of the check, and refuses the request when the result is after the
/// expiry of the grant. Thus an accepted step
/// is not executed after its grant expired. A result that the wall clock
/// cannot hold is refused.
fn check_grant_outlasts(
    grant: &PrivilegeGrant,
    validity: &RequestValidity,
    clock: &HelperClock,
) -> Result<(), RefusalReason> {
    const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;
    let Some(expiry) = grant.expires_at else {
        return Ok(());
    };
    let remaining: Nanoseconds = validity
        .expires_at
        .checked_duration_since(clock.monotonic)
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    let total: u128 = u128::from(clock.wall.subsecond_nanoseconds())
        .checked_add(u128::from(remaining.get()))
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    let last_call: WallTime = i64::try_from(total / NANOSECONDS_PER_SECOND)
        .ok()
        .and_then(|seconds: i64| clock.wall.unix_seconds().checked_add(seconds))
        .zip(u32::try_from(total % NANOSECONDS_PER_SECOND).ok())
        .and_then(|(seconds, fraction): (i64, u32)| WallTime::from_unix(seconds, fraction).ok())
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    if last_call > expiry {
        return Err(RefusalReason::GrantExpiresBeforeRequest);
    }
    Ok(())
}

/// Checks the entries and adds their bounds.
fn check_entries(
    eviction: &EvictEntries,
    limits: &GrantLimits,
) -> Result<(Vec<BoundedEntry>, WorkCharge), RefusalReason> {
    let count: usize = eviction.entries.len();
    if count == 0 {
        return Err(RefusalReason::NoTarget);
    }
    if count > MAX_TARGETS_PER_REQUEST || count > limits.max_targets {
        return Err(RefusalReason::TargetCeiling);
    }
    let mut entries: Vec<BoundedEntry> = Vec::with_capacity(count);
    let mut total: WorkCharge = WorkCharge::ZERO;
    for target in &eviction.entries {
        match target.object_type {
            FileObjectType::RegularFile
            | FileObjectType::Directory
            | FileObjectType::SymbolicLink => {}
            FileObjectType::Unrecognized(_) => return Err(RefusalReason::ObjectType),
        }
        let path: EntryPath =
            EntryPath::parse(&target.relative_entry).map_err(RefusalReason::TargetPath)?;
        // A privileged removal needs the identity of its object. A name
        // alone is not a target.
        let object: FileObjectEvidence =
            target.object.ok_or(RefusalReason::ObjectEvidenceAbsent)?;
        if target.charge.items == EntryCount::ZERO {
            return Err(RefusalReason::ChargeWithoutItem);
        }
        if entries
            .iter()
            .any(|entry: &BoundedEntry| entry.path == path)
        {
            return Err(RefusalReason::DuplicateTarget);
        }
        total = total
            .checked_add(target.charge)
            .ok_or(RefusalReason::ArithmeticOverflow)?;
        entries.push(BoundedEntry {
            path,
            object_type: target.object_type.clone(),
            object,
            limit: target.charge,
        });
    }
    Ok((entries, total))
}

/// Checks the work of the request against the ceiling of one operation.
fn check_operation_ceiling(grant: &PrivilegeGrant, total: WorkCharge) -> Result<(), RefusalReason> {
    if total.work_bytes > grant.ceiling.work_bytes {
        return Err(RefusalReason::BytesCeiling);
    }
    if total.items > grant.ceiling.items {
        return Err(RefusalReason::ItemsCeiling);
    }
    Ok(())
}

/// Checks the request against the rate ceiling of its grant. The accepted
/// requests of each generation of the grant count: a new generation does
/// not start a new window.
fn check_rate(
    state: &HelperState,
    record: &HelperGrant,
    total: WorkCharge,
    clock: &HelperClock,
) -> Result<(), RefusalReason> {
    let rate: RateCeiling = record.limits().rate;
    let usage: RateUsage = state
        .consumed
        .usage(&record.grant().grant_id, clock, rate.window)
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    let requests: u32 = usage
        .requests
        .checked_add(1)
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    if requests > rate.max_requests {
        return Err(RefusalReason::RateCeiling);
    }
    let work: WorkCharge = usage
        .work
        .checked_add(total)
        .ok_or(RefusalReason::ArithmeticOverflow)?;
    if !work.fits_in(&rate.work) {
        return Err(RefusalReason::RateWorkCeiling);
    }
    Ok(())
}
