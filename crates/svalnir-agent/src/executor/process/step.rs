//! One step of an application intervention: the final check, the calls,
//! and the observation of the exit.
//!
//! [`ProcessExecutor::begin`] does the final check and issues the calls of
//! one step. It never waits. When a call was issued, it returns an
//! [`Observation`]; the caller calls [`Observation::poll`] at the times it
//! selects, until the step is [`StepRun::Finished`]. Between two calls the
//! executor holds no lock and no native resource, so a wait for an
//! application does not stop a collector or a query.

use std::collections::BTreeMap;

use svalnir_core::action::{
    ActionClass, ApplicationBinding, Attribution, DispatchConsumption, DispatchReceipt,
    DispatchState, Escalation, ExecutorRole, NativeResult, RequestEnvelope, StopReason,
    TargetBinding, TargetEffect, TargetResult, check_dispatch_recording,
};
use svalnir_core::id::{BootId, ClockDomainId, ExecutorEpochId, ProcessGenerationId};
use svalnir_core::policy::{ProtectionContext, ProtectionFact, hard_protection};
use svalnir_core::process::{AttributionMethod, Pid, ProcessAssociation, ProcessIdentity, Uid};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::control::{
    ApplicationCallResult, ApplicationExpectation, ApplicationRequest, GracefulSignal,
    ProcessControl, ProcessSignal, SignalResult, StepClock,
};
use super::identity::{GenerationState, Revalidation, observe, revalidate};
use super::record::{ExecutorError, Failure, Outcome, RecordBase, code};
use crate::platform::process::{ProcessSource, QueryFailure};

/// The number of consecutive polls with no clock value after which an
/// observation ends.
pub const MAX_CLOCK_FAILURES: u32 = 3;

/// The lifetime that the executor runs in. A request with evidence of a
/// different boot, clock domain, or executor lifetime is not executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorContext {
    /// The current boot.
    pub boot_id: BootId,
    /// The clock domain of the [`StepClock`].
    pub clock_domain: ClockDomainId,
    /// The lifetime of this executor.
    pub executor_epoch: ExecutorEpochId,
}

/// The configuration of the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecutorConfig {
    /// The signal of a graceful request to a job process.
    pub graceful_signal: GracefulSignal,
}

/// A request to stop the step at its next boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRequest {
    /// The operation was canceled.
    Canceled,
    /// The agent or the policy was paused.
    Paused,
    /// The policy revision or a grant changed.
    PolicyChanged,
    /// The trigger of the automatic work cleared.
    TriggerCleared,
    /// The plan expired or the deadline passed.
    DeadlineExpired,
    /// The necessary authority is missing.
    AuthorityMissing,
}

impl StopRequest {
    /// The stop reason of a result that this request stopped.
    pub const fn reason(self) -> StopReason {
        match self {
            Self::Canceled => StopReason::Canceled,
            Self::Paused => StopReason::Paused,
            Self::PolicyChanged => StopReason::PolicyChanged,
            Self::TriggerCleared => StopReason::TriggerCleared,
            Self::DeadlineExpired => StopReason::DeadlineExpired,
            Self::AuthorityMissing => StopReason::AuthorityMissing,
        }
    }
}

/// The record of the graceful step that a force step of the strategy
/// `force_after_grace` follows.
#[derive(Debug, Clone, Copy)]
pub struct GracefulRecord<'a> {
    /// The monotonic time of the submission of the graceful request:
    /// [`StepReport::submitted_at`] of the graceful step. The grace period
    /// starts at this time. A later query or a reconnection does not
    /// change it.
    pub submitted_at: MonotonicNanos,
    /// The target results of the graceful step.
    pub results: &'a [TargetResult],
}

/// The input of one step.
#[derive(Debug, Clone, Copy)]
pub struct StepInput<'a> {
    /// The request envelope of the step.
    pub envelope: &'a RequestEnvelope,
    /// The receipt of the dispatch consumption of this step. The
    /// coordinator records the intent and consumes the dispatch before it
    /// calls the executor.
    pub receipt: &'a DispatchReceipt,
    /// The fact of the hard-protection catalog for the members of the
    /// target, evaluated at this boundary with the control plane of the
    /// caller. Only `NotProtected` permits a call.
    pub protection: ProtectionFact,
    /// The record of the graceful step. A force step of the strategy
    /// `force_after_grace` needs it, and no other step has one.
    pub graceful: Option<GracefulRecord<'a>>,
    /// A stop request that the caller has at this boundary.
    pub stop: Option<StopRequest>,
}

/// What the caller can do after a graceful step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// No force step: the step was a force step, no call was submitted, or
    /// no member with a submitted request is running.
    None,
    /// The strategy permits a force step at or after this time, after a
    /// fresh admission check.
    Force {
        /// The end of the grace period.
        not_before: MonotonicNanos,
    },
    /// A member is running and the strategy has no force step.
    ForceNotPermitted,
    /// A member is running and this stop request ended the step. The
    /// request that was issued is not recalled.
    Stopped(StopRequest),
    /// The effect on a member is not known. Reconcile before a force step.
    Reconcile,
}

/// The result of one member of the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberOutcome {
    /// The planned process generation.
    pub generation_id: ProcessGenerationId,
    /// What the last reading showed about the planned generation. `None`
    /// when the executor did not read the process.
    pub state: Option<GenerationState>,
    /// The target result.
    pub result: TargetResult,
}

/// The report of one finished step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// One result for each member of the target, in the sequence of the
    /// binding.
    pub members: Vec<MemberOutcome>,
    /// The monotonic time of a clock reading after the first call of the
    /// step. `None` when no call was issued, or when the clock gave no
    /// value after the call; an earlier time is never used in its place.
    pub submitted_at: Option<MonotonicNanos>,
    /// What the caller can do next.
    pub next: NextStep,
}

impl StepReport {
    /// The target results, for the journal and for the aggregation.
    pub fn results(&self) -> Vec<TargetResult> {
        self.members
            .iter()
            .map(|member| member.result.clone())
            .collect()
    }
}

/// A step after [`ProcessExecutor::begin`] or [`Observation::poll`].
#[derive(Debug)]
pub enum StepRun {
    /// A call was issued and the exit of a member is not yet observed.
    Observing(Box<Observation>),
    /// Each member has a result.
    Finished(StepReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepKind {
    Graceful,
    Force,
}

/// The backend of one member.
#[derive(Debug, Clone, Copy)]
enum Backend<'a> {
    /// The registered process of an application: the application API.
    Application(&'a str),
    /// A job process, or a listed helper in a force step: one signal.
    Signal,
    /// A helper in a graceful step: the request to the application process
    /// applies to it, and it gets no call of its own.
    Follow,
    /// The membership is not of a kind that this build knows.
    Unsupported,
}

fn backend_of(kind: StepKind, member: &ProcessIdentity) -> Backend<'_> {
    match &member.association {
        ProcessAssociation::Application {
            bundle_identifier,
            attribution: AttributionMethod::LaunchServices,
            ..
        } => Backend::Application(bundle_identifier),
        ProcessAssociation::Application {
            attribution: AttributionMethod::ResponsibleProcess,
            ..
        } => match kind {
            StepKind::Graceful => Backend::Follow,
            StepKind::Force => Backend::Signal,
        },
        ProcessAssociation::ManagedJob {
            attribution: AttributionMethod::LaunchdJob,
            ..
        } => Backend::Signal,
        _ => Backend::Unsupported,
    }
}

/// A member whose exit is not yet observed.
#[derive(Debug)]
struct Pending {
    index: usize,
    member: ProcessIdentity,
    /// The full check before the call found the planned generation.
    verified: bool,
    last: GenerationState,
}

/// The results and the waiting members of one step.
#[derive(Debug)]
struct Work {
    base: RecordBase,
    kind: StepKind,
    escalation: Escalation,
    grace: Option<Nanoseconds>,
    wall: Option<WallTime>,
    slots: Vec<Option<MemberOutcome>>,
    pending: Vec<Pending>,
    submitted_at: Option<MonotonicNanos>,
}

impl Work {
    fn settle(
        &mut self,
        index: usize,
        member: &ProcessIdentity,
        state: Option<GenerationState>,
        outcome: Outcome,
    ) -> Result<(), ExecutorError> {
        let result: TargetResult = self
            .base
            .record(&member.generation_id, outcome, self.wall)?;
        let slot: &mut Option<MemberOutcome> = self
            .slots
            .get_mut(index)
            .ok_or(ExecutorError::MemberNotSettled)?;
        *slot = Some(MemberOutcome {
            generation_id: member.generation_id.clone(),
            state,
            result,
        });
        Ok(())
    }

    fn wait(&mut self, index: usize, member: &ProcessIdentity, verified: bool) {
        self.pending.push(Pending {
            index,
            member: member.clone(),
            verified,
            last: GenerationState::Running,
        });
    }

    fn finish(self, stop: Option<StopRequest>) -> Result<StepReport, ExecutorError> {
        let members: Vec<MemberOutcome> = self
            .slots
            .into_iter()
            .collect::<Option<Vec<MemberOutcome>>>()
            .ok_or(ExecutorError::MemberNotSettled)?;
        let next: NextStep = next_step(
            self.kind,
            &self.escalation,
            self.grace,
            self.submitted_at,
            &members,
            stop,
        );
        Ok(StepReport {
            members,
            submitted_at: self.submitted_at,
            next,
        })
    }
}

fn next_step(
    kind: StepKind,
    escalation: &Escalation,
    grace: Option<Nanoseconds>,
    submitted_at: Option<MonotonicNanos>,
    members: &[MemberOutcome],
    stop: Option<StopRequest>,
) -> NextStep {
    if kind == StepKind::Force {
        return NextStep::None;
    }
    if members
        .iter()
        .any(|member| member.result.effect.is_indeterminate())
    {
        return NextStep::Reconcile;
    }
    // A force step follows only a request that was submitted and that left
    // the member running.
    let is_running = |member: &MemberOutcome| {
        matches!(
            member.result.effect,
            TargetEffect::StillRunning | TargetEffect::Refused
        )
    };
    if !members.iter().any(is_running) {
        return NextStep::None;
    }
    if let Some(stop) = stop {
        return NextStep::Stopped(stop);
    }
    let grace_end: Option<MonotonicNanos> = match (escalation, grace, submitted_at) {
        (Escalation::ForceAfterGrace, Some(grace), Some(submitted_at)) => {
            submitted_at.checked_add(grace)
        }
        _ => None,
    };
    grace_end.map_or(NextStep::ForceNotPermitted, |not_before| NextStep::Force {
        not_before,
    })
}

/// What the graceful step recorded for one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prior {
    /// The member was in its final condition.
    Exited,
    /// A request was submitted and the member was running.
    Running,
    /// No request was submitted for the member, or its effect is not
    /// known.
    NotSubmitted,
}

/// The last result of each member in the record of a graceful step.
fn prior_of(
    record: &GracefulRecord<'_>,
    base: &RecordBase,
) -> Result<impl Fn(&ProcessGenerationId) -> Prior + use<>, ExecutorError> {
    let mut whole: Option<&TargetResult> = None;
    let mut members: BTreeMap<&str, &TargetResult> = BTreeMap::new();
    for result in record.results {
        if &result.target_id != base.target_id() {
            return Err(ExecutorError::GracefulRecord);
        }
        // As in the aggregation: a later record for the target as a whole
        // replaces each earlier record.
        match &result.member {
            None => {
                members.clear();
                whole = Some(result);
            }
            Some(member) => {
                members.insert(member.as_str(), result);
            }
        }
    }
    let classify = |result: &TargetResult| {
        // A record with a value that this build does not recognize passed
        // no consistency check. It is not read as a known result, and it
        // permits no force call.
        let recognized: bool = result.dispatch.is_recognized()
            && result.attribution.is_recognized()
            && result.durability.is_recognized()
            && result.stop_reason.is_recognized()
            && !matches!(result.evidence.native, NativeResult::Unrecognized);
        let running: bool = matches!(
            result.effect,
            TargetEffect::StillRunning | TargetEffect::Refused
        ) && matches!(result.dispatch, DispatchState::Submitted);
        if !recognized {
            Prior::NotSubmitted
        } else if result.effect.is_final_condition_met() {
            Prior::Exited
        } else if running {
            Prior::Running
        } else {
            Prior::NotSubmitted
        }
    };
    let priors: BTreeMap<String, Prior> = members
        .into_iter()
        .map(|(member, result)| (member.to_owned(), classify(result)))
        .collect();
    let fallback: Prior = whole.map_or(Prior::NotSubmitted, classify);
    Ok(
        move |member: &ProcessGenerationId| {
            priors.get(member.as_str()).copied().unwrap_or(fallback)
        },
    )
}

/// The process executor: it does one step of an application intervention
/// on the verified members of one target.
///
/// The executor does not select a target, does not decide policy, and does
/// not write the journal.
#[derive(Debug)]
pub struct ProcessExecutor<S, C, K> {
    source: S,
    control: C,
    clock: K,
    context: ExecutorContext,
    config: ExecutorConfig,
}

impl<S: ProcessSource, C: ProcessControl, K: StepClock> ProcessExecutor<S, C, K> {
    /// Makes an executor from its process source, its native calls, its
    /// clock, its context, and its configuration.
    pub const fn new(
        source: S,
        control: C,
        clock: K,
        context: ExecutorContext,
        config: ExecutorConfig,
    ) -> Self {
        Self {
            source,
            control,
            clock,
            context,
            config,
        }
    }

    /// Does the final check of one step and issues its calls.
    ///
    /// The step is `RequestApplicationExit` or `ForceApplicationExit` on an
    /// application target. The sequence is:
    ///
    /// 1. The checks of the step as a whole: the stop request, the context,
    ///    the deadline, the evidence validity, the leases, the grace
    ///    period of a force step, the protection fact, and the hard
    ///    refusals of the executor. A check that fails gives a `Skipped`
    ///    result for each member, and no call is issued.
    /// 2. For each member that gets a call: the identity check
    ///    (`revalidate`) immediately before the call, then one call.
    /// 3. When a call was issued, an [`Observation`] of the members whose
    ///    exit is not yet observed.
    ///
    /// The return value of a call is never a result: a member is
    /// `ExitVerified` only after a later reading shows that the planned
    /// generation does not exist.
    ///
    /// # Errors
    ///
    /// Returns an [`ExecutorError`] when the step is not one that this
    /// executor does, when the receipt or the recording does not permit a
    /// submission, or when the record of the graceful step does not agree
    /// with the step. No call was issued. Returns
    /// [`ExecutorError::Record`] and the other defect variants only for a
    /// defect of the executor.
    pub fn begin(&self, input: StepInput<'_>) -> Result<StepRun, ExecutorError> {
        let envelope: &RequestEnvelope = input.envelope;
        let kind: StepKind = match envelope.action_class {
            ActionClass::RequestApplicationExit => StepKind::Graceful,
            ActionClass::ForceApplicationExit => StepKind::Force,
            _ => return Err(ExecutorError::NotApplicationStep),
        };
        let TargetBinding::Application(application) = &envelope.target.binding else {
            return Err(ExecutorError::NotApplicationStep);
        };
        if !matches!(envelope.executor, ExecutorRole::User) {
            return Err(ExecutorError::NotApplicationStep);
        }
        if !matches!(input.receipt.consumption, DispatchConsumption::Consumed) {
            return Err(ExecutorError::DispatchNotConsumed(
                input.receipt.consumption,
            ));
        }
        check_dispatch_recording(
            &envelope.action_class,
            &envelope.trigger.class,
            &envelope.recording,
            &input.receipt.durability,
        )
        .map_err(ExecutorError::Recording)?;
        let graceful: Option<GracefulRecord<'_>> =
            match (kind, &envelope.limits.escalation, input.graceful) {
                (StepKind::Force, Escalation::ForceAfterGrace, Some(record)) => Some(record),
                (StepKind::Force, Escalation::ImmediateForce, None)
                | (StepKind::Graceful, Escalation::None | Escalation::ForceAfterGrace, None) => {
                    None
                }
                _ => return Err(ExecutorError::GracefulRecord),
            };
        let base: RecordBase = RecordBase::new(envelope, input.receipt.durability.clone())?;
        let prior = match &graceful {
            Some(record) => Some(prior_of(record, &base)?),
            None => None,
        };

        let mut work: Work = Work {
            base,
            kind,
            escalation: envelope.limits.escalation.clone(),
            grace: envelope.limits.grace,
            wall: self.clock.wall_now(),
            slots: vec![None; application.members.len()],
            pending: Vec::new(),
            submitted_at: None,
        };
        let window: Nanoseconds = match self.check_step(&input, kind, application) {
            Ok(checked) => checked,
            Err(outcome) => {
                for (index, member) in application.members.iter().enumerate() {
                    work.settle(index, member, None, (*outcome).clone())?;
                }
                return Ok(StepRun::Finished(work.finish(input.stop)?));
            }
        };

        self.dispatch(&mut work, kind, envelope, application, prior.as_ref())?;
        if work.pending.is_empty() {
            return Ok(StepRun::Finished(work.finish(None)?));
        }
        Ok(StepRun::Observing(Box::new(Observation {
            window_ends_at: window_end(work.submitted_at, window),
            work,
            window,
            clock_failures: 0,
        })))
    }

    /// The checks of the step as a whole. Returns the observation window,
    /// or the result that each member gets.
    fn check_step(
        &self,
        input: &StepInput<'_>,
        kind: StepKind,
        application: &ApplicationBinding,
    ) -> Result<Nanoseconds, Box<Outcome>> {
        let envelope: &RequestEnvelope = input.envelope;
        let skip = |failure: Failure| Box::new(Outcome::skipped(failure, false));
        if let Some(stop) = input.stop {
            return Err(Box::new(Outcome::stopped(stop.reason())));
        }
        let Ok(now) = self.clock.monotonic_now() else {
            return Err(skip(Failure::evidence(code::CLOCK_UNAVAILABLE)));
        };
        let evidence = &envelope.evidence;
        if evidence.boot_id != self.context.boot_id
            || evidence.clock_domain != self.context.clock_domain
            || evidence.executor_epoch != self.context.executor_epoch
        {
            return Err(skip(Failure::evidence(code::EXECUTOR_CONTEXT_CHANGED)));
        }
        if let Some(outcome) = expired(envelope, now) {
            return Err(Box::new(outcome));
        }
        // The grace period is the observation window of a graceful step
        // that a force step can follow.
        let window: Nanoseconds = match (kind, &envelope.limits.escalation) {
            (StepKind::Graceful, Escalation::ForceAfterGrace) => envelope
                .limits
                .grace
                .unwrap_or(envelope.limits.verification_window),
            _ => envelope.limits.verification_window,
        };
        if now.checked_add(window).is_none() {
            return Err(skip(Failure::limits(code::WINDOW_OVERFLOW)));
        }
        if let Some(record) = &input.graceful {
            let grace_end: Option<MonotonicNanos> = envelope
                .limits
                .grace
                .and_then(|grace| record.submitted_at.checked_add(grace));
            if grace_end.is_none_or(|grace_end| now < grace_end) {
                return Err(skip(Failure::limits(code::GRACE_NOT_EXPIRED)));
            }
        }
        if let Some(failure) = self.refusal(envelope.principal.uid, application, input.protection) {
            return Err(skip(failure));
        }
        Ok(window)
    }

    /// The hard refusals of the executor. They apply to each plan, each
    /// trigger, and each strategy.
    fn refusal(
        &self,
        principal: Uid,
        application: &ApplicationBinding,
        protection: ProtectionFact,
    ) -> Option<Failure> {
        match protection {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => {
                return Some(Failure::eligibility(code::TARGET_PROTECTED));
            }
            ProtectionFact::Unknown => {
                return Some(Failure::eligibility(code::TARGET_PROTECTION_UNKNOWN));
            }
        }
        let (Some(own), Some(parent)) = (self.control.own_process(), self.control.parent_process())
        else {
            return Some(Failure::eligibility(code::CONTROL_PLANE_UNKNOWN));
        };
        let user: Uid = self.source.effective_uid();
        if principal != user {
            return Some(Failure::eligibility(code::TARGET_OTHER_USER));
        }
        for member in &application.members {
            let pid: Pid = member.pid;
            // PID 1 is `launchd`. `Pid` has no value of 0 or less.
            if pid.get() <= 1 {
                return Some(Failure::eligibility(code::TARGET_PROTECTED));
            }
            if pid == own || pid == parent {
                return Some(Failure::eligibility(code::TARGET_IS_CONTROL_PLANE));
            }
            if member.uid != user || member.uid.get() == 0 {
                return Some(Failure::eligibility(code::TARGET_OTHER_USER));
            }
            if member.boot_id != self.context.boot_id {
                return Some(Failure::evidence(code::EXECUTOR_CONTEXT_CHANGED));
            }
        }
        // The catalog rules that need no control plane: the owner,
        // `launchd`, the bundle identifier, and the executable path. With
        // no control plane the catalog gives `Protected` or `Unknown`; only
        // `Protected` is a result here.
        let context: ProtectionContext<'_> = ProtectionContext {
            principal,
            control_plane: None,
        };
        if hard_protection(&application.members, &context) == ProtectionFact::Protected {
            return Some(Failure::eligibility(code::TARGET_PROTECTED));
        }
        None
    }

    /// Issues the calls of the step, in this sequence: the first reading
    /// of each helper that gets no call, the application processes, and
    /// then each other member.
    fn dispatch(
        &self,
        work: &mut Work,
        kind: StepKind,
        envelope: &RequestEnvelope,
        application: &ApplicationBinding,
        prior: Option<&impl Fn(&ProcessGenerationId) -> Prior>,
    ) -> Result<(), ExecutorError> {
        let mut followers: Vec<(usize, &ProcessIdentity, GenerationState)> = Vec::new();
        let mut first: Vec<(usize, &ProcessIdentity, Backend<'_>)> = Vec::new();
        let mut second: Vec<(usize, &ProcessIdentity, Backend<'_>)> = Vec::new();
        for (index, member) in application.members.iter().enumerate() {
            match prior.map(|prior| prior(&member.generation_id)) {
                Some(Prior::Exited) => {
                    work.settle(index, member, None, Outcome::already_exited(false))?;
                    continue;
                }
                Some(Prior::NotSubmitted) => {
                    let failure: Failure =
                        Failure::eligibility(code::GRACEFUL_REQUEST_NOT_SUBMITTED);
                    work.settle(index, member, None, Outcome::skipped(failure, false))?;
                    continue;
                }
                Some(Prior::Running) | None => {}
            }
            match backend_of(kind, member) {
                Backend::Follow => {
                    followers.push((index, member, observe(&self.source, member)));
                }
                backend @ Backend::Application(_) => first.push((index, member, backend)),
                backend @ Backend::Signal => second.push((index, member, backend)),
                Backend::Unsupported => {
                    let failure: Failure = Failure::evidence(code::MEMBERSHIP_NOT_VERIFIED);
                    work.settle(index, member, None, Outcome::skipped(failure, false))?;
                }
            }
        }
        // The result of the request to the application process, which
        // applies to each helper that gets no call of its own.
        let mut request: Acted = Acted::NotIssued;
        for (index, member, backend) in first.into_iter().chain(second) {
            let acted: Acted = self.act(work, kind, envelope, index, member, backend)?;
            if matches!(backend, Backend::Application(_)) {
                request = match (request, acted) {
                    (Acted::Accepted, _) | (_, Acted::Accepted) => Acted::Accepted,
                    (Acted::Declined, _) | (_, Acted::Declined) => Acted::Declined,
                    _ => Acted::NotIssued,
                };
            }
        }
        for (index, member, before) in followers {
            let outcome: Outcome = match (before, request) {
                (GenerationState::Exited | GenerationState::Replaced, _) => {
                    Outcome::already_exited(true)
                }
                (GenerationState::Running, Acted::Accepted) => {
                    work.wait(index, member, true);
                    continue;
                }
                (GenerationState::Unknown(_), Acted::Accepted) => {
                    work.wait(index, member, false);
                    continue;
                }
                // The application declined the request for the instance, so
                // the helper has the same refusal. A force step can follow.
                (GenerationState::Running, Acted::Declined) => Outcome::refused(
                    NativeResult::Refused,
                    Failure::native(code::APPLICATION_DECLINED_REQUEST),
                ),
                (GenerationState::Running, Acted::NotIssued) => Outcome::skipped(
                    Failure::eligibility(code::APPLICATION_REQUEST_NOT_SUBMITTED),
                    true,
                ),
                (GenerationState::Unknown(failure), _) => query_failure(failure),
            };
            work.settle(index, member, Some(before), outcome)?;
        }
        Ok(())
    }

    /// Checks the limits and the identity of one member and issues its
    /// call.
    fn act(
        &self,
        work: &mut Work,
        kind: StepKind,
        envelope: &RequestEnvelope,
        index: usize,
        member: &ProcessIdentity,
        backend: Backend<'_>,
    ) -> Result<Acted, ExecutorError> {
        // The calls of the earlier members took time. The limits are read
        // again, before the identity check, so that the identity query
        // stays the last query before the call.
        let limit: Option<Outcome> = match self.clock.monotonic_now() {
            Ok(now) => expired(envelope, now),
            Err(_) => Some(Outcome::skipped(
                Failure::evidence(code::CLOCK_UNAVAILABLE),
                false,
            )),
        };
        if let Some(outcome) = limit {
            work.settle(index, member, None, outcome)?;
            return Ok(Acted::NotIssued);
        }
        let (state, outcome): (GenerationState, Outcome) = match revalidate(&self.source, member) {
            Revalidation::Same => match self.call(kind, member, backend) {
                Call::NotIssued(outcome) => (GenerationState::Running, outcome),
                Call::Issued(result) => {
                    // The time of the submission is a reading after the
                    // call. With no clock value it stays unknown; an
                    // earlier time is never used in its place.
                    if work.submitted_at.is_none() {
                        work.submitted_at = self.clock.monotonic_now().ok();
                    }
                    match result {
                        None => {
                            work.wait(index, member, true);
                            return Ok(Acted::Accepted);
                        }
                        Some((state, outcome)) => {
                            let declined: bool = matches!(outcome.effect, TargetEffect::Refused);
                            work.settle(index, member, Some(state), outcome)?;
                            return Ok(if declined {
                                Acted::Declined
                            } else {
                                Acted::NotIssued
                            });
                        }
                    }
                }
            },
            Revalidation::Exited => (GenerationState::Exited, Outcome::already_exited(true)),
            Revalidation::Replaced => (
                GenerationState::Replaced,
                Outcome::skipped(Failure::evidence(code::PROCESS_REPLACED), true),
            ),
            Revalidation::OwnerChanged => (
                GenerationState::Running,
                Outcome::skipped(Failure::evidence(code::PROCESS_OWNER_CHANGED), true),
            ),
            Revalidation::ExecutableChanged => (
                GenerationState::Running,
                Outcome::skipped(Failure::evidence(code::PROCESS_EXECUTABLE_CHANGED), true),
            ),
            Revalidation::EvidenceMissing => (
                GenerationState::Running,
                Outcome::skipped(Failure::evidence(code::PROCESS_EVIDENCE_MISSING), true),
            ),
            Revalidation::Unknown(failure) => {
                (GenerationState::Unknown(failure), query_failure(failure))
            }
        };
        work.settle(index, member, Some(state), outcome)?;
        Ok(Acted::NotIssued)
    }

    /// Issues the one call of a member whose identity agrees.
    fn call(&self, kind: StepKind, member: &ProcessIdentity, backend: Backend<'_>) -> Call {
        match backend {
            Backend::Signal => {
                let signal: ProcessSignal = match kind {
                    StepKind::Graceful => ProcessSignal::Graceful(self.config.graceful_signal),
                    StepKind::Force => ProcessSignal::Kill,
                };
                signal_outcome(self.control.signal(member.pid, signal))
            }
            Backend::Application(bundle_identifier) => {
                let Some(executable) = &member.executable else {
                    return Call::NotIssued(Outcome::skipped(
                        Failure::evidence(code::PROCESS_EVIDENCE_MISSING),
                        true,
                    ));
                };
                let expected: ApplicationExpectation<'_> = ApplicationExpectation {
                    pid: member.pid,
                    bundle_identifier,
                    executable_path: &executable.path,
                };
                let request: ApplicationRequest = match kind {
                    StepKind::Graceful => ApplicationRequest::Terminate,
                    StepKind::Force => ApplicationRequest::ForceTerminate,
                };
                let result: ApplicationCallResult =
                    self.control.request_application_exit(&expected, request);
                self.application_outcome(result, member)
            }
            Backend::Follow | Backend::Unsupported => Call::NotIssued(Outcome::skipped(
                Failure::evidence(code::MEMBERSHIP_NOT_VERIFIED),
                false,
            )),
        }
    }

    fn application_outcome(&self, result: ApplicationCallResult, member: &ProcessIdentity) -> Call {
        let skip = |failure: Failure| Call::NotIssued(Outcome::skipped(failure, true));
        match result {
            ApplicationCallResult::Accepted => Call::Issued(None),
            ApplicationCallResult::Declined => {
                // `false` is also the result for an application that exited
                // before the call. Only a reading can tell the two apart.
                let state: GenerationState = observe(&self.source, member);
                let outcome: Outcome = match state {
                    GenerationState::Exited | GenerationState::Replaced => {
                        Outcome::exited_before_call(NativeResult::Refused)
                    }
                    // The request was not sent. With a failed reading the
                    // refusal stays the result, and the state says that the
                    // process was not read.
                    GenerationState::Running | GenerationState::Unknown(_) => Outcome::refused(
                        NativeResult::Refused,
                        Failure::native(code::APPLICATION_DECLINED_REQUEST),
                    ),
                };
                Call::Issued(Some((state, outcome)))
            }
            ApplicationCallResult::NotRegistered => {
                skip(Failure::evidence(code::APPLICATION_NOT_REGISTERED))
            }
            ApplicationCallResult::IdentityMismatch => {
                skip(Failure::evidence(code::APPLICATION_IDENTITY_MISMATCH))
            }
            ApplicationCallResult::Terminated => {
                skip(Failure::evidence(code::APPLICATION_TERMINATED))
            }
            ApplicationCallResult::Unsupported => {
                let failure: Failure = Failure {
                    stage: svalnir_core::action::ActionStage::Dispatch,
                    ..Failure::native(code::BACKEND_UNSUPPORTED)
                };
                skip(failure)
            }
        }
    }
}

/// The result of the call of one member.
#[derive(Debug)]
enum Call {
    /// No call was issued.
    NotIssued(Outcome),
    /// A call was issued. `None` means that the backend accepted it and
    /// the exit is not yet observed. In each other case the value has the
    /// state of the process at the call and its result.
    Issued(Option<(GenerationState, Outcome)>),
}

/// What the call of one member did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Acted {
    /// No call was issued, or the call found no process.
    NotIssued,
    /// The backend accepted the call, and the member waits for a reading.
    Accepted,
    /// The backend refused the call.
    Declined,
}

/// The result of each member when a time limit of the step is at its end.
fn expired(envelope: &RequestEnvelope, now: MonotonicNanos) -> Option<Outcome> {
    let evidence = &envelope.evidence;
    if now >= envelope.limits.deadline {
        return Some(Outcome::stopped(StopReason::DeadlineExpired));
    }
    if now < evidence.observed_at || now >= evidence.valid_until {
        return Some(Outcome::skipped(
            Failure::evidence(code::EVIDENCE_EXPIRED),
            false,
        ));
    }
    if envelope.leases.iter().any(|lease| now >= lease.expires_at) {
        return Some(Outcome::skipped(
            Failure::limits(code::LEASE_EXPIRED),
            false,
        ));
    }
    None
}

/// The end of the observation window. With no known submission time, or
/// with an end that is not representable, the window has no end on the
/// clock; a stop request or the clock-failure limit ends the observation.
fn window_end(submitted_at: Option<MonotonicNanos>, window: Nanoseconds) -> MonotonicNanos {
    submitted_at
        .and_then(|submitted_at| submitted_at.checked_add(window))
        .unwrap_or(MonotonicNanos::new(u64::MAX))
}

fn signal_outcome(result: SignalResult) -> Call {
    match result {
        SignalResult::Delivered => Call::Issued(None),
        // The process exited between the check and the call. No signal was
        // delivered, and the member is not signaled again.
        SignalResult::NoSuchProcess => Call::Issued(Some((
            GenerationState::Exited,
            Outcome::exited_before_call(NativeResult::Errno { errno: libc::ESRCH }),
        ))),
        // The check before the call showed the process.
        SignalResult::NotPermitted => Call::Issued(Some((
            GenerationState::Running,
            Outcome::refused(
                NativeResult::Errno { errno: libc::EPERM },
                Failure::native(code::SIGNAL_NOT_PERMITTED),
            ),
        ))),
        SignalResult::Failed(errno) => Call::Issued(Some((
            GenerationState::Running,
            Outcome::refused(
                NativeResult::Errno { errno },
                Failure::native(code::SIGNAL_FAILED),
            ),
        ))),
        SignalResult::InvalidTarget => Call::NotIssued(Outcome::skipped(
            Failure::eligibility(code::TARGET_PROTECTED),
            true,
        )),
    }
}

/// The result of a member whose identity query failed before a call.
fn query_failure(failure: QueryFailure) -> Outcome {
    let code: &'static str = match failure {
        QueryFailure::PermissionDenied => code::PROCESS_QUERY_DENIED,
        _ => code::PROCESS_QUERY_FAILED,
    };
    Outcome::skipped(Failure::evidence(code), true)
}

/// The members of a step whose exit is not yet observed.
///
/// The value holds no lock and no native resource. The caller can keep it
/// for the time of the grace period and do other work.
#[derive(Debug)]
pub struct Observation {
    work: Work,
    window: Nanoseconds,
    window_ends_at: MonotonicNanos,
    clock_failures: u32,
}

impl Observation {
    /// The monotonic time at which the observation ends: the time of the
    /// first call plus the grace period (a graceful step that a force step
    /// can follow) or plus the verification window (each other step). The
    /// value is the largest time while the submission time is not known.
    pub const fn window_ends_at(&self) -> MonotonicNanos {
        self.window_ends_at
    }

    /// The monotonic time immediately after the first call of the step.
    pub const fn submitted_at(&self) -> Option<MonotonicNanos> {
        self.work.submitted_at
    }

    /// The number of members whose exit is not yet observed.
    pub fn waiting(&self) -> usize {
        self.work.pending.len()
    }

    /// Reads each waiting member one time.
    ///
    /// A member whose planned generation does not exist gets
    /// `ExitVerified`. The step is finished when no member waits, when the
    /// clock of `executor` is at or after
    /// [`window_ends_at`](Self::window_ends_at), when `stop` has a value,
    /// or after [`MAX_CLOCK_FAILURES`] consecutive polls with no clock
    /// value. At that time a member that the last reading showed running
    /// gets `StillRunning`, and a member whose last reading failed gets
    /// `UnknownOutcome`. `StillRunning` at the end of a force step with no
    /// stop request has the stop reason `FAILED`.
    ///
    /// A stop request ends the observation. It does not recall a request
    /// that was issued: the results have the dispatch state `submitted`.
    ///
    /// # Errors
    ///
    /// Returns an [`ExecutorError`] only for a defect of the executor.
    pub fn poll<S: ProcessSource, C: ProcessControl, K: StepClock>(
        mut self,
        executor: &ProcessExecutor<S, C, K>,
        stop: Option<StopRequest>,
    ) -> Result<StepRun, ExecutorError> {
        let now: Result<MonotonicNanos, QueryFailure> = executor.clock.monotonic_now();
        self.work.wall = executor.clock.wall_now();
        let mut waiting: Vec<Pending> = Vec::with_capacity(self.work.pending.len());
        for mut pending in std::mem::take(&mut self.work.pending) {
            let state: GenerationState = observe(&executor.source, &pending.member);
            let attribution: Attribution = match state {
                GenerationState::Exited if pending.verified => Attribution::Established,
                // A different generation has the PID, or the member was not
                // read before the call: the planned generation exited, and
                // the time of its exit is not known.
                GenerationState::Exited | GenerationState::Replaced => Attribution::Possible,
                GenerationState::Running | GenerationState::Unknown(_) => {
                    pending.last = state;
                    waiting.push(pending);
                    continue;
                }
            };
            let outcome: Outcome =
                Outcome::exit_verified(NativeResult::Succeeded, attribution, StopReason::Completed);
            self.work
                .settle(pending.index, &pending.member, Some(state), outcome)?;
        }
        let ended: bool = if let Ok(now) = now {
            // The clock gave no value after the first call. This later
            // reading is the submission time: the grace period then ends
            // later, and not earlier, than the true one.
            if self.work.submitted_at.is_none() {
                self.work.submitted_at = Some(now);
                self.window_ends_at = window_end(Some(now), self.window);
            }
            self.clock_failures = 0;
            now >= self.window_ends_at
        } else {
            self.clock_failures = self.clock_failures.saturating_add(1);
            self.clock_failures >= MAX_CLOCK_FAILURES
        };
        if !waiting.is_empty() && stop.is_none() && !ended {
            self.work.pending = waiting;
            return Ok(StepRun::Observing(Box::new(self)));
        }
        let stop_reason: Option<StopReason> = stop.map(StopRequest::reason);
        for pending in waiting {
            let outcome: Outcome = match pending.last {
                GenerationState::Unknown(_) => Outcome::unknown(
                    NativeResult::Succeeded,
                    stop_reason.clone(),
                    code::EXIT_NOT_VERIFIABLE,
                ),
                // A force request that left the process running is a known
                // failure. A graceful request that an application did not
                // follow is not one.
                _ => match (&stop_reason, self.work.kind) {
                    (None, StepKind::Force) => {
                        Outcome::still_running_after_force(NativeResult::Succeeded)
                    }
                    _ => Outcome::still_running(
                        NativeResult::Succeeded,
                        stop_reason.clone().unwrap_or(StopReason::Completed),
                    ),
                },
            };
            self.work
                .settle(pending.index, &pending.member, Some(pending.last), outcome)?;
        }
        Ok(StepRun::Finished(self.work.finish(stop)?))
    }
}
