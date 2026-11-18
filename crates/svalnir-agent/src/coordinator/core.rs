//! The coordinator: its state, its start, and its public calls.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use svalnir_core::action::{
    ActionError, ActionStage, Admission, DispatchState, Durability, ErrorFamily, ExecutorRole,
    JournalError, LeaseResource, Operation, Plan, PlanApproval, Principal, RecordingMode,
    ResourceEffect, ResourceLease, StopFence, StopReason, TargetBinding, TargetResult,
    VolatileJournalError, WorkCharge, critical_exception_applies,
};
use svalnir_core::grant::{ActionRequest, EvidenceStamp, IncidentBudget};
use svalnir_core::id::{
    AdapterId, ExecutorEpochId, OperationId, PlanId, RequestId, RootId, StepId, TargetId, VolumeId,
};
use svalnir_core::observation::Observation;
use svalnir_core::plan::{
    ApplyRefusal, CurrentRevisions, PlanMode, RevisionChange, check_apply, mode_of,
};
use svalnir_core::policy::{ContinuityGeneration, ProtectionFact};
use svalnir_core::quantity::{Bytes, Nanoseconds};
use svalnir_core::state::PressureState;
use svalnir_core::time::MonotonicNanos;

use super::board::{
    Board, CoordinatorHandle, OperationView, Phase, StopAcknowledgement, StopView, WaitOutcome,
    WorkTotals,
};
use super::error::{CoordinatorError, StartError, action_error, code};
use super::ledger::{Hold, IncidentAllowance, JournalUsage, Ledger, LedgerRefusal};
use super::ports::{
    ApplicationExecutor, AuthoritySource, Clock, CoordinatorJournal, FilesystemExecutor, IdSource,
    Measurements, RevisionSnapshot, TargetProbe, TimeReading, TriggerStanding,
};
use crate::executor::fs::{ApprovedRoot, ApprovedRoots, RootError};
use crate::executor::process::{NextStep, Observation as ExitObservation};
use crate::journal::{
    ClaimedRequest, CoordinationStart, CoordinatorLock, CoordinatorLockError, CoordinatorRole,
    RequestBody, RequestCompletion, VolatileRecord,
};

/// The largest number of admitted operations that wait for the active
/// one. A further apply is refused with `queue_full`.
pub const MAX_WAITING_OPERATIONS: usize = 16;

/// The largest number of volumes whose capacity one operation measures.
pub const MAX_MEASURED_VOLUMES: usize = 8;

/// The number of applied plans above which the coordinator keeps only the
/// plans of its unfinished and volatile operations in memory.
pub const MAX_KNOWN_PLANS: usize = 1024;

/// The settings of a coordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// The adapter identity in the envelope of a filesystem step.
    pub filesystem_adapter: AdapterId,
    /// The adapter identity in the envelope of an application step.
    pub process_adapter: AdapterId,
    /// The number of filesystem targets between two capacity
    /// measurements. A stop request is read before each target.
    pub batch_targets: usize,
    /// The time between two readings of an exit observation.
    pub poll_interval: Nanoseconds,
    /// The capacity of the volatile record of the critical-memory
    /// exception, in steps.
    pub volatile_capacity: usize,
    /// The kind of this process, for a process that finds the
    /// coordinator lock held.
    pub role: CoordinatorRole,
}

/// The collaborators of a coordinator.
#[derive(Debug)]
pub struct Dependencies {
    /// The clocks.
    pub clock: Box<dyn Clock + Send>,
    /// The authority records and the policy facts.
    pub authority: Box<dyn AuthoritySource + Send>,
    /// The measurements of outcome verification.
    pub measurements: Box<dyn Measurements + Send>,
    /// The identities of new operations and leases.
    pub ids: Box<dyn IdSource + Send>,
    /// The filesystem executor.
    pub filesystem: Box<dyn FilesystemExecutor + Send>,
    /// The approved roots of the filesystem executor that this process
    /// has from its own configuration. An automatic operation acts only
    /// under these roots. A manual operation acts under the roots that
    /// its sealed plan binds; see [`approved_roots_of`].
    pub roots: ApprovedRoots,
    /// The process executor.
    pub application: Box<dyn ApplicationExecutor + Send>,
    /// The fresh evidence of restart reconciliation.
    pub probe: Box<dyn TargetProbe + Send>,
}

/// The result of [`Coordinator::start`].
#[derive(Debug)]
pub enum Start<J: CoordinatorJournal> {
    /// This process is the coordinator of the journal.
    Coordinating(Box<Coordinator<J>>),
    /// A different coordinator holds the lock. Write the request to the
    /// request queue of the journal and read its status; this process
    /// dispatches nothing.
    Busy {
        /// The journal, for the queue calls of the client.
        journal: J,
        /// The collaborators, which the coordinator did not take.
        dependencies: Box<Dependencies>,
        /// The kind of the process that holds the lock, from the lock
        /// file. [`CoordinatorRole::Client`] when the role cannot be
        /// read: a client holder releases the lock after its request, so
        /// an agent that gets this value tries again.
        holder: CoordinatorRole,
    },
}

/// A request to apply a stored plan.
#[derive(Debug, Clone)]
pub struct ApplyRequest {
    /// The plan identity and the digest that the client reviewed.
    pub approval: PlanApproval,
    /// The authenticated user and client.
    pub principal: Principal,
    /// The plan, when the caller has it in memory (the controller). The
    /// coordinator stores it before the admission. `None` reads the plan
    /// that the client stored in the journal.
    pub plan: Option<Plan>,
    /// The allowance of the incident of an automatic plan, as the policy
    /// module computed it.
    pub incident: Option<IncidentAllowance>,
}

/// The result of an apply request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The plan is admitted as this operation.
    Admitted {
        /// The new operation.
        operation_id: OperationId,
    },
    /// The plan was applied before. This is its operation; no second one
    /// was made.
    Existing {
        /// The operation of the earlier apply.
        operation: Box<Operation>,
    },
    /// The request was refused. Nothing changed.
    Refused {
        /// The reason.
        error: ActionError,
    },
}

/// What one call of [`Coordinator::step`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// True when the call did work and a further call can do more now.
    pub worked: bool,
    /// The time at which a waiting operation needs the next call. `None`
    /// when no operation waits for a time.
    pub wake_at: Option<MonotonicNanos>,
}

/// How the caller of [`Coordinator::run_until_finished`] waits between
/// two steps.
pub trait Idle {
    /// Waits until `wake_at`, or for the idle interval of the caller when
    /// no operation waits for a time.
    fn idle(&mut self, wake_at: Option<MonotonicNanos>);
}

/// The record of the graceful step of one target, for its force step.
#[derive(Debug, Clone)]
pub(super) struct GracefulOutcome {
    /// The graceful step that gave the results.
    pub(super) step_id: StepId,
    pub(super) submitted_at: Option<MonotonicNanos>,
    pub(super) results: Vec<TargetResult>,
    pub(super) next: NextStep,
    /// The clock continuity at the dispatch of the graceful step, or at
    /// the latest start of the grace period. A different value at the
    /// force step shows a sleep in the grace period.
    pub(super) continuity: Option<ContinuityGeneration>,
}

/// An exit observation in progress.
#[derive(Debug)]
pub(super) struct Observing {
    pub(super) observation: Box<ExitObservation>,
    pub(super) next_poll: MonotonicNanos,
    /// True when the step of the observation charged the slot.
    pub(super) charged: bool,
}

/// The measurements before the first step.
#[derive(Debug, Default)]
pub(super) struct Baseline {
    pub(super) taken: bool,
    pub(super) capacity: Vec<(VolumeId, Observation<Bytes>)>,
    pub(super) pressure: Option<Observation<PressureState>>,
}

/// One admitted operation of this executor lifetime.
#[derive(Debug)]
pub(super) struct Active {
    pub(super) plan: Plan,
    pub(super) operation: Operation,
    pub(super) approval: PlanApproval,
    pub(super) principal: Principal,
    pub(super) hold: Hold,
    pub(super) leases: Vec<ResourceLease>,
    /// The approved roots of the filesystem steps of the operation.
    pub(super) roots: ApprovedRoots,
    pub(super) deadline: MonotonicNanos,
    pub(super) volatile: bool,
    pub(super) next_step: usize,
    pub(super) observing: Option<Observing>,
    pub(super) graceful: BTreeMap<TargetId, GracefulOutcome>,
    /// The clock continuity at the dispatch of the latest application
    /// step.
    pub(super) step_continuity: Option<ContinuityGeneration>,
    pub(super) stop: Option<StopView>,
    pub(super) baseline: Baseline,
    pub(super) effects: Vec<ResourceEffect>,
    pub(super) work: WorkTotals,
    pub(super) unsaved: BTreeSet<StepId>,
    pub(super) degraded: bool,
    pub(super) since_measurement: usize,
    /// The filesystem charge that no step consumed.
    pub(super) unused: Option<WorkCharge>,
    /// True when the operation is settled in memory and the journal did
    /// not take its record.
    pub(super) unrecorded: bool,
}

impl Active {
    pub(super) fn recording(&self) -> RecordingMode {
        if self.volatile {
            RecordingMode::VolatileCriticalException
        } else {
            RecordingMode::Durable
        }
    }

    pub(super) fn is_automatic(&self) -> bool {
        self.plan.trigger.class.is_automatic()
    }

    pub(super) fn view(&self, phase: Phase) -> OperationView {
        OperationView {
            operation: self.operation.clone(),
            phase,
            stop: self.stop.clone(),
            resource_effects: self.effects.clone(),
            work: self.work,
            degraded_recording: self.degraded || self.volatile,
        }
    }
}

/// The operation coordinator of one executor lifetime.
///
/// See the [module documentation](super) for the interface and the
/// concurrency design.
#[derive(Debug)]
pub struct Coordinator<J: CoordinatorJournal> {
    pub(super) journal: J,
    // The lock is held while the coordinator exists.
    pub(super) lock: CoordinatorLock,
    pub(super) epoch: ExecutorEpochId,
    pub(super) config: CoordinatorConfig,
    pub(super) clock: Box<dyn Clock + Send>,
    pub(super) authority: Box<dyn AuthoritySource + Send>,
    pub(super) measurements: Box<dyn Measurements + Send>,
    pub(super) ids: Box<dyn IdSource + Send>,
    pub(super) filesystem: Box<dyn FilesystemExecutor + Send>,
    pub(super) roots: ApprovedRoots,
    pub(super) application: Box<dyn ApplicationExecutor + Send>,
    pub(super) probe: Box<dyn TargetProbe + Send>,
    pub(super) volatile: VolatileRecord,
    pub(super) ledger: Ledger,
    pub(super) board: Arc<Board>,
    pub(super) active: Option<Box<Active>>,
    pub(super) waiting: VecDeque<Box<Active>>,
    /// The operation of each plan that this lifetime admitted, with the
    /// user of the apply.
    pub(super) plans: BTreeMap<PlanId, (OperationId, Principal)>,
    /// The operations that this lifetime left unsettled. Their leases and
    /// reservations stay until a reconciliation settles them.
    pub(super) parked: BTreeMap<OperationId, Box<Active>>,
    pub(super) reconciliation_pending: bool,
    pub(super) start: CoordinationStart,
    /// A claimed request that a pending reconciliation stopped.
    pub(super) held_request: Option<ClaimedRequest>,
    /// The completion of a claimed request that the journal did not
    /// record.
    pub(super) unwritten_completion: Option<(RequestId, RequestCompletion)>,
    /// True after [`Coordinator::stop_claims`]: this lifetime claims and
    /// executes no further request of the journal queue.
    pub(super) claims_stopped: bool,
    /// The time of the next reconciliation of the `UnknownOutcome`
    /// operations of an earlier lifetime whose resources the ledger holds.
    pub(super) held_reconciliation_at: Option<MonotonicNanos>,
    /// A claimed rearm request that waits for the controller of the agent
    /// ([`Coordinator::take_rearm`]). No further request is claimed while
    /// it waits.
    pub(super) pending_rearm: Option<ClaimedRequest>,
}

fn refused(error: ActionError) -> ApplyOutcome {
    ApplyOutcome::Refused { error }
}

/// The error record of an admission refusal.
fn admission_error(code: &str, family: ErrorFamily, plan_id: &PlanId) -> ActionError {
    action_error(
        code,
        family,
        ActionStage::Admission,
        Some(plan_id),
        None,
        None,
    )
}

fn apply_refusal_error(refusal: &ApplyRefusal, plan_id: &PlanId) -> ActionError {
    let text: &str = match refusal {
        ApplyRefusal::Approval(_) => code::APPROVAL_MISMATCH,
        ApplyRefusal::Expiry(_) => code::PLAN_EXPIRED,
        ApplyRefusal::Revision(RevisionChange::PolicyRevision) => code::POLICY_REVISION_CHANGED,
        ApplyRefusal::Revision(RevisionChange::ActionGrant(_)) => code::ACTION_GRANT_CHANGED,
        ApplyRefusal::Revision(RevisionChange::PrivilegeGrant) => code::PRIVILEGE_GRANT_CHANGED,
        ApplyRefusal::Revision(RevisionChange::Rule(_)) => code::RULE_REVISION_CHANGED,
    };
    admission_error(text, refusal.family(), plan_id)
}

/// A plan whose charge cannot be computed: a step names no target, or
/// the sum of the charges does not fit.
#[derive(Debug, Clone, Copy)]
struct NotChargeable;

/// The sum of the charges of the file targets of a plan. `None` for an
/// application plan, which uses one slot.
fn total_charge(plan: &Plan) -> Result<Option<WorkCharge>, NotChargeable> {
    let mut total: Option<WorkCharge> = None;
    for step in &plan.steps {
        match plan.target(&step.target_id).map(|target| &target.binding) {
            Some(TargetBinding::File(file)) => {
                let sum: WorkCharge = total
                    .unwrap_or(WorkCharge::ZERO)
                    .checked_add(file.charge)
                    .ok_or(NotChargeable)?;
                total = Some(sum);
            }
            Some(TargetBinding::Application(_) | TargetBinding::Process(_)) => {}
            None => return Err(NotChargeable),
        }
    }
    Ok(total)
}

/// The approved roots of the filesystem steps of an operation of `plan`.
///
/// An automatic plan acts only under the roots that the process has from
/// its own configuration (`configured`).
///
/// A manual plan acts under the roots that its file targets bind. The
/// sealed plan has the identity, the path, the object, the volume, and
/// the mount generation of the root of each file target, and the digest
/// that the user approved covers them. Thus a coordinator that did not
/// build the plan (an agent that takes the request from the queue of the
/// journal, or a client that executes a request of a different client)
/// has the approved roots of the request and no wider set. A configured
/// root with the identity of a bound root is used in its place, so the
/// executor compares the two records (`approved_root_mismatch`). The
/// executor opens each root with no-follow protection and compares its
/// object as before.
///
/// # Errors
///
/// Returns a [`RootError`] when the plan binds more roots than a set can
/// have, or when a root path is not an absolute normalized path.
pub fn approved_roots_of(
    plan: &Plan,
    configured: &ApprovedRoots,
) -> Result<ApprovedRoots, RootError> {
    if plan.trigger.class.is_automatic() {
        return Ok(configured.clone());
    }
    let mut roots: BTreeMap<&RootId, ApprovedRoot> = BTreeMap::new();
    for target in &plan.targets {
        let TargetBinding::File(file) = &target.binding else {
            continue;
        };
        roots.entry(&file.root_id).or_insert_with(|| {
            configured
                .root(&file.root_id)
                .cloned()
                .unwrap_or_else(|| ApprovedRoot {
                    root_id: file.root_id.clone(),
                    path: file.root_path.clone(),
                    object: file.root_object,
                    volume_id: file.volume_id.clone(),
                    mount_id: file.mount_id.clone(),
                })
        });
    }
    ApprovedRoots::new(roots.into_values().collect())
}

/// The conflict domains of a plan: each member generation of an
/// application target, and each cleanup root and each volume of a file
/// target.
fn lease_resources(plan: &Plan) -> Vec<LeaseResource> {
    lease_resources_of(plan.targets.iter().map(|target| &target.binding))
}

/// The conflict domains of the target bindings `bindings`. See
/// [`lease_resources`].
pub(super) fn lease_resources_of<'a>(
    bindings: impl Iterator<Item = &'a TargetBinding>,
) -> Vec<LeaseResource> {
    let mut resources: BTreeSet<LeaseResource> = BTreeSet::new();
    for binding in bindings {
        match binding {
            TargetBinding::File(file) => {
                resources.insert(LeaseResource::CleanupRoot(file.root_id.clone()));
                resources.insert(LeaseResource::Volume(file.volume_id.clone()));
            }
            TargetBinding::Application(application) => {
                for member in &application.members {
                    resources.insert(LeaseResource::ProcessGeneration(
                        member.generation_id.clone(),
                    ));
                }
            }
            TargetBinding::Process(binding) => {
                resources.insert(LeaseResource::ProcessGeneration(
                    binding.process.generation_id.clone(),
                ));
            }
        }
    }
    resources.into_iter().collect()
}

impl<J: CoordinatorJournal> Coordinator<J> {
    /// Takes the coordinator lock of the journal at `database` and
    /// registers this executor lifetime.
    ///
    /// When the lifetime before this one did not stop cleanly, or the
    /// journal has an operation that is not settled, the coordinator
    /// reconciles before its first admission and its first dispatch: the
    /// first call of [`Coordinator::step`] or [`Coordinator::apply`] does
    /// it.
    ///
    /// # Errors
    ///
    /// Returns a [`StartError`] when the lock file cannot be used, when
    /// the journal refuses the registration, or when a clock gives no
    /// value. A lock that a different coordinator holds is not an error:
    /// the result is [`Start::Busy`].
    pub fn start(
        mut journal: J,
        database: &Path,
        epoch: ExecutorEpochId,
        config: CoordinatorConfig,
        dependencies: Dependencies,
    ) -> Result<Start<J>, StartError> {
        let lock: CoordinatorLock = match CoordinatorLock::try_acquire(database, config.role) {
            Ok(lock) => lock,
            Err(CoordinatorLockError::Held) => {
                return Ok(Start::Busy {
                    journal,
                    dependencies: Box::new(dependencies),
                    holder: CoordinatorLock::confirmed_holder_role(database),
                });
            }
            Err(error) => return Err(error.into()),
        };
        let time: TimeReading = dependencies.clock.now().ok_or(StartError::Clock)?;
        let start: CoordinationStart = journal
            .begin_coordination(&lock, &epoch, time.wall)
            .map_err(StartError::Journal)?;
        // Volatile counts were possibly lost when the lifetime before
        // this one did not stop cleanly, or when a reconciliation that an
        // earlier lifetime left is pending. An operation that stays
        // `UnknownOutcome` after a clean stop makes the registration
        // pending and does not make the stop unclean. With no
        // predecessor, pending work was written outside the protocol.
        let unclean: bool = start
            .predecessor
            .as_ref()
            .map_or(start.reconciliation_pending, |predecessor| {
                !predecessor.released || predecessor.reconciliation_pending
            });
        // An operation that is not settled is reconciled also after a
        // clean stop: no operation of an earlier lifetime is dispatched.
        let unsettled: bool = journal
            .unsettled_operation_count()
            .map_or(true, |count| count > 0);
        let Dependencies {
            clock,
            authority,
            measurements,
            ids,
            filesystem,
            roots,
            application,
            probe,
        } = dependencies;
        Ok(Start::Coordinating(Box::new(Self {
            journal,
            lock,
            volatile: VolatileRecord::new(epoch.clone(), config.volatile_capacity),
            ledger: Ledger::new(epoch.clone(), unclean, time.clock.now),
            epoch,
            config,
            clock,
            authority,
            measurements,
            ids,
            filesystem,
            roots,
            application,
            probe,
            board: Arc::new(Board::default()),
            active: None,
            waiting: VecDeque::new(),
            plans: BTreeMap::new(),
            parked: BTreeMap::new(),
            reconciliation_pending: start.reconciliation_pending || unsettled,
            start,
            held_request: None,
            unwritten_completion: None,
            claims_stopped: false,
            held_reconciliation_at: None,
            pending_rearm: None,
        })))
    }

    /// The registration result of the journal: the coordinator before
    /// this one and the number of requests that went back to the queue.
    pub const fn coordination_start(&self) -> &CoordinationStart {
        &self.start
    }

    /// The executor lifetime of this coordinator.
    pub const fn executor_epoch(&self) -> &ExecutorEpochId {
        &self.epoch
    }

    /// Whether a reconciliation is pending. The coordinator admits and
    /// dispatches nothing while it is.
    pub const fn reconciliation_pending(&self) -> bool {
        self.reconciliation_pending
    }

    /// The interface for a different thread.
    pub fn handle(&self) -> CoordinatorHandle {
        CoordinatorHandle {
            board: Arc::clone(&self.board),
        }
    }

    /// The journal, for the read and maintenance calls of the owner.
    pub const fn journal(&self) -> &J {
        &self.journal
    }

    /// The database path of the coordinator lock.
    pub fn database(&self) -> &Path {
        self.lock.database()
    }

    /// Applies a plan: checks the request, reserves its budget, takes its
    /// leases, and admits one operation. The operation runs in the later
    /// calls of [`Coordinator::step`].
    ///
    /// A refusal changes nothing: no record, no reservation, and no lease
    /// stays. The coordinator records no rejection, so a plan that was
    /// refused for a condition that can change (a lease, a budget, a
    /// cooldown) can be applied again before its expiry.
    pub fn apply(&mut self, request: ApplyRequest) -> ApplyOutcome {
        let plan_id: PlanId = request.approval.plan_id.clone();
        let Some(time) = self.clock.now() else {
            return refused(admission_error(
                code::CLOCK_UNAVAILABLE,
                ErrorFamily::Limits,
                &plan_id,
            ));
        };
        if self.reconciliation_pending {
            self.reconcile();
        }
        if self.reconciliation_pending {
            return refused(action_error(
                code::RECONCILIATION_PENDING,
                ErrorFamily::Outcome,
                ActionStage::Reconciliation,
                Some(&plan_id),
                None,
                None,
            ));
        }
        // The volatile history goes to the journal before a durable
        // admission. A failure leaves it pending.
        if !self.volatile.pending_records().is_empty() {
            drop(self.journal.persist_volatile(&mut self.volatile));
        }
        if request
            .plan
            .as_ref()
            .is_some_and(|plan| plan.plan_id != plan_id)
        {
            return refused(admission_error(
                code::APPROVAL_MISMATCH,
                ErrorFamily::Authority,
                &plan_id,
            ));
        }
        let plan: Plan = match &request.plan {
            Some(plan) => plan.clone(),
            None => match self.journal.plan(&plan_id) {
                Ok(Some(plan)) => plan,
                Ok(None) => {
                    return refused(admission_error(
                        code::PLAN_NOT_FOUND,
                        ErrorFamily::Request,
                        &plan_id,
                    ));
                }
                Err(_) => {
                    return refused(admission_error(
                        code::ADMISSION_NOT_RECORDED,
                        ErrorFamily::Recording,
                        &plan_id,
                    ));
                }
            },
        };
        match self.check_request(&plan, &request, &time) {
            Ok(None) => {}
            Ok(Some(existing)) => return existing,
            Err(error) => return refused(*error),
        }
        // The plan of the controller is stored with the admission record,
        // after the reservation and the leases (`record_admission`). A
        // refusal before that point (a budget, a lease, the queue bound,
        // the roots) leaves no plan record.
        self.admit(plan, request, &time)
    }

    /// The checks of an apply request that reserve nothing. `Ok(Some)` is
    /// the operation of an earlier apply of the plan in this lifetime.
    fn check_request(
        &mut self,
        plan: &Plan,
        request: &ApplyRequest,
        time: &TimeReading,
    ) -> Result<Option<ApplyOutcome>, Box<ActionError>> {
        let plan_id: &PlanId = &plan.plan_id;
        if !plan.is_bound_by(&request.approval) {
            return Err(Box::new(admission_error(
                code::APPROVAL_MISMATCH,
                ErrorFamily::Authority,
                plan_id,
            )));
        }
        if let Some((operation_id, principal)) = self.plans.get(plan_id) {
            if principal.uid != request.principal.uid {
                return Err(Box::new(admission_error(
                    code::PLAN_CONFLICT,
                    ErrorFamily::Request,
                    plan_id,
                )));
            }
            if let Some(operation) = self.known_operation(operation_id) {
                // The same plan identity with different content is not
                // the plan of the earlier apply.
                if operation.plan_digest() != plan.digest() {
                    return Err(Box::new(admission_error(
                        code::PLAN_CONFLICT,
                        ErrorFamily::Request,
                        plan_id,
                    )));
                }
                return Ok(Some(ApplyOutcome::Existing {
                    operation: Box::new(operation),
                }));
            }
        }
        let Some(mode) = mode_of(plan) else {
            return Err(Box::new(admission_error(
                code::PLAN_NOT_EXECUTABLE,
                ErrorFamily::Request,
                plan_id,
            )));
        };
        // Milestone 2 calls no helper.
        if !matches!(plan.executor, ExecutorRole::User) {
            return Err(Box::new(admission_error(
                code::HELPER_NOT_AVAILABLE,
                ErrorFamily::Request,
                plan_id,
            )));
        }
        self.check_revisions(plan, &request.approval, mode, time)?;
        self.authorize_each(
            plan,
            &request.approval,
            &request.principal,
            &RecordingMode::Durable,
            &ActionStage::Admission,
            time,
        )?;
        // The catalog of hard protections, for the members of an
        // application target and for the one process of a process target.
        for target in &plan.targets {
            if let Some(processes) = target.binding.processes()
                && self.authority.protection(processes) != ProtectionFact::NotProtected
            {
                return Err(Box::new(admission_error(
                    code::TARGET_PROTECTED,
                    ErrorFamily::Eligibility,
                    plan_id,
                )));
            }
        }
        Ok(None)
    }

    fn check_revisions(
        &self,
        plan: &Plan,
        approval: &PlanApproval,
        mode: PlanMode,
        time: &TimeReading,
    ) -> Result<(), Box<ActionError>> {
        let snapshot: RevisionSnapshot = self.authority.revisions(mode, time);
        let Some(policy_revision) = &snapshot.policy_revision else {
            return Err(Box::new(admission_error(
                code::POLICY_REVISION_CHANGED,
                ErrorFamily::Authority,
                &plan.plan_id,
            )));
        };
        let current = CurrentRevisions {
            policy_revision,
            action_grants: &snapshot.action_grants,
            privilege_grant: None,
            rules: &snapshot.rules,
        };
        check_apply(plan, approval, mode, &time.clock, &current)
            .map_err(|refusal| Box::new(apply_refusal_error(&refusal, &plan.plan_id)))
    }

    /// The incident record and the trigger evidence of an automatic plan.
    pub(super) fn automatic_evidence(
        &self,
        plan: &Plan,
        stage: &ActionStage,
        time: &TimeReading,
    ) -> Result<(Option<IncidentBudget>, Option<EvidenceStamp>), Box<ActionError>> {
        if !plan.trigger.class.is_automatic() {
            return Ok((None, None));
        }
        let incident: Option<IncidentBudget> = plan
            .trigger
            .incident_id
            .as_ref()
            .and_then(|incident_id| self.authority.incident(incident_id));
        match self.authority.trigger(plan, time) {
            TriggerStanding::Holds(stamp) => Ok((incident, Some(stamp))),
            TriggerStanding::Cleared | TriggerStanding::Unknown => Err(Box::new(action_error(
                code::TRIGGER_NOT_CURRENT,
                ErrorFamily::Evidence,
                stage.clone(),
                Some(&plan.plan_id),
                None,
                None,
            ))),
        }
    }

    /// Asks the authorization of each step of a plan.
    fn authorize_each(
        &self,
        plan: &Plan,
        approval: &PlanApproval,
        principal: &Principal,
        recording: &RecordingMode,
        stage: &ActionStage,
        time: &TimeReading,
    ) -> Result<(), Box<ActionError>> {
        let (incident, evidence) = self.automatic_evidence(plan, stage, time)?;
        for step in &plan.steps {
            let request = ActionRequest {
                principal: principal.uid,
                plan,
                step_id: &step.step_id,
                stage: stage.clone(),
                approval: Some(approval),
                recording,
                incident: incident.as_ref(),
                evidence: evidence.as_ref(),
            };
            self.authority
                .authorize(&request, time)
                .map_err(|refusal| {
                    refusal.action_error().unwrap_or_else(|_| {
                        admission_error(code::PLAN_NOT_EXECUTABLE, refusal.family(), &plan.plan_id)
                    })
                })?;
        }
        Ok(())
    }

    /// Reserves the budget of a plan. A refusal changed no allowance of a
    /// later request: an incident record that the call made stays, and it
    /// has no reservation.
    fn reserve(
        &mut self,
        plan: &Plan,
        request: &ApplyRequest,
        total: Option<WorkCharge>,
        time: &TimeReading,
    ) -> Result<Hold, LedgerRefusal> {
        if !plan.trigger.class.is_automatic() {
            return Ledger::reserve_manual(plan.limits.work, total);
        }
        let missing = LedgerRefusal {
            code: code::INCIDENT_ALLOWANCE_MISSING,
        };
        let incident_id = plan.trigger.incident_id.as_ref().ok_or(missing)?;
        // An automatic plan is applied by the controller, with the
        // allowance of its incident. A request with no allowance (a
        // request of the journal queue, or a client that applies a stored
        // automatic plan) does not use the allowance that the ledger has
        // from an earlier request of the guard.
        let given: &IncidentAllowance = request.incident.as_ref().ok_or(missing)?;
        if &given.incident_id != incident_id {
            return Err(missing);
        }
        let first_record: bool = !self.ledger.knows(incident_id, given.generation);
        // A new record reads the consumed dispatches of the journal.
        let journal: Option<JournalUsage> = if self.ledger.has(incident_id) {
            None
        } else {
            Some(self.journal_usage(given))
        };
        self.ledger
            .observe_incident(given, journal, time.clock.now)?;
        if first_record {
            let volatile_exception: bool = self
                .authority
                .incident(incident_id)
                .is_some_and(|budget| budget.volatile_exception_at_open);
            self.ledger
                .exhaust_slots_if_volatile_lost(given, volatile_exception);
        }
        self.ledger
            .reserve_incident(incident_id, total, time.clock.now)
    }

    /// The consumed work of an incident that the journal has: its usage
    /// row, which the consumption of each dispatch changes and which the
    /// retention keeps while the incident is open.
    fn journal_usage(&self, given: &IncidentAllowance) -> JournalUsage {
        match self.journal.incident_usage(&given.incident_id) {
            Ok(Some(usage)) => JournalUsage::Known {
                slots: usage.slots,
                work: usage.work,
            },
            Ok(None) => JournalUsage::Known {
                slots: 0,
                work: WorkCharge::ZERO,
            },
            Err(_) => JournalUsage::Unknown,
        }
    }

    /// Reserves, takes the leases, and records the admission.
    fn admit(&mut self, plan: Plan, request: ApplyRequest, time: &TimeReading) -> ApplyOutcome {
        let plan_id: PlanId = plan.plan_id.clone();
        let limits = |text: &str| refused(admission_error(text, ErrorFamily::Limits, &plan_id));
        let Ok(total) = total_charge(&plan) else {
            return refused(admission_error(
                code::PLAN_NOT_EXECUTABLE,
                ErrorFamily::Request,
                &plan_id,
            ));
        };
        let (Some(deadline), Some(operation_id)) = (
            time.clock.now.checked_add(plan.limits.execution_deadline),
            self.ids.operation_id(),
        ) else {
            return limits(code::IDENTITY_UNAVAILABLE);
        };
        if self.waiting.len() >= MAX_WAITING_OPERATIONS {
            return limits(code::QUEUE_FULL);
        }
        let Ok(roots) = approved_roots_of(&plan, &self.roots) else {
            return refused(admission_error(
                code::PLAN_NOT_EXECUTABLE,
                ErrorFamily::Request,
                &plan_id,
            ));
        };
        let mut hold: Hold = match self.reserve(&plan, &request, total, time) {
            Ok(hold) => hold,
            Err(refusal) => return limits(refusal.code),
        };
        let leases: Vec<ResourceLease> = match self.ledger.acquire_leases(
            &lease_resources(&plan),
            &operation_id,
            deadline,
            self.ids.as_mut(),
        ) {
            Ok(leases) => leases,
            Err(refusal) => {
                self.ledger.release(&mut hold, total);
                return limits(refusal.code);
            }
        };
        let admitted: Result<(Operation, bool), Box<ApplyOutcome>> =
            self.record_admission(&plan, &request, &operation_id, time);
        let (operation, volatile) = match admitted {
            Ok(admitted) => admitted,
            Err(outcome) => {
                self.ledger.release(&mut hold, total);
                self.ledger.release_leases(&operation_id);
                return *outcome;
            }
        };
        if self.plans.len() >= MAX_KNOWN_PLANS {
            self.forget_finished_plans();
        }
        self.plans
            .insert(plan_id, (operation_id.clone(), request.principal.clone()));
        let active = Box::new(Active {
            plan,
            operation,
            approval: request.approval,
            principal: request.principal,
            hold,
            leases,
            roots,
            deadline,
            volatile,
            next_step: 0,
            observing: None,
            graceful: BTreeMap::new(),
            step_continuity: None,
            stop: None,
            baseline: Baseline::default(),
            effects: Vec::new(),
            work: WorkTotals {
                exact: true,
                ..WorkTotals::default()
            },
            unsaved: BTreeSet::new(),
            degraded: false,
            since_measurement: 0,
            unused: total,
            unrecorded: false,
        });
        if self.active.is_none() && self.waiting.is_empty() {
            self.board.publish(active.view(Phase::Running));
            self.active = Some(active);
        } else {
            self.board.publish(active.view(Phase::Waiting));
            self.waiting.push_back(active);
        }
        ApplyOutcome::Admitted { operation_id }
    }

    /// Records the plan of the controller and the admission in the
    /// durable journal, or the admission in the volatile record when the
    /// storage of the journal failed and the critical-memory exception is
    /// authorized for each step of the plan. A locked journal is a
    /// refusal with `admission_not_recorded` and never the exception. The
    /// second value is true for the volatile record.
    ///
    /// The plan record is written here and not before the reservation, so
    /// that a plan whose admission was refused for a limit leaves no
    /// record. The caller releases the reservation and the leases for
    /// each error of this function.
    fn record_admission(
        &mut self,
        plan: &Plan,
        request: &ApplyRequest,
        operation_id: &OperationId,
        time: &TimeReading,
    ) -> Result<(Operation, bool), Box<ApplyOutcome>> {
        let plan_id: &PlanId = &plan.plan_id;
        let request_error =
            |text: &str, family: ErrorFamily| refused(admission_error(text, family, plan_id));
        // A locked journal is a refusal of this attempt and not a storage
        // failure: it never permits the critical-memory exception. The
        // controller tries again at its next evaluation.
        let locked = || request_error(code::ADMISSION_NOT_RECORDED, ErrorFamily::Recording);
        let mut storage_failed: bool = false;
        if request.plan.is_some() {
            match self.journal.record_plan(plan) {
                Ok(()) => {}
                Err(JournalError::Busy) => return Err(Box::new(locked())),
                Err(error) if error.family() == ErrorFamily::Recording => storage_failed = true,
                Err(_) => {
                    return Err(Box::new(request_error(
                        code::PLAN_CONFLICT,
                        ErrorFamily::Request,
                    )));
                }
            }
        }
        if !storage_failed {
            let operation: Operation = Operation::admit(
                plan,
                operation_id.clone(),
                self.epoch.clone(),
                Durability::Durable,
                time.wall,
            )
            .map_err(|_| request_error(code::PLAN_NOT_EXECUTABLE, ErrorFamily::Request))?;
            match self
                .journal
                .admit(&request.approval, &request.principal, &operation)
            {
                Ok(Admission::Admitted) => return Ok((operation, false)),
                Ok(Admission::Existing { operation }) => {
                    return Err(Box::new(ApplyOutcome::Existing { operation }));
                }
                Ok(Admission::Rejected { error }) => return Err(Box::new(refused(error))),
                Err(JournalError::NotFound) => {
                    return Err(Box::new(request_error(
                        code::PLAN_NOT_FOUND,
                        ErrorFamily::Request,
                    )));
                }
                Err(JournalError::Conflict) => {
                    return Err(Box::new(request_error(
                        code::PLAN_CONFLICT,
                        ErrorFamily::Request,
                    )));
                }
                Err(JournalError::Expired) => {
                    return Err(Box::new(request_error(
                        code::PLAN_CONSUMPTION_EXPIRED,
                        ErrorFamily::Limits,
                    )));
                }
                Err(JournalError::Sequence) => {
                    // The journal has a pending reconciliation. The next
                    // step does it.
                    self.reconciliation_pending = true;
                    self.start.reconciliation_pending = true;
                    return Err(Box::new(refused(action_error(
                        code::RECONCILIATION_PENDING,
                        ErrorFamily::Outcome,
                        ActionStage::Reconciliation,
                        Some(plan_id),
                        None,
                        None,
                    ))));
                }
                Err(JournalError::Busy) => return Err(Box::new(locked())),
                Err(_) => storage_failed = true,
            }
        }
        debug_assert!(storage_failed);
        let not_recorded = || request_error(code::ADMISSION_NOT_RECORDED, ErrorFamily::Recording);
        // The critical-memory exception: each step is an application step
        // with the global critical-memory trigger, and the grant module
        // authorizes the volatile recording for exactly this plan.
        let applies: bool = plan
            .steps
            .iter()
            .all(|step| critical_exception_applies(&step.action_class, &plan.trigger.class));
        if !applies {
            return Err(Box::new(not_recorded()));
        }
        self.authorize_each(
            plan,
            &request.approval,
            &request.principal,
            &RecordingMode::VolatileCriticalException,
            &ActionStage::Admission,
            time,
        )
        .map_err(|_| not_recorded())?;
        let operation: Operation = Operation::admit(
            plan,
            operation_id.clone(),
            self.epoch.clone(),
            Durability::Volatile,
            time.wall,
        )
        .map_err(|_| not_recorded())?;
        self.volatile
            .register(plan, &request.principal, operation.clone())
            .map_err(|_| request_error(code::VOLATILE_RECORD_REFUSED, ErrorFamily::Recording))?;
        Ok((operation, true))
    }

    /// Removes the plans of the operations that are finished and that
    /// the durable journal has. The journal returns the operation of such
    /// a plan for a repeated apply.
    fn forget_finished_plans(&mut self) {
        let live: BTreeSet<OperationId> = self
            .active
            .iter()
            .chain(self.waiting.iter())
            .chain(self.parked.values())
            .map(|active| active.operation.operation_id().clone())
            .collect();
        let volatile = &self.volatile;
        self.plans.retain(|_, (operation_id, _)| {
            live.contains(operation_id) || volatile.operation(operation_id).is_some()
        });
    }

    /// The record of an operation that this lifetime has in memory, in its
    /// volatile record, or in the journal.
    fn known_operation(&self, operation_id: &OperationId) -> Option<Operation> {
        if let Some(active) = &self.active
            && active.operation.operation_id() == operation_id
        {
            return Some(active.operation.clone());
        }
        self.waiting
            .iter()
            .chain(self.parked.values())
            .find(|active| active.operation.operation_id() == operation_id)
            .map(|active| active.operation.clone())
            .or_else(|| self.board.view(operation_id).map(|view| view.operation))
            .or_else(|| self.volatile.operation(operation_id).cloned())
            .or_else(|| self.journal.operation(operation_id).ok().flatten())
    }

    /// Reads an operation: the view of the status board for an operation
    /// of this lifetime, or the record of the journal.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] when the journal cannot be read.
    pub fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OperationView>, CoordinatorError> {
        if let Some(view) = self.board.view(operation_id) {
            return Ok(Some(view));
        }
        let stored: Option<Operation> = self
            .journal
            .operation(operation_id)
            .map_err(CoordinatorError::Record)?;
        let Some(operation) = stored else {
            return Ok(None);
        };
        // A fence that cannot be read is not reported as no fence.
        let fenced: bool = self
            .journal
            .has_stop_fence(operation_id)
            .map_err(CoordinatorError::Record)?;
        Ok(Some({
            let finished: bool = operation.state().is_settled();
            OperationView {
                stop: fenced.then_some(StopView {
                    reason: StopReason::Canceled,
                    acknowledgement: if finished {
                        StopAcknowledgement::Settled
                    } else {
                        StopAcknowledgement::DurableFence
                    },
                }),
                operation,
                phase: Phase::Finished,
                // The observations that the coordinator of the operation
                // recorded. A record that cannot be read is not reported
                // as no observation.
                resource_effects: self
                    .journal
                    .resource_effects(operation_id)
                    .map_err(|error| CoordinatorError::Record(error.to_journal_error()))?,
                work: WorkTotals::default(),
                degraded_recording: false,
            }
        }))
    }

    /// Cancels an operation: no further step of it is dispatched. A call
    /// that was issued is not recalled, and a settled canceled operation
    /// can have effects of earlier steps.
    ///
    /// # Errors
    ///
    /// Returns an [`ActionError`] of the family `request` when no
    /// operation has the identity, and of the family `recording` when the
    /// journal cannot be read for an operation that this lifetime does
    /// not have in memory.
    pub fn cancel(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<StopAcknowledgement, Box<ActionError>> {
        let time: Option<TimeReading> = self.clock.now();
        // An operation that waits is settled now: it has no step in
        // progress.
        if let Some(position) = self
            .waiting
            .iter()
            .position(|active| active.operation.operation_id() == operation_id)
            && let Some(mut active) = self.waiting.remove(position)
        {
            self.fence(&mut active, StopReason::Canceled);
            let level: StopAcknowledgement = active
                .stop
                .as_ref()
                .map_or(StopAcknowledgement::CurrentInstance, |stop| {
                    stop.acknowledgement
                });
            self.stop_and_finish(active, &StopReason::Canceled, None, time.as_ref());
            // The operation is settled only when the journal took its
            // record. If not, it is parked with the level of its fence.
            return Ok(if self.parked.contains_key(operation_id) {
                level
            } else {
                StopAcknowledgement::Settled
            });
        }
        if let Some(mut active) = self.active.take() {
            if active.operation.operation_id() == operation_id {
                let level: StopAcknowledgement = self.fence(&mut active, StopReason::Canceled);
                self.board.publish(active.view(match &active.observing {
                    Some(observing) => Phase::Observing {
                        until: observing.observation.window_ends_at(),
                    },
                    None => Phase::Running,
                }));
                self.active = Some(active);
                return Ok(level);
            }
            self.active = Some(active);
        }
        // A parked operation dispatches no further step. The journal does
        // not have its result (or the result is not known), so the level
        // is the level of its stop, and never `Settled`.
        if let Some(mut active) = self.parked.remove(operation_id) {
            let level: StopAcknowledgement = self.fence(&mut active, StopReason::Canceled);
            self.board.publish(active.view(Phase::Finished));
            self.parked.insert(operation_id.clone(), active);
            return Ok(level);
        }
        let not_found = |family: ErrorFamily| {
            action_error(
                code::OPERATION_NOT_FOUND,
                family,
                ActionStage::Admission,
                None,
                Some(operation_id),
                None,
            )
        };
        if let Some(view) = self.board.view(operation_id)
            && view.phase == Phase::Finished
            && view.operation.state().is_settled()
        {
            return Ok(StopAcknowledgement::Settled);
        }
        match self.journal.operation(operation_id) {
            Ok(Some(operation)) if operation.state().is_settled() => {
                Ok(StopAcknowledgement::Settled)
            }
            Ok(Some(_)) => Ok(match self.journal.stop_fence(operation_id) {
                StopFence::Durable => StopAcknowledgement::DurableFence,
                StopFence::CurrentInstance => StopAcknowledgement::CurrentInstance,
            }),
            Ok(None) => Err(Box::new(not_found(ErrorFamily::Request))),
            Err(_) => Err(Box::new(not_found(ErrorFamily::Recording))),
        }
    }

    /// Records the stop of an operation in memory and in its journal.
    pub(super) fn fence(&mut self, active: &mut Active, reason: StopReason) -> StopAcknowledgement {
        let operation_id: OperationId = active.operation.operation_id().clone();
        let level: StopAcknowledgement = if active.volatile {
            // The volatile record keeps the stop of this instance only.
            let _unknown: Result<(), VolatileJournalError> = self.volatile.stop(&operation_id);
            StopAcknowledgement::CurrentInstance
        } else {
            match self.journal.stop_fence(&operation_id) {
                StopFence::Durable => StopAcknowledgement::DurableFence,
                StopFence::CurrentInstance => StopAcknowledgement::CurrentInstance,
            }
        };
        let acknowledgement: StopAcknowledgement = active
            .stop
            .as_ref()
            .map_or(level, |stop| stop.acknowledgement.max(level));
        let reason: StopReason = active
            .stop
            .as_ref()
            .map_or(reason, |stop| stop.reason.clone());
        active.stop = Some(StopView {
            reason,
            acknowledgement,
        });
        acknowledgement
    }

    /// Does one bounded unit of work and returns. The call never sleeps:
    /// a grace period or an exit observation is a time in the result.
    ///
    /// One call does, in this sequence: a pending reconciliation; the
    /// stop requests of the status board; one request of the journal
    /// queue; and one unit of the active operation (one filesystem
    /// target, the start of one application step, or one reading of an
    /// exit observation).
    pub fn step(&mut self) -> Progress {
        let Some(time) = self.clock.now() else {
            return Progress {
                worked: false,
                wake_at: None,
            };
        };
        if self.reconciliation_pending {
            self.reconcile();
            return Progress {
                worked: !self.reconciliation_pending,
                wake_at: None,
            };
        }
        self.reconcile_held(time.clock.now);
        if !self.parked.is_empty() {
            self.retry_parked(&time);
        }
        for operation_id in self.board.take_stop_requests() {
            // The request is on the board; the result of the fence is in
            // the view of the operation.
            drop(self.cancel(&operation_id));
        }
        let mut worked: bool = self.serve_queue();
        if self.active.is_none() {
            self.active = self.waiting.pop_front();
        }
        let mut wake_at: Option<MonotonicNanos> = None;
        if let Some(active) = self.active.take() {
            match self.advance(active, &time) {
                super::dispatch::Advance::Continue(active) => {
                    self.active = Some(active);
                    worked = true;
                }
                super::dispatch::Advance::Wait(active, until) => {
                    self.active = Some(active);
                    wake_at = Some(until);
                }
                super::dispatch::Advance::Finished => worked = true,
            }
        }
        if self.active.is_none() && !self.waiting.is_empty() {
            worked = true;
        }
        if let Some(at) = self.held_reconciliation_at {
            wake_at = Some(wake_at.map_or(at, |wake| wake.min(at)));
        }
        Progress { worked, wake_at }
    }

    /// Claims one request of the journal queue and executes it. Returns
    /// true when a request was executed.
    ///
    /// A request that a pending reconciliation stopped is held and is
    /// executed again by a later call, before a new claim. A completion
    /// that the journal did not record is written again by a later call,
    /// before a new claim. Thus the coordinator holds at most one request
    /// and one completion.
    pub fn serve_queue(&mut self) -> bool {
        if let Some((request_id, completion)) = self.unwritten_completion.take() {
            // An error that is not a storage failure shows that the
            // request is not a claim of this lifetime, or that it has a
            // different result. A new write cannot change that.
            if let Err(error) = self
                .journal
                .complete_request(&request_id, &self.epoch, &completion)
                && error.is_storage_failure()
            {
                self.unwritten_completion = Some((request_id, completion));
                return false;
            }
        }
        // A request that cannot be executed now is not claimed. After
        // `stop_claims`, a request stays in the queue for the next
        // coordinator. A request that this lifetime claimed and holds is
        // not executed: the next coordinator puts it in the queue again.
        if self.reconciliation_pending || self.claims_stopped || self.pending_rearm.is_some() {
            return false;
        }
        let claimed: ClaimedRequest = match self.held_request.take() {
            Some(held) => held,
            None => match self.journal.claim_next_request(&self.epoch) {
                Ok(Some(claimed)) => claimed,
                Ok(None) | Err(_) => return false,
            },
        };
        let request_id = claimed.request.request_id.clone();
        let completion: RequestCompletion = match claimed.request.body.clone() {
            RequestBody::Apply { approval } => {
                let outcome: ApplyOutcome = self.apply(ApplyRequest {
                    approval,
                    principal: claimed.request.principal.clone(),
                    plan: None,
                    incident: None,
                });
                match outcome {
                    ApplyOutcome::Admitted { operation_id } => {
                        RequestCompletion::Operation { operation_id }
                    }
                    ApplyOutcome::Existing { operation } => RequestCompletion::Operation {
                        operation_id: operation.operation_id().clone(),
                    },
                    // A pending reconciliation is not a rejection of the
                    // request. The request stays claimed, and this
                    // lifetime executes it after the reconciliation.
                    ApplyOutcome::Refused { error }
                        if error.code.as_str() == code::RECONCILIATION_PENDING =>
                    {
                        self.held_request = Some(claimed);
                        return true;
                    }
                    ApplyOutcome::Refused { error } => RequestCompletion::Rejected { error },
                }
            }
            RequestBody::Cancel { operation_id } => {
                self.cancel_for(&operation_id, &claimed.request.principal)
            }
            RequestBody::Acknowledge { operation_id } => {
                match self.acknowledge(&operation_id, &claimed.request.principal) {
                    Ok(acknowledged) => RequestCompletion::Acknowledged {
                        acknowledged_at: acknowledged.acknowledgment.acknowledged_at,
                        repeated: acknowledged.repeated,
                    },
                    Err(error) => RequestCompletion::Rejected { error: *error },
                }
            }
            // The budget generation is state of the controller of the
            // agent. The agent takes the request with `take_rearm`; a
            // client coordinator has no controller.
            RequestBody::Rearm { .. } if self.config.role == CoordinatorRole::Agent => {
                self.pending_rearm = Some(claimed);
                return true;
            }
            RequestBody::Rearm { .. } => RequestCompletion::Rejected {
                error: super::error::rearm_rejection(
                    code::AGENT_NOT_RUNNING,
                    ErrorFamily::Evidence,
                ),
            },
        };
        self.record_completion(request_id, completion);
        true
    }

    /// Writes the completion of a claimed request. A completion that a
    /// storage failure stopped is written again before the next claim. If
    /// this lifetime ends first, a later lifetime gets the request again,
    /// and the journal then returns the operation of an apply.
    pub(super) fn record_completion(
        &mut self,
        request_id: RequestId,
        completion: RequestCompletion,
    ) {
        if let Err(error) = self
            .journal
            .complete_request(&request_id, &self.epoch, &completion)
            && error.is_storage_failure()
        {
            self.unwritten_completion = Some((request_id, completion));
        }
    }

    /// The user of the apply of an operation that this lifetime admitted.
    pub(super) fn applicant(&self, operation_id: &OperationId) -> Option<&Principal> {
        self.active
            .iter()
            .chain(self.waiting.iter())
            .chain(self.parked.values())
            .find(|active| active.operation.operation_id() == operation_id)
            .map(|active| &active.principal)
            .or_else(|| {
                self.plans
                    .values()
                    .find(|(known, _)| known == operation_id)
                    .map(|(_, principal)| principal)
            })
    }

    /// Executes a cancel request of the journal queue for `principal`.
    fn cancel_for(
        &mut self,
        operation_id: &OperationId,
        principal: &Principal,
    ) -> RequestCompletion {
        // A request of a different user does not stop the operation.
        if self
            .applicant(operation_id)
            .is_some_and(|applicant| applicant.uid != principal.uid)
        {
            return RequestCompletion::Rejected {
                error: action_error(
                    code::PRINCIPAL_MISMATCH,
                    ErrorFamily::Authority,
                    ActionStage::Admission,
                    None,
                    Some(operation_id),
                    None,
                ),
            };
        }
        match self.cancel(operation_id) {
            Ok(StopAcknowledgement::Received | StopAcknowledgement::CurrentInstance) => {
                RequestCompletion::Stopped {
                    fence: StopFence::CurrentInstance,
                }
            }
            // The result of a volatile operation is not in the durable
            // journal, so its stop is not reported as durable.
            Ok(StopAcknowledgement::Settled) if self.volatile.operation(operation_id).is_some() => {
                RequestCompletion::Stopped {
                    fence: StopFence::CurrentInstance,
                }
            }
            Ok(StopAcknowledgement::DurableFence | StopAcknowledgement::Settled) => {
                RequestCompletion::Stopped {
                    fence: StopFence::Durable,
                }
            }
            Err(error) => RequestCompletion::Rejected { error: *error },
        }
    }

    /// Calls [`Coordinator::step`] until the operation is finished or the
    /// monotonic time `give_up_at` of the caller comes. The end of the
    /// time cancels nothing: the operation stays admitted and continues
    /// with the later steps.
    pub fn run_until_finished(
        &mut self,
        operation_id: &OperationId,
        give_up_at: MonotonicNanos,
        idle: &mut dyn Idle,
    ) -> WaitOutcome {
        loop {
            let Some(view) = self.board.view(operation_id) else {
                return WaitOutcome::Unknown;
            };
            if view.phase == Phase::Finished {
                return WaitOutcome::Finished(Box::new(view));
            }
            let late: bool = self
                .clock
                .now()
                .is_none_or(|time| time.clock.now >= give_up_at);
            if late {
                return WaitOutcome::TimedOut(Box::new(view));
            }
            let progress: Progress = self.step();
            if !progress.worked {
                // With no wake time, the caller selects its idle interval.
                idle.idle(progress.wake_at.map(|wake_at| wake_at.min(give_up_at)));
            }
        }
    }

    /// Stops the claims of the request queue, for a coordinator that
    /// stops. After the call, [`Coordinator::serve_queue`] claims and
    /// executes no request: a queued request stays in the queue of the
    /// journal for the next coordinator. A completion that the journal
    /// did not record is still written. The call cannot be undone.
    pub const fn stop_claims(&mut self) {
        self.claims_stopped = true;
    }

    /// Gives the active operation and each waiting operation the stop
    /// request of [`Coordinator::cancel`], and returns their identities.
    ///
    /// A waiting operation is settled at once with no dispatch. The
    /// active operation ends its step in progress at its safe boundary
    /// in the later calls of [`Coordinator::step`], and no later step of
    /// it is dispatched. A parked operation is not in the result: it
    /// dispatches no further step.
    pub fn cancel_active(&mut self) -> Vec<OperationId> {
        let operations: Vec<OperationId> = self
            .active
            .iter()
            .chain(self.waiting.iter())
            .map(|active| active.operation.operation_id().clone())
            .collect();
        for operation_id in &operations {
            // The result of the stop request is in the view of the
            // operation.
            drop(self.cancel(operation_id));
        }
        operations
    }

    /// Whether a further call of [`Coordinator::step`] can settle or
    /// record work of this lifetime: an operation is active or waits, a
    /// settled operation has a record that the journal did not take, or
    /// the completion of a request is not written. An operation whose
    /// outcome is not known is not such work: no step of this lifetime
    /// settles it.
    pub fn has_work_in_progress(&self) -> bool {
        self.active.is_some()
            || !self.waiting.is_empty()
            || self.unwritten_completion.is_some()
            || self
                .parked
                .values()
                .any(|active| active.unrecorded && !active.volatile)
    }

    /// Stops the coordinator cleanly and releases its registration.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::Unsettled`] with no change when an
    /// operation of this lifetime is not settled, or when the journal
    /// did not take a record of the volatile history: the registration
    /// then stays, and the next lifetime reconciles and applies the
    /// conservative budget rule. Returns
    /// [`CoordinatorError::Journal`] when the journal does not record the
    /// release.
    pub fn shutdown(mut self) -> Result<J, (Box<Self>, CoordinatorError)> {
        if self.reconciliation_pending {
            self.reconcile();
        }
        if self.reconciliation_pending
            || self.active.is_some()
            || !self.waiting.is_empty()
            || !self.parked.is_empty()
        {
            return Err((Box::new(self), CoordinatorError::Unsettled));
        }
        if !self.volatile.pending_records().is_empty() {
            drop(self.journal.persist_volatile(&mut self.volatile));
        }
        // A volatile record that the journal does not have is lost with
        // this process. The registration then stays, so the next lifetime
        // starts as after an unclean stop and does not replenish a budget
        // from a journal that has no record of the volatile consumption.
        if !self.volatile.pending_records().is_empty() {
            return Err((Box::new(self), CoordinatorError::Unsettled));
        }
        match self.journal.end_coordination(&self.epoch) {
            Ok(()) => Ok(self.journal),
            Err(error) => Err((Box::new(self), CoordinatorError::Journal(error))),
        }
    }

    /// The application slots that an incident has left in this executor
    /// lifetime. `None` when the ledger has no record of the incident.
    pub fn remaining_slots(&self, incident_id: &svalnir_core::id::IncidentId) -> Option<u32> {
        self.ledger.remaining_slots(incident_id)
    }

    /// The end of the cooldown of an incident, when the ledger has one.
    pub fn cooldown_until(
        &self,
        incident_id: &svalnir_core::id::IncidentId,
    ) -> Option<MonotonicNanos> {
        self.ledger.cooldown_until(incident_id)
    }
}

/// Whether a call of an operation was, or possibly was, submitted.
pub(super) fn possibly_submitted(operation: &Operation) -> bool {
    !matches!(operation.dispatch(), DispatchState::NotSubmitted)
}
