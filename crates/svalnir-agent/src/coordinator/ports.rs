//! The interfaces that the coordinator needs from its environment.
//!
//! Each interface is a trait, so a test gives a temporary journal, a
//! controlled clock, synthetic measurements, and a synthetic process
//! backend. The production implementations are in this file also, where
//! one exists.

use std::fmt::Debug;

use svalnir_core::action::{ApplicationBinding, Journal, Plan, StopFence, TargetBinding};
use svalnir_core::file::FileObjectEvidence;
use svalnir_core::grant::{ActionRequest, Authorization, EvidenceStamp, IncidentBudget, Refusal};
use svalnir_core::id::{ExecutorEpochId, IncidentId, LeaseId, OperationId, RequestId, VolumeId};
use svalnir_core::observation::Observation;
use svalnir_core::plan::PlanMode;
use svalnir_core::policy::{EvaluationClock, ProtectionFact};
use svalnir_core::process::ProcessIdentity;
use svalnir_core::quantity::Bytes;
use svalnir_core::state::PressureState;
use svalnir_core::time::WallTime;

use crate::executor::fs::{AdmittedStep, ApprovedRoots, FsExecutor, StepOutcome};
use crate::executor::process::{
    ExecutorError, GenerationState, Observation as ExitObservation, ProcessControl,
    ProcessExecutor, StepClock, StepInput, StepRun, StopRequest,
};
use crate::journal::{
    ClaimedRequest, ConsumedDispatch, CoordinationStart, CoordinatorLock, OperationJournal,
    OperationJournalError, RecoveryRecord, RequestCompletion, VolatilePersistReport,
    VolatileRecord,
};
use crate::platform::process::ProcessSource;

/// One reading of the clocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeReading {
    /// The monotonic time with its clock domain and its boot.
    pub clock: EvaluationClock,
    /// The wall-clock time, for history records and grant expiry.
    pub wall: WallTime,
}

/// The clocks of the coordinator.
///
/// The coordinator never sleeps and reads no other clock, so a test moves
/// the time between two calls of
/// [`Coordinator::step`](super::Coordinator::step).
pub trait Clock: Debug {
    /// The current time. `None` when a clock gave no value: the
    /// coordinator then dispatches nothing.
    fn now(&self) -> Option<TimeReading>;
}

/// The revisions that are in effect now, for the comparison with the
/// revisions that a plan is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevisionSnapshot {
    /// The policy revision in effect. `None` before the first activation.
    pub policy_revision: Option<svalnir_core::id::PolicyRevisionId>,
    /// The current generation of each action grant that is in effect.
    pub action_grants: Vec<svalnir_core::authority::ActionGrantRef>,
    /// The rule revisions that the registry has now for the mode.
    pub rules: Vec<svalnir_core::rule::RuleRef>,
}

/// Whether the trigger of an automatic plan holds at a dispatch boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerStanding {
    /// The qualified predicate holds, with the newest measurement that
    /// supports it.
    Holds(EvidenceStamp),
    /// The predicate does not hold now. The incident can stay open.
    Cleared,
    /// No fresh evaluation exists. This permits no dispatch.
    Unknown,
}

/// The authority records and the policy facts that admission and each
/// dispatch boundary read.
///
/// The owner of the records (the controller and the agent runtime) changes
/// them between two calls; the coordinator reads them again at each
/// boundary and keeps no copy.
pub trait AuthoritySource: Debug {
    /// Asks [`svalnir_core::grant::authorize`] with the current records.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] of the grant module.
    fn authorize(
        &self,
        request: &ActionRequest<'_>,
        time: &TimeReading,
    ) -> Result<Authorization, Refusal>;

    /// The revisions in effect, for a plan of `mode`.
    fn revisions(&self, mode: PlanMode, time: &TimeReading) -> RevisionSnapshot;

    /// The budget record of an incident.
    fn incident(&self, incident_id: &IncidentId) -> Option<IncidentBudget>;

    /// Whether the trigger of an automatic plan holds now.
    fn trigger(&self, plan: &Plan, time: &TimeReading) -> TriggerStanding;

    /// The fact of the hard-protection catalog for the members of an
    /// application target, with the control plane of this process.
    fn protection(&self, binding: &ApplicationBinding) -> ProtectionFact;
}

/// The measurements of outcome verification.
///
/// A measurement that is not available is an unavailable observation. It
/// is never zero.
pub trait Measurements: Debug {
    /// The available capacity of a volume.
    fn capacity(&mut self, volume: &VolumeId) -> Observation<Bytes>;

    /// The memory pressure of the host.
    fn memory_pressure(&mut self) -> Observation<PressureState>;
}

/// The identities that the coordinator makes.
pub trait IdSource: Debug {
    /// A new operation identity. Each call gives a different value.
    fn operation_id(&mut self) -> Option<OperationId>;

    /// A new lease identity. Each call gives a different value.
    fn lease_id(&mut self) -> Option<LeaseId>;
}

/// The filesystem executor, as the coordinator calls it.
pub trait FilesystemExecutor: Debug {
    /// Does one admitted step under `roots`.
    ///
    /// # Errors
    ///
    /// Returns the fault of the executor: it finished the work on the
    /// target and made no consistent target result.
    fn execute(&self, roots: &ApprovedRoots, step: AdmittedStep<'_>) -> StepOutcome;
}

impl FilesystemExecutor for FsExecutor {
    fn execute(&self, roots: &ApprovedRoots, step: AdmittedStep<'_>) -> StepOutcome {
        self.execute_step(roots, step)
    }
}

/// The process executor, as the coordinator calls it. Neither function
/// waits.
pub trait ApplicationExecutor: Debug {
    /// Starts one step.
    ///
    /// # Errors
    ///
    /// Returns the [`ExecutorError`] of the executor. No call was issued.
    fn begin(&self, input: StepInput<'_>) -> Result<StepRun, ExecutorError>;

    /// Reads the members of an observation one time.
    ///
    /// # Errors
    ///
    /// Returns the [`ExecutorError`] of the executor.
    fn poll(
        &self,
        observation: Box<ExitObservation>,
        stop: Option<StopRequest>,
    ) -> Result<StepRun, ExecutorError>;
}

impl<S, C, K> ApplicationExecutor for ProcessExecutor<S, C, K>
where
    S: ProcessSource + Debug,
    C: ProcessControl + Debug,
    K: StepClock + Debug,
{
    fn begin(&self, input: StepInput<'_>) -> Result<StepRun, ExecutorError> {
        ProcessExecutor::begin(self, input)
    }

    fn poll(
        &self,
        observation: Box<ExitObservation>,
        stop: Option<StopRequest>,
    ) -> Result<StepRun, ExecutorError> {
        observation.poll(self, stop)
    }
}

/// What a fresh reading shows about a planned file object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileProbe {
    /// The name has no entry.
    Absent,
    /// The name has the planned object.
    PlannedObject,
    /// The name has a different object, or the plan has no identity to
    /// compare. A different object is a different target.
    OtherObject,
    /// The reading failed. It supports no conclusion.
    Unknown,
}

/// The fresh evidence of restart reconciliation. Each function only
/// reads.
pub trait TargetProbe: Debug {
    /// Reads the entry of a file target.
    fn file(&self, target: &TargetBinding) -> FileProbe;

    /// Reads one planned process generation.
    fn process(&self, planned: &ProcessIdentity) -> GenerationState;
}

/// The probe of the running system: `lstat` on the approved root, on each
/// directory below it, and on the entry of a file target, and the
/// process source of the collector for a process generation. The probe
/// reads by path: it is evidence for a record, and no action follows it.
#[derive(Debug)]
pub struct SystemProbe<S> {
    roots: ApprovedRoots,
    source: S,
}

impl<S: ProcessSource + Debug> SystemProbe<S> {
    /// Makes the probe for the approved roots and a process source.
    pub const fn new(roots: ApprovedRoots, source: S) -> Self {
        Self { roots, source }
    }
}

impl<S: ProcessSource + Debug> TargetProbe for SystemProbe<S> {
    fn file(&self, target: &TargetBinding) -> FileProbe {
        use std::os::unix::fs::MetadataExt;

        let TargetBinding::File(file) = target else {
            return FileProbe::Unknown;
        };
        let Some(root) = self.roots.root(&file.root_id) else {
            return FileProbe::Unknown;
        };
        // `st_dev` is a signed number, and the standard library gives it
        // with its sign extended.
        let is_object = |metadata: &std::fs::Metadata, object: &FileObjectEvidence| {
            u64::from_ne_bytes(i64::from(object.device.get()).to_ne_bytes()) == metadata.dev()
                && object.inode.get() == metadata.ino()
        };
        // The root must be the approved directory. A root that is absent
        // (a volume that is not mounted) or replaced gives no conclusion
        // about an entry below it.
        let mut path = root.path.to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && is_object(&metadata, &root.object) => {}
            _ => return FileProbe::Unknown,
        }
        // Each directory between the root and the entry must be a
        // directory and not a symbolic link: a link can lead to a place
        // where the name is absent.
        let relative = file.relative_entry.to_path_buf();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            path.push(component);
            if components.peek().is_none() {
                break;
            }
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return FileProbe::Absent;
                }
                Ok(_) | Err(_) => return FileProbe::Unknown,
            }
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => match &file.object {
                Some(object) if is_object(&metadata, object) => FileProbe::PlannedObject,
                _ => FileProbe::OtherObject,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => FileProbe::Absent,
            Err(_) => FileProbe::Unknown,
        }
    }

    fn process(&self, planned: &ProcessIdentity) -> GenerationState {
        use crate::platform::process::QueryFailure;

        match self.source.process_info(planned.pid) {
            Err(QueryFailure::Gone) => GenerationState::Exited,
            Err(failure) => GenerationState::Unknown(failure),
            Ok(info) if info.pid != planned.pid => {
                GenerationState::Unknown(QueryFailure::Inconsistent)
            }
            Ok(info) if info.start_time != planned.start_time => GenerationState::Replaced,
            Ok(info) if info.zombie => GenerationState::Exited,
            Ok(_) => GenerationState::Running,
        }
    }
}

/// The operation journal with the coordination, queue, and recovery
/// functions that the coordinator calls.
///
/// [`OperationJournal`] is the implementation. A test wraps it to make a
/// write fail at a selected point.
pub trait CoordinatorJournal: Journal {
    /// Registers this coordinator. See
    /// [`OperationJournal::begin_coordination`].
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn begin_coordination(
        &mut self,
        lock: &CoordinatorLock,
        epoch: &ExecutorEpochId,
        started_at: WallTime,
    ) -> Result<CoordinationStart, OperationJournalError>;

    /// Ends a pending reconciliation.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn complete_reconciliation(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<(), OperationJournalError>;

    /// Releases the registration at a clean stop.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn end_coordination(&mut self, epoch: &ExecutorEpochId) -> Result<(), OperationJournalError>;

    /// The number of operations that are not settled.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn unsettled_operation_count(&self) -> Result<u64, OperationJournalError>;

    /// The operations that are not settled, with their recovery evidence.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn recovery_records(&self, limit: usize) -> Result<Vec<RecoveryRecord>, OperationJournalError>;

    /// The consumed dispatches of an incident.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn consumed_dispatches(
        &self,
        incident_id: &IncidentId,
        limit: usize,
    ) -> Result<Vec<ConsumedDispatch>, OperationJournalError>;

    /// Claims the oldest queued request.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn claim_next_request(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<Option<ClaimedRequest>, OperationJournalError>;

    /// Completes a claimed request.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn complete_request(
        &mut self,
        request_id: &RequestId,
        epoch: &ExecutorEpochId,
        completion: &RequestCompletion,
    ) -> Result<(), OperationJournalError>;

    /// Writes the pending records of the volatile record to this journal.
    ///
    /// # Errors
    ///
    /// Returns the error of the journal.
    fn persist_volatile(
        &mut self,
        record: &mut VolatileRecord,
    ) -> Result<VolatilePersistReport, OperationJournalError>;

    /// Writes the stop fence of an operation. The result says whether the
    /// fence is durable or is a stop of this instance only.
    fn stop_fence(&mut self, operation_id: &OperationId) -> StopFence {
        match self.set_stop_fence(operation_id) {
            Ok(()) => StopFence::Durable,
            Err(_) => StopFence::CurrentInstance,
        }
    }
}

impl CoordinatorJournal for OperationJournal {
    fn begin_coordination(
        &mut self,
        lock: &CoordinatorLock,
        epoch: &ExecutorEpochId,
        started_at: WallTime,
    ) -> Result<CoordinationStart, OperationJournalError> {
        Self::begin_coordination(self, lock, epoch, started_at)
    }

    fn complete_reconciliation(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<(), OperationJournalError> {
        Self::complete_reconciliation(self, epoch)
    }

    fn end_coordination(&mut self, epoch: &ExecutorEpochId) -> Result<(), OperationJournalError> {
        Self::end_coordination(self, epoch)
    }

    fn unsettled_operation_count(&self) -> Result<u64, OperationJournalError> {
        Self::unsettled_operation_count(self)
    }

    fn recovery_records(&self, limit: usize) -> Result<Vec<RecoveryRecord>, OperationJournalError> {
        Self::recovery_records(self, limit)
    }

    fn consumed_dispatches(
        &self,
        incident_id: &IncidentId,
        limit: usize,
    ) -> Result<Vec<ConsumedDispatch>, OperationJournalError> {
        Self::consumed_dispatches(self, incident_id, limit)
    }

    fn claim_next_request(
        &mut self,
        epoch: &ExecutorEpochId,
    ) -> Result<Option<ClaimedRequest>, OperationJournalError> {
        Self::claim_next_request(self, epoch)
    }

    fn complete_request(
        &mut self,
        request_id: &RequestId,
        epoch: &ExecutorEpochId,
        completion: &RequestCompletion,
    ) -> Result<(), OperationJournalError> {
        Self::complete_request(self, request_id, epoch, completion)
    }

    fn persist_volatile(
        &mut self,
        record: &mut VolatileRecord,
    ) -> Result<VolatilePersistReport, OperationJournalError> {
        record.persist_into(self)
    }
}
