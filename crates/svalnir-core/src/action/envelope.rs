//! The immutable request envelope of one step.
//!
//! `docs/ACTION_CONTRACTS.md` section 3 owns the envelope. The coordinator
//! makes it from the stored plan and the admitted operation and gives it
//! to an executor. A client never makes one: a client submits a
//! [`PlanApproval`](super::plan::PlanApproval).
//!
//! [`RequestEnvelope`] is the checked form. It has no mutable access.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::budget::{LeaseResource, ResourceLease, WorkCharge};
use super::checked::{Check, Checked};
use super::class::ActionClass;
use super::journal::critical_exception_applies;
use super::plan::{
    ClientRole, Escalation, ExecutorRole, PLAN_SCHEMA_VERSION, PlanError, PlanTarget, Principal,
    TargetBinding, Trigger, check_application_binding, check_file_binding,
    check_trigger_identities, step_agrees_with_escalation,
};
use crate::authority::AuthorityBinding;
use crate::digest::ContentDigest;
use crate::encoding::wire_enum;
use crate::id::{
    AdapterId, BootId, ClockDomainId, ExecutorEpochId, IncidentId, OperationId, PlanId, StepId,
};
use crate::quantity::Nanoseconds;
use crate::time::MonotonicNanos;

wire_enum! {
    /// The recording that a step needs before its external call.
    RecordingMode {
        /// Durable intent and durable dispatch consumption.
        Durable => "durable",
        /// The critical-memory exception: intent and dispatch consumption
        /// together in bounded volatile state. Admission permitted it
        /// explicitly.
        VolatileCriticalException => "volatile_critical_exception",
    }
}

/// The identities of the request and of its parent records.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    /// The plan.
    pub plan_id: PlanId,
    /// The digest of the plan.
    pub plan_digest: ContentDigest,
    /// The operation.
    pub operation_id: OperationId,
    /// The step.
    pub step_id: StepId,
    /// The operation of the agent, when the helper does this step.
    pub parent_operation_id: Option<OperationId>,
}

/// The provenance and the validity limits of the evidence of the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBinding {
    /// The clock domain of the monotonic times of the request.
    pub clock_domain: ClockDomainId,
    /// The boot of the evidence.
    pub boot_id: BootId,
    /// The executor lifetime that made the request. An executor of a
    /// later lifetime does not execute the request.
    pub executor_epoch: ExecutorEpochId,
    /// The monotonic time of the latest validation of the target.
    pub observed_at: MonotonicNanos,
    /// The monotonic time after which the evidence is not valid.
    pub valid_until: MonotonicNanos,
}

/// The budget that the admission reserved for the step.
///
/// JSON encodes the value as an object with a `kind` field. An unknown
/// `kind` is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reservation {
    /// The charge of one filesystem unit.
    Work {
        /// The reserved charge.
        charge: WorkCharge,
    },
    /// One application slot. A graceful step and its force step have the
    /// same slot.
    ApplicationSlot {
        /// The memory incident of the slot. A manual operation has none:
        /// it uses its own one-shot limit.
        incident_id: Option<IncidentId>,
    },
}

/// The limits of one step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepLimits {
    /// The reserved budget.
    pub reservation: Reservation,
    /// The monotonic time after which the step is not submitted.
    pub deadline: MonotonicNanos,
    /// The grace period that follows a graceful request.
    pub grace: Option<Nanoseconds>,
    /// The time for which the outcome is observed.
    pub verification_window: Nanoseconds,
    /// The force strategy of the plan.
    pub escalation: Escalation,
}

/// The content of a request envelope. [`RequestEnvelope`] is the checked
/// form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeContent {
    /// The schema version: [`PLAN_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The action class of the step.
    pub action_class: ActionClass,
    /// The adapter that does the step. The rule revision of a file target
    /// is in the target binding.
    pub adapter: AdapterId,
    /// The identities of the request.
    pub correlation: Correlation,
    /// The authenticated user and client.
    pub principal: Principal,
    /// The executor that does the step.
    pub executor: ExecutorRole,
    /// The policy revision and the grant generations.
    pub authority: AuthorityBinding,
    /// The trigger of the plan.
    pub trigger: Trigger,
    /// The verified target.
    pub target: PlanTarget,
    /// The provenance and the validity limits of the evidence.
    pub evidence: EvidenceBinding,
    /// The limits.
    pub limits: StepLimits,
    /// The leases that the operation holds for the step.
    pub leases: Vec<ResourceLease>,
    /// The recording that the step needs.
    pub recording: RecordingMode,
}

/// A request envelope whose fields agree with each other.
pub type RequestEnvelope = Checked<EnvelopeContent>;

/// The reason an envelope content was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// The schema version is not the version of this build.
    #[error("the schema version of the envelope is not supported")]
    SchemaVersion,
    /// A value of the envelope is one that this build does not recognize.
    #[error("the envelope has a value that this build does not recognize")]
    Unrecognized,
    /// The trigger cannot select the action class, or the trigger
    /// identities do not agree with the trigger class.
    #[error("the trigger does not agree with the action class")]
    Trigger,
    /// The action class does not agree with the force strategy or the
    /// grace period.
    #[error("the action class does not agree with the force strategy")]
    Escalation,
    /// The target or the reservation is not of the kind of the action
    /// class, the binding of the target does not agree with the
    /// principal or with its own evidence, or the slot is not a slot of
    /// the incident of the trigger.
    #[error("the target or the reservation does not agree with the action class")]
    Target,
    /// The privilege grant does not agree with the executor, or an
    /// automatic request names no action grant.
    #[error("the privilege grant does not agree with the executor")]
    Authority,
    /// The evidence is not valid at the time of its observation.
    #[error("the validity of the evidence is empty")]
    Evidence,
    /// The step has no lease, a lease has a different owner or executor
    /// lifetime, or no lease is for the conflict domain of the target.
    #[error("the leases do not agree with the operation")]
    Lease,
    /// Volatile recording is not permitted for the action class and the
    /// trigger.
    #[error("volatile recording is not permitted for the request")]
    Recording,
}

impl Check for EnvelopeContent {
    type Error = EnvelopeError;

    fn check(&self) -> Result<(), EnvelopeError> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            return Err(EnvelopeError::SchemaVersion);
        }
        let recognized: bool = self.action_class.is_recognized()
            && self.trigger.class.is_recognized()
            && self.principal.role.is_recognized()
            && self.executor.is_recognized()
            && self.limits.escalation.is_recognized()
            && self.recording.is_recognized();
        if !recognized {
            return Err(EnvelopeError::Unrecognized);
        }
        check_trigger_identities(&self.trigger).map_err(|_| EnvelopeError::Trigger)?;
        if !self.action_class.accepts_trigger(&self.trigger.class) {
            return Err(EnvelopeError::Trigger);
        }
        // The checks of the plan for an automatic trigger: the agent is the
        // client, and the plan names an action grant.
        if self.trigger.class.is_automatic() {
            if !matches!(self.principal.role, ClientRole::Agent) {
                return Err(EnvelopeError::Trigger);
            }
            if self.authority.action_grants.is_empty() {
                return Err(EnvelopeError::Authority);
            }
        }
        if !step_agrees_with_escalation(
            &self.action_class,
            &self.limits.escalation,
            self.limits.grace,
        ) {
            return Err(EnvelopeError::Escalation);
        }
        // The same binding rules as the plan: an envelope has its own copy
        // of the target.
        let uid = self.principal.uid;
        let binding_error = |error: PlanError| match error {
            PlanError::Unrecognized => EnvelopeError::Unrecognized,
            _ => EnvelopeError::Target,
        };
        let target_agrees: bool = match (&self.target.binding, &self.limits.reservation) {
            (TargetBinding::File(file), Reservation::Work { charge }) => {
                check_file_binding(&self.action_class, file, uid, &self.executor)
                    .map_err(binding_error)?;
                charge == &file.charge
            }
            (
                TargetBinding::Application(application),
                Reservation::ApplicationSlot { incident_id },
            ) => {
                check_application_binding(application, uid, &self.executor)
                    .map_err(binding_error)?;
                // A manual operation has no incident, and an automatic slot
                // is a slot of the incident of the trigger.
                self.action_class.is_application_intervention()
                    && incident_id == &self.trigger.incident_id
            }
            _ => false,
        };
        if !target_agrees {
            return Err(EnvelopeError::Target);
        }
        let is_helper: bool = matches!(self.executor, ExecutorRole::Helper);
        if self.authority.privilege_grant.is_some() != is_helper {
            return Err(EnvelopeError::Authority);
        }
        if self.evidence.observed_at >= self.evidence.valid_until {
            return Err(EnvelopeError::Evidence);
        }
        let lease_agrees = |lease: &ResourceLease| {
            lease.owner == self.correlation.operation_id
                && lease.executor_epoch == self.evidence.executor_epoch
        };
        if self.leases.is_empty() || !self.leases.iter().all(lease_agrees) {
            return Err(EnvelopeError::Lease);
        }
        // A lease is for the conflict domain of the target: the cleanup
        // root of a file target, or a member generation of an application
        // target. A lease on a different domain coordinates nothing for
        // this step.
        //
        // TODO(npochaev): require a lease for each member generation. The
        // coordinator acquires one for each member; the envelope fixtures
        // of the process executor and of the journal have one for the
        // first member only.
        let holds =
            |resource: &LeaseResource| self.leases.iter().any(|lease| &lease.resource == resource);
        let domain_held: bool = match &self.target.binding {
            TargetBinding::File(file) => holds(&LeaseResource::CleanupRoot(file.root_id.clone())),
            TargetBinding::Application(application) => application.members.iter().any(|member| {
                holds(&LeaseResource::ProcessGeneration(
                    member.generation_id.clone(),
                ))
            }),
        };
        if !domain_held {
            return Err(EnvelopeError::Lease);
        }
        if matches!(self.recording, RecordingMode::VolatileCriticalException)
            && !critical_exception_applies(&self.action_class, &self.trigger.class)
        {
            return Err(EnvelopeError::Recording);
        }
        Ok(())
    }
}
