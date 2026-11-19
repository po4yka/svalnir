//! The errors of the coordinator and the stable codes of its refusals.

use svalnir_core::action::{ActionError, ActionStage, DispatchState, ErrorCode, ErrorFamily};
use svalnir_core::id::{OperationId, PlanId, StepId};
use thiserror::Error;

use crate::journal::{CoordinatorLockError, OperationJournalError};

/// The error codes that the coordinator makes. A refusal of the grant
/// module has the code of its
/// [`RefusalReason`](svalnir_core::grant::RefusalReason), and a refusal of
/// the apply checks of the plan module has a code of this list.
pub mod code {
    /// The journal has no plan with the identity.
    pub const PLAN_NOT_FOUND: &str = "plan_not_found";
    /// The approval names a different plan or a different digest.
    pub const APPROVAL_MISMATCH: &str = "approval_mismatch";
    /// The plan is expired, or its clock is not the current clock.
    pub const PLAN_EXPIRED: &str = "plan_expired";
    /// The plan was consumed with different content or by a different
    /// principal.
    pub const PLAN_CONFLICT: &str = "plan_conflict";
    /// The consumption record of the plan is older than the retention.
    pub const PLAN_CONSUMPTION_EXPIRED: &str = "plan_consumption_expired";
    /// The plan has a content that the coordinator cannot execute.
    pub const PLAN_NOT_EXECUTABLE: &str = "plan_not_executable";
    /// The policy revision of the plan is not the one in effect.
    pub const POLICY_REVISION_CHANGED: &str = "policy_revision_changed";
    /// An action grant of the plan is not in effect with its generation.
    pub const ACTION_GRANT_CHANGED: &str = "action_grant_changed";
    /// The privilege grant of the plan is not in effect.
    pub const PRIVILEGE_GRANT_CHANGED: &str = "privilege_grant_changed";
    /// A rule revision of the plan is not registered for the mode.
    pub const RULE_REVISION_CHANGED: &str = "rule_revision_changed";
    /// The plan needs the privileged helper, which Milestone 2 does not
    /// call.
    pub const HELPER_NOT_AVAILABLE: &str = "helper_not_available";
    /// An allowance has no room for the charge of the plan.
    pub const BUDGET_EXHAUSTED: &str = "budget_exhausted";
    /// The incident of the plan has no allowance record.
    pub const INCIDENT_ALLOWANCE_MISSING: &str = "incident_allowance_missing";
    /// The allowance of the incident is of a different budget generation
    /// than the plan.
    pub const INCIDENT_MISMATCH: &str = "incident_mismatch";
    /// A cooldown or a backoff of the incident is in force.
    pub const COOLDOWN_ACTIVE: &str = "cooldown_active";
    /// A different operation holds a lease on a resource of the plan.
    pub const LEASE_UNAVAILABLE: &str = "lease_unavailable";
    /// The lease of the operation expired.
    pub const LEASE_EXPIRED: &str = "lease_expired";
    /// The number of admitted operations that wait is at its limit.
    pub const QUEUE_FULL: &str = "queue_full";
    /// A clock gave no value.
    pub const CLOCK_UNAVAILABLE: &str = "clock_unavailable";
    /// The journal did not record the admission.
    pub const ADMISSION_NOT_RECORDED: &str = "admission_not_recorded";
    /// The journal did not record the intent of the step.
    pub const INTENT_NOT_RECORDED: &str = "intent_not_recorded";
    /// The journal did not record the dispatch consumption of the step.
    pub const DISPATCH_NOT_RECORDED: &str = "dispatch_not_recorded";
    /// A different caller consumed the dispatch of the step.
    pub const DISPATCH_CONSUMED_ELSEWHERE: &str = "dispatch_consumed_elsewhere";
    /// The bounded volatile record is full or refused the step.
    pub const VOLATILE_RECORD_REFUSED: &str = "volatile_record_refused";
    /// The trigger of the automatic plan does not hold now.
    pub const TRIGGER_NOT_CURRENT: &str = "trigger_not_current";
    /// The hard protection of the target is not `NotProtected`.
    pub const TARGET_PROTECTED: &str = "target_protected";
    /// The catalog of protected file locations gave no fact for a file
    /// target: a location of the user or of the control plane is not
    /// known, or the entry did not resolve.
    pub const TARGET_PROTECTION_UNKNOWN: &str = "target_protection_unknown";
    /// The producer of the data of an eviction target is active at the
    /// fresh check before the step. The target is skipped with no call.
    pub const PRODUCER_ACTIVE: &str = "producer_active";
    /// The fresh check before an eviction step gave no evidence that the
    /// producer of the data is inactive. The target is skipped with no
    /// call.
    pub const PRODUCER_ACTIVITY_UNKNOWN: &str = "producer_activity_unknown";
    /// The executor refused the step before a call.
    pub const EXECUTOR_REFUSED_STEP: &str = "executor_refused_step";
    /// The executor made no consistent result.
    pub const EXECUTOR_FAULT: &str = "executor_fault";
    /// The graceful step has no submission time, so the grace period is
    /// not established.
    pub const GRACE_NOT_ESTABLISHED: &str = "grace_not_established";
    /// The graceful step left no member that a force step can act on.
    pub const FORCE_NOT_APPLICABLE: &str = "force_not_applicable";
    /// The effect of an earlier step is not known.
    pub const RECONCILE_BEFORE_FORCE: &str = "reconcile_before_force";
    /// The executor lifetime of the operation ended before the step.
    pub const EXECUTOR_RESTARTED: &str = "executor_restarted";
    /// The evidence after a restart does not establish the effect.
    pub const EFFECT_NOT_ESTABLISHED: &str = "effect_not_established";
    /// The object is at its name after a submitted call.
    pub const OBJECT_STILL_PRESENT: &str = "object_still_present";
    /// The coordinator has no operation with the identity.
    pub const OPERATION_NOT_FOUND: &str = "operation_not_found";
    /// The request is of a different user than the apply of the
    /// operation.
    pub const PRINCIPAL_MISMATCH: &str = "principal_mismatch";
    /// The coordinator made no new identity.
    pub const IDENTITY_UNAVAILABLE: &str = "identity_unavailable";
    /// A reconciliation is pending and is not complete.
    pub const RECONCILIATION_PENDING: &str = "reconciliation_pending";
    /// An acknowledgment names an operation that is not `UnknownOutcome`.
    pub const OPERATION_NOT_UNKNOWN_OUTCOME: &str = "operation_not_unknown_outcome";
    /// The journal did not record the acknowledgment.
    pub const ACKNOWLEDGMENT_NOT_RECORDED: &str = "acknowledgment_not_recorded";
    /// A rearm request reached a coordinator that is not an agent: only
    /// the controller of the agent has the budget generation of an
    /// incident.
    pub const AGENT_NOT_RUNNING: &str = "agent_not_running";
    /// The journal did not record the controller state with the new
    /// budget generation, so the rearm is not in effect.
    pub const REARM_NOT_RECORDED: &str = "rearm_not_recorded";
}

/// The rejection of a queued rearm request, for
/// [`super::Coordinator::complete_rearm`]. It names no plan and no
/// operation.
pub fn rearm_rejection(code: &str, family: ErrorFamily) -> ActionError {
    action_error(code, family, ActionStage::Admission, None, None, None)
}

/// The reason the coordinator did not start.
#[derive(Debug, Error)]
pub enum StartError {
    /// The lock file cannot be opened or locked.
    #[error("the coordinator lock cannot be taken")]
    Lock(#[source] std::io::Error),
    /// The journal refused the registration.
    #[error("the journal refused the registration of the coordinator")]
    Journal(#[source] OperationJournalError),
    /// A clock gave no value.
    #[error("a clock gave no value")]
    Clock,
}

impl From<CoordinatorLockError> for StartError {
    fn from(error: CoordinatorLockError) -> Self {
        match error {
            // The caller of `start` handles a held lock before this
            // conversion; a held lock here is reported as a lock error.
            CoordinatorLockError::Held => {
                Self::Lock(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            CoordinatorLockError::Io(source) => Self::Lock(source),
        }
    }
}

/// An error of a call of the coordinator that is not a refusal of the
/// action contract.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// The journal failed.
    #[error("the operation journal failed")]
    Journal(#[source] OperationJournalError),
    /// The journal failed, as the journal contract reports it.
    #[error("the operation journal failed: {0}")]
    Record(#[source] svalnir_core::action::JournalError),
    /// The coordinator has an operation that is not settled, so it does
    /// not release its registration.
    #[error("an operation is not settled")]
    Unsettled,
}

/// Makes an error record with the dispatch state `not_submitted`.
///
/// Each code of [`code`] is an accepted code. A code that is not accepted
/// gives the code `invalid_error_code`, so the function has no error.
pub(super) fn action_error(
    code: &str,
    family: ErrorFamily,
    stage: ActionStage,
    plan_id: Option<&PlanId>,
    operation_id: Option<&OperationId>,
    step_id: Option<&StepId>,
) -> ActionError {
    action_error_with(
        code,
        family,
        stage,
        DispatchState::NotSubmitted,
        plan_id,
        operation_id,
        step_id,
    )
}

/// Makes an error record with a stated dispatch state.
pub(super) fn action_error_with(
    code: &str,
    family: ErrorFamily,
    stage: ActionStage,
    dispatch: DispatchState,
    plan_id: Option<&PlanId>,
    operation_id: Option<&OperationId>,
    step_id: Option<&StepId>,
) -> ActionError {
    let code: ErrorCode = ErrorCode::new(code)
        .or_else(|_| ErrorCode::new("invalid_error_code"))
        .unwrap_or_else(|_| fallback_code());
    ActionError {
        code,
        family,
        stage,
        dispatch,
        plan_id: plan_id.cloned(),
        operation_id: operation_id.cloned(),
        step_id: step_id.cloned(),
    }
}

/// A code for the case that no text is an accepted code. `ErrorCode::new`
/// accepts each lower-case text, so the loop ends at its first value.
fn fallback_code() -> ErrorCode {
    let mut text = String::from("e");
    loop {
        if let Ok(code) = ErrorCode::new(text.clone()) {
            return code;
        }
        text.push('e');
    }
}
