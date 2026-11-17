//! The target results of the process executor and its error codes.
//!
//! Each function makes the fields of one result for one member. The fields
//! agree with the rules of `docs/ACTION_CONTRACTS.md` section 9, and
//! [`svalnir_core::action::Checked`] checks them again.

use svalnir_core::action::{
    ActionError, ActionStage, Attribution, Checked, DispatchConsumption, DispatchState, Durability,
    EffectEvidence, ErrorCode, ErrorCodeError, ErrorFamily, NativeResult, OutcomeError,
    RecordingRefusal, RequestEnvelope, StopReason, TargetEffect, TargetResult, TargetResultRecord,
};
use svalnir_core::id::{
    AdapterId, IdError, OperationId, PlanId, ProcessGenerationId, StepId, TargetId,
};
use svalnir_core::time::WallTime;
use thiserror::Error;

use crate::platform::process::ADAPTER_ID;

/// The reason the executor did not start a step, or could not make a
/// result record. No external call was issued when `begin` returns one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecutorError {
    /// The step is not an application intervention on an application
    /// target for the user executor.
    #[error("the step is not an application intervention on an application target")]
    NotApplicationStep,
    /// The dispatch receipt is not the receipt of a consumption by this
    /// caller. The caller queries the state of the step; it does not submit
    /// a call.
    #[error("the dispatch receipt does not permit a submission: {0:?}")]
    DispatchNotConsumed(DispatchConsumption),
    /// The record of the intent and of the dispatch consumption does not
    /// permit the external call.
    #[error("the recording of the step does not permit a submission")]
    Recording(#[source] RecordingRefusal),
    /// A force step of the strategy `force_after_grace` has no record of
    /// its graceful step, or a different step has one.
    #[error("the record of the graceful step does not agree with the step")]
    GracefulRecord,
    /// A member of the target has no result at the end of the step. This
    /// is a defect of the executor.
    #[error("a member of the target has no result")]
    MemberNotSettled,
    /// A result record does not agree with itself. This is a defect of the
    /// executor.
    #[error("a target result does not agree with itself")]
    Record(#[source] OutcomeError),
    /// An error code is not valid. This is a defect of the executor.
    #[error("an error code of the executor is not valid")]
    Code(#[source] ErrorCodeError),
    /// The adapter identity is not valid. This is a defect of the executor.
    #[error("the adapter identity of the executor is not valid")]
    Adapter(#[source] IdError),
}

/// The error of a skipped, refused, or failed member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Failure {
    pub(super) code: &'static str,
    pub(super) family: ErrorFamily,
    pub(super) stage: ActionStage,
}

impl Failure {
    /// A changed or absent item of the target evidence.
    pub(super) const fn evidence(code: &'static str) -> Self {
        Self {
            code,
            family: ErrorFamily::Evidence,
            stage: ActionStage::Dispatch,
        }
    }

    /// A target that the executor does not act on.
    pub(super) const fn eligibility(code: &'static str) -> Self {
        Self {
            code,
            family: ErrorFamily::Eligibility,
            stage: ActionStage::Dispatch,
        }
    }

    /// A limit of the step.
    pub(super) const fn limits(code: &'static str) -> Self {
        Self {
            code,
            family: ErrorFamily::Limits,
            stage: ActionStage::Dispatch,
        }
    }

    /// A refusal or a failure of the native call.
    pub(super) const fn native(code: &'static str) -> Self {
        Self {
            code,
            family: ErrorFamily::Native,
            stage: ActionStage::Execution,
        }
    }

    /// An effect that the observation cannot establish.
    pub(super) const fn outcome(code: &'static str) -> Self {
        Self {
            code,
            family: ErrorFamily::Outcome,
            stage: ActionStage::Verification,
        }
    }
}

/// The error codes of the process executor.
pub mod code {
    /// The PID belongs to a process generation that is not the planned one.
    pub const PROCESS_REPLACED: &str = "process_replaced";
    /// The effective or the real user of the process is not the planned
    /// owner.
    pub const PROCESS_OWNER_CHANGED: &str = "process_owner_changed";
    /// The executable of the process is not the planned one.
    pub const PROCESS_EXECUTABLE_CHANGED: &str = "process_executable_changed";
    /// The plan or the fresh reading has no executable evidence, or one has
    /// an item that the other does not have.
    pub const PROCESS_EVIDENCE_MISSING: &str = "process_evidence_missing";
    /// The identity query failed.
    pub const PROCESS_QUERY_FAILED: &str = "process_query_failed";
    /// The identity query was denied.
    pub const PROCESS_QUERY_DENIED: &str = "process_query_denied";
    /// The member has no verified membership of a kind that this build
    /// knows.
    pub const MEMBERSHIP_NOT_VERIFIED: &str = "membership_not_verified";
    /// The boot, the clock domain, or the executor lifetime of the evidence
    /// is not that of the executor.
    pub const EXECUTOR_CONTEXT_CHANGED: &str = "executor_context_changed";
    /// The evidence of the request is not valid at this time.
    pub const EVIDENCE_EXPIRED: &str = "evidence_expired";
    /// The clock gave no value.
    pub const CLOCK_UNAVAILABLE: &str = "clock_unavailable";
    /// Launch Services has no running application with the PID.
    pub const APPLICATION_NOT_REGISTERED: &str = "application_not_registered";
    /// The registered application of the PID is not the planned one.
    pub const APPLICATION_IDENTITY_MISMATCH: &str = "application_identity_mismatch";
    /// The registered application reports that it terminated, and the
    /// process exists.
    pub const APPLICATION_TERMINATED: &str = "application_terminated";
    /// The hard-protection catalog, or a check of the executor, protects
    /// the target.
    pub const TARGET_PROTECTED: &str = "target_protected";
    /// The hard protection of the target is not known.
    pub const TARGET_PROTECTION_UNKNOWN: &str = "target_protection_unknown";
    /// A member is the executor or its parent.
    pub const TARGET_IS_CONTROL_PLANE: &str = "target_is_control_plane";
    /// A member, or the principal, is not the user of the executor, or is
    /// root.
    pub const TARGET_OTHER_USER: &str = "target_other_user";
    /// The executor cannot establish its own process or its parent.
    pub const CONTROL_PLANE_UNKNOWN: &str = "control_plane_unknown";
    /// The graceful step submitted no request for the member, so the force
    /// step does not act on it.
    pub const GRACEFUL_REQUEST_NOT_SUBMITTED: &str = "graceful_request_not_submitted";
    /// No request was sent to the application process, so no request
    /// applies to its helper.
    pub const APPLICATION_REQUEST_NOT_SUBMITTED: &str = "application_request_not_submitted";
    /// The grace period that follows the graceful request is not at its
    /// end.
    pub const GRACE_NOT_EXPIRED: &str = "grace_not_expired";
    /// A lease of the step is at or after its expiry.
    pub const LEASE_EXPIRED: &str = "lease_expired";
    /// The end of the observation window is not a representable time.
    pub const WINDOW_OVERFLOW: &str = "window_overflow";
    /// `kill` returned `EPERM`.
    pub const SIGNAL_NOT_PERMITTED: &str = "signal_not_permitted";
    /// `kill` returned an error other than `ESRCH` and `EPERM`.
    pub const SIGNAL_FAILED: &str = "signal_failed";
    /// The application API returned `false` and the process exists.
    pub const APPLICATION_DECLINED_REQUEST: &str = "application_declined_request";
    /// The host has no application backend.
    pub const BACKEND_UNSUPPORTED: &str = "backend_unsupported";
    /// The process was running at the end of the verification window of a
    /// force step.
    pub const EXIT_NOT_OBSERVED: &str = "exit_not_observed";
    /// The observation after the call could not establish whether the
    /// process exited.
    pub const EXIT_NOT_VERIFIABLE: &str = "exit_not_verifiable";
}

/// The fields of one result, without the identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Outcome {
    pub(super) dispatch: DispatchState,
    pub(super) effect: TargetEffect,
    pub(super) native: NativeResult,
    pub(super) attribution: Attribution,
    pub(super) stop_reason: StopReason,
    pub(super) failure: Option<Failure>,
    /// Whether the executor read the process for this result.
    pub(super) observed: bool,
}

impl Outcome {
    /// No call, because the fresh check did not permit the target.
    pub(super) const fn skipped(failure: Failure, observed: bool) -> Self {
        Self {
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            native: NativeResult::NotCalled,
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::TargetSkipped,
            failure: Some(failure),
            observed,
        }
    }

    /// No call, because the step stopped before it.
    pub(super) const fn stopped(reason: StopReason) -> Self {
        Self {
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            native: NativeResult::NotCalled,
            attribution: Attribution::NotApplicable,
            stop_reason: reason,
            failure: None,
            observed: false,
        }
    }

    /// No call, because the process was not running.
    pub(super) const fn already_exited(observed: bool) -> Self {
        Self {
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::AlreadyExited,
            native: NativeResult::NotCalled,
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Completed,
            failure: None,
            observed,
        }
    }

    /// A call that found no process: the process exited between the check
    /// and the call.
    pub(super) const fn exited_before_call(native: NativeResult) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::AlreadyExited,
            native,
            attribution: Attribution::Possible,
            stop_reason: StopReason::Completed,
            failure: None,
            observed: true,
        }
    }

    /// A call that the backend refused.
    pub(super) const fn refused(native: NativeResult, failure: Failure) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::Refused,
            native,
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Failed,
            failure: Some(failure),
            observed: true,
        }
    }

    /// The planned generation was observed absent after the call.
    pub(super) const fn exit_verified(
        native: NativeResult,
        attribution: Attribution,
        stop_reason: StopReason,
    ) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::ExitVerified,
            native,
            attribution,
            stop_reason,
            failure: None,
            observed: true,
        }
    }

    /// The planned generation was running at the end of the observation.
    pub(super) const fn still_running(native: NativeResult, stop_reason: StopReason) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::StillRunning,
            native,
            attribution: Attribution::NotApplicable,
            stop_reason,
            failure: None,
            observed: true,
        }
    }

    /// The planned generation was running at the end of the verification
    /// window of a force step: the force request did not end the process.
    pub(super) const fn still_running_after_force(native: NativeResult) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::StillRunning,
            native,
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Failed,
            failure: Some(Failure::outcome(code::EXIT_NOT_OBSERVED)),
            observed: true,
        }
    }

    /// The observation after the call established nothing.
    pub(super) fn unknown(
        native: NativeResult,
        stop: Option<StopReason>,
        code: &'static str,
    ) -> Self {
        let (stop_reason, failure) = match stop {
            Some(reason) => (reason, None),
            None => (StopReason::Failed, Some(Failure::outcome(code))),
        };
        Self {
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::UnknownOutcome,
            native,
            attribution: Attribution::Possible,
            stop_reason,
            failure,
            observed: true,
        }
    }
}

/// The identities and the durability that each result of one step has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordBase {
    target_id: TargetId,
    plan_id: PlanId,
    operation_id: OperationId,
    step_id: StepId,
    durability: Durability,
    observer: AdapterId,
}

impl RecordBase {
    pub(super) fn new(
        envelope: &RequestEnvelope,
        durability: Durability,
    ) -> Result<Self, ExecutorError> {
        Ok(Self {
            target_id: envelope.target.target_id.clone(),
            plan_id: envelope.correlation.plan_id.clone(),
            operation_id: envelope.correlation.operation_id.clone(),
            step_id: envelope.correlation.step_id.clone(),
            durability,
            observer: AdapterId::new(ADAPTER_ID).map_err(ExecutorError::Adapter)?,
        })
    }

    pub(super) const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    /// Makes the checked result of one member.
    pub(super) fn record(
        &self,
        member: &ProcessGenerationId,
        outcome: Outcome,
        observed_at: Option<WallTime>,
    ) -> Result<TargetResult, ExecutorError> {
        let failure: Option<ActionError> = match outcome.failure {
            Some(failure) => Some(ActionError {
                code: ErrorCode::new(failure.code).map_err(ExecutorError::Code)?,
                family: failure.family,
                stage: failure.stage,
                dispatch: outcome.dispatch.clone(),
                plan_id: Some(self.plan_id.clone()),
                operation_id: Some(self.operation_id.clone()),
                step_id: Some(self.step_id.clone()),
            }),
            None => None,
        };
        let evidence: EffectEvidence = EffectEvidence {
            native: outcome.native,
            source: outcome.observed.then(|| self.observer.clone()),
            observed_at: if outcome.observed { observed_at } else { None },
            trash_item: None,
        };
        Checked::new(TargetResultRecord {
            target_id: self.target_id.clone(),
            member: Some(member.clone()),
            dispatch: outcome.dispatch,
            effect: outcome.effect,
            evidence,
            attribution: outcome.attribution,
            durability: self.durability.clone(),
            stop_reason: outcome.stop_reason,
            failure,
        })
        .map_err(ExecutorError::Record)
    }
}
