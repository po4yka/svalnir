//! Target results, aggregation, and resource effects.
//!
//! `docs/ACTION_CONTRACTS.md` section 9 owns the contract. Dispatch, target
//! effect, aggregate completion, and resource observation are separate
//! facts. A successful native call is not a verified effect, and a verified
//! effect is not a resource improvement.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::checked::{Check, Checked};
use super::error::ActionError;
use super::state::{DispatchState, Durability, OperationState, StepState};
use crate::encoding::wire_enum;
use crate::file::LosslessPath;
use crate::id::{AdapterId, ProcessGenerationId, TargetId};
use crate::observation::Observation;
use crate::quantity::{ByteDelta, Bytes};
use crate::state::PressureState;
use crate::time::WallTime;

wire_enum! {
    /// The observed result of an action on one target. The serialized
    /// spelling is the name in the specification.
    TargetEffect {
        /// The entry was moved to Trash. This is not reclaimed capacity.
        Trashed => "Trashed",
        /// The directory entry was removed.
        Removed => "Removed",
        /// The exit of the process was observed after the request.
        ExitVerified => "ExitVerified",
        /// The entry was absent.
        AlreadyAbsent => "AlreadyAbsent",
        /// The process was not running.
        AlreadyExited => "AlreadyExited",
        /// No call was issued for the target. The stop reason says why.
        Skipped => "Skipped",
        /// The backend refused the call.
        Refused => "Refused",
        /// The process was running at the end of the observation window.
        StillRunning => "StillRunning",
        /// The evidence cannot establish the effect.
        UnknownOutcome => "UnknownOutcome",
    }
}

impl TargetEffect {
    /// Each effect that this build knows.
    pub const ALL: [Self; 9] = [
        Self::Trashed,
        Self::Removed,
        Self::ExitVerified,
        Self::AlreadyAbsent,
        Self::AlreadyExited,
        Self::Skipped,
        Self::Refused,
        Self::StillRunning,
        Self::UnknownOutcome,
    ];

    /// Whether the effect is a verified effect of a submitted call.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Trashed | Self::Removed | Self::ExitVerified)
    }

    /// Whether the target is in its requested final condition: a verified
    /// effect, or a target that was absent or not running.
    pub fn is_final_condition_met(&self) -> bool {
        self.is_verified() || matches!(self, Self::AlreadyAbsent | Self::AlreadyExited)
    }

    /// Whether the effect is indeterminate. An effect that this build does
    /// not recognize is indeterminate; it is never read as a known result.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::UnknownOutcome | Self::Unrecognized(_))
    }
}

wire_enum! {
    /// Whether the action of Svalnir caused the observed condition.
    Attribution {
        /// The evidence establishes that the action caused the condition.
        Established => "established",
        /// The action possibly caused the condition.
        Possible => "possible",
        /// No call was issued, or the condition is not an effect.
        NotApplicable => "not_applicable",
    }
}

wire_enum! {
    /// Why work on a target stopped.
    StopReason {
        /// The work came to its normal end.
        Completed => "COMPLETED",
        /// The operation was canceled.
        Canceled => "CANCELED",
        /// The agent or the policy was paused.
        Paused => "PAUSED",
        /// The policy revision or a grant changed.
        PolicyChanged => "POLICY_CHANGED",
        /// The trigger of the automatic work cleared.
        TriggerCleared => "TRIGGER_CLEARED",
        /// The plan expired or the deadline passed.
        DeadlineExpired => "DEADLINE_EXPIRED",
        /// The necessary authority was missing.
        AuthorityMissing => "AUTHORITY_MISSING",
        /// The fresh check before dispatch did not permit this target: its
        /// evidence, its eligibility, or a limit. This is not an execution
        /// error.
        TargetSkipped => "TARGET_SKIPPED",
        /// A known failure.
        Failed => "FAILED",
    }
}

/// The result of the native call.
///
/// JSON encodes the value as an object with a `kind` field. A `kind` that
/// this build does not know decodes to `Unrecognized`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeResult {
    /// No native call was issued.
    NotCalled,
    /// The call returned success. This is not a verified effect.
    Succeeded,
    /// The call returned an error number.
    Errno {
        /// The error number.
        errno: i32,
    },
    /// The backend refused the request without an error number.
    Refused,
    /// The call was, or possibly was, issued and its result is not known.
    Unavailable,
    /// No call was issued for this member of an application target: the
    /// request to the application covers it. The record of the member has
    /// the dispatch state `submitted`, because the request to its
    /// application was submitted. Only a result of one member has this
    /// value. A build that does not know the value reads it as
    /// `Unrecognized`.
    CoveredByApplicationRequest,
    /// A result kind that this build does not recognize.
    #[serde(other)]
    Unrecognized,
}

/// The evidence of one target result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectEvidence {
    /// The result of the native call.
    pub native: NativeResult,
    /// The adapter that observed the effect. `None` means that no
    /// observation was made.
    pub source: Option<AdapterId>,
    /// The wall-clock time of the observation, for history only.
    pub observed_at: Option<WallTime>,
    /// The item in Trash, when the backend returned one. The name can be
    /// different from the source name.
    pub trash_item: Option<LosslessPath>,
}

impl EffectEvidence {
    /// The evidence of a target for which no call was issued and no
    /// observation was made.
    pub const fn none() -> Self {
        Self {
            native: NativeResult::NotCalled,
            source: None,
            observed_at: None,
            trash_item: None,
        }
    }
}

/// The fields of one target result. [`TargetResult`] is the checked form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetResultRecord {
    /// The target.
    pub target_id: TargetId,
    /// The member of an application target that this result is for.
    /// `None` means that the result is for the target as a whole.
    pub member: Option<ProcessGenerationId>,
    /// Whether the call for this target was submitted.
    pub dispatch: DispatchState,
    /// The observed result.
    pub effect: TargetEffect,
    /// The native result and the observation.
    pub evidence: EffectEvidence,
    /// Whether the action caused the observed condition.
    pub attribution: Attribution,
    /// How the record was kept.
    pub durability: Durability,
    /// Why work on the target stopped.
    pub stop_reason: StopReason,
    /// The error, when the target was skipped, was refused, or failed.
    pub failure: Option<ActionError>,
}

/// One target result whose fields agree with each other.
///
/// A record with a value that this build does not recognize is kept as it
/// is. [`aggregate`] reads it as an indeterminate effect.
pub type TargetResult = Checked<TargetResultRecord>;

/// The reason a target result or a result list was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OutcomeError {
    /// The dispatch state is not possible for the effect.
    #[error("the dispatch state is not possible for the effect")]
    Dispatch,
    /// The attribution is not possible for the effect and the dispatch
    /// state.
    #[error("the attribution is not possible for the effect and the dispatch state")]
    Attribution,
    /// The stop reason is not possible for the effect.
    #[error("the stop reason is not possible for the effect")]
    StopReason,
    /// A skipped, refused, or failed target has no error, a verified
    /// effect has one, or the error says that no call was submitted and
    /// the record says that a call was, or possibly was, submitted.
    #[error("the error record does not agree with the effect and the stop reason")]
    Failure,
    /// The evidence is not possible for the effect.
    #[error("the evidence is not possible for the effect")]
    Evidence,
    /// The list has no result. An operation has a minimum of one target.
    #[error("the result list is empty")]
    NoResults,
}

impl TargetResultRecord {
    fn is_recognized(&self) -> bool {
        self.dispatch.is_recognized()
            && self.effect.is_recognized()
            && self.attribution.is_recognized()
            && self.durability.is_recognized()
            && self.stop_reason.is_recognized()
            && !matches!(self.evidence.native, NativeResult::Unrecognized)
    }
}

impl Check for TargetResultRecord {
    type Error = OutcomeError;

    fn check(&self) -> Result<(), OutcomeError> {
        use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};
        if !self.is_recognized() {
            return Ok(());
        }
        let dispatch_agrees: bool = match self.effect {
            TargetEffect::Trashed
            | TargetEffect::Removed
            | TargetEffect::ExitVerified
            | TargetEffect::Refused
            | TargetEffect::StillRunning => matches!(self.dispatch, Submitted),
            TargetEffect::Skipped => matches!(self.dispatch, NotSubmitted),
            TargetEffect::UnknownOutcome => {
                matches!(self.dispatch, Submitted | SubmissionUncertain)
            }
            _ => true,
        };
        if !dispatch_agrees {
            return Err(OutcomeError::Dispatch);
        }
        let attribution_agrees: bool = match self.effect {
            TargetEffect::Trashed | TargetEffect::Removed | TargetEffect::ExitVerified => {
                matches!(
                    self.attribution,
                    Attribution::Established | Attribution::Possible
                )
            }
            // A target that was absent before the call is a no-op. After a
            // possible call, the cause of the absence is not established.
            TargetEffect::AlreadyAbsent | TargetEffect::AlreadyExited => match self.dispatch {
                NotSubmitted => matches!(self.attribution, Attribution::NotApplicable),
                _ => matches!(self.attribution, Attribution::Possible),
            },
            TargetEffect::UnknownOutcome => matches!(self.attribution, Attribution::Possible),
            _ => matches!(self.attribution, Attribution::NotApplicable),
        };
        if !attribution_agrees {
            return Err(OutcomeError::Attribution);
        }
        let stop_agrees: bool = match self.effect {
            TargetEffect::Skipped => !matches!(self.stop_reason, StopReason::Completed),
            TargetEffect::Refused => matches!(self.stop_reason, StopReason::Failed),
            // A target in its final condition is not a failure.
            TargetEffect::Trashed
            | TargetEffect::Removed
            | TargetEffect::ExitVerified
            | TargetEffect::AlreadyAbsent
            | TargetEffect::AlreadyExited => !matches!(
                self.stop_reason,
                StopReason::Failed | StopReason::TargetSkipped
            ),
            _ => !matches!(self.stop_reason, StopReason::TargetSkipped),
        };
        if !stop_agrees {
            return Err(OutcomeError::StopReason);
        }
        let needs_failure: bool = matches!(
            self.stop_reason,
            StopReason::Failed | StopReason::TargetSkipped
        );
        if needs_failure != self.failure.is_some() {
            return Err(OutcomeError::Failure);
        }
        // The next step of an error comes from its own dispatch state. An
        // error that says `not_submitted` in a record whose call was, or
        // possibly was, submitted would permit a retry before
        // reconciliation.
        let failure_understates: bool = self.dispatch.is_possibly_submitted()
            && self
                .failure
                .as_ref()
                .is_some_and(|failure| matches!(failure.dispatch, NotSubmitted));
        if failure_understates {
            return Err(OutcomeError::Failure);
        }
        let has_trash_item: bool = self.evidence.trash_item.is_some();
        let called: bool = !matches!(self.evidence.native, NativeResult::NotCalled);
        let evidence_agrees: bool = match self.dispatch {
            NotSubmitted => !called && !has_trash_item,
            _ => called && (!has_trash_item || matches!(self.effect, TargetEffect::Trashed)),
        };
        if !evidence_agrees {
            return Err(OutcomeError::Evidence);
        }
        // A covered member is one member of an application target whose
        // application got the request. The value is not possible for a
        // whole target, for a file effect, or for a call that possibly was
        // not submitted.
        let is_covered: bool = matches!(
            self.evidence.native,
            NativeResult::CoveredByApplicationRequest
        );
        let covered_agrees: bool = self.member.is_some()
            && matches!(self.dispatch, Submitted)
            && !matches!(
                self.effect,
                TargetEffect::Trashed | TargetEffect::Removed | TargetEffect::AlreadyAbsent
            );
        if is_covered && !covered_agrees {
            return Err(OutcomeError::Evidence);
        }
        // A verified effect is an observation of the target after the
        // call: a native call that succeeded is not a verified effect. A
        // record with no observation source states that no observation
        // was made, so it cannot have a verified effect.
        if self.effect.is_verified() && self.evidence.source.is_none() {
            return Err(OutcomeError::Evidence);
        }
        Ok(())
    }
}

/// A target, or one member of an application target.
type ResultKey<'a> = (&'a TargetId, Option<&'a ProcessGenerationId>);

/// Aggregates the target results of an operation into its state.
///
/// `results` has the results of the steps in execution sequence. When more
/// than one step has a result for one target or one member, for example a
/// graceful step and a force step, the last result is its final condition.
///
/// The precedence is that of the specification:
///
/// 1. `UnknownOutcome`, when a result of a step has an indeterminate
///    effect or a field with a value that this build does not recognize.
/// 2. `Completed`, when each target is in its final condition and a call
///    was, or possibly was, submitted. `NoAction`, when each target is in
///    its final condition and no call was submitted.
/// 3. `Partial`, when the final result of a target is a verified effect
///    and that of another target is not a final condition.
/// 4. `Failed`, when no final result is a verified effect and a result
///    has the stop reason `FAILED`.
/// 5. `Incomplete`, when a call was, or possibly was, submitted.
/// 6. `NoAction`.
///
/// # Errors
///
/// Returns [`OutcomeError::NoResults`] when `results` is empty. An
/// operation that stops before its first target records a skipped result
/// for each target.
pub fn aggregate(results: &[TargetResult]) -> Result<OperationState, OutcomeError> {
    if results.is_empty() {
        return Err(OutcomeError::NoResults);
    }
    // A record with a field that this build does not recognize passed no
    // consistency check, so no field of it is read as a known result.
    let indeterminate =
        |result: &TargetResult| result.effect.is_indeterminate() || !result.is_recognized();
    if results.iter().any(indeterminate) {
        return Ok(OperationState::UnknownOutcome);
    }
    let mut final_results: BTreeMap<ResultKey<'_>, &TargetResult> = BTreeMap::new();
    for result in results {
        // A later record for the target as a whole replaces each earlier
        // record of the target, and a later record for one member
        // replaces the earlier record for the target as a whole.
        match &result.member {
            None => final_results.retain(|(target, _), _| *target != &result.target_id),
            Some(_) => {
                final_results.remove(&(&result.target_id, None));
            }
        }
        final_results.insert((&result.target_id, result.member.as_ref()), result);
    }
    let submitted: bool = results
        .iter()
        .any(|result| result.dispatch.is_possibly_submitted());
    let all_met: bool = final_results
        .values()
        .all(|result| result.effect.is_final_condition_met());
    let state = if all_met {
        if submitted {
            OperationState::Completed
        } else {
            OperationState::NoAction
        }
    } else if final_results
        .values()
        .any(|result| result.effect.is_verified())
    {
        OperationState::Partial
    } else if results
        .iter()
        .any(|result| matches!(result.stop_reason, StopReason::Failed))
    {
        OperationState::Failed
    } else if submitted {
        OperationState::Incomplete
    } else {
        OperationState::NoAction
    };
    Ok(state)
}

/// Aggregates the target results of one step into the state of the step,
/// with the rules of [`aggregate`].
///
/// # Errors
///
/// Returns [`OutcomeError::NoResults`] when `results` is empty.
pub fn aggregate_step(results: &[TargetResult]) -> Result<StepState, OutcomeError> {
    let state = match aggregate(results)? {
        OperationState::Completed => StepState::Completed,
        OperationState::Partial => StepState::Partial,
        OperationState::Incomplete => StepState::Incomplete,
        OperationState::NoAction => StepState::NoAction,
        OperationState::Failed => StepState::Failed,
        _ => StepState::UnknownOutcome,
    };
    Ok(state)
}

/// One resource effect: an observation before and after an operation.
///
/// Other workloads run at the same time, so a change is not exact causal
/// reclamation. A completed operation can have no improvement, and a
/// negative capacity change is valid.
///
/// JSON encodes the value as an object with a `resource` field. A
/// `resource` that this build does not know decodes to `Unrecognized`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum ResourceEffect {
    /// The available capacity of a volume or a capacity domain.
    Capacity(CapacityEffect),
    /// The memory pressure of the host.
    MemoryPressure {
        /// The `memory.pressure` observation before the operation.
        before: Observation<PressureState>,
        /// The `memory.pressure` observation after the operation.
        after: Observation<PressureState>,
    },
    /// A resource kind that this build does not recognize.
    #[serde(other)]
    Unrecognized,
}

/// The available capacity before and after an operation. The observations
/// have the source, the scope, the time window, and the quality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CapacityEffectWire")]
pub struct CapacityEffect {
    before: Observation<Bytes>,
    after: Observation<Bytes>,
    delta: Option<ByteDelta>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityEffectWire {
    before: Observation<Bytes>,
    after: Observation<Bytes>,
    delta: Option<ByteDelta>,
}

/// The reason a capacity effect was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the capacity change is not the difference of the two observations")]
pub struct CapacityEffectError;

impl TryFrom<CapacityEffectWire> for CapacityEffect {
    type Error = CapacityEffectError;

    fn try_from(wire: CapacityEffectWire) -> Result<Self, Self::Error> {
        let effect = Self::new(wire.before, wire.after);
        if effect.delta == wire.delta {
            Ok(effect)
        } else {
            Err(CapacityEffectError)
        }
    }
}

impl CapacityEffect {
    /// Makes the effect from the two observations.
    ///
    /// The change is known only when the two observations have a value and
    /// the same scope. An observation that is not available gives no
    /// change; it does not give zero.
    pub fn new(before: Observation<Bytes>, after: Observation<Bytes>) -> Self {
        let delta: Option<ByteDelta> = match (before.value(), after.value()) {
            (Some(earlier), Some(later)) if before.scope == after.scope => {
                Some(later.delta_from(*earlier))
            }
            _ => None,
        };
        Self {
            before,
            after,
            delta,
        }
    }

    /// The observation before the operation.
    pub fn before(&self) -> &Observation<Bytes> {
        &self.before
    }

    /// The observation after the operation.
    pub fn after(&self) -> &Observation<Bytes> {
        &self.after
    }

    /// The signed change of the available capacity: positive when the
    /// available capacity increased. `None` when the change is not known.
    pub fn delta(&self) -> Option<ByteDelta> {
        self.delta
    }
}
