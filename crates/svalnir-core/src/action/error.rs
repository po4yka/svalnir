//! The error and retry taxonomy.
//!
//! `docs/ACTION_CONTRACTS.md` section 10 owns the families and their
//! permitted next steps. An error states the contract boundary that failed,
//! whether a submission occurred, and how to continue. It is not reduced to
//! a permission failure.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::state::DispatchState;
use crate::encoding::wire_enum;
use crate::id::{OperationId, PlanId, StepId};

wire_enum! {
    /// The family of an error: the contract boundary that failed.
    ErrorFamily {
        /// A malformed schema, a conflicting duplicate identity, or an
        /// action or version that is not supported.
        Request => "request",
        /// A wrong principal, a missing or revoked grant, or a policy
        /// revision that does not match.
        Authority => "authority",
        /// A stale sample, an identity that is not supported, a changed
        /// target, or an ambiguous membership.
        Evidence => "evidence",
        /// A protected target, an active cache, or a layout that is not
        /// supported.
        Eligibility => "eligibility",
        /// An exhausted budget, an expired deadline, a full queue, or a
        /// lease that is not available.
        Limits => "limits",
        /// A full database, a sync failure, or a journal that is not
        /// available.
        Recording => "recording",
        /// A refusal, a denied access, a backend that is not supported, or
        /// a definite failure with no effect.
        Native => "native",
        /// A lost reply, an interrupted execution, or an effect that cannot
        /// be verified.
        Outcome => "outcome",
    }
}

wire_enum! {
    /// What the caller is permitted to do after an error.
    PermittedNextStep {
        /// Correct the request. Do not mutate.
        CorrectRequest => "correct_request",
        /// Resolve the authority, then prepare a current plan.
        ResolveAuthority => "resolve_authority",
        /// Make a new observation or inspect the target. Do not retry
        /// against the stale target.
        RefreshObservation => "refresh_observation",
        /// Skip the target. Do not fall back to a broader action.
        SkipTarget => "skip_target",
        /// Respect the cooldown and the admission policy.
        RespectLimits => "respect_limits",
        /// Stop normal mutation. Only the exact critical-memory exception
        /// can continue.
        StopMutation => "stop_mutation",
        /// Report the failure. Retry only after a fresh admission, and only
        /// if that is safe.
        ReportAndReadmit => "report_and_readmit",
        /// Reconcile the outcome before any conflicting action.
        Reconcile => "reconcile",
    }
}

impl ErrorFamily {
    /// Each family that this build knows, in the sequence of the
    /// specification.
    pub const ALL: [Self; 8] = [
        Self::Request,
        Self::Authority,
        Self::Evidence,
        Self::Eligibility,
        Self::Limits,
        Self::Recording,
        Self::Native,
        Self::Outcome,
    ];

    /// The permitted next step of the family.
    ///
    /// A family that this build does not recognize gives
    /// [`PermittedNextStep::Reconcile`], the most restrictive step: the
    /// caller cannot know that no effect occurred.
    pub fn permitted_next_step(&self) -> PermittedNextStep {
        match self {
            Self::Request => PermittedNextStep::CorrectRequest,
            Self::Authority => PermittedNextStep::ResolveAuthority,
            Self::Evidence => PermittedNextStep::RefreshObservation,
            Self::Eligibility => PermittedNextStep::SkipTarget,
            Self::Limits => PermittedNextStep::RespectLimits,
            Self::Recording => PermittedNextStep::StopMutation,
            Self::Native => PermittedNextStep::ReportAndReadmit,
            Self::Outcome | Self::Unrecognized(_) => PermittedNextStep::Reconcile,
        }
    }
}

wire_enum! {
    /// The stage of an operation at which an error occurred.
    ActionStage {
        /// Admission of the plan.
        Admission => "admission",
        /// Recording of the intent.
        Intent => "intent",
        /// Consumption of the dispatch and the final check.
        Dispatch => "dispatch",
        /// The external call.
        Execution => "execution",
        /// Observation of the outcome.
        Verification => "verification",
        /// Reconciliation after a restart or a lost reply.
        Reconciliation => "reconciliation",
    }
}

/// The largest length of an error code, in bytes.
pub const MAX_ERROR_CODE_LENGTH: usize = 64;

/// The reason an error code was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the error code is empty, is longer than 64 bytes, or is not lower-case snake case")]
pub struct ErrorCodeError;

/// The stable identifier of one error: lower-case letters, digits, and `_`,
/// for example `plan_expired`. The codes of the CLI have the same form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErrorCode(String);

impl ErrorCode {
    /// Makes the code from its text.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCodeError`] when the text is empty, is too long, or
    /// has a character other than `a-z`, `0-9`, and `_`.
    pub fn new(text: impl Into<String>) -> Result<Self, ErrorCodeError> {
        let text: String = text.into();
        let is_permitted =
            |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
        if text.is_empty() || text.len() > MAX_ERROR_CODE_LENGTH || !text.bytes().all(is_permitted)
        {
            return Err(ErrorCodeError);
        }
        Ok(Self(text))
    }

    /// The text of the code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErrorCode {
    type Error = ErrorCodeError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<ErrorCode> for String {
    fn from(code: ErrorCode) -> Self {
        code.0
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One error of the action contract.
///
/// The record has no message and no payload from another party. A client
/// makes its text from the code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Error)]
#[error("{family} error {code} at {stage}")]
pub struct ActionError {
    /// The stable identifier of the error.
    pub code: ErrorCode,
    /// The contract boundary that failed.
    pub family: ErrorFamily,
    /// The stage at which the error occurred.
    pub stage: ActionStage,
    /// Whether an external call was submitted before the error. A native
    /// error is not proof of no effect.
    pub dispatch: DispatchState,
    /// The plan, when the error has one.
    pub plan_id: Option<PlanId>,
    /// The operation, when the error has one.
    pub operation_id: Option<OperationId>,
    /// The step, when the error has one.
    pub step_id: Option<StepId>,
}

impl ActionError {
    /// The permitted next step.
    ///
    /// The step of the family applies only when no call was submitted. When
    /// a call was, or possibly was, submitted, or when the dispatch state is
    /// one that this build does not recognize, the step is
    /// [`PermittedNextStep::Reconcile`].
    pub fn permitted_next_step(&self) -> PermittedNextStep {
        match self.dispatch {
            DispatchState::NotSubmitted => self.family.permitted_next_step(),
            _ => PermittedNextStep::Reconcile,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ActionError, ActionStage, ErrorCode, ErrorFamily, PermittedNextStep};
    use crate::action::state::DispatchState;
    use crate::id::PlanId;

    #[test]
    fn each_family_has_its_spelling_and_its_next_step() {
        let expected = [
            ("request", PermittedNextStep::CorrectRequest),
            ("authority", PermittedNextStep::ResolveAuthority),
            ("evidence", PermittedNextStep::RefreshObservation),
            ("eligibility", PermittedNextStep::SkipTarget),
            ("limits", PermittedNextStep::RespectLimits),
            ("recording", PermittedNextStep::StopMutation),
            ("native", PermittedNextStep::ReportAndReadmit),
            ("outcome", PermittedNextStep::Reconcile),
        ];
        for (family, (text, step)) in ErrorFamily::ALL.iter().zip(expected) {
            let json = format!("\"{text}\"");
            assert_eq!(serde_json::to_string(family).unwrap(), json);
            assert_eq!(&serde_json::from_str::<ErrorFamily>(&json).unwrap(), family);
            assert_eq!(family.permitted_next_step(), step);
        }
    }

    #[test]
    fn an_unknown_family_needs_reconciliation() {
        let family: ErrorFamily = serde_json::from_str("\"quota\"").unwrap();
        assert!(!family.is_recognized());
        assert_ne!(family, ErrorFamily::Request);
        assert_eq!(family.permitted_next_step(), PermittedNextStep::Reconcile);
        assert_eq!(serde_json::to_string(&family).unwrap(), "\"quota\"");
        let step: PermittedNextStep = serde_json::from_str("\"retry\"").unwrap();
        assert!(!step.is_recognized());
        let stage: ActionStage = serde_json::from_str("\"cleanup\"").unwrap();
        assert!(!stage.is_recognized());
    }

    #[test]
    fn an_error_code_is_lower_case_snake_case() {
        assert_eq!(
            ErrorCode::new("plan_expired").unwrap().as_str(),
            "plan_expired"
        );
        assert!(ErrorCode::new("e2").is_ok());
        for bad in ["", "PLAN_EXPIRED", "plan expired", "plan-expired", "план"] {
            assert!(ErrorCode::new(bad).is_err(), "{bad}");
        }
        assert!(ErrorCode::new("a".repeat(64)).is_ok());
        assert!(ErrorCode::new("a".repeat(65)).is_err());
        assert!(serde_json::from_str::<ErrorCode>("\"bad code\"").is_err());
    }

    fn example(family: ErrorFamily, dispatch: DispatchState) -> ActionError {
        ActionError {
            code: ErrorCode::new("plan_expired").unwrap(),
            family,
            stage: ActionStage::Admission,
            dispatch,
            plan_id: Some(PlanId::new("plan_1").unwrap()),
            operation_id: None,
            step_id: None,
        }
    }

    #[test]
    fn an_error_round_trips() {
        let error = example(ErrorFamily::Limits, DispatchState::NotSubmitted);
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(
            value,
            json!({
                "code": "plan_expired",
                "family": "limits",
                "stage": "admission",
                "dispatch": "not_submitted",
                "plan_id": "plan_1",
                "operation_id": null,
                "step_id": null,
            })
        );
        assert_eq!(serde_json::from_value::<ActionError>(value).unwrap(), error);
        assert_eq!(error.to_string(), "limits error plan_expired at admission");
    }

    #[test]
    fn a_submitted_call_needs_reconciliation_in_each_family() {
        for family in &ErrorFamily::ALL {
            let before = example(family.clone(), DispatchState::NotSubmitted);
            assert_eq!(before.permitted_next_step(), family.permitted_next_step());
            for dispatch in [
                DispatchState::Submitted,
                DispatchState::SubmissionUncertain,
                DispatchState::from_wire("queued"),
            ] {
                let after = example(family.clone(), dispatch);
                assert_eq!(after.permitted_next_step(), PermittedNextStep::Reconcile);
            }
        }
    }
}
