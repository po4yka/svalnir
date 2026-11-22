//! The reply of the helper to one request.
//!
//! `docs/INTERFACES.md` section 10 owns the content of a reply: the
//! delegated step, its observed state, the durability of the record, the
//! native result and the evidence, and the uncertainty that remains. Each
//! result type is the type of `svalnir-core` for that fact, so a reply and
//! the journal of the agent use one error and outcome taxonomy
//! (`docs/ACTION_CONTRACTS.md` sections 9 and 10).
//!
//! # The three bodies
//!
//! | Body | Meaning | The step |
//! | --- | --- | --- |
//! | [`ResponseBody::Step`] | The record of the helper has the step. The report has its state. | Consumed. A repeat gets the same record. |
//! | [`ResponseBody::Refused`] | The helper decoded the request and refused it. | Not consumed by this request. No call was submitted. |
//! | [`ResponseBody::Rejected`] | The helper did not decode the request, or did not verify the peer. | Not known. No call was submitted. |
//!
//! A reply has no path, no name, and no text of the caller. An entry is
//! named by its position in the request.
//!
//! # The encoded form
//!
//! [`HelperResponse::encode`] gives the JSON form, and [`decode_response`]
//! reads it for a client with the size limit and the nesting limit of a
//! request. A value of a `svalnir-core` enumeration that the reader does
//! not recognize decodes to its `Unrecognized` variant, which the reader
//! handles as an indeterminate result.

use serde::{Deserialize, Serialize};
use svalnir_core::action::{
    ActionError, ActionStage, Attribution, DispatchState, Durability, EffectEvidence, ErrorCode,
    ErrorFamily, NativeResult, OutcomeError, StepState, StopReason, TargetEffect, TargetResult,
    TargetResultRecord, WorkCharge,
};
use svalnir_core::id::{RequestId, TargetId};
use thiserror::Error;

use crate::request::{
    DecodeError, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolMismatch, ProtocolVersion,
    StepCorrelation, check_nesting,
};

#[cfg(test)]
mod tests;

/// The largest encoded response, in bytes: 1 MiB
/// (`docs/INTERFACES.md` section 9).
pub const MAX_ENCODED_RESPONSE_BYTES: usize = 1 << 20;

/// A condition of the service, of the transport, or of the executor that
/// is not a refusal of the validation. Each condition has one error
/// family and one stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Condition {
    /// The platform did not verify the code identity of the peer.
    #[error("the code identity of the peer is not verified")]
    PeerUnverified,
    /// The platform gave no effective user for the peer.
    #[error("the platform gave no user for the peer")]
    PeerUserUnavailable,
    /// The transport message is not one request in the frame of the
    /// protocol.
    #[error("the transport message is not a request frame")]
    FrameMalformed,
    /// The state of the helper is not usable.
    #[error("the state of the helper is not available")]
    StateUnavailable,
    /// The helper cannot read its clock.
    #[error("the clock of the helper is not available")]
    ClockUnavailable,
    /// The record of the consumed step was not made durable. No call was
    /// submitted.
    #[error("the record of the step is not durable")]
    RecordNotDurable,
    /// The record of the result was not made durable.
    #[error("the record of the result is not durable")]
    ResultNotDurable,
    /// The response is larger than the limit.
    #[error("the response is larger than the limit")]
    ResponseTooLarge,
    /// The path of the root cannot be opened as directories with no
    /// symbolic link.
    #[error("the root cannot be opened")]
    RootUnavailable,
    /// The root is not a directory of the helper or of the administrator,
    /// or another user can write to it.
    #[error("the root is not controlled by the administrator")]
    RootNotControlled,
    /// The root is on a filesystem that is not local, or the mount flags
    /// cannot be read.
    #[error("the root is not on a local filesystem")]
    RootNotLocal,
    /// A directory in the path of an entry is absent, is not a directory,
    /// or is a symbolic link.
    #[error("the path of an entry changed")]
    PathChanged,
    /// A directory in the path of an entry is not a directory of the
    /// helper or of the administrator, or another user can write to it.
    #[error("the path of an entry is not controlled by the administrator")]
    PathNotControlled,
    /// A directory or an object of an entry is on a different mounted
    /// filesystem than the root.
    #[error("an entry is on a different filesystem than the root")]
    MountCrossing,
    /// The object of an entry cannot be measured.
    #[error("an entry cannot be measured")]
    TargetUnreadable,
    /// The object at the name of an entry has a different type or
    /// different native identifiers than the request states.
    #[error("the object of an entry changed")]
    TargetChanged,
    /// The object of an entry is not owned by the helper or by the
    /// administrator.
    #[error("the object of an entry has a different owner")]
    TargetNotOwned,
    /// The object of an entry has more than one name.
    #[error("the object of an entry has more than one link")]
    TargetHardLinked,
    /// The object of an entry is a dataless placeholder.
    #[error("the object of an entry is dataless")]
    TargetDataless,
    /// The object of an entry is larger than the bound of the entry.
    #[error("the object of an entry is larger than its bound")]
    TargetOverBound,
    /// The object of a directory entry is the home directory of the user
    /// of the step or a directory that contains it, or the helper could
    /// not establish the home directory of that user.
    #[error("the object of an entry is or contains the home directory of the user")]
    HomeDirectoryProtected,
    /// The removal call returned a definite refusal.
    #[error("the removal call was refused")]
    RemovalRefused,
    /// The removal call of a directory found an entry in it.
    #[error("the directory of an entry is not empty")]
    DirectoryNotEmpty,
    /// The result of the removal call does not establish the effect.
    #[error("the effect of the removal call is not known")]
    RemovalUnknown,
}

impl Condition {
    /// Each condition.
    pub const ALL: [Self; 24] = [
        Self::PeerUnverified,
        Self::PeerUserUnavailable,
        Self::FrameMalformed,
        Self::StateUnavailable,
        Self::ClockUnavailable,
        Self::RecordNotDurable,
        Self::ResultNotDurable,
        Self::ResponseTooLarge,
        Self::RootUnavailable,
        Self::RootNotControlled,
        Self::RootNotLocal,
        Self::PathChanged,
        Self::PathNotControlled,
        Self::MountCrossing,
        Self::TargetUnreadable,
        Self::TargetChanged,
        Self::TargetNotOwned,
        Self::TargetHardLinked,
        Self::TargetDataless,
        Self::TargetOverBound,
        Self::HomeDirectoryProtected,
        Self::RemovalRefused,
        Self::DirectoryNotEmpty,
        Self::RemovalUnknown,
    ];

    /// The error family of the condition.
    pub fn family(self) -> ErrorFamily {
        match self {
            Self::FrameMalformed => ErrorFamily::Request,
            Self::PeerUnverified | Self::PeerUserUnavailable => ErrorFamily::Authority,
            Self::ClockUnavailable
            | Self::RootUnavailable
            | Self::PathChanged
            | Self::TargetUnreadable
            | Self::TargetChanged => ErrorFamily::Evidence,
            Self::RootNotControlled
            | Self::RootNotLocal
            | Self::PathNotControlled
            | Self::MountCrossing
            | Self::TargetNotOwned
            | Self::TargetHardLinked
            | Self::TargetDataless
            | Self::HomeDirectoryProtected => ErrorFamily::Eligibility,
            Self::ResponseTooLarge | Self::TargetOverBound => ErrorFamily::Limits,
            Self::StateUnavailable | Self::RecordNotDurable | Self::ResultNotDurable => {
                ErrorFamily::Recording
            }
            Self::RemovalRefused | Self::DirectoryNotEmpty => ErrorFamily::Native,
            Self::RemovalUnknown => ErrorFamily::Outcome,
        }
    }

    /// The stable code of the condition: lower-case letters, digits, and
    /// `_`.
    pub fn code(self) -> &'static str {
        match self {
            Self::PeerUnverified => "helper_peer_unverified",
            Self::PeerUserUnavailable => "helper_peer_user_unavailable",
            Self::FrameMalformed => "helper_frame_malformed",
            Self::StateUnavailable => "helper_state_unavailable",
            Self::ClockUnavailable => "helper_clock_unavailable",
            Self::RecordNotDurable => "helper_record_not_durable",
            Self::ResultNotDurable => "helper_result_not_durable",
            Self::ResponseTooLarge => "helper_response_too_large",
            Self::RootUnavailable => "helper_root_unavailable",
            Self::RootNotControlled => "helper_root_not_controlled",
            Self::RootNotLocal => "helper_root_not_local",
            Self::PathChanged => "helper_path_changed",
            Self::PathNotControlled => "helper_path_not_controlled",
            Self::MountCrossing => "helper_mount_crossing",
            Self::TargetUnreadable => "helper_target_unreadable",
            Self::TargetChanged => "helper_target_changed",
            Self::TargetNotOwned => "helper_target_not_owned",
            Self::TargetHardLinked => "helper_target_hard_linked",
            Self::TargetDataless => "helper_target_dataless",
            Self::TargetOverBound => "helper_target_over_bound",
            Self::HomeDirectoryProtected => "helper_home_directory_protected",
            Self::RemovalRefused => "helper_removal_refused",
            Self::DirectoryNotEmpty => "helper_directory_not_empty",
            Self::RemovalUnknown => "helper_removal_unknown",
        }
    }
}

/// Makes an error of the action contract from a code of this crate.
///
/// Each code of this crate is a permitted error code; a test checks each
/// one. The fallback keeps the function total with no panic: its code is a
/// literal that the grammar permits.
pub(crate) fn action_error(
    code: &'static str,
    family: ErrorFamily,
    stage: ActionStage,
    dispatch: DispatchState,
    correlation: Option<&StepCorrelation>,
) -> ActionError {
    let code: ErrorCode = ErrorCode::new(code).unwrap_or_else(|_| fallback_code());
    ActionError {
        code,
        family,
        stage,
        dispatch,
        plan_id: correlation.map(|correlation: &StepCorrelation| correlation.plan_id.clone()),
        operation_id: correlation
            .map(|correlation: &StepCorrelation| correlation.operation_id.clone()),
        step_id: correlation.map(|correlation: &StepCorrelation| correlation.step_id.clone()),
    }
}

/// The code of an error whose own code the grammar refuses. The grammar
/// permits each code of this crate, so no call reaches this function.
#[expect(
    clippy::expect_used,
    reason = "the literal is a permitted error code, and a test checks it; `ErrorCode` has no infallible constructor"
)]
fn fallback_code() -> ErrorCode {
    ErrorCode::new(FALLBACK_CODE).expect("the literal is a permitted error code")
}

/// The code of [`fallback_code`].
const FALLBACK_CODE: &str = "helper_error";

impl Condition {
    /// The condition as an error of the action contract.
    pub fn to_action_error(
        self,
        stage: ActionStage,
        dispatch: DispatchState,
        correlation: Option<&StepCorrelation>,
    ) -> ActionError {
        action_error(self.code(), self.family(), stage, dispatch, correlation)
    }
}

/// Whether a report is the result of this request or the record of an
/// earlier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportOrigin {
    /// This request consumed the step, and the report is its result.
    ThisRequest,
    /// The record had the step. The helper accepted nothing and submitted
    /// no call for this request.
    Record,
}

/// The result of one entry of an eviction.
///
/// The fields are those of a target record of `docs/ACTION_CONTRACTS.md`
/// section 9. The record of the helper has no target identity of the
/// agent: `index` is the position of the entry in the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryReport {
    /// The position of the entry in the request, from zero.
    pub index: u32,
    /// Whether the removal call for the entry was submitted.
    pub dispatch: DispatchState,
    /// The observed result.
    pub effect: TargetEffect,
    /// The native result and the observation.
    pub evidence: EffectEvidence,
    /// Whether the call caused the observed condition. A removal has
    /// `possible`: macOS has no removal call that is conditional on the
    /// identity of the object.
    pub attribution: Attribution,
    /// Why work on the entry stopped.
    pub stop_reason: StopReason,
    /// The error, when the entry was skipped by its check, was refused, or
    /// failed.
    pub failure: Option<ActionError>,
    /// The work that the helper measured for the object immediately before
    /// a submitted call. It is an estimate of what the call removed, and
    /// it is not reclaimed capacity.
    pub removed: WorkCharge,
}

impl EntryReport {
    /// The report as a target result of the action contract, for the
    /// target identity that the agent has for the entry.
    ///
    /// # Errors
    ///
    /// Returns an [`OutcomeError`] when the fields of the report do not
    /// agree with each other.
    pub fn to_target_result(
        &self,
        target_id: TargetId,
        durability: Durability,
    ) -> Result<TargetResult, OutcomeError> {
        TargetResult::new(TargetResultRecord {
            target_id,
            member: None,
            dispatch: self.dispatch.clone(),
            effect: self.effect.clone(),
            evidence: self.evidence.clone(),
            attribution: self.attribution.clone(),
            durability,
            stop_reason: self.stop_reason.clone(),
            failure: self.failure.clone(),
        })
    }

    /// Whether the removal call for the entry was, or possibly was,
    /// submitted.
    pub fn is_possibly_submitted(&self) -> bool {
        self.dispatch.is_possibly_submitted()
            || !matches!(self.evidence.native, NativeResult::NotCalled)
    }
}

/// The recorded state of one delegated step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepReport {
    /// The plan, the operation, and the step.
    pub correlation: StepCorrelation,
    /// Whether this request consumed the step.
    pub origin: ReportOrigin,
    /// The state of the step. `DispatchConsumed` and `Verifying` mean that
    /// the step is in work. `UnknownOutcome` needs reconciliation.
    pub state: StepState,
    /// How the helper kept the record of this state. `persistence_failed`
    /// means that the consumption of the step is durable and its result is
    /// not: after a restart of the helper the step is `UnknownOutcome`.
    pub durability: Durability,
    /// The result of each entry, in the sequence of the request. `None`
    /// means that the record has no entry results: the step submitted no
    /// call for a reason of the step, or an earlier lifetime of the helper
    /// did the step.
    pub entries: Option<Vec<EntryReport>>,
    /// The error of the step as a whole: a record that is not durable, or
    /// the condition that stopped the step before its last entry.
    pub error: Option<ActionError>,
}

/// A refused request. The helper accepted nothing, and this request
/// consumed no step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalReport {
    /// The plan, the operation, and the step of the refused request.
    pub correlation: StepCorrelation,
    /// The reason. The stage is admission, and no call was submitted.
    pub error: ActionError,
}

/// A request that the helper did not decode, or a peer that the helper
/// did not verify.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    /// The reason. The error names no plan, operation, or step.
    pub error: ActionError,
}

/// The body of a response.
///
/// JSON encodes the value as an object with one field: the name of the
/// body in lower-case snake case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseBody {
    /// The recorded state of the step.
    Step(StepReport),
    /// The helper refused the request.
    Refused(RefusalReport),
    /// The helper did not decode the request or did not verify the peer.
    Rejected(Rejection),
}

/// One response of the helper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperResponse {
    /// The protocol version of the helper.
    pub protocol: ProtocolVersion,
    /// The transport correlation identity of the request. `None` when the
    /// helper did not decode the request.
    pub request_id: Option<RequestId>,
    /// The body.
    pub body: ResponseBody,
}

/// The reason a response has no encoded form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncodeError {
    /// The response has no JSON encoding.
    #[error("the response cannot be encoded")]
    NotEncodable,
    /// The encoded form is longer than [`MAX_ENCODED_RESPONSE_BYTES`].
    #[error("the encoded response is larger than the limit")]
    TooLarge,
}

impl HelperResponse {
    /// Makes a response with the protocol version of this build.
    pub fn new(request_id: Option<RequestId>, body: ResponseBody) -> Self {
        Self {
            protocol: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            request_id,
            body,
        }
    }

    /// Makes the response for a request that was not decoded or for a peer
    /// that was not verified.
    pub fn rejected(code: &'static str, family: ErrorFamily) -> Self {
        Self::new(
            None,
            ResponseBody::Rejected(Rejection {
                error: action_error(
                    code,
                    family,
                    ActionStage::Admission,
                    DispatchState::NotSubmitted,
                    None,
                ),
            }),
        )
    }

    /// The JSON form of the response.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] when the response has no encoding or
    /// when the encoded form is larger than the limit.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let bytes: Vec<u8> = serde_json::to_vec(self).map_err(|_| EncodeError::NotEncodable)?;
        if bytes.len() > MAX_ENCODED_RESPONSE_BYTES {
            return Err(EncodeError::TooLarge);
        }
        Ok(bytes)
    }
}

/// Decodes the JSON form of one response, for a client of the helper.
///
/// The decoder applies the size limit and the nesting limit, then the
/// protocol major version, then strict decoding of the records of this
/// module.
///
/// # Errors
///
/// Returns a [`DecodeError`] for the first check that fails.
pub fn decode_response(bytes: &[u8]) -> Result<HelperResponse, DecodeError> {
    if bytes.len() > MAX_ENCODED_RESPONSE_BYTES {
        return Err(DecodeError::TooLarge);
    }
    check_nesting(bytes)?;
    let response: HelperResponse =
        serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
    if response.protocol.major != PROTOCOL_MAJOR {
        return Err(DecodeError::Protocol(ProtocolMismatch::Major));
    }
    Ok(response)
}
