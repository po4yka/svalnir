//! The reasons for which the helper refuses a request.
//!
//! `docs/ACTION_CONTRACTS.md` section 10 owns the error families. Each
//! reason has one family and one stable code. A refusal has no path, no
//! name, and no text of the caller.

use svalnir_core::action::{
    ActionError, ActionStage, DispatchState, ErrorCode, ErrorCodeError, ErrorFamily,
};
use thiserror::Error;

use super::path::PathDefect;
use crate::request::{ProtocolMismatch, StepCorrelation};

/// The reason for which the helper refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum RefusalReason {
    /// The protocol major version is not the major version of the helper.
    #[error("the protocol major version is not supported")]
    ProtocolMajor,
    /// The protocol minor version is later than the supported one.
    #[error("the protocol minor version is later than the supported one")]
    ProtocolMinor,
    /// The content of the request has no encoding, so it has no digest.
    #[error("the content of the request cannot be encoded")]
    ContentNotEncodable,
    /// The record has the step with a different content. The same identity
    /// with a different content is not an update.
    #[error("the step is recorded with a different content")]
    ConflictingDuplicate,
    /// The record has the transport identity for a different step.
    #[error("the request identity is recorded for a different step")]
    RequestIdReused,
    /// The record does not have the step for this user.
    #[error("the step is not recorded")]
    StepNotRecorded,
    /// The helper cannot execute the rule revision below the root.
    #[error("the rule revision is not supported for the root")]
    RuleNotSupported,
    /// The request has no entry.
    #[error("the request has no entry")]
    NoTarget,
    /// An entry is not a list of names below its root.
    #[error("an entry is not permitted: {0}")]
    TargetPath(#[source] PathDefect),
    /// The type of an object is one that this build does not recognize.
    #[error("the type of an object is not supported")]
    ObjectType,
    /// The request has one entry two times.
    #[error("the request has an entry two times")]
    DuplicateTarget,
    /// The bound of an entry has no item. An entry is one item or more.
    #[error("the bound of an entry has no item")]
    ChargeWithoutItem,
    /// The request expires at or before the time at which it was made.
    #[error("the validity of the request is empty")]
    ValidityEmpty,

    /// The code-signing identity of the caller is not the identity of the
    /// agent.
    #[error("the caller is not the agent")]
    CallerNotPermitted,
    /// The role of the caller cannot request the operation.
    #[error("the role of the caller cannot request the operation")]
    RoleNotPermitted,
    /// The helper has no grant with this identity for the authenticated
    /// user. A grant of a different user gives the same reason.
    #[error("the helper has no such grant for the user")]
    GrantUnknown,
    /// The request names a generation before the current one. The grant
    /// changed or was revoked after the plan was built.
    #[error("the generation of the grant is before the current one")]
    GrantGenerationStale,
    /// The request names a generation after the current one. The helper
    /// has no record of it.
    #[error("the generation of the grant is after the current one")]
    GrantGenerationUnknown,
    /// The grant was revoked.
    #[error("the grant was revoked")]
    GrantRevoked,
    /// The grant is expired.
    #[error("the grant is expired")]
    GrantExpired,
    /// The grant expires before the request does. An accepted step can be
    /// executed until the expiry of its request, so the grant must apply
    /// for that full time.
    #[error("the grant expires before the request")]
    GrantExpiresBeforeRequest,
    /// The grant does not have the root.
    #[error("the grant does not have the root")]
    RootNotGranted,
    /// The final check of the grant did not cover the operation.
    #[error("the grant does not cover the operation")]
    GrantDoesNotCover,

    /// An entry has no native identifiers. The helper does not remove an
    /// object that the executor cannot identify.
    #[error("an entry has no native identifiers")]
    ObjectEvidenceAbsent,
    /// The times of the request are on a different clock domain or boot,
    /// or the request is from a time after the clock of the helper.
    #[error("the times of the request cannot be compared with the clock")]
    ClockNotComparable,

    /// The request is expired.
    #[error("the request is expired")]
    RequestExpired,
    /// The validity of the request is longer than the helper permits.
    #[error("the validity of the request is longer than the limit")]
    ValidityTooLong,
    /// The request has more entries than the ceiling.
    #[error("the request has more entries than the ceiling")]
    TargetCeiling,
    /// The work of the request is more bytes than the ceiling of one
    /// operation.
    #[error("the work is more bytes than the ceiling")]
    BytesCeiling,
    /// The work of the request is more items than the ceiling of one
    /// operation.
    #[error("the work is more items than the ceiling")]
    ItemsCeiling,
    /// The grant accepted its largest number of requests in the window.
    #[error("the rate ceiling of the grant is reached")]
    RateCeiling,
    /// The work of the request does not fit in the work ceiling of the
    /// window.
    #[error("the work does not fit in the rate ceiling of the grant")]
    RateWorkCeiling,
    /// A sum does not fit its type. The helper does not saturate.
    #[error("a sum of the limits does not fit its type")]
    ArithmeticOverflow,
    /// The record of consumed requests is full. The helper does not remove
    /// a record to make room.
    #[error("the record of consumed requests is full")]
    RecordFull,
    /// The user has the largest number of records that one user can have.
    #[error("the record quota of the user is reached")]
    RecordQuota,
}

impl RefusalReason {
    /// Each reason. A path reason is there one time, with one defect.
    pub const ALL: [Self; 35] = [
        Self::ProtocolMajor,
        Self::ProtocolMinor,
        Self::ContentNotEncodable,
        Self::ConflictingDuplicate,
        Self::RequestIdReused,
        Self::StepNotRecorded,
        Self::RuleNotSupported,
        Self::NoTarget,
        Self::TargetPath(PathDefect::ParentDirectory),
        Self::ObjectType,
        Self::DuplicateTarget,
        Self::ChargeWithoutItem,
        Self::ValidityEmpty,
        Self::CallerNotPermitted,
        Self::RoleNotPermitted,
        Self::GrantUnknown,
        Self::GrantGenerationStale,
        Self::GrantGenerationUnknown,
        Self::GrantRevoked,
        Self::GrantExpired,
        Self::GrantExpiresBeforeRequest,
        Self::RootNotGranted,
        Self::GrantDoesNotCover,
        Self::ObjectEvidenceAbsent,
        Self::ClockNotComparable,
        Self::RequestExpired,
        Self::ValidityTooLong,
        Self::TargetCeiling,
        Self::BytesCeiling,
        Self::ItemsCeiling,
        Self::RateCeiling,
        Self::RateWorkCeiling,
        Self::ArithmeticOverflow,
        Self::RecordFull,
        Self::RecordQuota,
    ];

    /// The error family of the reason.
    pub fn family(&self) -> ErrorFamily {
        match self {
            Self::ProtocolMajor
            | Self::ProtocolMinor
            | Self::ContentNotEncodable
            | Self::ConflictingDuplicate
            | Self::RequestIdReused
            | Self::StepNotRecorded
            | Self::RuleNotSupported
            | Self::NoTarget
            | Self::TargetPath(_)
            | Self::ObjectType
            | Self::DuplicateTarget
            | Self::ChargeWithoutItem
            | Self::ValidityEmpty => ErrorFamily::Request,
            Self::CallerNotPermitted
            | Self::RoleNotPermitted
            | Self::GrantUnknown
            | Self::GrantGenerationStale
            | Self::GrantGenerationUnknown
            | Self::GrantRevoked
            | Self::GrantExpired
            | Self::GrantExpiresBeforeRequest
            | Self::RootNotGranted
            | Self::GrantDoesNotCover => ErrorFamily::Authority,
            Self::ObjectEvidenceAbsent | Self::ClockNotComparable => ErrorFamily::Evidence,
            Self::RequestExpired
            | Self::ValidityTooLong
            | Self::TargetCeiling
            | Self::BytesCeiling
            | Self::ItemsCeiling
            | Self::RateCeiling
            | Self::RateWorkCeiling
            | Self::ArithmeticOverflow
            | Self::RecordFull
            | Self::RecordQuota => ErrorFamily::Limits,
        }
    }

    /// The stable code of the reason: lower-case letters, digits, and `_`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProtocolMajor => "helper_protocol_major_mismatch",
            Self::ProtocolMinor => "helper_protocol_minor_unsupported",
            Self::ContentNotEncodable => "helper_request_not_encodable",
            Self::ConflictingDuplicate => "helper_conflicting_duplicate",
            Self::RequestIdReused => "helper_request_id_reused",
            Self::StepNotRecorded => "helper_step_not_recorded",
            Self::RuleNotSupported => "helper_rule_not_supported",
            Self::NoTarget => "helper_no_target",
            Self::TargetPath(_) => "helper_target_path_not_permitted",
            Self::ObjectType => "helper_object_type_unsupported",
            Self::DuplicateTarget => "helper_duplicate_target",
            Self::ChargeWithoutItem => "helper_charge_without_item",
            Self::ValidityEmpty => "helper_validity_empty",
            Self::CallerNotPermitted => "helper_caller_not_permitted",
            Self::RoleNotPermitted => "helper_role_not_permitted",
            Self::GrantUnknown => "helper_grant_unknown",
            Self::GrantGenerationStale => "helper_grant_generation_stale",
            Self::GrantGenerationUnknown => "helper_grant_generation_unknown",
            Self::GrantRevoked => "helper_grant_revoked",
            Self::GrantExpired => "helper_grant_expired",
            Self::GrantExpiresBeforeRequest => "helper_grant_expires_before_request",
            Self::RootNotGranted => "helper_root_not_granted",
            Self::GrantDoesNotCover => "helper_grant_does_not_cover",
            Self::ObjectEvidenceAbsent => "helper_object_evidence_absent",
            Self::ClockNotComparable => "helper_clock_not_comparable",
            Self::RequestExpired => "helper_request_expired",
            Self::ValidityTooLong => "helper_validity_too_long",
            Self::TargetCeiling => "helper_target_ceiling",
            Self::BytesCeiling => "helper_bytes_ceiling",
            Self::ItemsCeiling => "helper_items_ceiling",
            Self::RateCeiling => "helper_rate_ceiling",
            Self::RateWorkCeiling => "helper_rate_work_ceiling",
            Self::ArithmeticOverflow => "helper_arithmetic_overflow",
            Self::RecordFull => "helper_record_full",
            Self::RecordQuota => "helper_record_quota",
        }
    }
}

impl From<ProtocolMismatch> for RefusalReason {
    fn from(mismatch: ProtocolMismatch) -> Self {
        match mismatch {
            ProtocolMismatch::Major => Self::ProtocolMajor,
            ProtocolMismatch::Minor => Self::ProtocolMinor,
        }
    }
}

/// A refused request. The helper accepted nothing and consumed no step.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the helper refused the request: {reason}")]
pub struct Refusal {
    /// The reason.
    pub reason: RefusalReason,
    /// The plan, the operation, and the step of the refused request.
    pub correlation: StepCorrelation,
}

impl Refusal {
    /// The refusal as an error of the action contract. The stage is
    /// admission, and no call was submitted.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCodeError`] when the code of the reason is not a
    /// permitted error code. Each code of this build is permitted; a test
    /// checks each one.
    pub fn to_action_error(&self) -> Result<ActionError, ErrorCodeError> {
        Ok(ActionError {
            code: ErrorCode::new(self.reason.code())?,
            family: self.reason.family(),
            stage: ActionStage::Admission,
            dispatch: DispatchState::NotSubmitted,
            plan_id: Some(self.correlation.plan_id.clone()),
            operation_id: Some(self.correlation.operation_id.clone()),
            step_id: Some(self.correlation.step_id.clone()),
        })
    }
}
