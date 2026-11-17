//! The request envelope and the closed set of operations.

use serde::{Deserialize, Serialize};
use svalnir_core::action::{FileObjectType, WorkCharge};
use svalnir_core::authority::PrivilegeGrantRef;
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::id::{BootId, ClockDomainId, OperationId, PlanId, RequestId, RootId, StepId};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::MonotonicNanos;
use thiserror::Error;

/// The protocol major version of this build. `docs/INTERFACES.md` section 2
/// proposes 1 as the initial major version.
pub const PROTOCOL_MAJOR: u16 = 1;

/// The largest protocol minor version of this build.
pub const PROTOCOL_MINOR: u16 = 0;

/// The largest number of entries in one request: the ceiling of explicit
/// target references of `docs/INTERFACES.md` section 9. A grant can set a
/// smaller ceiling and cannot set a larger one.
pub const MAX_TARGETS_PER_REQUEST: usize = 128;

/// A protocol version. JSON encodes each part as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    /// The major version. A different major version is not compatible.
    pub major: u16,
    /// The minor version.
    pub minor: u16,
}

/// The reason a protocol version is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolMismatch {
    /// The major version is not the major version of the helper.
    #[error("the protocol major version is not supported")]
    Major,
    /// The minor version is later than the latest one of the helper. The
    /// helper did not negotiate it and does not downgrade a request.
    #[error("the protocol minor version is later than the supported one")]
    Minor,
}

/// The protocol versions that the helper supports: one major version and
/// each minor version up to a maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SupportedProtocols {
    /// The supported major version.
    pub major: u16,
    /// The latest supported minor version.
    pub max_minor: u16,
}

impl SupportedProtocols {
    /// The versions of this build.
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        max_minor: PROTOCOL_MINOR,
    };

    /// Checks that the helper supports `version`.
    ///
    /// # Errors
    ///
    /// Returns a [`ProtocolMismatch`] when the major version is different or
    /// the minor version is later than the supported one.
    pub fn check(&self, version: ProtocolVersion) -> Result<(), ProtocolMismatch> {
        if version.major != self.major {
            return Err(ProtocolMismatch::Major);
        }
        if version.minor > self.max_minor {
            return Err(ProtocolMismatch::Minor);
        }
        Ok(())
    }
}

/// The plan, the operation, and the step that a request belongs to.
///
/// `operation_id` is the operation of the agent: the parent operation of
/// the delegated step. The helper deduplicates by the authenticated user,
/// this operation, and the step. An identity correlates records; it is not
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepCorrelation {
    /// The plan.
    pub plan_id: PlanId,
    /// The digest of the plan content.
    pub plan_digest: ContentDigest,
    /// The operation of the agent that delegates the step.
    pub operation_id: OperationId,
    /// The delegated step.
    pub step_id: StepId,
}

/// The time for which a request is valid, on the monotonic timeline of one
/// clock domain and one boot.
///
/// The clock domain and the boot name the timeline of the two times. They
/// are not evidence: the helper compares them with its own clock and
/// refuses a request of a different timeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestValidity {
    /// The clock domain of the two monotonic times.
    pub clock_domain: ClockDomainId,
    /// The boot of the two monotonic times.
    pub boot_id: BootId,
    /// The monotonic time at which the agent made the request.
    pub issued_at: MonotonicNanos,
    /// The monotonic time at which the request expires. The helper does
    /// not accept the request at this time or after it.
    pub expires_at: MonotonicNanos,
}

/// One entry to remove, relative to the approved root of the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryTarget {
    /// The entry, relative to the root. The helper splits it into names
    /// and refuses an absolute path, an empty name, `.`, and `..`.
    pub relative_entry: LosslessPath,
    /// The type of the object that the agent observed.
    pub object_type: FileObjectType,
    /// The native identifiers that the agent observed. `None` means that
    /// the evidence is absent, and the helper refuses such an entry. The
    /// value can only narrow the operation: the executor does not remove
    /// an object with different identifiers.
    pub object: Option<FileObjectEvidence>,
    /// The conservative bound of the work of this entry. The helper adds
    /// the bounds and compares the sum with its own ceilings. The executor
    /// does not remove an entry that is larger than its bound.
    pub charge: WorkCharge,
}

/// Permanent removal of listed entries below one approved root.
///
/// The root is helper-owned data or a reviewed administrator-controlled
/// disposable namespace that the privilege grant lists. The request names
/// the root by its identity. The path of the root comes from the record of
/// the helper, not from the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictEntries {
    /// The privilege grant and the generation that the plan was built
    /// with. The helper compares the reference with its current record; the
    /// reference gives no authority.
    pub grant: PrivilegeGrantRef,
    /// The approved root.
    pub root_id: RootId,
    /// The rule revision that selected the entries. The helper accepts
    /// only a revision that its record lists for the root.
    pub rule: RuleRef,
    /// The entries. One request has 1 to [`MAX_TARGETS_PER_REQUEST`]
    /// entries, each one time.
    pub entries: Vec<EntryTarget>,
}

/// A query of the recorded state of the step that the correlation names.
/// The operation has no field and no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryStepStatus {}

/// The closed set of operations.
///
/// JSON encodes the value as an object with one field: the name of the
/// operation in lower-case snake case. Decoding rejects an unknown name.
/// The set has no variant for a value that this build does not recognize.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperOperation {
    /// Permanent removal of listed entries below one approved root.
    EvictEntries(EvictEntries),
    /// A query of the recorded state of the step.
    QueryStepStatus(QueryStepStatus),
}

/// The kind of an operation, without its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationKind {
    /// [`HelperOperation::EvictEntries`].
    EvictEntries,
    /// [`HelperOperation::QueryStepStatus`].
    QueryStepStatus,
}

impl HelperOperation {
    /// The kind of the operation.
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::EvictEntries(_) => OperationKind::EvictEntries,
            Self::QueryStepStatus(_) => OperationKind::QueryStepStatus,
        }
    }
}

impl OperationKind {
    /// Each kind, in the sequence of the declaration.
    pub const ALL: [Self; 2] = [Self::EvictEntries, Self::QueryStepStatus];

    /// Whether the operation changes the host.
    pub fn is_mutation(self) -> bool {
        match self {
            Self::EvictEntries => true,
            Self::QueryStepStatus => false,
        }
    }
}

/// One request to the helper: one delegated step.
///
/// The request has no field for the user, the process, or the role of the
/// caller. Those values are in the
/// [`CallerIdentity`](super::CallerIdentity) that the transport makes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    /// The protocol version of the request.
    pub protocol: ProtocolVersion,
    /// The correlation identity of the transport exchange. It is not a
    /// deduplication boundary: a new value does not make the effect of a
    /// consumed step executable again.
    pub request_id: RequestId,
    /// The plan, the operation, and the step.
    pub correlation: StepCorrelation,
    /// The validity of the request.
    pub validity: RequestValidity,
    /// The operation.
    pub operation: HelperOperation,
}
