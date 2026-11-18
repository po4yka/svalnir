//! The typed operations of the helper.
//!
//! A request is one delegated step. It has a transport correlation
//! identity, the protocol version, the plan, operation, and step that it
//! belongs to, its validity, and one operation of a closed set. No request
//! has shell text, a script body, a caller-chosen executable, an
//! unrestricted root path, or a statement that a target was approved.
//!
//! # The operation set
//!
//! | Operation | Effect | Source |
//! | --- | --- | --- |
//! | [`HelperOperation::EvictEntries`] | Permanent removal of listed entries below one approved root of the grant: helper-owned data or a reviewed administrator-controlled disposable namespace. The action class is `EvictRegenerableData`. | `docs/THREAT_MODEL.md` section 4.2, `docs/ACTION_CONTRACTS.md` section 7 ("Shared preconditions"), `docs/CLEANUP_RULES.md` ("Initial root-executed cleanup") |
//! | [`HelperOperation::QueryStepStatus`] | No effect. Returns the recorded state of a delegated step after a lost reply. | `docs/INTERFACES.md` sections 10 and 12, `docs/ACTION_CONTRACTS.md` section 11 |
//!
//! The specifications permit no other operation at this boundary:
//!
//! - `MoveToTrash` and `DeleteSelectedFiles` use the privileges of the
//!   owning user. The helper is not a root deletion override
//!   (`docs/ACTION_CONTRACTS.md` section 7).
//! - The initial process-control surface has the user executor only
//!   (`docs/ACTION_CONTRACTS.md` section 3). Thus the critical-memory
//!   exception of the journal does not apply to a helper step.
//! - The enrollment and the expansion of a grant are a separate
//!   administrative flow (`docs/INTERFACES.md` section 10). They are not a
//!   request of the agent.
//! - The host lease broker (`docs/ARCHITECTURE.md` section 3) has no request
//!   contract in an owning specification. Milestone 2 uses the single-user
//!   mutation mode, which `docs/THREAT_MODEL.md` (`T-13`) permits.
//!
//! # The identity of the caller
//!
//! [`CallerIdentity`] is not a part of the request. Only the transport of
//! this crate can make it, from the code-signing identity, the audited
//! user, and the login session of the live connection. A request body has
//! no field for a user ID, a session, or a process ID, and decoding rejects
//! a body that has one.
//!
//! # The encoded form
//!
//! [`decode_request`] decodes the JSON form. It rejects an unknown
//! operation, an unknown field at each level, a value that is not in its
//! one canonical encoding, and an encoded form over the size or the nesting
//! limit. `docs/INTERFACES.md` section 9 does not require JSON at the
//! privileged boundary. A typed transport can make a [`HelperRequest`]
//! directly; the validation is the same.
//!
//! Owning specifications: `docs/INTERFACES.md` sections 9, 10, and 12, and
//! `docs/ACTION_CONTRACTS.md` sections 3 and 11.

mod decode;
mod identity;
mod operation;

pub use decode::{DecodeError, MAX_ENCODED_REQUEST_BYTES, MAX_NESTING_DEPTH, decode_request};
pub use identity::{
    CallerIdentity, CodeIdentity, CodeIdentityError, LoginSessionId, MAX_CODE_IDENTITY_BYTES,
};
pub use operation::{
    EntryTarget, EvictEntries, HelperOperation, HelperRequest, MAX_TARGETS_PER_REQUEST,
    OperationKind, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolMismatch, ProtocolVersion,
    QueryStepStatus, RequestValidity, StepCorrelation, SupportedProtocols,
};
