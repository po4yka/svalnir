//! The error codes of the filesystem executor and the mapping from an
//! error number to an error family.
//!
//! `docs/ACTION_CONTRACTS.md` section 10 owns the families. A family states
//! the contract boundary that failed; it is not reduced to a permission
//! failure. An error number of a mutation call is not always proof of no
//! effect: [`mutation_verdict`] separates the definite failures from the
//! results that need an observation.

use svalnir_core::action::{
    ActionError, ActionStage, DispatchState, ErrorCode, ErrorCodeError, ErrorFamily,
    RequestEnvelope,
};

/// The stable error codes of the filesystem executor.
pub mod code {
    /// The relative entry is absolute or has an empty component, a `.`, or
    /// a `..`.
    pub const RELATIVE_ENTRY_INVALID: &str = "relative_entry_invalid";
    /// The object type of the binding is one that this build does not
    /// recognize.
    pub const OBJECT_TYPE_UNRECOGNIZED: &str = "object_type_unrecognized";
    /// The action class is one that this executor does not do.
    pub const ACTION_CLASS_UNSUPPORTED: &str = "action_class_unsupported";
    /// The effective user of the process is not the principal of the
    /// request.
    pub const PRINCIPAL_MISMATCH: &str = "principal_mismatch";
    /// The root of the target is not an approved root.
    pub const OUTSIDE_APPROVED_ROOTS: &str = "outside_approved_roots";
    /// The approved root with the identity of the target does not have
    /// the path and the object that the plan binds for the root.
    pub const APPROVED_ROOT_MISMATCH: &str = "approved_root_mismatch";
    /// The target is the home directory or a directory that contains it.
    pub const HOME_DIRECTORY_PROTECTED: &str = "home_directory_protected";
    /// The target is the approved root itself.
    pub const APPROVED_ROOT_IS_TARGET: &str = "approved_root_is_target";
    /// The object is not a regular file, a directory, or a symbolic link.
    pub const UNSUPPORTED_FILE_TYPE: &str = "unsupported_file_type";
    /// A directory is a dataless placeholder. To read it starts a
    /// download.
    pub const DATALESS_DIRECTORY: &str = "dataless_directory";
    /// The binding has no device and inode evidence.
    pub const IDENTITY_EVIDENCE_ABSENT: &str = "identity_evidence_absent";
    /// The volume or the mount generation of the binding is not that of
    /// the approved root.
    pub const VOLUME_MISMATCH: &str = "volume_mismatch";
    /// The device of the target is not the device of the approved root.
    pub const DEVICE_MISMATCH: &str = "device_mismatch";
    /// The approved root is absent.
    pub const ROOT_UNAVAILABLE: &str = "root_unavailable";
    /// The mount flags report the filesystem of the approved root as not
    /// local: a network filesystem or an automounter map.
    pub const ROOT_NOT_LOCAL: &str = "root_not_local";
    /// The mount table cannot be read, or it has no mount for the path or
    /// the device of the approved root.
    pub const ROOT_LOCALITY_UNKNOWN: &str = "root_locality_unknown";
    /// The device or the inode of the approved root changed, or a
    /// component of its path is a symbolic link or is not a directory.
    pub const ROOT_IDENTITY_CHANGED: &str = "root_identity_changed";
    /// A component between the root and the target is a symbolic link or
    /// is not a directory.
    pub const PARENT_NOT_DIRECTORY: &str = "parent_not_directory";
    /// A component between the root and the target, or an entry of the
    /// tree, is on another device: a mount point.
    pub const MOUNT_CROSSED: &str = "mount_crossed";
    /// The inode of the target is not the inode of the plan.
    pub const TARGET_IDENTITY_CHANGED: &str = "target_identity_changed";
    /// The type of the target is not the type of the plan.
    pub const TARGET_TYPE_CHANGED: &str = "target_type_changed";
    /// The owner of the target is not the owner of the plan.
    pub const TARGET_OWNER_CHANGED: &str = "target_owner_changed";
    /// An entry of a directory target changed between the measurement of
    /// the tree and its removal.
    pub const TREE_CHANGED: &str = "tree_changed";
    /// An entry of a directory target has another owner than the target.
    pub const TREE_ENTRY_OWNER_MISMATCH: &str = "tree_entry_owner_mismatch";
    /// The directory target has more nested levels than the limit.
    pub const TREE_DEPTH_LIMIT: &str = "tree_depth_limit";
    /// The directory target has more entries than the limit.
    pub const TREE_ENTRY_LIMIT: &str = "tree_entry_limit";
    /// The directory target needs more open descriptors than the limit.
    pub const DESCRIPTOR_LIMIT: &str = "descriptor_limit";
    /// The process or the system has no free descriptor.
    pub const DESCRIPTORS_EXHAUSTED: &str = "descriptors_exhausted";
    /// The system has no memory for the call.
    pub const OUT_OF_MEMORY: &str = "out_of_memory";
    /// The entry is absent.
    pub const ENTRY_ABSENT: &str = "entry_absent";
    /// `EACCES`.
    pub const PERMISSION_DENIED: &str = "permission_denied";
    /// `EPERM`.
    pub const OPERATION_NOT_PERMITTED: &str = "operation_not_permitted";
    /// `EROFS`.
    pub const READ_ONLY_FILESYSTEM: &str = "read_only_filesystem";
    /// `EBUSY`.
    pub const RESOURCE_BUSY: &str = "resource_busy";
    /// `ENOTEMPTY` or `EEXIST`.
    pub const DIRECTORY_NOT_EMPTY: &str = "directory_not_empty";
    /// `ENOTDIR`.
    pub const NOT_A_DIRECTORY: &str = "not_a_directory";
    /// `EISDIR`.
    pub const IS_A_DIRECTORY: &str = "is_a_directory";
    /// `ELOOP`.
    pub const SYMBOLIC_LINK_IN_PATH: &str = "symbolic_link_in_path";
    /// `ENAMETOOLONG`.
    pub const NAME_TOO_LONG: &str = "name_too_long";
    /// `ENOSPC`.
    pub const NO_SPACE: &str = "no_space";
    /// `EDQUOT`.
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    /// A regular file is a dataless placeholder (`SF_DATALESS`), as a target
    /// or as an entry of a directory target, and gets no removal call: in
    /// a File Provider or iCloud Drive domain, the removal of a placeholder
    /// can remove the copy in the cloud. Also `EDEADLK`: the object is
    /// dataless and the thread does not materialize it.
    pub const DATALESS_OBJECT: &str = "dataless_object";
    /// The target, its parent directory, or an entry of a directory target
    /// has a flag that prevents its removal or the removal of its entries
    /// (`uchg`, `uappnd`, `schg`, `sappnd`, or `restricted`). The target
    /// gets no call, so that the removal does not stop after a part of a
    /// tree.
    pub const LOCKED_OBJECT: &str = "locked_object";
    /// A target of a permanent removal is larger than the work charge of
    /// its binding: its allocated bytes, or for a directory its number of
    /// entries. The plan does not authorize the entries or the data that
    /// appeared after it was made.
    pub const TARGET_GREW: &str = "target_grew";
    /// A regular file of an eviction, or a regular file in a directory
    /// target of an eviction, has more than one name. Its removal frees no
    /// space while another name keeps the data.
    pub const TARGET_HARD_LINKED: &str = "target_hard_linked";
    /// A directory target of an eviction has a Git marker (`.git`) at some
    /// depth. A repository can hold commits and changes that exist nowhere
    /// else, so no build makes it again.
    pub const NESTED_REPOSITORY: &str = "nested_repository";
    /// `EINTR`.
    pub const INTERRUPTED: &str = "interrupted";
    /// `EIO`.
    pub const IO_ERROR: &str = "io_error";
    /// `ETIMEDOUT`.
    pub const TIMED_OUT: &str = "timed_out";
    /// `ESTALE`.
    pub const STALE_HANDLE: &str = "stale_handle";
    /// An error number that the executor has no specific code for, or a
    /// failure with no error number.
    pub const NATIVE_ERROR: &str = "native_error";
    /// The observation after a call did not establish its effect.
    pub const OUTCOME_UNVERIFIED: &str = "outcome_unverified";
    /// The Trash backend does not support the target.
    pub const TRASH_UNSUPPORTED: &str = "trash_unsupported";
    /// The Trash backend failed with no error number.
    pub const TRASH_FAILED: &str = "trash_failed";
    /// The Trash backend gave no result.
    pub const TRASH_RESULT_UNKNOWN: &str = "trash_result_unknown";
    /// The item that the Trash backend moved is not the object of the
    /// plan.
    pub const TRASH_ITEM_IDENTITY_MISMATCH: &str = "trash_item_identity_mismatch";

    /// The batch has more steps than the limit.
    pub const BATCH_LIMIT: &str = "batch_limit";

    /// Each code of the executor.
    pub const ALL: [&str; 57] = [
        LOCKED_OBJECT,
        TARGET_GREW,
        TARGET_HARD_LINKED,
        NESTED_REPOSITORY,
        APPROVED_ROOT_MISMATCH,
        TREE_ENTRY_OWNER_MISMATCH,
        BATCH_LIMIT,
        TRASH_ITEM_IDENTITY_MISMATCH,
        RELATIVE_ENTRY_INVALID,
        OBJECT_TYPE_UNRECOGNIZED,
        ACTION_CLASS_UNSUPPORTED,
        PRINCIPAL_MISMATCH,
        OUTSIDE_APPROVED_ROOTS,
        HOME_DIRECTORY_PROTECTED,
        APPROVED_ROOT_IS_TARGET,
        UNSUPPORTED_FILE_TYPE,
        DATALESS_DIRECTORY,
        IDENTITY_EVIDENCE_ABSENT,
        VOLUME_MISMATCH,
        DEVICE_MISMATCH,
        ROOT_UNAVAILABLE,
        ROOT_NOT_LOCAL,
        ROOT_LOCALITY_UNKNOWN,
        ROOT_IDENTITY_CHANGED,
        PARENT_NOT_DIRECTORY,
        MOUNT_CROSSED,
        TARGET_IDENTITY_CHANGED,
        TARGET_TYPE_CHANGED,
        TARGET_OWNER_CHANGED,
        TREE_CHANGED,
        TREE_DEPTH_LIMIT,
        TREE_ENTRY_LIMIT,
        DESCRIPTOR_LIMIT,
        DESCRIPTORS_EXHAUSTED,
        OUT_OF_MEMORY,
        ENTRY_ABSENT,
        PERMISSION_DENIED,
        OPERATION_NOT_PERMITTED,
        READ_ONLY_FILESYSTEM,
        RESOURCE_BUSY,
        DIRECTORY_NOT_EMPTY,
        NOT_A_DIRECTORY,
        IS_A_DIRECTORY,
        SYMBOLIC_LINK_IN_PATH,
        NAME_TOO_LONG,
        NO_SPACE,
        QUOTA_EXCEEDED,
        DATALESS_OBJECT,
        INTERRUPTED,
        IO_ERROR,
        TIMED_OUT,
        STALE_HANDLE,
        NATIVE_ERROR,
        OUTCOME_UNVERIFIED,
        TRASH_UNSUPPORTED,
        TRASH_FAILED,
        TRASH_RESULT_UNKNOWN,
    ];
}

/// The family and the code of one error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Cause {
    pub(super) family: ErrorFamily,
    pub(super) code: &'static str,
}

impl Cause {
    pub(super) const fn new(family: ErrorFamily, code: &'static str) -> Self {
        Self { family, code }
    }

    pub(super) const fn request(code: &'static str) -> Self {
        Self::new(ErrorFamily::Request, code)
    }

    pub(super) const fn authority(code: &'static str) -> Self {
        Self::new(ErrorFamily::Authority, code)
    }

    pub(super) const fn evidence(code: &'static str) -> Self {
        Self::new(ErrorFamily::Evidence, code)
    }

    pub(super) const fn eligibility(code: &'static str) -> Self {
        Self::new(ErrorFamily::Eligibility, code)
    }

    pub(super) const fn limits(code: &'static str) -> Self {
        Self::new(ErrorFamily::Limits, code)
    }

    pub(super) const fn native(code: &'static str) -> Self {
        Self::new(ErrorFamily::Native, code)
    }

    pub(super) const fn outcome(code: &'static str) -> Self {
        Self::new(ErrorFamily::Outcome, code)
    }

    /// Makes the error record of the action contract.
    pub(super) fn to_action_error(
        &self,
        stage: ActionStage,
        dispatch: DispatchState,
        envelope: &RequestEnvelope,
    ) -> Result<ActionError, ErrorCodeError> {
        Ok(ActionError {
            code: ErrorCode::new(self.code)?,
            family: self.family.clone(),
            stage,
            dispatch,
            plan_id: Some(envelope.correlation.plan_id.clone()),
            operation_id: Some(envelope.correlation.operation_id.clone()),
            step_id: Some(envelope.correlation.step_id.clone()),
        })
    }
}

/// The cause of an error number of a call. `None` is a failure with no
/// error number.
///
/// The `outcome` family is for the error numbers after which the effect of
/// a mutation call is not established: an interrupted call, an I/O error,
/// a timeout, a stale handle, and each number that the table does not
/// have.
fn cause_of_errno(errno: Option<i32>) -> Cause {
    match errno {
        Some(libc::EACCES) => Cause::native(code::PERMISSION_DENIED),
        Some(libc::EPERM) => Cause::native(code::OPERATION_NOT_PERMITTED),
        Some(libc::EROFS) => Cause::native(code::READ_ONLY_FILESYSTEM),
        Some(libc::EBUSY) => Cause::native(code::RESOURCE_BUSY),
        Some(libc::ENOTEMPTY | libc::EEXIST) => Cause::native(code::DIRECTORY_NOT_EMPTY),
        Some(libc::ENOTDIR) => Cause::native(code::NOT_A_DIRECTORY),
        Some(libc::EISDIR) => Cause::native(code::IS_A_DIRECTORY),
        Some(libc::ELOOP) => Cause::native(code::SYMBOLIC_LINK_IN_PATH),
        Some(libc::ENAMETOOLONG) => Cause::native(code::NAME_TOO_LONG),
        Some(libc::ENOSPC) => Cause::native(code::NO_SPACE),
        Some(libc::EDQUOT) => Cause::native(code::QUOTA_EXCEEDED),
        Some(libc::EDEADLK) => Cause::eligibility(code::DATALESS_OBJECT),
        Some(libc::EMFILE | libc::ENFILE) => Cause::limits(code::DESCRIPTORS_EXHAUSTED),
        Some(libc::ENOMEM) => Cause::limits(code::OUT_OF_MEMORY),
        Some(libc::ENOENT) => Cause::evidence(code::ENTRY_ABSENT),
        Some(libc::EINTR) => Cause::outcome(code::INTERRUPTED),
        Some(libc::EIO) => Cause::outcome(code::IO_ERROR),
        Some(libc::ETIMEDOUT) => Cause::outcome(code::TIMED_OUT),
        Some(libc::ESTALE) => Cause::outcome(code::STALE_HANDLE),
        _ => Cause::outcome(code::NATIVE_ERROR),
    }
}

/// The cause of a failed read-only call: `open`, `fstat`, `fstatat`, or
/// `readdir`. A read-only call has no effect on the target, so a result
/// that the table gives to the `outcome` family is a `native` failure
/// here.
pub(super) fn read_cause(errno: Option<i32>) -> Cause {
    let cause: Cause = cause_of_errno(errno);
    if matches!(cause.family, ErrorFamily::Outcome) {
        Cause::native(cause.code)
    } else {
        cause
    }
}

/// What an error number of a mutation call establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CallVerdict {
    /// `ENOENT`: the entry was absent when the call ran.
    Absent,
    /// The call definitely had no effect.
    NoEffect(Cause),
    /// The error number does not establish the effect. The caller observes
    /// the entry; it does not repeat the call.
    Indeterminate(Cause),
}

/// The verdict for the error number of an `unlinkat` call or of a Trash
/// backend.
pub(super) fn mutation_verdict(errno: Option<i32>) -> CallVerdict {
    if errno == Some(libc::ENOENT) {
        return CallVerdict::Absent;
    }
    let cause: Cause = cause_of_errno(errno);
    if matches!(cause.family, ErrorFamily::Outcome) {
        CallVerdict::Indeterminate(cause)
    } else {
        CallVerdict::NoEffect(cause)
    }
}
