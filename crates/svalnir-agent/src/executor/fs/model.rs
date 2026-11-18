//! The public types of the filesystem executor.

use std::collections::BTreeMap;
use std::ffi::CString;

use svalnir_core::action::{
    ActionClass, DispatchConsumption, DispatchReceipt, DispatchState, Durability, ErrorCodeError,
    ExecutorRole, FileBinding, MAX_PLAN_TARGETS, OutcomeError, RequestEnvelope, StopReason,
    TargetBinding, TargetResult,
};
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::id::{MountId, RootId, TargetId, VolumeId};
use svalnir_core::quantity::{Bytes, EntryCount};
use thiserror::Error;

/// The largest number of approved roots in one [`ApprovedRoots`] set.
pub const MAX_APPROVED_ROOTS: usize = 256;

/// The largest permitted value of [`ExecutorLimits::max_tree_depth`].
pub const MAX_TREE_DEPTH_LIMIT: u32 = 128;

/// The largest permitted value of [`ExecutorLimits::max_tree_entries`].
pub const MAX_TREE_ENTRIES_LIMIT: u64 = 1_000_000;

/// The smallest permitted value of
/// [`ExecutorLimits::max_open_descriptors`]: the walk to a target holds two
/// descriptors, and a directory target needs one more.
pub const MIN_OPEN_DESCRIPTORS: u32 = 3;

/// The largest permitted value of
/// [`ExecutorLimits::max_open_descriptors`].
pub const MAX_OPEN_DESCRIPTORS_LIMIT: u32 = 1024;

/// The largest number of steps in one batch: the largest number of targets
/// of one plan.
pub const MAX_BATCH_STEPS: usize = MAX_PLAN_TARGETS;

/// Splits a path into its components.
///
/// Returns `None` when a component is empty, is `.`, or is `..`, when the
/// path has no component, or when the leading `/` does not agree with
/// `absolute`. A trailing `/` and a repeated `/` give an empty component.
pub(super) fn path_components(bytes: &[u8], absolute: bool) -> Option<Vec<CString>> {
    let relative: &[u8] = match (bytes.strip_prefix(b"/"), absolute) {
        (Some(rest), true) => rest,
        (None, false) => bytes,
        _ => return None,
    };
    if relative.is_empty() {
        return None;
    }
    relative
        .split(|byte| *byte == b'/')
        .map(|component| {
            if component.is_empty() || component == b"." || component == b".." {
                None
            } else {
                CString::new(component).ok()
            }
        })
        .collect()
}

/// One approved root: a directory that file targets must stay under, with
/// the identity evidence that the agent holds for it.
///
/// The foundation types have the identity of a root ([`RootId`]) in a
/// [`FileBinding`] and no record of the root itself. This type is that
/// record for the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedRoot {
    /// The identity of the root, as a [`FileBinding`] names it.
    pub root_id: RootId,
    /// The absolute path of the root directory. The path has no `.`, no
    /// `..`, no empty component, and no symbolic link: the executor opens
    /// each component with no-follow protection.
    pub path: LosslessPath,
    /// The device and the inode of the root directory.
    pub object: FileObjectEvidence,
    /// The volume of the root.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
}

/// The reason a set of approved roots was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RootError {
    /// The set has more than [`MAX_APPROVED_ROOTS`] roots.
    #[error("the set has more approved roots than the limit")]
    TooMany,
    /// Two roots have the same identity.
    #[error("two approved roots have the same identity")]
    Duplicate,
    /// The path of a root is not absolute, is `/`, or has an empty
    /// component, a `.`, or a `..`.
    #[error("the path of an approved root is not an absolute normalized path below `/`")]
    Path,
}

/// A root with its path components.
#[derive(Debug, Clone)]
pub(super) struct AnchoredRoot {
    pub(super) root: ApprovedRoot,
    pub(super) components: Vec<CString>,
}

/// The approved roots that the executor can act under.
///
/// A target whose root is not in the set is refused.
#[derive(Debug, Clone, Default)]
pub struct ApprovedRoots {
    roots: BTreeMap<RootId, AnchoredRoot>,
}

impl ApprovedRoots {
    /// Makes the set.
    ///
    /// # Errors
    ///
    /// Returns a [`RootError`] when the set is too large, when two roots
    /// have the same identity, or when a path is not an absolute normalized
    /// path below `/`.
    pub fn new(roots: Vec<ApprovedRoot>) -> Result<Self, RootError> {
        if roots.len() > MAX_APPROVED_ROOTS {
            return Err(RootError::TooMany);
        }
        let mut anchored: BTreeMap<RootId, AnchoredRoot> = BTreeMap::new();
        for root in roots {
            let components: Vec<CString> =
                path_components(root.path.as_bytes(), true).ok_or(RootError::Path)?;
            let root_id: RootId = root.root_id.clone();
            if anchored
                .insert(root_id, AnchoredRoot { root, components })
                .is_some()
            {
                return Err(RootError::Duplicate);
            }
        }
        Ok(Self { roots: anchored })
    }

    /// The root with the identity `root_id`.
    pub fn root(&self, root_id: &RootId) -> Option<&ApprovedRoot> {
        self.roots.get(root_id).map(|anchored| &anchored.root)
    }

    /// The number of roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the set has no root.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub(super) fn anchored(&self, root_id: &RootId) -> Option<&AnchoredRoot> {
        self.roots.get(root_id)
    }
}

/// The reason a limit set was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a limit of the filesystem executor is zero or is larger than its maximum")]
pub struct LimitsError;

/// The bounds of the removal of one directory target.
///
/// A directory tree that does not fit the bounds is not removed in part:
/// the executor measures the tree first and skips the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorLimits {
    tree_depth: u32,
    tree_entries: u64,
    open_descriptors: u32,
}

impl ExecutorLimits {
    /// Makes the limits.
    ///
    /// `max_tree_depth` is the largest number of nested directory levels of
    /// one target, the target directory included. `max_tree_entries` is the
    /// largest number of entries below one target directory.
    /// `max_open_descriptors` is the largest number of descriptors that the
    /// executor holds at one time.
    ///
    /// # Errors
    ///
    /// Returns a [`LimitsError`] when a value is zero, when
    /// `max_open_descriptors` is smaller than [`MIN_OPEN_DESCRIPTORS`], or
    /// when a value is larger than its maximum.
    pub fn new(
        max_tree_depth: u32,
        max_tree_entries: u64,
        max_open_descriptors: u32,
    ) -> Result<Self, LimitsError> {
        let depth_agrees: bool = (1..=MAX_TREE_DEPTH_LIMIT).contains(&max_tree_depth);
        let entries_agree: bool = (1..=MAX_TREE_ENTRIES_LIMIT).contains(&max_tree_entries);
        let descriptors_agree: bool =
            (MIN_OPEN_DESCRIPTORS..=MAX_OPEN_DESCRIPTORS_LIMIT).contains(&max_open_descriptors);
        if depth_agrees && entries_agree && descriptors_agree {
            Ok(Self {
                tree_depth: max_tree_depth,
                tree_entries: max_tree_entries,
                open_descriptors: max_open_descriptors,
            })
        } else {
            Err(LimitsError)
        }
    }

    /// The largest number of nested directory levels of one target.
    pub const fn max_tree_depth(&self) -> u32 {
        self.tree_depth
    }

    /// The largest number of entries below one target directory.
    pub const fn max_tree_entries(&self) -> u64 {
        self.tree_entries
    }

    /// The largest number of descriptors that the executor holds.
    pub const fn max_open_descriptors(&self) -> u32 {
        self.open_descriptors
    }
}

impl Default for ExecutorLimits {
    /// 32 directory levels, 100 000 entries, and 48 descriptors.
    fn default() -> Self {
        Self {
            tree_depth: 32,
            tree_entries: 100_000,
            open_descriptors: 48,
        }
    }
}

/// The configuration of a filesystem executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsExecutorConfig {
    /// The home directory of the user, as an absolute normalized path with
    /// no symbolic link. The executor refuses a target that is this
    /// directory or a directory that contains it.
    pub home_directory: LosslessPath,
    /// The bounds of a directory target.
    pub limits: ExecutorLimits,
}

/// The reason a configuration was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The home directory is not an absolute normalized path below `/`.
    #[error("the home directory is not an absolute normalized path below `/`")]
    HomeDirectory,
    /// The home directory cannot be opened from `/` one component at a
    /// time: a component is absent, is a symbolic link, or is not a
    /// directory. The executor needs the identity of the home directory to
    /// refuse it under each of its names.
    #[error("the home directory cannot be opened without a symbolic link")]
    HomeUnavailable,
}

/// The reason a step cannot be given to the executor. The executor issued
/// no call and made no target result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdmissionRefusal {
    /// The action class is not a filesystem class.
    #[error("the action class of the step is not a filesystem class")]
    ActionClass,
    /// The target is not a file target.
    #[error("the target of the step is not a file target")]
    Target,
    /// The executor of the step is not the executor of the owning user.
    #[error("the step is not a step of the user executor")]
    Executor,
    /// The receipt is not for a consumption by this caller: an earlier
    /// caller consumed the dispatch, or the operation has a stop fence.
    #[error("the dispatch of the step was not consumed by this caller")]
    NotConsumed,
    /// The intent and the dispatch consumption are not durable. A
    /// filesystem step always needs the durable journal.
    #[error("the record of the step is not durable")]
    NotDurable,
}

/// One step that the executor can do: a request envelope of a filesystem
/// class with the receipt that shows that the journal recorded the intent
/// and consumed the dispatch of the step.
///
/// The executor takes only this type, so a call without a receipt does not
/// compile, and a receipt that does not permit a submission makes no value.
/// [`DispatchReceipt`] names no step, so the type cannot show that the
/// receipt is the receipt of this envelope; the coordinator pairs them.
///
/// The value has no copy, and the executor takes it by value: one consumed
/// dispatch gives one call.
#[derive(Debug)]
pub struct AdmittedStep<'a> {
    envelope: &'a RequestEnvelope,
    file: &'a FileBinding,
    durability: &'a Durability,
}

impl<'a> AdmittedStep<'a> {
    /// Pairs an envelope with the receipt of its dispatch consumption.
    ///
    /// # Errors
    ///
    /// Returns an [`AdmissionRefusal`] when the envelope is not a
    /// filesystem step of the user executor, or when the receipt does not
    /// permit the submission of a filesystem call.
    pub fn new(
        envelope: &'a RequestEnvelope,
        receipt: &'a DispatchReceipt,
    ) -> Result<Self, AdmissionRefusal> {
        if !envelope.action_class.is_filesystem() {
            return Err(AdmissionRefusal::ActionClass);
        }
        let TargetBinding::File(file) = &envelope.target.binding else {
            return Err(AdmissionRefusal::Target);
        };
        if !matches!(envelope.executor, ExecutorRole::User) {
            return Err(AdmissionRefusal::Executor);
        }
        if !matches!(receipt.consumption, DispatchConsumption::Consumed) {
            return Err(AdmissionRefusal::NotConsumed);
        }
        // The rule of the journal contract, and then the rule of this
        // executor: a filesystem call follows a durable record only.
        let permitted: bool = receipt.permits_submission(
            &envelope.action_class,
            &envelope.trigger.class,
            &envelope.recording,
        );
        if !permitted || !receipt.durability.is_durable() {
            return Err(AdmissionRefusal::NotDurable);
        }
        Ok(Self {
            envelope,
            file,
            durability: &receipt.durability,
        })
    }

    /// The request envelope.
    pub fn envelope(&self) -> &'a RequestEnvelope {
        self.envelope
    }

    /// The file binding of the target.
    pub fn file(&self) -> &'a FileBinding {
        self.file
    }

    /// The action class.
    pub fn action_class(&self) -> &'a ActionClass {
        &self.envelope.action_class
    }

    /// The target.
    pub fn target_id(&self) -> &'a TargetId {
        &self.envelope.target.target_id
    }

    pub(super) fn durability(&self) -> &'a Durability {
        self.durability
    }
}

/// A reason to stop before the next target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stop {
    /// The operation was canceled, or it has a stop fence.
    Canceled,
    /// The agent or the policy was paused.
    Paused,
    /// The policy revision or a grant changed.
    PolicyChanged,
    /// The trigger of the automatic work cleared.
    TriggerCleared,
    /// The plan expired or the deadline passed.
    DeadlineExpired,
    /// The necessary authority is missing.
    AuthorityMissing,
}

impl Stop {
    /// The stop reason of a target result.
    pub fn stop_reason(self) -> StopReason {
        match self {
            Self::Canceled => StopReason::Canceled,
            Self::Paused => StopReason::Paused,
            Self::PolicyChanged => StopReason::PolicyChanged,
            Self::TriggerCleared => StopReason::TriggerCleared,
            Self::DeadlineExpired => StopReason::DeadlineExpired,
            Self::AuthorityMissing => StopReason::AuthorityMissing,
        }
    }
}

/// The stop signal of the coordinator.
///
/// The executor has no clock and reads no policy. The coordinator gives
/// the cancellation, the pause, the revision and grant changes, the trigger
/// continuity, and the deadline of the step through this signal. The
/// executor reads it at the start of a batch and before each target.
pub trait StopSignal {
    /// The reason to stop now, or `None` to continue.
    fn check(&self) -> Option<Stop>;
}

impl<F: Fn() -> Option<Stop>> StopSignal for F {
    fn check(&self) -> Option<Stop> {
        self()
    }
}

/// A signal that never stops.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverStop;

impl StopSignal for NeverStop {
    fn check(&self) -> Option<Stop> {
        None
    }
}

/// The work that the calls for one target did.
///
/// The values are what the executor measured immediately before each call.
/// They are not reclaimed capacity: a successful unlink removes a directory
/// entry, and the storage can stay in use through an open descriptor, a
/// second hard link, a clone, or a snapshot. The caller measures the
/// capacity change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessedWork {
    /// The entries that the executor removed, a removed target directory
    /// included.
    pub removed_entries: EntryCount,
    /// The sum of `st_size` of the removed regular files and symbolic
    /// links.
    pub removed_logical_bytes: Bytes,
    /// The sum of `st_blocks * 512` of the removed entries. A regular file
    /// with more than one link is not in the sum: the removal of one name
    /// releases no storage of that file.
    pub removed_allocated_bytes: Bytes,
    /// The removed regular files that had more than one link.
    pub multiply_linked_entries: EntryCount,
    /// The entries of the measured tree that the executor did not remove:
    /// a changed entry, a refused call, or a call with a result that is
    /// not known.
    pub remaining_entries: EntryCount,
    /// The entries of the measured tree that were absent when their call
    /// ran, with each entry below them. Another actor removed or moved
    /// them; the executor did not.
    pub vanished_entries: EntryCount,
    /// The entries that the executor moved to Trash: one for a target that
    /// was moved, with its content.
    pub trashed_entries: EntryCount,
    /// `st_size` of a regular file or a symbolic link that was moved to
    /// Trash. `None` for a directory: the executor does not measure the
    /// content of a directory that it moves.
    pub trashed_logical_bytes: Option<Bytes>,
    /// Whether each sum is exact. `false` when a size from the operating
    /// system was not valid, when a sum did not fit its type, or when an
    /// unlink call returned an error number that does not establish its
    /// effect and the entry is absent. Each sum is then a lower bound of
    /// the measured sizes.
    ///
    /// An exact sum is the sum of the measurements of the planned objects
    /// immediately before their calls. Each removal has the attribution
    /// `possible` (an actor can replace an entry between the comparison and
    /// the call), so the sums are an estimate of what the calls removed in
    /// each case, never a measurement of reclaimed capacity.
    pub exact: bool,
}

impl ProcessedWork {
    /// No work.
    pub(super) const fn none() -> Self {
        Self {
            removed_entries: EntryCount::ZERO,
            removed_logical_bytes: Bytes::ZERO,
            removed_allocated_bytes: Bytes::ZERO,
            multiply_linked_entries: EntryCount::ZERO,
            remaining_entries: EntryCount::ZERO,
            vanished_entries: EntryCount::ZERO,
            trashed_entries: EntryCount::ZERO,
            trashed_logical_bytes: None,
            exact: true,
        }
    }
}

/// The result of one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsTargetOutcome {
    /// The target result, in the form of the action contract.
    pub result: TargetResult,
    /// The work that the calls did.
    pub work: ProcessedWork,
    /// The item that the Trash backend returned. The value is present for
    /// each reply that names an item, also when the result is not
    /// `Trashed` because the identity of the item is not the identity of
    /// the plan.
    pub trash_item: Option<LosslessPath>,
}

/// The reason the executor made no consistent target result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FaultReason {
    /// The fields of the record do not agree with each other.
    #[error("the fields of the target result do not agree: {0}")]
    Record(#[from] OutcomeError),
    /// An error code of the executor is not a valid code.
    #[error("an error code of the executor is not valid: {0}")]
    Code(#[from] ErrorCodeError),
}

/// A defect of the executor: it finished the work on a target and could
/// not make a target result that passes the consistency check of the
/// action contract.
///
/// The unit tests of the executor make each result form, so this value
/// shows a programming error. The caller records the target as
/// `UnknownOutcome` when `dispatch` is not `not_submitted`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the executor made no consistent result for the target {target_id}: {reason}")]
pub struct ExecutionFault {
    /// The target.
    pub target_id: TargetId,
    /// Whether a call for the target was, or possibly was, submitted.
    pub dispatch: DispatchState,
    /// Why the record was rejected.
    pub reason: FaultReason,
    /// The work that the calls for the target did before the fault. The
    /// values are those of [`FsTargetOutcome::work`]: entries that the
    /// executor removed or moved stay removed or moved.
    pub work: ProcessedWork,
    /// The item that the Trash backend returned, when it named one.
    pub trash_item: Option<LosslessPath>,
}

/// The result of one step: a target outcome, or the fault that prevented
/// its record. The fault is boxed: it has the work of the target, and it
/// is the rare result.
pub type StepOutcome = Result<FsTargetOutcome, Box<ExecutionFault>>;

/// The result of one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchOutcome {
    /// One result for each step of the batch, in the sequence of the
    /// batch. A step that was not started has a `Skipped` result with the
    /// stop reason of the signal.
    pub outcomes: Vec<StepOutcome>,
    /// The stop that the signal gave, when it gave one. Each step after
    /// the stop was not started.
    pub stopped: Option<Stop>,
}
