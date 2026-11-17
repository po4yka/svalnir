//! The filesystem executor.
//!
//! The executor carries out one admitted filesystem step on the target
//! that the plan names, and reports what it observed: `MoveToTrash` through
//! the supported Trash operation, and `DeleteSelectedFiles` and
//! `EvictRegenerableData` through descriptor-relative, no-follow removal of
//! a bounded enumeration under an anchored root. A failed Trash move does
//! not become a permanent removal, and a denied user-scope action is not
//! retried as root.
//!
//! Owning specifications: `docs/ACTION_CONTRACTS.md` sections 6, 7, 9, and
//! 10, `docs/ARCHITECTURE.md` section 8, and `docs/CLEANUP_RULES.md`
//! sections 6 and 9.
//!
//! # Use
//!
//! The coordinator records the intent of a step and consumes its dispatch
//! in the journal, and then makes an [`AdmittedStep`] from the
//! [`RequestEnvelope`](svalnir_core::action::RequestEnvelope) and the
//! [`DispatchReceipt`](svalnir_core::action::DispatchReceipt). The executor
//! takes no other input, so it cannot run without a receipt. Call
//! [`FsExecutor::execute_batch`] for each batch with the [`ApprovedRoots`]
//! of the plan and a [`StopSignal`], record each
//! [`TargetResult`](svalnir_core::action::TargetResult), and measure the
//! capacity after the batch.
//!
//! # What the executor does not do
//!
//! - It decides no policy and no eligibility. The target, the action
//!   class, and the root are those of the envelope.
//! - It writes no journal and measures no capacity. [`ProcessedWork`] has
//!   the entries and the bytes that the calls acted on; that is not
//!   reclaimed capacity.
//! - It reads no clock for a deadline. The coordinator gives the deadline,
//!   the cancellation, and each revision change through the
//!   [`StopSignal`].
//! - It repeats no call. After an error number that does not establish the
//!   effect, it observes the entry one time and reports what it found.
//!
//! # Revalidation
//!
//! Immediately before each target the executor opens the approved root
//! from `/` one component at a time, walks to the parent directory of the
//! entry with `openat`, `O_NOFOLLOW`, and `O_DIRECTORY`, measures the entry
//! with `fstatat` and `AT_SYMLINK_NOFOLLOW`, and compares the device, the
//! inode, the type, and the owner with the binding of the plan. A
//! difference is a `Skipped` result with its reason. No call resolves a
//! path of more than one component.
//!
//! # Refusals that no plan removes
//!
//! - A relative entry that is absolute or has an empty component, a `.`,
//!   or a `..`; a root path that is `/` or is not normalized
//!   ([`ApprovedRoots::new`] rejects it).
//! - The home directory, and each directory that contains it.
//! - The approved root itself. No action class of this build permits it.
//! - A target whose root is not in the [`ApprovedRoots`] of the call.
//! - A target, a directory between the root and the target, or an entry
//!   of a directory target on another device than the root.
//! - A binding with no device and inode evidence.
//! - A step whose principal is not the effective user of the process.
//!
//! # Races that remain
//!
//! The comparison of an entry and the call on its name are two system
//! calls. `docs/ACTION_CONTRACTS.md` section 7 states that no conditional
//! unlink exists. An actor that can write to the parent directory can
//! replace the entry between them:
//!
//! - `unlinkat` then removes the replacement of the same name in the same
//!   open directory. It follows no symbolic link and cannot leave that
//!   directory. A replacement directory is removed only when it is empty.
//! - The Trash operation takes a path. A replaced component of the path
//!   can redirect it. The executor compares the identity of the moved item
//!   after the call and reports a difference as `UnknownOutcome` with the
//!   item that was moved.

mod errors;
mod executor;
mod model;
mod native;
mod remove;
mod resolve;
mod trash;

#[cfg(test)]
mod tests;

pub use errors::code;
pub use executor::FsExecutor;
pub use model::{
    AdmissionRefusal, AdmittedStep, ApprovedRoot, ApprovedRoots, BatchOutcome, ConfigError,
    ExecutionFault, ExecutorLimits, FaultReason, FsExecutorConfig, FsTargetOutcome, LimitsError,
    MAX_APPROVED_ROOTS, MAX_BATCH_STEPS, MAX_OPEN_DESCRIPTORS_LIMIT, MAX_TREE_DEPTH_LIMIT,
    MAX_TREE_ENTRIES_LIMIT, MIN_OPEN_DESCRIPTORS, NeverStop, ProcessedWork, RootError, StepOutcome,
    Stop, StopSignal,
};
pub use trash::{SystemTrash, TrashBackend, TrashFailure, TrashReply, TrashRequest};
