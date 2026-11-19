//! The eviction executor of the host filesystem.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use svalnir_core::action::{
    ActionStage, Attribution, DispatchState, EffectEvidence, FileObjectType, NativeResult,
    StopReason, TargetEffect, WorkCharge,
};
use svalnir_core::id::AdapterId;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use super::{EvictionExecutor, Execution, Gate};
use crate::native::{self, Kind, Metadata};
use crate::request::StepCorrelation;
use crate::response::{Condition, EntryReport, action_error};
use crate::validation::{ApprovedRoot, BoundedEntry, BoundedEviction, RefusalReason};

/// The observation source of a removal: the second measurement of the
/// name, which this executor makes after its call.
const ADAPTER: &str = "svalnir.helper.fs";

/// The size in bytes of one `st_blocks` unit.
const BLOCK_BYTES: u64 = 512;

/// The permission bits that let a user other than the owner write.
const WRITE_BY_OTHERS: u32 = 0o022;

/// The eviction executor of the host filesystem.
///
/// The executor acts as the effective user of its process. It removes an
/// object only when that user or user 0 owns the object and each directory
/// from the approved root to the object, and no other user can write to
/// one of those directories. For the installed helper the effective user
/// is user 0. A test runs the executor as the user of the test, in a
/// temporary directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsEvictor {
    controller: u32,
}

impl FsEvictor {
    /// Makes the executor for the effective user of this process.
    pub fn new() -> Self {
        Self {
            controller: native::effective_uid(),
        }
    }

    fn is_controlling_owner(self, owner: u32) -> bool {
        owner == 0 || owner == self.controller
    }

    fn is_controlled_directory(self, metadata: &Metadata) -> bool {
        metadata.kind == Kind::Directory
            && self.is_controlling_owner(metadata.owner)
            && metadata.permissions & WRITE_BY_OTHERS == 0
    }

    /// Opens the approved root from `/`, one name at a time, and checks
    /// it.
    fn open_root(self, root: &ApprovedRoot) -> Result<Root, Condition> {
        let mut directory: OwnedFd =
            native::open_filesystem_root().map_err(|_| Condition::RootUnavailable)?;
        for name in root.path().names() {
            let name: CString = CString::new(name).map_err(|_| Condition::RootUnavailable)?;
            directory = native::open_directory_at(directory.as_fd(), &name)
                .map_err(|_| Condition::RootUnavailable)?;
        }
        let metadata: Metadata =
            native::stat_descriptor(directory.as_fd()).map_err(|_| Condition::RootUnavailable)?;
        let device: i32 = metadata.device.ok_or(Condition::RootUnavailable)?;
        if !self.is_controlled_directory(&metadata) {
            return Err(Condition::RootNotControlled);
        }
        if native::is_on_local_filesystem(directory.as_fd()) != Some(true) {
            return Err(Condition::RootNotLocal);
        }
        Ok(Root { directory, device })
    }

    /// Opens the directory that has the object of `entry`. `Ok(None)`
    /// means that a directory of the path is absent, so the object is
    /// absent.
    fn open_parent(self, root: &Root, parents: &[&[u8]]) -> Result<Option<OwnedFd>, Condition> {
        let mut directory: OwnedFd = root
            .directory
            .try_clone()
            .map_err(|_| Condition::PathChanged)?;
        for name in parents {
            let name: CString = CString::new(*name).map_err(|_| Condition::PathChanged)?;
            let next: OwnedFd = match native::open_directory_at(directory.as_fd(), &name) {
                Ok(next) => next,
                Err(error) if is_absent(&error) => return Ok(None),
                Err(_) => return Err(Condition::PathChanged),
            };
            let metadata: Metadata =
                native::stat_descriptor(next.as_fd()).map_err(|_| Condition::PathChanged)?;
            if metadata.device != Some(root.device) {
                return Err(Condition::MountCrossing);
            }
            if !self.is_controlled_directory(&metadata) {
                return Err(Condition::PathNotControlled);
            }
            directory = next;
        }
        Ok(Some(directory))
    }

    /// Checks the object at the name of `entry` against the request and
    /// the rules of the executor. Returns the measured work of the object.
    fn check_object(
        self,
        root: &Root,
        entry: &BoundedEntry,
        metadata: &Metadata,
    ) -> Result<WorkCharge, Condition> {
        let type_agrees: bool = match (&entry.object_type, metadata.kind) {
            (FileObjectType::RegularFile, Kind::File)
            | (FileObjectType::Directory, Kind::Directory)
            | (FileObjectType::SymbolicLink, Kind::Symlink) => true,
            (
                FileObjectType::RegularFile
                | FileObjectType::Directory
                | FileObjectType::SymbolicLink
                | FileObjectType::Unrecognized(_),
                _,
            ) => false,
        };
        if !type_agrees
            || metadata.device != Some(entry.object.device.get())
            || metadata.inode != entry.object.inode.get()
        {
            return Err(Condition::TargetChanged);
        }
        if metadata.device != Some(root.device) {
            return Err(Condition::MountCrossing);
        }
        if !self.is_controlling_owner(metadata.owner) {
            return Err(Condition::TargetNotOwned);
        }
        if metadata.dataless {
            return Err(Condition::TargetDataless);
        }
        if metadata.kind == Kind::File && metadata.link_count > 1 {
            return Err(Condition::TargetHardLinked);
        }
        let bytes: u64 = u64::try_from(metadata.blocks)
            .ok()
            .and_then(|blocks: u64| blocks.checked_mul(BLOCK_BYTES))
            .ok_or(Condition::TargetUnreadable)?;
        if bytes > entry.limit.work_bytes.get() {
            return Err(Condition::TargetOverBound);
        }
        Ok(WorkCharge::new(Bytes::new(bytes), EntryCount::new(1)))
    }

    fn evict_entry(
        self,
        root: &Root,
        entry: &BoundedEntry,
        reports: &Reports<'_>,
        index: u32,
        wall: WallTime,
    ) -> EntryReport {
        let names: Vec<&[u8]> = entry.path.names().collect();
        let Some((leaf, parents)) = names.split_last() else {
            return reports.skipped(index, Condition::PathChanged);
        };
        let directory: OwnedFd = match self.open_parent(root, parents) {
            Ok(Some(directory)) => directory,
            Ok(None) => return Reports::absent_before(index),
            Err(condition) => return reports.skipped(index, condition),
        };
        let directory: BorrowedFd<'_> = directory.as_fd();
        let Ok(leaf) = CString::new(*leaf) else {
            return reports.skipped(index, Condition::PathChanged);
        };
        let metadata: Metadata = match native::stat_at(directory, &leaf) {
            Ok(metadata) => metadata,
            Err(error) if is_absent(&error) => return Reports::absent_before(index),
            Err(_) => return reports.skipped(index, Condition::TargetUnreadable),
        };
        let work: WorkCharge = match self.check_object(root, entry, &metadata) {
            Ok(work) => work,
            Err(condition) => return reports.skipped(index, condition),
        };
        // The one call of this entry. A directory is removed only when it
        // is empty.
        match native::unlink_at(directory, &leaf, metadata.kind == Kind::Directory) {
            Ok(()) => match native::stat_at(directory, &leaf) {
                Err(error) if is_absent(&error) => reports.removed(index, wall, work),
                // The call succeeded, and the name is there again or
                // cannot be measured: the final condition is not verified.
                Ok(_) | Err(_) => reports.unknown(index, NativeResult::Succeeded),
            },
            Err(error) => reports.after_failed_call(index, &error),
        }
    }
}

impl Default for FsEvictor {
    fn default() -> Self {
        Self::new()
    }
}

impl EvictionExecutor for FsEvictor {
    fn evict(&mut self, eviction: &BoundedEviction, gate: &mut Gate<'_>) -> Execution {
        let reports: Reports<'_> = Reports {
            correlation: &eviction.correlation,
        };
        let mut entries: Vec<EntryReport> = Vec::with_capacity(eviction.entries.len());
        let mut stopped: Option<RefusalReason> = None;
        // The root is opened one time, after the gate permitted the first
        // entry. Each entry is then resolved from this handle.
        let mut root: Option<Result<Root, Condition>> = None;
        for (position, entry) in eviction.entries.iter().enumerate() {
            let index: u32 = u32::try_from(position).unwrap_or(u32::MAX);
            if let Some(reason) = stopped {
                entries.push(Reports::stopped(index, reason));
                continue;
            }
            let wall: WallTime = match gate() {
                Ok(wall) => wall,
                Err(reason) => {
                    stopped = Some(reason);
                    entries.push(Reports::stopped(index, reason));
                    continue;
                }
            };
            let report: EntryReport =
                match root.get_or_insert_with(|| self.open_root(&eviction.root)) {
                    Ok(root) => self.evict_entry(root, entry, &reports, index, wall),
                    Err(condition) => reports.skipped(index, *condition),
                };
            entries.push(report);
        }
        Execution { entries, stopped }
    }
}

/// The open approved root.
struct Root {
    directory: OwnedFd,
    device: i32,
}

fn is_absent(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOENT)
}

/// The maker of the entry reports of one step.
struct Reports<'step> {
    correlation: &'step StepCorrelation,
}

impl Reports<'_> {
    /// The fresh check did not permit the entry. No call was submitted.
    fn skipped(&self, index: u32, condition: Condition) -> EntryReport {
        EntryReport {
            index,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::TargetSkipped,
            failure: Some(condition.to_action_error(
                ActionStage::Dispatch,
                DispatchState::NotSubmitted,
                Some(self.correlation),
            )),
            removed: WorkCharge::ZERO,
        }
    }

    /// The gate stopped the step at or before the entry. No call was
    /// submitted. The reason is the error of the step, not of the entry.
    fn stopped(index: u32, reason: RefusalReason) -> EntryReport {
        let stop_reason: StopReason = match reason {
            RefusalReason::RequestExpired | RefusalReason::ClockNotComparable => {
                StopReason::DeadlineExpired
            }
            _ => StopReason::AuthorityMissing,
        };
        EntryReport {
            index,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            stop_reason,
            failure: None,
            removed: WorkCharge::ZERO,
        }
    }

    /// The name was absent before a call. No call was submitted.
    fn absent_before(index: u32) -> EntryReport {
        EntryReport {
            index,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::AlreadyAbsent,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Completed,
            failure: None,
            removed: WorkCharge::ZERO,
        }
    }

    /// The call succeeded, and the name is absent after it.
    fn removed(&self, index: u32, wall: WallTime, work: WorkCharge) -> EntryReport {
        let Ok(source) = AdapterId::new(ADAPTER) else {
            // A removal with no observation source is not a verified
            // effect.
            return self.unknown(index, NativeResult::Succeeded);
        };
        EntryReport {
            index,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::Removed,
            evidence: EffectEvidence {
                native: NativeResult::Succeeded,
                source: Some(source),
                observed_at: Some(wall),
                trash_item: None,
            },
            attribution: Attribution::Possible,
            stop_reason: StopReason::Completed,
            failure: None,
            removed: work,
        }
    }

    /// The call was submitted, and its effect is not established.
    fn unknown(&self, index: u32, native: NativeResult) -> EntryReport {
        EntryReport {
            index,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::UnknownOutcome,
            evidence: EffectEvidence {
                native,
                source: None,
                observed_at: None,
                trash_item: None,
            },
            attribution: Attribution::Possible,
            stop_reason: StopReason::Failed,
            failure: Some(Condition::RemovalUnknown.to_action_error(
                ActionStage::Verification,
                DispatchState::Submitted,
                Some(self.correlation),
            )),
            removed: WorkCharge::ZERO,
        }
    }

    /// The call was submitted and returned an error.
    fn after_failed_call(&self, index: u32, error: &io::Error) -> EntryReport {
        let Some(errno) = error.raw_os_error() else {
            return self.unknown(index, NativeResult::Unavailable);
        };
        let native: NativeResult = NativeResult::Errno { errno };
        let condition: Condition = match errno {
            // The name was absent at the call: another actor removed it
            // after the check.
            libc::ENOENT => {
                return EntryReport {
                    index,
                    dispatch: DispatchState::Submitted,
                    effect: TargetEffect::AlreadyAbsent,
                    evidence: EffectEvidence {
                        native,
                        source: None,
                        observed_at: None,
                        trash_item: None,
                    },
                    attribution: Attribution::Possible,
                    stop_reason: StopReason::Completed,
                    failure: None,
                    removed: WorkCharge::ZERO,
                };
            }
            libc::ENOTEMPTY | libc::EEXIST => Condition::DirectoryNotEmpty,
            // Each of these errors is a definite failure of `unlinkat`
            // with no effect.
            libc::EACCES
            | libc::EPERM
            | libc::EBUSY
            | libc::EROFS
            | libc::ENOTDIR
            | libc::EISDIR
            | libc::ELOOP
            | libc::ENAMETOOLONG => Condition::RemovalRefused,
            // A native error is not always proof of no effect.
            _ => return self.unknown(index, native),
        };
        EntryReport {
            index,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::Refused,
            evidence: EffectEvidence {
                native,
                source: None,
                observed_at: None,
                trash_item: None,
            },
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Failed,
            failure: Some(action_error(
                condition.code(),
                condition.family(),
                ActionStage::Execution,
                DispatchState::Submitted,
                Some(self.correlation),
            )),
            removed: WorkCharge::ZERO,
        }
    }
}
