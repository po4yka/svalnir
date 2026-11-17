//! Permanent removal of one revalidated target.
//!
//! A regular file or a symbolic link is removed with one `unlinkat` on the
//! open parent directory. A directory is removed in two passes:
//!
//! 1. The measurement reads the tree through descriptors and keeps the
//!    name, the device, the inode, and the type of each entry. It issues no
//!    mutation. A tree that does not fit the depth, entry, or descriptor
//!    bound, that has a mount point, a dataless directory, or a type that
//!    is not supported, is refused as a whole: nothing is removed.
//! 2. The removal goes bottom-up through the measured entries only. It
//!    compares each entry with its measurement immediately before the
//!    call, never follows a symbolic link, and never reads a directory
//!    again. An entry that appeared after the measurement is not removed,
//!    so its directory stays and the result is partial.
//!
//! The comparison and the `unlinkat` call are not one atomic step. An actor
//! that can write to the directory can replace an entry between them; the
//! call then removes the replacement of the same name in the same
//! directory. It cannot leave the directory, because the call is relative
//! to the open descriptor.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use svalnir_core::action::Attribution;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence};
use svalnir_core::quantity::{Bytes, EntryCount};

use super::errors::{CallVerdict, Cause, code, mutation_verdict, read_cause};
use super::model::{ExecutorLimits, ProcessedWork};
use super::native::{self, DirStream, Kind, Metadata};
use super::resolve::{
    Checkpoint, Injection, Located, Refusal, identity_of, is_absent, is_not_directory, push_name,
};

/// The size in bytes of one `st_blocks` unit.
const BLOCK_BYTES: u64 = 512;

/// The result of one `unlinkat` call, after the observation of the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EntryOutcome {
    /// The name is absent after the call.
    Removed {
        /// `Established` when the call returned success. `Possible` when
        /// the call returned an error number that does not establish the
        /// effect and the name is absent, or when the observation failed.
        attribution: Attribution,
        /// The error number of the call, when it returned one.
        errno: Option<i32>,
    },
    /// The call returned `ENOENT`: the entry was absent when it ran.
    Absent,
    /// The call had no effect.
    NoEffect {
        /// The error number of the call.
        errno: Option<i32>,
        /// The cause.
        cause: Cause,
    },
    /// The effect of the call is not established.
    Unknown {
        /// The error number of the call, when it returned one.
        errno: Option<i32>,
        /// The cause.
        cause: Cause,
    },
}

/// What the observation after a call found at the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Observed {
    /// No entry has the name.
    Gone,
    /// Another object has the name.
    Replaced,
    /// The object of the call has the name.
    Present,
    /// The observation failed.
    Unobserved,
}

/// Measures the name after a call, to observe the effect of the call.
pub(super) fn observe_entry(
    parent: BorrowedFd<'_>,
    name: &CStr,
    object: Option<FileObjectEvidence>,
    injection: &Injection,
    path: &[u8],
) -> Observed {
    match native::stat_at(parent, name) {
        Ok(measured) => {
            let measured: Metadata = injection.observe(path, measured);
            if object.is_some() && identity_of(&measured) == object {
                Observed::Present
            } else {
                Observed::Replaced
            }
        }
        Err(error) if is_absent(&error) => Observed::Gone,
        Err(_) => Observed::Unobserved,
    }
}

/// Reads the result of an `unlinkat` call and observes the entry. The call
/// is not repeated for any result.
///
/// `Established` states that the call returned success for the name and
/// that the object of the comparison does not have the name after it. It
/// does not state that the removed object was the object of the plan: see
/// the race in the module documentation.
pub(super) fn settle_unlink(
    result: &io::Result<()>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    object: Option<FileObjectEvidence>,
    injection: &Injection,
    path: &[u8],
) -> EntryOutcome {
    let observed: Observed = observe_entry(parent, name, object, injection, path);
    let error: &io::Error = match result {
        Ok(()) => {
            return match observed {
                Observed::Gone | Observed::Replaced => EntryOutcome::Removed {
                    attribution: Attribution::Established,
                    errno: None,
                },
                Observed::Unobserved => EntryOutcome::Removed {
                    attribution: Attribution::Possible,
                    errno: None,
                },
                // The call returned success and the same object has the
                // name, for example through a second link that another
                // actor moved in.
                Observed::Present => EntryOutcome::Unknown {
                    errno: None,
                    cause: Cause::outcome(code::OUTCOME_UNVERIFIED),
                },
            };
        }
        Err(error) => error,
    };
    let errno: Option<i32> = error.raw_os_error();
    match mutation_verdict(errno) {
        CallVerdict::Absent => EntryOutcome::Absent,
        CallVerdict::NoEffect(cause) => EntryOutcome::NoEffect { errno, cause },
        CallVerdict::Indeterminate(cause) => match observed {
            Observed::Gone => EntryOutcome::Removed {
                attribution: Attribution::Possible,
                errno,
            },
            // The same object at the name does not establish that the call
            // had no effect: another actor can link a file with a second
            // name back in. The result stays in the `outcome` family.
            Observed::Present | Observed::Replaced | Observed::Unobserved => {
                EntryOutcome::Unknown { errno, cause }
            }
        },
    }
}

fn add_bytes(sum: &mut Bytes, exact: &mut bool, value: Option<Bytes>) {
    match value.and_then(|value| sum.checked_add(value)) {
        Some(total) => *sum = total,
        None => *exact = false,
    }
}

fn add_entries(count: &mut EntryCount, exact: &mut bool, entries: u64) {
    match count.checked_add(EntryCount::new(entries)) {
        Some(total) => *count = total,
        None => *exact = false,
    }
}

/// Adds one removed entry to the work.
pub(super) fn count_removed(work: &mut ProcessedWork, metadata: &Metadata) {
    add_entries(&mut work.removed_entries, &mut work.exact, 1);
    let logical: Option<Bytes> = u64::try_from(metadata.size).ok().map(Bytes::new);
    let allocated: Option<Bytes> = u64::try_from(metadata.blocks)
        .ok()
        .and_then(|blocks| Bytes::new(blocks).checked_mul(BLOCK_BYTES));
    match metadata.kind {
        Kind::File => {
            add_bytes(&mut work.removed_logical_bytes, &mut work.exact, logical);
            if metadata.link_count > 1 {
                add_entries(&mut work.multiply_linked_entries, &mut work.exact, 1);
            } else {
                add_bytes(
                    &mut work.removed_allocated_bytes,
                    &mut work.exact,
                    allocated,
                );
            }
        }
        Kind::Symlink => {
            add_bytes(&mut work.removed_logical_bytes, &mut work.exact, logical);
            add_bytes(
                &mut work.removed_allocated_bytes,
                &mut work.exact,
                allocated,
            );
        }
        Kind::Directory | Kind::Other => {
            add_bytes(
                &mut work.removed_allocated_bytes,
                &mut work.exact,
                allocated,
            );
        }
    }
}

/// Removes a revalidated regular file or symbolic link with one
/// `unlinkat` on its open parent directory.
pub(super) fn remove_file(located: &Located, injection: &Injection) -> EntryOutcome {
    let result: io::Result<()> = native::unlink_at(located.parent.as_fd(), &located.name, false);
    settle_unlink(
        &result,
        located.parent.as_fd(),
        &located.name,
        Some(located.object),
        injection,
        &located.path,
    )
}

/// One measured entry of a directory target.
#[derive(Debug)]
struct Snapshot {
    name: CString,
    metadata: Metadata,
    /// The measured entries of a directory. Empty for each other type.
    children: Vec<Snapshot>,
}

impl Snapshot {
    /// The number of entries of the subtree, this entry included.
    fn entries(&self) -> u64 {
        self.children
            .iter()
            .fold(1_u64, |sum, child| sum.saturating_add(child.entries()))
    }
}

/// The read-only measurement of a directory target.
struct Measure<'a> {
    limits: &'a ExecutorLimits,
    device: DeviceNumber,
    injection: &'a Injection,
    entries: u64,
}

impl Measure<'_> {
    /// Opens the directory `name` of `parent`, compares it with
    /// `expected`, and measures its entries. `level` is 1 for the target
    /// directory. `path` is the path of the directory.
    fn directory(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: &Metadata,
        level: u32,
        path: &mut Vec<u8>,
    ) -> Result<Vec<Snapshot>, Refusal> {
        if level > self.limits.max_tree_depth() {
            return Err(Refusal::skipped(Cause::limits(code::TREE_DEPTH_LIMIT)));
        }
        // The parent directory of the target, and one stream for each
        // level to this one.
        if level.saturating_add(1) > self.limits.max_open_descriptors() {
            return Err(Refusal::skipped(Cause::limits(code::DESCRIPTOR_LIMIT)));
        }
        if expected.dataless {
            return Err(Refusal::skipped(Cause::eligibility(
                code::DATALESS_DIRECTORY,
            )));
        }
        let changed = || {
            let code: &'static str = if level == 1 {
                code::TARGET_IDENTITY_CHANGED
            } else {
                code::TREE_CHANGED
            };
            Refusal::skipped(Cause::evidence(code))
        };
        let descriptor: OwnedFd = open_checked(parent, name, expected, self.injection, path)
            .map_err(|failure| match failure {
                OpenFailure::Changed => changed(),
                OpenFailure::Read(error) => Refusal::read_failure(&error),
            })?;
        let mut stream: DirStream = DirStream::from_descriptor(descriptor)
            .map_err(|error| Refusal::read_failure(&error))?;
        let mut entries: Vec<Snapshot> = Vec::new();
        let mut buffer: Vec<u8> = Vec::new();
        let directory_length: usize = path.len();
        loop {
            match stream.next_name(&mut buffer) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => return Err(Refusal::read_failure(&error)),
            }
            let Ok(entry_name) = CString::from_vec_with_nul(buffer.clone()) else {
                return Err(Refusal {
                    cause: Cause::native(code::NATIVE_ERROR),
                    stop_reason: svalnir_core::action::StopReason::Failed,
                });
            };
            path.truncate(directory_length);
            push_name(path, &entry_name);
            let metadata: Metadata = match native::stat_at(stream.descriptor(), &entry_name) {
                Ok(metadata) => self.injection.observe(path, metadata),
                // The entry went away after `readdir` gave its name.
                Err(error) if is_absent(&error) => continue,
                Err(error) => return Err(Refusal::read_failure(&error)),
            };
            self.entries = self.entries.saturating_add(1);
            if self.entries > self.limits.max_tree_entries() {
                return Err(Refusal::skipped(Cause::limits(code::TREE_ENTRY_LIMIT)));
            }
            if metadata.device != Some(self.device) {
                return Err(Refusal::skipped(Cause::evidence(code::MOUNT_CROSSED)));
            }
            let children: Vec<Snapshot> = match metadata.kind {
                Kind::Other => {
                    return Err(Refusal::skipped(Cause::eligibility(
                        code::UNSUPPORTED_FILE_TYPE,
                    )));
                }
                Kind::Directory => self.directory(
                    stream.descriptor(),
                    &entry_name,
                    &metadata,
                    level.saturating_add(1),
                    path,
                )?,
                Kind::File | Kind::Symlink => Vec::new(),
            };
            entries.push(Snapshot {
                name: entry_name,
                metadata,
                children,
            });
        }
        path.truncate(directory_length);
        Ok(entries)
    }
}

/// Why a directory was not opened.
enum OpenFailure {
    /// The name is absent, is a symbolic link, is not a directory, or is
    /// another directory than the measured one.
    Changed,
    /// The call failed for another reason.
    Read(io::Error),
}

/// Opens the directory `name` of `parent` with no-follow protection and
/// compares the open object with `expected`.
fn open_checked(
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: &Metadata,
    injection: &Injection,
    path: &[u8],
) -> Result<OwnedFd, OpenFailure> {
    let descriptor: OwnedFd = match native::open_directory_at(parent, name) {
        Ok(descriptor) => descriptor,
        Err(error) if is_absent(&error) || is_not_directory(&error) => {
            return Err(OpenFailure::Changed);
        }
        Err(error) => return Err(OpenFailure::Read(error)),
    };
    let opened: Metadata = match native::stat_descriptor(descriptor.as_fd()) {
        Ok(opened) => injection.observe(path, opened),
        Err(error) => return Err(OpenFailure::Read(error)),
    };
    let same: bool = opened.kind == Kind::Directory
        && identity_of(&opened).is_some()
        && identity_of(&opened) == identity_of(expected);
    if same {
        Ok(descriptor)
    } else {
        Err(OpenFailure::Changed)
    }
}

/// What the removal did for one measured entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Attempt {
    /// The entry was absent before its call. No call was issued for it.
    Vanished,
    /// No call was issued for the entry: it changed, or a read-only call
    /// failed.
    NotAttempted(Refusal),
    /// The call was issued.
    Called(EntryOutcome),
}

/// The result of the removal of a directory target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TreeRemoval {
    /// What the removal did for the target directory itself.
    pub(super) root: Attempt,
    /// The work of the calls.
    pub(super) work: ProcessedWork,
    /// The cause of the first entry that was not removed.
    pub(super) first_cause: Option<Cause>,
    /// The cause of the first call whose effect is not established.
    pub(super) indeterminate: Option<Cause>,
}

/// The removal pass over the measured tree.
struct Removal<'a> {
    injection: &'a Injection,
    work: ProcessedWork,
    first_cause: Option<Cause>,
    indeterminate: Option<Cause>,
}

impl Removal<'_> {
    fn note(&mut self, cause: &Cause) {
        if self.first_cause.is_none() {
            self.first_cause = Some(cause.clone());
        }
    }

    fn remain(&mut self, entries: u64) {
        add_entries(
            &mut self.work.remaining_entries,
            &mut self.work.exact,
            entries,
        );
    }

    /// Removes one measured entry and counts the result. `path` is the
    /// path of the entry.
    fn entry(
        &mut self,
        parent: BorrowedFd<'_>,
        snapshot: &Snapshot,
        path: &mut Vec<u8>,
    ) -> Attempt {
        let attempt: Attempt = self.attempt(parent, snapshot, path);
        match &attempt {
            // The name is absent. That does not show where the object is:
            // another actor can have moved the subtree.
            Attempt::Vanished => add_entries(
                &mut self.work.vanished_entries,
                &mut self.work.exact,
                snapshot.entries(),
            ),
            Attempt::Called(EntryOutcome::Absent) => {
                add_entries(&mut self.work.vanished_entries, &mut self.work.exact, 1);
            }
            Attempt::NotAttempted(refusal) => {
                self.note(&refusal.cause);
                // No entry of the subtree was removed.
                self.remain(snapshot.entries());
            }
            Attempt::Called(EntryOutcome::Removed { errno, .. }) => {
                count_removed(&mut self.work, &snapshot.metadata);
                // The call returned an error number: the removal is
                // possible, not established.
                if errno.is_some() {
                    self.work.exact = false;
                }
            }
            Attempt::Called(EntryOutcome::NoEffect { cause, .. }) => {
                self.note(cause);
                self.remain(1);
            }
            Attempt::Called(EntryOutcome::Unknown { cause, .. }) => {
                if self.indeterminate.is_none() {
                    self.indeterminate = Some(cause.clone());
                }
                self.remain(1);
            }
        }
        attempt
    }

    fn attempt(
        &mut self,
        parent: BorrowedFd<'_>,
        snapshot: &Snapshot,
        path: &mut Vec<u8>,
    ) -> Attempt {
        let name: &CStr = &snapshot.name;
        let changed =
            || Attempt::NotAttempted(Refusal::skipped(Cause::evidence(code::TREE_CHANGED)));
        let current: Metadata = match native::stat_at(parent, name) {
            Ok(current) => self.injection.observe(path, current),
            Err(error) if is_absent(&error) => return Attempt::Vanished,
            Err(error) => {
                return Attempt::NotAttempted(Refusal {
                    cause: read_cause(error.raw_os_error()),
                    stop_reason: svalnir_core::action::StopReason::Failed,
                });
            }
        };
        let object: Option<FileObjectEvidence> = identity_of(&snapshot.metadata);
        if object.is_none()
            || identity_of(&current) != object
            || current.kind != snapshot.metadata.kind
        {
            return changed();
        }
        self.injection.reach(Checkpoint::EntryChecked, path);
        let is_directory: bool = snapshot.metadata.kind == Kind::Directory;
        let remaining_before: EntryCount = self.work.remaining_entries;
        let indeterminate_before: bool = self.indeterminate.is_some();
        if is_directory {
            let descriptor: OwnedFd =
                match open_checked(parent, name, &snapshot.metadata, self.injection, path) {
                    Ok(descriptor) => descriptor,
                    Err(OpenFailure::Changed) => return changed(),
                    Err(OpenFailure::Read(error)) => {
                        return Attempt::NotAttempted(Refusal::read_failure(&error));
                    }
                };
            let directory_length: usize = path.len();
            for child in &snapshot.children {
                path.truncate(directory_length);
                push_name(path, &child.name);
                let _attempt: Attempt = self.entry(descriptor.as_fd(), child, path);
            }
            path.truncate(directory_length);
            // The descriptor is closed before the directory is removed.
            drop(descriptor);
        }
        // `AT_REMOVEDIR` removes an empty directory only. A directory with
        // an entry that was not removed, or with an entry that appeared
        // after the measurement, stays, and the call returns `ENOTEMPTY`.
        let result: io::Result<()> = native::unlink_at(parent, name, is_directory);
        let mut outcome: EntryOutcome =
            settle_unlink(&result, parent, name, object, self.injection, path);
        if !is_directory {
            return Attempt::Called(outcome);
        }
        let children_done: bool = self.work.remaining_entries == remaining_before
            && self.indeterminate.is_some() == indeterminate_before;
        match &mut outcome {
            // The directory was empty when the call ran, so no entry of it
            // remains. An entry that was counted as remaining went away by
            // another cause, and the sums are not exact.
            EntryOutcome::Removed { .. } if !children_done => {
                self.work.remaining_entries = remaining_before;
                self.work.exact = false;
            }
            // Each measured entry is gone and the directory is not empty:
            // an entry appeared after the measurement. That is a changed
            // target, not a refusal of the backend.
            EntryOutcome::NoEffect { errno, cause }
                if children_done && matches!(errno, Some(libc::ENOTEMPTY | libc::EEXIST)) =>
            {
                *cause = Cause::evidence(code::TREE_CHANGED);
            }
            _ => {}
        }
        Attempt::Called(outcome)
    }
}

/// Removes a revalidated directory target.
///
/// # Errors
///
/// Returns the [`Refusal`] of the measurement when the tree is not
/// permitted. No mutation call was issued then.
pub(super) fn remove_tree(
    located: &Located,
    limits: &ExecutorLimits,
    injection: &Injection,
) -> Result<TreeRemoval, Refusal> {
    let mut path: Vec<u8> = located.path.clone();
    let mut measure = Measure {
        limits,
        device: located.device,
        injection,
        entries: 0,
    };
    let children: Vec<Snapshot> = measure.directory(
        located.parent.as_fd(),
        &located.name,
        &located.metadata,
        1,
        &mut path,
    )?;
    let root = Snapshot {
        name: located.name.clone(),
        metadata: located.metadata,
        children,
    };
    injection.reach(Checkpoint::TreeEnumerated, &located.path);
    let mut removal = Removal {
        injection,
        work: ProcessedWork::none(),
        first_cause: None,
        indeterminate: None,
    };
    let mut path: Vec<u8> = located.path.clone();
    let attempt: Attempt = removal.entry(located.parent.as_fd(), &root, &mut path);
    Ok(TreeRemoval {
        root: attempt,
        work: removal.work,
        first_cause: removal.first_cause,
        indeterminate: removal.indeterminate,
    })
}
