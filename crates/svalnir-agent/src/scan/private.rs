//! The private allocated bytes of the root of a scan.
//!
//! `docs/RESOURCE_MODEL.md` section 8 defines the two quantities. The
//! traversal gives each counted object to a [`PrivateTally`]; the tally adds
//! the private part of each object to the private allocated bytes, keeps the
//! hard-linked objects until the scan ends, and adds the shared part of each
//! clone family whose members the scan found to the complete-family shared
//! bytes. The private allocated bytes count no shared block, so they are the
//! lower figure. The complete-family shared bytes are not a reclaim figure:
//! a modified clone outside the root or a snapshot can hold them. The tally
//! does no native call.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;

use svalnir_core::quantity::{Bytes, EntryCount};

use super::model::{PrivateAllocation, PrivateBytes, PrivateSizeUnavailable};
use super::native::PrivateAttributes;

/// The largest number of clone families that one scan tracks. A member of
/// a family above this number adds nothing to the complete-family shared
/// bytes.
pub(super) const MAX_CLONE_FAMILIES: usize = 1_000_000;

/// The membership of one file in a clone family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CloneShare {
    /// `ATTR_CMNEXT_CLONEID`.
    pub(super) family: u64,
    /// `ATTR_CMNEXT_CLONE_REFCNT`: the number of files of the family.
    pub(super) members: u32,
    /// The allocated size minus the private size of the file, or the
    /// allocated size of a compressed file. It can be zero.
    pub(super) shared: Bytes,
}

/// What one counted regular file adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilePart {
    /// The private part, and the clone family when the file is a member.
    Private {
        /// The bytes that only this file uses.
        private: Bytes,
        /// The clone family, when the clone count is above 1.
        clone: Option<CloneShare>,
    },
    /// The file adds its allocated size: it is dataless, its private size
    /// is above its allocated size, or it is compressed with a clone count
    /// of 1.
    Allocated(Bytes),
    /// A compressed file whose clone count the volume did not report. It
    /// adds zero, because its blocks can be shared.
    UnknownSharing,
}

/// The cause of a failed private-size call.
pub(super) fn cause_of_error(error: &io::Error) -> PrivateSizeUnavailable {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => PrivateSizeUnavailable::PermissionDenied,
        Some(libc::ENOENT) => PrivateSizeUnavailable::IdentityChanged,
        // The kernel does not support an attribute of the request.
        Some(libc::EINVAL | libc::ENOTSUP) => PrivateSizeUnavailable::NotReported,
        _ => PrivateSizeUnavailable::QueryFailed,
    }
}

/// Whether the kernel refused an attribute of the request.
pub(super) fn is_unsupported_request(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP))
}

/// Classifies the attributes of one regular file.
///
/// `inode`, `allocated`, and `compressed` are from the `fstatat`
/// measurement of the file.
///
/// # Errors
///
/// Returns the cause that makes the quantities of the scan unavailable.
pub(super) fn file_part(
    attributes: io::Result<PrivateAttributes>,
    inode: u64,
    allocated: Bytes,
    compressed: bool,
) -> Result<FilePart, PrivateSizeUnavailable> {
    let attributes: PrivateAttributes = attributes.map_err(|error| cause_of_error(&error))?;
    let file_id: u64 = attributes
        .file_id
        .ok_or(PrivateSizeUnavailable::NotReported)?;
    if file_id != inode {
        return Err(PrivateSizeUnavailable::IdentityChanged);
    }
    let private_size: i64 = attributes
        .private_size
        .ok_or(PrivateSizeUnavailable::NotReported)?;
    let private: Bytes = u64::try_from(private_size)
        .map(Bytes::new)
        .map_err(|_| PrivateSizeUnavailable::InconsistentValue)?;
    let family = |shared: Bytes| match (attributes.clone_id, attributes.clone_count) {
        (Some(family), Some(members)) if members > 1 => Some(CloneShare {
            family,
            members,
            shared,
        }),
        _ => None,
    };
    if compressed {
        // APFS does not count compressed data in the private size.
        return Ok(match attributes.clone_count {
            None => FilePart::UnknownSharing,
            Some(0 | 1) => FilePart::Allocated(allocated),
            Some(_) => match family(allocated) {
                Some(clone) => FilePart::Private {
                    private: Bytes::ZERO,
                    clone: Some(clone),
                },
                None => FilePart::UnknownSharing,
            },
        });
    }
    if private > allocated {
        return Ok(FilePart::Allocated(allocated));
    }
    let shared: Bytes = Bytes::new(allocated.get() - private.get());
    Ok(FilePart::Private {
        private,
        clone: family(shared),
    })
}

/// A hard-linked object that the scan counted one time.
#[derive(Debug, Clone, Copy)]
struct LinkedObject {
    /// `st_nlink` at the first name.
    links: u64,
    /// The names that the scan found.
    found: u64,
    part: FilePart,
}

/// The members of one clone family that the scan found.
#[derive(Debug, Clone, Copy)]
struct Family {
    /// The largest clone count that a member reported.
    members: u32,
    found: u32,
    /// The largest shared part of a member.
    shared: Bytes,
}

/// Adds `bytes` to a running sum. The first cause stays.
fn add_to(sum: &mut Result<Bytes, PrivateSizeUnavailable>, bytes: Bytes) {
    if let Ok(value) = *sum {
        *sum = value
            .checked_add(bytes)
            .ok_or(PrivateSizeUnavailable::Overflow);
    }
}

fn reading(sum: Result<Bytes, PrivateSizeUnavailable>) -> PrivateBytes {
    match sum {
        Ok(bytes) => PrivateBytes::Available { bytes },
        Err(cause) => PrivateBytes::Unavailable { cause },
    }
}

fn bump(count: &mut EntryCount) {
    if let Some(next) = count.checked_add(EntryCount::new(1)) {
        *count = next;
    }
}

/// The running calculation of the private allocated bytes of one scan.
#[derive(Debug)]
pub(super) struct PrivateTally {
    /// The sum of the private parts, or the first cause of unavailability.
    sum: Result<Bytes, PrivateSizeUnavailable>,
    linked: HashMap<u64, LinkedObject>,
    families: HashMap<u64, Family>,
    family_limit: usize,
    files_by_private_size: EntryCount,
    files_by_allocated_size: EntryCount,
    compressed_files_with_unknown_sharing: EntryCount,
    clone_members_without_shared_part: EntryCount,
    clone_families_not_tracked: EntryCount,
    hard_linked_objects_with_names_outside: EntryCount,
    entries_without_allocated_size: EntryCount,
}

impl PrivateTally {
    pub(super) fn new(family_limit: usize) -> Self {
        Self {
            sum: Ok(Bytes::ZERO),
            linked: HashMap::new(),
            families: HashMap::new(),
            family_limit,
            files_by_private_size: EntryCount::ZERO,
            files_by_allocated_size: EntryCount::ZERO,
            compressed_files_with_unknown_sharing: EntryCount::ZERO,
            clone_members_without_shared_part: EntryCount::ZERO,
            clone_families_not_tracked: EntryCount::ZERO,
            hard_linked_objects_with_names_outside: EntryCount::ZERO,
            entries_without_allocated_size: EntryCount::ZERO,
        }
    }

    /// Whether the quantities can still be available. When they cannot,
    /// the traversal does not read the attributes of a later file.
    pub(super) fn is_available(&self) -> bool {
        self.sum.is_ok()
    }

    /// Makes the quantities unavailable. The first cause stays.
    pub(super) fn fail(&mut self, cause: PrivateSizeUnavailable) {
        if self.sum.is_ok() {
            self.sum = Err(cause);
        }
    }

    /// Adds an object that is not a regular file and adds its allocated
    /// size: the root, a directory, or a symbolic link.
    pub(super) fn add_allocated(&mut self, allocated: Bytes) {
        add_to(&mut self.sum, allocated);
    }

    /// Records a counted entry that has no allocated size and adds zero.
    pub(super) fn add_without_size(&mut self) {
        bump(&mut self.entries_without_allocated_size);
    }

    /// Adds a regular file with one name.
    pub(super) fn add_file(&mut self, part: FilePart) {
        self.count(part);
    }

    /// Adds the first name of a hard-linked regular file. The object adds
    /// its part at the end, when the scan found each of its names.
    pub(super) fn add_first_link(&mut self, inode: u64, links: u64, part: FilePart) {
        self.linked.insert(
            inode,
            LinkedObject {
                links,
                found: 1,
                part,
            },
        );
    }

    /// Adds a later name of a hard-linked regular file.
    pub(super) fn add_later_link(&mut self, inode: u64) {
        if let Some(object) = self.linked.get_mut(&inode) {
            object.found = object.found.saturating_add(1);
        }
    }

    fn count(&mut self, part: FilePart) {
        match part {
            FilePart::Allocated(allocated) => {
                bump(&mut self.files_by_allocated_size);
                add_to(&mut self.sum, allocated);
            }
            FilePart::UnknownSharing => bump(&mut self.compressed_files_with_unknown_sharing),
            FilePart::Private { private, clone } => {
                bump(&mut self.files_by_private_size);
                add_to(&mut self.sum, private);
                if let Some(clone) = clone {
                    self.join(clone);
                }
            }
        }
    }

    fn join(&mut self, clone: CloneShare) {
        if clone.shared == Bytes::ZERO {
            bump(&mut self.clone_members_without_shared_part);
        }
        let tracked: usize = self.families.len();
        match self.families.entry(clone.family) {
            Entry::Occupied(mut occupied) => {
                let family: &mut Family = occupied.get_mut();
                family.found = family.found.saturating_add(1);
                family.members = family.members.max(clone.members);
                family.shared = family.shared.max(clone.shared);
            }
            Entry::Vacant(vacant) if tracked < self.family_limit => {
                vacant.insert(Family {
                    members: clone.members,
                    found: 1,
                    shared: clone.shared,
                });
            }
            Entry::Vacant(_) => bump(&mut self.clone_families_not_tracked),
        }
    }

    /// Ends the calculation.
    pub(super) fn finish(mut self) -> PrivateAllocation {
        let linked: Vec<LinkedObject> = self.linked.drain().map(|(_, object)| object).collect();
        for object in linked {
            if object.found >= object.links {
                self.count(object.part);
            } else {
                bump(&mut self.hard_linked_objects_with_names_outside);
            }
        }
        let mut complete: EntryCount = EntryCount::ZERO;
        let mut shared: Result<Bytes, PrivateSizeUnavailable> = self.sum.map(|_| Bytes::ZERO);
        for family in self.families.values() {
            if family.found >= family.members {
                bump(&mut complete);
                add_to(&mut shared, family.shared);
            }
        }
        PrivateAllocation {
            bytes: reading(self.sum),
            complete_family_shared_bytes: reading(shared),
            files_by_private_size: self.files_by_private_size,
            files_by_allocated_size: self.files_by_allocated_size,
            compressed_files_with_unknown_sharing: self.compressed_files_with_unknown_sharing,
            clone_families: EntryCount::new(u64::try_from(self.families.len()).unwrap_or(u64::MAX)),
            clone_families_complete: complete,
            clone_members_without_shared_part: self.clone_members_without_shared_part,
            clone_families_not_tracked: self.clone_families_not_tracked,
            hard_linked_objects_with_names_outside: self.hard_linked_objects_with_names_outside,
            entries_without_allocated_size: self.entries_without_allocated_size,
        }
    }
}
