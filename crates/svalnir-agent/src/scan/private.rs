//! The private allocated bytes of the root of a scan.
//!
//! `docs/RESOURCE_MODEL.md` section 8 defines the quantity. The traversal
//! gives each counted object to a [`PrivateTally`]; the tally adds the
//! private part of each object, keeps the hard-linked objects until the
//! scan ends, and adds the shared part of each clone family whose members
//! the scan found. The tally does no native call.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;

use svalnir_core::quantity::{Bytes, EntryCount};

use super::model::{PrivateAllocation, PrivateBytes, PrivateSizeUnavailable};
use super::native::PrivateAttributes;

/// The largest number of clone families that one scan tracks. A member of
/// a family above this number adds only its private part, which can only
/// make the quantity smaller.
pub(super) const MAX_CLONE_FAMILIES: usize = 1_000_000;

/// The membership of one file in a clone family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CloneShare {
    /// `ATTR_CMNEXT_CLONEID`.
    pub(super) family: u64,
    /// `ATTR_CMNEXT_CLONE_REFCNT`: the number of files of the family.
    pub(super) members: u32,
    /// The allocated size minus the private size of the file.
    pub(super) shared: Bytes,
}

/// What one counted regular file adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilePart {
    /// The volume reported the private size.
    Private {
        /// `ATTR_CMNEXT_PRIVATESIZE`.
        private: Bytes,
        /// The clone family, when the file shares blocks with clones.
        clone: Option<CloneShare>,
    },
    /// The file adds its allocated size: it is compressed or dataless, or
    /// its private size is above its allocated size.
    Allocated(Bytes),
}

/// Classifies the attributes of one regular file.
///
/// `inode` and `allocated` are from the `fstatat` measurement of the file.
///
/// # Errors
///
/// Returns the cause that makes the quantity of the scan unavailable.
pub(super) fn file_part(
    attributes: io::Result<PrivateAttributes>,
    inode: u64,
    allocated: Bytes,
) -> Result<FilePart, PrivateSizeUnavailable> {
    let attributes: PrivateAttributes = attributes.map_err(|error| match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => PrivateSizeUnavailable::PermissionDenied,
        Some(libc::ENOENT) => PrivateSizeUnavailable::IdentityChanged,
        _ => PrivateSizeUnavailable::QueryFailed,
    })?;
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
    if private > allocated {
        return Ok(FilePart::Allocated(allocated));
    }
    let shared: Bytes = Bytes::new(allocated.get() - private.get());
    let clone: Option<CloneShare> = match (attributes.clone_id, attributes.clone_count) {
        (Some(family), Some(members)) if members > 1 && shared > Bytes::ZERO => Some(CloneShare {
            family,
            members,
            shared,
        }),
        _ => None,
    };
    Ok(FilePart::Private { private, clone })
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
    clone_families_not_tracked: EntryCount,
    hard_linked_objects_with_names_outside: EntryCount,
}

fn bump(count: &mut EntryCount) {
    if let Some(next) = count.checked_add(EntryCount::new(1)) {
        *count = next;
    }
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
            clone_families_not_tracked: EntryCount::ZERO,
            hard_linked_objects_with_names_outside: EntryCount::ZERO,
        }
    }

    /// Whether the quantity can still be available. When it cannot, the
    /// traversal does not read the attributes of a later file.
    pub(super) fn is_available(&self) -> bool {
        self.sum.is_ok()
    }

    /// Makes the quantity unavailable. The first cause stays.
    pub(super) fn fail(&mut self, cause: PrivateSizeUnavailable) {
        if self.sum.is_ok() {
            self.sum = Err(cause);
        }
    }

    fn add(&mut self, bytes: Bytes) {
        if let Ok(sum) = self.sum {
            self.sum = sum
                .checked_add(bytes)
                .ok_or(PrivateSizeUnavailable::Overflow);
        }
    }

    /// Adds an object that is not a regular file and adds its allocated
    /// size: the root, a directory, or a symbolic link.
    pub(super) fn add_allocated(&mut self, allocated: Bytes) {
        self.add(allocated);
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
                self.add(allocated);
            }
            FilePart::Private { private, clone } => {
                bump(&mut self.files_by_private_size);
                self.add(private);
                if let Some(clone) = clone {
                    self.join(clone);
                }
            }
        }
    }

    fn join(&mut self, clone: CloneShare) {
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
        let shared: Vec<Bytes> = self
            .families
            .values()
            .filter(|family| family.found >= family.members)
            .map(|family| family.shared)
            .collect();
        for bytes in shared {
            bump(&mut complete);
            self.add(bytes);
        }
        PrivateAllocation {
            bytes: match self.sum {
                Ok(bytes) => PrivateBytes::Available { bytes },
                Err(cause) => PrivateBytes::Unavailable { cause },
            },
            files_by_private_size: self.files_by_private_size,
            files_by_allocated_size: self.files_by_allocated_size,
            clone_families: EntryCount::new(u64::try_from(self.families.len()).unwrap_or(u64::MAX)),
            clone_families_complete: complete,
            clone_families_not_tracked: self.clone_families_not_tracked,
            hard_linked_objects_with_names_outside: self.hard_linked_objects_with_names_outside,
        }
    }
}
