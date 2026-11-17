//! Revalidation of one file target immediately before its call.
//!
//! [`locate`] applies the hard refusals, opens the approved root one
//! component at a time from `/`, walks to the parent directory of the
//! entry, and compares the device, the inode, the type, and the owner of
//! the entry with the binding of the plan. A difference is a skip with its
//! reason. No step falls back to the path string, and no call resolves a
//! path of more than one component.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};

use svalnir_core::action::{FileBinding, FileObjectType, StopReason};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence};

use super::errors::{Cause, code, read_cause};
use super::model::{AnchoredRoot, ApprovedRoots, path_components};
use super::native::{self, Kind, Metadata};

/// A point of the execution at which a test can change the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Checkpoint {
    /// The target passed its revalidation. The call follows.
    Revalidated,
    /// The tree of a directory target was measured. The removal follows.
    TreeEnumerated,
    /// One entry of a tree passed its comparison with the measurement. Its
    /// call follows.
    EntryChecked,
}

/// A hook that replaces the metadata of the entry at a path.
pub(super) type MetadataHook = Box<dyn Fn(&[u8], &mut Metadata) + Send + Sync>;

/// A hook that runs at a checkpoint, with the path of the entry.
pub(super) type CheckpointHook = Box<dyn Fn(Checkpoint, &[u8]) + Send + Sync>;

/// The hooks of the tests. A production executor has none.
#[derive(Default)]
pub(super) struct Injection {
    /// Changes each measurement, for example to give an entry the device
    /// number of another filesystem.
    pub(super) metadata: Option<MetadataHook>,
    /// Runs between a check and the call that follows it.
    pub(super) checkpoint: Option<CheckpointHook>,
}

impl std::fmt::Debug for Injection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Injection")
            .field("metadata", &self.metadata.is_some())
            .field("checkpoint", &self.checkpoint.is_some())
            .finish()
    }
}

impl Injection {
    /// Gives a measurement to the metadata hook.
    pub(super) fn observe(&self, path: &[u8], mut metadata: Metadata) -> Metadata {
        if let Some(hook) = &self.metadata {
            hook(path, &mut metadata);
        }
        metadata
    }

    /// Runs the checkpoint hook.
    pub(super) fn reach(&self, checkpoint: Checkpoint, path: &[u8]) {
        if let Some(hook) = &self.checkpoint {
            hook(checkpoint, path);
        }
    }
}

/// The reason no call is issued for a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Refusal {
    pub(super) cause: Cause,
    /// `TARGET_SKIPPED` for a check that did not permit the target, and
    /// `FAILED` for a read-only call that failed.
    pub(super) stop_reason: StopReason,
}

impl Refusal {
    /// A check did not permit the target.
    pub(super) const fn skipped(cause: Cause) -> Self {
        Self {
            cause,
            stop_reason: StopReason::TargetSkipped,
        }
    }

    /// A read-only call failed.
    pub(super) fn read_failure(error: &io::Error) -> Self {
        Self {
            cause: read_cause(error.raw_os_error()),
            stop_reason: StopReason::Failed,
        }
    }
}

/// A target that passed its revalidation.
#[derive(Debug)]
pub(super) struct Located {
    /// The open parent directory of the entry.
    pub(super) parent: OwnedFd,
    /// The name of the entry in the parent directory.
    pub(super) name: CString,
    /// The measurement of the entry.
    pub(super) metadata: Metadata,
    /// The device of the approved root. Each entry of the target is on
    /// this device.
    pub(super) device: DeviceNumber,
    /// The identity of the entry.
    pub(super) object: FileObjectEvidence,
    /// The absolute path of the entry, for the Trash backend and the
    /// hooks. No removal call uses it.
    pub(super) path: Vec<u8>,
}

/// The result of a revalidation.
#[derive(Debug)]
pub(super) enum Resolution {
    /// The entry exists and agrees with the plan.
    Located(Located),
    /// The entry, or a directory between the root and the entry, is
    /// absent.
    Absent,
    /// No call is permitted.
    Refused(Refusal),
}

/// Whether an `openat` error shows a symbolic link or an object that is
/// not a directory. macOS gives `ELOOP` for a symbolic link with
/// `O_NOFOLLOW`; Linux gives `ENOTDIR` with `O_DIRECTORY`.
pub(super) fn is_not_directory(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP | libc::ENOTDIR | libc::EMLINK)
    )
}

pub(super) fn is_absent(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOENT)
}

/// Appends `/` and a name to a path.
pub(super) fn push_name(path: &mut Vec<u8>, name: &CStr) {
    path.push(b'/');
    path.extend_from_slice(name.to_bytes());
}

/// The identity of a measurement. `None` when the device number does not
/// fit its type.
pub(super) fn identity_of(metadata: &Metadata) -> Option<FileObjectEvidence> {
    Some(FileObjectEvidence {
        device: metadata.device?,
        inode: metadata.inode.into(),
    })
}

/// The home directory of the user, by its path and by its identity.
///
/// The path comparison alone is not sufficient. A filesystem that ignores
/// case or Unicode normalization gives one directory more than one
/// spelling, and a firmlink or a bind mount gives it more than one path;
/// no-follow protection stops none of these. The guard thus also holds the
/// device and the inode of the home directory and of each directory that
/// contains it, and a target with one of those identities is refused
/// under each name.
#[derive(Debug)]
pub(super) struct HomeGuard {
    components: Vec<CString>,
    objects: Vec<FileObjectEvidence>,
}

impl HomeGuard {
    /// Opens the home directory from `/`, one component at a time with
    /// no-follow protection, and keeps the identity of each directory of
    /// the path.
    ///
    /// # Errors
    ///
    /// Returns the error of the call when a component is absent, is a
    /// symbolic link, or is not a directory, or when an identity cannot
    /// be read.
    pub(super) fn anchor(components: Vec<CString>) -> io::Result<Self> {
        let mut objects: Vec<FileObjectEvidence> = Vec::with_capacity(components.len());
        let mut directory: OwnedFd = native::open_filesystem_root()?;
        for component in &components {
            directory = native::open_directory_at(directory.as_fd(), component)?;
            let measured: Metadata = native::stat_descriptor(directory.as_fd())?;
            let object: FileObjectEvidence = identity_of(&measured)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            objects.push(object);
        }
        Ok(Self {
            components,
            objects,
        })
    }

    /// Whether `object` is the home directory or a directory that
    /// contains it.
    fn has_object(&self, object: FileObjectEvidence) -> bool {
        self.objects.contains(&object)
    }
}

/// Whether the target path is the home directory or a directory that
/// contains it, by a comparison of whole components. [`HomeGuard`] also
/// compares the identity, because one directory can have more than one
/// path.
fn contains_home(root: &[CString], relative: &[CString], home: &[CString]) -> bool {
    let target = root.iter().chain(relative);
    let length: usize = root.len() + relative.len();
    length <= home.len() && target.zip(home).all(|(left, right)| left == right)
}

/// Opens the approved root from `/`, one component at a time, and compares
/// its identity with the evidence of the root.
fn open_root(root: &AnchoredRoot, injection: &Injection) -> Result<OwnedFd, Refusal> {
    let changed = || Refusal::skipped(Cause::evidence(code::ROOT_IDENTITY_CHANGED));
    let mut directory: OwnedFd =
        native::open_filesystem_root().map_err(|error| Refusal::read_failure(&error))?;
    for component in &root.components {
        directory = match native::open_directory_at(directory.as_fd(), component) {
            Ok(next) => next,
            Err(error) if is_absent(&error) => {
                return Err(Refusal::skipped(Cause::evidence(code::ROOT_UNAVAILABLE)));
            }
            Err(error) if is_not_directory(&error) => return Err(changed()),
            Err(error) => return Err(Refusal::read_failure(&error)),
        };
    }
    let measured: Metadata = native::stat_descriptor(directory.as_fd())
        .map_err(|error| Refusal::read_failure(&error))?;
    let measured: Metadata = injection.observe(root.root.path.as_bytes(), measured);
    if identity_of(&measured) == Some(root.root.object) && measured.kind == Kind::Directory {
        Ok(directory)
    } else {
        Err(changed())
    }
}

/// Checks the binding before any call: the refusals that need no
/// filesystem access.
fn check_binding<'a>(
    file: &FileBinding,
    roots: &'a ApprovedRoots,
    home: &HomeGuard,
) -> Result<(&'a AnchoredRoot, Vec<CString>, FileObjectEvidence), Refusal> {
    let Some(root) = roots.anchored(&file.root_id) else {
        return Err(Refusal::skipped(Cause::eligibility(
            code::OUTSIDE_APPROVED_ROOTS,
        )));
    };
    let Some(relative) = path_components(file.relative_entry.as_bytes(), false) else {
        return Err(Refusal::skipped(Cause::request(
            code::RELATIVE_ENTRY_INVALID,
        )));
    };
    if !file.object_type.is_recognized() {
        return Err(Refusal::skipped(Cause::request(
            code::OBJECT_TYPE_UNRECOGNIZED,
        )));
    }
    if contains_home(&root.components, &relative, &home.components) {
        return Err(Refusal::skipped(Cause::eligibility(
            code::HOME_DIRECTORY_PROTECTED,
        )));
    }
    if file.volume_id != root.root.volume_id || file.mount_id != root.root.mount_id {
        return Err(Refusal::skipped(Cause::evidence(code::VOLUME_MISMATCH)));
    }
    let Some(object) = file.object else {
        return Err(Refusal::skipped(Cause::evidence(
            code::IDENTITY_EVIDENCE_ABSENT,
        )));
    };
    if home.has_object(object) {
        return Err(Refusal::skipped(Cause::eligibility(
            code::HOME_DIRECTORY_PROTECTED,
        )));
    }
    if object.device != root.root.object.device {
        return Err(Refusal::skipped(Cause::evidence(code::DEVICE_MISMATCH)));
    }
    if object == root.root.object {
        return Err(Refusal::skipped(Cause::eligibility(
            code::APPROVED_ROOT_IS_TARGET,
        )));
    }
    Ok((root, relative, object))
}

/// Compares the measurement of the entry with the binding of the plan.
fn check_entry(
    file: &FileBinding,
    object: FileObjectEvidence,
    root: &AnchoredRoot,
    home: &HomeGuard,
    measured: &Metadata,
) -> Result<(), Refusal> {
    let skip = |cause: Cause| Err(Refusal::skipped(cause));
    let device: DeviceNumber = root.root.object.device;
    if measured.device != Some(device) {
        return skip(Cause::evidence(code::MOUNT_CROSSED));
    }
    let planned: Kind = match file.object_type {
        FileObjectType::RegularFile => Kind::File,
        FileObjectType::Directory => Kind::Directory,
        FileObjectType::SymbolicLink => Kind::Symlink,
        FileObjectType::Unrecognized(_) => {
            return skip(Cause::request(code::OBJECT_TYPE_UNRECOGNIZED));
        }
    };
    if measured.kind == Kind::Other {
        return skip(Cause::eligibility(code::UNSUPPORTED_FILE_TYPE));
    }
    if measured.kind != planned {
        return skip(Cause::evidence(code::TARGET_TYPE_CHANGED));
    }
    let measured_object: Option<FileObjectEvidence> = identity_of(measured);
    // The measured identity, under each name that reaches it.
    if measured_object.is_some_and(|measured| home.has_object(measured)) {
        return skip(Cause::eligibility(code::HOME_DIRECTORY_PROTECTED));
    }
    if measured_object != Some(object) {
        return skip(Cause::evidence(code::TARGET_IDENTITY_CHANGED));
    }
    if measured_object == Some(root.root.object) {
        return skip(Cause::eligibility(code::APPROVED_ROOT_IS_TARGET));
    }
    if measured.owner != file.owner.get() {
        return skip(Cause::evidence(code::TARGET_OWNER_CHANGED));
    }
    Ok(())
}

/// Revalidates the target of `file`.
///
pub(super) fn locate(
    file: &FileBinding,
    roots: &ApprovedRoots,
    home: &HomeGuard,
    injection: &Injection,
) -> Resolution {
    let (root, relative, object) = match check_binding(file, roots, home) {
        Ok(checked) => checked,
        Err(refusal) => return Resolution::Refused(refusal),
    };
    let Some((name, parents)) = relative.split_last() else {
        return Resolution::Refused(Refusal::skipped(Cause::request(
            code::RELATIVE_ENTRY_INVALID,
        )));
    };
    let mut directory: OwnedFd = match open_root(root, injection) {
        Ok(directory) => directory,
        Err(refusal) => return Resolution::Refused(refusal),
    };
    let device: DeviceNumber = root.root.object.device;
    let mut path: Vec<u8> = root.root.path.as_bytes().to_vec();
    for component in parents {
        push_name(&mut path, component);
        directory = match native::open_directory_at(directory.as_fd(), component) {
            Ok(next) => next,
            Err(error) if is_absent(&error) => return Resolution::Absent,
            Err(error) if is_not_directory(&error) => {
                return Resolution::Refused(Refusal::skipped(Cause::evidence(
                    code::PARENT_NOT_DIRECTORY,
                )));
            }
            Err(error) => return Resolution::Refused(Refusal::read_failure(&error)),
        };
        let measured: Metadata = match native::stat_descriptor(directory.as_fd()) {
            Ok(measured) => injection.observe(&path, measured),
            Err(error) => return Resolution::Refused(Refusal::read_failure(&error)),
        };
        if measured.device != Some(device) {
            return Resolution::Refused(Refusal::skipped(Cause::evidence(code::MOUNT_CROSSED)));
        }
    }
    push_name(&mut path, name);
    let measured: Metadata = match native::stat_at(directory.as_fd(), name) {
        Ok(measured) => injection.observe(&path, measured),
        Err(error) if is_absent(&error) => return Resolution::Absent,
        // A parent that is not a directory any more.
        Err(error) if is_not_directory(&error) => {
            return Resolution::Refused(Refusal::skipped(Cause::evidence(
                code::PARENT_NOT_DIRECTORY,
            )));
        }
        Err(error) => return Resolution::Refused(Refusal::read_failure(&error)),
    };
    if let Err(refusal) = check_entry(file, object, root, home, &measured) {
        return Resolution::Refused(refusal);
    }
    Resolution::Located(Located {
        parent: directory,
        name: name.clone(),
        metadata: measured,
        device,
        object,
        path,
    })
}
