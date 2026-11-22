//! The identity checks of the executable and of the scope root.

use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use svalnir_core::action::{ExecutableBinding, GROUP_OR_OTHER_WRITE};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::process::Uid;
use svalnir_core::quantity::Bytes;

/// The user ID of root.
const ROOT_UID: u32 = 0;

/// The permission bits of a mode.
const PERMISSION_BITS: u32 = 0o7777;

/// The execute bits of a mode.
const EXECUTE_BITS: u32 = 0o111;

/// Why an executable is not bound or is not the bound one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableProblem {
    /// No file is at the path, or the path is not absolute.
    NotFound,
    /// The object at the path is a symbolic link, is not a regular file,
    /// or has no execute bit.
    NotExecutable,
    /// The owner of the file or of a directory above it is not root or the
    /// principal, its mode permits a write by the group or by others, or a
    /// directory above it is a symbolic link.
    NotTrusted,
    /// The file is larger than the limit of the digest, or a read failed.
    NotReadable,
    /// The file changed between two readings of it.
    Changed,
}

/// Whether a different user cannot change an object of `metadata`: the
/// owner is root or `principal`, and the mode has no write bit for the
/// group or for others.
fn is_trusted(metadata: &Metadata, principal: Uid) -> bool {
    let owner: u32 = metadata.uid();
    (owner == ROOT_UID || owner == principal.get()) && metadata.mode() & GROUP_OR_OTHER_WRITE == 0
}

/// The device and the inode of `metadata`.
pub(super) fn object_of(metadata: &Metadata) -> Option<FileObjectEvidence> {
    // `st_dev` is a signed number, and the standard library gives it with
    // its sign extended.
    let device: i32 = i32::try_from(i64::from_ne_bytes(metadata.dev().to_ne_bytes())).ok()?;
    Some(FileObjectEvidence {
        device: DeviceNumber::new(device),
        inode: InodeNumber::new(metadata.ino()),
    })
}

/// Examines the executable at `path` for a binding of `principal`.
///
/// The path must be absolute, and each directory above it must be a
/// directory, not a symbolic link, with root or `principal` as its owner
/// and no write bit for the group or for others. The file must be a regular
/// file with an execute bit and the same owner rule and mode rule. The
/// executor reads the file through a descriptor that it opened with no
/// symbolic link, compares the descriptor with the path, and reads at most
/// `limit` bytes for the SHA-256 digest. This build reads no code-signing
/// identity.
///
/// # Errors
///
/// Returns the [`ExecutableProblem`] of the first check that fails.
pub fn examine_executable(
    path: &Path,
    principal: Uid,
    limit: u64,
) -> Result<ExecutableBinding, ExecutableProblem> {
    if !path.is_absolute() {
        return Err(ExecutableProblem::NotFound);
    }
    let metadata: Metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ExecutableProblem::NotFound);
        }
        Err(_) => return Err(ExecutableProblem::NotReadable),
    };
    if !metadata.file_type().is_file() || metadata.mode() & EXECUTE_BITS == 0 {
        return Err(ExecutableProblem::NotExecutable);
    }
    if !is_trusted(&metadata, principal) {
        return Err(ExecutableProblem::NotTrusted);
    }
    for ancestor in path.ancestors().skip(1) {
        let directory: Metadata =
            fs::symlink_metadata(ancestor).map_err(|_| ExecutableProblem::NotTrusted)?;
        if !directory.file_type().is_dir() || !is_trusted(&directory, principal) {
            return Err(ExecutableProblem::NotTrusted);
        }
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ExecutableProblem::NotReadable)?;
    let opened: Metadata = file
        .metadata()
        .map_err(|_| ExecutableProblem::NotReadable)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(ExecutableProblem::Changed);
    }
    if opened.len() > limit {
        return Err(ExecutableProblem::NotReadable);
    }
    let digest: ContentDigest =
        ContentDigest::of_reader(&file, limit).map_err(|_| ExecutableProblem::NotReadable)?;
    let after: Metadata = file
        .metadata()
        .map_err(|_| ExecutableProblem::NotReadable)?;
    if after.len() != opened.len() || after.mtime() != opened.mtime() {
        return Err(ExecutableProblem::Changed);
    }
    Ok(ExecutableBinding {
        path: LosslessPath::from_path(path).map_err(|_| ExecutableProblem::NotFound)?,
        object: object_of(&opened).ok_or(ExecutableProblem::NotReadable)?,
        owner: Uid::new(opened.uid()),
        mode: opened.mode() & PERMISSION_BITS,
        size: Bytes::new(opened.len()),
        digest,
        signature: None,
    })
}

/// Why the executor refuses the executable of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutableRefusal {
    /// The file is not the file of the plan.
    Changed,
    /// The owner or the mode of the file or of a directory above it
    /// permits a change by a different user.
    NotTrusted,
}

/// Compares the executable at the path of `planned` with the plan, and
/// examines its owner and its mode again.
pub(super) fn check_executable(
    planned: &ExecutableBinding,
    principal: Uid,
    limit: u64,
) -> Result<(), ExecutableRefusal> {
    let path = planned.path.to_path_buf();
    match examine_executable(&path, principal, limit) {
        Ok(current) => {
            // The code-signing identity is not read in this build; each
            // other value must be the value of the plan.
            let same: bool = current.path == planned.path
                && current.object == planned.object
                && current.owner == planned.owner
                && current.mode == planned.mode
                && current.size == planned.size
                && current.digest == planned.digest;
            if same {
                Ok(())
            } else {
                Err(ExecutableRefusal::Changed)
            }
        }
        Err(ExecutableProblem::NotTrusted) => Err(ExecutableRefusal::NotTrusted),
        Err(_) => Err(ExecutableRefusal::Changed),
    }
}

/// Whether the scope root at `path` is the planned directory: a directory,
/// not a symbolic link, with the planned device, inode, and owner.
pub(super) fn is_planned_root(path: &Path, object: &FileObjectEvidence, owner: Uid) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && object_of(&metadata).as_ref() == Some(object)
            && metadata.uid() == owner.get()
    })
}
