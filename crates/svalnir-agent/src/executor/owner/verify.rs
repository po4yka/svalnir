//! The identity checks of the executable and of the scope root.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use svalnir_core::action::{
    ExecutableBinding, FileTimestamp, GROUP_OR_OTHER_WRITE, InterpreterBinding,
};
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
    /// The `#!` line of a script names an interpreter that is not an
    /// interpreter location of the declaration.
    InterpreterNotDeclared,
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
    let changed_at: FileTimestamp = timestamp(after.ctime(), after.ctime_nsec())?;
    let modified_at: FileTimestamp = timestamp(after.mtime(), after.mtime_nsec())?;
    let unchanged: bool = after.len() == opened.len()
        && timestamp(opened.ctime(), opened.ctime_nsec())? == changed_at
        && timestamp(opened.mtime(), opened.mtime_nsec())? == modified_at;
    if !unchanged {
        return Err(ExecutableProblem::Changed);
    }
    Ok(ExecutableBinding {
        path: LosslessPath::from_path(path).map_err(|_| ExecutableProblem::NotFound)?,
        object: object_of(&opened).ok_or(ExecutableProblem::NotReadable)?,
        owner: Uid::new(opened.uid()),
        mode: opened.mode() & PERMISSION_BITS,
        size: Bytes::new(opened.len()),
        changed_at,
        modified_at,
        digest,
        signature: None,
    })
}

/// A file time from its seconds and its nanoseconds.
fn timestamp(seconds: i64, nanoseconds: i64) -> Result<FileTimestamp, ExecutableProblem> {
    Ok(FileTimestamp {
        seconds,
        nanoseconds: u32::try_from(nanoseconds).map_err(|_| ExecutableProblem::NotReadable)?,
    })
}

/// The kind of an executable file, from its first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutableKind {
    /// A Mach-O file, thin or universal.
    MachO,
    /// A script: the interpreter path and the interpreter argument of its
    /// `#!` line.
    Script {
        /// The path of the `#!` line.
        interpreter: PathBuf,
        /// The argument of the `#!` line, when it has one.
        argument: Option<String>,
    },
}

/// The magic numbers of a Mach-O file and of a universal file, as the
/// first four bytes in file order.
const MACH_O_MAGIC: [[u8; 4]; 6] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe],
    [0xbe, 0xba, 0xfe, 0xca],
];

/// The longest `#!` line that the executor reads.
const MAX_SHEBANG_BYTES: usize = 256;

/// The kind of the file at `path`, from at most its first 256 bytes.
///
/// # Errors
///
/// Returns [`ExecutableProblem::NotExecutable`] for a file that is not a
/// Mach-O file and has no valid `#!` line: a line that is longer than the
/// limit, that is not UTF-8, that has no absolute interpreter path, or
/// that has more than one argument.
pub fn executable_kind(path: &Path) -> Result<ExecutableKind, ExecutableProblem> {
    let mut file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ExecutableProblem::NotReadable)?;
    let mut head: Vec<u8> = vec![0; MAX_SHEBANG_BYTES];
    let mut filled: usize = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ExecutableProblem::NotReadable),
        }
    }
    head.truncate(filled);
    if head.len() >= 4 && MACH_O_MAGIC.iter().any(|magic| head[..4] == *magic) {
        return Ok(ExecutableKind::MachO);
    }
    let line: &[u8] = head
        .strip_prefix(b"#!")
        .and_then(|rest| rest.split(|byte| *byte == b'\n').next())
        .filter(|_| head.contains(&b'\n'))
        .ok_or(ExecutableProblem::NotExecutable)?;
    let line: &str = std::str::from_utf8(line).map_err(|_| ExecutableProblem::NotExecutable)?;
    let mut words = line.split_ascii_whitespace();
    let interpreter: PathBuf = PathBuf::from(words.next().ok_or(ExecutableProblem::NotExecutable)?);
    let argument: Option<String> = words.next().map(str::to_owned);
    if words.next().is_some() || !interpreter.is_absolute() {
        return Err(ExecutableProblem::NotExecutable);
    }
    Ok(ExecutableKind::Script {
        interpreter,
        argument,
    })
}

/// The path of `env`, which a `#!` line can name to find its interpreter.
const ENV_PATH: &str = "/usr/bin/env";

/// Binds the executable at `path` and, for a script, its interpreter
/// (owner decision D2 of 2026-11-22).
///
/// `interpreters` are the canonical interpreter locations of the
/// declaration. The interpreter of the `#!` line must be one of them, with
/// its symbolic links resolved; for `#!/usr/bin/env NAME`, it is the one
/// whose file name is `NAME`, so `env` never searches `PATH`. The
/// interpreter must be a Mach-O file.
///
/// # Errors
///
/// Returns the [`ExecutableProblem`] of the first check that fails.
pub fn examine_program(
    path: &Path,
    interpreters: &[PathBuf],
    principal: Uid,
    limit: u64,
) -> Result<(ExecutableBinding, Option<InterpreterBinding>), ExecutableProblem> {
    let executable: ExecutableBinding = examine_executable(path, principal, limit)?;
    let (interpreter, arguments): (PathBuf, Vec<String>) = match executable_kind(path)? {
        ExecutableKind::MachO => return Ok((executable, None)),
        ExecutableKind::Script {
            interpreter,
            argument,
        } if interpreter == Path::new(ENV_PATH) => {
            let name: String = argument.ok_or(ExecutableProblem::NotExecutable)?;
            if name.starts_with('-') || name.contains('=') {
                return Err(ExecutableProblem::NotExecutable);
            }
            let found: PathBuf = interpreters
                .iter()
                .find(|candidate| {
                    candidate
                        .file_name()
                        .is_some_and(|file| file == name.as_str())
                })
                .cloned()
                .ok_or(ExecutableProblem::InterpreterNotDeclared)?;
            (found, Vec::new())
        }
        ExecutableKind::Script {
            interpreter,
            argument,
        } => {
            let resolved: PathBuf = fs::canonicalize(&interpreter)
                .map_err(|_| ExecutableProblem::InterpreterNotDeclared)?;
            if !interpreters.contains(&resolved) {
                return Err(ExecutableProblem::InterpreterNotDeclared);
            }
            (resolved, argument.into_iter().collect())
        }
    };
    if executable_kind(&interpreter)? != ExecutableKind::MachO {
        return Err(ExecutableProblem::NotExecutable);
    }
    let interpreter: ExecutableBinding = examine_executable(&interpreter, principal, limit)?;
    Ok((
        executable,
        Some(InterpreterBinding {
            executable: interpreter,
            arguments,
        }),
    ))
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
                && current.changed_at == planned.changed_at
                && current.modified_at == planned.modified_at
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

/// Whether the file of `planned` has its planned identity and change time
/// now, by its metadata only: the check after the suspended start, which
/// reads no content.
pub(super) fn has_planned_identity(planned: &ExecutableBinding) -> bool {
    fs::symlink_metadata(planned.path.to_path_buf()).is_ok_and(|metadata| {
        object_of(&metadata).as_ref() == Some(&planned.object)
            && timestamp(metadata.ctime(), metadata.ctime_nsec()).ok() == Some(planned.changed_at)
            && metadata.len() == planned.size.get()
    })
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
