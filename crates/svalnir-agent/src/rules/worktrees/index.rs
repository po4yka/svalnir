//! A reader for the entries of a Git index file, and the comparison of
//! their metadata with the work tree.
//!
//! The comparison reads metadata only. It does not read the content of a
//! file, so it runs no clean filter that the configuration of the
//! repository can name, as `git status` or `git diff-files` can. A file
//! whose metadata differs from its entry is counted as changed although
//! its content can be the same; that is the safe failure for a report of
//! the work that a removal can lose.
//!
//! The reader accepts the versions 2, 3, and 4 of the format with SHA-1
//! object names. A split index (the extension `link`) and a repository
//! with another object format are not accepted.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The length of a SHA-1 object name, in bytes.
const SHA1_LENGTH: usize = 20;

/// The largest number of entries that the reader accepts.
pub(super) const MAX_ENTRIES: u32 = 2_000_000;

/// The part of an index entry that the comparison uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IndexEntry {
    pub(super) path: Vec<u8>,
    pub(super) ctime: (u32, u32),
    pub(super) mtime: (u32, u32),
    pub(super) inode: u32,
    pub(super) mode: u32,
    pub(super) size: u32,
    pub(super) stage: u16,
    pub(super) skip_worktree: bool,
}

/// The big-endian `u32` at `offset`.
fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// The big-endian `u16` at `offset`.
fn half(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice: &[u8] = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// The offset variable-length integer of version 4 at `offset`, and the
/// offset after it.
fn varint(bytes: &[u8], mut offset: usize) -> Option<(usize, usize)> {
    let mut byte: u8 = *bytes.get(offset)?;
    offset += 1;
    let mut value: usize = usize::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *bytes.get(offset)?;
        offset += 1;
        value = value
            .checked_add(1)?
            .checked_mul(128)?
            .checked_add(usize::from(byte & 0x7f))?;
    }
    Some((value, offset))
}

/// The entries of the index file `bytes`.
///
/// # Errors
///
/// Returns a stable reason when the file does not have an accepted form.
pub(super) fn parse(bytes: &[u8]) -> Result<Vec<IndexEntry>, &'static str> {
    const INVALID: &str = "index_not_valid";
    if bytes.get(..4) != Some(b"DIRC") {
        return Err(INVALID);
    }
    let version: u32 = word(bytes, 4).ok_or(INVALID)?;
    if !(2..=4).contains(&version) {
        return Err("index_version_not_supported");
    }
    let count: u32 = word(bytes, 8).ok_or(INVALID)?;
    if count > MAX_ENTRIES {
        return Err("index_too_large");
    }
    let end: usize = bytes.len().checked_sub(SHA1_LENGTH).ok_or(INVALID)?;
    let mut offset: usize = 12;
    let mut entries: Vec<IndexEntry> = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let field = |index: usize| word(bytes, offset + 4 * index).ok_or(INVALID);
        let fixed: usize = offset.checked_add(40 + SHA1_LENGTH).ok_or(INVALID)?;
        let flags: u16 = half(bytes, fixed).ok_or(INVALID)?;
        let mut cursor: usize = fixed + 2;
        let mut skip_worktree: bool = false;
        if flags & 0x4000 != 0 {
            if version < 3 {
                return Err(INVALID);
            }
            let extended: u16 = half(bytes, cursor).ok_or(INVALID)?;
            skip_worktree = extended & 0x4000 != 0;
            cursor += 2;
        }
        let path: Vec<u8> = if version == 4 {
            let (strip, after) = varint(bytes, cursor).ok_or(INVALID)?;
            let keep: usize = previous.len().checked_sub(strip).ok_or(INVALID)?;
            let tail: &[u8] = bytes.get(after..end).ok_or(INVALID)?;
            let length: usize = tail.iter().position(|byte| *byte == 0).ok_or(INVALID)?;
            let mut path: Vec<u8> = previous[..keep].to_vec();
            path.extend_from_slice(&tail[..length]);
            cursor = after + length + 1;
            path
        } else {
            let tail: &[u8] = bytes.get(cursor..end).ok_or(INVALID)?;
            let length: usize = tail.iter().position(|byte| *byte == 0).ok_or(INVALID)?;
            let path: Vec<u8> = tail[..length].to_vec();
            // One to eight NUL bytes pad the entry to a multiple of eight.
            let size: usize = cursor - offset + length;
            cursor = offset + ((size + 8) & !7);
            path
        };
        if cursor > end {
            return Err(INVALID);
        }
        entries.push(IndexEntry {
            ctime: (field(0)?, field(1)?),
            mtime: (field(2)?, field(3)?),
            inode: field(5)?,
            mode: field(6)?,
            size: field(9)?,
            stage: (flags >> 12) & 0x3,
            skip_worktree,
            path: path.clone(),
        });
        previous = path;
        offset = cursor;
    }
    // The extensions, each with a signature and a size.
    while offset < end {
        let signature: &[u8] = bytes.get(offset..offset + 4).ok_or(INVALID)?;
        if signature == b"link" {
            return Err("split_index_not_supported");
        }
        let size: usize =
            usize::try_from(word(bytes, offset + 4).ok_or(INVALID)?).map_err(|_| INVALID)?;
        offset = offset
            .checked_add(8)
            .and_then(|start| start.checked_add(size))
            .ok_or(INVALID)?;
    }
    if offset != end {
        return Err(INVALID);
    }
    Ok(entries)
}

/// The mode type of a symbolic link, a submodule, and a directory of a
/// sparse index.
const TYPE_MASK: u32 = 0o170_000;
const TYPE_SYMLINK: u32 = 0o120_000;
const TYPE_GITLINK: u32 = 0o160_000;
const TYPE_DIRECTORY: u32 = 0o040_000;

/// Whether the path of an entry is a plain relative path in the work
/// tree.
fn is_plain(path: &[u8]) -> bool {
    !path.is_empty()
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".." | b".git"))
}

/// The result of the comparison of the entries with the work tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Comparison {
    /// The entries whose file is absent, or whose metadata differs from
    /// the entry, or whose entry has no nanoseconds and whose file is not
    /// older than the index (a racy entry).
    pub(super) changed: u64,
}

/// Compares the entries of stage 0 with the work tree at `work_tree`.
/// `index_mtime` is the modification time of the index file, in seconds.
///
/// An entry of a submodule, of a sparse directory, or with the flag
/// skip-worktree is not compared. A directory on the path of an entry
/// must not be a symbolic link, so that no metadata read leaves the work
/// tree.
///
/// # Errors
///
/// Returns a stable reason when an entry has a path that is not plain, a
/// metadata read fails for another cause than an absent file, or the
/// deadline passes.
pub(super) fn compare(
    entries: &[IndexEntry],
    work_tree: &Path,
    index_mtime: i64,
    deadline: Instant,
) -> Result<Comparison, &'static str> {
    let mut changed: u64 = 0;
    let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
    for (count, entry) in entries.iter().enumerate() {
        if count % 1024 == 0 && Instant::now() >= deadline {
            return Err("deadline_reached");
        }
        let kind: u32 = entry.mode & TYPE_MASK;
        if entry.stage != 0 || entry.skip_worktree || kind == TYPE_GITLINK || kind == TYPE_DIRECTORY
        {
            continue;
        }
        if !is_plain(&entry.path) {
            return Err("index_path_not_plain");
        }
        let path: PathBuf = work_tree.join(OsStr::from_bytes(&entry.path));
        // Each directory above the file is a directory, not a symbolic
        // link; a directory that is absent makes the file absent.
        let mut parent_absent: bool = false;
        for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
            if ancestor == work_tree || !ancestor.starts_with(work_tree) {
                break;
            }
            if directories.contains(ancestor) {
                break;
            }
            match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    directories.insert(ancestor.to_path_buf());
                }
                Ok(_) => {
                    parent_absent = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    parent_absent = true;
                    break;
                }
                Err(_) => return Err("work_tree_not_readable"),
            }
        }
        if parent_absent {
            changed += 1;
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                changed += 1;
                continue;
            }
            Err(_) => return Err("work_tree_not_readable"),
        };
        let is_link: bool = metadata.file_type().is_symlink();
        let kind_differs: bool = if kind == TYPE_SYMLINK {
            !is_link
        } else {
            !metadata.file_type().is_file()
        };
        // Git keeps the low 32 bits of each value.
        let low = |value: u64| (value & 0xffff_ffff) as u32;
        let time = |seconds: i64, nanoseconds: i64| {
            (
                low(seconds.cast_unsigned()),
                low(nanoseconds.cast_unsigned()),
            )
        };
        let same_time = |entry: (u32, u32), file: (u32, u32)| {
            entry.0 == file.0 && (entry.1 == 0 || entry.1 == file.1)
        };
        let executable_differs: bool =
            kind != TYPE_SYMLINK && (metadata.mode() & 0o100 != 0) != (entry.mode & 0o100 != 0);
        let differs: bool = kind_differs
            || low(metadata.size()) != entry.size
            || low(metadata.ino()) != entry.inode
            || !same_time(entry.mtime, time(metadata.mtime(), metadata.mtime_nsec()))
            || !same_time(entry.ctime, time(metadata.ctime(), metadata.ctime_nsec()))
            || executable_differs
            // Git marks an entry that is racy when it writes the index. An
            // entry with no nanoseconds cannot show a change in the second
            // of the index write, so such a file is counted.
            || (entry.mtime.1 == 0 && metadata.mtime() >= index_mtime);
        if differs {
            changed += 1;
        }
    }
    Ok(Comparison { changed })
}
