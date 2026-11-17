//! Lexical checks of a root path and of an entry below a root.
//!
//! `docs/ACTION_CONTRACTS.md` section 7 and `docs/THREAT_MODEL.md` (`T-04`)
//! own the rule: a path string is not a deletion capability, and a
//! string-prefix check is not a scope check. This module does not compare
//! prefixes and does not read the filesystem. It splits a path into names
//! and refuses each name that can leave the directory before it. The
//! result is a list of names, not a path string, so the executor has no
//! string to give to a call that follows links: it opens each name
//! relative to the handle of the directory before it, without following a
//! symbolic link, and checks the identity of each object.

use svalnir_core::file::LosslessPath;
use thiserror::Error;

/// The largest length of one name, in bytes (`NAME_MAX`).
pub const MAX_COMPONENT_BYTES: usize = 255;

/// The largest length of a root path or of an entry, in bytes (`PATH_MAX`).
pub const MAX_PATH_BYTES: usize = 1024;

/// The largest number of names in a root path or in an entry.
pub const MAX_PATH_DEPTH: usize = 32;

/// The reason a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum PathDefect {
    /// The path is empty.
    #[error("the path is empty")]
    Empty,
    /// The path has a NUL byte.
    #[error("the path has a NUL byte")]
    ContainsNul,
    /// The entry starts with `/`. An entry is relative to its root.
    #[error("the entry is an absolute path")]
    Absolute,
    /// The root does not start with `/`. A root is an absolute path.
    #[error("the root is a relative path")]
    Relative,
    /// The root is `/`. The filesystem root is not an approved root.
    #[error("the root is the filesystem root")]
    FilesystemRoot,
    /// The path has an empty name: `//` or a `/` at the end.
    #[error("the path has an empty name")]
    EmptyComponent,
    /// The path has the name `.`.
    #[error("the path has the name `.`")]
    CurrentDirectory,
    /// The path has the name `..`.
    #[error("the path has the name `..`")]
    ParentDirectory,
    /// A name is longer than [`MAX_COMPONENT_BYTES`].
    #[error("a name of the path is too long")]
    ComponentTooLong,
    /// The path is longer than [`MAX_PATH_BYTES`].
    #[error("the path is too long")]
    TooLong,
    /// The path has more than [`MAX_PATH_DEPTH`] names.
    #[error("the path has too many names")]
    TooDeep,
}

/// Splits `bytes` at each `/` and checks each name. The caller removed the
/// `/` at the start of an absolute path.
fn split_names(bytes: &[u8]) -> Result<Vec<Vec<u8>>, PathDefect> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for name in bytes.split(|byte: &u8| *byte == b'/') {
        if name.is_empty() {
            return Err(PathDefect::EmptyComponent);
        }
        if name == b"." {
            return Err(PathDefect::CurrentDirectory);
        }
        if name == b".." {
            return Err(PathDefect::ParentDirectory);
        }
        if name.contains(&0) {
            return Err(PathDefect::ContainsNul);
        }
        if name.len() > MAX_COMPONENT_BYTES {
            return Err(PathDefect::ComponentTooLong);
        }
        if names.len() >= MAX_PATH_DEPTH {
            return Err(PathDefect::TooDeep);
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

fn check_length(bytes: &[u8]) -> Result<(), PathDefect> {
    if bytes.is_empty() {
        return Err(PathDefect::Empty);
    }
    if bytes.len() > MAX_PATH_BYTES {
        return Err(PathDefect::TooLong);
    }
    Ok(())
}

/// An entry below a root, as a list of checked names.
///
/// Each name is not empty, is not `.` or `..`, and has no `/` and no NUL
/// byte. Thus no name can leave the directory that the name before it
/// selects, when the executor does not follow a symbolic link. The check
/// is lexical: it does not show that a name is not a symbolic link. The
/// executor finds that.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryPath {
    names: Vec<Vec<u8>>,
}

impl EntryPath {
    /// Checks an entry that is relative to a root.
    ///
    /// # Errors
    ///
    /// Returns a [`PathDefect`] when the entry is absolute, is too long, or
    /// has a name that the type does not permit.
    pub fn parse(path: &LosslessPath) -> Result<Self, PathDefect> {
        let bytes: &[u8] = path.as_bytes();
        check_length(bytes)?;
        if bytes.first() == Some(&b'/') {
            return Err(PathDefect::Absolute);
        }
        Ok(Self {
            names: split_names(bytes)?,
        })
    }

    /// The names of the entry, from the root to the object.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.names.iter().map(Vec::as_slice)
    }

    /// The number of names. The value is 1 or more.
    pub fn depth(&self) -> usize {
        self.names.len()
    }
}

/// The absolute path of an approved root, as a list of checked names.
///
/// The value comes from the record of the helper. A request does not
/// supply it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootPath {
    names: Vec<Vec<u8>>,
}

impl RootPath {
    /// Checks the path of a root.
    ///
    /// # Errors
    ///
    /// Returns a [`PathDefect`] when the path is relative, is the
    /// filesystem root, is too long, or has a name that the type does not
    /// permit.
    pub fn parse(path: &LosslessPath) -> Result<Self, PathDefect> {
        let bytes: &[u8] = path.as_bytes();
        check_length(bytes)?;
        let Some((b'/', below_root)) = bytes.split_first() else {
            return Err(PathDefect::Relative);
        };
        if below_root.is_empty() {
            return Err(PathDefect::FilesystemRoot);
        }
        Ok(Self {
            names: split_names(below_root)?,
        })
    }

    /// The names of the path, from the filesystem root to the directory.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.names.iter().map(Vec::as_slice)
    }

    /// Whether `other` is this root or a directory below it. The helper
    /// uses the result only to refuse a record that has one root below
    /// another. It is not a scope check of a target.
    pub fn contains(&self, other: &Self) -> bool {
        other.names.starts_with(&self.names)
    }
}
