//! The catalog of hard protections of file locations.
//!
//! Owning specification: `docs/CLEANUP_RULES.md` section 5. OS-managed
//! protected storage, swap storage, and the control-plane and recovery
//! state of Svalnir are hard exclusions for each cleanup action. No mode,
//! preset, policy, grant, or manual request removes them. The catalog also
//! protects the home directory of the user and each directory that
//! contains it: a cleanup removes entries below the home directory and not
//! the directory.
//!
//! The catalog is pure. The caller gives the path of one entry and the
//! locations of the user and of the control plane, and gets a
//! [`ProtectionFact`]. The caller resolves symbolic links first: the
//! catalog compares the text of the paths.
//!
//! Each rule can only add a protection. A path never makes an entry a
//! target. An entry that the catalog cannot classify is
//! [`ProtectionFact::Unknown`], which each plan leaves out.
//!
//! The comparison is the fail-closed comparison of the exclusion lists of
//! this module (`PathSet`): it ignores case, and two components that are
//! not equal count as a match when one of them has a non-ASCII byte. It
//! over-protects, and it never under-protects a path that differs only in
//! case or in Unicode normalization.

use super::control::{ProtectionFact, components, has_prefix};
use super::protection::{LOCAL_DIRECTORY, SYSTEM_DIRECTORIES};
use crate::file::LosslessPath;

/// The directories of the virtual-memory storage of the operating system:
/// the swap files and the sleep image. `/var` is a symbolic link to
/// `/private/var`, and the two spellings are in the list for a caller that
/// could not resolve the link.
pub const VIRTUAL_MEMORY_DIRECTORIES: [&str; 2] = ["/private/var/vm/", "/var/vm/"];

/// The locations that the catalog needs about the user and the control
/// plane. Each path is absolute, has no `.` and no `..` component, and has
/// no symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileProtectionContext<'a> {
    /// The home directory of the user that the plan is for. `None` when
    /// the caller could not establish it: then no entry is known to be
    /// outside the directories that contain the home directory.
    pub home_directory: Option<&'a LosslessPath>,
    /// The state directory of Svalnir: the policy, the grants, the
    /// operation journal, and the recovery state. `None` when the caller
    /// could not establish it: then no entry is known to be outside the
    /// control-plane state.
    pub state_directory: Option<&'a LosslessPath>,
}

/// True when the path is absolute and has no empty, `.`, or `..`
/// component after the first `/`. A different path can name a location
/// outside its text prefix, so the catalog cannot classify it. One `/` at
/// the end is accepted.
fn is_classifiable(path: &LosslessPath) -> bool {
    let bytes: &[u8] = path.as_bytes();
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return false;
    };
    let rest: &[u8] = rest.strip_suffix(b"/").unwrap_or(rest);
    rest.is_empty()
        || rest
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// True when `path` is `location`, is inside it, or contains it.
fn overlaps(path: &[Vec<u8>], location: &[Vec<u8>]) -> bool {
    has_prefix(path, location) || has_prefix(location, path)
}

/// The hard protection of the file entry at `path`.
///
/// The entry is protected when one of these is true:
///
/// - It is one of the [`SYSTEM_DIRECTORIES`], is inside one, or contains
///   one. An entry at or below [`LOCAL_DIRECTORY`] is not protected by
///   this rule: the operating system does not own that directory.
/// - It is one of the [`VIRTUAL_MEMORY_DIRECTORIES`], is inside one, or
///   contains one.
/// - It is the state directory of Svalnir, is inside it, or contains it.
/// - It is the home directory of the user or a directory that contains
///   the home directory.
///
/// A parent that contains a protected location is protected, because the
/// removal of the parent removes the location. `/` contains each location.
///
/// With no protection, the entry is [`ProtectionFact::Unknown`] when its
/// path is not absolute or has an empty, `.`, or `..` component, when the
/// home directory or the state directory is not known, or when one of the
/// two has a path that the catalog cannot classify. In each other case it
/// is [`ProtectionFact::NotProtected`].
pub fn file_hard_protection(
    path: &LosslessPath,
    context: &FileProtectionContext<'_>,
) -> ProtectionFact {
    if !is_classifiable(path) {
        return ProtectionFact::Unknown;
    }
    let entry: Vec<Vec<u8>> = components(path.as_bytes());
    // The exception removes a protection, so its comparison is exact: the
    // fail-closed comparison would place `/usr/NAME` in the local directory
    // for each name that is not ASCII.
    let local: Vec<Vec<u8>> = components(LOCAL_DIRECTORY.as_bytes());
    let in_local: bool =
        entry.len() >= local.len() && entry.iter().zip(&local).all(|(a, b)| a == b);
    let system_protected: bool = SYSTEM_DIRECTORIES.iter().any(|directory| {
        let directory: Vec<Vec<u8>> = components(directory.as_bytes());
        // An entry that contains the directory is protected also when the
        // comparison places the entry below the local directory.
        has_prefix(&directory, &entry) || (has_prefix(&entry, &directory) && !in_local)
    });
    let memory_protected: bool = VIRTUAL_MEMORY_DIRECTORIES
        .iter()
        .any(|directory| overlaps(&entry, &components(directory.as_bytes())));
    if system_protected || memory_protected {
        return ProtectionFact::Protected;
    }

    let location = |path: Option<&LosslessPath>| {
        path.filter(|path| is_classifiable(path))
            .map(|path| components(path.as_bytes()))
    };
    let state: Option<Vec<Vec<u8>>> = location(context.state_directory);
    let home: Option<Vec<Vec<u8>>> = location(context.home_directory);
    let state_protected: bool = state.as_ref().is_some_and(|state| overlaps(&entry, state));
    // The entry is the home directory or contains it.
    let home_protected: bool = home.as_ref().is_some_and(|home| has_prefix(home, &entry));
    if state_protected || home_protected {
        ProtectionFact::Protected
    } else if state.is_none() || home.is_none() {
        ProtectionFact::Unknown
    } else {
        ProtectionFact::NotProtected
    }
}

#[cfg(test)]
mod tests {
    use super::{FileProtectionContext, file_hard_protection};
    use crate::file::LosslessPath;
    use crate::policy::ProtectionFact;

    fn path(text: &str) -> LosslessPath {
        LosslessPath::from_bytes(text).unwrap()
    }

    /// The protection of `entry` for the user `a` and the usual state
    /// directory.
    fn protection(entry: &str) -> ProtectionFact {
        let home = path("/Users/a");
        let state = path("/Users/a/Library/Application Support/Svalnir");
        file_hard_protection(
            &path(entry),
            &FileProtectionContext {
                home_directory: Some(&home),
                state_directory: Some(&state),
            },
        )
    }

    #[test]
    fn storage_of_the_operating_system_and_swap_storage_are_protected() {
        for entry in [
            "/System",
            "/System/Library/Caches/com.apple.x",
            "/System/Volumes/VM/swapfile0",
            "/usr",
            "/usr/lib/libz.dylib",
            "/bin/sh",
            "/sbin",
            "/Library/Apple/usr",
            "/private/var/vm",
            "/private/var/vm/swapfile0",
            "/private/var/vm/sleepimage",
            "/var/vm/swapfile1",
            // The default volume ignores case.
            "/SYSTEM/library",
            "/Private/Var/VM/swapfile0",
        ] {
            assert_eq!(protection(entry), ProtectionFact::Protected, "{entry}");
        }
        // A parent of a protected location: its removal removes the
        // location.
        for entry in ["/", "/private", "/private/var", "/var", "/Library"] {
            assert_eq!(protection(entry), ProtectionFact::Protected, "{entry}");
        }
        // A name that is not ASCII is not the local directory.
        for entry in ["/usr/loc\u{e1}l/x", "/usr/\u{df}/y"] {
            assert_eq!(protection(entry), ProtectionFact::Protected, "{entry}");
        }
        // The operating system does not own the local directory.
        for entry in ["/usr/local", "/usr/local/Cellar/x/cache"] {
            assert_eq!(protection(entry), ProtectionFact::NotProtected, "{entry}");
        }
    }

    #[test]
    fn the_state_of_the_control_plane_is_protected() {
        for entry in [
            "/Users/a/Library/Application Support/Svalnir",
            "/Users/a/Library/Application Support/Svalnir/operations.sqlite",
            "/Users/a/Library/Application Support/Svalnir/plans/plan-1.json",
            // A directory that contains the state directory.
            "/Users/a/Library/Application Support",
            "/Users/a/Library",
            "/users/A/library/application support/svalnir/plans",
        ] {
            assert_eq!(protection(entry), ProtectionFact::Protected, "{entry}");
        }
        assert_eq!(
            protection("/Users/a/Library/Application Support/Other"),
            ProtectionFact::NotProtected
        );
    }

    #[test]
    fn the_home_directory_and_each_directory_that_contains_it_are_protected() {
        for entry in ["/Users/a", "/Users/a/", "/Users", "/USERS/A"] {
            assert_eq!(protection(entry), ProtectionFact::Protected, "{entry}");
        }
        for entry in [
            "/Users/a/Library/Caches/example",
            "/Users/a/Documents/thesis.txt",
            "/Users/ab",
            "/Volumes/Work/build",
            "/private/var/folders/xy/T/cache",
        ] {
            assert_eq!(protection(entry), ProtectionFact::NotProtected, "{entry}");
        }
    }

    #[test]
    fn an_entry_that_the_catalog_cannot_classify_is_unknown() {
        for entry in [
            "Users/a/Library/Caches/example",
            "/Users/a/../b/cache",
            "/Users/a/./cache",
            "/Users//a/cache",
        ] {
            assert_eq!(protection(entry), ProtectionFact::Unknown, "{entry}");
        }
        let home = path("/Users/a");
        let state = path("/Users/a/Library/Application Support/Svalnir");
        let relative = path("Users/a");
        let entry = path("/Volumes/Work/build");
        let with = |home_directory, state_directory| {
            file_hard_protection(
                &entry,
                &FileProtectionContext {
                    home_directory,
                    state_directory,
                },
            )
        };
        assert_eq!(
            with(Some(&home), Some(&state)),
            ProtectionFact::NotProtected
        );
        // A location that is not known is not a location that the entry is
        // outside of.
        assert_eq!(with(None, Some(&state)), ProtectionFact::Unknown);
        assert_eq!(with(Some(&home), None), ProtectionFact::Unknown);
        assert_eq!(with(Some(&relative), Some(&state)), ProtectionFact::Unknown);
        assert_eq!(with(Some(&home), Some(&relative)), ProtectionFact::Unknown);

        // An unknown location does not remove a protection that is known.
        let system = path("/System/Library");
        let unknown = FileProtectionContext {
            home_directory: None,
            state_directory: None,
        };
        assert_eq!(
            file_hard_protection(&system, &unknown),
            ProtectionFact::Protected
        );
        let inside_state = path("/Users/a/Library/Application Support/Svalnir/x");
        assert_eq!(
            file_hard_protection(
                &inside_state,
                &FileProtectionContext {
                    home_directory: None,
                    state_directory: Some(&state),
                }
            ),
            ProtectionFact::Protected
        );
    }

    #[test]
    fn a_name_in_a_different_normalization_form_stays_protected() {
        // The state directory of a user whose name is not ASCII, and the
        // same name in the decomposed form.
        let home = path("/Users/jos\u{e9}");
        let state = path("/Users/jos\u{e9}/Library/Application Support/Svalnir");
        let decomposed = path("/Users/jose\u{301}/Library/Application Support/Svalnir/plans");
        assert_eq!(
            file_hard_protection(
                &decomposed,
                &FileProtectionContext {
                    home_directory: Some(&home),
                    state_directory: Some(&state),
                }
            ),
            ProtectionFact::Protected
        );
    }
}
