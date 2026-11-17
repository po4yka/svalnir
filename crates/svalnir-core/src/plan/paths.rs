//! Path lists for the exclusion checks of a manual plan.
//!
//! The comparison is the one of the policy module
//! (`crate::policy::control::PathSet`), which is private to that module.
//! This file has the same rules, and a test compares the two through
//! [`plan_cleanup`](crate::policy::plan_cleanup).
//!
//! The default APFS volume ignores case and Unicode normalization. This
//! module has no normalization table, so the comparison fails closed:
//!
//! - A component is folded with the full Unicode lowercase mapping. A
//!   component that is not UTF-8 is folded by ASCII case only.
//! - Two components that are not byte-equal after folding, where either one
//!   has a non-ASCII byte, count as a match. They can be the same name in a
//!   different normalization form, and a missed match would expose a
//!   protected path.
//!
//! The rule over-protects. It never under-protects a path that differs only
//! in case or normalization.

use crate::config::{ConfigPath, PathBase};
use crate::file::LosslessPath;

/// A path as folded components.
pub(super) type Components = Vec<Vec<u8>>;

/// A list of paths as components, ready for a comparison.
#[derive(Debug, Default)]
pub(super) struct PathSet {
    entries: Vec<Components>,
    /// True when a path starts from the home directory and no usable home
    /// directory was given. A home directory is usable when it is absolute,
    /// canonical, and has no empty component.
    pub(super) unresolved: bool,
}

fn fold(bytes: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_lowercase().into_bytes(),
        Err(_) => bytes.to_ascii_lowercase(),
    }
}

/// The folded components of a path. Empty components are ignored.
pub(super) fn components(bytes: &[u8]) -> Components {
    bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(fold)
        .collect()
}

/// True when two folded components name the same entry, or can name it in a
/// different normalization form.
fn component_matches(left: &[u8], right: &[u8]) -> bool {
    left == right || !left.is_ascii() || !right.is_ascii()
}

/// True when `path` starts with all components of `prefix`: `path` is
/// `prefix` or is inside `prefix`.
pub(super) fn has_prefix(path: &[Vec<u8>], prefix: &[Vec<u8>]) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix)
            .all(|(left, right)| component_matches(left, right))
}

/// True when the path is absolute and has no `.` or `..` component. A path
/// list cannot be applied to a different path: a component-wise comparison
/// of such a path can miss a protection.
pub(super) fn is_canonical(path: &LosslessPath) -> bool {
    let bytes: &[u8] = path.as_bytes();
    bytes.first() == Some(&b'/')
        && bytes
            .split(|byte| *byte == b'/')
            .all(|component| component != b"." && component != b"..")
}

/// True when the path is relative, is not empty, and has no empty, `.`, or
/// `..` component.
pub(super) fn is_canonical_relative(path: &LosslessPath) -> bool {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// True when `path` is exactly `root` and then `relative`: the exact
/// components of the root, followed by the exact components of the relative
/// entry. No case is folded: the texts name the same entry only when the
/// bytes agree.
pub(super) fn joins_to(path: &LosslessPath, root: &LosslessPath, relative: &LosslessPath) -> bool {
    let split = |bytes: &[u8]| -> Vec<Vec<u8>> {
        bytes
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    let mut joined: Vec<Vec<u8>> = split(root.as_bytes());
    let relative: Vec<Vec<u8>> = split(relative.as_bytes());
    if relative.is_empty() {
        return false;
    }
    joined.extend(relative);
    split(path.as_bytes()) == joined
}

/// True when a home directory can anchor `~/` paths: it is canonical, it is
/// not the root, and it has no repeated or trailing `/`.
fn is_usable_home(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

impl PathSet {
    /// Resolves the paths of one or more configuration lists.
    pub(super) fn resolve<'a>(
        paths: impl Iterator<Item = &'a ConfigPath>,
        home: Option<&LosslessPath>,
    ) -> Self {
        let home_components: Option<Components> = home
            .map(LosslessPath::as_bytes)
            .filter(|bytes| is_usable_home(bytes))
            .map(components);
        let mut set: Self = Self::default();
        for path in paths {
            let mut entry: Components = match (path.base(), &home_components) {
                (PathBase::Root, _) => Vec::new(),
                (PathBase::Home, Some(home)) => home.clone(),
                (PathBase::Home, None) => {
                    set.unresolved = true;
                    continue;
                }
            };
            entry.extend(
                path.components()
                    .map(|component| fold(component.as_bytes())),
            );
            set.entries.push(entry);
        }
        set
    }

    /// Makes the list from paths that are relative to one root, for example
    /// the protected descendants of a rule.
    pub(super) fn of_relative(paths: &[LosslessPath]) -> Self {
        Self {
            entries: paths
                .iter()
                .map(|path| components(path.as_bytes()))
                .collect(),
            unresolved: false,
        }
    }

    /// True when `path` is an entry or is inside an entry.
    pub(super) fn covers(&self, path: &LosslessPath) -> bool {
        let path: Components = components(path.as_bytes());
        self.entries.iter().any(|entry| has_prefix(&path, entry))
    }

    /// True when `path` is an entry, is inside an entry, or contains an
    /// entry.
    pub(super) fn overlaps(&self, path: &LosslessPath) -> bool {
        let path: Components = components(path.as_bytes());
        self.entries
            .iter()
            .any(|entry| has_prefix(&path, entry) || has_prefix(entry, &path))
    }
}
