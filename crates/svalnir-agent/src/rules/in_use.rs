//! The use check of a file rule: whether a running process of the user
//! uses a unit now.
//!
//! Owning specification: `docs/CLEANUP_RULES.md` section 6, "Use by a
//! running process". The inventory comes from
//! [`crate::platform::process::collect_path_uses`]; this module gives the
//! scopes of the inventory and the result for each unit.
//!
//! Two paths are compared by component, with no difference of ASCII case:
//! a difference of case thus gives a use, the safe result on a volume that
//! is case-sensitive. A unit has these forms: the path as the discovery
//! found it, the path with its symbolic links resolved, and the form of
//! each one below `/System/Volumes/Data`. The kernel gives the resolved
//! path of a vnode, and it can give either form of the data volume.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use svalnir_core::process::Uid;

use crate::platform::process::{
    InventoryGap, PathInventory, PathUseKind, ProcessSource, UseLimits, collect_path_uses,
};

/// The largest number of use records of one unit. The count of the other
/// records is in [`UnitUse::InUse::omitted`].
pub const MAX_USE_RECORDS: usize = 16;

/// The prefix of the data volume of macOS.
const DATA_VOLUME: &str = "/System/Volumes/Data";

/// One path and its other forms, for a comparison by component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitScope {
    /// The path as the caller gave it.
    path: PathBuf,
    /// Each form, as its normal components.
    forms: Vec<Vec<Vec<u8>>>,
}

/// The normal components of an absolute path, or `None` for a path that is
/// not absolute or that has `.` or `..`.
fn components(path: &Path) -> Option<Vec<Vec<u8>>> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut iterator = path.components();
    if iterator.next() != Some(Component::RootDir) {
        return None;
    }
    for component in iterator {
        match component {
            Component::Normal(name) => parts.push(name.as_bytes().to_vec()),
            _ => return None,
        }
    }
    Some(parts)
}

/// The form of `path` below `/System/Volumes/Data`, and the form below
/// `/` of a path below it.
fn data_volume_form(path: &Path) -> Option<PathBuf> {
    match path.strip_prefix(DATA_VOLUME) {
        Ok(rest) => Some(Path::new("/").join(rest)),
        Err(_) => path
            .strip_prefix("/")
            .ok()
            .map(|rest| Path::new(DATA_VOLUME).join(rest)),
    }
}

impl UnitScope {
    /// The scope of the unit at `path`. The resolution of the symbolic
    /// links reads the filesystem; a path that cannot be resolved has its
    /// given form and its data-volume form only.
    #[must_use]
    pub fn new(path: &Path) -> Self {
        let mut texts: Vec<PathBuf> = vec![path.to_path_buf()];
        if let Ok(resolved) = std::fs::canonicalize(path) {
            texts.push(resolved);
        }
        let others: Vec<PathBuf> = texts
            .iter()
            .filter_map(|text| data_volume_form(text))
            .collect();
        texts.extend(others);
        let mut forms: Vec<Vec<Vec<u8>>> = Vec::new();
        for text in &texts {
            if let Some(parts) = components(text)
                && !forms.contains(&parts)
            {
                forms.push(parts);
            }
        }
        Self {
            path: path.to_path_buf(),
            forms,
        }
    }

    /// The path as the caller gave it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The part of `path` below the unit, when `path` is the unit or is
    /// below it in one form. An empty path is the unit itself.
    #[must_use]
    pub fn relative(&self, path: &Path) -> Option<PathBuf> {
        let parts: Vec<Vec<u8>> = components(path)?;
        self.forms.iter().find_map(|form| {
            let head = parts.get(..form.len())?;
            let same: bool = head
                .iter()
                .zip(form)
                .all(|(found, expected)| found.eq_ignore_ascii_case(expected));
            same.then(|| {
                parts
                    .get(form.len()..)
                    .unwrap_or_default()
                    .iter()
                    .map(|part| OsStr::from_bytes(part))
                    .collect::<PathBuf>()
            })
        })
    }

    /// Whether `path` is the unit or is below it.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        self.relative(path).is_some()
    }
}

/// One use of a unit by one process. The record has no part of the command
/// line beyond the path relative to the unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UseRecord {
    /// The process ID at the time of the inventory.
    pub pid: i32,
    /// The file name of the executable.
    pub name: String,
    /// The kind of use.
    pub kind: PathUseKind,
    /// The path relative to the unit. Empty for the unit itself.
    pub relative: PathBuf,
}

/// The result of the use check for one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnitUse {
    /// A complete inventory has no use of the unit.
    NotInUse,
    /// A process of the user uses the unit.
    InUse {
        /// The first uses, at most [`MAX_USE_RECORDS`].
        uses: Vec<UseRecord>,
        /// The number of other uses.
        omitted: u64,
    },
    /// The inventory has no use of the unit, and it does not show that no
    /// process uses it.
    Unknown {
        /// The stable name of the cause: the gap of the inventory, or
        /// `process_not_readable` when only some processes are unknown.
        reason: &'static str,
        /// The processes of the user whose uses are not known, at most
        /// [`MAX_UNKNOWN_PROCESSES`](crate::platform::process::MAX_UNKNOWN_PROCESSES).
        processes: Vec<UnknownRecord>,
        /// The number of unknown processes that are not in `processes`.
        omitted: u64,
    },
}

/// One process of the user whose uses are not known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownRecord {
    /// The process ID at the time of the inventory.
    pub pid: i32,
    /// The file name of the executable, or empty when it is not known.
    pub name: String,
    /// The stable name of the failed query or of the bound.
    pub reason: &'static str,
}

impl UnitUse {
    /// The stable reason that refuses the unit, or `None` when the check
    /// permits it.
    #[must_use]
    pub const fn refusal(&self) -> Option<&'static str> {
        match self {
            Self::NotInUse => None,
            Self::InUse { .. } => Some("unit_in_use"),
            Self::Unknown { .. } => Some("unit_use_unknown"),
        }
    }
}

/// Whether `path` is in one of `scopes`.
#[must_use]
pub fn in_scopes(scopes: &[UnitScope], path: &Path) -> bool {
    scopes.iter().any(|scope| scope.contains(path))
}

/// The inventory of the processes of `principal` from `source`, with the
/// paths in `scopes` only, under the default bounds.
pub fn inventory_of<S: ProcessSource + ?Sized>(
    source: &S,
    principal: Uid,
    scopes: &[UnitScope],
) -> PathInventory {
    if scopes.is_empty() {
        // An inventory with no scope keeps nothing, and it shows nothing.
        return PathInventory::incomplete(InventoryGap::ProcessListEmpty, None);
    }
    collect_path_uses(
        source,
        principal,
        &|path: &Path| in_scopes(scopes, path),
        UseLimits::default(),
    )
}

/// The use of the unit of `scope` in `inventory`.
#[must_use]
pub fn uses_of(inventory: &PathInventory, scope: &UnitScope) -> UnitUse {
    if scope.forms.is_empty() {
        // A unit with no absolute form matches no path, so no inventory
        // shows that it is not used.
        return UnitUse::Unknown {
            reason: "unit_path_not_absolute",
            processes: Vec::new(),
            omitted: 0,
        };
    }
    let mut uses: Vec<UseRecord> = Vec::new();
    let mut omitted: u64 = 0;
    for process in &inventory.processes {
        for found in &process.uses {
            let Some(relative) = scope.relative(&found.path) else {
                continue;
            };
            if uses.len() < MAX_USE_RECORDS {
                uses.push(UseRecord {
                    pid: process.pid.get(),
                    name: process.name.clone(),
                    kind: found.kind,
                    relative,
                });
            } else {
                omitted = omitted.saturating_add(1);
            }
        }
    }
    if !uses.is_empty() {
        return UnitUse::InUse { uses, omitted };
    }
    let processes: Vec<UnknownRecord> = inventory
        .unknown
        .iter()
        .map(|process| UnknownRecord {
            pid: process.pid.get(),
            name: process.name.clone(),
            reason: process.reason.as_str(),
        })
        .collect();
    let omitted: u64 = inventory.unknown_omitted;
    match inventory.gap {
        Some(gap) => UnitUse::Unknown {
            reason: gap.as_str(),
            processes,
            omitted,
        },
        // An unknown process can use each unit.
        None if !processes.is_empty() || omitted > 0 => UnitUse::Unknown {
            reason: "process_not_readable",
            processes,
            omitted,
        },
        None => UnitUse::NotInUse,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use svalnir_core::process::Pid;

    use super::{UnitScope, UnitUse, uses_of};
    use crate::platform::process::{
        InventoryGap, PathInventory, PathUseKind, ProcessPathUse, ProcessUses, UnknownProcess,
    };

    fn inventory(kind: PathUseKind, path: &str) -> PathInventory {
        PathInventory {
            processes: vec![ProcessUses {
                pid: Pid::new(42).unwrap(),
                name: "node".to_owned(),
                uses: vec![ProcessPathUse {
                    kind,
                    path: PathBuf::from(path),
                }],
            }],
            ..PathInventory::default()
        }
    }

    #[test]
    fn containment_is_by_component_with_no_ascii_case_and_both_volume_forms() {
        let scope: UnitScope = UnitScope::new(Path::new("/Users/u/app/node_modules"));
        assert_eq!(
            scope.relative(Path::new("/Users/u/app/node_modules/a/b.js")),
            Some(PathBuf::from("a/b.js"))
        );
        assert_eq!(
            scope.relative(Path::new("/Users/u/app/node_modules")),
            Some(PathBuf::new())
        );
        // A sibling with the same prefix of text is not in the unit.
        assert!(!scope.contains(Path::new("/Users/u/app/node_modules2/a")));
        assert!(!scope.contains(Path::new("/Users/u/app")));
        // A difference of case is a use: the safe result.
        assert!(scope.contains(Path::new("/users/U/App/Node_Modules/x")));
        // The kernel can give the path below the data volume.
        assert_eq!(
            scope.relative(Path::new("/System/Volumes/Data/Users/u/app/node_modules/x")),
            Some(PathBuf::from("x"))
        );
        // A relative path from a source is in no unit.
        assert!(!scope.contains(Path::new("node_modules/x")));
    }

    #[test]
    fn a_unit_path_with_a_symbolic_link_matches_its_resolved_form() {
        let directory = tempfile::tempdir().unwrap();
        let real: PathBuf = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link: PathBuf = directory.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let scope: UnitScope = UnitScope::new(&link);
        let resolved: PathBuf = std::fs::canonicalize(&real).unwrap().join("f");
        assert_eq!(scope.relative(&resolved), Some(PathBuf::from("f")));
    }

    #[test]
    fn the_result_names_the_use_and_fails_closed_for_unknown_processes() {
        let scope: UnitScope = UnitScope::new(Path::new("/p/node_modules"));
        let found = uses_of(
            &inventory(PathUseKind::Argument, "/p/node_modules/.bin/vite"),
            &scope,
        );
        let UnitUse::InUse { uses, omitted } = &found else {
            panic!("{found:?}");
        };
        assert_eq!((uses.len(), *omitted), (1, 0));
        assert_eq!(uses[0].pid, 42);
        assert_eq!(uses[0].name, "node");
        assert_eq!(uses[0].kind, PathUseKind::Argument);
        assert_eq!(uses[0].relative, PathBuf::from(".bin/vite"));
        assert_eq!(found.refusal(), Some("unit_in_use"));
        // A use elsewhere and a complete inventory: not in use.
        let other = inventory(PathUseKind::OpenFile, "/q/file");
        assert_eq!(uses_of(&other, &scope), UnitUse::NotInUse);
        assert_eq!(UnitUse::NotInUse.refusal(), None);
        // An unknown process can use each unit; the result names it.
        let mut unknown = other.clone();
        unknown.unknown.push(UnknownProcess {
            pid: Pid::new(7).unwrap(),
            name: "dmd".to_owned(),
            reason: InventoryGap::ProcessQueryDenied,
        });
        let result = uses_of(&unknown, &scope);
        let UnitUse::Unknown {
            reason, processes, ..
        } = &result
        else {
            panic!("{result:?}");
        };
        assert_eq!(*reason, "process_not_readable");
        assert_eq!(processes[0].name, "dmd");
        assert_eq!(processes[0].reason, "process_query_denied");
        assert_eq!(result.refusal(), Some("unit_use_unknown"));
        // A gap of the inventory gives its name.
        let mut gap = other;
        gap.gap = Some(InventoryGap::ProcessListUnavailable);
        assert!(matches!(
            uses_of(&gap, &scope),
            UnitUse::Unknown {
                reason: "process_list_unavailable",
                ..
            }
        ));
    }
}
