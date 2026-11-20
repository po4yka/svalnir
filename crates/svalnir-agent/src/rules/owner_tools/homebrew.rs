//! The inspection of `homebrew.cleanup`: the old versions of the formulae
//! of a Homebrew installation, from the layout of its prefix.
//!
//! Homebrew installs each version of a formula as a keg
//! `PREFIX/Cellar/FORMULA/VERSION`, and links the current version as
//! `PREFIX/opt/FORMULA`. `brew cleanup` removes the other kegs of a
//! formula that is not pinned (`PREFIX/var/homebrew/pinned/FORMULA`), and
//! old downloads. The inspection reads these names and links, measures
//! each old keg, and gives the owner workflow. It runs no `brew` command:
//! the executable and the Ruby code that it loads are in the prefix, which
//! the user can change.
//!
//! The current keg of each formula, a keg whose current version is not
//! known, the Caskroom, and the downloads are never a unit. The downloads
//! are the rule `homebrew.download-cache`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::rule::{LayoutSupport, RuleRef};

use super::{OwnerToolHost, OwnerToolRules};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::rules::caches::{CacheMeasurement, InspectionLimits, ReclaimBasis, measure_unit};
use crate::rules::projects::BuildProcesses;
use crate::rules::unit::{ObjectKind, WalkStop, lstat, walk_local};
use crate::scan::{CancellationToken, ScanClock};

/// The documented prefixes of Homebrew: Apple silicon, then Intel.
pub const HOMEBREW_PREFIXES: [&str; 2] = ["/opt/homebrew", "/usr/local"];

/// The largest number of formulae of one prefix that the inspection reads.
const MAX_FORMULAE: usize = 10_000;

/// The largest number of kegs of one formula that the inspection reads.
const MAX_KEGS: usize = 64;

/// The result of one prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum PrefixOutcome {
    /// The Cellar was read. `true` when the formula bound stopped the
    /// reading.
    Examined(bool),
    /// The prefix has no Cellar.
    Absent,
    /// The Cellar failed a check. The reason is a stable name.
    Refused(&'static str),
}

/// The result of one keg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KegOutcome {
    /// A version that is not the current version of a formula that is not
    /// pinned: `brew cleanup` removes it. The figure is the allocated size,
    /// which is not exclusive storage.
    OldVersion(CacheMeasurement),
    /// The version that `opt` links. It is not a unit.
    Current,
    /// The formula is pinned, and `brew cleanup` keeps each of its kegs.
    Pinned,
    /// `opt` has no link to a keg of the formula, so the current version is
    /// not known. No keg of the formula is a unit.
    CurrentVersionUnknown,
    /// The process inventory is not complete, so whether a process runs
    /// an executable of the keg is not known.
    ActivityUnknown {
        /// The stable name of the cause.
        reason: &'static str,
    },
    /// A process of the user runs an executable of the keg.
    InUse {
        /// The executable.
        executable: PathBuf,
    },
    /// The keg failed a check. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
    },
}

/// One keg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HomebrewKeg {
    /// The name of the formula.
    pub formula: String,
    /// The version.
    pub version: String,
    /// The directory of the keg.
    pub path: PathBuf,
    /// The result.
    pub outcome: KegOutcome,
}

/// The report of one prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HomebrewPrefixReport {
    /// The prefix.
    pub prefix: PathBuf,
    /// The result.
    pub outcome: PrefixOutcome,
    /// The kegs of each formula with more than one keg.
    pub kegs: Vec<HomebrewKeg>,
}

/// The inspection of `homebrew.cleanup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HomebrewInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// Each layout of the declaration with its lifecycle state.
    pub layouts: Vec<LayoutSupport>,
    /// The prefixes, in the sequence of the caller.
    pub prefixes: Vec<HomebrewPrefixReport>,
    /// The owner workflow. Svalnir does not run it.
    pub owner_workflow: &'static str,
}

/// The names of the entries of `path` that are directories of `owner`,
/// with no symbolic link, sorted, at most `limit`. `None` when the
/// directory cannot be read. The second value is `true` when the bound
/// stopped the reading.
fn directories(
    path: &Path,
    owner: svalnir_core::process::Uid,
    limit: usize,
) -> Option<(Vec<String>, bool)> {
    let mut names: Vec<String> = fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .filter(|name| {
            lstat(&path.join(name))
                .is_ok_and(|found| found.kind == ObjectKind::Directory && found.owner == owner)
        })
        .collect();
    names.sort();
    let truncated: bool = names.len() > limit;
    names.truncate(limit);
    Some((names, truncated))
}

/// The version that the link `PREFIX/opt/FORMULA` names, when it is a
/// symbolic link to `../Cellar/FORMULA/VERSION` or to
/// `PREFIX/Cellar/FORMULA/VERSION`. The link is read, not followed.
fn current_version(prefix: &Path, formula: &str) -> Option<String> {
    let target: PathBuf = fs::read_link(prefix.join("opt").join(formula)).ok()?;
    let rest: &Path = target
        .strip_prefix("../Cellar")
        .or_else(|_| target.strip_prefix(prefix.join("Cellar")))
        .ok()?;
    let mut components = rest.components();
    let (Some(Component::Normal(name)), Some(Component::Normal(version)), None) =
        (components.next(), components.next(), components.next())
    else {
        return None;
    };
    (name == formula).then(|| version.to_string_lossy().into_owned())
}

impl OwnerToolRules {
    /// Inspects the Cellar of each prefix of `prefixes`.
    pub fn inspect_homebrew(
        &self,
        host: OwnerToolHost<'_>,
        prefixes: &[PathBuf],
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> HomebrewInspection {
        self.inspect_homebrew_with_mounts(host, prefixes, limits, cancel, clock, MountTable::read)
    }

    /// [`OwnerToolRules::inspect_homebrew`] with another source of the
    /// mount table.
    pub(crate) fn inspect_homebrew_with_mounts(
        &self,
        host: OwnerToolHost<'_>,
        prefixes: &[PathBuf],
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
        mounts: MountTableSource,
    ) -> HomebrewInspection {
        let rule = self.homebrew();
        let table: Option<MountTable> = mounts().ok();
        let reports: Vec<HomebrewPrefixReport> = prefixes
            .iter()
            .map(|prefix| match &table {
                Some(table) => prefix_report(host, prefix, table, limits, cancel, clock),
                None => HomebrewPrefixReport {
                    prefix: prefix.clone(),
                    outcome: PrefixOutcome::Refused("root_locality_unknown"),
                    kegs: Vec::new(),
                },
            })
            .collect();
        HomebrewInspection {
            rule: rule.reference.clone(),
            layouts: rule.layouts.clone(),
            prefixes: reports,
            owner_workflow: "Run `brew cleanup --dry-run` to see what `brew cleanup` removes, then `brew cleanup FORMULA` for one formula or `brew cleanup` for each one. It keeps the current version and the formulae that `brew pin` pinned. Svalnir does not run them.",
        }
    }
}

/// The report of the prefix `prefix`.
fn prefix_report(
    host: OwnerToolHost<'_>,
    prefix: &Path,
    mounts: &MountTable,
    limits: InspectionLimits,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> HomebrewPrefixReport {
    let mut report: HomebrewPrefixReport = HomebrewPrefixReport {
        prefix: prefix.to_path_buf(),
        outcome: PrefixOutcome::Absent,
        kegs: Vec::new(),
    };
    let cellar: PathBuf = prefix.join("Cellar");
    if host.locations.of_text(&cellar) != ProtectionFact::NotProtected {
        report.outcome = PrefixOutcome::Refused("root_protected");
        return report;
    }
    let root = match walk_local(&cellar, mounts) {
        Ok(root) => root,
        Err(WalkStop::Absent) => return report,
        Err(WalkStop::NotLocal | WalkStop::LocalityUnknown) => {
            report.outcome = PrefixOutcome::Refused("root_not_local");
            return report;
        }
        Err(_) => {
            report.outcome = PrefixOutcome::Refused("root_not_readable");
            return report;
        }
    };
    if root.kind != ObjectKind::Directory {
        report.outcome = PrefixOutcome::Refused("root_not_directory");
        return report;
    }
    // Homebrew installs as the user; a Cellar of another owner is not the
    // installation of the user.
    if root.owner != host.principal {
        report.outcome = PrefixOutcome::Refused("root_owner");
        return report;
    }
    let Some((formulae, truncated)) = directories(&cellar, host.principal, MAX_FORMULAE) else {
        report.outcome = PrefixOutcome::Refused("root_not_readable");
        return report;
    };
    let processes: BuildProcesses = host.processes.build_processes(host.principal);
    for formula in formulae {
        let Some((versions, _)) = directories(&cellar.join(&formula), host.principal, MAX_KEGS)
        else {
            continue;
        };
        // A formula with one keg has nothing for `brew cleanup`.
        if versions.len() < 2 {
            continue;
        }
        let current: Option<String> =
            current_version(prefix, &formula).filter(|version| versions.contains(version));
        let pinned: bool = lstat(&prefix.join("var/homebrew/pinned").join(&formula)).is_ok();
        for version in versions {
            let path: PathBuf = cellar.join(&formula).join(&version);
            let outcome: KegOutcome = if current.as_deref() == Some(version.as_str()) {
                KegOutcome::Current
            } else if current.is_none() {
                KegOutcome::CurrentVersionUnknown
            } else if pinned {
                KegOutcome::Pinned
            } else {
                old_keg(host, &processes, &path, limits, cancel, clock)
            };
            report.kegs.push(HomebrewKeg {
                formula: formula.clone(),
                version,
                path,
                outcome,
            });
        }
    }
    report.outcome = PrefixOutcome::Examined(truncated);
    report
}

/// The result of the old keg at `path`.
fn old_keg(
    host: OwnerToolHost<'_>,
    processes: &BuildProcesses,
    path: &Path,
    limits: InspectionLimits,
    cancel: &CancellationToken,
    clock: &dyn ScanClock,
) -> KegOutcome {
    if host
        .user_exclusions
        .iter()
        .any(|excluded| path.starts_with(excluded) || excluded.starts_with(path))
    {
        return KegOutcome::Refused {
            reason: "unit_excluded",
        };
    }
    if let Some(executable) = processes.blocking(path) {
        return KegOutcome::InUse {
            executable: executable.to_path_buf(),
        };
    }
    if let Some(reason) = processes.incomplete {
        return KegOutcome::ActivityUnknown { reason };
    }
    match measure_unit(path, limits, cancel, clock, ReclaimBasis::AllocatedBytes) {
        Some(measurement) => KegOutcome::OldVersion(measurement),
        None => KegOutcome::Refused {
            reason: "unit_not_readable",
        },
    }
}
