//! The inspection of `project.dependency-directory`.
//!
//! The inspection is read-only. It reads directory entries and metadata
//! below the search roots, runs the read-only Git queries of
//! [`crate::rules::git`], reads the process table, and measures each unit
//! with the scanner. It changes nothing and gives no candidate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::config::{SKIPPED_DIRECTORY_NAMES, UserLayout};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{LayoutSupport, RuleRef};
use svalnir_core::time::MonotonicNanos;

use super::ProjectRule;
use super::activity::{BuildProcesses, ProcessEvidence};
use super::layouts::{
    DirectoryName, MarkerKind, PROJECT_LAYOUTS, PackageCheckouts, ProjectLayout,
    USER_LAYOUT_IMPACT, USER_LAYOUT_WORKFLOW,
};
use super::recency::{
    AgentListing, ProjectRecency, RecencyHost, RecencyState, SourceReading, assess_with_head,
};
use crate::platform::process::PathInventory;
use crate::platform::volume::{MountTable, MountTableSource};
use crate::protection::ProtectedLocations;
use crate::rules::caches::{
    CacheMeasurement, InspectionLimits, ReclaimBasis, measure_unit_observed,
};
use crate::rules::git::{
    GitFailure, GitOutput, GitTool, GitToolProblem, Repository, RepositoryLookup, find_repository,
};
use crate::rules::in_use::{UnitScope, UnitUse, uses_of};
use crate::rules::nested_git::{
    DetectionLimits, MarkerObserver, RefusalReason, RepositoryRefusal, SwiftPmCheckouts, Verdict,
    check_unit,
};
use crate::rules::unit::{
    ObjectKind, ObjectSnapshot, WalkStop, is_plain_relative, lstat, walk_local,
};
use crate::scan::{CancellationToken, ScanClock};

/// The largest number of search roots of one inspection.
pub const MAX_SEARCH_ROOTS: usize = 16;

/// The largest output of a Git query of this rule, in bytes.
const MAX_GIT_OUTPUT: usize = 4 * 1024;

/// The directories that the user names for the rule, each relative to the
/// home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRoots(Vec<PathBuf>);

impl SearchRoots {
    /// The search roots `relative`.
    ///
    /// # Errors
    ///
    /// Returns the first path that is not a plain relative path (an empty
    /// path, an absolute path, or a path with `.` or `..`), a repeated
    /// path, or `None` when the list is longer than [`MAX_SEARCH_ROOTS`].
    pub fn new(relative: Vec<PathBuf>) -> Result<Self, Option<PathBuf>> {
        if relative.len() > MAX_SEARCH_ROOTS {
            return Err(None);
        }
        for (index, path) in relative.iter().enumerate() {
            if !is_plain_relative(path) || relative[..index].contains(path) {
                return Err(Some(path.clone()));
            }
        }
        Ok(Self(relative))
    }

    /// The search roots, relative to the home directory.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.0
    }
}

/// The host facts of an inspection.
#[derive(Clone, Copy)]
#[expect(
    missing_debug_implementations,
    reason = "the process evidence is a trait object with no `Debug` bound"
)]
pub struct ProjectHost<'a> {
    /// The user. Each search root, each project directory, and each unit
    /// must have this owner.
    pub principal: Uid,
    /// The home directory and the state directory, resolved.
    pub locations: &'a ProtectedLocations,
    /// The paths of `[protections]` and of the disk guard exclusions.
    pub user_exclusions: &'a [PathBuf],
    /// The Git executable, or why none was accepted.
    pub git: Result<&'a GitTool, GitToolProblem>,
    /// The process evidence.
    pub processes: &'a dyn ProcessEvidence,
    /// The sources and the quiet period of the project activity.
    pub recency: RecencyHost<'a>,
    /// The layouts of `[[cleanup.projects.layouts]]`, which the
    /// configuration validated. Each one has the layout name
    /// `user-configured`.
    pub layouts: &'a [UserLayout],
}

/// The bounds of an inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectLimits {
    /// The deepest directory level below a search root that the walk
    /// reads.
    pub max_depth: u32,
    /// The largest number of directories that the walk reads, for all the
    /// search roots.
    pub max_directories: usize,
    /// The largest number of units in the report.
    pub max_units: usize,
    /// The longest time of the walk and of the checks.
    pub max_duration: Duration,
    /// The bounds of the measurement of one unit.
    pub measure: InspectionLimits,
}

impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_directories: 50_000,
            max_units: 1_000,
            max_duration: Duration::from_secs(60),
            measure: InspectionLimits::default(),
        }
    }
}

/// Why the walk of a search root ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchCompletion {
    /// The walk read each directory to the depth bound, and no directory
    /// is below that bound.
    Complete,
    /// A directory is below the depth bound and was not read.
    DepthLimitReached,
    /// The walk read the largest number of directories.
    DirectoryLimitReached,
    /// The report has the largest number of units.
    UnitLimitReached,
    /// The walk passed its time bound.
    DeadlineReached,
    /// The caller cancelled the inspection.
    Cancelled,
}

/// The result of one search root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum SearchRootOutcome {
    /// The walk ran.
    Examined(SearchCompletion),
    /// The directory does not exist.
    Absent,
    /// The root failed a check. The reason is a stable name.
    Refused(&'static str),
}

/// The report of one search root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchRootReport {
    /// The path relative to the home directory, as the user named it.
    pub relative: PathBuf,
    /// The path, when the home directory is known.
    pub path: Option<PathBuf>,
    /// The result.
    pub outcome: SearchRootOutcome,
    /// The directories below the root that could not be read.
    pub unreadable_directories: u64,
}

/// The evidence of Git for one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VersionControl {
    /// Git ignores the directory, and the index has no path in it.
    Ignored,
    /// Git does not ignore the directory.
    NotIgnored,
    /// The index has a path in the directory, or the directory itself.
    Tracked,
    /// No directory from the project up to the search root has `.git`.
    NoRepository,
    /// The evidence is not known.
    Unknown {
        /// The stable name of the cause.
        reason: &'static str,
    },
}

/// The process evidence for one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectActivity {
    /// A complete and current inventory has no build process with a
    /// working directory or an executable in the project.
    Inactive,
    /// A build process of the user has its working directory or its
    /// executable in the project.
    Active {
        /// The executable of the process.
        executable: PathBuf,
    },
    /// The evidence is not known.
    Unknown {
        /// The stable name of the cause.
        reason: &'static str,
    },
}

/// The result of one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectUnitOutcome {
    /// Each check of the inspection is satisfied, and the unit was
    /// measured. The rule is `proposed`, so the unit is not a candidate of
    /// a plan.
    Measured(CacheMeasurement),
    /// The unit failed a check. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
    },
    /// The unit holds a Git repository, or the walk that looks for one did
    /// not examine each entry (`docs/CLEANUP_RULES.md` section 6,
    /// "Repositories in a unit"). It is not measured.
    RepositoryRefused(RepositoryRefusal),
}

/// The report of one generated directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectUnitReport {
    /// The path of the generated directory.
    pub path: PathBuf,
    /// The project directory.
    pub project: PathBuf,
    /// The layout name: a layout of the catalog, or `user-configured`.
    pub layout: &'static str,
    /// The entry at a protected path of the layout, relative to the unit,
    /// when the check found one (`protected_child`).
    pub protected_child: Option<PathBuf>,
    /// The layout of the earlier unit of the project that this unit is,
    /// holds, or is in (`overlaps_unit`). That unit has the checks.
    pub overlapping_layout: Option<&'static str>,
    /// The evidence of Git, when the checks came to it.
    pub version_control: Option<VersionControl>,
    /// The process evidence, when the checks came to it.
    pub activity: Option<ProjectActivity>,
    /// The use check of `docs/CLEANUP_RULES.md` section 6, when the checks
    /// came to it: whether a process of the user uses the unit.
    pub uses: Option<UnitUse>,
    /// The project activity of `docs/CLEANUP_RULES.md` section 6, when
    /// the checks came to it. Only a busy project refuses the unit.
    pub recency: Option<ProjectRecency>,
    /// The result.
    pub outcome: ProjectUnitOutcome,
    /// The owner workflow, as a text for the user. Svalnir does not run
    /// it.
    pub owner_workflow: &'static str,
    /// The consequence of a removal.
    pub rebuild_impact: &'static str,
}

/// Which Git executable the inspection used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitAvailability {
    /// The executable that passed the checks.
    Located {
        /// Its resolved path.
        executable: PathBuf,
    },
    /// No executable passed the checks, so no unit has Git evidence.
    NotAvailable {
        /// Why.
        problem: GitToolProblem,
    },
}

/// The inspection of `project.dependency-directory`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// Each layout of the declaration with its lifecycle state. Each
    /// layout of this build is `proposed`, and `user-configured` permits at
    /// most a manual mode in each state.
    pub layouts: Vec<LayoutSupport>,
    /// The Git executable.
    pub git: GitAvailability,
    /// The search roots, in the sequence of the caller.
    pub roots: Vec<SearchRootReport>,
    /// The generated directories, in the sequence of the walk.
    pub units: Vec<ProjectUnitReport>,
}

/// The context of one inspection.
struct Inspector<'a> {
    host: ProjectHost<'a>,
    home: &'a Path,
    limits: ProjectLimits,
    cancel: &'a CancellationToken,
    clock: &'a dyn ScanClock,
    mounts: MountTable,
    deadline: Instant,
    expiry: Nanoseconds,
    processes: BuildProcesses,
    /// The path-use inventory of the current search root, and its scope.
    uses: Option<(UnitScope, PathInventory)>,
    /// The Paseo listing, read one time when the first unit needs it.
    agents: Option<AgentListing>,
    /// The reading of the Git source of each Git directory, read one time
    /// for the inspection. The unit bound bounds it.
    heads: BTreeMap<PathBuf, SourceReading>,
    /// The layouts of the catalog, then the layouts of the configuration.
    layouts: Vec<Layout<'a>>,
    /// The path of each unit of the report. The walk does not enter it.
    matched: BTreeSet<PathBuf>,
    directories: usize,
    units: Vec<ProjectUnitReport>,
}

/// One layout as the inspection uses it: a layout of the catalog or of the
/// configuration.
#[derive(Debug, Clone)]
struct Layout<'a> {
    id: &'static str,
    directory: &'a str,
    markers: Vec<(&'a str, MarkerKind)>,
    inner_marker: Option<&'a str>,
    project_file: Option<&'a str>,
    protected: Vec<&'a str>,
    name: DirectoryName,
    checkouts: PackageCheckouts,
    reclaim: ReclaimBasis,
    owner_workflow: &'static str,
    rebuild_impact: &'static str,
    /// The quiet period of the layout, in place of the period of the host.
    quiet_period: Option<Nanoseconds>,
}

impl<'a> Layout<'a> {
    fn built_in(layout: &'static ProjectLayout) -> Self {
        Self {
            id: layout.layout,
            directory: layout.directory,
            markers: layout
                .project_markers
                .iter()
                .map(|marker| (marker.name, marker.kind))
                .collect(),
            inner_marker: layout.inner_marker,
            project_file: layout.project_file,
            protected: layout.protected.to_vec(),
            name: layout.name,
            checkouts: layout.checkouts,
            reclaim: layout.reclaim,
            owner_workflow: layout.owner_workflow,
            rebuild_impact: layout.rebuild_impact,
            quiet_period: None,
        }
    }

    /// A layout of the configuration. Its name is generic: a directory with
    /// no marker is not listed. Its markers are regular files.
    fn configured(layout: &'a UserLayout) -> Self {
        Self {
            id: svalnir_core::rule::USER_CONFIGURED_LAYOUT,
            directory: &layout.directory,
            markers: layout
                .markers
                .iter()
                .map(|marker| (marker.as_str(), MarkerKind::File))
                .collect(),
            inner_marker: layout.inner_marker.as_deref(),
            project_file: None,
            protected: layout.protected.iter().map(String::as_str).collect(),
            name: DirectoryName::Generic,
            checkouts: PackageCheckouts::None,
            reclaim: ReclaimBasis::AllocatedBytes,
            owner_workflow: USER_LAYOUT_WORKFLOW,
            rebuild_impact: USER_LAYOUT_IMPACT,
            // The validation bounds the period to 90 days, so it fits.
            quiet_period: layout
                .quiet_period
                .and_then(|period| Nanoseconds::try_from(period).ok()),
        }
    }

    /// The first name of the directory, which is an entry of the project
    /// directory.
    fn first_name(&self) -> &'a str {
        self.directory.split('/').next().unwrap_or(self.directory)
    }
}

/// The layouts of the catalog, then the layouts of `configured`.
fn catalog(configured: &[UserLayout]) -> Vec<Layout<'_>> {
    PROJECT_LAYOUTS
        .iter()
        .map(Layout::built_in)
        .chain(configured.iter().map(Layout::configured))
        .collect()
}

/// Whether `name` matches `pattern`: `*` matches each sequence of bytes,
/// also an empty one, `?` matches one byte, and each other byte matches
/// itself. With `fold`, the case of ASCII letters is ignored.
pub(super) fn glob_matches(pattern: &[u8], name: &[u8], fold: bool) -> bool {
    let same = |left: u8, right: u8| {
        if fold {
            left.eq_ignore_ascii_case(&right)
        } else {
            left == right
        }
    };
    let (mut at_pattern, mut at_name): (usize, usize) = (0, 0);
    // The position after the last `*`, and the name position that it
    // matched up to.
    let mut star: Option<(usize, usize)> = None;
    while at_name < name.len() {
        match (pattern.get(at_pattern), name.get(at_name)) {
            (Some(b'*'), _) => {
                at_pattern += 1;
                star = Some((at_pattern, at_name));
            }
            (Some(&byte), Some(&found)) if byte == b'?' || same(byte, found) => {
                at_pattern += 1;
                at_name += 1;
            }
            _ => match star {
                Some((after, matched)) => {
                    at_pattern = after;
                    at_name = matched + 1;
                    star = Some((after, matched + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(at_pattern..)
        .is_some_and(|rest| rest.iter().all(|byte| *byte == b'*'))
}

/// Whether `marker` is a pattern: it has `*` or `?`.
fn is_pattern(marker: &str) -> bool {
    marker.contains(['*', '?'])
}

/// The result of the search for a protected child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ChildSearch {
    /// No entry is at a protected path.
    Clear,
    /// The entry at a protected path, relative to the unit.
    Found(PathBuf),
    /// A directory on the way could not be read completely, or the search
    /// passed its bound.
    Unknown,
}

/// The largest number of directories that the search for the protected
/// children of one unit reads.
const MAX_PROTECTED_DIRECTORIES: usize = 4_096;

/// The first entry below `unit` whose path matches one of `patterns`, by
/// component. The comparison ignores the case of ASCII letters, so it
/// finds more entries on a volume that ignores case, not fewer. No symbolic
/// link is followed: only a directory is entered on the way, and the last
/// component matches an entry of each type.
pub(super) fn find_protected(unit: &Path, patterns: &[&str]) -> ChildSearch {
    let mut budget: usize = MAX_PROTECTED_DIRECTORIES;
    for pattern in patterns {
        let components: Vec<&str> = pattern.split('/').collect();
        match search_child(unit, Path::new(""), &components, &mut budget) {
            ChildSearch::Clear => {}
            other => return other,
        }
    }
    ChildSearch::Clear
}

fn search_child(
    directory: &Path,
    relative: &Path,
    components: &[&str],
    budget: &mut usize,
) -> ChildSearch {
    let Some((first, rest)) = components.split_first() else {
        return ChildSearch::Clear;
    };
    if *budget == 0 {
        return ChildSearch::Unknown;
    }
    *budget -= 1;
    let Ok(entries) = fs::read_dir(directory) else {
        return ChildSearch::Unknown;
    };
    let limit: usize = crate::rules::worktrees::MAX_DIRECTORY_ENTRIES;
    let mut names: Vec<OsString> = Vec::new();
    for entry in entries.take(limit + 1) {
        let Ok(entry) = entry else {
            return ChildSearch::Unknown;
        };
        names.push(entry.file_name());
    }
    if names.len() > limit {
        return ChildSearch::Unknown;
    }
    for name in names {
        if !glob_matches(first.as_bytes(), name.as_encoded_bytes(), true) {
            continue;
        }
        let found: PathBuf = relative.join(&name);
        if rest.is_empty() {
            return ChildSearch::Found(found);
        }
        let child: PathBuf = directory.join(&name);
        match lstat(&child) {
            Ok(snapshot) if snapshot.kind == ObjectKind::Directory => {}
            Ok(_) => continue,
            Err(_) => return ChildSearch::Unknown,
        }
        match search_child(&child, &found, rest, budget) {
            ChildSearch::Clear => {}
            other => return other,
        }
    }
    ChildSearch::Clear
}

/// Whether the directory `project`, whose entries are `names`, has a marker
/// of `layout`.
fn has_marker(layout: &Layout<'_>, project: &Path, names: &BTreeSet<OsString>) -> bool {
    let is_kind = |name: &OsStr, kind: MarkerKind| {
        lstat(&project.join(name)).is_ok_and(|found| match kind {
            MarkerKind::File => found.kind == ObjectKind::RegularFile,
            MarkerKind::Directory => found.kind == ObjectKind::Directory,
        })
    };
    layout.markers.iter().any(|(marker, kind)| {
        if is_pattern(marker) {
            names
                .iter()
                .filter(|name| glob_matches(marker.as_bytes(), name.as_encoded_bytes(), false))
                .any(|name| is_kind(name, *kind))
        } else {
            is_kind(OsStr::new(marker), *kind)
        }
    })
}

/// Whether the walk never enters a directory with the name `name`: a
/// directory of version control or the shared cache directory
/// ([`SKIPPED_DIRECTORY_NAMES`]). The comparison ignores the case of ASCII
/// letters.
fn is_skipped(name: &OsStr) -> bool {
    SKIPPED_DIRECTORY_NAMES.iter().any(|skipped| {
        name.as_encoded_bytes()
            .eq_ignore_ascii_case(skipped.as_bytes())
    })
}

/// Whether one path is the other path or is below it, by component.
fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// The checks of the search root at `path`, and its path with the stored
/// names and its snapshot.
///
/// # Errors
///
/// Returns [`SearchRootOutcome::Absent`] for a root that does not exist,
/// and a refusal for a root that fails a check.
pub(in crate::rules) fn open_search_root(
    path: &Path,
    locations: &ProtectedLocations,
    user_exclusions: &[PathBuf],
    principal: Uid,
    mounts: &MountTable,
) -> Result<(PathBuf, ObjectSnapshot), SearchRootOutcome> {
    let refused = SearchRootOutcome::Refused;
    // The text checks make no call on the path.
    match locations.of_text(path) {
        ProtectionFact::NotProtected => {}
        ProtectionFact::Protected => return Err(refused("root_protected")),
        ProtectionFact::Unknown => return Err(refused("root_protection_unknown")),
    }
    if user_exclusions
        .iter()
        .any(|excluded| path.starts_with(excluded))
    {
        return Err(refused("root_excluded"));
    }
    let snapshot: ObjectSnapshot = match walk_local(path, mounts) {
        Ok(snapshot) => snapshot,
        Err(WalkStop::Absent) => return Err(SearchRootOutcome::Absent),
        Err(WalkStop::LinkInAncestor) => return Err(refused("root_path_not_plain")),
        Err(WalkStop::NotLocal) => return Err(refused("root_not_local")),
        Err(WalkStop::LocalityUnknown) => return Err(refused("root_locality_unknown")),
        Err(WalkStop::Failed(_)) => return Err(refused("root_not_readable")),
    };
    if snapshot.kind != ObjectKind::Directory {
        return Err(refused("root_not_directory"));
    }
    if snapshot.owner != principal {
        return Err(refused("root_owner"));
    }
    Ok((stored_case(path), snapshot))
}

/// The path with the names that the filesystem stores, when they differ
/// from `path` in case only.
///
/// A volume that ignores case finds `~/code` for a directory `~/Code`, and
/// the kernel gives the stored names in the working directory of a
/// process. The walk reads the names below the root from the directory, so
/// only the root itself can have the case of the caller. The path has no
/// symbolic link (the walk of the local filesystems shows it), so its
/// resolved form differs from it in the case of its names only; a resolved
/// form that differs in more is not used.
fn stored_case(path: &Path) -> PathBuf {
    match fs::canonicalize(path) {
        Ok(resolved)
            if resolved.as_os_str().len() == path.as_os_str().len()
                && resolved
                    .as_os_str()
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(path.as_os_str().as_encoded_bytes()) =>
        {
            resolved
        }
        _ => path.to_path_buf(),
    }
}

impl ProjectRule {
    /// Inspects the search roots `roots` below the home directory.
    ///
    /// The function never fails as a whole: each search root and each
    /// unit has its result.
    pub fn inspect(
        &self,
        host: ProjectHost<'_>,
        roots: &SearchRoots,
        limits: ProjectLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> ProjectInspection {
        self.inspect_with_mounts(host, roots, limits, cancel, clock, MountTable::read)
    }

    /// [`ProjectRule::inspect`] with another source of the mount table.
    pub(crate) fn inspect_with_mounts(
        &self,
        host: ProjectHost<'_>,
        roots: &SearchRoots,
        limits: ProjectLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
        mounts: MountTableSource,
    ) -> ProjectInspection {
        let git: GitAvailability = match host.git {
            Ok(tool) => GitAvailability::Located {
                executable: tool.executable().to_path_buf(),
            },
            Err(problem) => GitAvailability::NotAvailable { problem },
        };
        let mut reports: Vec<SearchRootReport> = Vec::new();
        let mut units: Vec<ProjectUnitReport> = Vec::new();
        let refuse_all = |reason: &'static str, home: Option<&Path>| {
            roots
                .paths()
                .iter()
                .map(|relative| SearchRootReport {
                    relative: relative.clone(),
                    path: home.map(|home| home.join(relative)),
                    outcome: SearchRootOutcome::Refused(reason),
                    unreadable_directories: 0,
                })
                .collect::<Vec<SearchRootReport>>()
        };
        match (host.locations.home_directory(), mounts()) {
            (None, _) => reports = refuse_all("home_unknown", None),
            (Some(home), Err(_)) => reports = refuse_all("root_locality_unknown", Some(home)),
            (Some(home), Ok(table)) => {
                let mut inspector: Inspector<'_> = Inspector {
                    host,
                    home,
                    limits,
                    cancel,
                    clock,
                    mounts: table,
                    deadline: Instant::now() + limits.max_duration,
                    expiry: self.rule().activity.evidence_expiry,
                    processes: host.processes.build_processes(host.principal),
                    uses: None,
                    agents: None,
                    heads: BTreeMap::new(),
                    layouts: catalog(host.layouts),
                    matched: BTreeSet::new(),
                    directories: 0,
                    units: Vec::new(),
                };
                for relative in roots.paths() {
                    reports.push(inspector.root(relative));
                }
                units = inspector.units;
            }
        }
        ProjectInspection {
            rule: self.rule().reference.clone(),
            layouts: self.rule().layouts.clone(),
            git,
            roots: reports,
            units,
        }
    }
}

impl Inspector<'_> {
    fn root(&mut self, relative: &Path) -> SearchRootReport {
        let path: PathBuf = self.home.join(relative);
        let mut report: SearchRootReport = SearchRootReport {
            relative: relative.to_path_buf(),
            path: Some(path.clone()),
            outcome: SearchRootOutcome::Absent,
            unreadable_directories: 0,
        };
        let (path, snapshot): (PathBuf, ObjectSnapshot) = match open_search_root(
            &path,
            self.host.locations,
            self.host.user_exclusions,
            self.host.principal,
            &self.mounts,
        ) {
            Ok(opened) => opened,
            Err(outcome) => {
                report.outcome = outcome;
                return report;
            }
        };
        report.path = Some(path.clone());
        // One inventory for each search root, with the root as its scope.
        let scope: UnitScope = UnitScope::new(&path);
        let inventory: PathInventory = self
            .host
            .processes
            .path_uses(self.host.principal, std::slice::from_ref(&scope));
        self.uses = Some((scope, inventory));
        let completion: SearchCompletion = self.walk(&path, snapshot, &mut report);
        report.outcome = SearchRootOutcome::Examined(completion);
        report
    }

    /// The stop of the walk now, when one applies.
    fn stop(&self) -> Option<SearchCompletion> {
        if self.cancel.is_cancelled() {
            Some(SearchCompletion::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(SearchCompletion::DeadlineReached)
        } else if self.units.len() >= self.limits.max_units {
            Some(SearchCompletion::UnitLimitReached)
        } else if self.directories >= self.limits.max_directories {
            Some(SearchCompletion::DirectoryLimitReached)
        } else {
            None
        }
    }

    /// Reads the directories below `root` breadth first.
    fn walk(
        &mut self,
        root: &Path,
        snapshot: ObjectSnapshot,
        report: &mut SearchRootReport,
    ) -> SearchCompletion {
        let device = snapshot.object.device;
        let mut queue: VecDeque<(PathBuf, u32)> = VecDeque::from([(root.to_path_buf(), 0)]);
        let mut depth_limited: bool = false;
        while let Some((directory, depth)) = queue.pop_front() {
            if let Some(stop) = self.stop() {
                return stop;
            }
            self.directories += 1;
            let Ok(entries) = fs::read_dir(&directory) else {
                report.unreadable_directories += 1;
                continue;
            };
            let names: BTreeSet<OsString> = entries
                .take(crate::rules::worktrees::MAX_DIRECTORY_ENTRIES)
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect();
            self.project(&directory, root, &names);
            for name in &names {
                let child: PathBuf = directory.join(name);
                // A unit, a directory of version control, and the shared
                // cache directory are not entered.
                if is_skipped(name) || self.matched.contains(&child) {
                    continue;
                }
                let Ok(found) = lstat(&child) else {
                    continue;
                };
                // No symbolic link is followed, no other device is
                // entered, and a directory of another owner is not read.
                if found.kind != ObjectKind::Directory
                    || found.object.device != device
                    || found.owner != self.host.principal
                {
                    continue;
                }
                if self.host.locations.of_text(&child) != ProtectionFact::NotProtected
                    || self
                        .host
                        .user_exclusions
                        .iter()
                        .any(|excluded| child.starts_with(excluded))
                {
                    continue;
                }
                if depth >= self.limits.max_depth {
                    depth_limited = true;
                    continue;
                }
                queue.push_back((child, depth + 1));
            }
        }
        if depth_limited {
            SearchCompletion::DepthLimitReached
        } else {
            SearchCompletion::Complete
        }
    }

    /// The units of the directory `project`, whose entries are `names`.
    ///
    /// For each directory of the layouts, the first layout whose marker is
    /// present gives the unit. With no such layout, a distinctive name gives
    /// a unit that the checks refuse (`project_marker_missing`), and a
    /// generic name gives no unit.
    fn project(&mut self, project: &Path, root: &Path, names: &BTreeSet<OsString>) {
        let mut directories: Vec<&str> = Vec::new();
        for layout in &self.layouts {
            if !directories.contains(&layout.directory)
                && names.contains(OsStr::new(layout.first_name()))
            {
                directories.push(layout.directory);
            }
        }
        // The units of this project so far, with their layouts.
        let mut earlier: Vec<(PathBuf, &'static str)> = Vec::new();
        for directory in directories {
            if self.stop().is_some() {
                return;
            }
            let path: PathBuf = project.join(directory);
            // A path of two names needs its second name.
            if directory.contains('/') && lstat(&path).is_err() {
                continue;
            }
            let chosen: Option<Layout<'_>> = {
                let mut of_directory = self
                    .layouts
                    .iter()
                    .filter(|layout| layout.directory == directory);
                of_directory
                    .clone()
                    .find(|layout| has_marker(layout, project, names))
                    .or_else(|| {
                        of_directory.find(|layout| layout.name == DirectoryName::Distinctive)
                    })
                    .cloned()
            };
            let Some(layout) = chosen else {
                continue;
            };
            let mut report: ProjectUnitReport = ProjectUnitReport {
                path: path.clone(),
                project: project.to_path_buf(),
                layout: layout.id,
                protected_child: None,
                overlapping_layout: None,
                version_control: None,
                activity: None,
                uses: None,
                recency: None,
                outcome: ProjectUnitOutcome::Refused { reason: "" },
                owner_workflow: layout.owner_workflow,
                rebuild_impact: layout.rebuild_impact,
            };
            // One directory is never in two units: a unit that is, holds, or
            // is in an earlier unit of the project is refused, and only the
            // earlier unit is measured.
            if let Some((_, other)) = earlier.iter().find(|(unit, _)| overlaps(unit, &path)) {
                report.overlapping_layout = Some(other);
                report.outcome = ProjectUnitOutcome::Refused {
                    reason: "overlaps_unit",
                };
            } else {
                report.outcome = self.unit(&layout, project, root, names, &path, &mut report);
            }
            earlier.push((path.clone(), layout.id));
            self.matched.insert(path);
            self.units.push(report);
        }
    }

    /// The checks of the objects of one unit: the directories on the way,
    /// the unit, the project marker, the inner marker, and the protected
    /// children. The error is the stable reason of the refusal.
    fn shape(
        &self,
        layout: &Layout<'_>,
        project: &Path,
        names: &BTreeSet<OsString>,
        path: &Path,
        report: &mut ProjectUnitReport,
    ) -> Result<(), &'static str> {
        let Ok(parent) = lstat(project) else {
            return Err("project_not_readable");
        };
        // Each directory between the project and the unit, for a path of
        // two names, is a directory of the user on the same device, not a
        // symbolic link.
        let mut between: PathBuf = project.to_path_buf();
        let mut components = layout.directory.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            between.push(component);
            match lstat(&between) {
                Ok(found)
                    if found.kind == ObjectKind::Directory
                        && found.owner == self.host.principal
                        && found.object.device == parent.object.device => {}
                Ok(_) => return Err("unit_path_not_plain"),
                Err(_) => return Err("unit_not_readable"),
            }
        }
        let snapshot: ObjectSnapshot = match lstat(path) {
            Ok(snapshot) => snapshot,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err("unit_absent"),
            Err(_) => return Err("unit_not_readable"),
        };
        match snapshot.kind {
            ObjectKind::Directory => {}
            ObjectKind::SymbolicLink => return Err("unit_symbolic_link"),
            _ => return Err("unit_not_directory"),
        }
        if snapshot.owner != self.host.principal {
            return Err("unit_owner");
        }
        if snapshot.object.device != parent.object.device {
            return Err("unit_device");
        }
        if !has_marker(layout, project, names) {
            return Err("project_marker_missing");
        }
        if let Some(inner) = layout.inner_marker
            && !lstat(&path.join(inner)).is_ok_and(|found| found.kind == ObjectKind::RegularFile)
        {
            return Err("unsupported_layout");
        }
        if let Some(file) = layout.project_file
            && !is_plain_file(project, file)
        {
            return Err("unsupported_layout");
        }
        match find_protected(path, &layout.protected) {
            ChildSearch::Clear => Ok(()),
            ChildSearch::Found(child) => {
                report.protected_child = Some(child);
                Err("protected_child")
            }
            ChildSearch::Unknown => Err("protected_child_unknown"),
        }
    }

    /// The checks of one unit, in sequence, and its measurement.
    fn unit(
        &mut self,
        layout: &Layout<'_>,
        project: &Path,
        root: &Path,
        names: &BTreeSet<OsString>,
        path: &Path,
        report: &mut ProjectUnitReport,
    ) -> ProjectUnitOutcome {
        let refused = |reason: &'static str| ProjectUnitOutcome::Refused { reason };
        // The text checks come before a call on a name in the unit.
        match self.host.locations.of_text(path) {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => return refused("unit_protected"),
            ProtectionFact::Unknown => return refused("unit_protection_unknown"),
        }
        if self
            .host
            .user_exclusions
            .iter()
            .any(|excluded| overlaps(path, excluded))
        {
            return refused("unit_excluded");
        }
        if let Err(reason) = self.shape(layout, project, names, path, report) {
            return refused(reason);
        }
        let (version_control, repository): (VersionControl, Option<Repository>) =
            self.version_control(project, root, path);
        report.version_control = Some(version_control.clone());
        match version_control {
            VersionControl::Ignored => {}
            VersionControl::NotIgnored => return refused("not_ignored"),
            VersionControl::Tracked => return refused("tracked_files"),
            VersionControl::NoRepository => return refused("no_repository"),
            VersionControl::Unknown { .. } => return refused("version_control_unknown"),
        }
        let Some(repository) = repository else {
            return refused("version_control_unknown");
        };
        let recency: ProjectRecency = self.recency(&repository, layout.quiet_period);
        let busy: bool = recency.state == RecencyState::Busy;
        report.recency = Some(recency);
        if busy {
            return refused("project_busy");
        }
        let activity: ProjectActivity = self.activity(project, root);
        report.activity = Some(activity.clone());
        match activity {
            ProjectActivity::Inactive => {}
            ProjectActivity::Active { .. } => return refused("producer_active"),
            ProjectActivity::Unknown { .. } => return refused("activity_unknown"),
        }
        let uses: UnitUse = self.unit_use(path);
        report.uses = Some(uses.clone());
        if let Some(reason) = uses.refusal() {
            return refused(reason);
        }
        // The measurement also looks for a clone with commits or changes
        // that exist nowhere else. For a layout with the checkouts of Swift
        // Package Manager, a unit with a repository is examined again with
        // the exception of `docs/CLEANUP_RULES.md` section 6.
        let mut repositories: MarkerObserver<'_> = MarkerObserver::new(path);
        match measure_unit_observed(
            path,
            self.limits.measure,
            self.cancel,
            self.clock,
            layout.reclaim,
            &mut repositories,
        ) {
            Some((measurement, result)) => match repositories.verdict(&result) {
                Verdict::Clear => ProjectUnitOutcome::Measured(measurement),
                Verdict::Refused(refusal) => {
                    match self.package_checkouts(layout, project, names, path, &refusal) {
                        Some(Verdict::Clear) => ProjectUnitOutcome::Measured(measurement),
                        Some(Verdict::Refused(refusal)) => {
                            ProjectUnitOutcome::RepositoryRefused(refusal)
                        }
                        None => ProjectUnitOutcome::RepositoryRefused(refusal),
                    }
                }
            },
            None => refused("unit_not_readable"),
        }
    }

    /// The verdict of the exception for the checkouts of Swift Package
    /// Manager, for a unit whose measurement found a repository, or `None`
    /// when the exception does not apply: the layout has no checkouts, the
    /// refusal is not a repository, or no one package, workspace, or
    /// project gives the pins.
    fn package_checkouts(
        &self,
        layout: &Layout<'_>,
        project: &Path,
        names: &BTreeSet<OsString>,
        path: &Path,
        refusal: &RepositoryRefusal,
    ) -> Option<Verdict> {
        if refusal.reason != RefusalReason::NestedRepository {
            return None;
        }
        let checkouts: SwiftPmCheckouts = match layout.checkouts {
            PackageCheckouts::None => return None,
            PackageCheckouts::PackageBuild => SwiftPmCheckouts::of_package_build(path)?,
            PackageCheckouts::XcodeDerivedData => {
                SwiftPmCheckouts::of_xcode_project(path, &pin_container(project, names)?)?
            }
        };
        let limits: DetectionLimits = DetectionLimits {
            max_duration: self
                .deadline
                .saturating_duration_since(Instant::now())
                .min(DetectionLimits::default().max_duration),
            ..DetectionLimits::default()
        };
        Some(check_unit(
            path,
            Some(&checkouts),
            self.host.git,
            &limits,
            Some(self.cancel),
        ))
    }

    /// Whether Git ignores the unit at `path` and tracks no path in it,
    /// and the repository when the lookup found one.
    fn version_control(
        &self,
        project: &Path,
        root: &Path,
        path: &Path,
    ) -> (VersionControl, Option<Repository>) {
        let unknown = |reason: &'static str| VersionControl::Unknown { reason };
        let Ok(git) = self.host.git else {
            return (unknown("git_not_available"), None);
        };
        let repository = match find_repository(project, root, self.host.principal, &self.mounts) {
            RepositoryLookup::Found(repository) => repository,
            RepositoryLookup::NotFound => return (VersionControl::NoRepository, None),
            RepositoryLookup::Unknown(reason) => return (unknown(reason), None),
        };
        let evidence: VersionControl = Self::ignored(git, &repository, path);
        (evidence, Some(repository))
    }

    /// The queries of [`Inspector::version_control`] for `repository`.
    fn ignored(git: &GitTool, repository: &Repository, path: &Path) -> VersionControl {
        let unknown = |reason: &'static str| VersionControl::Unknown { reason };
        let Ok(relative) = path.strip_prefix(&repository.work_tree) else {
            return unknown("unit_outside_work_tree");
        };
        let relative: &OsStr = relative.as_os_str();
        // The pathspec of `ls-files` is literal, so a name with `*` is not
        // a pattern. `check-ignore` takes a path, not a pathspec.
        let mut literal: OsString = OsString::from(":(literal)");
        literal.push(relative);
        let run = |arguments: &[&OsStr]| {
            git.run(
                &repository.git_dir,
                Some(&repository.work_tree),
                arguments,
                MAX_GIT_OUTPUT,
            )
        };
        // The index: a path in the unit, or the unit itself as a file or a
        // submodule, is tracked.
        let tracked: Result<GitOutput, GitFailure> = run(&[
            OsStr::new("ls-files"),
            OsStr::new("-z"),
            OsStr::new("--cached"),
            OsStr::new("--"),
            &literal,
        ]);
        match tracked {
            Ok(output) if output.code == 0 && output.stdout.is_empty() && !output.truncated => {}
            Ok(output) if output.code == 0 => return VersionControl::Tracked,
            Ok(_) => return unknown("git_query_failed"),
            Err(failure) => return unknown(failure.as_str()),
        }
        // The ignore rules of each level. Exit 0: ignored; exit 1: not
        // ignored; another exit: an error.
        let ignored: Result<GitOutput, GitFailure> = run(&[
            OsStr::new("check-ignore"),
            OsStr::new("-q"),
            OsStr::new("--no-index"),
            OsStr::new("--"),
            relative,
        ]);
        match ignored {
            Ok(output) if output.code == 0 => VersionControl::Ignored,
            Ok(output) if output.code == 1 => VersionControl::NotIgnored,
            Ok(_) => unknown("git_query_failed"),
            Err(failure) => unknown(failure.as_str()),
        }
    }

    /// The project activity of `repository`. The Paseo listing is read one
    /// time for the inspection, and the Git source one time for each Git
    /// directory.
    fn recency(&mut self, repository: &Repository, quiet: Option<Nanoseconds>) -> ProjectRecency {
        let mut host: RecencyHost<'_> = self.host.recency;
        if let Some(quiet) = quiet {
            host.quiet_period = quiet;
        }
        let git: SourceReading = *self
            .heads
            .entry(repository.git_dir.clone())
            .or_insert_with(|| host.head.head_activity(repository));
        let listing: &AgentListing = self
            .agents
            .get_or_insert_with(|| host.agents.agent_listing());
        assess_with_head(&host, listing, repository, git, self.clock.now().wall)
    }

    /// The use of the unit at `path`, from the inventory of the search root.
    /// An inventory that is older than the expiry of the rule is read again.
    fn unit_use(&mut self, path: &Path) -> UnitUse {
        let expiry: Nanoseconds = self.expiry;
        let now: Option<MonotonicNanos> = self.host.processes.monotonic_now();
        let Some((scope, inventory)) = &mut self.uses else {
            return UnitUse::Unknown {
                reason: "no_inventory",
                processes: Vec::new(),
                omitted: 0,
            };
        };
        let current: bool = inventory
            .observed_at
            .zip(now)
            .and_then(|(observed, now)| now.checked_duration_since(observed))
            .is_some_and(|age| age <= expiry);
        if !current {
            *inventory = self
                .host
                .processes
                .path_uses(self.host.principal, std::slice::from_ref(scope));
        }
        uses_of(inventory, &UnitScope::new(path))
    }

    /// The process evidence for the project at `project`. Evidence that is
    /// older than the expiry of the rule is read again.
    fn activity(&mut self, project: &Path, root: &Path) -> ProjectActivity {
        let expiry: Nanoseconds = self.expiry;
        let is_current = |processes: &BuildProcesses, now: Option<MonotonicNanos>| {
            processes
                .observed_at
                .zip(now)
                .and_then(|(observed, now)| now.checked_duration_since(observed))
                .is_some_and(|age| age <= expiry)
        };
        if !is_current(&self.processes, self.host.processes.monotonic_now()) {
            self.processes = self.host.processes.build_processes(self.host.principal);
        }
        if let Some(executable) = self.processes.blocking(project) {
            return ProjectActivity::Active {
                executable: executable.to_path_buf(),
            };
        }
        if self.processes.above(project, root).is_some() {
            return ProjectActivity::Unknown {
                reason: "build_process_above_project",
            };
        }
        if let Some(reason) = self.processes.incomplete {
            return ProjectActivity::Unknown { reason };
        }
        if is_current(&self.processes, self.host.processes.monotonic_now()) {
            ProjectActivity::Inactive
        } else {
            ProjectActivity::Unknown {
                reason: "evidence_expired",
            }
        }
    }
}

/// The package, workspace, or project beside a `DerivedData` directory of
/// a project whose pins its checkouts have: `Package.swift`, else the one
/// `*.xcworkspace`, else the one `*.xcodeproj`. `None` when no one of them
/// is beside it.
fn pin_container(project: &Path, names: &BTreeSet<OsString>) -> Option<PathBuf> {
    let is = |name: &OsStr, kind: ObjectKind| {
        lstat(&project.join(name)).is_ok_and(|found| found.kind == kind)
    };
    if is(OsStr::new("Package.swift"), ObjectKind::RegularFile) {
        return Some(project.to_path_buf());
    }
    for extension in ["xcworkspace", "xcodeproj"] {
        let found: Vec<&OsString> = names
            .iter()
            .filter(|name| {
                Path::new(name).extension() == Some(OsStr::new(extension))
                    && is(name, ObjectKind::Directory)
            })
            .collect();
        match found.as_slice() {
            [one] => return Some(project.join(one)),
            [] => {}
            _ => return None,
        }
    }
    None
}

/// Whether `relative`, below `project`, is a regular file, with each
/// directory on its way a directory and not a symbolic link.
fn is_plain_file(project: &Path, relative: &str) -> bool {
    let mut path: PathBuf = project.to_path_buf();
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        path.push(component);
        let Ok(found) = lstat(&path) else {
            return false;
        };
        let expected: ObjectKind = if components.peek().is_some() {
            ObjectKind::Directory
        } else {
            ObjectKind::RegularFile
        };
        if found.kind != expected {
            return false;
        }
    }
    true
}
