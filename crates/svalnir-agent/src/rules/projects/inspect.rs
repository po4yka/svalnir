//! The inspection of `project.dependency-directory`.
//!
//! The inspection is read-only. It reads directory entries and metadata
//! below the search roots, runs the read-only Git queries of
//! [`crate::rules::git`], reads the process table, and measures each unit
//! with the scanner. It changes nothing and gives no candidate.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{LayoutSupport, RuleRef};
use svalnir_core::time::MonotonicNanos;

use super::activity::{BuildProcesses, ProcessEvidence};
use super::{CARGO_RULE_ID, CARGO_TARGET, PROJECT_LAYOUTS, ProjectLayout, ProjectRule};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::protection::ProtectedLocations;
use crate::rules::caches::{CacheMeasurement, InspectionLimits, measure_unit};
use crate::rules::git::{
    GitFailure, GitOutput, GitTool, GitToolProblem, RepositoryLookup, find_repository,
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
    /// Another rule owns the directory (`docs/CLEANUP_RULES.md` section
    /// 8). It is not measured.
    OwnedByOtherRule {
        /// The identity of that rule.
        rule: &'static str,
    },
}

/// The report of one generated directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectUnitReport {
    /// The path of the generated directory.
    pub path: PathBuf,
    /// The project directory.
    pub project: PathBuf,
    /// The layout. Empty for a directory of another rule.
    pub layout: &'static str,
    /// The evidence of Git, when the checks came to it.
    pub version_control: Option<VersionControl>,
    /// The process evidence, when the checks came to it.
    pub activity: Option<ProjectActivity>,
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
    /// layout of this build is `proposed`.
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
    directories: usize,
    units: Vec<ProjectUnitReport>,
}

/// The names of the directories that the walk does not enter: the Git
/// directory and the generated directories of each layout.
fn is_not_entered(name: &OsStr, names: &BTreeSet<OsString>) -> bool {
    name == ".git"
        || PROJECT_LAYOUTS
            .iter()
            .any(|layout| name == layout.directory)
        || (name == CARGO_TARGET.0 && names.contains(OsStr::new(CARGO_TARGET.1)))
}

/// Whether one path is the other path or is below it, by component.
fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
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
        let refused = SearchRootOutcome::Refused;
        // The text checks make no call on the path.
        match self.host.locations.of_text(&path) {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => {
                report.outcome = refused("root_protected");
                return report;
            }
            ProtectionFact::Unknown => {
                report.outcome = refused("root_protection_unknown");
                return report;
            }
        }
        if self
            .host
            .user_exclusions
            .iter()
            .any(|excluded| path.starts_with(excluded))
        {
            report.outcome = refused("root_excluded");
            return report;
        }
        let snapshot: ObjectSnapshot = match walk_local(&path, &self.mounts) {
            Ok(snapshot) => snapshot,
            Err(WalkStop::Absent) => return report,
            Err(WalkStop::LinkInAncestor) => {
                report.outcome = refused("root_path_not_plain");
                return report;
            }
            Err(WalkStop::NotLocal) => {
                report.outcome = refused("root_not_local");
                return report;
            }
            Err(WalkStop::LocalityUnknown) => {
                report.outcome = refused("root_locality_unknown");
                return report;
            }
            Err(WalkStop::Failed(_)) => {
                report.outcome = refused("root_not_readable");
                return report;
            }
        };
        if snapshot.kind != ObjectKind::Directory {
            report.outcome = refused("root_not_directory");
            return report;
        }
        if snapshot.owner != self.host.principal {
            report.outcome = refused("root_owner");
            return report;
        }
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
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect();
            self.project(&directory, root, &names);
            for name in &names {
                if is_not_entered(name, &names) {
                    continue;
                }
                let child: PathBuf = directory.join(name);
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
    fn project(&mut self, project: &Path, root: &Path, names: &BTreeSet<OsString>) {
        for layout in &PROJECT_LAYOUTS {
            if !names.contains(OsStr::new(layout.directory)) || self.stop().is_some() {
                continue;
            }
            let path: PathBuf = project.join(layout.directory);
            let mut report: ProjectUnitReport = ProjectUnitReport {
                path: path.clone(),
                project: project.to_path_buf(),
                layout: layout.layout,
                version_control: None,
                activity: None,
                outcome: ProjectUnitOutcome::Refused { reason: "" },
                owner_workflow: layout.owner_workflow,
                rebuild_impact: layout.rebuild_impact,
            };
            report.outcome = self.unit(layout, project, root, &path, &mut report);
            self.units.push(report);
        }
        let (target, manifest) = CARGO_TARGET;
        if names.contains(OsStr::new(target))
            && names.contains(OsStr::new(manifest))
            && self.stop().is_none()
        {
            self.units.push(ProjectUnitReport {
                path: project.join(target),
                project: project.to_path_buf(),
                layout: "",
                version_control: None,
                activity: None,
                outcome: ProjectUnitOutcome::OwnedByOtherRule {
                    rule: CARGO_RULE_ID,
                },
                owner_workflow: "Run `cargo clean` in the workspace. Svalnir does not run it. The rule `cargo.build-output` owns this directory.",
                rebuild_impact: "The next build compiles the workspace and its dependencies again.",
            });
        }
    }

    /// The checks of one unit, in sequence, and its measurement.
    fn unit(
        &mut self,
        layout: &ProjectLayout,
        project: &Path,
        root: &Path,
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
        let Ok(parent) = lstat(project) else {
            return refused("project_not_readable");
        };
        let snapshot: ObjectSnapshot = match lstat(path) {
            Ok(snapshot) => snapshot,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return refused("unit_absent"),
            Err(_) => return refused("unit_not_readable"),
        };
        match snapshot.kind {
            ObjectKind::Directory => {}
            ObjectKind::SymbolicLink => return refused("unit_symbolic_link"),
            _ => return refused("unit_not_directory"),
        }
        if snapshot.owner != self.host.principal {
            return refused("unit_owner");
        }
        if snapshot.object.device != parent.object.device {
            return refused("unit_device");
        }
        let has_marker: bool = layout.project_markers.iter().any(|marker| {
            lstat(&project.join(marker)).is_ok_and(|found| found.kind == ObjectKind::RegularFile)
        });
        if !has_marker {
            return refused("project_marker_missing");
        }
        if let Some(inner) = layout.inner_marker
            && !lstat(&path.join(inner)).is_ok_and(|found| found.kind == ObjectKind::RegularFile)
        {
            return refused("unsupported_layout");
        }
        let version_control: VersionControl = self.version_control(project, root, path);
        report.version_control = Some(version_control.clone());
        match version_control {
            VersionControl::Ignored => {}
            VersionControl::NotIgnored => return refused("not_ignored"),
            VersionControl::Tracked => return refused("tracked_files"),
            VersionControl::NoRepository => return refused("no_repository"),
            VersionControl::Unknown { .. } => return refused("version_control_unknown"),
        }
        let activity: ProjectActivity = self.activity(project);
        report.activity = Some(activity.clone());
        match activity {
            ProjectActivity::Inactive => {}
            ProjectActivity::Active { .. } => return refused("producer_active"),
            ProjectActivity::Unknown { .. } => return refused("activity_unknown"),
        }
        match measure_unit(
            path,
            self.limits.measure,
            self.cancel,
            self.clock,
            layout.reclaim,
        ) {
            Some(measurement) => ProjectUnitOutcome::Measured(measurement),
            None => refused("unit_not_readable"),
        }
    }

    /// Whether Git ignores the unit at `path` and tracks no path in it.
    fn version_control(&self, project: &Path, root: &Path, path: &Path) -> VersionControl {
        let unknown = |reason: &'static str| VersionControl::Unknown { reason };
        let Ok(git) = self.host.git else {
            return unknown("git_not_available");
        };
        let repository = match find_repository(project, root, self.host.principal, &self.mounts) {
            RepositoryLookup::Found(repository) => repository,
            RepositoryLookup::NotFound => return VersionControl::NoRepository,
            RepositoryLookup::Unknown(reason) => return unknown(reason),
        };
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
            Ok(output) if output.code == 0 && output.stdout.is_empty() => {}
            Ok(output) if output.code == 0 => return VersionControl::Tracked,
            // More output than the bound is more than one tracked path.
            Err(GitFailure::OutputTooLarge) => return VersionControl::Tracked,
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

    /// The process evidence for the project at `project`. Evidence that is
    /// older than the expiry of the rule is read again.
    fn activity(&mut self, project: &Path) -> ProjectActivity {
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
