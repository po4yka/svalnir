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
use svalnir_core::action::AdmittedRepository;
pub(super) use svalnir_core::config::glob_matches;
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
    USER_LAYOUT_IMPACT, USER_LAYOUT_WORKFLOW, Unmarked,
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
    DetectionLimits, MarkerObserver, REPOSITORY_CHANGED_CODE, RefusalReason, RepositoryRecheck,
    RepositoryRefusal, SwiftPmCheckouts, Verdict, check_unit, recheck_admitted,
};
use crate::rules::unit::{
    ObjectKind, ObjectSnapshot, WalkStop, is_plain_relative, lstat, walk_local,
};
use crate::scan::{CancellationToken, ScanClock};

/// The largest number of search roots of one inspection.
pub const MAX_SEARCH_ROOTS: usize = 16;

/// The largest number of project roots of one inspection, for example the
/// project roots that mise records.
pub const MAX_PROJECT_ROOTS: usize = 256;

/// The largest output of a Git query of this rule, in bytes.
const MAX_GIT_OUTPUT: usize = 4 * 1024;

/// How the inspection examines a root of its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A search root: the walk reads the directories below it.
    Search,
    /// A project directory: the inspection examines the units of that
    /// directory only, and the walk reads no directory below it.
    Project,
}

/// Where a root of a request comes from. The report of each root has it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootSource {
    /// The caller of the library function.
    Caller,
    /// `[cleanup.projects].search_roots` of the configuration.
    Configuration,
    /// A `--root` argument of the command.
    Argument,
    /// A configuration file that mise records in its tracked-configs
    /// directory. The path is the target of the link that mise made.
    Mise {
        /// The configuration file.
        config: PathBuf,
    },
}

/// One root of a request, relative to the home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRootEntry {
    /// The path, relative to the home directory.
    pub relative: PathBuf,
    /// How the inspection examines the root.
    pub kind: RootKind,
    /// Where the root comes from.
    pub source: RootSource,
}

/// The roots of one request, each relative to the home directory: the
/// search roots, then the project roots, and the roots that the request
/// left out, each with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRoots {
    entries: Vec<SearchRootEntry>,
    dropped: Vec<(SearchRootEntry, &'static str)>,
}

/// The reason of a root that has the path of an earlier root.
pub const REPEATED_ROOT: &str = "repeated_root";

/// The reason of a root that is in a search root of the request: the walk
/// of that search root examines it.
pub const IN_SEARCH_ROOT: &str = "in_search_root";

impl SearchRoots {
    /// The search roots `relative`, from the caller.
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
        Self::with_entries(
            relative
                .into_iter()
                .map(|relative| SearchRootEntry {
                    relative,
                    kind: RootKind::Search,
                    source: RootSource::Caller,
                })
                .collect(),
        )
    }

    /// The roots of `entries`, in their sequence, with the search roots
    /// before the project roots, so that no directory is walked twice.
    ///
    /// The comparisons ignore the case of ASCII letters. A root with the
    /// path of an earlier root is left out ([`REPEATED_ROOT`]), and so is
    /// a search root below another search root, and a project root that is
    /// a search root or is below one ([`IN_SEARCH_ROOT`]).
    /// [`SearchRoots::dropped`] has each root that is left out.
    ///
    /// # Errors
    ///
    /// Returns the first path that is not a plain relative path, or `None`
    /// when the list has more than [`MAX_SEARCH_ROOTS`] search roots or
    /// more than [`MAX_PROJECT_ROOTS`] project roots after the removals.
    pub fn with_entries(entries: Vec<SearchRootEntry>) -> Result<Self, Option<PathBuf>> {
        if let Some(entry) = entries
            .iter()
            .find(|entry| !is_plain_relative(&entry.relative))
        {
            return Err(Some(entry.relative.clone()));
        }
        let (search, projects): (Vec<SearchRootEntry>, Vec<SearchRootEntry>) = entries
            .into_iter()
            .partition(|entry| entry.kind == RootKind::Search);
        let same = |left: &Path, right: &Path| is_within(left, right) && is_within(right, left);
        let mut dropped: Vec<(SearchRootEntry, &'static str)> = Vec::new();
        let mut unique: Vec<SearchRootEntry> = Vec::new();
        for entry in search {
            if unique
                .iter()
                .any(|known| same(&known.relative, &entry.relative))
            {
                dropped.push((entry, REPEATED_ROOT));
            } else {
                unique.push(entry);
            }
        }
        let mut kept: Vec<SearchRootEntry> = Vec::new();
        for (index, entry) in unique.iter().enumerate() {
            let nested: bool = unique.iter().enumerate().any(|(other, known)| {
                other != index && is_within(&entry.relative, &known.relative)
            });
            if nested {
                dropped.push((entry.clone(), IN_SEARCH_ROOT));
            } else {
                kept.push(entry.clone());
            }
        }
        let searches: usize = kept.len();
        for entry in projects {
            if kept.iter().any(|known| {
                known.kind == RootKind::Search && is_within(&entry.relative, &known.relative)
            }) {
                dropped.push((entry, IN_SEARCH_ROOT));
            } else if kept
                .iter()
                .any(|known| same(&known.relative, &entry.relative))
            {
                dropped.push((entry, REPEATED_ROOT));
            } else {
                kept.push(entry);
            }
        }
        if searches > MAX_SEARCH_ROOTS || kept.len() - searches > MAX_PROJECT_ROOTS {
            return Err(None);
        }
        Ok(Self {
            entries: kept,
            dropped,
        })
    }

    /// The roots, in their sequence.
    #[must_use]
    pub fn entries(&self) -> &[SearchRootEntry] {
        &self.entries
    }

    /// The roots that the request left out, each with its reason.
    #[must_use]
    pub fn dropped(&self) -> &[(SearchRootEntry, &'static str)] {
        &self.dropped
    }

    /// Whether the request has no root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a root that the user names on the command line is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentRootError {
    /// The path is not absolute.
    NotAbsolute,
    /// The path has a `..` component.
    NotPlain,
    /// The path is not below the home directory, or it is the home
    /// directory.
    NotBelowHome,
    /// The path does not exist.
    NotFound,
    /// The object at the path is not a directory. A symbolic link is not a
    /// directory.
    NotDirectory,
}

impl ArgumentRootError {
    /// The stable name of the error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "search_root_not_absolute",
            Self::NotPlain => "search_root_not_plain",
            Self::NotBelowHome => "search_root_not_below_home",
            Self::NotFound => "search_root_not_found",
            Self::NotDirectory => "search_root_not_directory",
        }
    }
}

/// The path `path` with each `.` component removed, or `None` when it has a
/// `..` component. A `..` is not applied to the text: after a symbolic link
/// it names a different directory than the text shows, so the argument is
/// refused (fail closed).
fn without_current(path: &Path) -> Option<PathBuf> {
    let mut result: PathBuf = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return None,
            other => result.push(other),
        }
    }
    Some(result)
}

/// The search root of a `--root PATH` argument, relative to the home
/// directory `home` (with its symbolic links resolved).
///
/// `path` is absolute: the caller resolved a relative argument against the
/// invocation directory. A `.` component is removed, and a path with a
/// `..` component is refused. A path whose text is not below `home` is
/// compared again in its resolved form, so that `/var` and `/private/var`
/// name one directory. The root must be a directory below the home
/// directory; the walk then makes each check of a search root
/// (`docs/CLEANUP_RULES.md` section 4).
///
/// # Errors
///
/// Returns an [`ArgumentRootError`].
pub fn argument_root(path: &Path, home: &Path) -> Result<PathBuf, ArgumentRootError> {
    if !path.is_absolute() {
        return Err(ArgumentRootError::NotAbsolute);
    }
    let mut absolute: PathBuf = without_current(path).ok_or(ArgumentRootError::NotPlain)?;
    if !absolute.starts_with(home) {
        absolute = match fs::canonicalize(&absolute) {
            Ok(resolved) => resolved,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ArgumentRootError::NotFound);
            }
            Err(_) => return Err(ArgumentRootError::NotBelowHome),
        };
    }
    let relative: PathBuf = match absolute.strip_prefix(home) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.to_path_buf(),
        _ => return Err(ArgumentRootError::NotBelowHome),
    };
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() => Ok(relative),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ArgumentRootError::NotFound),
        // A symbolic link, another kind of object, or an object that cannot
        // be read.
        Ok(_) | Err(_) => Err(ArgumentRootError::NotDirectory),
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
    /// True when a distinctive directory of a layout with
    /// [`Unmarked::ManualOnly`] and no project marker is a unit of its
    /// unmarked layout name (`--allow-unmarked`), for a manual plan only.
    /// Each other check of the layout applies unchanged.
    pub allow_unmarked: bool,
}

/// The evidence of a unit of an unmarked layout name: the directory has no
/// project marker, and the request allowed it for a manual plan.
pub const PROJECT_MARKER_ABSENT_ALLOWED: &str = "project_marker_absent_allowed";

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
    /// The request left the root out, because another root of the request
    /// examines it ([`REPEATED_ROOT`] or [`IN_SEARCH_ROOT`]). It was not
    /// walked.
    Covered(&'static str),
}

/// The report of one search root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchRootReport {
    /// The path relative to the home directory, as the user named it.
    pub relative: PathBuf,
    /// The path, when the home directory is known.
    pub path: Option<PathBuf>,
    /// How the inspection examined the root.
    pub kind: RootKind,
    /// Where the root comes from.
    pub source: RootSource,
    /// The result.
    pub outcome: SearchRootOutcome,
    /// The directories below the root that could not be read.
    pub unreadable_directories: u64,
}

impl SearchRootReport {
    /// The report of `entry` with the outcome `outcome`, before the walk.
    #[must_use]
    pub fn of(entry: &SearchRootEntry, home: Option<&Path>, outcome: SearchRootOutcome) -> Self {
        Self {
            relative: entry.relative.clone(),
            path: home.map(|home| home.join(&entry.relative)),
            kind: entry.kind,
            source: entry.source.clone(),
            outcome,
            unreadable_directories: 0,
        }
    }
}

/// The evidence of Git for one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VersionControl {
    /// Git ignores the directory, and the index has no path in it.
    Ignored {
        /// What makes Git ignore the directory.
        basis: IgnoreBasis,
    },
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

/// What makes Git ignore a unit (`docs/CLEANUP_RULES.md` section 12,
/// "Version-control evidence").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnoreBasis {
    /// The ignore rules of a level above the unit ignore the directory.
    IgnoreRules,
    /// The unit has the file `.gitignore` of its producer with the first
    /// rule `*`, Git reports no untracked entry in it that it does not
    /// ignore, and its layout permits this evidence.
    OwnIgnoreFile,
}

/// The name of the ignore file of a unit.
const OWN_IGNORE_FILE: &str = ".gitignore";

/// The largest size of the ignore file of a unit that the check reads.
const MAX_OWN_IGNORE_FILE: u64 = 4 * 1024;

/// Whether the unit at `unit` has a regular file `.gitignore` at its top,
/// not a symbolic link, of at most [`MAX_OWN_IGNORE_FILE`] bytes, whose
/// first line that is not empty and is not a comment is exactly `*`.
pub(super) fn has_own_ignore_file(unit: &Path) -> bool {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // `O_NOFOLLOW` refuses a symbolic link at the last name; the type of
    // the open file is read from the descriptor.
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(unit.join(OWN_IGNORE_FILE))
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_OWN_IGNORE_FILE {
        return false;
    }
    let mut content: Vec<u8> = Vec::new();
    if file
        .take(MAX_OWN_IGNORE_FILE + 1)
        .read_to_end(&mut content)
        .is_err()
        || content.len() as u64 > MAX_OWN_IGNORE_FILE
    {
        return false;
    }
    content
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty() && !line.starts_with(b"#"))
        .is_some_and(|line| line == b"*")
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
    /// Each check before the measurement is satisfied, and the unit was not
    /// measured: the discovery for an eviction measures it
    /// ([`super::ProjectRequest`]). An inspection never gives this
    /// result.
    Checked,
}

/// The report of one generated directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectUnitReport {
    /// The path of the generated directory.
    pub path: PathBuf,
    /// The path of the root of the request whose walk found the unit.
    pub search_root: PathBuf,
    /// The project directory.
    pub project: PathBuf,
    /// The layout name: a layout of the catalog, the unmarked layout name of
    /// a layout of the catalog, or `user-configured`.
    pub layout: &'static str,
    /// [`PROJECT_MARKER_ABSENT_ALLOWED`] for a unit of an unmarked layout
    /// name, else `None`.
    pub marker_allowance: Option<&'static str>,
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
    /// The checkouts of Swift Package Manager and their pins, for a layout
    /// that has them and a project that gives the pins. The eviction
    /// discovery uses them for the exception of
    /// `docs/CLEANUP_RULES.md` section 6.
    #[serde(skip)]
    pub checkouts: Option<SwiftPmCheckouts>,
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
    /// The option `--allow-unmarked` of the request.
    allow_unmarked: bool,
    /// The path of each unit of the report, of each project of the
    /// inspection, with its layout name and the directory of its layout.
    /// The walk does not enter it, and a later unit that is, holds, or is
    /// in one of them is not a second unit.
    matched: BTreeMap<PathBuf, (&'static str, &'a str)>,
    directories: usize,
    units: Vec<ProjectUnitReport>,
    /// False for the discovery for an eviction: a unit that passes each
    /// check before the measurement is [`ProjectUnitOutcome::Checked`], and
    /// the discovery measures it.
    measure: bool,
    /// The root of the walk now.
    current_root: PathBuf,
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
    /// Whether the layout permits the evidence of an own ignore file.
    own_ignore_file: bool,
    owner_workflow: &'static str,
    rebuild_impact: &'static str,
    /// The quiet period of the layout, in place of the period of the host.
    quiet_period: Option<Nanoseconds>,
    /// The layout name of an unmarked unit, when the layout permits one.
    unmarked: Option<&'static str>,
    /// True for a layout of the configuration.
    configured: bool,
}

impl<'a> Layout<'a> {
    fn built_in(layout: &'a ProjectLayout) -> Self {
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
            own_ignore_file: layout.own_ignore_file,
            owner_workflow: layout.owner_workflow,
            rebuild_impact: layout.rebuild_impact,
            quiet_period: None,
            unmarked: match layout.unmarked {
                Unmarked::Never => None,
                Unmarked::ManualOnly { layout } => Some(layout),
            },
            configured: false,
        }
    }

    /// A layout of the configuration. Its name is generic: a directory with
    /// no marker is not listed. A marker that ends with `/` is a directory;
    /// each other marker is a regular file.
    fn configured(layout: &'a UserLayout) -> Self {
        Self {
            id: svalnir_core::rule::USER_CONFIGURED_LAYOUT,
            directory: &layout.directory,
            markers: layout
                .markers
                .iter()
                .map(|marker| match marker.strip_suffix('/') {
                    Some(directory) => (directory, MarkerKind::Directory),
                    None => (marker.as_str(), MarkerKind::File),
                })
                .collect(),
            inner_marker: layout.inner_marker.as_deref(),
            project_file: None,
            protected: layout.protected.iter().map(String::as_str).collect(),
            name: DirectoryName::Generic,
            checkouts: PackageCheckouts::None,
            reclaim: ReclaimBasis::AllocatedBytes,
            own_ignore_file: false,
            owner_workflow: USER_LAYOUT_WORKFLOW,
            rebuild_impact: USER_LAYOUT_IMPACT,
            // The validation bounds the period to 90 days, so it fits.
            quiet_period: layout
                .quiet_period
                .and_then(|period| Nanoseconds::try_from(period).ok()),
            unmarked: None,
            configured: true,
        }
    }

    /// The first name of the directory, which is an entry of the project
    /// directory. It can be a pattern.
    fn first_name(&self) -> &'a str {
        self.directory.split('/').next().unwrap_or(self.directory)
    }

    /// Whether the directory of the layout is `names`, the names of a
    /// directory relative to the project directory: the first name matches
    /// the first name of the layout, as a pattern or a literal, and each
    /// other name is the same.
    fn has_directory(&self, names: &[&OsStr]) -> bool {
        let parts: Vec<&str> = self.directory.split('/').collect();
        parts.len() == names.len()
            && parts
                .iter()
                .zip(names)
                .enumerate()
                .all(|(index, (part, name))| {
                    if index == 0 {
                        name_matches(part, name)
                    } else {
                        name.as_encoded_bytes() == part.as_bytes()
                    }
                })
    }
}

/// Whether the entry `name` of a project directory matches `part`, the
/// first name of the directory of a layout: the same bytes for a literal,
/// or a match with the case kept for a pattern. A pattern never matches a
/// name of the skip list of the walk ([`is_skipped`]).
fn name_matches(part: &str, name: &OsStr) -> bool {
    if is_pattern(part) {
        !is_skipped(name) && glob_matches(part.as_bytes(), name.as_encoded_bytes(), false)
    } else {
        name.as_encoded_bytes() == part.as_bytes()
    }
}

/// The layouts of `table`, then the layouts of `configured`.
fn catalog<'a>(table: &'a [ProjectLayout], configured: &'a [UserLayout]) -> Vec<Layout<'a>> {
    table
        .iter()
        .map(Layout::built_in)
        .chain(configured.iter().map(Layout::configured))
        .collect()
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
/// of `layout`. A marker of more than one name is a path below `project`:
/// each directory on its way is a directory of `principal`, not a symbolic
/// link, and its last name has the kind of the marker.
fn has_marker(
    principal: Uid,
    layout: &Layout<'_>,
    project: &Path,
    names: &BTreeSet<OsString>,
) -> bool {
    let is_kind = |name: &OsStr, kind: MarkerKind| {
        lstat(&project.join(name)).is_ok_and(|found| match kind {
            MarkerKind::File => found.kind == ObjectKind::RegularFile,
            MarkerKind::Directory => found.kind == ObjectKind::Directory,
        })
    };
    layout.markers.iter().any(|(marker, kind)| {
        if marker.contains('/') {
            is_marker_path(principal, project, marker, *kind)
        } else if is_pattern(marker) {
            names
                .iter()
                .filter(|name| glob_matches(marker.as_bytes(), name.as_encoded_bytes(), false))
                .any(|name| is_kind(name, *kind))
        } else {
            is_kind(OsStr::new(marker), *kind)
        }
    })
}

/// The largest number of names of a project marker path.
const MAX_MARKER_NAMES: usize = svalnir_core::config::MAX_MARKER_COMPONENTS;

/// Whether `marker`, a path of names below `project`, is an entry of the
/// kind `kind`, with each directory on its way a directory of `principal`
/// and not a symbolic link. A path of more than [`MAX_MARKER_NAMES`] names
/// is not a marker.
fn is_marker_path(principal: Uid, project: &Path, marker: &str, kind: MarkerKind) -> bool {
    let components: Vec<&str> = marker.split('/').collect();
    if components.len() > MAX_MARKER_NAMES {
        return false;
    }
    let mut path: PathBuf = project.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        if !is_plain_name(component) {
            return false;
        }
        path.push(component);
        let Ok(found) = lstat(&path) else {
            return false;
        };
        let is_last: bool = index + 1 == components.len();
        let expected: ObjectKind = match (is_last, kind) {
            (false, _) | (true, MarkerKind::Directory) => ObjectKind::Directory,
            (true, MarkerKind::File) => ObjectKind::RegularFile,
        };
        if found.kind != expected || (!is_last && found.owner != principal) {
            return false;
        }
    }
    true
}

/// Whether `name` is one name with no pattern: not empty, not `.` or `..`.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !is_pattern(name)
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

/// Whether one path is the other path or is below it, by component, with
/// the case of ASCII letters ignored: a volume that ignores case finds
/// `~/documents` for `~/Documents`, so the exclusion check fails closed.
fn overlaps(first: &Path, second: &Path) -> bool {
    is_within(first, second) || is_within(second, first)
}

/// Whether `path` is `directory` or is below it, by component, with the
/// case of ASCII letters ignored.
pub(super) fn is_within(path: &Path, directory: &Path) -> bool {
    let mut components = path.components();
    directory.components().all(|expected| {
        components.next().is_some_and(|found| {
            found
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(expected.as_os_str().as_encoded_bytes())
        })
    })
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
    // The comparison ignores the case of ASCII letters, and it is made
    // again with the stored names below.
    let is_excluded = |path: &Path| {
        user_exclusions
            .iter()
            .any(|excluded| is_within(path, excluded))
    };
    if is_excluded(path) {
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
    let stored: PathBuf = stored_case(path);
    if locations.of_text(&stored) != ProtectionFact::NotProtected {
        return Err(refused("root_protected"));
    }
    if is_excluded(&stored) {
        return Err(refused("root_excluded"));
    }
    Ok((stored, snapshot))
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
    /// Inspects the roots `roots` below the home directory.
    ///
    /// The function never fails as a whole: each root and each unit has its
    /// result.
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
        self.examine(host, roots, limits, cancel, clock, mounts, true)
    }

    /// The walk and the checks of the inspection. With `measure` false, a
    /// unit that passes each check before the measurement is
    /// [`ProjectUnitOutcome::Checked`] and is not measured.
    #[expect(
        clippy::too_many_arguments,
        reason = "the inspection and the discovery share one walk with these inputs"
    )]
    pub(super) fn examine(
        &self,
        host: ProjectHost<'_>,
        roots: &SearchRoots,
        limits: ProjectLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
        mounts: MountTableSource,
        measure: bool,
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
                .entries()
                .iter()
                .map(|entry| SearchRootReport::of(entry, home, SearchRootOutcome::Refused(reason)))
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
                    layouts: catalog(self.table(), host.layouts),
                    allow_unmarked: host.allow_unmarked,
                    matched: BTreeMap::new(),
                    directories: 0,
                    units: Vec::new(),
                    measure,
                    current_root: PathBuf::new(),
                };
                for entry in roots.entries() {
                    reports.push(inspector.root(entry));
                }
                units = inspector.units;
                reports.extend(roots.dropped().iter().map(|(entry, reason)| {
                    SearchRootReport::of(entry, Some(home), SearchRootOutcome::Covered(reason))
                }));
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
    fn root(&mut self, entry: &SearchRootEntry) -> SearchRootReport {
        let path: PathBuf = self.home.join(&entry.relative);
        let mut report: SearchRootReport =
            SearchRootReport::of(entry, Some(self.home), SearchRootOutcome::Absent);
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
        self.current_root.clone_from(&path);
        // One inventory for each root, with the root as its scope.
        let scope: UnitScope = UnitScope::new(&path);
        let inventory: PathInventory = self
            .host
            .processes
            .path_uses(self.host.principal, std::slice::from_ref(&scope));
        self.uses = Some((scope, inventory));
        let completion: SearchCompletion = match entry.kind {
            RootKind::Search => self.walk(&path, snapshot, &mut report),
            RootKind::Project => self.project_only(&path, &mut report),
        };
        report.outcome = SearchRootOutcome::Examined(completion);
        report
    }

    /// The units of the project directory `project` only: a project root
    /// is not a search root, so no directory below it is read.
    fn project_only(&mut self, project: &Path, report: &mut SearchRootReport) -> SearchCompletion {
        if let Some(stop) = self.stop() {
            return stop;
        }
        self.directories += 1;
        let Ok(entries) = fs::read_dir(project) else {
            report.unreadable_directories += 1;
            return SearchCompletion::Complete;
        };
        let names: BTreeSet<OsString> = entries
            .take(crate::rules::worktrees::MAX_DIRECTORY_ENTRIES)
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        self.project(project, project, &names);
        SearchCompletion::Complete
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
                if is_skipped(name) || self.matched.contains_key(&child) {
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
                        .any(|excluded| is_within(&child, excluded))
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
    /// present gives the unit ([`Inspector::choose`]). With no such layout,
    /// a distinctive name gives a unit that the checks refuse
    /// (`project_marker_missing`), or a unit of an unmarked layout name, and
    /// a generic name gives no unit.
    fn project(&mut self, project: &Path, root: &Path, names: &BTreeSet<OsString>) {
        // The directories of the layouts, relative to the project, in the
        // sequence of the layouts.
        let directories: Vec<PathBuf> = layout_directories(&self.layouts, names);
        for relative in directories {
            if self.stop().is_some() {
                return;
            }
            let path: PathBuf = project.join(&relative);
            let parts: Vec<&OsStr> = relative.iter().collect();
            // A path of two or three names needs its last name.
            if parts.len() > 1 && lstat(&path).is_err() {
                continue;
            }
            let Some((layout, unmarked)) = self.choose(project, names, &parts) else {
                continue;
            };
            // A directory that is a unit of an earlier project, for example
            // `P/var/cache` of `P` for the project `P/var`. With the same
            // layout it stays one unit; with another layout both claims are
            // refused, so that the checks of neither layout alone permit a
            // removal.
            if let Some(&(earlier, directory)) = self.matched.get(&path) {
                if (earlier, directory) != (layout.id, layout.directory) {
                    self.refuse_claimed(&path, project, &layout, unmarked, earlier);
                }
                continue;
            }
            let mut report: ProjectUnitReport = ProjectUnitReport {
                path: path.clone(),
                search_root: self.current_root.clone(),
                project: project.to_path_buf(),
                layout: unmarked.unwrap_or(layout.id),
                marker_allowance: unmarked.map(|_| PROJECT_MARKER_ABSENT_ALLOWED),
                protected_child: None,
                overlapping_layout: None,
                version_control: None,
                activity: None,
                uses: None,
                recency: None,
                outcome: ProjectUnitOutcome::Refused { reason: "" },
                owner_workflow: layout.owner_workflow,
                rebuild_impact: layout.rebuild_impact,
                checkouts: Self::checkouts_of(&layout, project, names, &path),
            };
            // One directory is never in two units: a unit that holds or is
            // in an earlier unit, of this project or of a project above it,
            // is refused, and only the earlier unit is measured.
            if let Some((_, (other, _))) =
                self.matched.iter().find(|(unit, _)| overlaps(unit, &path))
            {
                report.overlapping_layout = Some(other);
                report.outcome = ProjectUnitOutcome::Refused {
                    reason: "overlaps_unit",
                };
            } else {
                report.outcome = self.unit(&layout, project, root, names, &path, &mut report);
            }
            self.matched.insert(path, (layout.id, layout.directory));
            self.units.push(report);
        }
    }

    /// Refuses the unit at `path` of the earlier layout `earlier` and the
    /// later claim of `layout` for the project `project` with
    /// `overlaps_unit`.
    fn refuse_claimed(
        &mut self,
        path: &Path,
        project: &Path,
        layout: &Layout<'_>,
        unmarked: Option<&'static str>,
        earlier: &'static str,
    ) {
        let later: &'static str = unmarked.unwrap_or(layout.id);
        let refused = ProjectUnitOutcome::Refused {
            reason: "overlaps_unit",
        };
        if let Some(report) = self.units.iter_mut().find(|report| report.path == path) {
            report.overlapping_layout = Some(later);
            report.outcome = refused.clone();
        }
        self.units.push(ProjectUnitReport {
            path: path.to_path_buf(),
            search_root: self.current_root.clone(),
            project: project.to_path_buf(),
            layout: later,
            marker_allowance: unmarked.map(|_| PROJECT_MARKER_ABSENT_ALLOWED),
            protected_child: None,
            overlapping_layout: Some(earlier),
            version_control: None,
            activity: None,
            uses: None,
            recency: None,
            outcome: refused,
            owner_workflow: layout.owner_workflow,
            rebuild_impact: layout.rebuild_impact,
            checkouts: None,
        });
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
        let marker: MarkerCheck = if report.marker_allowance.is_some() {
            MarkerCheck::AbsenceAllowed
        } else {
            MarkerCheck::Required
        };
        unit_shape(self.host.principal, layout, project, names, path, marker).map_err(
            |(reason, child)| {
                report.protected_child = child;
                reason
            },
        )
    }
}

impl<'a> Inspector<'a> {
    /// The layout that gives the unit of the directory `parts` (relative to
    /// the project), and its unmarked layout name when the unit has no
    /// project marker and the request allows it.
    ///
    /// The first layout of the directory whose marker is present gives the
    /// unit. With no such layout, the first distinctive layout gives a unit
    /// that the checks refuse (`project_marker_missing`), or a unit of its
    /// unmarked layout name with `--allow-unmarked`. A generic name gives
    /// no unit. A name of the skip list of the walk, such as `.cache`, is a
    /// unit only of a layout of the table whose marker is present: with no
    /// marker it is not listed.
    fn choose(
        &self,
        project: &Path,
        names: &BTreeSet<OsString>,
        parts: &[&OsStr],
    ) -> Option<(Layout<'a>, Option<&'static str>)> {
        match choose_in(&self.layouts, self.host.principal, project, names, parts)? {
            Chosen::Marked(layout) => Some((layout.clone(), None)),
            Chosen::Distinctive(layout) => {
                let unmarked: Option<&'static str> =
                    layout.unmarked.filter(|_| self.allow_unmarked);
                Some((layout.clone(), unmarked))
            }
        }
    }
}

/// The layout of `layouts` that gives a unit of the directory `parts`
/// (relative to the project `project`, whose entries are `names`).
enum Chosen<'l, 'a> {
    /// The first layout of the directory whose marker is present.
    Marked(&'l Layout<'a>),
    /// No layout of the directory has its marker: the first distinctive
    /// layout of the directory.
    Distinctive(&'l Layout<'a>),
}

/// The choice of [`Inspector::choose`]: the first layout of the directory
/// whose marker is present, else the first distinctive layout. A name of
/// the skip list of the walk, such as `.cache`, has only a layout of the
/// table whose marker is present.
fn choose_in<'l, 'a>(
    layouts: &'l [Layout<'a>],
    principal: Uid,
    project: &Path,
    names: &BTreeSet<OsString>,
    parts: &[&OsStr],
) -> Option<Chosen<'l, 'a>> {
    let skipped: bool = parts.first().is_some_and(|first| is_skipped(first));
    let of_directory: Vec<&'l Layout<'a>> = layouts
        .iter()
        .filter(|layout| layout.has_directory(parts))
        .filter(|layout| !(skipped && layout.configured))
        .collect();
    if let Some(layout) = of_directory
        .iter()
        .find(|layout| has_marker(principal, layout, project, names))
    {
        return Some(Chosen::Marked(layout));
    }
    if skipped {
        return None;
    }
    of_directory
        .into_iter()
        .find(|layout| layout.name == DirectoryName::Distinctive)
        .map(Chosen::Distinctive)
}

/// The directories of the layouts of `layouts` in the directory whose
/// entries are `names`, relative to it, in the sequence of the layouts and
/// each one time. A pattern name is compared with the entries, so no
/// directory is read again.
fn layout_directories(layouts: &[Layout<'_>], names: &BTreeSet<OsString>) -> Vec<PathBuf> {
    let mut directories: Vec<PathBuf> = Vec::new();
    for layout in layouts {
        let first: &str = layout.first_name();
        for name in names.iter().filter(|name| name_matches(first, name)) {
            let mut relative: PathBuf = PathBuf::from(name);
            relative.extend(layout.directory.split('/').skip(1));
            if !directories.contains(&relative) {
                directories.push(relative);
            }
        }
    }
    directories
}

/// Whether the checks of a unit need the project marker of its layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerCheck {
    /// The directory that holds the unit has a marker of the layout.
    Required,
    /// The unit has an unmarked layout name: the request allowed a unit
    /// with no marker. Each other check applies.
    AbsenceAllowed,
}

/// The checks of the objects of one unit of `layout` at `path`, in the
/// project directory `project` whose entries are `names`: the directories
/// on the way, the unit, the project marker, the inner marker, and the
/// protected children. The error is the stable reason of the refusal, with
/// the protected child that the check found.
fn unit_shape(
    principal: Uid,
    layout: &Layout<'_>,
    project: &Path,
    names: &BTreeSet<OsString>,
    path: &Path,
    marker: MarkerCheck,
) -> Result<(), (&'static str, Option<PathBuf>)> {
    let plain = |reason: &'static str| Err((reason, None));
    let Ok(parent) = lstat(project) else {
        return plain("project_not_readable");
    };
    let Ok(relative) = path.strip_prefix(project) else {
        return plain("unit_path_not_plain");
    };
    // Each directory between the project and the unit, for a path of two
    // or three names, is a directory of the user on the same device, not a
    // symbolic link. No one of them is a unit.
    let mut between: PathBuf = project.to_path_buf();
    let mut components = relative.iter().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        between.push(component);
        match lstat(&between) {
            Ok(found)
                if found.kind == ObjectKind::Directory
                    && found.owner == principal
                    && found.object.device == parent.object.device => {}
            Ok(_) => return plain("unit_path_not_plain"),
            Err(_) => return plain("unit_not_readable"),
        }
    }
    let snapshot: ObjectSnapshot = match lstat(path) {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return plain("unit_absent"),
        Err(_) => return plain("unit_not_readable"),
    };
    match snapshot.kind {
        ObjectKind::Directory => {}
        ObjectKind::SymbolicLink => return plain("unit_symbolic_link"),
        _ => return plain("unit_not_directory"),
    }
    if snapshot.owner != principal {
        return plain("unit_owner");
    }
    if snapshot.object.device != parent.object.device {
        return plain("unit_device");
    }
    if marker == MarkerCheck::Required && !has_marker(principal, layout, project, names) {
        return plain("project_marker_missing");
    }
    if let Some(inner) = layout.inner_marker
        && !is_plain_file(path, inner)
    {
        return plain("unsupported_layout");
    }
    if let Some(file) = layout.project_file
        && !is_plain_file(project, file)
    {
        return plain("unsupported_layout");
    }
    match find_protected(path, &layout.protected) {
        ChildSearch::Clear => Ok(()),
        ChildSearch::Found(child) => Err(("protected_child", Some(child))),
        ChildSearch::Unknown => plain("protected_child_unknown"),
    }
}

impl Inspector<'_> {
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
            self.version_control(project, root, path, layout.own_ignore_file);
        report.version_control = Some(version_control.clone());
        match version_control {
            VersionControl::Ignored { .. } => {}
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
        if !self.measure {
            return ProjectUnitOutcome::Checked;
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

    /// The checkouts of Swift Package Manager and their pins for the unit
    /// at `path`, or `None` when the layout has none or no one package,
    /// workspace, or project gives the pins.
    fn checkouts_of(
        layout: &Layout<'_>,
        project: &Path,
        names: &BTreeSet<OsString>,
        path: &Path,
    ) -> Option<SwiftPmCheckouts> {
        match layout.checkouts {
            PackageCheckouts::None => None,
            PackageCheckouts::PackageBuild => SwiftPmCheckouts::of_package_build(path),
            PackageCheckouts::XcodeDerivedData => {
                SwiftPmCheckouts::of_xcode_project(path, &pin_container(project, names)?)
            }
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
        let checkouts: SwiftPmCheckouts = Self::checkouts_of(layout, project, names, path)?;
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
    /// and the repository when the lookup found one. With
    /// `own_ignore_file`, the layout permits the evidence of an own ignore
    /// file.
    fn version_control(
        &self,
        project: &Path,
        root: &Path,
        path: &Path,
        own_ignore_file: bool,
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
        let evidence: VersionControl = Self::ignored(git, &repository, path, own_ignore_file);
        (evidence, Some(repository))
    }

    /// The queries of [`Inspector::version_control`] for `repository`.
    fn ignored(
        git: &GitTool,
        repository: &Repository,
        path: &Path,
        own_ignore_file: bool,
    ) -> VersionControl {
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
            Ok(output) if output.code == 0 => {
                return VersionControl::Ignored {
                    basis: IgnoreBasis::IgnoreRules,
                };
            }
            Ok(output) if output.code == 1 => {}
            Ok(_) => return unknown("git_query_failed"),
            Err(failure) => return unknown(failure.as_str()),
        }
        // Git does not ignore the directory itself. A producer that writes
        // `.gitignore` with the first rule `*` in it makes Git ignore each
        // entry of it: the evidence needs that file and no untracked entry
        // in the unit that Git does not ignore.
        if !own_ignore_file || !has_own_ignore_file(path) {
            return VersionControl::NotIgnored;
        }
        let untracked: Result<GitOutput, GitFailure> = run(&[
            OsStr::new("ls-files"),
            OsStr::new("-z"),
            OsStr::new("--others"),
            OsStr::new("--exclude-standard"),
            OsStr::new("--"),
            &literal,
        ]);
        match untracked {
            Ok(output) if output.code == 0 && output.stdout.is_empty() && !output.truncated => {
                VersionControl::Ignored {
                    basis: IgnoreBasis::OwnIgnoreFile,
                }
            }
            Ok(output) if output.code == 0 => VersionControl::NotIgnored,
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

/// The result of the checks of a planned unit, made again immediately
/// before the step of an eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitRecheck {
    /// Each check is satisfied.
    Passed,
    /// A check refuses the unit. The name is a stable code.
    Refused(&'static str),
    /// The evidence of a check is not known. The name is a stable code.
    Unknown(&'static str),
    /// The unit is gone. The coordinator records it as a target that is
    /// already absent ([`UNIT_ABSENT`]), not as a skipped target.
    Absent,
}

/// The stable code of a unit that is gone at the check before its step.
pub const UNIT_ABSENT: &str = "unit_absent";

/// The inputs of [`recheck_unit`].
#[derive(Debug, Clone, Copy)]
pub struct RecheckInput<'a> {
    /// The user. The unit and each directory on its way must have this
    /// owner.
    pub principal: Uid,
    /// The layout that the sealed plan binds for the unit.
    pub layout: &'a str,
    /// The approved root of the unit: a search root or a project root.
    pub root: &'a Path,
    /// The unit.
    pub unit: &'a Path,
    /// The layouts of the configuration in effect.
    pub user_layouts: &'a [UserLayout],
    /// The build processes, read now.
    pub processes: &'a BuildProcesses,
    /// The monotonic time now, on the timeline of the processes.
    pub now: Option<MonotonicNanos>,
    /// The age after which the process evidence is not current.
    pub expiry: Nanoseconds,
    /// The Git executable that passed the checks, for the version-control
    /// evidence of a layout that permits an own ignore file. `None` when
    /// no executable passed them.
    pub git: Option<&'a GitTool>,
    /// The repositories that the sealed plan admits in the unit. The check
    /// runs the exception again and needs exactly this list
    /// (`docs/CLEANUP_RULES.md` section 6).
    pub admitted: &'a [AdmittedRepository],
}

/// Makes the checks of the unit `input.unit` of `project.dependency-directory`
/// again, immediately before the step of an eviction
/// (`docs/CLEANUP_RULES.md` section 12, "Manual eviction"): the unit has
/// the same layout (its project marker, with no earlier layout of the same
/// directory whose marker is now present, and its inner marker), it has no
/// entry at a protected path of the layout, and no build process of the
/// user works in its project.
///
/// For an unmarked layout name (it ends with
/// [`svalnir_core::rule::UNMARKED_LAYOUT_SUFFIX`]), the project must still
/// have no marker of a layout of the directory, and each other check of the
/// layout applies.
///
/// For a layout that permits the evidence of an own ignore file, the Git
/// queries of the inspection run again, because that evidence depends on
/// the entries of the unit. For each other layout, the Git evidence, the
/// project activity, and the measurement are not examined again here: the
/// use check of the coordinator and the walk of the executor examine the
/// unit before and during the removal.
#[must_use]
pub fn recheck_unit(input: &RecheckInput<'_>) -> UnitRecheck {
    recheck_unit_in(&PROJECT_LAYOUTS, input)
}

/// [`recheck_unit`] with the layouts of the table `table`.
pub(super) fn recheck_unit_in(table: &[ProjectLayout], input: &RecheckInput<'_>) -> UnitRecheck {
    match fs::symlink_metadata(input.unit) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return UnitRecheck::Absent,
        _ => {}
    }
    let layouts: Vec<Layout<'_>> = catalog(table, input.user_layouts);
    // A layout name of unmarked units names the layout of the table that
    // permits them.
    let unmarked: bool = input
        .layout
        .ends_with(svalnir_core::rule::UNMARKED_LAYOUT_SUFFIX);
    let names: Vec<&OsStr> = input.unit.iter().collect();
    let mut first: Option<UnitRecheck> = None;
    let mut found: bool = false;
    let bound = layouts.iter().filter(|layout| {
        if unmarked {
            layout.unmarked == Some(input.layout)
        } else {
            layout.id == input.layout
        }
    });
    for layout in bound {
        let count: usize = layout.directory.split('/').count();
        let Some(start) = names.len().checked_sub(count) else {
            continue;
        };
        let Some(parts) = names.get(start..) else {
            continue;
        };
        if !layout.has_directory(parts) {
            continue;
        }
        let Some(project) = (0..count).try_fold(input.unit, |path, _| path.parent()) else {
            continue;
        };
        found = true;
        let result: UnitRecheck = recheck_layout(input, &layouts, layout, project, parts, unmarked);
        if result == UnitRecheck::Passed {
            return result;
        }
        first.get_or_insert(result);
    }
    match first {
        Some(result) => result,
        // A layout of the configuration that the configuration in effect
        // does not have, for example after a change of the configuration.
        None if !found && input.layout == svalnir_core::rule::USER_CONFIGURED_LAYOUT => {
            UnitRecheck::Unknown("unit_layout_unknown")
        }
        None => UnitRecheck::Refused("unit_layout_changed"),
    }
}

/// The refusal of the check before a step from the version-control
/// evidence of the unit `input.unit` of the project `project`, made again
/// with the queries of the inspection. `None` when Git ignores the unit.
fn ignore_evidence(input: &RecheckInput<'_>, project: &Path) -> Option<UnitRecheck> {
    let unknown = Some(UnitRecheck::Unknown("version_control_unknown"));
    let Some(git) = input.git else {
        return unknown;
    };
    let Ok(mounts) = MountTable::read() else {
        return unknown;
    };
    let repository: Repository =
        match find_repository(project, input.root, input.principal, &mounts) {
            RepositoryLookup::Found(repository) => repository,
            RepositoryLookup::NotFound => return Some(UnitRecheck::Refused("no_repository")),
            RepositoryLookup::Unknown(_) => return unknown,
        };
    match Inspector::ignored(git, &repository, input.unit, true) {
        VersionControl::Ignored { .. } => None,
        VersionControl::NotIgnored => Some(UnitRecheck::Refused("not_ignored")),
        VersionControl::Tracked => Some(UnitRecheck::Refused("tracked_files")),
        VersionControl::NoRepository => Some(UnitRecheck::Refused("no_repository")),
        VersionControl::Unknown { .. } => unknown,
    }
}

/// The reading of the entries of the directory `directory`, bounded as the
/// walk is. `None` when it cannot be read completely.
fn directory_names(directory: &Path) -> Option<BTreeSet<OsString>> {
    let entries = fs::read_dir(directory).ok()?;
    let limit: usize = crate::rules::worktrees::MAX_DIRECTORY_ENTRIES;
    let mut names: BTreeSet<OsString> = BTreeSet::new();
    for entry in entries.take(limit + 1) {
        names.insert(entry.ok()?.file_name());
    }
    (names.len() <= limit).then_some(names)
}

/// The refusal of the check before a step when a unit that the walk finds
/// before the unit `input.unit` is, holds, or is in it, as the inspection
/// refuses it (`overlaps_unit`): a unit of a project directory between the
/// root and `project`, or a unit of `project` of an earlier directory of the
/// layouts. `None` when no such unit is there.
fn earlier_unit(
    input: &RecheckInput<'_>,
    layouts: &[Layout<'_>],
    project: &Path,
) -> Option<UnitRecheck> {
    let Ok(below) = project.strip_prefix(input.root) else {
        return Some(UnitRecheck::Unknown("unit_layout_unknown"));
    };
    // The project directories of the walk, from the root to `project`.
    let mut chain: Vec<PathBuf> = vec![input.root.to_path_buf()];
    for component in below {
        let next: PathBuf = chain
            .last()
            .map_or_else(PathBuf::new, |last| last.join(component));
        chain.push(next);
    }
    for directory in &chain {
        let Some(names) = directory_names(directory) else {
            return Some(UnitRecheck::Unknown("project_not_readable"));
        };
        let is_project: bool = directory.as_path() == project;
        for relative in layout_directories(layouts, &names) {
            let path: PathBuf = directory.join(&relative);
            if is_project && path == input.unit {
                break;
            }
            if !overlaps(&path, input.unit) {
                continue;
            }
            let parts: Vec<&OsStr> = relative.iter().collect();
            if parts.len() > 1 && lstat(&path).is_err() {
                continue;
            }
            if choose_in(layouts, input.principal, directory, &names, &parts).is_some() {
                return Some(UnitRecheck::Refused("overlaps_unit"));
            }
        }
    }
    // A project directory between `project` and the unit, such as `P/var`
    // for the unit `P/var/cache` of `P`, whose layouts give the same
    // directory a unit of another layout: the inspection refuses both
    // claims.
    let parent: &Path = input.unit.parent()?;
    for directory in parent.ancestors() {
        if directory == project || !directory.starts_with(project) {
            break;
        }
        let Some(names) = directory_names(directory) else {
            return Some(UnitRecheck::Unknown("project_not_readable"));
        };
        let Ok(relative) = input.unit.strip_prefix(directory) else {
            continue;
        };
        let parts: Vec<&OsStr> = relative.iter().collect();
        if choose_in(layouts, input.principal, directory, &names, &parts).is_some() {
            return Some(UnitRecheck::Refused("overlaps_unit"));
        }
    }
    None
}

/// The checks of [`recheck_unit`] for one layout and one project directory.
/// `parts` are the names of the unit relative to the project. With
/// `unmarked`, the plan binds the unmarked layout name of `layout`: a
/// marker of a layout of the directory that is now present makes the unit
/// a different kind of directory than at the plan.
fn recheck_layout(
    input: &RecheckInput<'_>,
    layouts: &[Layout<'_>],
    layout: &Layout<'_>,
    project: &Path,
    parts: &[&OsStr],
    unmarked: bool,
) -> UnitRecheck {
    let Ok(entries) = fs::read_dir(project) else {
        return UnitRecheck::Unknown("project_not_readable");
    };
    let limit: usize = crate::rules::worktrees::MAX_DIRECTORY_ENTRIES;
    let mut names: BTreeSet<OsString> = BTreeSet::new();
    for entry in entries.take(limit + 1) {
        let Ok(entry) = entry else {
            return UnitRecheck::Unknown("project_not_readable");
        };
        names.insert(entry.file_name());
    }
    if names.len() > limit {
        return UnitRecheck::Unknown("project_not_readable");
    }
    // The first layout of the directory whose marker is present gives the
    // unit. A different one now means that the unit is a different kind of
    // directory than at the plan. The comparison is of the entry of the
    // catalog, not of the layout name: each layout of the configuration has
    // the name `user-configured`, and only the first one whose marker is
    // present gives the unit.
    let chosen: Option<&Layout<'_>> = layouts
        .iter()
        .filter(|other| other.has_directory(parts))
        .find(|other| has_marker(input.principal, other, project, &names));
    let changed: bool = if unmarked {
        chosen.is_some()
    } else {
        chosen.is_some_and(|chosen| !std::ptr::eq(chosen, layout))
    };
    if changed {
        return UnitRecheck::Refused("unit_layout_changed");
    }
    if let Some(result) = earlier_unit(input, layouts, project) {
        return result;
    }
    let marker: MarkerCheck = if unmarked {
        MarkerCheck::AbsenceAllowed
    } else {
        MarkerCheck::Required
    };
    if let Err((reason, _)) =
        unit_shape(input.principal, layout, project, &names, input.unit, marker)
    {
        return match reason {
            UNIT_ABSENT => UnitRecheck::Absent,
            "project_not_readable" | "unit_not_readable" | "protected_child_unknown" => {
                UnitRecheck::Unknown(reason)
            }
            _ => UnitRecheck::Refused(reason),
        };
    }
    // The evidence of an own ignore file depends on the entries of the
    // unit, so the queries of the inspection run again: a unit that the
    // rules above it ignore passes with no own file, and a unit that its
    // own file ignores needs the file and no untracked entry that Git does
    // not ignore.
    if layout.own_ignore_file
        && let Some(result) = ignore_evidence(input, project)
    {
        return result;
    }
    let processes: &BuildProcesses = input.processes;
    if processes.blocking(project).is_some() {
        return UnitRecheck::Refused("producer_active");
    }
    if processes.above(project, input.root).is_some() {
        return UnitRecheck::Unknown("build_process_above_project");
    }
    if processes.incomplete.is_some() {
        return UnitRecheck::Unknown("activity_unknown");
    }
    let current: bool = processes
        .observed_at
        .zip(input.now)
        .and_then(|(observed, now)| now.checked_duration_since(observed))
        .is_some_and(|age| age <= input.expiry);
    if !current {
        return UnitRecheck::Unknown("activity_unknown");
    }
    // The clean checkouts of Swift Package Manager that the plan admits:
    // the checks run again and give exactly the sealed list.
    let checkouts: Option<SwiftPmCheckouts> =
        Inspector::checkouts_of(layout, project, &names, input.unit);
    // A layout with no checkouts admits no repository: the walk of the
    // check is not made for it, and the executor refuses each repository.
    let Some(checkouts) = checkouts else {
        return if input.admitted.is_empty() {
            UnitRecheck::Passed
        } else {
            UnitRecheck::Refused(REPOSITORY_CHANGED_CODE)
        };
    };
    match recheck_admitted(input.unit, Some(&checkouts), input.git, input.admitted) {
        RepositoryRecheck::Same => UnitRecheck::Passed,
        RepositoryRecheck::Refused(code) => UnitRecheck::Refused(code),
        RepositoryRecheck::Unknown(code) => UnitRecheck::Unknown(code),
    }
}
