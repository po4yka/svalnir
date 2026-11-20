//! The inspection of a cache rule: its roots, the measured size of each
//! unit, and the owner workflow.
//!
//! The inspection is read-only. It reads configuration files as text, the
//! mount table, and metadata, and the first bytes of one marker file of a
//! unit. It reads no other file content, runs no producer tool, and
//! changes nothing. It gives no candidate: each rule of this module has
//! the inspection mode only.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::ScanId;
use svalnir_core::observation::Coverage;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::rule::{LayoutSupport, RuleRef};

use super::config::{ConfigProblem, ConfigSource, ConfigValue, paths_of, read_source};
use super::{
    CacheRule, CacheSpec, ExclusionSpec, Location, Marker, PROJECT_MARKERS, ReclaimBasis, RootSpec,
    UnitSpec,
};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::protection::ProtectedLocations;
use crate::rules::eviction::{RootProblem, bind_root, refusal_name};
use crate::rules::model::{DiscoveryScope, RootBinding};
use crate::rules::unit::{
    ObjectKind, ObjectSnapshot, RecordRead, RootView, WalkStop, lstat, read_record, walk_local,
};
use crate::scan::{
    CancellationToken, NoObserver, ScanClock, ScanCompletion, ScanLimits, ScanRequest, ScanResult,
    run_scan,
};

/// The scan identity of a unit measurement. The result is not saved.
const INSPECTION_SCAN_ID: &str = "rule-cache-inspection";

/// The largest marker file that the inspection reads, in bytes.
const MAX_MARKER_BYTES: u64 = 4 * 1024;

/// The host facts of an inspection.
#[derive(Debug, Clone, Copy)]
pub struct InspectionHost<'a> {
    /// The user. Each root and each unit must have this owner.
    pub principal: Uid,
    /// The home directory and the state directory, resolved.
    pub locations: &'a ProtectedLocations,
    /// The paths of `[protections]` and of the disk guard exclusions. A
    /// unit that overlaps one is not measured.
    pub user_exclusions: &'a [PathBuf],
}

/// The bounds of the measurement of one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectionLimits {
    /// The largest number of entries that the scan of one unit examines.
    pub max_entries_per_unit: EntryCount,
    /// The deepest directory level below a unit that the scan reads.
    pub max_depth: u32,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_entries_per_unit: EntryCount::new(2_000_000),
            max_depth: 64,
        }
    }
}

/// How the path of a root was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootResolution {
    /// No configuration file below the home directory names a location,
    /// so the root is the documented default. A file outside the home
    /// directory, such as `/etc/homebrew/brew.env`, is not read. An environment variable of the shell of the
    /// user can name another location, and the inspection cannot see it.
    Default,
    /// A configuration file names the location.
    Configured {
        /// The configuration file.
        file: PathBuf,
        /// The key.
        key: &'static str,
    },
    /// A configuration file turns the cache off.
    Disabled {
        /// The configuration file.
        file: PathBuf,
        /// The key.
        key: &'static str,
    },
    /// The configuration gives no location that this build can use. The
    /// root has no path, and the default is not used in its place.
    NotResolved {
        /// The configuration file.
        file: PathBuf,
        /// The key.
        key: &'static str,
        /// The reason.
        problem: ConfigProblem,
    },
    /// The home directory of the user is not known.
    HomeUnknown,
    /// The mount table cannot be read, so no configuration file is read.
    MountTableUnavailable,
}

/// The result of one root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum RootOutcome {
    /// The checks passed, and each unit has its result.
    Examined,
    /// The directory does not exist. The producer is then not installed,
    /// has not made the cache, or uses another location. That is not an
    /// error.
    Absent,
    /// The root has no path ([`RootResolution`]).
    NoPath,
    /// The root failed a check. The reason is a stable name, for example
    /// `root_not_directory` for a symbolic link.
    Refused(&'static str),
}

/// The reclaim figure of a measured unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReclaimFigure {
    /// The allocated size of the unit. It is an upper estimate, not
    /// exclusive storage: APFS clones and snapshots can share it.
    AllocatedUpperBound {
        /// The allocated bytes.
        bytes: Bytes,
    },
    /// No figure. The producer links files from the cache into projects
    /// with hard links or clones, so the removal of a file whose content a
    /// project still has reclaims nothing for it. Neither the logical size
    /// nor the allocated size is the reclaim figure.
    NotKnownLinkedIntoProjects,
}

/// The measurement of one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheMeasurement {
    /// The sum of `st_size` of the files and the symbolic links. It is not
    /// a reclaim figure.
    pub logical_bytes: Bytes,
    /// The sum of `st_blocks * 512` of each object, an object with several
    /// hard links one time.
    pub allocated_bytes: Bytes,
    /// The regular files.
    pub files: EntryCount,
    /// The directories.
    pub directories: EntryCount,
    /// The symbolic links. A link is not followed.
    pub symlinks: EntryCount,
    /// Whether the scan read the full unit, stopped at its entry bound, or
    /// was cancelled.
    pub completion: ScanCompletion,
    /// Whether a region below the unit could not be measured.
    pub partial: bool,
    /// The reclaim figure.
    pub reclaim: ReclaimFigure,
}

/// The result of one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnitOutcome {
    /// The unit has the marker of its layout and was measured.
    Measured(CacheMeasurement),
    /// The unit does not exist.
    Absent,
    /// The unit exists and has no marker of a supported layout. It is not
    /// measured.
    UnsupportedLayout,
    /// The unit failed a check. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
    },
}

/// The report of one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheUnitReport {
    /// The path of the unit.
    pub path: PathBuf,
    /// The layout that the marker identifies.
    pub layout: &'static str,
    /// The result.
    pub outcome: UnitOutcome,
}

/// The report of one root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheRootReport {
    /// How the path was found.
    pub resolution: RootResolution,
    /// The path, when the resolution gives one.
    pub path: Option<PathBuf>,
    /// The result of the root.
    pub outcome: RootOutcome,
    /// The units, when the root was examined.
    pub units: Vec<CacheUnitReport>,
}

/// The inspection of one cache rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// The producer.
    pub producer: &'static str,
    /// Each layout of the declaration with its lifecycle state. Each
    /// layout of this build is `proposed`.
    pub layouts: Vec<LayoutSupport>,
    /// The roots, in the sequence of the declaration.
    pub roots: Vec<CacheRootReport>,
    /// The owner workflow, as a text for the user. Svalnir does not run
    /// it.
    pub owner_workflow: &'static str,
    /// The consequence of a removal.
    pub rebuild_impact: &'static str,
}

/// One location that a configuration file names, or the off value.
enum Configured {
    Path(PathBuf),
    Disabled,
}

/// Resolves the path of the root of `root` below `home`.
///
/// Each source is read. The first source with a problem ends the
/// resolution with no path. When no source names a location, the root is
/// the default. When the sources name more than one location, the root
/// has no path.
#[must_use]
pub fn resolve(
    root: &RootSpec,
    home: &Path,
    principal: Uid,
    mounts: &MountTable,
) -> (RootResolution, Option<PathBuf>) {
    let mut found: Vec<(&ConfigSource, Configured)> = Vec::new();
    for source in root.sources {
        let not_resolved = |problem: ConfigProblem| RootResolution::NotResolved {
            file: home.join(source.file),
            key: source.key,
            problem,
        };
        let raw: String = match read_source(source, home, principal, mounts) {
            ConfigValue::NotSet => continue,
            ConfigValue::Problem(problem) => return (not_resolved(problem), None),
            ConfigValue::Set(raw) => raw,
        };
        if root.disabled_value == Some(raw.as_str()) {
            found.push((source, Configured::Disabled));
            continue;
        }
        match paths_of(&raw, source, home) {
            Ok(paths) if paths.len() == 1 => {
                found.extend(
                    paths
                        .into_iter()
                        .map(|path| (source, Configured::Path(path))),
                );
            }
            Ok(_) => return (not_resolved(ConfigProblem::ValueNotSupported), None),
            Err(problem) => return (not_resolved(problem), None),
        }
    }
    let Some((first, value)) = found.first() else {
        return (RootResolution::Default, Some(home.join(root.default)));
    };
    let agrees: bool = found.iter().all(|(_, other)| match (value, other) {
        (Configured::Path(first), Configured::Path(other)) => first == other,
        (Configured::Disabled, Configured::Disabled) => true,
        _ => false,
    });
    let file: PathBuf = home.join(first.file);
    if !agrees {
        return (
            RootResolution::NotResolved {
                file,
                key: first.key,
                problem: ConfigProblem::Conflicting,
            },
            None,
        );
    }
    match value {
        Configured::Path(path) => (
            RootResolution::Configured {
                file,
                key: first.key,
            },
            Some(path.clone()),
        ),
        Configured::Disabled => (
            RootResolution::Disabled {
                file,
                key: first.key,
            },
            None,
        ),
    }
}

/// The excluded paths of `exclusion`: the default location and each
/// location that its configuration names. `None` when a configuration
/// file gives no value that this build can read, so the location is not
/// known.
fn excluded_paths(
    exclusion: &ExclusionSpec,
    home: &Path,
    principal: Uid,
    mounts: &MountTable,
) -> Option<Vec<PathBuf>> {
    let mut bases: Vec<PathBuf> = vec![match exclusion.default {
        Location::Home(relative) => home.join(relative),
        Location::Absolute(path) => PathBuf::from(path),
    }];
    for source in exclusion.sources {
        match read_source(source, home, principal, mounts) {
            ConfigValue::NotSet => {}
            ConfigValue::Problem(_) => return None,
            ConfigValue::Set(raw) => bases.extend(paths_of(&raw, source, home).ok()?),
        }
    }
    Some(
        bases
            .iter()
            .flat_map(|base| {
                exclusion.children.iter().map(move |child| {
                    if child.is_empty() {
                        base.clone()
                    } else {
                        base.join(child)
                    }
                })
            })
            .collect(),
    )
}

/// Whether one path is the other path or is below it, by component.
fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// Whether `directory` has an object with a name of [`PROJECT_MARKERS`].
fn has_project_marker(directory: &Path) -> bool {
    PROJECT_MARKERS
        .iter()
        .any(|marker| match lstat(&directory.join(marker)) {
            Ok(_) => true,
            // A name that cannot be examined can be a marker.
            Err(error) => error.kind() != io::ErrorKind::NotFound,
        })
}

/// Whether the root or a directory above it is a project directory. The
/// search stops below the home directory, or below `/` for a root outside
/// it: the home directory can be a repository of personal settings.
fn is_in_project(root: &Path, home: &Path) -> bool {
    root.ancestors()
        .take_while(|ancestor| *ancestor != home && ancestor.parent().is_some())
        .take_while(|ancestor| !home.starts_with(ancestor))
        .any(has_project_marker)
}

/// Whether the unit at `path` has the marker of its layout.
fn has_marker(path: &Path, marker: Marker, principal: Uid) -> bool {
    match marker {
        Marker::Directory => true,
        Marker::ChildDirectory(name) => {
            lstat(&path.join(name)).is_ok_and(|child| child.kind == ObjectKind::Directory)
        }
        Marker::FilePrefix { file, prefix } => {
            match read_record(&path.join(file), MAX_MARKER_BYTES, principal) {
                RecordRead::Read { bytes, .. } => bytes.starts_with(prefix),
                RecordRead::Absent | RecordRead::Denied | RecordRead::Invalid => false,
            }
        }
    }
}

/// The stable name of a stop of [`walk_local`].
fn walk_refusal(stop: &WalkStop) -> &'static str {
    match stop {
        WalkStop::Absent => RootProblem::Absent.as_str(),
        WalkStop::LinkInAncestor => "root_path_not_plain",
        WalkStop::NotLocal => "root_not_local",
        WalkStop::LocalityUnknown => "root_locality_unknown",
        WalkStop::Failed(_) => RootProblem::NotReadable.as_str(),
    }
}

/// The context of the inspection of one rule.
struct Inspector<'a> {
    spec: &'static CacheSpec,
    host: InspectionHost<'a>,
    home: &'a Path,
    limits: InspectionLimits,
    cancel: &'a CancellationToken,
    clock: &'a dyn ScanClock,
    mounts: MountTableSource,
}

impl CacheRule {
    /// Inspects each root of the rule.
    ///
    /// The function never fails as a whole: each root and each unit has
    /// its result. A cancelled inspection gives a measurement with the
    /// completion `cancelled` for the unit that the scan was reading.
    pub fn inspect(
        &self,
        host: InspectionHost<'_>,
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> CacheInspection {
        self.inspect_with_mounts(host, limits, cancel, clock, MountTable::read)
    }

    /// [`CacheRule::inspect`] with another source of the mount table.
    pub(crate) fn inspect_with_mounts(
        &self,
        host: InspectionHost<'_>,
        limits: InspectionLimits,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
        mounts: MountTableSource,
    ) -> CacheInspection {
        let spec: &'static CacheSpec = self.spec();
        let roots: Vec<CacheRootReport> = match host.locations.home_directory() {
            Some(home) => {
                let inspector: Inspector<'_> = Inspector {
                    spec,
                    host,
                    home,
                    limits,
                    cancel,
                    clock,
                    mounts,
                };
                spec.roots.iter().map(|root| inspector.root(root)).collect()
            }
            None => spec
                .roots
                .iter()
                .map(|_| CacheRootReport {
                    resolution: RootResolution::HomeUnknown,
                    path: None,
                    outcome: RootOutcome::NoPath,
                    units: Vec::new(),
                })
                .collect(),
        };
        CacheInspection {
            rule: self.rule().reference.clone(),
            producer: spec.producer,
            layouts: self.rule().layouts.clone(),
            roots,
            owner_workflow: spec.owner_workflow,
            rebuild_impact: spec.rebuild_impact,
        }
    }
}

impl Inspector<'_> {
    fn root(&self, root: &RootSpec) -> CacheRootReport {
        let Ok(mounts) = (self.mounts)() else {
            return CacheRootReport {
                resolution: RootResolution::MountTableUnavailable,
                path: None,
                outcome: RootOutcome::Refused("root_locality_unknown"),
                units: Vec::new(),
            };
        };
        let (resolution, path) = resolve(root, self.home, self.host.principal, &mounts);
        let Some(path) = path else {
            return CacheRootReport {
                resolution,
                path: None,
                outcome: RootOutcome::NoPath,
                units: Vec::new(),
            };
        };
        let (outcome, units) = match self.examine(root, &path, &mounts) {
            Ok(units) => (RootOutcome::Examined, units),
            Err(outcome) => (outcome, Vec::new()),
        };
        CacheRootReport {
            resolution,
            path: Some(path),
            outcome,
            units,
        }
    }

    /// The checks of the root at `path`, then the result of each unit.
    fn examine(
        &self,
        root: &RootSpec,
        path: &Path,
        mounts: &MountTable,
    ) -> Result<Vec<CacheUnitReport>, RootOutcome> {
        let refused = RootOutcome::Refused;
        // The text checks make no call on the root path. An exclusion can
        // read a configuration file, after its own walk of local
        // filesystems.
        match self.host.locations.of_text(path) {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => return Err(refused("root_protected")),
            ProtectionFact::Unknown => return Err(refused("root_protection_unknown")),
        }
        for exclusion in self.spec.exclusions {
            let Some(excluded) = excluded_paths(exclusion, self.home, self.host.principal, mounts)
            else {
                return Err(refused("exclusion_not_resolved"));
            };
            if excluded.iter().any(|entry| overlaps(path, entry)) {
                return Err(refused("root_overlaps_excluded"));
            }
        }
        // The walk examines each component from `/` on local filesystems
        // only, before `bind_root` makes a call on the path.
        match walk_local(path, mounts) {
            Ok(_) => {}
            Err(WalkStop::Absent) => return Err(RootOutcome::Absent),
            Err(stop) => return Err(refused(walk_refusal(&stop))),
        }
        let bound = bind_root(path).map_err(|problem| match problem {
            RootProblem::Absent => RootOutcome::Absent,
            other => refused(other.as_str()),
        })?;
        let binding: RootBinding = bound.binding;
        let protected: Vec<PathBuf> = self
            .host
            .locations
            .state_directory()
            .map(Path::to_path_buf)
            .into_iter()
            .collect();
        let scope: DiscoveryScope<'_> = DiscoveryScope {
            root: &binding,
            principal: self.host.principal,
            protected_paths: &protected,
            user_exclusions: self.host.user_exclusions,
        };
        let view: RootView =
            RootView::open(&scope, mounts).map_err(|error| refused(refusal_name(&error)))?;
        if is_in_project(path, self.home) {
            return Err(refused("root_in_project"));
        }
        let units: Vec<CacheUnitReport> = root
            .units
            .iter()
            .map(|unit| CacheUnitReport {
                path: if unit.relative.is_empty() {
                    path.to_path_buf()
                } else {
                    path.join(unit.relative)
                },
                layout: unit.layout,
                outcome: self.unit(&view, unit),
            })
            .collect();
        view.verify_unchanged()
            .map_err(|error| refused(refusal_name(&error)))?;
        Ok(units)
    }

    fn unit(&self, view: &RootView, unit: &UnitSpec) -> UnitOutcome {
        let refused = |reason: &'static str| UnitOutcome::Refused { reason };
        // A text comparison, before a call on a name in the unit.
        if view.is_excluded(Path::new(unit.relative)) {
            return refused("unit_excluded");
        }
        let path: PathBuf = if unit.relative.is_empty() {
            view.path.clone()
        } else {
            let path: PathBuf = view.path.join(unit.relative);
            let snapshot: ObjectSnapshot = match lstat(&path) {
                Ok(snapshot) => snapshot,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return UnitOutcome::Absent;
                }
                Err(_) => return refused("unit_not_readable"),
            };
            if snapshot.kind != ObjectKind::Directory {
                return refused("unit_not_directory");
            }
            if snapshot.owner != self.host.principal {
                return refused("unit_owner");
            }
            if snapshot.object.device != view.device() {
                return refused("unit_device");
            }
            if has_project_marker(&path) {
                return refused("unit_in_project");
            }
            path
        };
        if !has_marker(&path, unit.marker, self.host.principal) {
            return UnitOutcome::UnsupportedLayout;
        }
        match self.measure(&path) {
            Some(measurement) => UnitOutcome::Measured(measurement),
            None => refused("unit_not_readable"),
        }
    }

    /// Measures the unit at `path` with the read-only scanner.
    fn measure(&self, path: &Path) -> Option<CacheMeasurement> {
        let request: ScanRequest = ScanRequest {
            scan_id: ScanId::new(INSPECTION_SCAN_ID).ok()?,
            root: LosslessPath::from_path(path).ok()?,
            limits: ScanLimits {
                max_depth: self.limits.max_depth,
                max_entries: self.limits.max_entries_per_unit,
                max_largest_files: 0,
                max_largest_directories: 0,
                max_recorded_regions: 64,
                max_recorded_boundaries: 16,
                max_hard_link_objects: 100_000,
            },
            volume: None,
        };
        let result: ScanResult =
            run_scan(&request, self.cancel, self.clock, &mut NoObserver).ok()?;
        let totals = &result.totals;
        Some(CacheMeasurement {
            logical_bytes: totals.logical_bytes,
            allocated_bytes: totals.allocated_bytes,
            files: totals.files,
            directories: totals.directories,
            symlinks: totals.symlinks,
            completion: result.completion,
            partial: result.coverage != Coverage::Complete,
            reclaim: match self.spec.reclaim {
                ReclaimBasis::AllocatedBytes => ReclaimFigure::AllocatedUpperBound {
                    bytes: totals.allocated_bytes,
                },
                ReclaimBasis::LinkedIntoProjects => ReclaimFigure::NotKnownLinkedIntoProjects,
            },
        })
    }
}
