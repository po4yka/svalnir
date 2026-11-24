//! The rule `xcode.inactive-derived-data`.
//!
//! `docs/CLEANUP_RULES.md` section 11 owns the contract. The rule finds a
//! fixed generated subset of one identified project directory of a
//! `DerivedData` root. It removes nothing, and it never selects the root.
//! It selects a full project directory only for the layout
//! [`XCODE_ORPHAN_LAYOUT`], when the project of `WorkspacePath` is gone
//! (section 11, "Orphan project directories"); that layout is for a manual
//! eviction only.
//!
//! # Identification
//!
//! A project directory is recognized only when each of these is true:
//!
//! - It is a directory of the root, with the owner of the discovery, on
//!   the device of the root, and its name ends with `-` and 28 lower-case
//!   letters.
//! - It has a regular file `info.plist`, an XML property list whose root
//!   dictionary has the string `WorkspacePath` and the date
//!   `LastAccessedDate`.
//!
//! The name is a rejection hint only. The attribution to one project is
//! the `WorkspacePath` of `info.plist`. Each other layout is a skip with
//! the reason `unsupported_layout`. Apple documents the location of
//! `DerivedData` and that it holds indexes, logs, and build products. Apple
//! does not document `info.plist`, the name form, or the directories
//! below a project directory, so no Xcode version is confirmed from
//! documentation, and the layout is `proposed`.
//!
//! # Units
//!
//! The units of one project directory are the directories
//! [`UNIT_PATHS`]. Each one is a separate candidate. Logs, test results,
//! package checkouts, and each unknown child of a project directory are
//! never a unit. The module, symbol, and compilation caches at the root
//! are shared between projects and are never a unit.
//!
//! Each child of a unit must be on a fixed allow-list of the children that
//! the build system makes for that unit. Below `Build/Products`, that is a
//! directory of a configuration of [`BUILD_CONFIGURATIONS`] with a suffix of
//! [`PLATFORM_SUFFIXES`]; below `Build/Intermediates.noindex`, a directory
//! of [`INTERMEDIATES_CHILDREN`], a directory `NAME.build`, or a directory
//! `GeneratedModuleMaps` with a platform suffix; below `Index.noindex`, a
//! directory of [`INDEX_CHILDREN`]. Each unit also accepts the Finder file
//! `.DS_Store`. A unit with a child that the list does not
//! accept is skipped as a whole with the reason `unsupported_layout`: no
//! part of it is a candidate. The list is a first list from the public
//! knowledge of the Xcode build output. Promotion evidence from real Xcode
//! installations must confirm it before the layout leaves `proposed`.
//!
//! A unit with a debug-symbol bundle, an archive, archive intermediates,
//! a test result bundle, signing material, or a database is skipped as a
//! whole. This deny-list applies at each depth, also below an accepted
//! child. The one database that the rule accepts is the build database
//! `XCBuildData/build.db` of the build system.
//!
//! # What the rule can and cannot establish
//!
//! The rule establishes the identity and the owner of a unit, that the
//! project of `WorkspacePath` is present, the newest of the examined
//! times, that no other process holds an advisory lock on a build
//! database, that each child of the unit has a name and a type of the
//! allow-list, and the complete charge. The caller gives the evidence of
//! the producer processes. The rule cannot see a writer that takes no
//! lock, an open file of another process, a build in a directory that it
//! did not examine, or a file that a person put below an accepted child
//! with a name that the deny-list does not have.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{RuleId, RuleRevisionId};
use svalnir_core::policy::{ActivityFact, RebuildCost};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, Fact, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::git::{GitTool, GitToolProblem};
use super::model::{
    DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError,
    DiscoveryMode, DiscoveryScope, SkipReason,
};
use super::native::is_locked_by_another_process;
use super::nested_git::{RepositoryPolicy, SwiftPmCheckouts};
use super::plist::{ProjectInfo, parse_project_info};
use super::registry::RegistryError;
use super::unit::{
    Assessment, Collector, ObjectKind, ObjectSnapshot, RecordRead, RootView, UnitUnderMeasurement,
    WalkStop, check_known, elapsed_between, establish_charge, is_plain_absolute, list_root, lstat,
    read_record, reason_of, target_evidence, walk_local,
};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::scan::EntryKind;

/// The identity of the rule.
pub const XCODE_DERIVED_DATA_RULE_ID: &str = "xcode.inactive-derived-data";

/// The implementation revision of the rule in this build. Revision `r2`
/// added the layout [`XCODE_ORPHAN_LAYOUT`]. Revision `r3` admits the clean
/// clones of Swift Package Manager in the unit of that layout.
pub const XCODE_DERIVED_DATA_REVISION: &str = "r3";

/// The layout of the generated subset of a project directory whose project
/// is present.
pub const XCODE_DERIVED_DATA_LAYOUT: &str = "derived-data-project-v1";

/// The layout of a whole project directory whose project is gone: the
/// `WorkspacePath` of its `info.plist` names a path that does not exist on
/// a mounted volume. The layout is for a manual eviction only: no
/// lifecycle state, also a fixture state, permits an automatic eviction
/// of it, and the discovery for an automatic eviction gives none of its
/// units.
pub const XCODE_ORPHAN_LAYOUT: &str = "derived-data-orphan-v1";

/// The units of one project directory, relative to it.
pub const UNIT_PATHS: [&str; 3] = [
    "Build/Intermediates.noindex",
    "Build/Products",
    "Index.noindex",
];

/// The configurations whose directories the rule accepts below
/// `Build/Products`: the two configurations of a new Xcode project. A
/// configuration name is free text in a project, so each other name is
/// not known to be build output.
pub const BUILD_CONFIGURATIONS: [&str; 2] = ["Debug", "Release"];

/// The values of the build setting `EFFECTIVE_PLATFORM_NAME` that the rule
/// accepts as the suffix of a configuration directory. A macOS build has
/// no suffix.
pub const PLATFORM_SUFFIXES: [&str; 11] = [
    "",
    "-iphoneos",
    "-iphonesimulator",
    "-appletvos",
    "-appletvsimulator",
    "-watchos",
    "-watchsimulator",
    "-xros",
    "-xrsimulator",
    "-maccatalyst",
    "-driverkit",
];

/// The fixed directory names of `Build/Intermediates.noindex`. The rule also
/// accepts a directory `NAME.build` (the intermediates of one project) and
/// `GeneratedModuleMaps` with a suffix of [`PLATFORM_SUFFIXES`].
pub const INTERMEDIATES_CHILDREN: [&str; 4] = [
    "XCBuildData",
    "PrecompiledHeaders",
    "ExplicitPrecompiledModules",
    "SwiftExplicitPrecompiledModules",
];

/// The directory names of `Index.noindex`: the index store, the build of
/// the indexer, and its precompiled headers.
pub const INDEX_CHILDREN: [&str; 3] = ["DataStore", "Build", "PrecompiledHeaders"];

/// The one file that the rule accepts as a child of each unit: the view
/// settings that Finder writes in a directory that a person opened. It has
/// no content of the user.
const FINDER_METADATA: &str = ".DS_Store";

/// The prefix of the module map directories of `Build/Intermediates.noindex`.
const GENERATED_MODULE_MAPS: &str = "GeneratedModuleMaps";

/// The entries of a `DerivedData` root that more than one project uses. No
/// one of them is a unit.
pub const SHARED_ROOT_ENTRIES: [&str; 4] = [
    "ModuleCache.noindex",
    "SDKStatCaches.noindex",
    "SymbolCache.noindex",
    "CompilationCache.noindex",
];

/// The executable names of the producer: Xcode, its build service, the
/// command-line build, the indexer, and the test runner. A process with
/// one of these names makes the producer active. A name never makes a
/// process or a directory a target.
pub const XCODE_PRODUCER_EXECUTABLES: [&str; 9] = [
    "Xcode",
    "xcodebuild",
    "XCBBuildService",
    "SWBBuildService",
    "swift-build",
    "SourceKitService",
    "sourcekit-lsp",
    "xctest",
    "XCTRunner",
];

/// The build databases of one project directory, relative to it. The
/// build system holds a lock on its database during a build.
const BUILD_DATABASES: [&str; 2] = [
    "Build/Intermediates.noindex/XCBuildData/build.db",
    "Index.noindex/Build/Intermediates.noindex/XCBuildData/build.db",
];

/// The suffixes of the files that SQLite keeps next to a database during
/// a transaction or while a connection is open.
const DATABASE_SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];

const INFO_PLIST: &str = "info.plist";

/// The largest size of `info.plist`, in bytes.
const MAX_INFO_PLIST_BYTES: u64 = 64 * 1024;

/// The number of lower-case letters at the end of a project directory
/// name.
const NAME_HASH_LENGTH: usize = 28;

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// Whether a process of the producer runs, from the process inventory of
/// the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerProcesses {
    /// The inventory is absent, stale, or not complete. No unit is known
    /// to be inactive.
    Unknown,
    /// A process of the producer runs.
    Running,
    /// A complete and current inventory of the processes of the user has
    /// no process of the producer.
    NotRunning,
}

impl ProducerProcesses {
    /// The evidence of a complete and current inventory, from the file
    /// names of the executables of the user.
    pub fn from_complete_inventory<'a>(executables: impl IntoIterator<Item = &'a str>) -> Self {
        let mut is_empty: bool = true;
        let mut runs: bool = false;
        for name in executables {
            is_empty = false;
            runs = runs || XCODE_PRODUCER_EXECUTABLES.contains(&name);
        }
        if runs {
            Self::Running
        } else if is_empty {
            // A complete inventory has the process of the caller. An
            // inventory with no process is a failed query, not evidence.
            Self::Unknown
        } else {
            Self::NotRunning
        }
    }
}

/// The evidence that the rule takes from the caller.
#[derive(Debug, Clone, Copy)]
pub struct XcodeEvidence {
    /// Whether a process of the producer runs.
    pub producer_processes: ProducerProcesses,
    /// The time of the process inventory, on the monotonic timeline of the
    /// clock of the discovery ([`DiscoveryControl::clock`]). The rule
    /// compares it with the time of the assessment of each unit: evidence
    /// that is older than `evidence_expiry` of the rule does not show that
    /// no process of the producer runs.
    pub observed_at: MonotonicNanos,
}

impl XcodeEvidence {
    /// The process evidence at `now`, the monotonic time of the assessment
    /// of one unit. [`ProducerProcesses::NotRunning`] is evidence of
    /// inactivity only for `expiry` after its observation. After that time,
    /// with no monotonic time, or with a time before the observation (a
    /// different clock domain or boot), the result is
    /// [`ProducerProcesses::Unknown`]. The other two values permit no
    /// candidate, so they do not expire.
    fn processes_at(self, now: Option<MonotonicNanos>, expiry: Nanoseconds) -> ProducerProcesses {
        if self.producer_processes != ProducerProcesses::NotRunning {
            return self.producer_processes;
        }
        let age: Option<Nanoseconds> =
            now.and_then(|now| now.checked_duration_since(self.observed_at));
        match age {
            Some(age) if age <= expiry => ProducerProcesses::NotRunning,
            _ => ProducerProcesses::Unknown,
        }
    }
}

/// The lock query of a build database.
type LockProbe = fn(&File) -> io::Result<bool>;

/// The rule `xcode.inactive-derived-data`.
#[derive(Debug, Clone)]
pub struct XcodeDerivedDataRule {
    rule: Rule,
    lock_probe: LockProbe,
    mounts: MountTableSource,
}

/// The declaration of the revision of this build. Each layout is
/// `proposed`: no validation record exists for the rule.
fn declaration() -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(XCODE_DERIVED_DATA_RULE_ID)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(XCODE_DERIVED_DATA_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: "xcode".to_owned(),
            attribution: OwnerAttribution::ProducerIndex,
        },
        layouts: vec![
            LayoutSupport {
                layout: XCODE_DERIVED_DATA_LAYOUT.to_owned(),
                lifecycle: LifecycleState::Proposed,
            },
            LayoutSupport {
                layout: XCODE_ORPHAN_LAYOUT.to_owned(),
                lifecycle: LifecycleState::Proposed,
            },
        ],
        roots: vec![ApprovedRoot {
            base: RootBase::ProducerConfiguration,
            relative: path("Library/Developer/Xcode/DerivedData")?,
        }],
        retention: Retention {
            age_basis: AgeBasis::ProducerIndex,
            minimum_age: Nanoseconds::new(14 * DAY),
        },
        activity: ActivityProtocol {
            checks: vec![
                ActivityCheck::ProducerLock,
                ActivityCheck::ProducerProcessAbsent,
            ],
            quiescence: Nanoseconds::new(DAY),
            evidence_expiry: Nanoseconds::new(30_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: SHARED_ROOT_ENTRIES
                .iter()
                .map(|entry| path(entry))
                .collect::<Result<Vec<LosslessPath>, RegistryError>>()?,
            supported_object_types: vec![
                FileObjectType::RegularFile,
                FileObjectType::Directory,
                FileObjectType::SymbolicLink,
            ],
            skip_hard_linked: true,
        },
        modes: vec![
            RuleMode::Inspection,
            RuleMode::ManualEviction,
            RuleMode::AutomaticEviction,
        ],
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::Medium,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(20 * GIBIBYTE), EntryCount::new(500_000)),
            per_pass: WorkCharge::new(Bytes::new(50 * GIBIBYTE), EntryCount::new(1_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// Whether `name` has the form of a project directory name: a stem, `-`,
/// and 28 lower-case letters.
fn has_project_name_form(name: &Path) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.rsplit_once('-').is_some_and(|(stem, hash)| {
        !stem.is_empty()
            && hash.len() == NAME_HASH_LENGTH
            && hash.bytes().all(|byte| byte.is_ascii_lowercase())
    })
}

/// Whether `relative`, a path below the unit `unit`, is a build database
/// of [`BUILD_DATABASES`] or one of its SQLite files. A file with the same
/// name at another place is not the reviewed exception.
fn is_build_database(unit: &Path, relative: &Path) -> bool {
    let Some(name) = relative.to_str() else {
        return false;
    };
    BUILD_DATABASES
        .iter()
        .filter_map(|database| Path::new(database).strip_prefix(unit).ok()?.to_str())
        .any(|database| {
            name.strip_prefix(database)
                .is_some_and(|suffix| suffix.is_empty() || DATABASE_SIDECARS.contains(&suffix))
        })
}

/// Whether `name` is one of `prefixes` followed by a suffix of
/// [`PLATFORM_SUFFIXES`].
fn has_platform_form(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|suffix| PLATFORM_SUFFIXES.contains(&suffix))
    })
}

/// Whether the allow-list of the unit `unit` accepts the child `name` of
/// the type `kind`. The comparison is exact: another case or another
/// spelling is not a name that the build system makes.
fn is_known_child(unit: &Path, name: &str, kind: EntryKind) -> bool {
    if name == FINDER_METADATA {
        return kind == EntryKind::File;
    }
    if kind != EntryKind::Directory {
        return false;
    }
    match unit.to_str() {
        Some("Build/Products") => has_platform_form(name, &BUILD_CONFIGURATIONS),
        Some("Build/Intermediates.noindex") => {
            INTERMEDIATES_CHILDREN.contains(&name)
                || has_platform_form(name, &[GENERATED_MODULE_MAPS])
                || name
                    .strip_suffix(".build")
                    .is_some_and(|stem| !stem.is_empty())
        }
        Some("Index.noindex") => INDEX_CHILDREN.contains(&name),
        _ => false,
    }
}

/// The reason an entry below a unit prevents a candidate.
///
/// A child of the unit must be on the allow-list of [`is_known_child`]:
/// another child gives `unsupported_layout`. Each entry, at each depth, is
/// then compared with a deny-list of names. A name is a rejection hint
/// only: an entry with no such name is not shown to be disposable.
fn classify_entry(unit: &Path, relative: &Path, kind: EntryKind) -> Option<SkipReason> {
    if let Some(reason) = deny_listed(unit, relative) {
        return Some(reason);
    }
    // A child of the unit, which is a path of one component.
    let is_child: bool = relative.parent() == Some(Path::new(""));
    let is_known: bool = relative
        .to_str()
        .is_some_and(|child| is_known_child(unit, child, kind));
    (is_child && !is_known).then_some(SkipReason::UnsupportedLayout)
}

/// The reason of the deny-list of names for an entry at `relative` below
/// the unit `unit` (an empty path for a whole project directory), at each
/// depth: a debug-symbol bundle, an archive, a test result bundle, signing
/// material, an installer, or a database that is not a build database.
fn deny_listed(unit: &Path, relative: &Path) -> Option<SkipReason> {
    const PRESERVED_SUFFIXES: [&str; 17] = [
        ".dsym",
        ".xcarchive",
        ".xcresult",
        ".mobileprovision",
        ".provisionprofile",
        ".p12",
        ".cer",
        ".pem",
        ".key",
        ".keychain",
        ".keychain-db",
        ".p8",
        ".pfx",
        ".der",
        ".ipa",
        ".pkg",
        ".dmg",
    ];
    const DATABASE_SUFFIXES: [&str; 12] = [
        ".sqlite",
        ".sqlite3",
        ".db",
        ".sqlite-wal",
        ".sqlite-shm",
        ".db-wal",
        ".db-shm",
        ".db-journal",
        ".sqlite-journal",
        ".realm",
        ".mdb",
        ".storedata",
    ];
    // A name that is not UTF-8 has no form that the rule knows.
    let Some(name) = relative.file_name()?.to_str() else {
        return Some(SkipReason::ProtectedData);
    };
    let name: String = name.to_ascii_lowercase();
    let has_suffix = |suffixes: &[&str]| suffixes.iter().any(|suffix| name.ends_with(suffix));
    let is_preserved: bool = has_suffix(&PRESERVED_SUFFIXES)
        || name == "archiveintermediates"
        || (has_suffix(&DATABASE_SUFFIXES) && !is_build_database(unit, relative));
    is_preserved.then_some(SkipReason::ProtectedData)
}

/// The lock state of the build databases of one project directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockState {
    /// The rule examined one build database or more, and no one has a
    /// lock that the query sees or an SQLite file of a transaction.
    Free,
    /// A build database is in use.
    Held,
    /// A query failed, a build database is not a plain file in plain
    /// directories, or the project has no build database to examine.
    Unknown,
}

/// What the rule knows about one recognized project directory.
#[derive(Debug)]
struct Project {
    /// The project directory, relative to the root.
    relative: PathBuf,
    snapshot: ObjectSnapshot,
    info: ProjectInfo,
    info_bytes: Vec<u8>,
    info_snapshot: ObjectSnapshot,
    /// Predicate 4, with the reason when it is not satisfied.
    regenerable: (Fact, Option<SkipReason>),
    /// Whether the project of `WorkspacePath` and the root overlap.
    /// `None`: the path has a symbolic link, so its text does not show
    /// the location of the project.
    overlaps_source: Option<bool>,
    /// Whether the project of `WorkspacePath` is gone, for the layout
    /// [`XCODE_ORPHAN_LAYOUT`].
    gone: WorkspaceGone,
}

/// Whether the project that `WorkspacePath` names is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkspaceGone {
    /// The path is a plain absolute path on a local filesystem, each
    /// component up to a missing one is a directory with no symbolic link,
    /// and the path is not on a volume of `/Volumes` that is not mounted.
    Gone,
    /// The project is present.
    Present,
    /// The rule cannot show that the project is gone: the path is on a
    /// volume of `/Volumes` that is not mounted, on a filesystem that is not
    /// local, has a symbolic link, or cannot be examined.
    Unknown,
}

/// Whether `path` is below `/Volumes/NAME` and no mount of `mounts` has the
/// mount point `/Volumes/NAME`: the volume of an external or a network disk
/// that is not connected. A path on such a volume is not gone.
pub(super) fn is_on_unmounted_volume(path: &Path, mounts: &MountTable) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let mut components = path.components();
    let (Some(std::path::Component::RootDir), Some(volumes), Some(name)) =
        (components.next(), components.next(), components.next())
    else {
        return false;
    };
    if volumes.as_os_str() != "Volumes" {
        return false;
    }
    let mut point: Vec<u8> = b"/Volumes/".to_vec();
    point.extend_from_slice(name.as_os_str().as_bytes());
    !mounts
        .mounts()
        .iter()
        .any(|mount| mount.mount_point.as_slice() == point.as_slice())
}

/// Whether the project at `workspace`, a `WorkspacePath`, is gone.
pub(super) fn workspace_gone(workspace: &Path, mounts: &MountTable) -> WorkspaceGone {
    if !is_plain_absolute(workspace) || is_on_unmounted_volume(workspace, mounts) {
        return WorkspaceGone::Unknown;
    }
    match walk_local(workspace, mounts) {
        Err(WalkStop::Absent) => WorkspaceGone::Gone,
        Ok(_) => WorkspaceGone::Present,
        Err(_) => WorkspaceGone::Unknown,
    }
}

/// The assessment of one unit, or the bound that stopped it.
enum Outcome {
    Assessed(Box<Assessment>),
    Absent,
    Stopped(DiscoveryCompletion),
}

impl XcodeDerivedDataRule {
    /// Makes the rule with the declaration of this build.
    pub(super) fn new() -> Result<Self, RegistryError> {
        Self::with_lock_probe(is_locked_by_another_process)
    }

    /// Makes the rule with a lock query. A test gives a query with a
    /// fixed result.
    pub(super) fn with_lock_probe(lock_probe: LockProbe) -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration()?).map_err(RegistryError::Incomplete)?;
        Ok(Self {
            rule,
            lock_probe,
            mounts: MountTable::read,
        })
    }

    /// The rule with another source of the mount table. A test gives a
    /// table with a filesystem that is not local.
    #[cfg(test)]
    pub(super) fn with_mount_table(self, mounts: MountTableSource) -> Self {
        Self { mounts, ..self }
    }

    /// The rule with `lifecycle` for each layout. Only a test build has
    /// this function ([`super::ReviewedRules::with_fixture_lifecycle`]).
    /// The layout [`XCODE_ORPHAN_LAYOUT`] gets at most
    /// [`LifecycleState::ManualActionValidated`]: it has no automatic mode.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_lifecycle(self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        let rule: Rule = super::registry::with_lifecycle(&self.rule, lifecycle)?;
        let mut declaration: RuleDeclaration = (*rule).clone();
        for layout in &mut declaration.layouts {
            if layout.layout != XCODE_ORPHAN_LAYOUT {
                continue;
            }
            if let LifecycleState::AutomaticEvictionValidated { evidence } = &layout.lifecycle {
                layout.lifecycle = LifecycleState::ManualActionValidated {
                    evidence: evidence.clone(),
                };
            }
        }
        Ok(Self {
            rule: Checked::new(declaration).map_err(RegistryError::Incomplete)?,
            ..self
        })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// Finds the candidates of the `DerivedData` root of `scope`.
    ///
    /// The discovery reads the mount table, metadata, and `info.plist`,
    /// opens each build database for a lock query, and reads the metadata
    /// of the project of `WorkspacePath` when the mount table reports its
    /// path as local. It changes nothing. With
    /// [`DiscoveryMode::KnownCandidatesOnly`] it lists no directory and
    /// measures no tree.
    ///
    /// # Errors
    ///
    /// Returns a [`DiscoveryError`] when a limit is too large, when the
    /// root fails a check (also when it is not on a local filesystem), when
    /// the root changed during the discovery, or when a known candidate
    /// belongs to another rule revision or root.
    pub fn discover(
        &self,
        scope: &DiscoveryScope<'_>,
        evidence: XcodeEvidence,
        mode: DiscoveryMode<'_>,
        control: &DiscoveryControl<'_>,
    ) -> Result<Discovery, DiscoveryError> {
        self.discover_with(scope, evidence, mode, control, &mut |_| {})
    }

    /// [`XcodeDerivedDataRule::discover`] with a function that runs after
    /// the measurement of each unit and before its evidence snapshot.
    pub(super) fn discover_with(
        &self,
        scope: &DiscoveryScope<'_>,
        evidence: XcodeEvidence,
        mode: DiscoveryMode<'_>,
        control: &DiscoveryControl<'_>,
        after_measurement: &mut dyn FnMut(&Path),
    ) -> Result<Discovery, DiscoveryError> {
        let mut collector: Collector<'_> = Collector::new(control)?;
        let mounts: MountTable =
            (self.mounts)().map_err(|_| DiscoveryError::RootLocalityUnknown)?;
        let root: RootView = RootView::open(scope, &mounts)?;
        let mut context = UnitContext {
            rule: self,
            root: &root,
            mounts: &mounts,
            scope,
            evidence,
            after_measurement,
        };
        let completion: DiscoveryCompletion = match mode {
            DiscoveryMode::Full => context.discover_full(&mut collector)?,
            DiscoveryMode::KnownCandidatesOnly(known) => {
                let known: &[DiscoveredCandidate] = check_known(&self.rule, &root, control, known)?;
                context.discover_known(known, &mut collector)?
            }
        };
        collector.finish(&self.rule, &root, completion)
    }
}

/// The inputs of the assessment of each unit of one discovery.
struct UnitContext<'a> {
    rule: &'a XcodeDerivedDataRule,
    root: &'a RootView,
    /// The mount table of the discovery, for the project path of each
    /// `info.plist`.
    mounts: &'a MountTable,
    scope: &'a DiscoveryScope<'a>,
    evidence: XcodeEvidence,
    after_measurement: &'a mut dyn FnMut(&Path),
}

impl UnitContext<'_> {
    fn discover_full(
        &mut self,
        collector: &mut Collector<'_>,
    ) -> Result<DiscoveryCompletion, DiscoveryError> {
        let names: Vec<PathBuf> = list_root(self.root, &collector.bounds, None)
            .map_err(DiscoveryError::RootUnavailable)?;
        for name in names {
            if !collector.has_candidate_room() {
                return Ok(DiscoveryCompletion::CandidateLimitReached);
            }
            if let Err(stopped) = collector.bounds.take_unit() {
                return Ok(stopped);
            }
            let project: Project = match self.recognize(name) {
                Ok(project) => project,
                Err(skip) => {
                    collector.add(&self.rule.rule, self.root, *skip)?;
                    continue;
                }
            };
            for unit in UNIT_PATHS {
                if !collector.has_candidate_room() {
                    return Ok(DiscoveryCompletion::CandidateLimitReached);
                }
                match self.assess(&project, Path::new(unit), None, collector)? {
                    Outcome::Assessed(assessment) => {
                        collector.add(&self.rule.rule, self.root, *assessment)?;
                    }
                    Outcome::Absent => {}
                    Outcome::Stopped(stopped) => return Ok(stopped),
                }
            }
            // A project directory whose project is gone is also one unit of
            // the layout of an orphan.
            if project.gone == WorkspaceGone::Gone {
                if !collector.has_candidate_room() {
                    return Ok(DiscoveryCompletion::CandidateLimitReached);
                }
                match self.assess_orphan(&project, collector)? {
                    Outcome::Assessed(assessment) => {
                        collector.add(&self.rule.rule, self.root, *assessment)?;
                    }
                    Outcome::Absent => {}
                    Outcome::Stopped(stopped) => return Ok(stopped),
                }
            }
        }
        Ok(DiscoveryCompletion::Finished)
    }

    fn discover_known(
        &mut self,
        known: &[DiscoveredCandidate],
        collector: &mut Collector<'_>,
    ) -> Result<DiscoveryCompletion, DiscoveryError> {
        for candidate in known {
            if let Err(stopped) = collector.bounds.take_unit() {
                return Ok(stopped);
            }
            let relative: PathBuf = candidate.evidence.relative_entry.to_path_buf();
            // A known unit is `PROJECT/UNIT`, with a unit of the fixed
            // list.
            let split: Option<(PathBuf, &Path)> = relative.components().next().and_then(|first| {
                let project: PathBuf = PathBuf::from(first.as_os_str());
                UNIT_PATHS
                    .iter()
                    .map(Path::new)
                    // The text is exactly `PROJECT/UNIT`: another spelling
                    // of the same path is not the known unit.
                    .find(|unit| project.join(unit).as_os_str() == relative.as_os_str())
                    .map(|unit| (project, unit))
            });
            let Some((project_name, unit)) = split else {
                return Err(DiscoveryError::KnownCandidate);
            };
            let project: Project = match self.recognize(project_name) {
                Ok(project) => project,
                Err(skip) => {
                    // The skip names the unit, not the project directory.
                    let mut skip: Assessment = *skip;
                    skip.relative = relative;
                    skip.evidence = None;
                    collector.add(&self.rule.rule, self.root, skip)?;
                    continue;
                }
            };
            match self.assess(&project, unit, Some(candidate), collector)? {
                Outcome::Assessed(assessment) => {
                    collector.add(&self.rule.rule, self.root, *assessment)?;
                }
                Outcome::Absent => {
                    let skip: Assessment = Assessment::skip(relative, SkipReason::Vanished);
                    collector.add(&self.rule.rule, self.root, skip)?;
                }
                Outcome::Stopped(stopped) => return Ok(stopped),
            }
        }
        Ok(DiscoveryCompletion::Finished)
    }

    /// Recognizes the project directory `name` of the root. `Err` is the
    /// skip of a name that is not a recognized project directory.
    fn recognize(&self, name: PathBuf) -> Result<Project, Box<Assessment>> {
        let path: PathBuf = self.root.path.join(&name);
        let snapshot: ObjectSnapshot = match lstat(&path) {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(Box::new(Assessment::skip(name, reason_of(&error)))),
        };
        let mut skip: Assessment = Assessment::new(name);
        skip.evidence = target_evidence(&skip.relative, &snapshot);
        let reject = |mut skip: Assessment, fact: Fact, reason: SkipReason| {
            skip.eligibility.rule_supports_layout = fact;
            skip.reasons.insert(reason);
            Err(Box::new(skip))
        };
        let is_shared: bool = SHARED_ROOT_ENTRIES
            .iter()
            .any(|entry| skip.relative.as_os_str() == *entry);
        if is_shared {
            skip.eligibility.identity_matches = Fact::NotSatisfied;
            return reject(skip, Fact::NotSatisfied, SkipReason::SharedOwnership);
        }
        match snapshot.kind {
            ObjectKind::Directory => {}
            ObjectKind::SymbolicLink => {
                return reject(skip, Fact::NotSatisfied, SkipReason::SymbolicLink);
            }
            ObjectKind::RegularFile => {
                return reject(skip, Fact::NotSatisfied, SkipReason::UnsupportedLayout);
            }
            ObjectKind::Other => {
                return reject(skip, Fact::NotSatisfied, SkipReason::UnsupportedObject);
            }
        }
        if !has_project_name_form(&skip.relative) {
            return reject(skip, Fact::NotSatisfied, SkipReason::UnsupportedLayout);
        }
        let (info, info_bytes, info_snapshot) = match self.read_info(&path) {
            Ok(read) => read,
            Err((fact, reason)) => return reject(skip, fact, reason),
        };
        let (regenerable, overlaps_source) = self.workspace_state(&info.workspace_path);
        let gone: WorkspaceGone = workspace_gone(&info.workspace_path, self.mounts);
        Ok(Project {
            relative: skip.relative,
            snapshot,
            info,
            info_bytes,
            info_snapshot,
            regenerable,
            overlaps_source,
            gone,
        })
    }

    /// Reads `info.plist` of the project directory at `path`.
    fn read_info(
        &self,
        path: &Path,
    ) -> Result<(ProjectInfo, Vec<u8>, ObjectSnapshot), (Fact, SkipReason)> {
        let read: RecordRead = read_record(
            &path.join(INFO_PLIST),
            MAX_INFO_PLIST_BYTES,
            self.scope.principal,
        );
        match read {
            RecordRead::Absent => Err((Fact::NotSatisfied, SkipReason::UnsupportedLayout)),
            RecordRead::Denied => Err((Fact::Unknown, SkipReason::AccessDenied)),
            RecordRead::Invalid => Err((Fact::NotSatisfied, SkipReason::RecordInvalid)),
            RecordRead::Read { bytes, snapshot } => match parse_project_info(&bytes) {
                Some(info) => Ok((info, bytes, snapshot)),
                None => Err((Fact::NotSatisfied, SkipReason::UnsupportedLayout)),
            },
        }
    }

    /// Whether the project of `WorkspacePath` is present (predicate 4),
    /// and whether it overlaps the root.
    ///
    /// The data can be made again only from the project. A project that
    /// is absent disqualifies the units; a project that the rule cannot
    /// examine leaves the predicate unknown.
    ///
    /// The value of `WorkspacePath` comes from a file that the user can
    /// write, and it can name a network volume or an automounter path. The
    /// rule examines it only with [`walk_local`]: the mount table is read
    /// before the first call that uses the path, and no call follows a
    /// symbolic link. A project on a filesystem that is not local, or a
    /// path with a symbolic link, leaves the predicate unknown. A path
    /// with a symbolic link also leaves the overlap unknown.
    fn workspace_state(&self, workspace: &Path) -> ((Fact, Option<SkipReason>), Option<bool>) {
        let unknown = (Fact::Unknown, Some(SkipReason::RegenerabilityUnknown));
        if !is_plain_absolute(workspace) {
            return (unknown, Some(false));
        }
        // A project in the root, or a root in the directory that holds
        // the project, is a root that overlaps source. The source
        // directory of a project or a workspace bundle is its parent; a
        // package is its own source directory. The path has no symbolic
        // link when the predicate can be satisfied, so the path as given
        // is its resolved form.
        let is_bundle: bool = matches!(
            workspace
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("xcodeproj" | "xcworkspace")
        );
        let in_source_directory: bool = is_bundle
            && workspace
                .parent()
                .is_some_and(|directory| self.root.is_within(directory));
        let overlaps_source: bool = self.root.overlaps_path(workspace) || in_source_directory;
        let has_file = |name: &str| {
            fs::symlink_metadata(workspace.join(name)).is_ok_and(|metadata| metadata.is_file())
        };
        let walk: Result<ObjectSnapshot, WalkStop> = walk_local(workspace, self.mounts);
        let linked: bool = match &walk {
            Ok(snapshot) => snapshot.kind == ObjectKind::SymbolicLink,
            Err(stop) => matches!(stop, WalkStop::LinkInAncestor),
        };
        let regenerable = match walk {
            Err(WalkStop::Absent) => (Fact::NotSatisfied, Some(SkipReason::NotRegenerable)),
            Err(WalkStop::NotLocal | WalkStop::LocalityUnknown) => {
                (Fact::Unknown, Some(SkipReason::SourceNotLocal))
            }
            Ok(snapshot) if snapshot.kind == ObjectKind::Directory => {
                let extension: Option<&str> = workspace
                    .extension()
                    .and_then(|extension| extension.to_str());
                let is_project: bool = match extension {
                    Some("xcodeproj") => has_file("project.pbxproj"),
                    Some("xcworkspace") => has_file("contents.xcworkspacedata"),
                    _ => has_file("Package.swift"),
                };
                if is_project {
                    (Fact::Satisfied, None)
                } else {
                    unknown
                }
            }
            Ok(_) | Err(WalkStop::LinkInAncestor | WalkStop::Failed(_)) => unknown,
        };
        (regenerable, (!linked).then_some(overlaps_source))
    }

    /// The snapshot of the unit `unit` of `project`. Each directory from
    /// the project directory to the unit must be a directory of the same
    /// owner and device: a symbolic link in the path is not followed.
    fn unit_snapshot(
        &self,
        project: &Project,
        unit: &Path,
    ) -> Result<Option<ObjectSnapshot>, SkipReason> {
        let mut path: PathBuf = self.root.path.join(&project.relative);
        let mut last: Option<ObjectSnapshot> = None;
        for component in unit.components() {
            path.push(component);
            let snapshot: ObjectSnapshot = match lstat(&path) {
                Ok(snapshot) => snapshot,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(reason_of(&error)),
            };
            match snapshot.kind {
                ObjectKind::Directory => {}
                ObjectKind::SymbolicLink => return Err(SkipReason::SymbolicLink),
                ObjectKind::RegularFile => return Err(SkipReason::UnsupportedLayout),
                ObjectKind::Other => return Err(SkipReason::UnsupportedObject),
            }
            if snapshot.owner != self.scope.principal {
                return Err(SkipReason::WrongOwner);
            }
            if snapshot.object.device != self.root.device() {
                return Err(SkipReason::MountCrossing);
            }
            last = Some(snapshot);
        }
        Ok(last)
    }

    /// Whether each component of `relative`, below the project directory
    /// `directory`, is a directory of the user on the device of the root.
    /// `Ok(false)` when a component is absent. `Err` when a component is
    /// a symbolic link or another object, or cannot be examined.
    fn has_directories(&self, directory: &Path, relative: &Path) -> Result<bool, ()> {
        let mut path: PathBuf = directory.to_path_buf();
        for component in relative.components() {
            path.push(component);
            match lstat(&path) {
                Ok(snapshot)
                    if snapshot.kind == ObjectKind::Directory
                        && snapshot.owner == self.scope.principal
                        && snapshot.object.device == self.root.device() => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                _ => return Err(()),
            }
        }
        Ok(true)
    }

    /// The lock state of one build database, and its modification time.
    /// `None` when the project has no intermediates directory for the
    /// database, so that no build wrote there.
    fn database_state(
        &self,
        directory: &Path,
        database: &Path,
    ) -> Option<(LockState, Option<WallTime>)> {
        let unknown = Some((LockState::Unknown, None));
        let (Some(build_data), Some(intermediates)) =
            (database.parent(), database.parent().and_then(Path::parent))
        else {
            return unknown;
        };
        match self.has_directories(directory, intermediates) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(()) => return unknown,
        }
        // Intermediates with no build database: the build system keeps
        // its lock at a place that the rule does not know.
        if self.has_directories(directory, build_data) != Ok(true) {
            return unknown;
        }
        let path: PathBuf = directory.join(database);
        let Ok(snapshot) = lstat(&path) else {
            return unknown;
        };
        let modified: Option<WallTime> = snapshot.modified();
        if snapshot.kind != ObjectKind::RegularFile {
            return Some((LockState::Unknown, modified));
        }
        let mut state: LockState = LockState::Free;
        for sidecar in DATABASE_SIDECARS {
            let mut name = path.clone().into_os_string();
            name.push(sidecar);
            match fs::symlink_metadata(&name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => state = LockState::Held,
                Err(_) => return Some((LockState::Unknown, modified)),
            }
        }
        let opened: io::Result<File> = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path);
        // The open file is the object of `lstat`.
        let probed: io::Result<bool> = opened.and_then(|file| {
            let is_same: bool = file
                .metadata()
                .is_ok_and(|metadata| metadata.ino() == snapshot.object.inode.get());
            if is_same {
                (self.rule.lock_probe)(&file)
            } else {
                Err(io::Error::other("the build database changed"))
            }
        });
        match probed {
            Ok(false) => Some((state, modified)),
            Ok(true) => Some((LockState::Held, modified)),
            Err(_) if state == LockState::Held => Some((LockState::Held, modified)),
            Err(_) => Some((LockState::Unknown, modified)),
        }
    }

    /// The lock state of the build databases of the project, and the
    /// newest modification time of a database. `Err` when a time does not
    /// fit the type.
    ///
    /// A project with no build database that the rule can examine is
    /// `unknown`: the lock check then has no result, and a check with no
    /// result is not a passed check.
    fn build_database_state(&self, project: &Project) -> (LockState, Result<Option<WallTime>, ()>) {
        let directory: PathBuf = self.root.path.join(&project.relative);
        let mut state: Option<LockState> = None;
        let mut newest: Result<Option<WallTime>, ()> = Ok(None);
        for database in BUILD_DATABASES {
            let Some((found, modified)) = self.database_state(&directory, Path::new(database))
            else {
                continue;
            };
            // `held` stays: a later unknown or free does not replace it.
            state = Some(match (state, found) {
                (Some(LockState::Held), _) | (_, LockState::Held) => LockState::Held,
                (Some(LockState::Unknown), _) | (_, LockState::Unknown) => LockState::Unknown,
                (Some(LockState::Free) | None, LockState::Free) => LockState::Free,
            });
            if found != LockState::Unknown || modified.is_some() {
                newest = match (newest, modified) {
                    (Ok(newest), Some(modified)) => Ok(newest.max(Some(modified))),
                    _ => Err(()),
                };
            }
        }
        (state.unwrap_or(LockState::Unknown), newest)
    }

    /// Assesses the unit `unit` of `project`. `known` is the candidate of
    /// an earlier discovery: the unit is then not measured.
    fn assess(
        &mut self,
        project: &Project,
        unit: &Path,
        known: Option<&DiscoveredCandidate>,
        collector: &mut Collector<'_>,
    ) -> Result<Outcome, DiscoveryError> {
        let relative: PathBuf = project.relative.join(unit);
        let path: PathBuf = self.root.path.join(&relative);
        let mut assessment: Assessment = Assessment::new(relative);
        assessment.layout = Some(XCODE_DERIVED_DATA_LAYOUT);
        assessment.eligibility.rule_supports_layout = Fact::Satisfied;

        // Predicate 2: the unit is a directory of the project directory,
        // with the same owner and device.
        let before: ObjectSnapshot = match self.unit_snapshot(project, unit) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return Ok(Outcome::Absent),
            Err(reason) => {
                assessment.eligibility.identity_matches = match reason {
                    SkipReason::AccessDenied | SkipReason::MeasurementIncomplete => Fact::Unknown,
                    _ => Fact::NotSatisfied,
                };
                assessment.reasons.insert(reason);
                return Ok(Outcome::Assessed(Box::new(assessment)));
            }
        };
        assessment.evidence = target_evidence(&assessment.relative, &before);
        let has_project_owner: bool = project.snapshot.owner == self.scope.principal
            && project.snapshot.object.device == self.root.device();
        assessment.eligibility.identity_matches = if has_project_owner {
            Fact::Satisfied
        } else {
            assessment.reasons.insert(SkipReason::WrongOwner);
            Fact::NotSatisfied
        };

        // Predicate 4: the project that makes the data again is present.
        let (regenerable, regenerable_reason) = project.regenerable.clone();
        assessment.eligibility.regenerable = regenerable;
        assessment.reasons.extend(regenerable_reason);

        // Predicate 7: the exclusions of the caller, and source overlap.
        // A workspace path with a symbolic link leaves the overlap unknown;
        // predicate 4 then has its reason.
        let is_excluded: bool =
            project.overlaps_source == Some(true) || self.root.is_excluded(&assessment.relative);
        assessment.eligibility.no_exclusion_overlap = if is_excluded {
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            Fact::NotSatisfied
        } else if project.overlaps_source.is_none() {
            Fact::Unknown
        } else {
            Fact::Satisfied
        };

        // A unit that is not positively attributed is not measured.
        if !assessment.reasons.is_empty() {
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }

        // Predicate 8: the complete unit and its charge.
        let stopped: Option<DiscoveryCompletion> = establish_charge(
            &mut assessment,
            known,
            &UnitUnderMeasurement {
                path: &path,
                before: &before,
                principal: self.scope.principal,
                repositories: None,
            },
            &self.rule.rule,
            &mut collector.bounds,
            &mut |relative: &Path, kind: EntryKind| classify_entry(unit, relative, kind),
        )?;
        if let Some(stopped) = stopped {
            return Ok(Outcome::Stopped(stopped));
        }
        (self.after_measurement)(&path);
        // The process evidence is examined at the time of this unit and
        // not at the start of the discovery: a measurement can be long.
        let processes: ProducerProcesses = self.evidence.processes_at(
            collector.bounds.monotonic_now(),
            self.rule.rule.activity.evidence_expiry,
        );
        self.assess_activity(
            &mut assessment,
            project,
            &before,
            processes,
            collector.observed_at(),
        );

        // The evidence snapshot: the unit, the project directory, and
        // `info.plist` are the objects that the assessment examined.
        let project_path: PathBuf = self.root.path.join(&project.relative);
        let unchanged: bool = lstat(&path).is_ok_and(|after| after == before)
            && lstat(&project_path).is_ok_and(|after| after == project.snapshot)
            && self
                .read_info(&project_path)
                .is_ok_and(|(_, bytes, _)| bytes == project.info_bytes);
        if !unchanged {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::IdentityChanged);
        }
        Ok(Outcome::Assessed(Box::new(assessment)))
    }

    /// Assesses the whole project directory of `project`, whose project is
    /// gone, as one unit of the layout [`XCODE_ORPHAN_LAYOUT`].
    ///
    /// The data of a project that no longer exists has no use, so predicate
    /// 4 is satisfied by the absence of the project, which the rule
    /// examined ([`workspace_gone`]). The measurement refuses a unit with a
    /// Git repository at any depth, except a clean clone of Swift Package
    /// Manager in `SourcePackages/checkouts` or `SourcePackages/repositories`
    /// that the pin-less check admits: a checkout with an edit or a local
    /// commit thus stays. The deny-list of the rule applies
    /// at each depth; the allow-list of the children of a unit does not.
    fn assess_orphan(
        &mut self,
        project: &Project,
        collector: &mut Collector<'_>,
    ) -> Result<Outcome, DiscoveryError> {
        let relative: PathBuf = project.relative.clone();
        let path: PathBuf = self.root.path.join(&relative);
        let before: ObjectSnapshot = project.snapshot;
        let mut assessment: Assessment = Assessment::new(relative);
        assessment.layout = Some(XCODE_ORPHAN_LAYOUT);
        assessment.eligibility.rule_supports_layout = Fact::Satisfied;
        assessment.evidence = target_evidence(&assessment.relative, &before);
        if before.owner != self.scope.principal || before.object.device != self.root.device() {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::WrongOwner);
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }
        assessment.eligibility.identity_matches = Fact::Satisfied;
        assessment.eligibility.regenerable = Fact::Satisfied;
        if self.root.is_excluded(&assessment.relative) {
            assessment.eligibility.no_exclusion_overlap = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }
        assessment.eligibility.no_exclusion_overlap = Fact::Satisfied;
        // The layout is for a manual eviction only. The clean clones of
        // Swift Package Manager in `SourcePackages` are admitted in the
        // pin-less mode (`docs/CLEANUP_RULES.md` section 6): the workspace
        // is gone, so no pin file exists.
        let git: Result<GitTool, GitToolProblem> = GitTool::locate();
        let policy: RepositoryPolicy<'_> = RepositoryPolicy {
            checkouts: SwiftPmCheckouts::of_orphan_project(&path),
            git: git.as_ref().map_err(|problem| *problem),
        };
        let stopped: Option<DiscoveryCompletion> = establish_charge(
            &mut assessment,
            None,
            &UnitUnderMeasurement {
                path: &path,
                before: &before,
                principal: self.scope.principal,
                repositories: Some(&policy),
            },
            &self.rule.rule,
            &mut collector.bounds,
            &mut |relative: &Path, _kind: EntryKind| deny_listed(Path::new(""), relative),
        )?;
        if let Some(stopped) = stopped {
            return Ok(Outcome::Stopped(stopped));
        }
        if !assessment.reasons.is_empty() {
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }
        (self.after_measurement)(&path);
        let processes: ProducerProcesses = self.evidence.processes_at(
            collector.bounds.monotonic_now(),
            self.rule.rule.activity.evidence_expiry,
        );
        self.assess_orphan_activity(&mut assessment, project, processes, collector.observed_at());
        let unchanged: bool = lstat(&path).is_ok_and(|after| after == before)
            && self
                .read_info(&path)
                .is_ok_and(|(_, bytes, _)| bytes == project.info_bytes)
            && workspace_gone(&project.info.workspace_path, self.mounts) == WorkspaceGone::Gone;
        if !unchanged {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::IdentityChanged);
        }
        Ok(Outcome::Assessed(Box::new(assessment)))
    }

    /// Establishes the producer processes, the lock of the build
    /// databases, and the age of an orphan unit (predicates 5 and 6). A
    /// project directory with no build database has no lock to examine: no
    /// build can run for a project that is gone, so only a held lock
    /// blocks the unit. The age is the time since the newest of
    /// `LastAccessedDate`, the times of the project directory and of
    /// `info.plist`, and the newest change below the unit.
    fn assess_orphan_activity(
        &self,
        assessment: &mut Assessment,
        project: &Project,
        processes: ProducerProcesses,
        now: Option<WallTime>,
    ) {
        let (lock, _) = self.build_database_state(project);
        let times: [Option<WallTime>; 4] = [
            Some(project.info.last_accessed),
            project.snapshot.modified(),
            project.info_snapshot.modified(),
            assessment.newest_content_change,
        ];
        let newest: Option<WallTime> = times.into_iter().flatten().max();
        let required: Nanoseconds = self
            .rule
            .rule
            .retention
            .minimum_age
            .max(self.rule.rule.activity.quiescence);
        let mut inactive_for: Option<Nanoseconds> = None;
        let age: Fact = match (newest, now) {
            (Some(newest), Some(now)) if newest > now => {
                assessment.reasons.insert(SkipReason::FutureTimestamp);
                Fact::Unknown
            }
            (Some(newest), Some(now)) => {
                inactive_for = elapsed_between(newest, now);
                if inactive_for.is_some_and(|elapsed| elapsed >= required) {
                    Fact::Satisfied
                } else {
                    assessment.reasons.insert(SkipReason::RetentionNotElapsed);
                    Fact::NotSatisfied
                }
            }
            _ => {
                assessment.reasons.insert(SkipReason::AgeUnknown);
                Fact::Unknown
            }
        };
        let is_active: bool = processes == ProducerProcesses::Running || lock == LockState::Held;
        let is_unknown: bool = processes == ProducerProcesses::Unknown;
        if is_active {
            assessment.reasons.insert(SkipReason::ActiveProducer);
        }
        if is_unknown {
            assessment.reasons.insert(SkipReason::ActivityUnknown);
        }
        assessment.eligibility.age_and_inactivity = if is_active || age == Fact::NotSatisfied {
            Fact::NotSatisfied
        } else if is_unknown {
            Fact::Unknown
        } else {
            age
        };
        assessment.activity = match (
            is_active,
            &assessment.eligibility.age_and_inactivity,
            inactive_for,
        ) {
            (true, _, _) => ActivityFact::Active,
            (false, Fact::Satisfied, Some(inactive_for)) => ActivityFact::Inactive { inactive_for },
            _ => ActivityFact::Unknown,
        };
        if !is_unknown {
            assessment.eligibility.protocols_valid = Fact::Satisfied;
        }
    }

    /// Establishes the producer processes, the lock of the build
    /// database, and the age of a unit (predicates 5 and 6).
    fn assess_activity(
        &self,
        assessment: &mut Assessment,
        project: &Project,
        before: &ObjectSnapshot,
        processes: ProducerProcesses,
        now: Option<WallTime>,
    ) {
        // Predicates 5 and 6: the producer processes, the lock of the
        // build database, and the age. The lock query is after the
        // measurement, so that it is as late as the discovery permits.
        let (lock, database_modified) = self.build_database_state(project);
        let content_change: Option<WallTime> = assessment.newest_content_change;
        let is_active: bool = processes == ProducerProcesses::Running || lock == LockState::Held;
        let is_unknown: bool =
            processes == ProducerProcesses::Unknown || lock == LockState::Unknown;
        let times: [Option<WallTime>; 4] = [
            Some(project.info.last_accessed),
            project.snapshot.modified(),
            project.info_snapshot.modified(),
            before.modified(),
        ];
        let newest: Option<WallTime> = match database_modified {
            // The times of the unit directory show a change of its own
            // names only. The newest change of the measured content shows
            // a file that was written in place below the unit.
            Ok(database) if times.iter().all(Option::is_some) => times
                .into_iter()
                .chain([database, content_change])
                .flatten()
                .max(),
            _ => None,
        };
        let required: Nanoseconds = self
            .rule
            .rule
            .retention
            .minimum_age
            .max(self.rule.rule.activity.quiescence);
        let mut inactive_for: Option<Nanoseconds> = None;
        let age: Fact = match (newest, now) {
            (Some(newest), Some(now)) if newest > now => {
                assessment.reasons.insert(SkipReason::FutureTimestamp);
                Fact::Unknown
            }
            (Some(newest), Some(now)) => {
                inactive_for = elapsed_between(newest, now);
                if inactive_for.is_some_and(|elapsed| elapsed >= required) {
                    Fact::Satisfied
                } else {
                    assessment.reasons.insert(SkipReason::RetentionNotElapsed);
                    Fact::NotSatisfied
                }
            }
            _ => {
                assessment.reasons.insert(SkipReason::AgeUnknown);
                Fact::Unknown
            }
        };
        if is_active {
            assessment.reasons.insert(SkipReason::ActiveProducer);
        }
        if is_unknown {
            assessment.reasons.insert(SkipReason::ActivityUnknown);
        }
        assessment.eligibility.age_and_inactivity = if is_active || age == Fact::NotSatisfied {
            Fact::NotSatisfied
        } else if is_unknown {
            Fact::Unknown
        } else {
            age
        };
        assessment.activity = match (
            is_active,
            &assessment.eligibility.age_and_inactivity,
            inactive_for,
        ) {
            (true, _, _) => ActivityFact::Active,
            (false, Fact::Satisfied, Some(inactive_for)) => ActivityFact::Inactive { inactive_for },
            _ => ActivityFact::Unknown,
        };
        // The protocol is valid only when each of its checks gave a
        // result. A check with no result is not a passed check.
        if assessment.eligibility.protocols_valid == Fact::Unknown && !is_unknown {
            assessment.eligibility.protocols_valid = Fact::Satisfied;
        }
    }
}

/// The check of a unit of the layout [`XCODE_ORPHAN_LAYOUT`] immediately
/// before its step: the unit at `path` is still a project directory of the
/// root `root` with the name form of the rule, a directory of the user
/// `principal`, with an `info.plist` whose project is still gone. A
/// project that is present again, or a volume of `/Volumes` that is not
/// mounted, refuses the step.
#[must_use]
pub(super) fn recheck_orphan(
    principal: svalnir_core::process::Uid,
    root: &Path,
    path: &Path,
    admitted: &[svalnir_core::action::AdmittedRepository],
) -> super::projects::UnitRecheck {
    use super::nested_git::{RepositoryRecheck, recheck_admitted};
    use super::projects::UnitRecheck;

    let Ok(relative) = path.strip_prefix(root) else {
        return UnitRecheck::Refused("unit_layout_changed");
    };
    if relative.components().count() != 1 || !has_project_name_form(relative) {
        return UnitRecheck::Refused("unit_layout_changed");
    }
    match lstat(path) {
        Ok(snapshot) if snapshot.kind == ObjectKind::Directory && snapshot.owner == principal => {}
        Ok(snapshot) if snapshot.kind != ObjectKind::Directory => {
            return UnitRecheck::Refused("unit_not_directory");
        }
        Ok(_) => return UnitRecheck::Refused("unit_owner"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return UnitRecheck::Absent,
        Err(_) => return UnitRecheck::Unknown("unit_not_readable"),
    }
    let info: ProjectInfo =
        match read_record(&path.join(INFO_PLIST), MAX_INFO_PLIST_BYTES, principal) {
            RecordRead::Read { bytes, .. } => match parse_project_info(&bytes) {
                Some(info) => info,
                None => return UnitRecheck::Refused("unit_layout_changed"),
            },
            RecordRead::Absent | RecordRead::Invalid => {
                return UnitRecheck::Refused("unit_layout_changed");
            }
            RecordRead::Denied => return UnitRecheck::Unknown("unit_not_readable"),
        };
    let Ok(mounts) = MountTable::read() else {
        return UnitRecheck::Unknown("workspace_state_unknown");
    };
    match workspace_gone(&info.workspace_path, &mounts) {
        WorkspaceGone::Gone => {}
        WorkspaceGone::Present => return UnitRecheck::Refused("workspace_present"),
        WorkspaceGone::Unknown => return UnitRecheck::Unknown("workspace_state_unknown"),
    }
    // The pin-less check of the clean clones of Swift Package Manager runs
    // again and must give exactly the list that the plan binds.
    let git: Result<GitTool, GitToolProblem> = GitTool::locate();
    let checkouts: SwiftPmCheckouts = SwiftPmCheckouts::of_orphan_project(path);
    match recheck_admitted(path, Some(&checkouts), git.as_ref().ok(), admitted) {
        RepositoryRecheck::Same => UnitRecheck::Passed,
        RepositoryRecheck::Refused(code) => UnitRecheck::Refused(code),
        RepositoryRecheck::Unknown(code) => UnitRecheck::Unknown(code),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use super::{UNIT_PATHS, classify_entry};
    use crate::scan::EntryKind;

    /// A volume of macOS refuses a name that is not UTF-8, so a test
    /// cannot make one. The classification of the name refuses it.
    #[test]
    fn a_child_name_that_is_not_utf_8_is_refused() {
        let name: &Path = Path::new(OsStr::from_bytes(b"Debug\xff"));
        for unit in UNIT_PATHS {
            for kind in [EntryKind::Directory, EntryKind::File] {
                assert!(
                    classify_entry(Path::new(unit), name, kind).is_some(),
                    "{unit}"
                );
            }
        }
    }
}
