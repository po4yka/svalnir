//! The rule `xcode.inactive-derived-data`.
//!
//! `docs/CLEANUP_RULES.md` section 11 owns the contract. The rule finds a
//! fixed generated subset of one identified project directory of a
//! `DerivedData` root. It removes nothing, and it never selects the root or
//! a full project directory.
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
//! A unit with a debug-symbol bundle, an archive, archive intermediates,
//! a test result bundle, signing material, or a database is skipped as a
//! whole. The one database that the rule accepts is the build database
//! `XCBuildData/build.db` of the build system.
//!
//! # What the rule can and cannot establish
//!
//! The rule establishes the identity and the owner of a unit, that the
//! project of `WorkspacePath` is present, the newest of the examined
//! times, that no other process holds an advisory lock on a build
//! database, and the complete charge. The caller gives the evidence of
//! the producer processes. The rule cannot see a writer that takes no
//! lock, an open file of another process, a build in a directory that it
//! did not examine, or a file that a person put in a unit.

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
use svalnir_core::time::WallTime;

use super::model::{
    DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError,
    DiscoveryMode, DiscoveryScope, SkipReason,
};
use super::native::is_locked_by_another_process;
use super::plist::{ProjectInfo, parse_project_info};
use super::registry::RegistryError;
use super::unit::{
    Assessment, Collector, ObjectKind, ObjectSnapshot, RecordRead, RootView, check_known,
    elapsed_between, establish_charge, is_plain_absolute, list_root, lstat, read_record, reason_of,
    target_evidence,
};
use crate::scan::EntryKind;

/// The identity of the rule.
pub const XCODE_DERIVED_DATA_RULE_ID: &str = "xcode.inactive-derived-data";

/// The implementation revision of the rule in this build.
pub const XCODE_DERIVED_DATA_REVISION: &str = "r1";

/// The one layout that the revision supports.
pub const XCODE_DERIVED_DATA_LAYOUT: &str = "derived-data-project-v1";

/// The units of one project directory, relative to it.
pub const UNIT_PATHS: [&str; 3] = [
    "Build/Intermediates.noindex",
    "Build/Products",
    "Index.noindex",
];

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
        let runs: bool = executables
            .into_iter()
            .any(|name| XCODE_PRODUCER_EXECUTABLES.contains(&name));
        if runs {
            Self::Running
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
}

/// The lock query of a build database.
type LockProbe = fn(&File) -> io::Result<bool>;

/// The rule `xcode.inactive-derived-data`.
#[derive(Debug, Clone)]
pub struct XcodeDerivedDataRule {
    rule: Rule,
    lock_probe: LockProbe,
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
        layouts: vec![LayoutSupport {
            layout: XCODE_DERIVED_DATA_LAYOUT.to_owned(),
            lifecycle: LifecycleState::Proposed,
        }],
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

/// The reason an entry below a unit prevents a candidate, from its name.
/// A name is a rejection hint only: an entry with no such name is not
/// shown to be disposable.
fn classify_entry(unit: &Path, relative: &Path) -> Option<SkipReason> {
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
    overlaps_source: bool,
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
        Ok(Self { rule, lock_probe })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// Finds the candidates of the `DerivedData` root of `scope`.
    ///
    /// The discovery reads metadata and `info.plist`, opens each build
    /// database for a lock query, and reads the metadata of the project of
    /// `WorkspacePath`. It changes nothing. With
    /// [`DiscoveryMode::KnownCandidatesOnly`] it lists no directory and
    /// measures no tree.
    ///
    /// # Errors
    ///
    /// Returns a [`DiscoveryError`] when a limit is too large, when the
    /// root fails a check, when the root changed during the discovery, or
    /// when a known candidate belongs to another rule revision or root.
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
        let root: RootView = RootView::open(scope)?;
        let mut context = UnitContext {
            rule: self,
            root: &root,
            scope,
            processes: evidence.producer_processes,
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
    scope: &'a DiscoveryScope<'a>,
    processes: ProducerProcesses,
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
        Ok(Project {
            relative: skip.relative,
            snapshot,
            info,
            info_bytes,
            info_snapshot,
            regenerable,
            overlaps_source,
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
    fn workspace_state(&self, workspace: &Path) -> ((Fact, Option<SkipReason>), bool) {
        if !is_plain_absolute(workspace) {
            let unknown = (Fact::Unknown, Some(SkipReason::RegenerabilityUnknown));
            return (unknown, false);
        }
        // A project in the root, or a root in the directory that holds
        // the project, is a root that overlaps source. The comparison
        // uses the path as given and the path with each symbolic link
        // resolved. The source directory of a project or a workspace
        // bundle is its parent; a package is its own source directory.
        let is_bundle: bool = matches!(
            workspace
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("xcodeproj" | "xcworkspace")
        );
        let resolved: Option<PathBuf> = fs::canonicalize(workspace).ok();
        let overlaps_source: bool =
            std::iter::once(workspace)
                .chain(resolved.as_deref())
                .any(|form| {
                    let in_source_directory: bool = is_bundle
                        && form
                            .parent()
                            .is_some_and(|directory| self.root.is_within(directory));
                    self.root.overlaps_path(form) || in_source_directory
                });
        let has_file = |name: &str| {
            fs::symlink_metadata(workspace.join(name)).is_ok_and(|metadata| metadata.is_file())
        };
        let regenerable = match fs::metadata(workspace) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                (Fact::NotSatisfied, Some(SkipReason::NotRegenerable))
            }
            Ok(metadata) if metadata.is_dir() => {
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
                    (Fact::Unknown, Some(SkipReason::RegenerabilityUnknown))
                }
            }
            _ => (Fact::Unknown, Some(SkipReason::RegenerabilityUnknown)),
        };
        (regenerable, overlaps_source)
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
        let is_excluded: bool =
            project.overlaps_source || self.root.is_excluded(&assessment.relative);
        assessment.eligibility.no_exclusion_overlap = if is_excluded {
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            Fact::NotSatisfied
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
            &path,
            &before,
            &self.rule.rule,
            &mut collector.bounds,
            &mut |relative: &Path, _: EntryKind| classify_entry(unit, relative),
        )?;
        if let Some(stopped) = stopped {
            return Ok(Outcome::Stopped(stopped));
        }
        (self.after_measurement)(&path);
        self.assess_activity(&mut assessment, project, &before, collector.observed_at());

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

    /// Establishes the producer processes, the lock of the build
    /// database, and the age of a unit (predicates 5 and 6).
    fn assess_activity(
        &self,
        assessment: &mut Assessment,
        project: &Project,
        before: &ObjectSnapshot,
        now: Option<WallTime>,
    ) {
        // Predicates 5 and 6: the producer processes, the lock of the
        // build database, and the age. The lock query is after the
        // measurement, so that it is as late as the discovery permits.
        let (lock, database_modified) = self.build_database_state(project);
        let is_active: bool =
            self.processes == ProducerProcesses::Running || lock == LockState::Held;
        let is_unknown: bool =
            self.processes == ProducerProcesses::Unknown || lock == LockState::Unknown;
        let times: [Option<WallTime>; 4] = [
            Some(project.info.last_accessed),
            project.snapshot.modified(),
            project.info_snapshot.modified(),
            before.modified(),
        ];
        let newest: Option<WallTime> = match database_modified {
            Ok(database) if times.iter().all(Option::is_some) => {
                times.into_iter().chain([database]).flatten().max()
            }
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
