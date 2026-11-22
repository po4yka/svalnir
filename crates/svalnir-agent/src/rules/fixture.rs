//! Fixtures of the rule tests of this crate and of its clients.
//!
//! Only a test build has this module: a unit test of this crate, or a
//! debug build with the feature `test-support`. A function of this module
//! writes only below a directory that the caller gives, which a test made
//! as a temporary directory. No function reads the home directory, a real
//! `DerivedData` root, or the process table.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime};

use svalnir_core::process::Uid;
use svalnir_core::rule::{LifecycleState, PromotionEvidence};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::eviction::DiscoveryEnvironment;
use super::projects::{BuildProcesses, ProjectProcess};
use super::xcode::{ProducerProcesses, XcodeEvidence};
use crate::scan::{ScanClock, ScanTimestamp};

/// The reference of a lifecycle state of a test. It names no validation
/// record of `docs/VALIDATION.md`.
pub const FIXTURE_EVIDENCE: &str = "test-fixture/no-recorded-evidence";

/// The lifecycle state of a fixture test that permits manual eviction and
/// not automatic eviction.
#[must_use]
pub fn manual_action_validated() -> LifecycleState {
    LifecycleState::ManualActionValidated {
        evidence: PromotionEvidence {
            record: FIXTURE_EVIDENCE.to_owned(),
        },
    }
}

/// The lifecycle state of a fixture test that permits automatic eviction.
#[must_use]
pub fn automatic_eviction_validated() -> LifecycleState {
    LifecycleState::AutomaticEvictionValidated {
        evidence: PromotionEvidence {
            record: FIXTURE_EVIDENCE.to_owned(),
        },
    }
}

const SECONDS_PER_DAY: i64 = 86_400;

/// The environment of a fixture test: the wall-clock time of the host
/// moved forward by a number of days, a process-local monotonic time, and
/// a producer state that the test sets.
///
/// A fixture has the modification times of the moment of its creation, so
/// a clock that is 30 days later makes each unit older than the minimum
/// age of `xcode.inactive-derived-data`.
#[derive(Debug, Clone)]
pub struct FixtureEnvironment {
    started: Instant,
    days_later: i64,
    producer: Arc<AtomicU8>,
    in_use: Arc<AtomicU8>,
    /// The working directory of a synthetic build process, for
    /// `project.dependency-directory`.
    build: Arc<Mutex<Option<PathBuf>>>,
}

/// The use state of the units of a fixture test, for the use check of
/// `docs/CLEANUP_RULES.md` section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureUse {
    /// No process uses a unit: the inventory is complete and empty.
    NotInUse,
    /// A synthetic process has its working directory in each scope.
    InUse,
    /// A synthetic process of the user cannot be read.
    Unknown,
}

const NOT_RUNNING: u8 = 0;
const RUNNING: u8 = 1;
const UNKNOWN: u8 = 2;

impl FixtureEnvironment {
    /// An environment whose wall-clock time is `days_later` days after
    /// the time of the host, with no process of the producer.
    #[must_use]
    pub fn days_later(days_later: i64) -> Self {
        Self {
            started: Instant::now(),
            days_later,
            producer: Arc::new(AtomicU8::new(NOT_RUNNING)),
            in_use: Arc::new(AtomicU8::new(NOT_RUNNING)),
            build: Arc::new(Mutex::new(None)),
        }
    }

    /// Sets the working directory of a synthetic build process (`cargo`)
    /// that each later inventory of the build processes has, or no such
    /// process. Each copy of the environment has the same state.
    pub fn set_build_process(&self, working_directory: Option<PathBuf>) {
        *self.build.lock().unwrap_or_else(PoisonError::into_inner) = working_directory;
    }

    /// Sets the producer state that each later reading gives. Each copy of
    /// the environment has the same state.
    pub fn set_producer(&self, producer: ProducerProcesses) {
        self.producer.store(
            match producer {
                ProducerProcesses::NotRunning => NOT_RUNNING,
                ProducerProcesses::Running => RUNNING,
                ProducerProcesses::Unknown => UNKNOWN,
            },
            Ordering::SeqCst,
        );
    }

    /// Sets the use state that each later use check gives. Each copy of
    /// the environment has the same state.
    pub fn set_use(&self, state: FixtureUse) {
        self.in_use.store(
            match state {
                FixtureUse::NotInUse => NOT_RUNNING,
                FixtureUse::InUse => RUNNING,
                FixtureUse::Unknown => UNKNOWN,
            },
            Ordering::SeqCst,
        );
    }

    fn monotonic(&self) -> MonotonicNanos {
        let elapsed: u64 = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        MonotonicNanos::new(1_000_000_000_u64.saturating_add(elapsed))
    }
}

impl ScanClock for FixtureEnvironment {
    fn now(&self) -> ScanTimestamp {
        let wall: Option<WallTime> = WallTime::try_from(SystemTime::now()).ok().and_then(|now| {
            WallTime::from_unix(
                now.unix_seconds()
                    .saturating_add(self.days_later.saturating_mul(SECONDS_PER_DAY)),
                0,
            )
            .ok()
        });
        ScanTimestamp {
            wall,
            monotonic_ns: Some(self.monotonic()),
        }
    }
}

impl DiscoveryEnvironment for FixtureEnvironment {
    /// The producer state that the test set
    /// ([`FixtureEnvironment::set_producer`]), for each producer.
    fn producer_processes(&self, principal: Uid, _names: &[&str]) -> ProducerProcesses {
        self.xcode_evidence(principal).producer_processes
    }

    fn xcode_evidence(&self, _principal: Uid) -> XcodeEvidence {
        XcodeEvidence {
            producer_processes: match self.producer.load(Ordering::SeqCst) {
                NOT_RUNNING => ProducerProcesses::NotRunning,
                RUNNING => ProducerProcesses::Running,
                _ => ProducerProcesses::Unknown,
            },
            observed_at: self.monotonic(),
        }
    }

    /// The inventory of the use state that the test set
    /// ([`FixtureEnvironment::set_use`]); no process table is read.
    fn path_uses(
        &self,
        _principal: Uid,
        scopes: &[crate::rules::in_use::UnitScope],
    ) -> crate::platform::process::PathInventory {
        use crate::platform::process::{
            InventoryGap, PathInventory, PathUseKind, ProcessPathUse, ProcessUses, UnknownProcess,
        };
        use svalnir_core::process::Pid;

        let mut inventory: PathInventory = PathInventory {
            observed_at: Some(self.monotonic()),
            ..PathInventory::default()
        };
        // PID 1 is a synthetic process here; no query names it.
        let Ok(pid) = Pid::new(1) else {
            return inventory;
        };
        match self.in_use.load(Ordering::SeqCst) {
            NOT_RUNNING => {}
            RUNNING => inventory.processes.push(ProcessUses {
                pid,
                name: "fixture".to_owned(),
                uses: scopes
                    .iter()
                    .map(|scope| ProcessPathUse {
                        kind: PathUseKind::WorkingDirectory,
                        path: scope.path().to_path_buf(),
                    })
                    .collect(),
            }),
            _ => inventory.unknown.push(UnknownProcess {
                pid,
                name: "fixture".to_owned(),
                reason: InventoryGap::ProcessQueryDenied,
            }),
        }
        inventory
    }

    /// A complete inventory with the synthetic build process that the test
    /// set ([`FixtureEnvironment::set_build_process`]), and a process that
    /// is not a build process; no process table is read.
    fn build_processes(&self, _principal: Uid) -> BuildProcesses {
        let mut processes: Vec<ProjectProcess> = vec![ProjectProcess {
            executable: PathBuf::from("/usr/bin/login"),
            working_directory: None,
        }];
        if let Some(directory) = self
            .build
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            processes.push(ProjectProcess {
                executable: PathBuf::from("/usr/local/bin/cargo"),
                working_directory: Some(directory),
            });
        }
        BuildProcesses {
            processes,
            incomplete: None,
            observed_at: Some(self.monotonic()),
        }
    }
}

/// The path of the `DerivedData` root below the home directory `home`,
/// as the declaration of `xcode.inactive-derived-data` gives it.
#[must_use]
pub fn derived_data_root(home: &Path) -> PathBuf {
    home.join("Library/Developer/Xcode/DerivedData")
}

/// Makes the Xcode project `NAME.xcodeproj` below `sources`, outside a
/// `DerivedData` root, and returns its path.
///
/// # Errors
///
/// Returns the error of the file system when a file cannot be written.
pub fn write_workspace(sources: &Path, name: &str) -> std::io::Result<PathBuf> {
    let workspace: PathBuf = sources.join(name).join(format!("{name}.xcodeproj"));
    fs::create_dir_all(&workspace)?;
    fs::write(workspace.join("project.pbxproj"), b"// project")?;
    Ok(workspace)
}

/// Makes the project directory `name` below the `DerivedData` root `root`
/// with the three units of the rule, a log directory, and an `info.plist`
/// that names `workspace` and that was accessed now. Returns its path.
///
/// `name` must have the form of a project directory name: a stem, `-`,
/// and 28 lower-case letters.
///
/// # Errors
///
/// Returns the error of the file system when a file cannot be written, or
/// an error when the clock of the host gives no time.
pub fn write_project(root: &Path, name: &str, workspace: &Path) -> std::io::Result<PathBuf> {
    let project: PathBuf = root.join(name);
    let write = |relative: &str, bytes: &[u8]| -> std::io::Result<()> {
        let path: PathBuf = project.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)
    };
    write(
        "Build/Intermediates.noindex/XCBuildData/build.db",
        &[0_u8; 2_048],
    )?;
    write(
        "Build/Intermediates.noindex/App.build/App.o",
        &[1_u8; 3_000],
    )?;
    write("Build/Products/Debug/App.app/App", &[2_u8; 5_000])?;
    write("Index.noindex/DataStore/v5/records/AB", &[3_u8; 700])?;
    write("Logs/Build/1.xcactivitylog", b"log")?;
    let accessed: String = WallTime::try_from(SystemTime::now())
        .map(|now| now.to_string())
        .map_err(|_| std::io::Error::other("the clock of the host gave no time"))?;
    write(
        "info.plist",
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n\
             \t<key>LastAccessedDate</key>\n\t<date>{accessed}</date>\n\
             \t<key>WorkspacePath</key>\n\t<string>{}</string>\n\
             </dict>\n</plist>\n",
            workspace.display()
        )
        .as_bytes(),
    )?;
    Ok(project)
}

/// The identity of the fixture rule of an owner operation. No registry
/// of a build has it: a test gives it to a registry of its own.
pub const OWNER_FIXTURE_RULE: &str = "fixture.owner-operation";

/// The layout of the fixture rule of an owner operation.
pub const OWNER_FIXTURE_LAYOUT: &str = "fixture-owner-v1";

/// The fixture rule of an owner operation, with `lifecycle` for its one
/// layout. Its deletion method is `producer_operation`, and its producer
/// is a test script ([`write_owner_script`]); no test runs a real
/// producer tool.
///
/// # Errors
///
/// Returns the error of the declaration check.
pub fn owner_fixture_rule(
    lifecycle: LifecycleState,
) -> Result<svalnir_core::rule::Rule, svalnir_core::rule::RuleDeclarationError> {
    use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
    use svalnir_core::file::LosslessPath;
    use svalnir_core::id::{RuleId, RuleRevisionId};
    use svalnir_core::policy::RebuildCost;
    use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
    use svalnir_core::rule::{
        ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
        OwnerAttribution, Retention, RootBase, RuleBudget, RuleDeclaration, RuleDeclarationError,
        RuleExclusions, RuleMode, RuleOwner, RuleRef,
    };
    const MINUTE: u64 = 60_000_000_000;
    Checked::new(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(OWNER_FIXTURE_RULE).map_err(|_| RuleDeclarationError::Text)?,
            revision: RuleRevisionId::new("r1").map_err(|_| RuleDeclarationError::Text)?,
        },
        owner: RuleOwner {
            producer: "fixture-producer".to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts: vec![LayoutSupport {
            layout: OWNER_FIXTURE_LAYOUT.to_owned(),
            lifecycle,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::UserHome,
            relative: LosslessPath::from_bytes("Library/Caches/fixture-producer")
                .map_err(|_| RuleDeclarationError::Root)?,
        }],
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(MINUTE),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::ProducerProcessAbsent],
            quiescence: Nanoseconds::new(MINUTE),
            evidence_expiry: Nanoseconds::new(MINUTE),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::Directory],
            skip_hard_linked: false,
        },
        modes: vec![
            RuleMode::Inspection,
            RuleMode::ManualEviction,
            RuleMode::AutomaticEviction,
        ],
        deletion_method: DeletionMethod::ProducerOperation,
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::Low,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(1 << 30), EntryCount::new(100_000)),
            per_pass: WorkCharge::new(Bytes::new(1 << 31), EntryCount::new(200_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// The owner-operation declaration of the fixture rule, with the test
/// script at the absolute path `executable`. The `prune` command is
/// `prune ROOT`, bounded to the scope, and the `clear` command is
/// `clear ROOT`, with no bound. The environment has `HOME` and a fixed
/// `PATH`.
///
/// # Errors
///
/// Returns the error of the declaration check.
pub fn owner_fixture_declaration(
    executable: &Path,
    command_deadline: svalnir_core::quantity::Nanoseconds,
) -> Result<
    svalnir_core::rule::owner::OwnerOperation,
    svalnir_core::rule::owner::OwnerDeclarationError,
> {
    use svalnir_core::action::{Checked, OwnerOperationBound, OwnerOperationKind};
    use svalnir_core::file::LosslessPath;
    use svalnir_core::id::{RuleId, RuleRevisionId};
    use svalnir_core::rule::RuleRef;
    use svalnir_core::rule::owner::{
        EnvironmentDeclaration, ExecutableBase, ExecutableLocation, OwnerCommand,
        OwnerDeclarationError, OwnerOperationDeclaration, ParameterPart,
    };
    let command = |kind: OwnerOperationKind, word: &str, bound: OwnerOperationBound| OwnerCommand {
        kind,
        arguments: vec![
            ParameterPart::Literal(word.to_owned()),
            ParameterPart::ScopeRoot,
        ],
        bound,
        expected_effect: format!("The fixture producer runs the command {word} on its cache."),
    };
    Checked::new(OwnerOperationDeclaration {
        rule: RuleRef {
            id: RuleId::new(OWNER_FIXTURE_RULE).map_err(|_| OwnerDeclarationError::Text)?,
            revision: RuleRevisionId::new("r1").map_err(|_| OwnerDeclarationError::Text)?,
        },
        executables: vec![ExecutableLocation {
            base: ExecutableBase::Absolute,
            path: LosslessPath::from_path(executable)
                .map_err(|_| OwnerDeclarationError::Executable)?,
        }],
        commands: vec![
            command(
                OwnerOperationKind::Prune,
                "prune",
                OwnerOperationBound::WithinScope,
            ),
            command(
                OwnerOperationKind::Clear,
                "clear",
                OwnerOperationBound::Unbounded,
            ),
        ],
        interpreters: vec![svalnir_core::rule::owner::InterpreterLocation {
            location: ExecutableLocation {
                base: ExecutableBase::Absolute,
                path: LosslessPath::from_bytes("/bin/sh")
                    .map_err(|_| OwnerDeclarationError::Executable)?,
            },
            argument: None,
        }],
        environment: vec![
            EnvironmentDeclaration {
                name: "HOME".to_owned(),
                value: ParameterPart::HomeDirectory,
            },
            EnvironmentDeclaration {
                name: "PATH".to_owned(),
                value: ParameterPart::Literal("/usr/bin:/bin".to_owned()),
            },
        ],
        command_deadline,
    })
}

/// Writes the test script `name` with `body` below `directory`, with the
/// mode `0755`, and returns its path. The script runs with `/bin/sh`; its
/// first argument is the command word and its second the scope root.
///
/// # Errors
///
/// Returns the error of the write.
pub fn write_owner_script(directory: &Path, name: &str, body: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path: PathBuf = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path)
}
