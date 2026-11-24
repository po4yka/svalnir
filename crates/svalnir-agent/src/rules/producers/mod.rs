//! The rules with an owner operation: a fixed command of a producer on
//! one measured scope root (`docs/CLEANUP_RULES.md` section 9, "Rules with
//! an owner operation").
//!
//! Each rule has an owner-operation declaration
//! ([`svalnir_core::rule::owner`]) with one command, and a layout for the
//! scope root as a whole. A rule of [`super::caches`] or
//! `homebrew.cleanup` that gets an owner operation has a new revision
//! (`r2`) whose declaration adds that layout and the mode
//! `manual_eviction`; the inspection of its units is unchanged. The other
//! rules of this module have their own declaration (`r1`). Each layout is
//! `proposed` (owner decision of 2026-11-22: a rule is ready for promotion
//! in code, and its layouts stay `proposed` until a host promotion record
//! exists), so a released build makes no plan of an owner operation.
//!
//! # Roots
//!
//! The scope root comes from the configuration files of the producer as
//! text ([`super::caches::resolve`]), or is the documented default. No
//! rule runs a query of the producer to find it. The command names that
//! root to the producer in its argument vector or its fixed environment, so
//! the producer acts on the root that the plan measured. The root passes
//! the checks of a cache root ([`super::caches`]) and the guard of the
//! rule.
//!
//! # Executables
//!
//! The executable is the first declared location that passes the checks of
//! the owner executor ([`super::owner_operation::resolve_program`]). A
//! shim of mise is not a location: it is a link to the mise executable,
//! which selects the tool from the name of the call. The installed version
//! of a tool of mise is the link `latest` of the installs directory of
//! mise.

mod guard;
mod specs;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::action::{
    Checked, EnvironmentEntry, ExecutorRole, FileObjectType, OwnerOperationBinding,
    OwnerOperationBound, OwnerOperationKind, ScopeMeasurement, WorkCharge,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{RuleId, RuleRevisionId};
use svalnir_core::policy::RebuildCost;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::owner::{
    EnvironmentDeclaration, ExecutableBase, ExecutableLocation, InterpreterLocation, OwnerCommand,
    OwnerOperation, OwnerOperationDeclaration, ParameterPart, ParameterValues,
};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};

pub use guard::{
    GuardOutcome, HOMEBREW_OVERRIDING_KEYS, HOMEBREW_SYSTEM_ENV_FILES, MAX_TRACKED_CONFIG_BYTES,
    homebrew_system_env, mise_tracked_configs,
};
pub use specs::{
    GO_BUILD, GO_MODULES, HOMEBREW_CLEANUP, MISE_CACHE, MISE_INSTALLS, NPM_CACHE, PIP_CACHE,
    PNPM_STORE, PRODUCER_SPECS, UV_CACHE, YARN_CACHE,
};

use super::caches::config::{ConfigValue, paths_of, read_source};
use super::caches::{
    ConfigSource, ExclusionSpec, InspectionHost, Location, LocationForm, Marker, RootOutcome,
    RootResolution, RootSpec, check_scope_root, has_marker, location_refusal, locations_of,
    resolve,
};
use super::eviction::BoundRoot;
use super::owner_operation::{
    OwnerBindError, OwnerBindRequest, bind_owner_operation, resolve_program,
};
use super::registry::RegistryError;
use crate::executor::fs::ApprovedRoot as ScopeRoot;
use crate::executor::owner::{ScopeLimits, measure_scope};
use crate::platform::volume::MountTable;
use crate::scan::{CancellationToken, ScanClock};

/// The revision of a rule of [`super::caches`] or of `homebrew.cleanup`
/// with an owner operation.
pub const EXTENDED_RULE_REVISION: &str = "r2";

/// The revision of a rule of this module with its own declaration.
pub const OWN_RULE_REVISION: &str = "r1";

/// The largest executable that a plan builder reads for its digest: the
/// default limit of the owner executor, so that the executor can examine
/// each file that a plan binds.
pub const MAX_PRODUCER_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// One part of an argument or of an environment value of a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// The literal text.
    Literal(&'static str),
    /// The absolute path of the scope root.
    ScopeRoot,
    /// The absolute path of the home directory.
    Home,
}

impl Part {
    fn parameter(self) -> ParameterPart {
        match self {
            Self::Literal(text) => ParameterPart::Literal(text.to_owned()),
            Self::ScopeRoot => ParameterPart::ScopeRoot,
            Self::Home => ParameterPart::HomeDirectory,
        }
    }
}

/// Where the rule declaration of a rule of this module comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerBase {
    /// The rule of [`super::caches`] with the same identity, in a new
    /// revision.
    Cache,
    /// `homebrew.cleanup` of [`super::owner_tools`], in a new revision.
    OwnerTool,
    /// A declaration of this module.
    Own {
        /// The cost to make the data again.
        rebuild_cost: RebuildCost,
    },
}

/// The guard of a rule: a check of the producer state before a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// No guard.
    None,
    /// Each tracked configuration file of mise loads
    /// ([`mise_tracked_configs`]).
    MiseTrackedConfigs,
    /// No system `brew.env` file of Homebrew changes the effect of the
    /// command ([`homebrew_system_env`]).
    HomebrewSystemEnv,
}

/// The stable code of a scope root with no marker of its producer.
pub const OWNER_SCOPE_UNMARKED: &str = "owner_scope_unmarked";

/// The stable code of a guard that refuses the operation.
pub const OWNER_GUARD_REFUSED: &str = "owner_guard_refused";

/// The stable code of a system `brew.env` file that changes the effect of
/// the command of `homebrew.cleanup`.
pub const HOMEBREW_ENV_OVERRIDES: &str = "homebrew_env_overrides";

/// The reviewed facts of one rule with an owner operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProducerSpec {
    /// The rule identity.
    pub id: &'static str,
    /// The producer.
    pub producer: &'static str,
    /// Where the rule declaration comes from.
    pub base: ProducerBase,
    /// The layout of the scope root as a whole.
    pub layout: &'static str,
    /// The kind of the one command.
    pub kind: OwnerOperationKind,
    /// The bound of the command.
    pub bound: OwnerOperationBound,
    /// Why the review gave the bound.
    pub bound_reason: &'static str,
    /// The scope root.
    pub root: &'static RootSpec,
    /// The locations that the scope root never overlaps.
    pub exclusions: &'static [ExclusionSpec],
    /// The paths of the executable, in sequence.
    pub executables: &'static [Location],
    /// The interpreters of a script, each with its interpreter argument.
    pub interpreters: &'static [(Location, Option<&'static str>)],
    /// The arguments after the name of the executable.
    pub arguments: &'static [Part],
    /// The only entries of the environment.
    pub environment: &'static [(&'static str, Part)],
    /// The deadline of the command, in seconds.
    pub deadline_seconds: u64,
    /// The expected effect statement.
    pub effect: &'static str,
    /// The consequence of the command.
    pub regeneration: &'static str,
    /// Whether the measurement is of the whole cache while the producer
    /// removes only a part of it.
    pub whole_cache: bool,
    /// The root when the configuration names no location and this source
    /// names a list of paths: the child path below the first path, as Go
    /// makes `GOMODCACHE` from `GOPATH`. `None`: the default of the root.
    pub default_below: Option<(ConfigSource, &'static str)>,
    /// The guard.
    pub guard: Guard,
    /// The executable file names of the processes of the producer: a
    /// process of the user with one of them makes the producer active, and
    /// the coordinator then starts no command. A name that ends with `*` is
    /// a prefix. A script producer runs as its interpreter, so the names
    /// include the interpreter, and each process of that interpreter
    /// inhibits the command.
    pub processes: &'static [&'static str],
    /// The markers of the producer: the scope root must have one of them
    /// at the plan, at admission, and before the step. An empty list binds
    /// no scope.
    pub markers: &'static [Marker],
    /// The lookup decision: how the root is found, and why no query of
    /// the producer runs.
    pub lookup: &'static str,
    /// What a configured location names for the rule
    /// ([`LocationForm`]). A rule with an owner operation takes `Itself`
    /// when a fixed argument or variable of its command names the scope
    /// root, and the configured location is then the scope root.
    pub location: LocationForm,
}

fn location(location: Location) -> Result<ExecutableLocation, RegistryError> {
    let (base, text): (ExecutableBase, &str) = match location {
        Location::Absolute(path) => (ExecutableBase::Absolute, path),
        Location::Home(path) => (ExecutableBase::UserHome, path),
    };
    Ok(ExecutableLocation {
        base,
        path: LosslessPath::from_bytes(text)
            .map_err(|_| RegistryError::Declaration("an executable path"))?,
    })
}

/// The owner-operation declaration of `spec` for the rule revision
/// `rule`, with `executables` and `interpreters`.
fn declaration(
    spec: &ProducerSpec,
    rule: RuleRef,
    executables: Vec<ExecutableLocation>,
    interpreters: Vec<InterpreterLocation>,
) -> Result<OwnerOperation, RegistryError> {
    Checked::new(OwnerOperationDeclaration {
        rule,
        executables,
        interpreters,
        commands: vec![OwnerCommand {
            kind: spec.kind,
            arguments: spec.arguments.iter().map(|part| part.parameter()).collect(),
            bound: spec.bound,
            expected_effect: spec.effect.to_owned(),
        }],
        environment: spec
            .environment
            .iter()
            .map(|(name, value)| EnvironmentDeclaration {
                name: (*name).to_owned(),
                value: value.parameter(),
            })
            .collect(),
        command_deadline: Nanoseconds::new(spec.deadline_seconds * 1_000_000_000),
    })
    .map_err(|_| RegistryError::Declaration("an owner-operation declaration"))
}

/// The declared executables and interpreters of `spec`.
fn declared_programs(
    spec: &ProducerSpec,
) -> Result<(Vec<ExecutableLocation>, Vec<InterpreterLocation>), RegistryError> {
    let executables: Vec<ExecutableLocation> = spec
        .executables
        .iter()
        .map(|entry| location(*entry))
        .collect::<Result<_, _>>()?;
    let interpreters: Vec<InterpreterLocation> = spec
        .interpreters
        .iter()
        .map(|(entry, argument)| {
            Ok(InterpreterLocation {
                location: location(*entry)?,
                argument: argument.map(str::to_owned),
            })
        })
        .collect::<Result<_, RegistryError>>()?;
    Ok((executables, interpreters))
}

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The root of the declaration of `spec`: the default below the home
/// directory, as a discovery hint.
fn declared_root(spec: &ProducerSpec) -> Result<ApprovedRoot, RegistryError> {
    Ok(ApprovedRoot {
        base: RootBase::ProducerConfiguration,
        relative: LosslessPath::from_bytes(spec.root.default)
            .map_err(|_| RegistryError::Declaration("a root"))?,
    })
}

/// The rule declaration of a rule of this module with its own declaration.
/// The layout is `proposed`; the modes are the inspection and the manual
/// eviction, which an owner operation uses.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them.
fn own_declaration(
    spec: &ProducerSpec,
    rebuild_cost: RebuildCost,
) -> Result<RuleDeclaration, RegistryError> {
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(spec.id)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(OWN_RULE_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: spec.producer.to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts: vec![LayoutSupport {
            layout: spec.layout.to_owned(),
            lifecycle: LifecycleState::Proposed,
        }],
        roots: vec![declared_root(spec)?],
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(7 * DAY),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::ProducerProcessAbsent],
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: Nanoseconds::new(30_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::Directory],
            skip_hard_linked: false,
        },
        modes: vec![RuleMode::Inspection, RuleMode::ManualEviction],
        deletion_method: DeletionMethod::ProducerOperation,
        executor: ExecutorRole::User,
        rebuild_cost,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            per_pass: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// The new revision of the rule `base` with the owner operation of
/// `spec`: the revision [`EXTENDED_RULE_REVISION`], the layout of the
/// scope root (`proposed`), the mode `manual_eviction`, and the root of
/// `spec` when the declaration does not have it.
fn extended_declaration(
    base: &Rule,
    spec: &ProducerSpec,
) -> Result<RuleDeclaration, RegistryError> {
    let mut declaration: RuleDeclaration = (**base).clone();
    declaration.reference.revision = RuleRevisionId::new(EXTENDED_RULE_REVISION)
        .map_err(|_| RegistryError::Declaration("the rule revision"))?;
    declaration.layouts.push(LayoutSupport {
        layout: spec.layout.to_owned(),
        lifecycle: LifecycleState::Proposed,
    });
    if !declaration.modes.contains(&RuleMode::ManualEviction) {
        declaration.modes.push(RuleMode::ManualEviction);
    }
    let root: ApprovedRoot = declared_root(spec)?;
    if !declaration.roots.contains(&root) {
        declaration.roots.push(root);
    }
    Ok(declaration)
}

/// The report of the scope root of one rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeReport {
    /// How the path was found.
    pub resolution: RootResolution,
    /// The path, when the resolution gave one.
    pub path: Option<PathBuf>,
    /// The result of the checks of the root.
    pub outcome: RootOutcome,
    /// The binding of the root, when the checks passed.
    #[serde(skip)]
    pub bound: Option<BoundRoot>,
}

/// The executable that the rule binds now, or why it binds none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgramReport {
    /// The canonical path of the executable.
    pub executable: Option<LosslessPath>,
    /// The canonical path of the interpreter of a script.
    pub interpreter: Option<LosslessPath>,
    /// The interpreter argument of the `#!` line.
    pub interpreter_arguments: Vec<String>,
    /// Why no executable is bound: a stable name.
    pub problem: Option<&'static str>,
}

/// The read-only inspection of one rule with an owner operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// The producer.
    pub producer: &'static str,
    /// The layout of the scope root with its lifecycle state.
    pub layout: LayoutSupport,
    /// The kind of the command.
    pub kind: OwnerOperationKind,
    /// Whether a plan needs `--include-clear`: true for the kind `clear`.
    pub needs_include_clear: bool,
    /// The bound of the command.
    pub bound: OwnerOperationBound,
    /// Why the review gave the bound.
    pub bound_reason: &'static str,
    /// The scope root.
    pub scope: ScopeReport,
    /// The executable.
    pub program: ProgramReport,
    /// The arguments after the name of the executable. A scope root with
    /// no path is the text `<scope root>`.
    pub arguments: Vec<String>,
    /// The only entries of the environment.
    pub environment: Vec<EnvironmentEntry>,
    /// The deadline of the command.
    pub deadline: Nanoseconds,
    /// The measurement of the scope, when the root passed its checks.
    pub measured: Option<ScopeMeasurement>,
    /// Whether the measurement is of the whole cache while the producer
    /// removes only a part of it.
    pub whole_cache: bool,
    /// The result of the guard.
    pub guard: GuardOutcome,
    /// The expected effect statement.
    pub effect: &'static str,
    /// The consequence of the command.
    pub regeneration: &'static str,
    /// How the root is found.
    pub lookup: &'static str,
}

/// The request of one binding.
#[derive(Debug, Clone, Copy)]
pub struct ProducerBindRequest<'a> {
    /// The user, the locations, and the user exclusions.
    pub host: InspectionHost<'a>,
    /// The explicit consent of the user to a `clear` command
    /// (`--include-clear`).
    pub include_clear: bool,
    /// The largest executable that the builder reads for its digest.
    pub max_executable_bytes: u64,
    /// The bounds of the measurement of the scope.
    pub scope_limits: ScopeLimits,
}

/// The binding of one rule, with the scope root that it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerBinding {
    /// The binding of the target.
    pub binding: OwnerOperationBinding,
    /// The scope root.
    pub root: BoundRoot,
    /// The report of the scope root.
    pub scope: ScopeReport,
    /// The result of the guard.
    pub guard: GuardOutcome,
}

/// Why a rule gives no binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerBindError {
    /// The command has the kind `clear`, and the request has no
    /// `--include-clear`.
    ClearNotIncluded,
    /// The scope root has no path or failed a check.
    NoScope(Box<ScopeReport>),
    /// The guard refused the operation.
    Guard(GuardOutcome),
    /// The binding of the command failed.
    Bind(OwnerBindError),
}

/// One rule with an owner operation: its checked rule declaration, its
/// owner-operation declaration, and its reviewed facts.
#[derive(Debug, Clone)]
pub struct ProducerRule {
    rule: Rule,
    operation: OwnerOperation,
    spec: &'static ProducerSpec,
}

/// The text of a scope root with no path in an inspection.
const NO_ROOT: &str = "<scope root>";

impl ProducerRule {
    /// Makes the rule of `spec`: from `base` for a rule of
    /// [`ProducerBase::Cache`] or [`ProducerBase::OwnerTool`], else from
    /// its own declaration.
    fn new(spec: &'static ProducerSpec, base: Option<&Rule>) -> Result<Self, RegistryError> {
        let declaration: RuleDeclaration = match (spec.base, base) {
            (ProducerBase::Own { rebuild_cost }, None) => own_declaration(spec, rebuild_cost)?,
            (ProducerBase::Cache | ProducerBase::OwnerTool, Some(base)) => {
                extended_declaration(base, spec)?
            }
            _ => return Err(RegistryError::Declaration("the base of a producer rule")),
        };
        let rule: Rule = Checked::new(declaration).map_err(RegistryError::Incomplete)?;
        let (executables, interpreters) = declared_programs(spec)?;
        let operation: OwnerOperation = declaration_for(spec, &rule, executables, interpreters)?;
        Ok(Self {
            rule,
            operation,
            spec,
        })
    }

    /// The checked rule declaration.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// The owner-operation declaration.
    pub fn operation(&self) -> &OwnerOperation {
        &self.operation
    }

    /// The reviewed facts.
    pub fn spec(&self) -> &'static ProducerSpec {
        self.spec
    }

    /// The layout of the scope root, with its lifecycle state.
    pub fn layout(&self) -> Option<&LayoutSupport> {
        self.rule
            .layouts
            .iter()
            .find(|support| support.layout == self.spec.layout)
    }

    /// Whether the declaration is of a rule of another module in a new
    /// revision, so the registry lists it with that module.
    pub fn extends(&self) -> bool {
        !matches!(self.spec.base, ProducerBase::Own { .. })
    }

    /// The rule with `lifecycle` for the layout of the scope root, at most
    /// [`LifecycleState::ManualActionValidated`]: this build has no
    /// automatic plan of an owner operation. The other layouts keep their
    /// state.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_lifecycle(&self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        let manual: LifecycleState = match lifecycle {
            LifecycleState::AutomaticEvictionValidated { evidence } => {
                LifecycleState::ManualActionValidated {
                    evidence: evidence.clone(),
                }
            }
            other => other.clone(),
        };
        let mut declaration: RuleDeclaration = (*self.rule).clone();
        for support in &mut declaration.layouts {
            if support.layout == self.spec.layout {
                support.lifecycle = manual.clone();
            }
        }
        Ok(Self {
            rule: Checked::new(declaration).map_err(RegistryError::Incomplete)?,
            operation: self.operation.clone(),
            spec: self.spec,
        })
    }

    /// The rule whose executable is the file of the same name in
    /// `directory`, a script of `/bin/sh`, for a fixture test that never
    /// runs a producer tool.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_fixture_executable(&self, directory: &Path) -> Result<Self, RegistryError> {
        let name: &str = self
            .spec
            .executables
            .first()
            .map(|entry| match entry {
                Location::Absolute(path) | Location::Home(path) => *path,
            })
            .and_then(|path| path.rsplit('/').next())
            .ok_or(RegistryError::Declaration("an executable name"))?;
        let executable: ExecutableLocation = ExecutableLocation {
            base: ExecutableBase::Absolute,
            path: LosslessPath::from_path(&directory.join(name))
                .map_err(|_| RegistryError::Declaration("a fixture path"))?,
        };
        let interpreter: InterpreterLocation = InterpreterLocation {
            location: location(Location::Absolute("/bin/sh"))?,
            argument: None,
        };
        Ok(Self {
            rule: self.rule.clone(),
            operation: declaration_for(self.spec, &self.rule, vec![executable], vec![interpreter])?,
            spec: self.spec,
        })
    }

    /// Resolves and checks the scope root below the home directory of
    /// `host`.
    #[must_use]
    pub fn scope(&self, host: &InspectionHost<'_>) -> ScopeReport {
        let Some(home) = host.locations.home_directory() else {
            return ScopeReport {
                resolution: RootResolution::HomeUnknown,
                path: None,
                outcome: RootOutcome::NoPath,
                bound: None,
            };
        };
        let Ok(mounts) = MountTable::read() else {
            return ScopeReport {
                resolution: RootResolution::MountTableUnavailable,
                path: None,
                outcome: RootOutcome::Refused("root_locality_unknown"),
                bound: None,
            };
        };
        let (resolution, path) = resolve(self.spec.root, home, host.principal, &mounts);
        let (resolution, path) = match (&resolution, self.spec.default_below) {
            (RootResolution::Default, Some((source, child))) => {
                match read_source(&source, home, host.principal, &mounts) {
                    ConfigValue::NotSet => (resolution, path),
                    ConfigValue::Problem(problem) => (
                        RootResolution::NotResolved {
                            file: home.join(source.file),
                            key: source.key,
                            problem,
                        },
                        None,
                    ),
                    ConfigValue::Set(raw) => match paths_of(&raw, &source, home) {
                        Ok(paths) if !paths.is_empty() => (
                            RootResolution::Configured {
                                file: home.join(source.file),
                                key: source.key,
                            },
                            paths.first().map(|first| first.join(child)),
                        ),
                        Ok(_) => (resolution, path),
                        Err(problem) => (
                            RootResolution::NotResolved {
                                file: home.join(source.file),
                                key: source.key,
                                problem,
                            },
                            None,
                        ),
                    },
                }
            }
            _ => (resolution, path),
        };
        // A configured location is the scope root, in place of the root of
        // the configuration files of the producer or the default. It has
        // the checks below, and the checks of a location first.
        let configured: Vec<PathBuf> = locations_of(host.cache_locations, self.spec.id);
        let (resolution, path) = match (self.spec.location, configured.first()) {
            (LocationForm::Itself, Some(location)) => {
                if let Some(code) = location_refusal(location, home, host.locations) {
                    return ScopeReport {
                        resolution: RootResolution::ConfiguredLocation,
                        path: Some(location.clone()),
                        outcome: RootOutcome::Refused(code),
                        bound: None,
                    };
                }
                (RootResolution::ConfiguredLocation, Some(location.clone()))
            }
            _ => (resolution, path),
        };
        let Some(path) = path else {
            return ScopeReport {
                resolution,
                path: None,
                outcome: RootOutcome::NoPath,
                bound: None,
            };
        };
        let (outcome, bound) =
            match check_scope_root(self.spec.exclusions, &path, host, home, &mounts) {
                Ok(_) if !self.has_marker(&path, host.principal) => {
                    (RootOutcome::Refused(OWNER_SCOPE_UNMARKED), None)
                }
                Ok(bound) => (RootOutcome::Examined, Some(bound)),
                Err(outcome) => (outcome, None),
            };
        ScopeReport {
            resolution,
            path: Some(path),
            outcome,
            bound,
        }
    }

    /// The result of the guard of the rule.
    #[must_use]
    pub fn guard(&self, home: &Path, principal: Uid) -> GuardOutcome {
        guard_of(self.spec, home, principal)
    }

    /// Whether the scope root at `root` has a marker of the producer.
    #[must_use]
    pub fn has_marker(&self, root: &Path, principal: Uid) -> bool {
        marked(self.spec, root, principal)
    }

    /// The read-only inspection of the rule: the scope root, the
    /// executable, the command, the measurement of the scope, and the
    /// guard. It runs no command and changes nothing.
    #[must_use]
    pub fn inspect(
        &self,
        host: &InspectionHost<'_>,
        max_executable_bytes: u64,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> OwnerInspection {
        let scope: ScopeReport = self.scope(host);
        let home: Option<&Path> = host.locations.home_directory();
        let program: ProgramReport = match home {
            Some(home) => {
                match resolve_program(&self.operation, home, host.principal, max_executable_bytes) {
                    Ok((executable, interpreter)) => ProgramReport {
                        executable: Some(executable.path),
                        interpreter_arguments: interpreter
                            .as_ref()
                            .map_or_else(Vec::new, |found| found.arguments.clone()),
                        interpreter: interpreter.map(|found| found.executable.path),
                        problem: None,
                    },
                    Err(error) => ProgramReport {
                        executable: None,
                        interpreter: None,
                        interpreter_arguments: Vec::new(),
                        problem: Some(error.as_str()),
                    },
                }
            }
            None => ProgramReport {
                executable: None,
                interpreter: None,
                interpreter_arguments: Vec::new(),
                problem: Some("home_directory_unknown"),
            },
        };
        let root_text: String = scope
            .path
            .as_ref()
            .and_then(|path| path.to_str())
            .map_or_else(|| NO_ROOT.to_owned(), str::to_owned);
        let home_text: String = home
            .and_then(Path::to_str)
            .map_or_else(|| "<home>".to_owned(), str::to_owned);
        let values = ParameterValues {
            scope_root: &root_text,
            home_directory: &home_text,
        };
        let arguments: Vec<String> = self
            .operation
            .command(self.spec.kind)
            .map_or_else(Vec::new, |command| command.resolved_arguments(&values));
        let measured: Option<ScopeMeasurement> = scope.bound.as_ref().and_then(|bound| {
            measure_scope(&bound.binding.path, ScopeLimits::default(), cancel, clock)
        });
        let guard: GuardOutcome =
            home.map_or(GuardOutcome::None, |home| self.guard(home, host.principal));
        OwnerInspection {
            rule: self.rule.reference.clone(),
            producer: self.spec.producer,
            layout: self.layout().cloned().unwrap_or_else(|| LayoutSupport {
                layout: self.spec.layout.to_owned(),
                lifecycle: LifecycleState::Proposed,
            }),
            kind: self.spec.kind,
            needs_include_clear: matches!(self.spec.kind, OwnerOperationKind::Clear),
            bound: self.spec.bound,
            bound_reason: self.spec.bound_reason,
            scope,
            program,
            arguments,
            environment: self.operation.resolved_environment(&values),
            deadline: self.operation.command_deadline,
            measured,
            whole_cache: self.spec.whole_cache,
            guard,
            effect: self.spec.effect,
            regeneration: self.spec.regeneration,
            lookup: self.spec.lookup,
        }
    }

    /// Binds the command of the rule to its scope root.
    ///
    /// # Errors
    ///
    /// Returns [`ProducerBindError::ClearNotIncluded`] for a `clear`
    /// command with no consent, [`ProducerBindError::NoScope`] when the
    /// scope root has no path or fails a check,
    /// [`ProducerBindError::Guard`] when the guard refuses, and
    /// [`ProducerBindError::Bind`] with the error of
    /// [`bind_owner_operation`].
    pub fn bind(
        &self,
        request: &ProducerBindRequest<'_>,
        cancel: &CancellationToken,
        clock: &dyn ScanClock,
    ) -> Result<ProducerBinding, ProducerBindError> {
        let is_clear: bool = matches!(self.spec.kind, OwnerOperationKind::Clear);
        if is_clear && !request.include_clear {
            return Err(ProducerBindError::ClearNotIncluded);
        }
        let scope: ScopeReport = self.scope(&request.host);
        let (Some(bound), Some(home)) =
            (scope.bound.clone(), request.host.locations.home_directory())
        else {
            return Err(ProducerBindError::NoScope(Box::new(scope)));
        };
        let guard: GuardOutcome = self.guard(home, request.host.principal);
        if !guard.permits() {
            return Err(ProducerBindError::Guard(guard));
        }
        let approved: ScopeRoot = bound
            .approved()
            .map_err(|_| ProducerBindError::Bind(OwnerBindError::PathNotUtf8))?;
        let binding: OwnerOperationBinding = bind_owner_operation(
            &OwnerBindRequest {
                declaration: &self.operation,
                kind: self.spec.kind,
                clear_opt_in: is_clear,
                scope: &approved,
                layout: self.spec.layout,
                home_directory: home,
                principal: request.host.principal,
                max_executable_bytes: request.max_executable_bytes,
                scope_limits: request.scope_limits,
            },
            cancel,
            clock,
        )
        .map_err(ProducerBindError::Bind)?;
        Ok(ProducerBinding {
            binding,
            root: bound,
            scope,
            guard,
        })
    }
}

/// The owner-operation declaration of `spec` for the revision of `rule`.
fn declaration_for(
    spec: &ProducerSpec,
    rule: &Rule,
    executables: Vec<ExecutableLocation>,
    interpreters: Vec<InterpreterLocation>,
) -> Result<OwnerOperation, RegistryError> {
    declaration(spec, rule.reference.clone(), executables, interpreters)
}

/// The result of the guard of `spec`.
fn guard_of(spec: &ProducerSpec, home: &Path, principal: Uid) -> GuardOutcome {
    match spec.guard {
        Guard::None => GuardOutcome::None,
        Guard::MiseTrackedConfigs => mise_tracked_configs(home, principal),
        Guard::HomebrewSystemEnv => homebrew_system_env(&HOMEBREW_SYSTEM_ENV_FILES),
    }
}

/// Whether the scope root at `root` has a marker of the producer of
/// `spec`. A spec with no marker binds no scope.
fn marked(spec: &ProducerSpec, root: &Path, principal: Uid) -> bool {
    spec.markers
        .iter()
        .any(|marker| has_marker(root, *marker, principal))
}

/// The checks of the scope root of an owner operation of the rule `rule`
/// at admission and immediately before its step
/// (`docs/CLEANUP_RULES.md` section 9): the marker of the producer and the
/// guards. A rule that is not of this module passes.
///
/// # Errors
///
/// Returns the stable code of the first check that fails:
/// [`OWNER_SCOPE_UNMARKED`], [`OWNER_GUARD_REFUSED`], or
/// [`HOMEBREW_ENV_OVERRIDES`].
pub fn scope_evidence(
    rule: &RuleRef,
    root: &Path,
    home: &Path,
    principal: Uid,
) -> Result<(), &'static str> {
    let Some(spec) = PRODUCER_SPECS
        .iter()
        .find(|spec| spec.id == rule.id.as_str())
    else {
        return Ok(());
    };
    if !marked(spec, root, principal) {
        return Err(OWNER_SCOPE_UNMARKED);
    }
    match guard_of(spec, home, principal) {
        GuardOutcome::None | GuardOutcome::Passed { .. } => Ok(()),
        GuardOutcome::Refused { reason, .. } => Err(guard_code(reason)),
    }
}

/// The stable code of a guard that refused with `reason`.
#[must_use]
pub fn guard_code(reason: &'static str) -> &'static str {
    if reason == HOMEBREW_ENV_OVERRIDES {
        HOMEBREW_ENV_OVERRIDES
    } else {
        OWNER_GUARD_REFUSED
    }
}

/// The executable names of the producer of the rule `id`, when `id` is a
/// rule of this module ([`ProducerSpec::processes`]).
#[must_use]
pub fn producer_process_names(id: &str) -> Option<&'static [&'static str]> {
    PRODUCER_SPECS
        .iter()
        .find(|spec| spec.id == id)
        .map(|spec| spec.processes)
}

/// The rules of this module. `base` gives the declaration of a rule of
/// another module by its identity.
///
/// # Errors
///
/// Returns a [`RegistryError`] when a declaration is not complete or a
/// base rule is not registered.
pub(super) fn producer_rules<'a>(
    base: impl Fn(&str) -> Option<&'a Rule>,
) -> Result<Vec<ProducerRule>, RegistryError> {
    PRODUCER_SPECS
        .iter()
        .map(|spec| {
            let found: Option<&Rule> = match spec.base {
                ProducerBase::Own { .. } => None,
                ProducerBase::Cache | ProducerBase::OwnerTool => Some(
                    base(spec.id)
                        .ok_or(RegistryError::Declaration("the base of a producer rule"))?,
                ),
            };
            ProducerRule::new(spec, found)
        })
        .collect()
}
