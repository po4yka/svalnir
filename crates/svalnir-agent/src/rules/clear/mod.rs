//! The clear rules of `docs/CLEANUP_RULES.md` section 12, "Clear rules".
//!
//! A clear rule is for a producer that has no cleanup command that is safe
//! to run: the rule removes the contents of one cache directory of the
//! producer, also data that a project uses now, so that the next build
//! downloads or makes it again. A clear rule is manual only (owner decision
//! of 2026-11-22):
//!
//! - Its declaration has the inspection mode and the manual eviction, and
//!   no automatic mode. A fixture lifecycle state of a test build gives it
//!   at most `manual_action_validated`.
//! - The discovery for an eviction examines it only for a manual eviction,
//!   never for known candidates (an automatic operation), and
//!   [`crate::rules::automatic_roots`] approves none of its roots.
//! - A client plans it only when the user gives the explicit consent
//!   (`clean plan --mode evict --include-clear`).
//!
//! Each layout is `proposed`: no validation record exists, so a released
//! build refuses the `evict` mode for each clear rule.
//!
//! # Roots
//!
//! The root of a rule is the cache directory whose contents the rule
//! removes. It comes from the documented default location of the producer
//! below the home directory ([`ClearSpec::roots`]), or, for
//! `maven.repository`, from `localRepository` of `~/.m2/settings.xml`. The
//! rule runs no producer tool (`zig env`, `gem env`, `deno info`) and
//! reads no environment variable: the environment of the agent or of a
//! client is not the environment of the shell of the user. A location that
//! only an environment variable moves (`CARGO_HOME`, `GRADLE_USER_HOME`,
//! `DENO_DIR`, `ZIG_GLOBAL_CACHE_DIR`, `HEX_HOME`, `REBAR_CACHE_DIR`,
//! `NUGET_PACKAGES`) is not covered. A component `*` of a default location
//! stands for each directory at that place, to a bound, for example each
//! Ruby version of `~/.rbenv/versions`.
//!
//! # Units
//!
//! A unit is one child of a root. The root itself is never a unit, so the
//! directory stays and only its contents go. A child whose name the rule
//! keeps ([`ClearSpec::keep`]) is never a unit. A unit that holds a Git
//! repository at any depth is refused by the measurement and by the
//! executor (section 6, "Repositories in a unit"), and a unit with a file
//! of [`ClearSpec::refuse_names`] at any depth is refused with
//! `protected_data`.

mod discover;

#[cfg(test)]
mod tests;

use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{RuleId, RuleRevisionId};
use svalnir_core::policy::RebuildCost;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};

pub use discover::recheck_unit;
pub(in crate::rules) use discover::{ClearDiscoveryInput, ProducerEvidence};

use super::registry::RegistryError;

/// The revision of each rule of this module.
pub const CLEAR_RULE_REVISION: &str = "r1";

/// The identity of the rule for the registry cache of Cargo.
pub const CARGO_REGISTRY_RULE_ID: &str = "cargo.registry-cache";
/// The identity of the rule for the caches of the Gradle user home.
pub const GRADLE_CACHES_RULE_ID: &str = "gradle.caches";
/// The identity of the rule for the local repository of Maven.
pub const MAVEN_REPOSITORY_RULE_ID: &str = "maven.repository";
/// The identity of the rule for the `.gem` copies of `RubyGems`.
pub const RUBYGEMS_CACHE_RULE_ID: &str = "rubygems.cache";
/// The identity of the rule for the remote modules of Deno.
pub const DENO_REMOTE_RULE_ID: &str = "deno.remote";
/// The identity of the rule for the npm cache of Deno.
pub const DENO_NPM_RULE_ID: &str = "deno.npm";
/// The identity of the rule for the emitted code of Deno.
pub const DENO_GEN_RULE_ID: &str = "deno.gen";
/// The identity of the rule for the global packages of `NuGet`.
pub const NUGET_PACKAGES_RULE_ID: &str = "nuget.packages";
/// The identity of the rule for the HTTP cache of `NuGet`.
pub const NUGET_HTTP_CACHE_RULE_ID: &str = "nuget.http-cache";
/// The identity of the rule for the shared cache of Swift Package Manager.
pub const SWIFTPM_CACHE_RULE_ID: &str = "swiftpm.cache";
/// The identity of the rule for the global cache of Zig.
pub const ZIG_GLOBAL_CACHE_RULE_ID: &str = "zig.global-cache";
/// The identity of the rule for the package cache of Hex.
pub const HEX_PACKAGES_RULE_ID: &str = "hex.packages";
/// The identity of the rule for the Hex cache of rebar3.
pub const REBAR3_HEX_RULE_ID: &str = "rebar3.hex";
/// The identity of the rule for the install cache of Bun.
pub const BUN_CACHE_RULE_ID: &str = "bun.cache";

/// The largest number of roots of one rule after the expansion of the
/// components `*`. The expansion stops at this bound, and the report says
/// that it is not complete.
pub const MAX_EXPANDED_ROOTS: usize = 32;

/// The largest size of `~/.m2/settings.xml` that the rule reads.
pub const MAX_SETTINGS_BYTES: u64 = 256 * 1024;

/// What a child of a root must be to be a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitForm {
    /// A directory or a regular file.
    Any,
    /// A regular file whose name ends with `.gem`. Each other child is
    /// skipped with `unsupported_layout`.
    GemFile,
    /// An artifact directory of a Maven repository, at some depth below the
    /// root: a directory `GROUP/.../ARTIFACT` with a version directory
    /// `VERSION` that holds a file `ARTIFACT-*.pom` or `ARTIFACT-*.jar`
    /// ([`is_artifact_directory`]). The walk to the artifact directories is
    /// bounded; a group directory, and an entry that is in no artifact
    /// directory, is never a unit. A unit with a `_remote.repositories`
    /// record that names no remote repository is refused, as a local
    /// install ([`has_local_install_record`]).
    MavenArtifact,
}

/// A configuration file of the producer that can name the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootConfiguration {
    /// `localRepository` of `~/.m2/settings.xml`.
    MavenSettings,
}

/// The reviewed facts of one clear rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearSpec {
    /// The rule identity.
    pub id: &'static str,
    /// The producer.
    pub producer: &'static str,
    /// The one layout of the rule.
    pub layout: &'static str,
    /// The default roots, relative to the home directory. A component `*`
    /// stands for each directory at that place.
    pub roots: &'static [&'static str],
    /// A configuration file that can name the root in place of the
    /// defaults.
    pub configuration: Option<RootConfiguration>,
    /// The names of the children of a root that are never a unit.
    pub keep: &'static [&'static str],
    /// The file names that refuse a unit that has one at any depth.
    pub refuse_names: &'static [&'static str],
    /// What a child must be to be a unit.
    pub units: UnitForm,
    /// The file names of the executables of the producer. A process of the
    /// user with one of them blocks the discovery and each step.
    pub processes: &'static [&'static str],
    /// The cost to make the data again.
    pub rebuild_cost: RebuildCost,
    /// The data of the producer that the rule keeps, as a text for the
    /// user.
    pub kept: &'static str,
    /// The consequence of a removal, as a text for the user.
    pub regeneration: &'static str,
}

/// The executables of a Java build tool: the Gradle daemon and Maven run in
/// `java`, and the rule cannot tell them from another Java process.
const JAVA: &[&str] = &["java"];

/// The executables of the BEAM virtual machine, in which `mix` and `rebar3`
/// run.
const BEAM: &[&str] = &["beam.smp", "beam"];

/// The rule `cargo.registry-cache`.
pub const CARGO_REGISTRY: ClearSpec = ClearSpec {
    id: CARGO_REGISTRY_RULE_ID,
    producer: "cargo",
    layout: "cargo-registry-v1",
    roots: &[".cargo/registry/cache", ".cargo/registry/src"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["cargo", "rustc"],
    rebuild_cost: RebuildCost::Medium,
    kept: "`~/.cargo/registry/index`, `~/.cargo/git` (its checkouts can hold work), `~/.cargo/bin`, and the configuration and credentials of the Cargo home stay.",
    regeneration: "The next build downloads each removed crate archive again and extracts its source; it needs a registry that is still available, and `cargo build --offline` fails for a crate whose archive is gone.",
};

/// The rule `gradle.caches`.
pub const GRADLE_CACHES: ClearSpec = ClearSpec {
    id: GRADLE_CACHES_RULE_ID,
    producer: "gradle",
    layout: "gradle-user-caches-v1",
    roots: &[".gradle/caches"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: JAVA,
    rebuild_cost: RebuildCost::Medium,
    kept: "`gradle.properties` (it can hold credentials), `init.d`, `wrapper/dists`, `jdks`, `daemon`, and `native` of `~/.gradle` stay.",
    regeneration: "The next build downloads each dependency again, runs each artifact transform again, and has an empty local build cache, so it runs each task.",
};

/// The rule `maven.repository`.
pub const MAVEN_REPOSITORY: ClearSpec = ClearSpec {
    id: MAVEN_REPOSITORY_RULE_ID,
    producer: "maven",
    layout: "maven-local-repository-v1",
    roots: &[".m2/repository"],
    configuration: Some(RootConfiguration::MavenSettings),
    keep: &[],
    refuse_names: &["maven-metadata-local.xml"],
    units: UnitForm::MavenArtifact,
    processes: JAVA,
    rebuild_cost: RebuildCost::Medium,
    kept: "`settings.xml`, `settings-security.xml`, `toolchains.xml`, and `extensions.xml` of `~/.m2` stay, and so does each artifact directory with a local install (`maven-metadata-local.xml`, or a `_remote.repositories` record with no remote repository).",
    regeneration: "The next build downloads each removed artifact again and needs a remote repository that still has it; an offline build fails for an artifact that is gone.",
};

/// The rule `rubygems.cache`.
pub const RUBYGEMS_CACHE: ClearSpec = ClearSpec {
    id: RUBYGEMS_CACHE_RULE_ID,
    producer: "rubygems",
    layout: "rubygems-gem-cache-v1",
    roots: &[
        ".gem/ruby/*/cache",
        ".local/share/gem/ruby/*/cache",
        ".rbenv/versions/*/lib/ruby/gems/*/cache",
        ".asdf/installs/ruby/*/lib/ruby/gems/*/cache",
        ".local/share/mise/installs/ruby/*/lib/ruby/gems/*/cache",
    ],
    configuration: None,
    keep: &["bundler"],
    refuse_names: &[],
    units: UnitForm::GemFile,
    processes: &["ruby"],
    rebuild_cost: RebuildCost::Low,
    kept: "The installed gems, `cache/bundler` (Bundler keeps a bare clone of each Git source there, which can hold commits that the remote no longer has), and each child of the cache that is not a `.gem` file stay.",
    regeneration: "`gem pristine` and `gem install` download a removed `.gem` file again; `bundle cache` without `--all-platforms` fails for a gem whose copy is gone.",
};

/// The rule `deno.remote`.
pub const DENO_REMOTE: ClearSpec = ClearSpec {
    id: DENO_REMOTE_RULE_ID,
    producer: "deno",
    layout: "deno-remote-v1",
    roots: &["Library/Caches/deno/remote", "Library/Caches/deno/deps"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["deno"],
    rebuild_cost: RebuildCost::Low,
    kept: "`location_data` (the localStorage and Cache API data of each script), `deno_history.txt` (the REPL history), and each other entry of the Deno directory stay.",
    regeneration: "The next run downloads each removed remote module again and needs the server that still serves it; `--cached-only` fails for a module that is gone.",
};

/// The rule `deno.npm`.
pub const DENO_NPM: ClearSpec = ClearSpec {
    id: DENO_NPM_RULE_ID,
    producer: "deno",
    layout: "deno-npm-v1",
    roots: &["Library/Caches/deno/npm"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["deno"],
    rebuild_cost: RebuildCost::Low,
    kept: "`location_data`, `deno_history.txt`, and each other entry of the Deno directory stay.",
    regeneration: "The next run downloads each removed npm package again and needs a registry that is still available.",
};

/// The rule `deno.gen`.
pub const DENO_GEN: ClearSpec = ClearSpec {
    id: DENO_GEN_RULE_ID,
    producer: "deno",
    layout: "deno-gen-v1",
    roots: &["Library/Caches/deno/gen"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["deno"],
    rebuild_cost: RebuildCost::Low,
    kept: "`location_data`, `deno_history.txt`, and each other entry of the Deno directory stay.",
    regeneration: "The next run transpiles and type-checks each module again.",
};

/// The rule `nuget.packages`.
pub const NUGET_PACKAGES: ClearSpec = ClearSpec {
    id: NUGET_PACKAGES_RULE_ID,
    producer: "nuget",
    layout: "nuget-global-packages-v1",
    roots: &[".nuget/packages"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["dotnet"],
    rebuild_cost: RebuildCost::Medium,
    kept: "`NuGet.Config` and the other folders of `~/.nuget` stay.",
    regeneration: "The next `dotnet restore` downloads each removed package again and needs a feed that still has it.",
};

/// The rule `nuget.http-cache`.
pub const NUGET_HTTP_CACHE: ClearSpec = ClearSpec {
    id: NUGET_HTTP_CACHE_RULE_ID,
    producer: "nuget",
    layout: "nuget-http-cache-v1",
    roots: &[
        ".local/share/NuGet/http-cache",
        ".local/share/NuGet/v3-cache",
    ],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["dotnet"],
    rebuild_cost: RebuildCost::Low,
    kept: "The global packages and the other folders of `~/.local/share/NuGet` stay.",
    regeneration: "The next restore asks each feed again for the removed responses.",
};

/// The rule `swiftpm.cache`.
pub const SWIFTPM_CACHE: ClearSpec = ClearSpec {
    id: SWIFTPM_CACHE_RULE_ID,
    producer: "swiftpm",
    layout: "swiftpm-shared-cache-v1",
    roots: &["Library/Caches/org.swift.swiftpm"],
    configuration: None,
    keep: &["artifacts", "prebuilts"],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &[
        "swift-build",
        "swift-package",
        "swift-frontend",
        "xcodebuild",
        "Xcode",
    ],
    rebuild_cost: RebuildCost::Medium,
    kept: "`artifacts` and `prebuilts` stay; `repositories` holds bare Git mirrors, which the repository check refuses, so it also stays.",
    regeneration: "The next package resolution downloads each removed manifest and registry archive again.",
};

/// The rule `zig.global-cache`.
pub const ZIG_GLOBAL_CACHE: ClearSpec = ClearSpec {
    id: ZIG_GLOBAL_CACHE_RULE_ID,
    producer: "zig",
    layout: "zig-global-cache-v1",
    roots: &[".cache/zig"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["zig"],
    rebuild_cost: RebuildCost::Medium,
    kept: "The Zig installation and each project-local `.zig-cache` stay.",
    regeneration: "The next build compiles each removed artifact again and downloads each removed package again from the URL of its `build.zig.zon`.",
};

/// The rule `hex.packages`.
pub const HEX_PACKAGES: ClearSpec = ClearSpec {
    id: HEX_PACKAGES_RULE_ID,
    producer: "hex",
    layout: "hex-packages-v1",
    roots: &[".hex/packages"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: BEAM,
    rebuild_cost: RebuildCost::Low,
    kept: "`hex.config` (it holds the API key of the user) and the registry cache of `~/.hex` stay.",
    regeneration: "The next `mix deps.get` downloads each removed package tarball again; `HEX_OFFLINE` cannot use a tarball that is gone.",
};

/// The rule `rebar3.hex`.
pub const REBAR3_HEX: ClearSpec = ClearSpec {
    id: REBAR3_HEX_RULE_ID,
    producer: "rebar3",
    layout: "rebar3-hex-v1",
    roots: &[".cache/rebar3/hex"],
    configuration: None,
    keep: &[],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: BEAM,
    rebuild_cost: RebuildCost::Low,
    kept: "`bin` and `vsns` (the rebar3 of `rebar3 local install`) and the global plugins of `~/.cache/rebar3` stay.",
    regeneration: "The next `rebar3 get-deps` downloads the package index and each removed tarball again.",
};

/// The rule `bun.cache`.
pub const BUN_CACHE: ClearSpec = ClearSpec {
    id: BUN_CACHE_RULE_ID,
    producer: "bun",
    layout: "bun-install-cache-v1",
    roots: &[".bun/install/cache"],
    configuration: None,
    keep: &["links"],
    refuse_names: &[],
    units: UnitForm::Any,
    processes: &["bun"],
    rebuild_cost: RebuildCost::Low,
    kept: "`links` (the global link store), the global packages of `~/.bun/install/global`, and the Bun executable stay.",
    regeneration: "The next `bun install` downloads each removed package again and needs a registry that is still available.",
};

/// The specifications of this module, in the sequence of the registry
/// table of section 10.
pub const CLEAR_SPECS: [ClearSpec; 14] = [
    CARGO_REGISTRY,
    GRADLE_CACHES,
    MAVEN_REPOSITORY,
    RUBYGEMS_CACHE,
    DENO_REMOTE,
    DENO_NPM,
    DENO_GEN,
    NUGET_PACKAGES,
    NUGET_HTTP_CACHE,
    SWIFTPM_CACHE,
    ZIG_GLOBAL_CACHE,
    HEX_PACKAGES,
    REBAR3_HEX,
    BUN_CACHE,
];

const MINUTE: u64 = 60_000_000_000;
const HOUR: u64 = 60 * MINUTE;
const GIBIBYTE: u64 = 1 << 30;

/// The age after which the process evidence of a clear rule is not
/// current.
pub const CLEAR_EVIDENCE_EXPIRY: Nanoseconds = Nanoseconds::new(30_000_000_000);

/// The specification of the clear rule `id`, when `id` is one.
#[must_use]
pub fn spec_of(id: &str) -> Option<&'static ClearSpec> {
    CLEAR_SPECS.iter().find(|spec| spec.id == id)
}

/// Whether `id` is the identity of a clear rule.
#[must_use]
pub fn is_clear_rule(id: &str) -> bool {
    spec_of(id).is_some()
}

/// The executables of the producer of the clear rule `id`, when `id` is
/// one.
#[must_use]
pub fn process_names(id: &str) -> Option<&'static [&'static str]> {
    spec_of(id).map(|spec| spec.processes)
}

/// The declaration of the rule of `spec`. The layout is `proposed`; the
/// implementation has the inspection mode and the manual eviction, and no
/// automatic eviction.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3). A clear
/// rule removes data that a project can use now, so the age is only the
/// quiet time of one hour that protects a download in progress.
fn declaration(spec: &ClearSpec) -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(spec.id)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(CLEAR_RULE_REVISION)
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
        // The default locations are discovery hints: a pattern with `*` is
        // expanded by the discovery ([`resolve`]), and the approved root of
        // a manual plan is the root that the discovery bound.
        roots: spec
            .roots
            .iter()
            .map(|root| {
                Ok(ApprovedRoot {
                    base: RootBase::ProducerConfiguration,
                    relative: path(root)?,
                })
            })
            .collect::<Result<Vec<ApprovedRoot>, RegistryError>>()?,
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(HOUR),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::ProducerProcessAbsent],
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: CLEAR_EVIDENCE_EXPIRY,
        },
        exclusions: RuleExclusions {
            // The kept children, relative to each root.
            descendants: spec
                .keep
                .iter()
                .map(|name| path(name))
                .collect::<Result<Vec<LosslessPath>, RegistryError>>()?,
            supported_object_types: vec![
                FileObjectType::RegularFile,
                FileObjectType::Directory,
                FileObjectType::SymbolicLink,
            ],
            skip_hard_linked: true,
        },
        // No automatic mode: a clear rule is manual only (owner decision of
        // 2026-11-22).
        modes: vec![RuleMode::Inspection, RuleMode::ManualEviction],
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: ExecutorRole::User,
        rebuild_cost: spec.rebuild_cost,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(50 * GIBIBYTE), EntryCount::new(2_000_000)),
            per_pass: WorkCharge::new(Bytes::new(200 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// One clear rule: its checked declaration and its reviewed facts.
#[derive(Debug, Clone)]
pub struct ClearRule {
    rule: Rule,
    spec: &'static ClearSpec,
}

impl ClearRule {
    fn new(spec: &'static ClearSpec) -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration(spec)?).map_err(RegistryError::Incomplete)?;
        Ok(Self { rule, spec })
    }

    /// The rule with `lifecycle` for its layout, limited to a manual mode:
    /// a state that permits an automatic eviction becomes
    /// [`LifecycleState::ManualActionValidated`] with the same evidence.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    fn with_lifecycle(self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        let manual: LifecycleState = match lifecycle {
            LifecycleState::AutomaticEvictionValidated { evidence } => {
                LifecycleState::ManualActionValidated {
                    evidence: evidence.clone(),
                }
            }
            other => other.clone(),
        };
        Ok(Self {
            rule: super::registry::with_lifecycle(&self.rule, &manual)?,
            ..self
        })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// The reviewed facts of the rule.
    pub fn spec(&self) -> &'static ClearSpec {
        self.spec
    }
}

/// The clear rules of this build.
#[derive(Debug, Clone)]
pub struct ClearRules {
    rules: Vec<ClearRule>,
}

impl ClearRules {
    /// Makes the rules with the declarations of this build.
    pub(super) fn new() -> Result<Self, RegistryError> {
        Ok(Self {
            rules: CLEAR_SPECS
                .iter()
                .map(ClearRule::new)
                .collect::<Result<Vec<ClearRule>, RegistryError>>()?,
        })
    }

    /// The rules with `lifecycle`, limited to a manual mode. Only a test
    /// build has this function.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_lifecycle(self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        Ok(Self {
            rules: self
                .rules
                .into_iter()
                .map(|rule| rule.with_lifecycle(lifecycle))
                .collect::<Result<Vec<ClearRule>, RegistryError>>()?,
        })
    }

    /// Each rule, in the sequence of the registry table.
    pub fn all(&self) -> &[ClearRule] {
        &self.rules
    }

    /// The rule with the identity `id`.
    pub fn get(&self, id: &str) -> Option<&ClearRule> {
        self.rules
            .iter()
            .find(|rule| rule.rule.reference.id.as_str() == id)
    }

    /// The checked declarations.
    pub(super) fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(ClearRule::rule)
    }
}

/// Where the path of one root comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootSource {
    /// The documented default location, as a discovery hint.
    Default {
        /// The pattern of the default location, relative to the home
        /// directory.
        pattern: &'static str,
    },
    /// A configuration file of the producer.
    Configuration {
        /// The file, relative to the home directory.
        file: &'static str,
    },
}

/// One root of a clear rule on this host, before its binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClearRootEntry {
    /// Where the path comes from.
    pub source: RootSource,
    /// The path. `None` when the source gives no usable path.
    pub path: Option<PathBuf>,
    /// The stable reason that the source gives no path.
    pub problem: Option<&'static str>,
}

/// The roots of the rule `spec` for the home directory `home`.
///
/// The roots are the paths of [`ClearSpec::roots`], each component `*`
/// replaced by each directory at that place, in name order, to
/// [`MAX_EXPANDED_ROOTS`] roots. A directory whose name starts with `.` and
/// a symbolic link are not expanded. A pattern with no `*` gives its path
/// also when it does not exist: the binding reports that it is absent.
/// For `maven.repository`, a `localRepository` of `~/.m2/settings.xml`
/// replaces the default, as `docs/CLEANUP_RULES.md` section 12 says.
///
/// The second value is false when the expansion stopped at its bound.
#[must_use]
pub fn resolve(spec: &ClearSpec, home: &Path) -> (Vec<ClearRootEntry>, bool) {
    if spec.configuration == Some(RootConfiguration::MavenSettings) {
        match maven_local_repository(home) {
            Configured::Unset => {}
            Configured::Path(path) => {
                return (
                    vec![ClearRootEntry {
                        source: RootSource::Configuration {
                            file: MAVEN_SETTINGS,
                        },
                        path: Some(path),
                        problem: None,
                    }],
                    true,
                );
            }
            Configured::Problem(problem) => {
                return (
                    vec![ClearRootEntry {
                        source: RootSource::Configuration {
                            file: MAVEN_SETTINGS,
                        },
                        path: None,
                        problem: Some(problem),
                    }],
                    true,
                );
            }
        }
    }
    let mut entries: Vec<ClearRootEntry> = Vec::new();
    let mut complete: bool = true;
    for pattern in spec.roots {
        let source = RootSource::Default { pattern };
        if !pattern.split('/').any(|component| component == "*") {
            entries.push(ClearRootEntry {
                source,
                path: Some(home.join(pattern)),
                problem: None,
            });
            continue;
        }
        let room: usize = MAX_EXPANDED_ROOTS.saturating_sub(entries.len());
        let (paths, finished) = expand(home, pattern, room);
        complete = complete && finished;
        entries.extend(paths.into_iter().map(|path| ClearRootEntry {
            source: source.clone(),
            path: Some(path),
            problem: None,
        }));
    }
    (entries, complete)
}

/// The paths of `pattern` below `home`, at most `room`. The second value
/// is false when more paths exist.
fn expand(home: &Path, pattern: &str, room: usize) -> (Vec<PathBuf>, bool) {
    let mut current: Vec<PathBuf> = vec![home.to_path_buf()];
    let mut complete: bool = true;
    for component in pattern.split('/') {
        let mut next: Vec<PathBuf> = Vec::new();
        for base in current {
            if component != "*" {
                next.push(base.join(component));
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&base) else {
                continue;
            };
            let mut names: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| PathBuf::from(entry.file_name()))
                .filter(|name| {
                    !name.as_os_str().as_encoded_bytes().starts_with(b".")
                        && std::fs::symlink_metadata(base.join(name))
                            .is_ok_and(|metadata| metadata.is_dir())
                })
                .take(MAX_EXPANDED_ROOTS.saturating_add(1))
                .collect();
            names.sort();
            next.extend(names.into_iter().map(|name| base.join(name)));
        }
        if next.len() > MAX_EXPANDED_ROOTS {
            next.truncate(MAX_EXPANDED_ROOTS);
            complete = false;
        }
        current = next;
    }
    // A pattern gives only the paths that exist: a version directory with
    // no cache has no root.
    let mut paths: Vec<PathBuf> = current
        .into_iter()
        .filter(|path| std::fs::symlink_metadata(path).is_ok())
        .collect();
    if paths.len() > room {
        paths.truncate(room);
        complete = false;
    }
    (paths, complete)
}

/// The largest number of directories that the walk to the artifact
/// directories of a Maven repository reads.
pub const MAX_ARTIFACT_WALK_DIRECTORIES: usize = 200_000;

/// The largest depth of an artifact directory below the root.
pub const MAX_ARTIFACT_DEPTH: usize = 16;

/// The largest number of entries of one directory that the check of an
/// artifact directory reads.
const MAX_ARTIFACT_PROBE_ENTRIES: usize = 4_096;

/// The largest size of a `_remote.repositories` record that the rule reads.
pub const MAX_REMOTE_RECORD_BYTES: u64 = 64 * 1024;

/// The name of the record of Maven Resolver of the origin of each file of
/// a version directory.
pub const REMOTE_RECORD: &str = "_remote.repositories";

/// Whether `directory` is an artifact directory of a Maven repository: a
/// directory with a version directory `VERSION` (not a symbolic link) that
/// holds a regular file whose name starts with `NAME-` and ends with `.pom`
/// or `.jar`, where `NAME` is the name of `directory`. A group directory has
/// no such file one level down.
#[must_use]
pub fn is_artifact_directory(directory: &Path) -> bool {
    let Some(name) = directory.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let prefix: String = format!("{name}-");
    let Ok(versions) = std::fs::read_dir(directory) else {
        return false;
    };
    for version in versions
        .filter_map(Result::ok)
        .take(MAX_ARTIFACT_PROBE_ENTRIES)
    {
        let path: PathBuf = version.path();
        if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&path) else {
            continue;
        };
        let found: bool = files
            .filter_map(Result::ok)
            .take(MAX_ARTIFACT_PROBE_ENTRIES)
            .any(|file| {
                let name = file.file_name();
                let Some(name) = name.to_str() else {
                    return false;
                };
                name.starts_with(&prefix)
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension == "pom" || extension == "jar")
                    && std::fs::symlink_metadata(file.path())
                        .is_ok_and(|metadata| metadata.is_file())
            });
        if found {
            return true;
        }
    }
    false
}

/// Whether the `_remote.repositories` record at `path` shows a local
/// install, or cannot be read: Maven Resolver writes `FILE>REPOSITORY=` for
/// a file that it downloaded from the repository `REPOSITORY`, and
/// `FILE>=` with no repository for a file that `mvn install` put there. A
/// record that is not a regular file, that is larger than
/// [`MAX_REMOTE_RECORD_BYTES`], or that is not text is treated as a local
/// install.
#[must_use]
pub fn has_local_install_record(path: &Path) -> bool {
    let readable: bool = std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= MAX_REMOTE_RECORD_BYTES);
    if !readable {
        return true;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|line| match line.split_once('>') {
            Some((_, rest)) => rest
                .split_once('=')
                .is_none_or(|(id, _)| id.trim().is_empty()),
            None => true,
        })
}

/// The artifact directories below `root`, relative to it, in name order, at
/// most `limit`. The walk reads only directories that are not symbolic
/// links and that are on the device `device`, to [`MAX_ARTIFACT_DEPTH`]
/// and [`MAX_ARTIFACT_WALK_DIRECTORIES`]; it does not enter an artifact
/// directory or a directory whose name starts with `.`. The second value is
/// false when a bound stopped the walk or a directory could not be read.
#[must_use]
pub fn artifact_directories(root: &Path, device: u64, limit: usize) -> (Vec<PathBuf>, bool) {
    use std::os::unix::fs::MetadataExt as _;

    let mut units: Vec<PathBuf> = Vec::new();
    let mut complete: bool = true;
    let mut visited: usize = 0;
    let mut pending: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0)];
    while let Some((relative, depth)) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_ARTIFACT_WALK_DIRECTORIES {
            return (units, false);
        }
        let directory: PathBuf = root.join(&relative);
        if depth > 0 && is_artifact_directory(&directory) {
            if units.len() >= limit {
                return (units, false);
            }
            units.push(relative);
            continue;
        }
        if depth >= MAX_ARTIFACT_DEPTH {
            complete = false;
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            complete = false;
            continue;
        };
        let mut children: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            let name = entry.file_name();
            if name.as_encoded_bytes().starts_with(b".") {
                continue;
            }
            let is_directory: bool = std::fs::symlink_metadata(entry.path())
                .is_ok_and(|metadata| metadata.is_dir() && metadata.dev() == device);
            if is_directory {
                children.push(relative.join(name));
            }
        }
        // The stack takes the last name first, so the sequence of the
        // result is the name order.
        children.sort();
        pending.extend(children.into_iter().rev().map(|child| (child, depth + 1)));
    }
    (units, complete)
}

/// The settings file of Maven, relative to the home directory.
pub const MAVEN_SETTINGS: &str = ".m2/settings.xml";

/// What a configuration file says about the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::rules) enum Configured {
    /// The file does not exist or names no location.
    Unset,
    /// The file names this location.
    Path(PathBuf),
    /// The file names a location that the rule cannot use, or cannot be
    /// read. The rule then has no root: the default can be a directory
    /// that Maven no longer uses.
    Problem(&'static str),
}

/// The value of `localRepository` of `~/.m2/settings.xml`.
///
/// The file is read as text, to [`MAX_SETTINGS_BYTES`]: XML comments are
/// left out, and the one element `localRepository` gives the value. The
/// property `${user.home}` is replaced with the home directory. A value
/// with another property or an entity, a relative value, a value with a
/// `.` or `..` component, and a value that is not below the home directory
/// give a problem. Two elements give a problem.
pub(in crate::rules) fn maven_local_repository(home: &Path) -> Configured {
    let file: PathBuf = home.join(MAVEN_SETTINGS);
    let metadata = match std::fs::symlink_metadata(&file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Configured::Unset;
        }
        Err(_) => return Configured::Problem("configuration_not_readable"),
    };
    if !metadata.is_file() {
        return Configured::Problem("configuration_not_regular_file");
    }
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Configured::Problem("configuration_too_large");
    }
    let Ok(bytes) = std::fs::read(&file) else {
        return Configured::Problem("configuration_not_readable");
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Configured::Problem("configuration_not_text");
    };
    local_repository_of(&text, home)
}

/// The value of `localRepository` in the text of a settings file.
pub(in crate::rules) fn local_repository_of(text: &str, home: &Path) -> Configured {
    const OPEN: &str = "<localRepository>";
    const CLOSE: &str = "</localRepository>";
    let Some(text) = without_comments(text) else {
        return Configured::Problem("configuration_not_valid");
    };
    let mut values: Vec<&str> = Vec::new();
    let mut rest: &str = &text;
    while let Some(start) = rest.find(OPEN) {
        let after: &str = &rest[start + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else {
            return Configured::Problem("configuration_not_valid");
        };
        values.push(after[..end].trim());
        rest = &after[end + CLOSE.len()..];
    }
    let value: &str = match values.as_slice() {
        [] => return Configured::Unset,
        [value] => value,
        _ => return Configured::Problem("configuration_conflicting"),
    };
    let Some(home_text) = home.to_str() else {
        return Configured::Problem("configuration_not_resolved");
    };
    let expanded: String = value.replace("${user.home}", home_text);
    if expanded.contains("${") || expanded.contains('&') || expanded.contains('<') {
        return Configured::Problem("configuration_not_resolved");
    }
    let path: PathBuf = PathBuf::from(expanded);
    let plain: bool = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !plain {
        return Configured::Problem("configuration_not_absolute");
    }
    if path == home || !path.starts_with(home) {
        return Configured::Problem("configuration_outside_home");
    }
    Configured::Path(path)
}

/// The text with each XML comment left out. `None` when a comment has no
/// end.
fn without_comments(text: &str) -> Option<String> {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let after: &str = &rest[start + 4..];
        let end: usize = after.find("-->")?;
        rest = &after[end + 3..];
    }
    out.push_str(rest);
    Some(out)
}
