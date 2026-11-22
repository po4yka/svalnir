//! The package and build cache rules of `docs/CLEANUP_RULES.md` section 10:
//! `pnpm.content-store`, `yarn.cache`, `go.build-cache`, `uv.cache`,
//! `homebrew.download-cache`, and `cocoapods.cache`.
//!
//! Section 12 owns the contract of each rule. Each rule has the
//! inspection mode only, and each of its layouts is `proposed`: no
//! validation record exists. A rule of this module finds no candidate, has
//! no discovery for an eviction, and removes nothing. The owner workflow
//! (for example `pnpm store prune`) is a text for the user; this build
//! runs no producer tool.
//!
//! # Roots
//!
//! The root of a rule is the location that the configuration of the
//! producer names ([`resolve`]). The inspection reads fixed keys of the
//! configuration files of the producer below the home directory, as text
//! ([`config`]). It runs no producer tool (`pnpm store path`, `brew
//! --cache`, ...), because no reviewed pattern for a producer query exists
//! (section 9), and it reads no environment variable: the environment of
//! the agent or of a client is not the environment of the shell in which
//! the user runs the tool. A location that only an environment variable of
//! the shell names is thus not seen, and the report says that the root is
//! the default location. When no file names a location, the root is the
//! documented default below the home directory, as a discovery hint.
//!
//! # Units
//!
//! The inspection measures fixed units below a root, each with a layout
//! that a marker identifies, for example the directory `v10` of a pnpm
//! store or the file `CACHEDIR.TAG` of a uv cache. A unit with no marker
//! has the result `unsupported_layout` and is not measured.

pub mod config;
mod inspect;

#[cfg(test)]
mod tests;

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

pub use config::{ConfigFormat, ConfigProblem, ConfigSource, MAX_CONFIG_BYTES};
pub use inspect::{
    CacheInspection, CacheMeasurement, CacheRootReport, CacheUnitReport, InspectionHost,
    InspectionLimits, ReclaimFigure, RootOutcome, RootResolution, UnitOutcome, resolve,
};
pub(in crate::rules) use inspect::{check_scope_root, measure_unit, measure_unit_observed};

use super::registry::RegistryError;

/// The revision of each rule of this module.
pub const CACHE_RULE_REVISION: &str = "r1";

/// The identity of the rule for the pnpm store.
pub const PNPM_CONTENT_STORE_RULE_ID: &str = "pnpm.content-store";
/// The identity of the rule for the Yarn cache.
pub const YARN_CACHE_RULE_ID: &str = "yarn.cache";
/// The identity of the rule for the Go build cache.
pub const GO_BUILD_CACHE_RULE_ID: &str = "go.build-cache";
/// The identity of the rule for the uv cache.
pub const UV_CACHE_RULE_ID: &str = "uv.cache";
/// The identity of the rule for the downloads of Homebrew.
pub const HOMEBREW_DOWNLOAD_CACHE_RULE_ID: &str = "homebrew.download-cache";
/// The identity of the rule for the `CocoaPods` cache.
pub const COCOAPODS_CACHE_RULE_ID: &str = "cocoapods.cache";

/// The names that mark a project directory. A root or a unit that has one
/// of these names, or that is below a directory with one, is in a project
/// and is refused (`root_in_project`): a cache in a project can be data
/// that no registry gives again (section 12, `yarn.cache`).
pub const PROJECT_MARKERS: [&str; 13] = [
    ".git",
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.work",
    "pyproject.toml",
    "uv.lock",
    "Podfile",
    "Podfile.lock",
    "Cargo.toml",
    "Package.swift",
    "Gemfile",
];

/// A location of the host that a rule refuses as a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// A path relative to the home directory.
    Home(&'static str),
    /// An absolute path.
    Absolute(&'static str),
}

/// What marks a unit as a supported layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// The unit is a directory with this child directory.
    ChildDirectory(&'static str),
    /// The unit is a directory.
    Directory,
    /// The unit has this regular file, and the file starts with these
    /// bytes.
    FilePrefix {
        /// The name of the file in the unit.
        file: &'static str,
        /// The first bytes of the file.
        prefix: &'static [u8],
    },
}

/// One unit of a root that the inspection measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSpec {
    /// The path relative to the root. An empty path is the root itself.
    pub relative: &'static str,
    /// The layout that the marker identifies.
    pub layout: &'static str,
    /// The marker.
    pub marker: Marker,
}

/// One root of a rule: its configuration sources, its default location,
/// and its units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootSpec {
    /// The configuration sources, in the sequence of the report. When two
    /// sources name different locations, the root has no path
    /// ([`ConfigProblem::Conflicting`]).
    pub sources: &'static [ConfigSource],
    /// The default location relative to the home directory. A discovery
    /// hint only.
    pub default: &'static str,
    /// A value of a source that turns the cache off, as `GOCACHE=off`.
    pub disabled_value: Option<&'static str>,
    /// The units.
    pub units: &'static [UnitSpec],
}

/// A location that is outside the rule, with the configuration that can
/// move it. A root that is the location, contains it, or is in it is
/// refused (`root_overlaps_excluded`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExclusionSpec {
    /// The configuration sources of the location.
    pub sources: &'static [ConfigSource],
    /// The default location.
    pub default: Location,
    /// The excluded paths below the location. An empty path is the
    /// location itself.
    pub children: &'static [&'static str],
}

/// What the reclaim figure of a measured unit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimBasis {
    /// The allocated size of the unit. It is not exclusive storage.
    AllocatedBytes,
    /// No figure: the producer links files from the cache into projects
    /// or environments with hard links or clones, so the removal of a
    /// cache file whose content a project still has reclaims nothing for
    /// it (`docs/CLEANUP_RULES.md` section 12).
    LinkedIntoProjects,
    /// No figure: the producer makes copies with APFS clones, which share
    /// their blocks with the source, as `simctl clone` does for a device.
    ClonedStorage,
}

/// The reviewed facts of one cache rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSpec {
    /// The rule identity.
    pub id: &'static str,
    /// The producer.
    pub producer: &'static str,
    /// The roots.
    pub roots: &'static [RootSpec],
    /// The locations outside the rule.
    pub exclusions: &'static [ExclusionSpec],
    /// What the reclaim figure is.
    pub reclaim: ReclaimBasis,
    /// The producer processes whose activity blocks a future admission.
    pub activity: &'static [ActivityCheck],
    /// The cost to make the data again.
    pub rebuild_cost: RebuildCost,
    /// The owner workflow, as a text for the user.
    pub owner_workflow: &'static str,
    /// The consequence of a removal.
    pub rebuild_impact: &'static str,
}

const fn source(
    file: &'static str,
    format: ConfigFormat,
    key: &'static str,
    tilde: bool,
) -> ConfigSource {
    ConfigSource {
        file,
        format,
        key,
        tilde,
        list: false,
    }
}

const PNPM_SOURCES: [ConfigSource; 2] = [
    source(
        "Library/Preferences/pnpm/rc",
        ConfigFormat::Ini,
        "store-dir",
        true,
    ),
    source(".npmrc", ConfigFormat::Ini, "store-dir", true),
];

const GO_ENV: &str = "Library/Application Support/go/env";

const UV_TOML: &str = ".config/uv/uv.toml";

/// The rule `pnpm.content-store`.
pub const PNPM: CacheSpec = CacheSpec {
    id: PNPM_CONTENT_STORE_RULE_ID,
    producer: "pnpm",
    roots: &[RootSpec {
        sources: &PNPM_SOURCES,
        default: "Library/pnpm/store",
        disabled_value: None,
        units: &[
            UnitSpec {
                relative: "v10",
                layout: "pnpm-store-v10",
                marker: Marker::ChildDirectory("files"),
            },
            UnitSpec {
                relative: "v3",
                layout: "pnpm-store-v3",
                marker: Marker::ChildDirectory("files"),
            },
        ],
    }],
    exclusions: &[],
    reclaim: ReclaimBasis::LinkedIntoProjects,
    activity: &[ActivityCheck::ProducerProcessAbsent],
    rebuild_cost: RebuildCost::Medium,
    owner_workflow: "Run `pnpm store prune` to remove the packages that no project refers to. Svalnir runs it only in a plan of `svalnir clean plan --mode owner` that you approve.",
    rebuild_impact: "A later install downloads each removed package again and needs a registry that is still available.",
};

/// The rule `yarn.cache`. This build does not confirm that Yarn expands a
/// value that starts with `~/`, so such a value gives no root.
pub const YARN: CacheSpec = CacheSpec {
    id: YARN_CACHE_RULE_ID,
    producer: "yarn",
    roots: &[
        RootSpec {
            sources: &[source(
                ".yarnrc",
                ConfigFormat::SpaceSeparated,
                "cache-folder",
                false,
            )],
            default: "Library/Caches/Yarn",
            disabled_value: None,
            units: &[UnitSpec {
                relative: "v6",
                layout: "yarn-classic-v6",
                marker: Marker::Directory,
            }],
        },
        RootSpec {
            sources: &[source(
                ".yarnrc.yml",
                ConfigFormat::YamlTopLevel,
                "globalFolder",
                false,
            )],
            default: ".yarn/berry",
            disabled_value: None,
            units: &[UnitSpec {
                relative: "cache",
                layout: "yarn-berry-global-cache",
                marker: Marker::Directory,
            }],
        },
    ],
    exclusions: &[],
    reclaim: ReclaimBasis::AllocatedBytes,
    activity: &[ActivityCheck::ProducerProcessAbsent],
    rebuild_cost: RebuildCost::Medium,
    owner_workflow: "Run `yarn cache clean` outside a project to clean the global cache. Svalnir runs it for Yarn 1 only in a plan of `svalnir clean plan --mode owner` that you approve. The cache of a project is outside this rule.",
    rebuild_impact: "A later install downloads each removed package again and needs a registry that is still available.",
};

/// The rule `go.build-cache`.
pub const GO: CacheSpec = CacheSpec {
    id: GO_BUILD_CACHE_RULE_ID,
    producer: "go",
    roots: &[RootSpec {
        sources: &[source(GO_ENV, ConfigFormat::Assignment, "GOCACHE", false)],
        default: "Library/Caches/go-build",
        disabled_value: Some("off"),
        units: &[UnitSpec {
            relative: "",
            layout: "go-build-cache",
            marker: Marker::FilePrefix {
                file: "README",
                prefix: b"This directory holds cached build artifacts from the Go build system.",
            },
        }],
    }],
    exclusions: &[
        ExclusionSpec {
            sources: &[source(
                GO_ENV,
                ConfigFormat::Assignment,
                "GOMODCACHE",
                false,
            )],
            default: Location::Home("go/pkg/mod"),
            children: &[""],
        },
        ExclusionSpec {
            sources: &[ConfigSource {
                file: GO_ENV,
                format: ConfigFormat::Assignment,
                key: "GOPATH",
                tilde: false,
                list: true,
            }],
            default: Location::Home("go"),
            children: &["src", "bin", "pkg/mod"],
        },
    ],
    reclaim: ReclaimBasis::AllocatedBytes,
    activity: &[ActivityCheck::ProducerProcessAbsent],
    rebuild_cost: RebuildCost::Medium,
    owner_workflow: "Run `go clean -cache` to remove the build cache. Svalnir runs it only in a plan of `svalnir clean plan --mode owner` that you approve. The module cache (`GOMODCACHE`) is outside this rule.",
    rebuild_impact: "The next build compiles each package again, and the next test run runs each test again.",
};

/// The rule `uv.cache`.
pub const UV: CacheSpec = CacheSpec {
    id: UV_CACHE_RULE_ID,
    producer: "uv",
    roots: &[RootSpec {
        sources: &[source(
            UV_TOML,
            ConfigFormat::TomlTopLevel,
            "cache-dir",
            true,
        )],
        default: ".cache/uv",
        disabled_value: None,
        units: &[UnitSpec {
            relative: "",
            layout: "uv-cache",
            marker: Marker::FilePrefix {
                file: "CACHEDIR.TAG",
                prefix: b"Signature: 8a477f597d28d172789f06886806bc55",
            },
        }],
    }],
    exclusions: &[
        ExclusionSpec {
            sources: &[source(
                UV_TOML,
                ConfigFormat::TomlTopLevel,
                "python-install-dir",
                true,
            )],
            default: Location::Home(".local/share/uv/python"),
            children: &[""],
        },
        ExclusionSpec {
            sources: &[],
            default: Location::Home(".local/share/uv/tools"),
            children: &[""],
        },
    ],
    reclaim: ReclaimBasis::LinkedIntoProjects,
    activity: &[
        ActivityCheck::ProducerProcessAbsent,
        ActivityCheck::ProducerLock,
    ],
    rebuild_cost: RebuildCost::Medium,
    owner_workflow: "Run `uv cache prune` to remove the entries that are not used, or `uv cache clean` to remove the cache. Svalnir runs `uv cache prune` only in a plan of `svalnir clean plan --mode owner` that you approve.",
    rebuild_impact: "A later install downloads and builds each removed package again and needs an index that is still available.",
};

/// The rule `homebrew.download-cache`.
pub const HOMEBREW: CacheSpec = CacheSpec {
    id: HOMEBREW_DOWNLOAD_CACHE_RULE_ID,
    producer: "homebrew",
    roots: &[RootSpec {
        sources: &[
            source(
                ".homebrew/brew.env",
                ConfigFormat::Assignment,
                "HOMEBREW_CACHE",
                false,
            ),
            source(
                ".config/homebrew/brew.env",
                ConfigFormat::Assignment,
                "HOMEBREW_CACHE",
                false,
            ),
        ],
        default: "Library/Caches/Homebrew",
        disabled_value: None,
        units: &[UnitSpec {
            relative: "downloads",
            layout: "homebrew-downloads",
            marker: Marker::Directory,
        }],
    }],
    exclusions: &[
        ExclusionSpec {
            sources: &[],
            default: Location::Absolute("/opt/homebrew"),
            children: &[""],
        },
        ExclusionSpec {
            sources: &[],
            default: Location::Absolute("/usr/local"),
            children: &["Homebrew", "Cellar", "Caskroom"],
        },
        ExclusionSpec {
            sources: &[],
            default: Location::Absolute("/home/linuxbrew/.linuxbrew"),
            children: &[""],
        },
    ],
    reclaim: ReclaimBasis::AllocatedBytes,
    activity: &[ActivityCheck::ProducerProcessAbsent],
    rebuild_cost: RebuildCost::Low,
    owner_workflow: "Run `brew cleanup` to remove old downloads and old versions. Svalnir does not run it. Installed kegs, the Cellar, the Caskroom, and taps are outside this rule.",
    rebuild_impact: "A later reinstall downloads the bottle or the source again and needs a network and a source that is still available.",
};

/// The rule `cocoapods.cache`.
pub const COCOAPODS: CacheSpec = CacheSpec {
    id: COCOAPODS_CACHE_RULE_ID,
    producer: "cocoapods",
    roots: &[RootSpec {
        sources: &[source(
            ".cocoapods/config.yaml",
            ConfigFormat::YamlTopLevel,
            "cache_root",
            true,
        )],
        default: "Library/Caches/CocoaPods",
        disabled_value: None,
        units: &[UnitSpec {
            relative: "Pods",
            layout: "cocoapods-download-cache",
            marker: Marker::Directory,
        }],
    }],
    exclusions: &[ExclusionSpec {
        sources: &[],
        default: Location::Home(".cocoapods"),
        children: &[""],
    }],
    reclaim: ReclaimBasis::AllocatedBytes,
    activity: &[ActivityCheck::ProducerProcessAbsent],
    rebuild_cost: RebuildCost::Medium,
    owner_workflow: "Run `pod cache list` to see the cache and `pod cache clean --all` to clean it. Svalnir does not run them. The `Pods` directory of a project and the spec repositories are outside this rule.",
    rebuild_impact: "A later `pod install` downloads each removed pod again and needs sources that are still available.",
};

/// The specifications of this module, in the sequence of section 10.
pub const CACHE_SPECS: [CacheSpec; 6] = [PNPM, YARN, GO, UV, HOMEBREW, COCOAPODS];

const MINUTE: u64 = 60_000_000_000;
const DAY: u64 = 86_400_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The declaration of the rule of `spec`. Each layout is `proposed`, and
/// the implementation has the inspection mode only, so no lifecycle
/// state, also a fixture state, can permit a removal.
///
/// The retention, the activity windows, and the budget are values of a
/// proposed rule. No promotion record confirms them (section 3).
fn declaration(spec: &CacheSpec) -> Result<RuleDeclaration, RegistryError> {
    let path = |text: &str| {
        LosslessPath::from_bytes(text).map_err(|_| RegistryError::Declaration("a path"))
    };
    let layouts: Vec<LayoutSupport> = spec
        .roots
        .iter()
        .flat_map(|root| root.units)
        .map(|unit| LayoutSupport {
            layout: unit.layout.to_owned(),
            lifecycle: LifecycleState::Proposed,
        })
        .collect();
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(spec.id)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(CACHE_RULE_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: spec.producer.to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts,
        roots: spec
            .roots
            .iter()
            .map(|root| {
                Ok(ApprovedRoot {
                    base: RootBase::ProducerConfiguration,
                    relative: path(root.default)?,
                })
            })
            .collect::<Result<Vec<ApprovedRoot>, RegistryError>>()?,
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(7 * DAY),
        },
        activity: ActivityProtocol {
            checks: spec.activity.to_vec(),
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: Nanoseconds::new(30_000_000_000),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::RegularFile, FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: vec![RuleMode::Inspection],
        deletion_method: DeletionMethod::ProducerOperation,
        executor: ExecutorRole::User,
        rebuild_cost: spec.rebuild_cost,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(50 * GIBIBYTE), EntryCount::new(2_000_000)),
            per_pass: WorkCharge::new(Bytes::new(100 * GIBIBYTE), EntryCount::new(4_000_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// One cache rule: its checked declaration and its reviewed facts.
#[derive(Debug, Clone)]
pub struct CacheRule {
    rule: Rule,
    spec: &'static CacheSpec,
}

impl CacheRule {
    /// Makes the rule of `spec` with the declaration of this build.
    pub(super) fn new(spec: &'static CacheSpec) -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration(spec)?).map_err(RegistryError::Incomplete)?;
        Ok(Self { rule, spec })
    }

    /// The rule with the declaration `rule` in place of its own: the new
    /// revision of a rule with an owner operation
    /// ([`super::producers`]).
    pub(super) fn with_rule(&self, rule: Rule) -> Self {
        Self {
            rule,
            spec: self.spec,
        }
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// The reviewed facts of the rule.
    pub fn spec(&self) -> &'static CacheSpec {
        self.spec
    }
}

/// The cache rules of this build, in the sequence of section 10.
///
/// # Errors
///
/// Returns a [`RegistryError`] when a declaration is not complete.
pub(super) fn cache_rules() -> Result<Vec<CacheRule>, RegistryError> {
    CACHE_SPECS.iter().map(CacheRule::new).collect()
}
