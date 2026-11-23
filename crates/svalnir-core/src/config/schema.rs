//! The typed values of a validated configuration, schema version 1.
//!
//! `docs/POLICY_SPEC.md` section 4 has the document that these types hold.
//! Each field has a value: an omitted key has the value of the template
//! (`super::template`). [`ValidatedConfig::is_explicit`] tells the two apart.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use super::path::ConfigPath;
use crate::id::RuleId;
use crate::quantity::{Bytes, EntryCount};

/// The schema version that this module reads.
pub const SCHEMA_VERSION: u32 = 1;

/// Makes an enumeration of configuration text values.
macro_rules! text_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// Each value, in the sequence of the specification.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The text of the value in a configuration document.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }

            /// Finds the value for a configuration text.
            pub fn from_text(text: &str) -> Option<Self> {
                match text {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

text_enum! {
    /// The profile that supplies the starting values
    /// (`docs/POLICY_SPEC.md` section 2). A profile does not create a grant.
    Profile {
        /// Collection and explanation, with no automatic intervention.
        Observe => "observe",
        /// Foreground protection and ordinary grace periods.
        Balanced => "balanced",
        /// Shorter configured waits and foreground eligibility.
        Aggressive => "aggressive",
    }
}

text_enum! {
    /// The pressure state that starts the global memory trigger
    /// (`docs/POLICY_SPEC.md` section 10).
    GlobalTrigger {
        /// Sustained native `critical` pressure.
        Critical => "critical",
    }
}

text_enum! {
    /// The removal mode of automatic disk-guard work.
    AutomaticMode {
        /// Permanent eviction of approved regenerable data.
        Permanent => "permanent",
    }
}

text_enum! {
    /// The restart strategy of an application budget
    /// (`docs/POLICY_SPEC.md` section 10, "Relaunch and restart").
    RestartPolicy {
        /// Svalnir does not start the application again.
        Never => "never",
    }
}

text_enum! {
    /// A group of applications that automatic memory intervention can select.
    EligibleGroup {
        /// Applications of the user that are not in the foreground.
        BackgroundUserApplications => "background-user-applications",
        /// Jobs that a supported managed-job adapter controls.
        ManagedJobs => "managed-jobs",
    }
}

/// Makes a validated text identifier.
macro_rules! text_identifier {
    ($(#[$meta:meta])* $name:ident, $max:literal, $extra:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The largest accepted length, in characters.
            pub const MAX_LENGTH: usize = $max;

            /// Validates the text. Returns `None` when the text is empty, is
            /// too long, or has a character outside the grammar.
            pub fn new(text: &str) -> Option<Self> {
                let accepted: bool = !text.is_empty()
                    && text.len() <= Self::MAX_LENGTH
                    && text.chars().all(|character: char| {
                        character.is_ascii_alphanumeric() || $extra.contains(character)
                    });
                accepted.then(|| Self(text.to_owned()))
            }

            /// The text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

text_identifier! {
    /// A logical volume selector such as `startup-data`: 1 to 128 characters
    /// of `A-Za-z0-9._:-`. The agent resolves it to a current volume
    /// identity; this module does not.
    VolumeSelector, 128, "._:-"
}

text_identifier! {
    /// A bundle identifier as text: 1 to 255 characters of `A-Za-z0-9.-_`.
    /// The text is not a verified application identity. The agent resolves
    /// and verifies it; this module does not.
    BundleId, 255, ".-_"
}

text_identifier! {
    /// The identifier of an application budget in the document: 1 to 128
    /// characters of `A-Za-z0-9._:-`.
    AppBudgetId, 128, "._:-"
}

impl VolumeSelector {
    /// The selector of the startup data volume.
    pub(super) fn startup_data() -> Self {
        Self("startup-data".to_owned())
    }
}

/// The `[agent]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentConfig {
    /// The profile that supplies the starting values.
    pub profile: Profile,
    /// The ordinary sampling interval.
    pub sample_interval: Duration,
    /// The sampling interval while a guard qualifies or has an incident.
    pub pressure_sample_interval: Duration,
    /// The largest age of a sample that a decision can use.
    pub decision_sample_max_age: Duration,
    /// The largest gap between two samples of one qualification window.
    pub max_qualifying_sample_gap: Duration,
    /// The lifetime of a plan that the agent prepares automatically.
    pub plan_ttl: Duration,
    /// The lifetime of a plan that a user prepares and reviews.
    pub manual_plan_ttl: Duration,
}

/// The `[protections]` table. It applies to manual and automatic actions. An
/// empty list does not disable a built-in protection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Protections {
    /// Paths that no action can include.
    pub excluded_paths: Vec<ConfigPath>,
    /// Bundle identifiers of protected applications, as unverified text.
    pub protected_bundle_ids: Vec<BundleId>,
    /// Executable paths of protected applications.
    pub protected_executable_paths: Vec<ConfigPath>,
}

/// The `[disk_guard.exclusions]` table. It applies to automatic disk-guard
/// work.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one key of the configuration schema"
)]
pub struct DiskExclusions {
    /// Paths that automatic disk-guard work cannot include.
    pub paths: Vec<ConfigPath>,
    /// Always true in schema version 1.
    pub protect_archives: bool,
    /// Always true in schema version 1.
    pub protect_backups: bool,
    /// Always true in schema version 1.
    pub protect_databases: bool,
    /// Always true in schema version 1.
    pub protect_model_weights: bool,
}

/// The `[disk_guard]` table. The validation makes sure that:
///
/// ```text
/// 0 < emergency_below < reclaim_below < warn_below < recover_above
/// 0 < emergency_sustain_for <= sustain_for
/// 0 < batch_limit <= pass_limit <= incident_limit
/// 0 < batch_item_limit <= pass_item_limit <= incident_item_limit
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskGuard {
    /// True when the document requests an active disk policy. The applicable
    /// action grant is a separate condition.
    pub enabled: bool,
    /// Logical volume selectors, not resolved.
    pub volumes: Vec<VolumeSelector>,
    /// Available capacity below which the warning starts.
    pub warn_below: Bytes,
    /// Available capacity below which an incident can start.
    pub reclaim_below: Bytes,
    /// Available capacity below which the shorter qualification applies.
    pub emergency_below: Bytes,
    /// Available capacity at which new dispatch stops.
    pub recover_above: Bytes,
    /// The qualification window of `reclaim_below`.
    pub sustain_for: Duration,
    /// The qualification window of `emergency_below`.
    pub emergency_sustain_for: Duration,
    /// The stable-recovery window.
    pub recovery_stable_for: Duration,
    /// The `work_bytes` ceiling of one batch.
    pub batch_limit: Bytes,
    /// The `work_bytes` ceiling of one pass.
    pub pass_limit: Bytes,
    /// The `work_bytes` ceiling of one incident.
    pub incident_limit: Bytes,
    /// The entry ceiling of one batch.
    pub batch_item_limit: EntryCount,
    /// The entry ceiling of one pass.
    pub pass_item_limit: EntryCount,
    /// The entry ceiling of one incident.
    pub incident_item_limit: EntryCount,
    /// The time ceiling of one pass.
    pub pass_time_limit: Duration,
    /// The pass ceiling of one incident.
    pub max_passes_per_incident: NonZeroU32,
    /// The wait before another pass.
    pub pass_cooldown: Duration,
    /// The wait before the measurement after an action.
    pub observe_after_action: Duration,
    /// The backoff after a pass with no effect.
    pub no_effect_backoff: Duration,
    /// The removal mode of automatic work.
    pub automatic_mode: AutomaticMode,
    /// Rule identifiers, with a valid grammar only. The agent looks them up
    /// in the compiled reviewed registry; this module does not.
    pub approved_rules: Vec<RuleId>,
    /// The `[disk_guard.exclusions]` table.
    pub exclusions: DiskExclusions,
}

/// One `[[memory_guard.app_budgets]]` table. The validation makes sure that
/// `0 < footprint_recover <= footprint_soft < footprint_stop`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppBudget {
    /// The identifier of the budget, unique in the document.
    pub id: AppBudgetId,
    /// The bundle identifier of the target, as unverified text, unique in
    /// the budgets of the document.
    pub bundle_id: BundleId,
    /// The advisory footprint threshold.
    pub footprint_soft: Bytes,
    /// The footprint threshold of stop eligibility.
    pub footprint_stop: Bytes,
    /// The footprint threshold of recovery. An omitted key has the value of
    /// `footprint_soft`.
    pub footprint_recover: Bytes,
    /// The qualification window of `footprint_stop`.
    pub over_limit_for: Duration,
    /// The cooldown of the application.
    pub cooldown: Duration,
    /// The restart strategy.
    pub restart: RestartPolicy,
}

/// The `[memory_guard]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one key of the configuration schema"
)]
pub struct MemoryGuard {
    /// True when the document requests an active memory policy. The
    /// applicable action grant is a separate condition.
    pub enabled: bool,
    /// The pressure state of the global trigger.
    pub global_trigger: GlobalTrigger,
    /// The qualification window of the global trigger.
    pub sustain_for: Duration,
    /// The wait between the graceful request and force escalation.
    pub grace_period: Duration,
    /// The wait before the measurement after an action.
    pub observe_after_action: Duration,
    /// The stable-recovery window.
    pub recovery_stable_for: Duration,
    /// The application ceiling of one incident.
    pub max_applications_per_incident: NonZeroU32,
    /// True when the foreground application is not eligible.
    pub protect_foreground: bool,
    /// True when the document permits automatic force quit.
    pub allow_force_quit: bool,
    /// True when the document permits memory intervention with a volatile
    /// journal during critical pressure.
    pub allow_volatile_journal_on_critical: bool,
    /// The groups that automatic memory intervention can select from.
    pub eligible_groups: Vec<EligibleGroup>,
    /// Bundle identifiers that automatic memory intervention cannot select,
    /// as unverified text.
    pub protected_bundle_ids: Vec<BundleId>,
    /// Executable paths that automatic memory intervention cannot select.
    pub protected_executable_paths: Vec<ConfigPath>,
    /// The application budgets, in the sequence of the document.
    pub app_budgets: Vec<AppBudget>,
}

/// The shortest accepted `[cleanup.projects].quiet_period`.
pub const MIN_QUIET_PERIOD: Duration = Duration::from_hours(1);

/// The longest accepted `[cleanup.projects].quiet_period`.
pub const MAX_QUIET_PERIOD: Duration = Duration::from_hours(90 * 24);

/// The `[cleanup.projects]` table: the project activity of
/// `docs/CLEANUP_RULES.md` section 6. The validation makes sure that
/// [`MIN_QUIET_PERIOD`] `<= quiet_period <=` [`MAX_QUIET_PERIOD`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProjectCleanup {
    /// The time with no project activity after which a project is quiet.
    pub quiet_period: Duration,
    /// True when the Paseo source of the project activity is on.
    pub paseo_agents: bool,
    /// The search roots of the rule, each a plain relative path below the
    /// home directory, in the sequence of the document. The template has
    /// none. The validation makes sure that each one has no empty, `.`,
    /// `..`, or `~` component, that no two are the same with the case of
    /// ASCII letters ignored, and that the list has at most
    /// [`MAX_SEARCH_ROOTS`] paths.
    pub search_roots: Vec<String>,
    /// The `[[cleanup.projects.layouts]]` tables, in the sequence of the
    /// document. The template has none.
    pub layouts: Vec<UserLayout>,
}

/// The largest number of `[cleanup.projects].search_roots`.
pub const MAX_SEARCH_ROOTS: usize = 16;

/// The largest number of `[[cleanup.projects.layouts]]` tables.
pub const MAX_USER_LAYOUTS: usize = 16;

/// The largest number of `markers` and of `protected` paths of one layout.
pub const MAX_LAYOUT_ENTRIES: usize = 8;

/// The names that the walk of `project.dependency-directory` never enters
/// and that a layout of the configuration cannot name: the directories of
/// version control and the shared cache directory
/// (`docs/CLEANUP_RULES.md` section 12).
pub const SKIPPED_DIRECTORY_NAMES: [&str; 5] = [".git", ".hg", ".jj", ".svn", ".cache"];

/// The first names of the directories of the built-in layouts of
/// `project.dependency-directory` (`docs/CLEANUP_RULES.md` section 12). A
/// layout of the configuration cannot start with one of them, so its units
/// cannot overlap a unit of a built-in layout. The agent has a test that
/// this list agrees with its catalog.
pub const BUILT_IN_LAYOUT_NAMES: [&str; 67] = [
    "node_modules",
    ".venv",
    "venv",
    "Pods",
    "target",
    "project",
    ".next",
    ".turbo",
    ".svelte-kit",
    ".astro",
    ".parcel-cache",
    ".nuxt",
    ".output",
    ".angular",
    ".nx",
    ".docusaurus",
    ".yarn",
    ".vercel",
    ".wrangler",
    "dist",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".pixi",
    ".gradle",
    ".kotlin",
    ".cxx",
    ".externalNativeBuild",
    "build",
    "_build",
    ".elixir_ls",
    ".lexical",
    ".expert",
    "obj",
    "bin",
    "artifacts",
    ".build",
    "DerivedData",
    "Carthage",
    ".zig-cache",
    "zig-cache",
    "vendor",
    "tmp",
    "var",
    ".dart_tool",
    ".bloop",
    ".metals",
    "out",
    ".godot",
    ".import",
    ".stack-work",
    "dist-newstyle",
    "elm-stuff",
    ".terraform",
    "cdk.out",
    ".aws-sam",
    ".serverless",
    "renv",
    ".direnv",
    ".devenv",
    ".jekyll-cache",
    "resources",
    "site",
];

/// The names that `docs/CLEANUP_RULES.md` section 12 keeps outside the rule
/// because a removal can lose data that no tool makes again, and that are
/// not a first name of a built-in layout: `zig-out` (install output),
/// `deps` of Mix (dependency sources), `_opam` (the pins and the sources of
/// a local switch), `.hypothesis` (the example database),
/// `.terragrunt-cache` (local state at each depth), `Saved` of Unreal Engine
/// (autosaves), and `UserSettings` of Unity (preferences). `vendor` (with
/// `vendor/cache` and Go `vendor`), `tmp`, `_build` (also beside
/// `rebar.config`), and the other first names of the table are in
/// [`BUILT_IN_LAYOUT_NAMES`].
pub const KEPT_OUT_LAYOUT_NAMES: [&str; 7] = [
    "zig-out",
    "deps",
    "_opam",
    ".hypothesis",
    ".terragrunt-cache",
    "Saved",
    "UserSettings",
];

/// The names of the protected locations of the home directory that a
/// layout of the configuration cannot name in a component: the names of
/// the personal folders of the template of `[protections]`, `Library`, and
/// `Applications`.
pub const PROTECTED_HOME_NAMES: [&str; 11] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Movies",
    "Music",
    "Pictures",
    "Public",
    "Library",
    "Applications",
    "Mobile Documents",
    "CloudStorage",
];

/// One `[[cleanup.projects.layouts]]` table: a layout of
/// `project.dependency-directory` that the user supplies
/// (`docs/CLEANUP_RULES.md` section 12, "User-configured layouts").
///
/// It is a parameter of the reviewed rule, not a rule: each check of the
/// rule applies to it unchanged, its layout name is `user-configured`, and
/// it is never used by an automatic operation. The validation makes sure
/// of the grammar of each field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UserLayout {
    /// The generated directory, relative to the project directory: one
    /// name, or two names with `/` between them.
    pub directory: String,
    /// The project markers. One of them must be a regular file in the
    /// directory that holds the first name of `directory`. A marker can be
    /// a pattern with `*` and `?`.
    pub markers: Vec<String>,
    /// A regular file that the unit must have, when the table gives one.
    pub inner_marker: Option<String>,
    /// The protected children: paths relative to the unit, each component
    /// a name or a pattern with `*` and `?`. A unit with an entry at one of
    /// them is refused.
    pub protected: Vec<String>,
    /// The quiet period of the projects of this layout, when the table
    /// gives one, in place of `[cleanup.projects].quiet_period`.
    pub quiet_period: Option<Duration>,
}

/// The `[cleanup]` table: the settings of the cleanup rules. A setting
/// gives no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cleanup {
    /// The `[cleanup.projects]` table.
    pub projects: ProjectCleanup,
}

/// The `[history]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct History {
    /// The retention of history records, best effort within the size limit.
    pub retention: Duration,
    /// The hard size limit of the history database.
    pub max_database_size: Bytes,
    /// True when an export redacts paths.
    pub redact_exported_paths: bool,
}

/// The `[privacy]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Privacy {
    /// True when the document permits telemetry.
    pub telemetry: bool,
    /// True when the document permits command arguments in records.
    pub include_command_arguments: bool,
}

/// A configuration that passed the syntax, schema, and relationship checks.
///
/// Only [`super::parse_and_validate`] makes this value, and it has no
/// mutable access, thus the relationships stay true. The value is a
/// proposal. It is not an effective revision: the rule registry, the volume
/// selectors, the application identities, the worker capabilities, and the
/// grants are not checked (`docs/INTERFACES.md` section 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub(super) template_revision: u32,
    pub(super) agent: AgentConfig,
    pub(super) protections: Protections,
    pub(super) disk_guard: DiskGuard,
    pub(super) memory_guard: MemoryGuard,
    pub(super) cleanup: Cleanup,
    pub(super) history: History,
    pub(super) privacy: Privacy,
    pub(super) explicit: BTreeSet<String>,
}

impl ValidatedConfig {
    /// The schema version of the document.
    pub const fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    /// The revision of the template that supplied the omitted values.
    pub const fn template_revision(&self) -> u32 {
        self.template_revision
    }

    /// The `[agent]` table.
    pub const fn agent(&self) -> &AgentConfig {
        &self.agent
    }

    /// The `[protections]` table.
    pub const fn protections(&self) -> &Protections {
        &self.protections
    }

    /// The `[disk_guard]` table.
    pub const fn disk_guard(&self) -> &DiskGuard {
        &self.disk_guard
    }

    /// The `[memory_guard]` table.
    pub const fn memory_guard(&self) -> &MemoryGuard {
        &self.memory_guard
    }

    /// The `[cleanup]` table.
    pub const fn cleanup(&self) -> &Cleanup {
        &self.cleanup
    }

    /// The `[history]` table.
    pub const fn history(&self) -> &History {
        &self.history
    }

    /// The `[privacy]` table.
    pub const fn privacy(&self) -> &Privacy {
        &self.privacy
    }

    /// True when the document gives the key, false when the value comes from
    /// the template. `key_path` has the format of a finding path, for
    /// example `disk_guard.warn_below` or
    /// `memory_guard.app_budgets[0].footprint_recover`.
    pub fn is_explicit(&self, key_path: &str) -> bool {
        self.explicit.contains(key_path)
    }

    /// The key paths that the document gives, in lexical sequence.
    pub fn explicit_keys(&self) -> impl Iterator<Item = &str> {
        self.explicit.iter().map(String::as_str)
    }

    /// Each personal folder of the template default of
    /// `[protections].excluded_paths` ([`super::PERSONAL_FOLDERS`]) that
    /// no path of the list protects: no path is the folder or a directory
    /// that contains it. The comparison is of the components, with ASCII
    /// case ignored, as on the default volume. A path that starts from `/`
    /// is compared with `home` when it is given, and else protects no
    /// folder. With the template default, the result is empty.
    pub fn unprotected_personal_folders(
        &self,
        home: Option<&std::path::Path>,
    ) -> Vec<&'static str> {
        let lower = |component: &str| component.to_ascii_lowercase();
        let covers = |path: &ConfigPath, folder: &ConfigPath| {
            if path.base() == folder.base() {
                let path: Vec<String> = path.components().map(lower).collect();
                let folder: Vec<String> = folder.components().map(lower).collect();
                return folder.starts_with(&path);
            }
            let expanded = |value: &ConfigPath| {
                home.and_then(|home| value.expand(home).ok())
                    .map(|expanded| expanded.to_string_lossy().to_ascii_lowercase())
            };
            match (expanded(path), expanded(folder)) {
                (Some(path), Some(folder)) => {
                    std::path::Path::new(&folder).starts_with(std::path::Path::new(&path))
                }
                _ => false,
            }
        };
        super::PERSONAL_FOLDERS
            .into_iter()
            .filter(|text| {
                ConfigPath::parse(text).is_ok_and(|folder| {
                    !self
                        .protections
                        .excluded_paths
                        .iter()
                        .any(|path| covers(path, &folder))
                })
            })
            .collect()
    }
}
