//! The template that supplies the value of each omitted key.
//!
//! `docs/POLICY_SPEC.md` section 3 requires that an omitted value resolves
//! through a versioned, bounded template and that omission never means
//! unlimited. The numbers here are the illustrative values of section 4 of
//! that document. They are provisional: the specification states that the
//! release defaults are not yet decided.
//!
//! An omitted key never expands authority. A guard is not enabled, force
//! quit and the volatile journal are not permitted, and the lists of approved
//! rules and eligible groups are empty. The three profiles have the same
//! template at this revision.

use std::num::NonZeroU32;
use std::time::Duration;

use super::path::ConfigPath;
use super::schema::{
    AgentConfig, AutomaticMode, CacheCleanup, Cleanup, DiskExclusions, DiskGuard, GlobalTrigger,
    History, MemoryGuard, Privacy, Profile, ProjectCleanup, VolumeSelector,
};
use crate::quantity::{Bytes, EntryCount};

/// The revision of the template. Increase it when a value changes.
pub const TEMPLATE_REVISION: u32 = 4;

/// The personal folders of the home directory: the default of
/// `[protections].excluded_paths` (`docs/POLICY_SPEC.md` section 12). Each
/// path protects the folder, each entry below it, and each directory that
/// contains it, for manual and automatic actions. A document that gives
/// the key replaces the list; `excluded_paths = []` permits a manual
/// selection inside these folders.
pub const PERSONAL_FOLDERS: [&str; 9] = [
    "~/Desktop",
    "~/Documents",
    "~/Downloads",
    "~/Movies",
    "~/Music",
    "~/Pictures",
    "~/Public",
    "~/Library/Mobile Documents",
    "~/Library/CloudStorage",
];

const MEBIBYTE: u64 = 1024 * 1024;
const GIBIBYTE: u64 = 1024 * MEBIBYTE;

const fn gibibytes(count: u64) -> Bytes {
    Bytes::new(count * GIBIBYTE)
}

/// The values of the omitted keys. Of `[protections]`, only
/// `excluded_paths` has a default that is not empty.
#[derive(Debug, Clone)]
pub(super) struct Template {
    pub(super) agent: AgentConfig,
    pub(super) excluded_paths: Vec<ConfigPath>,
    pub(super) disk_guard: DiskGuard,
    pub(super) memory_guard: MemoryGuard,
    pub(super) cleanup: Cleanup,
    pub(super) history: History,
    pub(super) privacy: Privacy,
}

impl Template {
    /// The template of schema version 1, revision [`TEMPLATE_REVISION`].
    pub(super) fn schema_v1() -> Self {
        Self {
            agent: AgentConfig {
                profile: Profile::Observe,
                sample_interval: Duration::from_mins(1),
                pressure_sample_interval: Duration::from_secs(5),
                decision_sample_max_age: Duration::from_secs(10),
                max_qualifying_sample_gap: Duration::from_secs(10),
                plan_ttl: Duration::from_secs(30),
                manual_plan_ttl: Duration::from_mins(10),
            },
            excluded_paths: PERSONAL_FOLDERS
                .iter()
                .filter_map(|text| ConfigPath::parse(text).ok())
                .collect(),
            disk_guard: DiskGuard {
                enabled: false,
                volumes: vec![VolumeSelector::startup_data()],
                warn_below: gibibytes(20),
                reclaim_below: gibibytes(10),
                emergency_below: gibibytes(2),
                recover_above: gibibytes(25),
                sustain_for: Duration::from_secs(30),
                emergency_sustain_for: Duration::from_secs(5),
                recovery_stable_for: Duration::from_mins(1),
                batch_limit: gibibytes(1),
                pass_limit: gibibytes(8),
                incident_limit: gibibytes(16),
                batch_item_limit: EntryCount::new(256),
                pass_item_limit: EntryCount::new(2048),
                incident_item_limit: EntryCount::new(4096),
                pass_time_limit: Duration::from_secs(30),
                max_passes_per_incident: NonZeroU32::MIN.saturating_add(1),
                pass_cooldown: Duration::from_mins(5),
                observe_after_action: Duration::from_secs(5),
                no_effect_backoff: Duration::from_mins(15),
                automatic_mode: AutomaticMode::Permanent,
                approved_rules: Vec::new(),
                exclusions: DiskExclusions {
                    paths: Vec::new(),
                    protect_archives: true,
                    protect_backups: true,
                    protect_databases: true,
                    protect_model_weights: true,
                },
            },
            memory_guard: MemoryGuard {
                enabled: false,
                global_trigger: GlobalTrigger::Critical,
                sustain_for: Duration::from_secs(15),
                grace_period: Duration::from_secs(10),
                observe_after_action: Duration::from_secs(15),
                recovery_stable_for: Duration::from_mins(1),
                max_applications_per_incident: NonZeroU32::MIN.saturating_add(2),
                protect_foreground: true,
                allow_force_quit: false,
                allow_volatile_journal_on_critical: false,
                eligible_groups: Vec::new(),
                protected_bundle_ids: Vec::new(),
                protected_executable_paths: Vec::new(),
                app_budgets: Vec::new(),
            },
            cleanup: Cleanup {
                projects: ProjectCleanup {
                    quiet_period: Duration::from_hours(24),
                    paseo_agents: false,
                    search_roots: Vec::new(),
                    claude_config_dirs: Vec::new(),
                    layouts: Vec::new(),
                },
                caches: CacheCleanup::default(),
            },
            history: History {
                retention: Duration::from_hours(30 * 24),
                max_database_size: Bytes::new(256 * MEBIBYTE),
                redact_exported_paths: true,
            },
            privacy: Privacy {
                telemetry: false,
                include_command_arguments: false,
            },
        }
    }
}
