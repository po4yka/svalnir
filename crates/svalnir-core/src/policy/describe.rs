//! Serializable descriptions of the standing policies, for `policy list`
//! and `policy show`.
//!
//! A description repeats the values of a validated configuration. A
//! validated configuration is a proposal: the description does not show
//! that a rule is in the registry, that a selector resolves, or that an
//! action class has a grant.

use serde::Serialize;

use super::control::PolicyId;
use super::evidence::nanoseconds;
use crate::config::{AppBudget, DiskGuard, MemoryGuard, Profile, ValidatedConfig};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};

/// The note that each description has.
pub const DESCRIPTION_NOTE: &str = "These values are a validated configuration. They are not an \
     effective revision: the rule registry, the volume selectors, the application identities, \
     and the action grants are not checked here.";

/// The action classes that a policy can request.
const fn action_classes(policy: PolicyId) -> &'static [&'static str] {
    match policy {
        PolicyId::DiskGuard => &["EvictRegenerableData"],
        PolicyId::MemoryGuard => &["RequestApplicationExit", "ForceApplicationExit"],
    }
}

const fn enabled(config: &ValidatedConfig, policy: PolicyId) -> bool {
    match policy {
        PolicyId::DiskGuard => config.disk_guard().enabled,
        PolicyId::MemoryGuard => config.memory_guard().enabled,
    }
}

/// One line of `policy list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyListEntry {
    /// The policy.
    pub policy: PolicyId,
    /// True when the configuration enables the guard.
    pub enabled: bool,
    /// The profile of the configuration.
    pub profile: &'static str,
    /// True when the guard is enabled and the profile is not `observe`.
    /// The applicable action grant is a separate condition.
    pub intervention_requested: bool,
    /// The action classes that the policy can request.
    pub action_classes: &'static [&'static str],
    /// The number of triggers: the selected volumes, or the global trigger
    /// and the application budgets.
    pub trigger_count: usize,
}

fn list_entry(config: &ValidatedConfig, policy: PolicyId) -> PolicyListEntry {
    let enabled: bool = enabled(config, policy);
    PolicyListEntry {
        policy,
        enabled,
        profile: config.agent().profile.as_str(),
        intervention_requested: enabled && config.agent().profile != Profile::Observe,
        action_classes: action_classes(policy),
        trigger_count: match policy {
            PolicyId::DiskGuard => config.disk_guard().volumes.len(),
            PolicyId::MemoryGuard => config.memory_guard().app_budgets.len().saturating_add(1),
        },
    }
}

/// The standing policies of a configuration, for `policy list`.
pub fn list_policies(config: &ValidatedConfig) -> Vec<PolicyListEntry> {
    PolicyId::ALL
        .iter()
        .map(|policy| list_entry(config, *policy))
        .collect()
}

/// The timing values of the `[agent]` table that each policy uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AgentTimingView {
    /// The ordinary sampling interval.
    pub sample_interval: Nanoseconds,
    /// The sampling interval while a guard qualifies or has an incident.
    pub pressure_sample_interval: Nanoseconds,
    /// The largest age of a sample that a decision can use.
    pub decision_sample_max_age: Nanoseconds,
    /// The largest gap between two samples of one qualification window.
    pub max_qualifying_sample_gap: Nanoseconds,
    /// The lifetime of a plan that the agent prepares automatically.
    pub plan_ttl: Nanoseconds,
}

/// The `[protections]` table, which applies to each policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionsView {
    /// Paths that no action can include.
    pub excluded_paths: Vec<String>,
    /// Bundle identifiers of protected applications.
    pub protected_bundle_ids: Vec<String>,
    /// Executable paths of protected applications.
    pub protected_executable_paths: Vec<String>,
}

/// The `[disk_guard]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one key of the configuration schema"
)]
pub struct DiskGuardView {
    /// The volume selectors.
    pub volumes: Vec<String>,
    /// Available capacity below which the warning starts.
    pub warn_below: Bytes,
    /// Available capacity below which an incident can start.
    pub reclaim_below: Bytes,
    /// Available capacity below which the shorter qualification applies.
    pub emergency_below: Bytes,
    /// Available capacity at which new dispatch stops.
    pub recover_above: Bytes,
    /// The qualification window of `reclaim_below`.
    pub sustain_for: Nanoseconds,
    /// The qualification window of `emergency_below`.
    pub emergency_sustain_for: Nanoseconds,
    /// The stable-recovery window.
    pub recovery_stable_for: Nanoseconds,
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
    pub pass_time_limit: Nanoseconds,
    /// The pass ceiling of one incident.
    pub max_passes_per_incident: u32,
    /// The wait before another pass.
    pub pass_cooldown: Nanoseconds,
    /// The wait before the measurement after an action.
    pub observe_after_action: Nanoseconds,
    /// The backoff after a pass with no effect.
    pub no_effect_backoff: Nanoseconds,
    /// The removal mode of automatic work.
    pub automatic_mode: &'static str,
    /// The approved rule identifiers. The sequence is the rule priority.
    pub approved_rules: Vec<String>,
    /// Paths that automatic disk-guard work cannot include.
    pub excluded_paths: Vec<String>,
    /// The protection of archives.
    pub protect_archives: bool,
    /// The protection of backups.
    pub protect_backups: bool,
    /// The protection of databases.
    pub protect_databases: bool,
    /// The protection of model weights.
    pub protect_model_weights: bool,
}

impl DiskGuardView {
    fn of(guard: &DiskGuard) -> Self {
        Self {
            volumes: guard.volumes.iter().map(ToString::to_string).collect(),
            warn_below: guard.warn_below,
            reclaim_below: guard.reclaim_below,
            emergency_below: guard.emergency_below,
            recover_above: guard.recover_above,
            sustain_for: nanoseconds(guard.sustain_for),
            emergency_sustain_for: nanoseconds(guard.emergency_sustain_for),
            recovery_stable_for: nanoseconds(guard.recovery_stable_for),
            batch_limit: guard.batch_limit,
            pass_limit: guard.pass_limit,
            incident_limit: guard.incident_limit,
            batch_item_limit: guard.batch_item_limit,
            pass_item_limit: guard.pass_item_limit,
            incident_item_limit: guard.incident_item_limit,
            pass_time_limit: nanoseconds(guard.pass_time_limit),
            max_passes_per_incident: guard.max_passes_per_incident.get(),
            pass_cooldown: nanoseconds(guard.pass_cooldown),
            observe_after_action: nanoseconds(guard.observe_after_action),
            no_effect_backoff: nanoseconds(guard.no_effect_backoff),
            automatic_mode: guard.automatic_mode.as_str(),
            approved_rules: guard
                .approved_rules
                .iter()
                .map(ToString::to_string)
                .collect(),
            excluded_paths: guard
                .exclusions
                .paths
                .iter()
                .map(ToString::to_string)
                .collect(),
            protect_archives: guard.exclusions.protect_archives,
            protect_backups: guard.exclusions.protect_backups,
            protect_databases: guard.exclusions.protect_databases,
            protect_model_weights: guard.exclusions.protect_model_weights,
        }
    }
}

/// One `[[memory_guard.app_budgets]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppBudgetView {
    /// The identifier of the budget.
    pub id: String,
    /// The bundle identifier of the target.
    pub bundle_id: String,
    /// The advisory footprint threshold.
    pub footprint_soft: Bytes,
    /// The footprint threshold of stop eligibility.
    pub footprint_stop: Bytes,
    /// The footprint threshold of recovery.
    pub footprint_recover: Bytes,
    /// The qualification window of `footprint_stop`.
    pub over_limit_for: Nanoseconds,
    /// The cooldown of the application.
    pub cooldown: Nanoseconds,
    /// The restart strategy.
    pub restart: &'static str,
}

impl AppBudgetView {
    fn of(budget: &AppBudget) -> Self {
        Self {
            id: budget.id.to_string(),
            bundle_id: budget.bundle_id.to_string(),
            footprint_soft: budget.footprint_soft,
            footprint_stop: budget.footprint_stop,
            footprint_recover: budget.footprint_recover,
            over_limit_for: nanoseconds(budget.over_limit_for),
            cooldown: nanoseconds(budget.cooldown),
            restart: budget.restart.as_str(),
        }
    }
}

/// The `[memory_guard]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryGuardView {
    /// The pressure state of the global trigger.
    pub global_trigger: &'static str,
    /// The qualification window of the global trigger.
    pub sustain_for: Nanoseconds,
    /// The wait between the graceful request and force escalation.
    pub grace_period: Nanoseconds,
    /// The wait before the measurement after an action.
    pub observe_after_action: Nanoseconds,
    /// The stable-recovery window.
    pub recovery_stable_for: Nanoseconds,
    /// The application ceiling of one incident.
    pub max_applications_per_incident: u32,
    /// True when the foreground application is not eligible.
    pub protect_foreground: bool,
    /// True when the configuration permits automatic force quit.
    pub allow_force_quit: bool,
    /// True when the configuration permits memory intervention with a
    /// volatile journal during critical pressure.
    pub allow_volatile_journal_on_critical: bool,
    /// The groups that automatic memory intervention can select from.
    pub eligible_groups: Vec<&'static str>,
    /// Bundle identifiers that automatic memory intervention cannot select.
    pub protected_bundle_ids: Vec<String>,
    /// Executable paths that automatic memory intervention cannot select.
    pub protected_executable_paths: Vec<String>,
    /// The application budgets.
    pub app_budgets: Vec<AppBudgetView>,
}

impl MemoryGuardView {
    fn of(guard: &MemoryGuard) -> Self {
        Self {
            global_trigger: guard.global_trigger.as_str(),
            sustain_for: nanoseconds(guard.sustain_for),
            grace_period: nanoseconds(guard.grace_period),
            observe_after_action: nanoseconds(guard.observe_after_action),
            recovery_stable_for: nanoseconds(guard.recovery_stable_for),
            max_applications_per_incident: guard.max_applications_per_incident.get(),
            protect_foreground: guard.protect_foreground,
            allow_force_quit: guard.allow_force_quit,
            allow_volatile_journal_on_critical: guard.allow_volatile_journal_on_critical,
            eligible_groups: guard
                .eligible_groups
                .iter()
                .map(|group| group.as_str())
                .collect(),
            protected_bundle_ids: guard
                .protected_bundle_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            protected_executable_paths: guard
                .protected_executable_paths
                .iter()
                .map(ToString::to_string)
                .collect(),
            app_budgets: guard.app_budgets.iter().map(AppBudgetView::of).collect(),
        }
    }
}

/// The settings of one policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PolicySettings {
    /// The settings of the disk guard.
    DiskGuard(Box<DiskGuardView>),
    /// The settings of the memory guard.
    MemoryGuard(Box<MemoryGuardView>),
}

/// The description of one policy, for `policy show`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDescription {
    /// The policy.
    pub policy: PolicyId,
    /// True when the configuration enables the guard.
    pub enabled: bool,
    /// The profile of the configuration.
    pub profile: &'static str,
    /// True when the guard is enabled and the profile is not `observe`.
    pub intervention_requested: bool,
    /// The action classes that the policy can request.
    pub action_classes: &'static [&'static str],
    /// The schema version of the configuration.
    pub schema_version: u32,
    /// The revision of the template that supplied the omitted values.
    pub template_revision: u32,
    /// The timing values that the policy uses.
    pub agent: AgentTimingView,
    /// The protections that apply to each policy.
    pub protections: ProtectionsView,
    /// The settings of the policy.
    pub settings: PolicySettings,
    /// The key paths of the policy, of `[agent]`, and of `[protections]`
    /// that the document gives. Each other value comes from the template.
    pub explicit_keys: Vec<String>,
    /// The note that the values are not an effective revision.
    pub note: &'static str,
}

/// The description of one policy of a configuration, for `policy show`.
pub fn show_policy(config: &ValidatedConfig, policy: PolicyId) -> PolicyDescription {
    let entry: PolicyListEntry = list_entry(config, policy);
    let agent = config.agent();
    let protections = config.protections();
    let table: &str = match policy {
        PolicyId::DiskGuard => "disk_guard.",
        PolicyId::MemoryGuard => "memory_guard.",
    };
    PolicyDescription {
        policy,
        enabled: entry.enabled,
        profile: entry.profile,
        intervention_requested: entry.intervention_requested,
        action_classes: entry.action_classes,
        schema_version: config.schema_version(),
        template_revision: config.template_revision(),
        agent: AgentTimingView {
            sample_interval: nanoseconds(agent.sample_interval),
            pressure_sample_interval: nanoseconds(agent.pressure_sample_interval),
            decision_sample_max_age: nanoseconds(agent.decision_sample_max_age),
            max_qualifying_sample_gap: nanoseconds(agent.max_qualifying_sample_gap),
            plan_ttl: nanoseconds(agent.plan_ttl),
        },
        protections: ProtectionsView {
            excluded_paths: protections
                .excluded_paths
                .iter()
                .map(ToString::to_string)
                .collect(),
            protected_bundle_ids: protections
                .protected_bundle_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            protected_executable_paths: protections
                .protected_executable_paths
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
        settings: match policy {
            PolicyId::DiskGuard => {
                PolicySettings::DiskGuard(Box::new(DiskGuardView::of(config.disk_guard())))
            }
            PolicyId::MemoryGuard => {
                PolicySettings::MemoryGuard(Box::new(MemoryGuardView::of(config.memory_guard())))
            }
        },
        explicit_keys: config
            .explicit_keys()
            .filter(|key| {
                key.starts_with(table)
                    || key.starts_with("agent.")
                    || key.starts_with("protections.")
            })
            .map(str::to_owned)
            .collect(),
        note: DESCRIPTION_NOTE,
    }
}
