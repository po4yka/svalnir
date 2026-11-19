//! The scope of a policy revision and the typed difference of two scopes.
//!
//! A [`PolicyScope`] is the part of a validated configuration that decides
//! what automatic work can do: the eligible roots, the approved rule
//! revisions, the action classes, the protections, and the thresholds. The
//! caller persists it with the revision, so that a later activation can be
//! compared with it.
//!
//! [`difference`] compares two scopes. Each [`ScopeDifference`] has a kind
//! and an effect: narrowing, neutral, or widening. A widening difference
//! needs a new acceptance for the guard that it applies to
//! (`docs/POLICY_SPEC.md` sections 2 and 5).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{ActionClass, Escalation};
use crate::config::{AppBudget, Profile, ValidatedConfig};
use crate::id::RuleId;
use crate::policy::PolicyId;
use crate::quantity::{Bytes, Nanoseconds};
use crate::rule::{ApprovedRoot, Rule, RuleMode, RuleRef, RuleRegistry};

/// The reason a configuration has no scope.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScopeError {
    /// The registry has no rule with an identity that the configuration
    /// approves.
    #[error("the rule {rule} is not registered")]
    UnknownRule {
        /// The rule identity.
        rule: RuleId,
    },
    /// The registry has more than one revision of an approved rule, so the
    /// revision that the configuration approves is not known.
    #[error("the rule {rule} has more than one registered revision")]
    AmbiguousRule {
        /// The rule identity.
        rule: RuleId,
    },
    /// The implementation of an approved rule has no automatic eviction
    /// mode.
    #[error("the rule {} has no automatic eviction mode", rule.id)]
    NoAutomaticMode {
        /// The rule revision.
        rule: RuleRef,
    },
    /// A value of the configuration does not fit the scope record.
    #[error("the value of {key} is out of range")]
    ValueOutOfRange {
        /// The key path of the value.
        key: String,
    },
}

/// One numeric value of a configuration: a threshold, a ceiling, or a time.
/// The key has the format of a finding path, for example
/// `disk_guard.reclaim_below` or `memory_guard.app_budgets[ID].cooldown`.
/// A size is in bytes, a time is in nanoseconds, and a count is a number;
/// [`Threshold::unit`] gives the unit of a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    /// The key path.
    pub key: String,
    /// The value.
    pub value: u64,
}

/// The unit of the value of a [`Threshold`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdUnit {
    /// A size in bytes.
    Bytes,
    /// A time in nanoseconds.
    Nanoseconds,
    /// A count with no unit.
    Count,
}

/// The fields of the configuration schema that are a size in bytes.
const SIZE_FIELDS: [&str; 10] = [
    "warn_below",
    "reclaim_below",
    "emergency_below",
    "recover_above",
    "batch_limit",
    "pass_limit",
    "incident_limit",
    "footprint_soft",
    "footprint_stop",
    "footprint_recover",
];

/// The fields of the configuration schema that are a time.
const TIME_FIELDS: [&str; 16] = [
    "sustain_for",
    "emergency_sustain_for",
    "recovery_stable_for",
    "pass_time_limit",
    "pass_cooldown",
    "observe_after_action",
    "no_effect_backoff",
    "grace_period",
    "over_limit_for",
    "cooldown",
    "sample_interval",
    "pressure_sample_interval",
    "decision_sample_max_age",
    "max_qualifying_sample_gap",
    "plan_ttl",
    "manual_plan_ttl",
];

/// The fields of the configuration schema that are a count.
const COUNT_FIELDS: [&str; 5] = [
    "batch_item_limit",
    "pass_item_limit",
    "incident_item_limit",
    "max_passes_per_incident",
    "max_applications_per_incident",
];

/// The tables of the configuration schema that have a threshold.
const THRESHOLD_TABLES: [&str; 3] = ["agent", "disk_guard", "memory_guard"];

/// The unit of the threshold with the key path `key`. `None` when the key
/// is not a key that [`PolicyScope::of`] makes: this build does not know the
/// unit of its value.
///
/// The unit comes from the field name, which is the text after the last
/// `.` of the key path. The identifier of an application budget is in
/// brackets before that point, so it has no effect.
pub fn threshold_unit(key: &str) -> Option<ThresholdUnit> {
    let (table, _) = key.split_once('.')?;
    if !THRESHOLD_TABLES.contains(&table) {
        return None;
    }
    let (_, field) = key.rsplit_once('.')?;
    if SIZE_FIELDS.contains(&field) {
        Some(ThresholdUnit::Bytes)
    } else if TIME_FIELDS.contains(&field) {
        Some(ThresholdUnit::Nanoseconds)
    } else if COUNT_FIELDS.contains(&field) {
        Some(ThresholdUnit::Count)
    } else {
        None
    }
}

/// The value of a [`Threshold`] with its unit.
///
/// The text form is the form of the configuration grammar with the largest
/// unit that gives the value with no fraction: `25GiB`, `2m`, or `3`. The
/// text of a size or of a time is a text that
/// [`parse_byte_size`](crate::byte_size::parse_byte_size) or
/// [`parse_duration`](crate::duration::parse_duration) reads back to the same
/// value. A time that is not a whole number of milliseconds has no text in
/// that grammar; its text has the unit `ns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "unit", content = "value", rename_all = "snake_case")]
pub enum ThresholdValue {
    /// A size.
    Bytes(Bytes),
    /// A time.
    Nanoseconds(Nanoseconds),
    /// A count.
    Count(u64),
}

/// The text of `value` with the largest unit of `units` that divides it
/// with no remainder. `units` is in the sequence from the largest factor to
/// the smallest, and its last factor is 1.
fn exact_text(value: u64, units: &[(u64, &str)]) -> String {
    for (factor, unit) in units {
        if value != 0 && value.is_multiple_of(*factor) {
            return format!("{}{unit}", value / factor);
        }
    }
    let unit: &str = units.last().map_or("", |(_, unit)| unit);
    format!("{value}{unit}")
}

impl std::fmt::Display for ThresholdValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KIB: u64 = 1024;
        const MILLISECOND: u64 = 1_000_000;
        const SECOND: u64 = 1000 * MILLISECOND;
        let text: String = match self {
            Self::Bytes(size) => exact_text(
                size.get(),
                &[
                    (KIB * KIB * KIB * KIB, "TiB"),
                    (KIB * KIB * KIB, "GiB"),
                    (KIB * KIB, "MiB"),
                    (KIB, "KiB"),
                    (1, "B"),
                ],
            ),
            // The zero time is `0s`, as the configuration writes it.
            Self::Nanoseconds(time) if time.get() == 0 => "0s".to_owned(),
            Self::Nanoseconds(time) => exact_text(
                time.get(),
                &[
                    (86_400 * SECOND, "d"),
                    (3600 * SECOND, "h"),
                    (60 * SECOND, "m"),
                    (SECOND, "s"),
                    (MILLISECOND, "ms"),
                    (1, "ns"),
                ],
            ),
            Self::Count(count) => count.to_string(),
        };
        formatter.write_str(&text)
    }
}

impl Threshold {
    /// The unit of the value. See [`threshold_unit`].
    pub fn unit(&self) -> Option<ThresholdUnit> {
        threshold_unit(&self.key)
    }

    /// The value with its unit. `None` when this build does not know the
    /// unit of the key: the number then has no known meaning, and a view
    /// shows it with no unit and says so.
    pub fn typed_value(&self) -> Option<ThresholdValue> {
        self.unit().map(|unit| match unit {
            ThresholdUnit::Bytes => ThresholdValue::Bytes(Bytes::new(self.value)),
            ThresholdUnit::Nanoseconds => ThresholdValue::Nanoseconds(Nanoseconds::new(self.value)),
            ThresholdUnit::Count => ThresholdValue::Count(self.value),
        })
    }
}

/// One setting of a configuration with a text value. The key has the
/// format of a finding path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    /// The key path.
    pub key: String,
    /// The value, as text.
    pub value: String,
}

/// One approved rule revision and its roots.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleScope {
    /// The rule revision.
    pub reference: RuleRef,
    /// The approved roots of the revision.
    pub roots: Vec<ApprovedRoot>,
}

/// The scope of the disk guard.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskScope {
    /// True when the configuration requests an active disk policy.
    pub requested: bool,
    /// The logical volume selectors.
    pub volumes: Vec<String>,
    /// The approved rule revisions.
    pub rules: Vec<RuleScope>,
    /// The paths of `[disk_guard.exclusions]`.
    pub excluded_paths: Vec<String>,
    /// The thresholds, ceilings, and times of `[disk_guard]`.
    pub thresholds: Vec<Threshold>,
}

/// The scope of the memory guard.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one key of the configuration schema"
)]
pub struct MemoryScope {
    /// True when the configuration requests an active memory policy.
    pub requested: bool,
    /// True when the configuration permits automatic force quit.
    pub allow_force_quit: bool,
    /// True when the configuration permits the critical-memory exception
    /// of the journal.
    pub allow_volatile_journal_on_critical: bool,
    /// True when the foreground application is not eligible.
    pub protect_foreground: bool,
    /// The groups that automatic intervention can select from.
    pub eligible_groups: Vec<String>,
    /// The application budgets, each as `ID=BUNDLE_ID`.
    pub app_budgets: Vec<String>,
    /// The bundle identifiers of `[memory_guard]` that automatic
    /// intervention cannot select.
    pub protected_bundle_ids: Vec<String>,
    /// The executable paths of `[memory_guard]` that automatic intervention
    /// cannot select.
    pub protected_executable_paths: Vec<String>,
    /// The thresholds, ceilings, and times of `[memory_guard]` and of its
    /// application budgets.
    pub thresholds: Vec<Threshold>,
}

/// The scope of one validated configuration. Each list is in a canonical
/// sequence, so that equal configurations give equal scopes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScope {
    /// The profile, as its configuration text. A profile is not a grant.
    pub profile: String,
    /// The paths of `[protections]` that no action can include.
    pub excluded_paths: Vec<String>,
    /// The protected bundle identifiers of `[protections]`.
    pub protected_bundle_ids: Vec<String>,
    /// The protected executable paths of `[protections]`.
    pub protected_executable_paths: Vec<String>,
    /// The times of `[agent]` that automatic work uses.
    pub agent_thresholds: Vec<Threshold>,
    /// The settings that have one value in schema version 1: the removal
    /// mode, the global trigger, the data-class protections, and the
    /// restart strategy of each application budget. The record has them so
    /// that a later schema with another value gives a difference.
    pub fixed_settings: Vec<Setting>,
    /// The disk guard.
    pub disk: DiskScope,
    /// The memory guard.
    pub memory: MemoryScope,
}

fn sorted(mut texts: Vec<String>) -> Vec<String> {
    texts.sort();
    texts.dedup();
    texts
}

fn texts<T: ToString>(items: &[T]) -> Vec<String> {
    sorted(items.iter().map(ToString::to_string).collect())
}

fn time(key: &str, value: Duration) -> Result<Threshold, ScopeError> {
    let value: u64 = u64::try_from(value.as_nanos()).map_err(|_| ScopeError::ValueOutOfRange {
        key: key.to_owned(),
    })?;
    Ok(number(key, value))
}

fn number(key: &str, value: u64) -> Threshold {
    Threshold {
        key: key.to_owned(),
        value,
    }
}

fn by_key(mut thresholds: Vec<Threshold>) -> Vec<Threshold> {
    thresholds.sort_by(|left, right| left.key.cmp(&right.key));
    thresholds
}

/// The registered revision of each approved rule.
fn rule_scopes(
    approved: &[RuleId],
    registry: &dyn RuleRegistry,
) -> Result<Vec<RuleScope>, ScopeError> {
    let registered: Vec<&Rule> = registry.rules();
    let mut scopes: Vec<RuleScope> = Vec::with_capacity(approved.len());
    for rule_id in approved {
        let mut revisions = registered
            .iter()
            .filter(|rule| &rule.reference.id == rule_id);
        let Some(rule) = revisions.next() else {
            return Err(ScopeError::UnknownRule {
                rule: rule_id.clone(),
            });
        };
        if revisions.next().is_some() {
            return Err(ScopeError::AmbiguousRule {
                rule: rule_id.clone(),
            });
        }
        if !rule.modes.contains(&RuleMode::AutomaticEviction) {
            return Err(ScopeError::NoAutomaticMode {
                rule: rule.reference.clone(),
            });
        }
        let mut roots: Vec<ApprovedRoot> = rule.roots.clone();
        roots.sort_by(|left, right| {
            (left.base.as_str(), &left.relative).cmp(&(right.base.as_str(), &right.relative))
        });
        if !scopes.iter().any(|scope| scope.reference == rule.reference) {
            scopes.push(RuleScope {
                reference: rule.reference.clone(),
                roots,
            });
        }
    }
    scopes.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok(scopes)
}

/// The settings that have one value in schema version 1.
fn fixed_settings(config: &ValidatedConfig) -> Vec<Setting> {
    let disk = config.disk_guard();
    let memory = config.memory_guard();
    let setting = |key: &str, value: String| Setting {
        key: key.to_owned(),
        value,
    };
    let exclusions = &disk.exclusions;
    let mut settings: Vec<Setting> = vec![
        setting("disk_guard.automatic_mode", disk.automatic_mode.to_string()),
        setting(
            "disk_guard.exclusions.protect_archives",
            exclusions.protect_archives.to_string(),
        ),
        setting(
            "disk_guard.exclusions.protect_backups",
            exclusions.protect_backups.to_string(),
        ),
        setting(
            "disk_guard.exclusions.protect_databases",
            exclusions.protect_databases.to_string(),
        ),
        setting(
            "disk_guard.exclusions.protect_model_weights",
            exclusions.protect_model_weights.to_string(),
        ),
        setting(
            "memory_guard.global_trigger",
            memory.global_trigger.to_string(),
        ),
    ];
    for budget in &memory.app_budgets {
        settings.push(setting(
            &format!("memory_guard.app_budgets[{}].restart", budget.id),
            budget.restart.to_string(),
        ));
    }
    settings.sort_by(|left, right| left.key.cmp(&right.key));
    settings
}

fn budget_thresholds(budget: &AppBudget) -> Result<[Threshold; 5], ScopeError> {
    let key = |field: &str| format!("memory_guard.app_budgets[{}].{field}", budget.id);
    Ok([
        number(&key("footprint_soft"), budget.footprint_soft.get()),
        number(&key("footprint_stop"), budget.footprint_stop.get()),
        number(&key("footprint_recover"), budget.footprint_recover.get()),
        time(&key("over_limit_for"), budget.over_limit_for)?,
        time(&key("cooldown"), budget.cooldown)?,
    ])
}

impl DiskScope {
    fn of(config: &ValidatedConfig, registry: &dyn RuleRegistry) -> Result<Self, ScopeError> {
        let guard = config.disk_guard();
        let thresholds: Vec<Threshold> = vec![
            number("disk_guard.warn_below", guard.warn_below.get()),
            number("disk_guard.reclaim_below", guard.reclaim_below.get()),
            number("disk_guard.emergency_below", guard.emergency_below.get()),
            number("disk_guard.recover_above", guard.recover_above.get()),
            time("disk_guard.sustain_for", guard.sustain_for)?,
            time(
                "disk_guard.emergency_sustain_for",
                guard.emergency_sustain_for,
            )?,
            time("disk_guard.recovery_stable_for", guard.recovery_stable_for)?,
            number("disk_guard.batch_limit", guard.batch_limit.get()),
            number("disk_guard.pass_limit", guard.pass_limit.get()),
            number("disk_guard.incident_limit", guard.incident_limit.get()),
            number("disk_guard.batch_item_limit", guard.batch_item_limit.get()),
            number("disk_guard.pass_item_limit", guard.pass_item_limit.get()),
            number(
                "disk_guard.incident_item_limit",
                guard.incident_item_limit.get(),
            ),
            time("disk_guard.pass_time_limit", guard.pass_time_limit)?,
            number(
                "disk_guard.max_passes_per_incident",
                u64::from(guard.max_passes_per_incident.get()),
            ),
            time("disk_guard.pass_cooldown", guard.pass_cooldown)?,
            time(
                "disk_guard.observe_after_action",
                guard.observe_after_action,
            )?,
            time("disk_guard.no_effect_backoff", guard.no_effect_backoff)?,
        ];
        Ok(Self {
            requested: guard.enabled,
            volumes: texts(&guard.volumes),
            rules: rule_scopes(&guard.approved_rules, registry)?,
            excluded_paths: texts(&guard.exclusions.paths),
            thresholds: by_key(thresholds),
        })
    }
}

impl MemoryScope {
    fn of(config: &ValidatedConfig) -> Result<Self, ScopeError> {
        let guard = config.memory_guard();
        let mut thresholds: Vec<Threshold> = vec![
            time("memory_guard.sustain_for", guard.sustain_for)?,
            time("memory_guard.grace_period", guard.grace_period)?,
            time(
                "memory_guard.observe_after_action",
                guard.observe_after_action,
            )?,
            time(
                "memory_guard.recovery_stable_for",
                guard.recovery_stable_for,
            )?,
            number(
                "memory_guard.max_applications_per_incident",
                u64::from(guard.max_applications_per_incident.get()),
            ),
        ];
        for budget in &guard.app_budgets {
            thresholds.extend(budget_thresholds(budget)?);
        }
        let app_budgets: Vec<String> = guard
            .app_budgets
            .iter()
            .map(|budget| format!("{}={}", budget.id, budget.bundle_id))
            .collect();
        Ok(Self {
            requested: guard.enabled,
            allow_force_quit: guard.allow_force_quit,
            allow_volatile_journal_on_critical: guard.allow_volatile_journal_on_critical,
            protect_foreground: guard.protect_foreground,
            eligible_groups: texts(&guard.eligible_groups),
            app_budgets: sorted(app_budgets),
            protected_bundle_ids: texts(&guard.protected_bundle_ids),
            protected_executable_paths: texts(&guard.protected_executable_paths),
            thresholds: by_key(thresholds),
        })
    }
}

impl PolicyScope {
    /// The scope of `config`. `registry` gives the registered revision and
    /// the roots of each approved rule.
    ///
    /// The lifecycle state of a rule is not checked here: a rule that is
    /// only proposed can be in a scope, and the authorization refuses its
    /// automatic use.
    ///
    /// # Errors
    ///
    /// Returns a [`ScopeError`] when an approved rule is not registered,
    /// has more than one registered revision, or has no automatic eviction
    /// mode, and when a time does not fit the record.
    pub fn of(config: &ValidatedConfig, registry: &dyn RuleRegistry) -> Result<Self, ScopeError> {
        let agent = config.agent();
        let protections = config.protections();
        let agent_thresholds: Vec<Threshold> = vec![
            time("agent.sample_interval", agent.sample_interval)?,
            time(
                "agent.pressure_sample_interval",
                agent.pressure_sample_interval,
            )?,
            time(
                "agent.decision_sample_max_age",
                agent.decision_sample_max_age,
            )?,
            time(
                "agent.max_qualifying_sample_gap",
                agent.max_qualifying_sample_gap,
            )?,
            time("agent.plan_ttl", agent.plan_ttl)?,
            time("agent.manual_plan_ttl", agent.manual_plan_ttl)?,
        ];
        Ok(Self {
            profile: agent.profile.as_str().to_owned(),
            excluded_paths: texts(&protections.excluded_paths),
            protected_bundle_ids: texts(&protections.protected_bundle_ids),
            protected_executable_paths: texts(&protections.protected_executable_paths),
            agent_thresholds: by_key(agent_thresholds),
            fixed_settings: fixed_settings(config),
            disk: DiskScope::of(config, registry)?,
            memory: MemoryScope::of(config)?,
        })
    }

    /// The scope before the first activation: the `observe` profile, no
    /// requested guard, no root, no rule, and no threshold.
    pub(super) fn none() -> Self {
        Self {
            profile: Profile::Observe.as_str().to_owned(),
            excluded_paths: Vec::new(),
            protected_bundle_ids: Vec::new(),
            protected_executable_paths: Vec::new(),
            agent_thresholds: Vec::new(),
            fixed_settings: Vec::new(),
            disk: DiskScope {
                requested: false,
                volumes: Vec::new(),
                rules: Vec::new(),
                excluded_paths: Vec::new(),
                thresholds: Vec::new(),
            },
            memory: MemoryScope {
                requested: false,
                allow_force_quit: false,
                allow_volatile_journal_on_critical: false,
                protect_foreground: true,
                eligible_groups: Vec::new(),
                app_budgets: Vec::new(),
                protected_bundle_ids: Vec::new(),
                protected_executable_paths: Vec::new(),
                thresholds: Vec::new(),
            },
        }
    }

    /// Whether the profile permits automatic intervention. Only `observe`
    /// does not. A profile text that this build does not know permits
    /// nothing.
    pub fn profile_permits_intervention(&self) -> bool {
        Profile::from_text(&self.profile).is_some_and(|profile| profile != Profile::Observe)
    }

    /// Whether the configuration requests `policy`.
    pub const fn requests(&self, policy: PolicyId) -> bool {
        match policy {
            PolicyId::DiskGuard => self.disk.requested,
            PolicyId::MemoryGuard => self.memory.requested,
        }
    }

    /// The action classes that the configuration of `policy` can use, in
    /// the sequence of the specification. A guard that the configuration
    /// does not request uses none. The acceptance of exactly these classes
    /// enables the guard.
    pub fn action_classes(&self, policy: PolicyId) -> Vec<ActionClass> {
        match policy {
            PolicyId::DiskGuard if self.disk.requested => {
                vec![ActionClass::EvictRegenerableData]
            }
            PolicyId::MemoryGuard if self.memory.requested && self.memory.allow_force_quit => {
                vec![
                    ActionClass::RequestApplicationExit,
                    ActionClass::ForceApplicationExit,
                ]
            }
            PolicyId::MemoryGuard if self.memory.requested => {
                vec![ActionClass::RequestApplicationExit]
            }
            PolicyId::DiskGuard | PolicyId::MemoryGuard => Vec::new(),
        }
    }

    /// The force strategies that the configuration of `policy` can use, in
    /// addition to a graceful request. The configuration of schema version
    /// 1 has no immediate force.
    pub fn escalations(&self, policy: PolicyId) -> Vec<Escalation> {
        match policy {
            PolicyId::MemoryGuard if self.memory.requested && self.memory.allow_force_quit => {
                vec![Escalation::ForceAfterGrace]
            }
            PolicyId::DiskGuard | PolicyId::MemoryGuard => Vec::new(),
        }
    }

    /// The rule revisions that the configuration of `policy` approves.
    pub fn rules(&self, policy: PolicyId) -> Vec<RuleRef> {
        match policy {
            PolicyId::DiskGuard => self
                .disk
                .rules
                .iter()
                .map(|rule| rule.reference.clone())
                .collect(),
            PolicyId::MemoryGuard => Vec::new(),
        }
    }
}

/// The kind of a scope difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDifferenceKind {
    /// The profile.
    Profile,
    /// A place or a target group that automatic work can select from: a
    /// volume, a root of a rule, an application group, or an application
    /// budget.
    EligibleRoot,
    /// An approved rule revision.
    ApprovedRule,
    /// An action class or a force strategy that a guard can use.
    ActionClass,
    /// The critical-memory exception of the journal.
    RecordingException,
    /// A protection of a target. The removal of a protection is an
    /// exception for the targets that it covered.
    ProtectedTargetException,
    /// A threshold, a ceiling, or a time.
    Threshold,
}

/// The effect of a scope difference on what automatic work can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeEffect {
    /// Automatic work can do less. No acceptance is necessary.
    Narrowing,
    /// Automatic work can do the same.
    Neutral,
    /// Automatic work can do more, or the effect is not known. A new
    /// acceptance is necessary.
    Widening,
}

/// The guards that a scope difference applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffectedGuards {
    /// The disk guard.
    DiskGuard,
    /// The memory guard.
    MemoryGuard,
    /// The two guards.
    Both,
}

impl AffectedGuards {
    /// Whether the difference applies to `policy`.
    pub const fn includes(self, policy: PolicyId) -> bool {
        matches!(
            (self, policy),
            (Self::Both, _)
                | (Self::DiskGuard, PolicyId::DiskGuard)
                | (Self::MemoryGuard, PolicyId::MemoryGuard)
        )
    }
}

/// The table of a protection entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTable {
    /// `[protections]`: manual and automatic actions.
    Protections,
    /// `[disk_guard.exclusions]`: automatic disk-guard work.
    DiskGuardExclusions,
    /// `[memory_guard]`: automatic memory intervention.
    MemoryGuard,
}

/// What a scope difference is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum ScopeSubject {
    /// The profile.
    Profile,
    /// A volume selector of the disk guard.
    Volume {
        /// The selector.
        selector: String,
    },
    /// An approved root of a rule revision.
    RuleRoot {
        /// The rule revision.
        rule: RuleRef,
        /// The root.
        root: ApprovedRoot,
    },
    /// A group that automatic memory intervention can select from.
    EligibleGroup {
        /// The group.
        group: String,
    },
    /// An application budget, as `ID=BUNDLE_ID`.
    AppBudget {
        /// The budget.
        budget: String,
    },
    /// An approved rule revision.
    ApprovedRule {
        /// The rule revision.
        rule: RuleRef,
    },
    /// An action class that a guard can use.
    ActionClass {
        /// The action class.
        class: ActionClass,
    },
    /// A force strategy that the memory guard can use.
    Escalation {
        /// The force strategy.
        escalation: Escalation,
    },
    /// The critical-memory exception of the journal.
    VolatileJournalOnCritical,
    /// A path that an action cannot include.
    ExcludedPath {
        /// The table of the entry.
        table: ProtectionTable,
        /// The path.
        path: String,
    },
    /// A bundle identifier of a protected application.
    ProtectedBundleId {
        /// The table of the entry.
        table: ProtectionTable,
        /// The bundle identifier.
        bundle_id: String,
    },
    /// An executable path of a protected application.
    ProtectedExecutablePath {
        /// The table of the entry.
        table: ProtectionTable,
        /// The path.
        path: String,
    },
    /// The protection of the foreground application.
    ForegroundProtection,
    /// A threshold, a ceiling, or a time.
    Threshold {
        /// The key path.
        key: String,
    },
}

/// How the subject changed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum ScopeChange {
    /// The new scope has the subject and the old scope does not.
    Added,
    /// The old scope has the subject and the new scope does not.
    Removed,
    /// The value of the subject changed.
    Changed {
        /// The old value.
        from: String,
        /// The new value.
        to: String,
    },
}

/// One difference of two scopes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDifference {
    /// The kind.
    pub kind: ScopeDifferenceKind,
    /// The guards that the difference applies to.
    pub guards: AffectedGuards,
    /// What the difference is about.
    pub subject: ScopeSubject,
    /// How the subject changed.
    pub change: ScopeChange,
    /// The effect on what automatic work can do.
    pub effect: ScopeEffect,
}

/// The direction in which a larger threshold value changes the scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// A larger value lets automatic work do more.
    LargerIsWider,
    /// A smaller value lets automatic work do more.
    SmallerIsWider,
    /// The value has no effect on what automatic work can do.
    Neutral,
    /// The effect of a change is not known, so each change is widening.
    Unordered,
}

/// The direction of the threshold `key`. A key that this build does not
/// know is unordered.
fn direction(key: &str) -> Direction {
    let section: &str = key.split('.').next().unwrap_or(key);
    let field: &str = key.rsplit('.').next().unwrap_or(key);
    let is_budget: bool = key.starts_with("memory_guard.app_budgets[");
    match (section, field) {
        ("agent", "sample_interval" | "pressure_sample_interval" | "manual_plan_ttl")
        | ("disk_guard", "warn_below") => Direction::Neutral,
        ("agent", "decision_sample_max_age" | "max_qualifying_sample_gap" | "plan_ttl")
        | (
            "disk_guard",
            "reclaim_below"
            | "emergency_below"
            | "recover_above"
            | "batch_limit"
            | "pass_limit"
            | "incident_limit"
            | "batch_item_limit"
            | "pass_item_limit"
            | "incident_item_limit"
            | "pass_time_limit"
            | "max_passes_per_incident",
        ) => Direction::LargerIsWider,
        (
            "disk_guard",
            "sustain_for"
            | "emergency_sustain_for"
            | "pass_cooldown"
            | "observe_after_action"
            | "no_effect_backoff",
        ) => Direction::SmallerIsWider,
        ("memory_guard", "footprint_soft") if is_budget => Direction::Neutral,
        ("memory_guard", "footprint_stop" | "over_limit_for" | "cooldown") if is_budget => {
            Direction::SmallerIsWider
        }
        ("memory_guard", "sustain_for" | "grace_period" | "observe_after_action") if !is_budget => {
            Direction::SmallerIsWider
        }
        ("memory_guard", "max_applications_per_incident") if !is_budget => Direction::LargerIsWider,
        _ => Direction::Unordered,
    }
}

/// The guards that the threshold `key` applies to.
fn guards_of(key: &str) -> AffectedGuards {
    match key.split('.').next() {
        Some("disk_guard") => AffectedGuards::DiskGuard,
        Some("memory_guard") => AffectedGuards::MemoryGuard,
        _ => AffectedGuards::Both,
    }
}

/// Collects the differences in a fixed sequence.
struct Differences(Vec<ScopeDifference>);

impl Differences {
    fn push(
        &mut self,
        kind: ScopeDifferenceKind,
        guards: AffectedGuards,
        subject: ScopeSubject,
        change: ScopeChange,
        effect: ScopeEffect,
    ) {
        self.0.push(ScopeDifference {
            kind,
            guards,
            subject,
            change,
            effect,
        });
    }

    /// The entries that only one of two lists has. `added` is the effect of
    /// an entry that only `new` has; a removed entry has the opposite
    /// effect.
    fn entries<T: PartialEq>(
        &mut self,
        kind: ScopeDifferenceKind,
        guards: AffectedGuards,
        (old, new): (&[T], &[T]),
        added: ScopeEffect,
        subject: impl Fn(&T) -> ScopeSubject,
    ) {
        let removed: ScopeEffect = match added {
            ScopeEffect::Widening => ScopeEffect::Narrowing,
            ScopeEffect::Narrowing => ScopeEffect::Widening,
            ScopeEffect::Neutral => ScopeEffect::Neutral,
        };
        for entry in new.iter().filter(|entry| !old.contains(entry)) {
            self.push(kind, guards, subject(entry), ScopeChange::Added, added);
        }
        for entry in old.iter().filter(|entry| !new.contains(entry)) {
            self.push(kind, guards, subject(entry), ScopeChange::Removed, removed);
        }
    }

    /// A flag whose `true` value lets automatic work do more.
    fn permission(
        &mut self,
        kind: ScopeDifferenceKind,
        guards: AffectedGuards,
        subject: ScopeSubject,
        (old, new): (bool, bool),
    ) {
        if old == new {
            return;
        }
        let (change, effect) = if new {
            (ScopeChange::Added, ScopeEffect::Widening)
        } else {
            (ScopeChange::Removed, ScopeEffect::Narrowing)
        };
        self.push(kind, guards, subject, change, effect);
    }

    fn thresholds(&mut self, old: &[Threshold], new: &[Threshold]) {
        let subject = |key: &str| ScopeSubject::Threshold {
            key: key.to_owned(),
        };
        // An application budget that only one scope has is an eligible-root
        // difference. Its thresholds are not listed again.
        let is_budget = |key: &str| key.starts_with("memory_guard.app_budgets[");
        for threshold in new {
            let key: &str = &threshold.key;
            let Some(earlier) = old.iter().find(|earlier| earlier.key == key) else {
                if !is_budget(key) {
                    self.push(
                        ScopeDifferenceKind::Threshold,
                        guards_of(key),
                        subject(key),
                        ScopeChange::Added,
                        ScopeEffect::Widening,
                    );
                }
                continue;
            };
            if earlier.value == threshold.value {
                continue;
            }
            let larger: bool = threshold.value > earlier.value;
            let effect: ScopeEffect = match direction(key) {
                Direction::Neutral => ScopeEffect::Neutral,
                Direction::Unordered => ScopeEffect::Widening,
                Direction::LargerIsWider if larger => ScopeEffect::Widening,
                Direction::SmallerIsWider if !larger => ScopeEffect::Widening,
                Direction::LargerIsWider | Direction::SmallerIsWider => ScopeEffect::Narrowing,
            };
            self.push(
                ScopeDifferenceKind::Threshold,
                guards_of(key),
                subject(key),
                ScopeChange::Changed {
                    from: earlier.value.to_string(),
                    to: threshold.value.to_string(),
                },
                effect,
            );
        }
        for threshold in old {
            let key: &str = &threshold.key;
            if !is_budget(key) && !new.iter().any(|later| later.key == key) {
                // The value that now applies is not known to this record.
                self.push(
                    ScopeDifferenceKind::Threshold,
                    guards_of(key),
                    subject(key),
                    ScopeChange::Removed,
                    ScopeEffect::Widening,
                );
            }
        }
    }

    /// A setting with one value in schema version 1. The effect of another
    /// value is not known to this build, so each difference is widening. A
    /// setting of an application budget that only one scope has is not
    /// listed: the budget is an eligible-root difference.
    fn fixed_settings(&mut self, old: &[Setting], new: &[Setting]) {
        let is_budget = |key: &str| key.starts_with("memory_guard.app_budgets[");
        let mut push = |key: &str, change: ScopeChange| {
            self.push(
                ScopeDifferenceKind::Threshold,
                guards_of(key),
                ScopeSubject::Threshold {
                    key: key.to_owned(),
                },
                change,
                ScopeEffect::Widening,
            );
        };
        for setting in new {
            match old.iter().find(|earlier| earlier.key == setting.key) {
                Some(earlier) if earlier.value == setting.value => {}
                Some(earlier) => push(
                    &setting.key,
                    ScopeChange::Changed {
                        from: earlier.value.clone(),
                        to: setting.value.clone(),
                    },
                ),
                None if is_budget(&setting.key) => {}
                None => push(&setting.key, ScopeChange::Added),
            }
        }
        for setting in old {
            if !is_budget(&setting.key) && !new.iter().any(|later| later.key == setting.key) {
                push(&setting.key, ScopeChange::Removed);
            }
        }
    }

    fn profile(&mut self, old: &PolicyScope, new: &PolicyScope) {
        if old.profile == new.profile {
            return;
        }
        // The values of a profile are compared one by one. Only the change
        // to or from `observe` has an effect of its own.
        let effect: ScopeEffect = match (
            old.profile_permits_intervention(),
            new.profile_permits_intervention(),
        ) {
            (false, true) => ScopeEffect::Widening,
            (true, false) => ScopeEffect::Narrowing,
            _ => ScopeEffect::Neutral,
        };
        self.push(
            ScopeDifferenceKind::Profile,
            AffectedGuards::Both,
            ScopeSubject::Profile,
            ScopeChange::Changed {
                from: old.profile.clone(),
                to: new.profile.clone(),
            },
            effect,
        );
    }

    fn protections(&mut self, old: &PolicyScope, new: &PolicyScope) {
        use ProtectionTable::{DiskGuardExclusions, MemoryGuard, Protections};
        let kind = ScopeDifferenceKind::ProtectedTargetException;
        let narrowing = ScopeEffect::Narrowing;
        let path_lists = [
            (
                Protections,
                AffectedGuards::DiskGuard,
                (&old.excluded_paths, &new.excluded_paths),
            ),
            (
                DiskGuardExclusions,
                AffectedGuards::DiskGuard,
                (&old.disk.excluded_paths, &new.disk.excluded_paths),
            ),
        ];
        for (table, guards, (before, after)) in path_lists {
            self.entries(kind, guards, (before, after), narrowing, |path| {
                ScopeSubject::ExcludedPath {
                    table,
                    path: path.clone(),
                }
            });
        }
        let memory = AffectedGuards::MemoryGuard;
        let bundle_lists = [
            (
                Protections,
                (&old.protected_bundle_ids, &new.protected_bundle_ids),
            ),
            (
                MemoryGuard,
                (
                    &old.memory.protected_bundle_ids,
                    &new.memory.protected_bundle_ids,
                ),
            ),
        ];
        for (table, (before, after)) in bundle_lists {
            self.entries(kind, memory, (before, after), narrowing, |bundle_id| {
                ScopeSubject::ProtectedBundleId {
                    table,
                    bundle_id: bundle_id.clone(),
                }
            });
        }
        let executable_lists = [
            (
                Protections,
                (
                    &old.protected_executable_paths,
                    &new.protected_executable_paths,
                ),
            ),
            (
                MemoryGuard,
                (
                    &old.memory.protected_executable_paths,
                    &new.memory.protected_executable_paths,
                ),
            ),
        ];
        for (table, (before, after)) in executable_lists {
            self.entries(kind, memory, (before, after), narrowing, |path| {
                ScopeSubject::ProtectedExecutablePath {
                    table,
                    path: path.clone(),
                }
            });
        }
        // The foreground application is eligible when the protection is off.
        self.permission(
            kind,
            memory,
            ScopeSubject::ForegroundProtection,
            (
                !old.memory.protect_foreground,
                !new.memory.protect_foreground,
            ),
        );
    }

    fn roots(&mut self, old: &PolicyScope, new: &PolicyScope) {
        let kind = ScopeDifferenceKind::EligibleRoot;
        let widening = ScopeEffect::Widening;
        let disk = AffectedGuards::DiskGuard;
        let memory = AffectedGuards::MemoryGuard;
        self.entries(
            kind,
            disk,
            (&old.disk.volumes, &new.disk.volumes),
            widening,
            |selector| ScopeSubject::Volume {
                selector: selector.clone(),
            },
        );
        let roots = |scope: &PolicyScope| -> Vec<(RuleRef, ApprovedRoot)> {
            scope
                .disk
                .rules
                .iter()
                .flat_map(|rule| {
                    rule.roots
                        .iter()
                        .map(|root| (rule.reference.clone(), root.clone()))
                })
                .collect()
        };
        self.entries(
            kind,
            disk,
            (&roots(old), &roots(new)),
            widening,
            |(rule, root)| ScopeSubject::RuleRoot {
                rule: rule.clone(),
                root: root.clone(),
            },
        );
        self.entries(
            kind,
            memory,
            (&old.memory.eligible_groups, &new.memory.eligible_groups),
            widening,
            |group| ScopeSubject::EligibleGroup {
                group: group.clone(),
            },
        );
        self.entries(
            kind,
            memory,
            (&old.memory.app_budgets, &new.memory.app_budgets),
            widening,
            |budget| ScopeSubject::AppBudget {
                budget: budget.clone(),
            },
        );
    }

    fn classes(&mut self, old: &PolicyScope, new: &PolicyScope) {
        let kind = ScopeDifferenceKind::ActionClass;
        let widening = ScopeEffect::Widening;
        for (policy, guards) in [
            (PolicyId::DiskGuard, AffectedGuards::DiskGuard),
            (PolicyId::MemoryGuard, AffectedGuards::MemoryGuard),
        ] {
            self.entries(
                kind,
                guards,
                (&old.action_classes(policy), &new.action_classes(policy)),
                widening,
                |class| ScopeSubject::ActionClass {
                    class: class.clone(),
                },
            );
            self.entries(
                kind,
                guards,
                (&old.escalations(policy), &new.escalations(policy)),
                widening,
                |escalation| ScopeSubject::Escalation {
                    escalation: escalation.clone(),
                },
            );
        }
        self.permission(
            ScopeDifferenceKind::RecordingException,
            AffectedGuards::MemoryGuard,
            ScopeSubject::VolatileJournalOnCritical,
            (
                old.memory.allow_volatile_journal_on_critical,
                new.memory.allow_volatile_journal_on_critical,
            ),
        );
    }
}

/// The differences from `old` to `new`, in a fixed sequence.
///
/// The classification fails closed:
///
/// - A new volume, rule root, application group, application budget, rule
///   revision, action class, or force strategy is widening. Its removal is
///   narrowing. A different revision of an approved rule is a removal and
///   an addition, so it is widening: the approval of a rule identity does
///   not approve a later implementation.
/// - The removal of a protection entry is widening, and its addition is
///   narrowing. Two entries are compared as text, so an entry that is
///   written differently is a removal and an addition.
/// - A setting that has one value in schema version 1 is widening for each
///   difference.
/// - A threshold is widening in the direction that lets automatic work
///   start earlier, do more, or wait less. A threshold with an effect that
///   is not known, and a threshold that only one scope has, is widening.
/// - A profile change is widening from `observe`, narrowing to `observe`,
///   and neutral between the other profiles: their values are compared one
///   by one.
pub fn difference(old: &PolicyScope, new: &PolicyScope) -> Vec<ScopeDifference> {
    let mut differences: Differences = Differences(Vec::new());
    differences.profile(old, new);
    differences.roots(old, new);
    differences.entries(
        ScopeDifferenceKind::ApprovedRule,
        AffectedGuards::DiskGuard,
        (
            &old.rules(PolicyId::DiskGuard),
            &new.rules(PolicyId::DiskGuard),
        ),
        ScopeEffect::Widening,
        |rule| ScopeSubject::ApprovedRule { rule: rule.clone() },
    );
    differences.classes(old, new);
    differences.protections(old, new);
    differences.thresholds(&old.agent_thresholds, &new.agent_thresholds);
    differences.thresholds(&old.disk.thresholds, &new.disk.thresholds);
    differences.thresholds(&old.memory.thresholds, &new.memory.thresholds);
    differences.fixed_settings(&old.fixed_settings, &new.fixed_settings);
    differences.0
}

/// The effect of `differences` on `policy`: widening when one difference
/// that applies to the guard is widening, else narrowing when one is
/// narrowing, else neutral.
pub fn effect_on(differences: &[ScopeDifference], policy: PolicyId) -> ScopeEffect {
    let effects = || {
        differences
            .iter()
            .filter(|difference| difference.guards.includes(policy))
            .map(|difference| difference.effect)
    };
    if effects().any(|effect| effect == ScopeEffect::Widening) {
        ScopeEffect::Widening
    } else if effects().any(|effect| effect == ScopeEffect::Narrowing) {
        ScopeEffect::Narrowing
    } else {
        ScopeEffect::Neutral
    }
}
