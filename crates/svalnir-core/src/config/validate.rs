//! The parse-and-validate pass.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::time::Duration;

use toml::Table;

use super::check::CheckReport;
use super::finding::{Finding, FindingCode, Location};
use super::path::ConfigPath;
use super::reader::{Context, Read, TableReader, join_path};
use super::schema::{
    AgentConfig, AppBudget, AppBudgetId, AutomaticMode, BundleId, CacheCleanup, Cleanup,
    DiskExclusions, DiskGuard, EligibleGroup, GlobalTrigger, History, MAX_QUIET_PERIOD,
    MIN_QUIET_PERIOD, MemoryGuard, Privacy, Profile, ProjectCleanup, Protections, RestartPolicy,
    SCHEMA_VERSION, ValidatedConfig, VolumeSelector,
};
use super::template::{TEMPLATE_REVISION, Template};
use crate::id::RuleId;
use crate::quantity::{Bytes, EntryCount};

/// The largest accepted size of a configuration text, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The largest number of `[[memory_guard.app_budgets]]` tables.
pub const MAX_APP_BUDGETS: usize = 256;

/// The result of [`parse_and_validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    /// The checks that ran and the checks that need the agent.
    pub checks: CheckReport,
    /// The validated configuration, or each finding of the portable checks.
    /// A list of findings is not empty.
    pub result: Result<ValidatedConfig, Vec<Finding>>,
}

impl Validation {
    /// The validated configuration, when the portable checks passed.
    pub fn config(&self) -> Option<&ValidatedConfig> {
        self.result.as_ref().ok()
    }

    /// The findings. The list is empty when the portable checks passed.
    pub fn findings(&self) -> &[Finding] {
        self.result.as_ref().err().map_or(&[], Vec::as_slice)
    }
}

/// Parses a configuration text and does the portable checks: syntax, schema,
/// and the required relationships of `docs/POLICY_SPEC.md` section 3.
///
/// The function is pure. It does not read a file, the environment, or the
/// clock, and it does not expand a path. It reports each finding of the
/// document, not only the first finding.
///
/// A result without findings is a validated proposal. It is not a statement
/// that the configuration can become active: [`Validation::checks`] names
/// the live checks that only the agent can do.
pub fn parse_and_validate(text: &str) -> Validation {
    let mut context: Context = Context::default();
    let table: Option<Table> = parse_document(&mut context, text);
    let (config, schema_complete): (Option<ValidatedConfig>, bool) = match &table {
        Some(table) => read_document(&mut context, table),
        None => (None, false),
    };
    let (findings, explicit): (Vec<Finding>, BTreeSet<String>) = context.into_parts();
    let checks: CheckReport =
        CheckReport::from_findings(&findings, table.is_some(), schema_complete);
    let result: Result<ValidatedConfig, Vec<Finding>> = match config {
        Some(mut config) if findings.is_empty() => {
            config.explicit = explicit;
            Ok(config)
        }
        _ => Err(findings),
    };
    Validation { checks, result }
}

fn parse_document(context: &mut Context, text: &str) -> Option<Table> {
    if text.len() > MAX_DOCUMENT_BYTES {
        context.report(
            FindingCode::DocumentTooLarge,
            "",
            format!("the document is larger than {MAX_DOCUMENT_BYTES} bytes"),
        );
        return None;
    }
    match toml::from_str::<Table>(text) {
        Ok(table) => Some(table),
        Err(error) => {
            let location: Option<Location> = error
                .span()
                .and_then(|span| text.get(..span.start))
                .map(location_after);
            // The parser message can repeat text of the document, thus the
            // finding has a fixed message and the position.
            context.report_at(
                FindingCode::Syntax,
                "",
                "the text is not a valid TOML document",
                location,
            );
            None
        }
    }
}

/// The position of the character that follows `before`.
fn location_after(before: &str) -> Location {
    let line: usize = before.matches('\n').count() + 1;
    let line_start: usize = before.rfind('\n').map_or(0, |index| index + 1);
    let column: usize = before
        .get(line_start..)
        .map_or(0, |line_text| line_text.chars().count())
        + 1;
    Location {
        line: u32::try_from(line).unwrap_or(u32::MAX),
        column: u32::try_from(column).unwrap_or(u32::MAX),
    }
}

/// Reads the document. The flag is false when the schema version stopped the
/// read before the tables.
fn read_document(context: &mut Context, table: &Table) -> (Option<ValidatedConfig>, bool) {
    let template: Template = Template::schema_v1();
    let mut root: TableReader<'_> = TableReader::new(Some(table), String::new());

    let version: Read<i64> = root.integer(context, "schema_version");
    if let Read::Valid(version) = version
        && version != i64::from(SCHEMA_VERSION)
    {
        context.report(
            FindingCode::UnsupportedSchemaVersion,
            "schema_version",
            format!("only schema version {SCHEMA_VERSION} is supported"),
        );
        return (None, false);
    }
    // An absent or mistyped version has a finding. Read the tables as
    // version 1, so that one pass shows the other findings also.
    let _: Option<i64> = root.require(context, "schema_version", version);

    let agent_table: TableReader<'_> = root.table(context, "agent");
    let (agent, plan_ttl): (AgentConfig, Option<Duration>) =
        read_agent(context, agent_table, &template.agent);
    let protections_table: TableReader<'_> = root.table(context, "protections");
    let protections: Protections =
        read_protections(context, protections_table, &template.excluded_paths);
    let disk_table: TableReader<'_> = root.table(context, "disk_guard");
    let disk_guard: DiskGuard = read_disk_guard(context, disk_table, &template.disk_guard);
    let memory_table: TableReader<'_> = root.table(context, "memory_guard");
    let (memory_guard, grace_period): (MemoryGuard, Option<Duration>) =
        read_memory_guard(context, memory_table, &template.memory_guard);
    let cleanup_table: TableReader<'_> = root.table(context, "cleanup");
    let cleanup: Cleanup = read_cleanup(context, cleanup_table, &template.cleanup);
    let history_table: TableReader<'_> = root.table(context, "history");
    let history: History = read_history(context, history_table, &template.history);
    let privacy_table: TableReader<'_> = root.table(context, "privacy");
    let privacy: Privacy = read_privacy(context, privacy_table, &template.privacy);
    root.finish(context);

    // A plan that the agent prepares must allow the grace interval.
    require_order(
        context,
        FindingCode::TimingOrder,
        ("memory_guard.grace_period", grace_period),
        Relation::AtMost,
        ("agent.plan_ttl", plan_ttl),
    );

    let config: ValidatedConfig = ValidatedConfig {
        template_revision: TEMPLATE_REVISION,
        agent,
        protections,
        disk_guard,
        memory_guard,
        cleanup,
        history,
        privacy,
        explicit: BTreeSet::new(),
    };
    (Some(config), true)
}

/// The relation that two values must have.
#[derive(Debug, Clone, Copy)]
enum Relation {
    Less,
    AtMost,
}

/// Reports a finding when `left` and `right` do not have the relation. A
/// `None` value already has a finding, and the function ignores the pair.
fn require_order<T: PartialOrd>(
    context: &mut Context,
    code: FindingCode,
    (left_path, left): (&str, Option<T>),
    relation: Relation,
    (right_path, right): (&str, Option<T>),
) {
    let (Some(left), Some(right)) = (left, right) else {
        return;
    };
    let (holds, words): (bool, &str) = match relation {
        Relation::Less => (left < right, "must be less than"),
        Relation::AtMost => (left <= right, "must not be larger than"),
    };
    if holds {
        return;
    }
    let left_explicit: bool = context.is_explicit(left_path);
    let right_explicit: bool = context.is_explicit(right_path);
    let note: &str = match (left_explicit, right_explicit) {
        (true, false) => "; the second value comes from the template, because the key is absent",
        (false, true) => "; the first value comes from the template, because the key is absent",
        _ => "",
    };
    let path: &str = if left_explicit || !right_explicit {
        left_path
    } else {
        right_path
    };
    context.report(
        code,
        path,
        format!("`{left_path}` {words} `{right_path}`{note}"),
    );
}

/// Reads an enumeration value.
fn read_choice<T: Copy>(
    context: &mut Context,
    read: Read<(String, &str)>,
    from_text: impl Fn(&str) -> Option<T>,
    permitted: &[&str],
) -> Read<T> {
    match read {
        Read::Absent => Read::Absent,
        Read::Invalid => Read::Invalid,
        Read::Valid((path, text)) => {
            if let Some(value) = from_text(text) {
                Read::Valid(value)
            } else {
                let list: String = permitted
                    .iter()
                    .map(|value| format!("`{value}`"))
                    .collect::<Vec<String>>()
                    .join(", ");
                context.report(
                    FindingCode::UnknownValue,
                    &path,
                    format!("the value is not supported in schema version 1; use {list}"),
                );
                Read::Invalid
            }
        }
    }
}

/// Converts each text of a list and reports each entry that occurs again.
/// An absent list is empty.
fn read_list<T: Ord + Clone>(
    context: &mut Context,
    read: Read<Vec<(String, &str)>>,
    code: FindingCode,
    convert: impl Fn(&str) -> Result<T, String>,
) -> Option<Vec<T>> {
    let texts: Vec<(String, &str)> = match read {
        Read::Absent => return Some(Vec::new()),
        Read::Invalid => return None,
        Read::Valid(texts) => texts,
    };
    let mut values: Vec<T> = Vec::with_capacity(texts.len());
    let mut seen: BTreeSet<T> = BTreeSet::new();
    let mut complete: bool = true;
    for (path, text) in texts {
        match convert(text) {
            Ok(value) => {
                if seen.insert(value.clone()) {
                    values.push(value);
                } else {
                    context.report(
                        FindingCode::DuplicateIdentifier,
                        &path,
                        "the entry occurs more than one time in the list",
                    );
                    complete = false;
                }
            }
            Err(message) => {
                context.report(code, &path, message);
                complete = false;
            }
        }
    }
    complete.then_some(values)
}

fn read_paths(context: &mut Context, read: Read<Vec<(String, &str)>>) -> Vec<ConfigPath> {
    read_list(context, read, FindingCode::InvalidPath, |text: &str| {
        ConfigPath::parse(text).map_err(|error| error.to_string())
    })
    .unwrap_or_default()
}

fn read_bundle_ids(context: &mut Context, read: Read<Vec<(String, &str)>>) -> Vec<BundleId> {
    read_list(
        context,
        read,
        FindingCode::InvalidIdentifier,
        |text: &str| BundleId::new(text).ok_or_else(|| BUNDLE_ID_GRAMMAR.to_owned()),
    )
    .unwrap_or_default()
}

const BUNDLE_ID_GRAMMAR: &str =
    "a bundle identifier has 1 to 255 characters of `A-Za-z0-9`, `.`, `-`, and `_`";
const IDENTIFIER_GRAMMAR: &str = "the identifier has 1 to 128 characters of `A-Za-z0-9._:-`";

/// Reads `[agent]`. The second value is `plan_ttl` for the check against the
/// grace period, or `None` when the key has a finding.
fn read_agent(
    context: &mut Context,
    mut table: TableReader<'_>,
    defaults: &AgentConfig,
) -> (AgentConfig, Option<Duration>) {
    let profile_text = table.text(context, "profile");
    let profile: Read<Profile> = read_choice(
        context,
        profile_text,
        Profile::from_text,
        &names(Profile::ALL.iter().map(|value| value.as_str())),
    );
    let sample_interval = table.duration(context, "sample_interval");
    let pressure = table
        .duration(context, "pressure_sample_interval")
        .or_template(defaults.pressure_sample_interval);
    let max_age = table
        .duration(context, "decision_sample_max_age")
        .or_template(defaults.decision_sample_max_age);
    let max_gap = table
        .duration(context, "max_qualifying_sample_gap")
        .or_template(defaults.max_qualifying_sample_gap);
    let plan_ttl = table
        .duration(context, "plan_ttl")
        .or_template(defaults.plan_ttl);
    let manual_plan_ttl = table.duration(context, "manual_plan_ttl");

    // The fast sampling interval must fit the maximum qualification gap and
    // the decision freshness limit.
    let pressure_path: String = table.key_path("pressure_sample_interval");
    for (key, limit) in [
        ("max_qualifying_sample_gap", max_gap),
        ("decision_sample_max_age", max_age),
    ] {
        require_order(
            context,
            FindingCode::TimingOrder,
            (&pressure_path, pressure),
            Relation::AtMost,
            (&table.key_path(key), limit),
        );
    }
    table.finish(context);

    let agent: AgentConfig = AgentConfig {
        profile: value_or(profile, defaults.profile),
        sample_interval: value_or(sample_interval, defaults.sample_interval),
        pressure_sample_interval: pressure.unwrap_or(defaults.pressure_sample_interval),
        decision_sample_max_age: max_age.unwrap_or(defaults.decision_sample_max_age),
        max_qualifying_sample_gap: max_gap.unwrap_or(defaults.max_qualifying_sample_gap),
        plan_ttl: plan_ttl.unwrap_or(defaults.plan_ttl),
        manual_plan_ttl: value_or(manual_plan_ttl, defaults.manual_plan_ttl),
    };
    (agent, plan_ttl)
}

/// The value of the key, or the template value when the key is absent or
/// has a finding. A value with a finding never reaches a caller, because the
/// result then has no configuration.
fn value_or<T>(read: Read<T>, template: T) -> T {
    match read {
        Read::Valid(value) => value,
        Read::Absent | Read::Invalid => template,
    }
}

fn names<'a>(values: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    values.collect()
}

/// Reads `[protections]`. An absent `excluded_paths` has the personal
/// folders of the template; a list in the document replaces them.
fn read_protections(
    context: &mut Context,
    mut table: TableReader<'_>,
    default_excluded: &[ConfigPath],
) -> Protections {
    let excluded = table.text_list(context, "excluded_paths");
    let excluded_paths: Vec<ConfigPath> = if matches!(excluded, Read::Absent) {
        default_excluded.to_vec()
    } else {
        read_paths(context, excluded)
    };
    let bundle_ids = table.text_list(context, "protected_bundle_ids");
    let executables = table.text_list(context, "protected_executable_paths");
    table.finish(context);
    Protections {
        excluded_paths,
        protected_bundle_ids: read_bundle_ids(context, bundle_ids),
        protected_executable_paths: read_paths(context, executables),
    }
}

/// Reads a protection flag. In schema version 1, `false` is a finding: the
/// flag makes the protection visible and cannot remove it.
fn read_protection(context: &mut Context, table: &mut TableReader<'_>, key: &'static str) -> bool {
    if table.boolean(context, key) == Read::Valid(false) {
        context.report(
            FindingCode::ProtectionDisabled,
            &table.key_path(key),
            "schema version 1 does not permit `false`; this data is not eligible for automatic \
             cleanup",
        );
    }
    true
}

fn read_exclusions(context: &mut Context, mut table: TableReader<'_>) -> DiskExclusions {
    let paths = table.text_list(context, "paths");
    let exclusions: DiskExclusions = DiskExclusions {
        paths: read_paths(context, paths),
        protect_archives: read_protection(context, &mut table, "protect_archives"),
        protect_backups: read_protection(context, &mut table, "protect_backups"),
        protect_databases: read_protection(context, &mut table, "protect_databases"),
        protect_model_weights: read_protection(context, &mut table, "protect_model_weights"),
    };
    table.finish(context);
    exclusions
}

/// Checks a sequence of values that must ascend. Each valid value is
/// compared with the nearest valid value before it, thus a value with a
/// finding does not hide a wrong order of its neighbors.
fn require_ascending<T: PartialOrd + Copy, const N: usize>(
    context: &mut Context,
    code: FindingCode,
    relation: Relation,
    table: &TableReader<'_>,
    keys: [&'static str; N],
    values: [Option<T>; N],
) {
    let mut previous: Option<(&'static str, T)> = None;
    for (key, value) in keys.into_iter().zip(values) {
        let Some(value) = value else {
            continue;
        };
        if let Some((previous_key, previous_value)) = previous {
            require_order(
                context,
                code,
                (&table.key_path(previous_key), Some(previous_value)),
                relation,
                (&table.key_path(key), Some(value)),
            );
        }
        previous = Some((key, value));
    }
}

fn read_passes(
    context: &mut Context,
    table: &mut TableReader<'_>,
    key: &'static str,
) -> Read<NonZeroU32> {
    let path: String = table.key_path(key);
    match table.positive_count(context, key) {
        Read::Absent => Read::Absent,
        Read::Invalid => Read::Invalid,
        Read::Valid(count) => {
            if let Some(count) = u32::try_from(count).ok().and_then(NonZeroU32::new) {
                Read::Valid(count)
            } else {
                context.report(
                    FindingCode::OutOfRange,
                    &path,
                    "the count is larger than the supported range",
                );
                Read::Invalid
            }
        }
    }
}

fn read_item_limit(
    context: &mut Context,
    table: &mut TableReader<'_>,
    key: &'static str,
    template: EntryCount,
) -> Option<EntryCount> {
    match table.positive_count(context, key) {
        Read::Absent => Some(template),
        Read::Invalid => None,
        Read::Valid(count) => Some(EntryCount::new(count)),
    }
}

/// The byte thresholds and ceilings of `[disk_guard]`.
fn read_disk_sizes(
    context: &mut Context,
    table: &mut TableReader<'_>,
    defaults: &DiskGuard,
) -> [Bytes; 7] {
    let thresholds: [(&'static str, Bytes); 4] = [
        ("emergency_below", defaults.emergency_below),
        ("reclaim_below", defaults.reclaim_below),
        ("warn_below", defaults.warn_below),
        ("recover_above", defaults.recover_above),
    ];
    let threshold_values: [Option<Bytes>; 4] =
        thresholds.map(|(key, template)| table.size(context, key).or_template(template));
    require_ascending(
        context,
        FindingCode::ThresholdOrder,
        Relation::Less,
        table,
        thresholds.map(|(key, _)| key),
        threshold_values,
    );

    let limits: [(&'static str, Bytes); 3] = [
        ("batch_limit", defaults.batch_limit),
        ("pass_limit", defaults.pass_limit),
        ("incident_limit", defaults.incident_limit),
    ];
    let limit_values: [Option<Bytes>; 3] =
        limits.map(|(key, template)| table.size(context, key).or_template(template));
    require_ascending(
        context,
        FindingCode::LimitOrder,
        Relation::AtMost,
        table,
        limits.map(|(key, _)| key),
        limit_values,
    );

    let [emergency, reclaim, warn, recover] = threshold_values;
    let [batch, pass, incident] = limit_values;
    [
        emergency.unwrap_or(defaults.emergency_below),
        reclaim.unwrap_or(defaults.reclaim_below),
        warn.unwrap_or(defaults.warn_below),
        recover.unwrap_or(defaults.recover_above),
        batch.unwrap_or(defaults.batch_limit),
        pass.unwrap_or(defaults.pass_limit),
        incident.unwrap_or(defaults.incident_limit),
    ]
}

/// Reads the volume selectors. An enabled guard with an explicit empty list
/// is a finding, because the guard then protects nothing.
fn read_volumes(
    context: &mut Context,
    table: &mut TableReader<'_>,
    enabled: bool,
    defaults: &DiskGuard,
) -> Vec<VolumeSelector> {
    let texts = table.text_list(context, "volumes");
    if texts == Read::Absent {
        return defaults.volumes.clone();
    }
    let volumes: Option<Vec<VolumeSelector>> = read_list(
        context,
        texts,
        FindingCode::InvalidIdentifier,
        |text: &str| VolumeSelector::new(text).ok_or_else(|| IDENTIFIER_GRAMMAR.to_owned()),
    );
    let Some(volumes) = volumes else {
        return defaults.volumes.clone();
    };
    if enabled && volumes.is_empty() {
        context.report(
            FindingCode::EmptySelection,
            &table.key_path("volumes"),
            "an enabled disk guard must select one or more volumes",
        );
    }
    volumes
}

fn read_disk_guard(
    context: &mut Context,
    mut table: TableReader<'_>,
    defaults: &DiskGuard,
) -> DiskGuard {
    let enabled: bool = value_or(table.boolean(context, "enabled"), defaults.enabled);

    let volumes: Vec<VolumeSelector> = read_volumes(context, &mut table, enabled, defaults);

    let [
        emergency_below,
        reclaim_below,
        warn_below,
        recover_above,
        batch_limit,
        pass_limit,
        incident_limit,
    ] = read_disk_sizes(context, &mut table, defaults);

    let sustain = table
        .duration(context, "sustain_for")
        .or_template(defaults.sustain_for);
    let emergency_sustain = table
        .duration(context, "emergency_sustain_for")
        .or_template(defaults.emergency_sustain_for);
    require_order(
        context,
        FindingCode::TimingOrder,
        (&table.key_path("emergency_sustain_for"), emergency_sustain),
        Relation::AtMost,
        (&table.key_path("sustain_for"), sustain),
    );
    let recovery_stable_for = table.duration(context, "recovery_stable_for");

    let item_keys: [&'static str; 3] =
        ["batch_item_limit", "pass_item_limit", "incident_item_limit"];
    let item_templates: [EntryCount; 3] = [
        defaults.batch_item_limit,
        defaults.pass_item_limit,
        defaults.incident_item_limit,
    ];
    let mut item_values: [Option<EntryCount>; 3] = [None; 3];
    for ((slot, key), template) in item_values.iter_mut().zip(item_keys).zip(item_templates) {
        *slot = read_item_limit(context, &mut table, key, template);
    }
    require_ascending(
        context,
        FindingCode::LimitOrder,
        Relation::AtMost,
        &table,
        item_keys,
        item_values,
    );
    let [batch_items, pass_items, incident_items] = item_values;

    let pass_time_limit = table.duration(context, "pass_time_limit");
    let max_passes = read_passes(context, &mut table, "max_passes_per_incident");
    let pass_cooldown = table.duration(context, "pass_cooldown");
    let observe_after_action = table.duration(context, "observe_after_action");
    let no_effect_backoff = table.duration(context, "no_effect_backoff");

    let mode_text = table.text(context, "automatic_mode");
    let automatic_mode: Read<AutomaticMode> = read_choice(
        context,
        mode_text,
        AutomaticMode::from_text,
        &names(AutomaticMode::ALL.iter().map(|value| value.as_str())),
    );
    let rule_texts = table.text_list(context, "approved_rules");
    let approved_rules: Vec<RuleId> = read_list(
        context,
        rule_texts,
        FindingCode::InvalidIdentifier,
        |text: &str| RuleId::new(text).map_err(|_| IDENTIFIER_GRAMMAR.to_owned()),
    )
    .unwrap_or_default();
    let exclusions_table: TableReader<'_> = table.table(context, "exclusions");
    let exclusions: DiskExclusions = read_exclusions(context, exclusions_table);
    table.finish(context);

    DiskGuard {
        enabled,
        volumes,
        warn_below,
        reclaim_below,
        emergency_below,
        recover_above,
        sustain_for: sustain.unwrap_or(defaults.sustain_for),
        emergency_sustain_for: emergency_sustain.unwrap_or(defaults.emergency_sustain_for),
        recovery_stable_for: value_or(recovery_stable_for, defaults.recovery_stable_for),
        batch_limit,
        pass_limit,
        incident_limit,
        batch_item_limit: batch_items.unwrap_or(defaults.batch_item_limit),
        pass_item_limit: pass_items.unwrap_or(defaults.pass_item_limit),
        incident_item_limit: incident_items.unwrap_or(defaults.incident_item_limit),
        pass_time_limit: value_or(pass_time_limit, defaults.pass_time_limit),
        max_passes_per_incident: value_or(max_passes, defaults.max_passes_per_incident),
        pass_cooldown: value_or(pass_cooldown, defaults.pass_cooldown),
        observe_after_action: value_or(observe_after_action, defaults.observe_after_action),
        no_effect_backoff: value_or(no_effect_backoff, defaults.no_effect_backoff),
        automatic_mode: value_or(automatic_mode, defaults.automatic_mode),
        approved_rules,
        exclusions,
    }
}

/// The `id` and `bundle_id` values of the budgets that are read.
#[derive(Debug, Default)]
struct BudgetIdentifiers {
    ids: BTreeSet<AppBudgetId>,
    bundle_ids: BTreeSet<BundleId>,
}

/// Reads one application budget. `None` means that a required key is absent
/// or has a finding. A valid identifier goes into `seen` also when another
/// key of the budget has a finding, so that a later budget with the same
/// identifier gets its finding in the same pass.
fn read_app_budget(
    context: &mut Context,
    mut table: TableReader<'_>,
    seen: &mut BudgetIdentifiers,
) -> Option<AppBudget> {
    let id_text = table.text(context, "id");
    let id: Option<AppBudgetId> = table
        .require(context, "id", id_text)
        .and_then(|(path, text)| {
            let id: Option<AppBudgetId> = AppBudgetId::new(text);
            if id.is_none() {
                context.report(FindingCode::InvalidIdentifier, &path, IDENTIFIER_GRAMMAR);
            }
            if let Some(id) = &id
                && !seen.ids.insert(id.clone())
            {
                context.report(
                    FindingCode::DuplicateIdentifier,
                    &path,
                    "an earlier application budget has the same `id`",
                );
            }
            id
        });
    let bundle_text = table.text(context, "bundle_id");
    let bundle_id: Option<BundleId> =
        table
            .require(context, "bundle_id", bundle_text)
            .and_then(|(path, text)| {
                let bundle_id: Option<BundleId> = BundleId::new(text);
                if bundle_id.is_none() {
                    context.report(FindingCode::InvalidIdentifier, &path, BUNDLE_ID_GRAMMAR);
                }
                if let Some(bundle_id) = &bundle_id
                    && !seen.bundle_ids.insert(bundle_id.clone())
                {
                    context.report(
                        FindingCode::DuplicateIdentifier,
                        &path,
                        "an earlier application budget has the same `bundle_id`",
                    );
                }
                bundle_id
            });

    let soft_read = table.size(context, "footprint_soft");
    let soft: Option<Bytes> = table.require(context, "footprint_soft", soft_read);
    let stop_read = table.size(context, "footprint_stop");
    let stop: Option<Bytes> = table.require(context, "footprint_stop", stop_read);
    // An absent recovery threshold has the value of the soft threshold.
    let recover: Option<Bytes> = match table.size(context, "footprint_recover") {
        Read::Absent => soft,
        Read::Invalid => None,
        Read::Valid(recover) => {
            require_order(
                context,
                FindingCode::ThresholdOrder,
                (&table.key_path("footprint_recover"), Some(recover)),
                Relation::AtMost,
                (&table.key_path("footprint_soft"), soft),
            );
            Some(recover)
        }
    };
    require_order(
        context,
        FindingCode::ThresholdOrder,
        (&table.key_path("footprint_soft"), soft),
        Relation::Less,
        (&table.key_path("footprint_stop"), stop),
    );

    let over_read = table.duration(context, "over_limit_for");
    let over_limit_for: Option<Duration> = table.require(context, "over_limit_for", over_read);
    let cooldown_read = table.duration(context, "cooldown");
    let cooldown: Option<Duration> = table.require(context, "cooldown", cooldown_read);
    let restart_text = table.text(context, "restart");
    let restart: Option<RestartPolicy> = read_choice(
        context,
        restart_text,
        RestartPolicy::from_text,
        &names(RestartPolicy::ALL.iter().map(|value| value.as_str())),
    )
    .or_template(RestartPolicy::Never);
    table.finish(context);

    Some(AppBudget {
        id: id?,
        bundle_id: bundle_id?,
        footprint_soft: soft?,
        footprint_stop: stop?,
        footprint_recover: recover?,
        over_limit_for: over_limit_for?,
        cooldown: cooldown?,
        restart: restart?,
    })
}

/// Reads the application budgets.
///
/// The second value is true when the document has budget tables, or when it
/// has an `app_budgets` key that was rejected (wrong type or too many entries).
/// A rejected key already has its finding; it is not the same as no budget.
fn read_app_budgets(context: &mut Context, table: &mut TableReader<'_>) -> (Vec<AppBudget>, bool) {
    let mut seen: BudgetIdentifiers = BudgetIdentifiers::default();
    let before: usize = context.finding_count();
    let tables: Vec<TableReader<'_>> = table.table_array(context, "app_budgets", MAX_APP_BUDGETS);
    let rejected: bool = tables.is_empty() && context.finding_count() > before;
    let count: bool = rejected || !tables.is_empty();
    let budgets: Vec<AppBudget> = tables
        .into_iter()
        .filter_map(|budget_table| read_app_budget(context, budget_table, &mut seen))
        .collect();
    (budgets, count)
}

/// Reads `[memory_guard]`. The second value is `grace_period` for the check
/// against the plan lifetime, or `None` when the key has a finding.
fn read_memory_guard(
    context: &mut Context,
    mut table: TableReader<'_>,
    defaults: &MemoryGuard,
) -> (MemoryGuard, Option<Duration>) {
    let memory_path: String = table.path().to_owned();
    let enabled = table.boolean(context, "enabled");
    let trigger_text = table.text(context, "global_trigger");
    let global_trigger: Read<GlobalTrigger> = read_choice(
        context,
        trigger_text,
        GlobalTrigger::from_text,
        &names(GlobalTrigger::ALL.iter().map(|value| value.as_str())),
    );
    let sustain_for = table.duration(context, "sustain_for");
    let grace = table
        .duration(context, "grace_period")
        .or_template(defaults.grace_period);
    let observe_after_action = table.duration(context, "observe_after_action");
    let recovery_stable_for = table.duration(context, "recovery_stable_for");
    let max_applications = read_passes(context, &mut table, "max_applications_per_incident");
    let protect_foreground = table.boolean(context, "protect_foreground");
    let allow_force_quit = table.boolean(context, "allow_force_quit");
    let allow_volatile = table.boolean(context, "allow_volatile_journal_on_critical");

    let group_texts = table.text_list(context, "eligible_groups");
    let groups: String = names(EligibleGroup::ALL.iter().map(|value| value.as_str()))
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<String>>()
        .join(", ");
    let eligible_groups: Option<Vec<EligibleGroup>> = read_list(
        context,
        group_texts,
        FindingCode::UnknownValue,
        |text: &str| {
            EligibleGroup::from_text(text).ok_or_else(|| {
                format!("the value is not supported in schema version 1; use {groups}")
            })
        },
    );
    let bundle_texts = table.text_list(context, "protected_bundle_ids");
    let protected_bundle_ids: Vec<BundleId> = read_bundle_ids(context, bundle_texts);
    let executable_texts = table.text_list(context, "protected_executable_paths");
    let protected_executable_paths: Vec<ConfigPath> = read_paths(context, executable_texts);
    let (app_budgets, budget_tables): (Vec<AppBudget>, bool) =
        read_app_budgets(context, &mut table);
    table.finish(context);

    // An enabled guard with no eligible group and no budget can select no
    // application: the protection is silently off.
    let enabled: bool = value_or(enabled, defaults.enabled);
    if enabled && !budget_tables && eligible_groups.as_ref().is_some_and(Vec::is_empty) {
        context.report(
            FindingCode::EmptySelection,
            &join_path(&memory_path, "eligible_groups"),
            "an enabled memory guard must have one or more eligible groups or application \
             budgets",
        );
    }
    let eligible_groups: Vec<EligibleGroup> = eligible_groups.unwrap_or_default();

    let memory_guard: MemoryGuard = MemoryGuard {
        enabled,
        global_trigger: value_or(global_trigger, defaults.global_trigger),
        sustain_for: value_or(sustain_for, defaults.sustain_for),
        grace_period: grace.unwrap_or(defaults.grace_period),
        observe_after_action: value_or(observe_after_action, defaults.observe_after_action),
        recovery_stable_for: value_or(recovery_stable_for, defaults.recovery_stable_for),
        max_applications_per_incident: value_or(
            max_applications,
            defaults.max_applications_per_incident,
        ),
        protect_foreground: value_or(protect_foreground, defaults.protect_foreground),
        allow_force_quit: value_or(allow_force_quit, defaults.allow_force_quit),
        allow_volatile_journal_on_critical: value_or(
            allow_volatile,
            defaults.allow_volatile_journal_on_critical,
        ),
        eligible_groups,
        protected_bundle_ids,
        protected_executable_paths,
        app_budgets,
    };
    (memory_guard, grace)
}

/// Reads `[cleanup]`. A quiet period outside [`MIN_QUIET_PERIOD`] to
/// [`MAX_QUIET_PERIOD`] has a finding. The template has no layout, so the
/// layouts are the tables of the document only.
fn read_cleanup(context: &mut Context, mut table: TableReader<'_>, defaults: &Cleanup) -> Cleanup {
    let mut projects_table: TableReader<'_> = table.table(context, "projects");
    let path: String = projects_table.key_path("quiet_period");
    let quiet_period: Read<Duration> = match projects_table.duration(context, "quiet_period") {
        Read::Valid(period) if !(MIN_QUIET_PERIOD..=MAX_QUIET_PERIOD).contains(&period) => {
            context.report(FindingCode::OutOfRange, &path, "must be from 1h to 90d");
            Read::Invalid
        }
        other => other,
    };
    let projects: ProjectCleanup = ProjectCleanup {
        quiet_period: value_or(quiet_period, defaults.projects.quiet_period),
        paseo_agents: value_or(
            projects_table.boolean(context, "paseo_agents"),
            defaults.projects.paseo_agents,
        ),
        search_roots: super::layout::read_search_roots(context, &mut projects_table)
            .unwrap_or_else(|| defaults.projects.search_roots.clone()),
        claude_config_dirs: super::layout::read_claude_config_dirs(context, &mut projects_table)
            .unwrap_or_else(|| defaults.projects.claude_config_dirs.clone()),
        layouts: super::layout::read_layouts(context, &mut projects_table),
    };
    projects_table.finish(context);
    let mut caches_table: TableReader<'_> = table.table(context, "caches");
    let caches: CacheCleanup = CacheCleanup {
        locations: super::locations::read_locations(context, &mut caches_table),
    };
    caches_table.finish(context);
    table.finish(context);
    Cleanup { projects, caches }
}

fn read_history(context: &mut Context, mut table: TableReader<'_>, defaults: &History) -> History {
    let history: History = History {
        retention: value_or(table.duration(context, "retention"), defaults.retention),
        max_database_size: value_or(
            table.size(context, "max_database_size"),
            defaults.max_database_size,
        ),
        redact_exported_paths: value_or(
            table.boolean(context, "redact_exported_paths"),
            defaults.redact_exported_paths,
        ),
    };
    table.finish(context);
    history
}

fn read_privacy(context: &mut Context, mut table: TableReader<'_>, defaults: &Privacy) -> Privacy {
    let privacy: Privacy = Privacy {
        telemetry: value_or(table.boolean(context, "telemetry"), defaults.telemetry),
        include_command_arguments: value_or(
            table.boolean(context, "include_command_arguments"),
            defaults.include_command_arguments,
        ),
    };
    table.finish(context);
    privacy
}
