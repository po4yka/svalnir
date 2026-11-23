//! Tests of the configuration schema and its validation.
//!
//! The two example documents come from the specification files at compile
//! time, thus a change to an example in a document runs against this module.

use std::fmt::Write as _;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    CheckId, CheckStatus, ConfigPath, ConfigPathError, ExpandPathError, Finding, FindingCode,
    MAX_DOCUMENT_BYTES, MAX_FINDINGS, MAX_LIST_ENTRIES, PathBase, Profile, RestartPolicy,
    TEMPLATE_REVISION, ValidatedConfig, Validation, parse_and_validate,
};
use crate::quantity::{Bytes, EntryCount};

const POLICY_SPEC: &str = include_str!("../../../../docs/POLICY_SPEC.md");
const README: &str = include_str!("../../../../README.md");

const GIBIBYTE: u64 = 1024 * 1024 * 1024;

/// The first TOML code block of a document that has `schema_version`.
fn example(document: &'static str) -> &'static str {
    document
        .split("```toml\n")
        .skip(1)
        .filter_map(|rest| rest.split("\n```").next())
        .find(|block| block.contains("schema_version"))
        .expect("the document has a configuration example")
}

/// The complete example with one text replaced.
fn spec_with(old: &str, new: &str) -> String {
    let text: &str = example(POLICY_SPEC);
    assert!(text.contains(old), "the example has `{old}`");
    text.replacen(old, new, 1)
}

fn valid(text: &str) -> ValidatedConfig {
    match parse_and_validate(text).result {
        Ok(config) => config,
        Err(findings) => panic!("the document must validate: {findings:#?}"),
    }
}

/// The code and the path of each finding.
fn findings(text: &str) -> Vec<(FindingCode, String)> {
    parse_and_validate(text)
        .findings()
        .iter()
        .map(|finding: &Finding| (finding.code, finding.path.clone()))
        .collect()
}

/// The `excluded_paths` line of the example of `docs/POLICY_SPEC.md`.
const SPEC_EXCLUDED_PATHS: &str = "excluded_paths = [\"~/Desktop\", \"~/Documents\", \"~/Downloads\", \"~/Movies\", \"~/Music\", \"~/Pictures\", \"~/Public\", \"~/Library/Mobile Documents\", \"~/Library/CloudStorage\"]";

/// Asserts that the document has exactly one finding.
#[track_caller]
fn assert_one(text: &str, code: FindingCode, path: &str) {
    assert_eq!(findings(text), vec![(code, path.to_owned())]);
}

#[test]
fn the_policy_spec_example_validates() {
    let config: ValidatedConfig = valid(example(POLICY_SPEC));
    assert_eq!(config.schema_version(), 1);
    assert_eq!(config.template_revision(), TEMPLATE_REVISION);
    assert_eq!(config.agent().profile, Profile::Balanced);
    assert_eq!(config.agent().manual_plan_ttl, Duration::from_mins(10));

    let disk = config.disk_guard();
    assert!(disk.enabled);
    assert_eq!(disk.volumes.len(), 1);
    assert_eq!(disk.volumes[0].as_str(), "startup-data");
    assert_eq!(disk.emergency_below, Bytes::new(2 * GIBIBYTE));
    assert_eq!(disk.recover_above, Bytes::new(25 * GIBIBYTE));
    assert_eq!(disk.incident_item_limit, EntryCount::new(4096));
    assert_eq!(disk.max_passes_per_incident, NonZeroU32::new(2).unwrap());
    assert_eq!(disk.no_effect_backoff, Duration::from_mins(15));
    let rules: Vec<&str> = disk
        .approved_rules
        .iter()
        .map(crate::id::RuleId::as_str)
        .collect();
    assert_eq!(
        rules,
        ["svalnir.expired-temporary", "xcode.inactive-derived-data"]
    );
    assert_eq!(disk.exclusions.paths.len(), 4);
    assert!(disk.exclusions.protect_model_weights);

    let memory = config.memory_guard();
    assert!(memory.allow_force_quit);
    assert_eq!(memory.eligible_groups.len(), 2);
    assert_eq!(memory.app_budgets.len(), 1);
    let budget = &memory.app_budgets[0];
    assert_eq!(budget.id.as_str(), "example-build-worker");
    assert_eq!(budget.bundle_id.as_str(), "com.example.BuildWorker");
    assert_eq!(budget.footprint_recover, Bytes::new(3 * GIBIBYTE));
    assert_eq!(budget.restart, RestartPolicy::Never);

    assert_eq!(config.history().retention, Duration::from_hours(720));
    assert!(!config.privacy().telemetry);
    assert!(config.is_explicit("disk_guard.incident_limit"));
    assert!(config.is_explicit("memory_guard.app_budgets[0].footprint_recover"));
}

#[test]
fn the_readme_example_validates_with_template_values() {
    let config: ValidatedConfig = valid(example(README));
    // The README example omits these keys; the template supplies them.
    assert!(!config.is_explicit("disk_guard.incident_limit"));
    assert!(!config.is_explicit("agent.plan_ttl"));
    assert_eq!(
        config.disk_guard().incident_limit,
        Bytes::new(16 * GIBIBYTE)
    );
    assert_eq!(
        config.disk_guard().emergency_sustain_for,
        Duration::from_secs(5)
    );
    assert_eq!(config.agent().plan_ttl, Duration::from_secs(30));
    // An omitted recovery threshold has the value of the soft threshold.
    let budget = &config.memory_guard().app_budgets[0];
    assert_eq!(budget.footprint_recover, budget.footprint_soft);
    assert!(config.is_explicit("disk_guard.warn_below"));
}

#[test]
fn the_readme_example_resolves_to_the_policy_spec_values() {
    let spec: ValidatedConfig = valid(example(POLICY_SPEC));
    let readme: ValidatedConfig = valid(example(README));
    assert_eq!(spec.agent(), readme.agent());
    assert_eq!(spec.disk_guard(), readme.disk_guard());
    assert_eq!(spec.history(), readme.history());
    assert_eq!(spec.privacy(), readme.privacy());
}

#[test]
fn an_omitted_key_never_expands_authority() {
    let config: ValidatedConfig = valid("schema_version = 1\n");
    assert_eq!(config.agent().profile, Profile::Observe);
    assert!(!config.disk_guard().enabled);
    assert_eq!(config.disk_guard().approved_rules.len(), 0);
    assert!(!config.memory_guard().enabled);
    assert!(!config.memory_guard().allow_force_quit);
    assert!(!config.memory_guard().allow_volatile_journal_on_critical);
    assert!(config.memory_guard().protect_foreground);
    assert_eq!(config.memory_guard().eligible_groups.len(), 0);
    assert!(config.history().redact_exported_paths);
    assert!(!config.privacy().telemetry);
    assert_eq!(
        config.explicit_keys().collect::<Vec<&str>>(),
        ["schema_version"]
    );

    // A guard table that only enables the guard gets the bounded template.
    let enabled: ValidatedConfig = valid("schema_version = 1\n[disk_guard]\nenabled = true\n");
    assert!(enabled.disk_guard().enabled);
    assert_eq!(enabled.disk_guard().pass_limit, Bytes::new(8 * GIBIBYTE));
}

#[test]
fn a_valid_document_reports_the_live_checks_as_not_done() {
    let validation: Validation = parse_and_validate(example(POLICY_SPEC));
    for check in [CheckId::Syntax, CheckId::Schema, CheckId::Relationships] {
        assert_eq!(validation.checks.status(check), CheckStatus::Passed);
    }
    let live: Vec<CheckId> = validation.checks.requires_agent().collect();
    assert_eq!(
        live,
        [
            CheckId::RuleRegistry,
            CheckId::VolumeSelectors,
            CheckId::ApplicationIdentities,
            CheckId::WorkerCapabilities,
            CheckId::ActionGrants,
        ]
    );
    // A rule that no registry has still passes the portable checks.
    let unknown_rule: String = spec_with("svalnir.expired-temporary", "no.such-rule");
    let validation: Validation = parse_and_validate(&unknown_rule);
    assert!(validation.config().is_some());
    assert_eq!(
        validation.checks.status(CheckId::RuleRegistry),
        CheckStatus::RequiresAgent
    );
}

#[test]
fn a_syntax_error_stops_the_other_checks() {
    let validation: Validation = parse_and_validate("schema_version = 1\n[agent\n");
    let all: &[Finding] = validation.findings();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].code, FindingCode::Syntax);
    assert_eq!(all[0].path, "");
    assert_eq!(all[0].location.map(|location| location.line), Some(2));
    assert_eq!(all[0].message, "the text is not a valid TOML document");
    assert_eq!(
        validation.checks.status(CheckId::Syntax),
        CheckStatus::Failed
    );
    assert_eq!(
        validation.checks.status(CheckId::Schema),
        CheckStatus::NotRun
    );
    assert_eq!(
        validation.checks.status(CheckId::Relationships),
        CheckStatus::NotRun
    );
    assert_eq!(
        validation.checks.status(CheckId::RuleRegistry),
        CheckStatus::RequiresAgent
    );

    // TOML rejects a key that occurs two times.
    assert_one(
        "schema_version = 1\nschema_version = 1\n",
        FindingCode::Syntax,
        "",
    );
}

#[test]
fn a_large_document_is_rejected_before_the_parse() {
    let text: String = "#".repeat(MAX_DOCUMENT_BYTES + 1);
    assert_one(&text, FindingCode::DocumentTooLarge, "");
}

#[test]
fn the_schema_version_must_be_supported() {
    // An unsupported version stops the read: the tables have another schema.
    let validation: Validation = parse_and_validate("schema_version = 2\n[unknown]\nkey = 1\n");
    assert_eq!(
        findings("schema_version = 2\n[unknown]\nkey = 1\n"),
        [(
            FindingCode::UnsupportedSchemaVersion,
            "schema_version".to_owned()
        )]
    );
    assert_eq!(
        validation.checks.status(CheckId::Schema),
        CheckStatus::Failed
    );
    assert_eq!(
        validation.checks.status(CheckId::Relationships),
        CheckStatus::NotRun
    );
    assert_one(
        "schema_version = 0\n",
        FindingCode::UnsupportedSchemaVersion,
        "schema_version",
    );
    assert_one("", FindingCode::MissingKey, "schema_version");
    assert_one(
        "schema_version = \"1\"\n",
        FindingCode::WrongType,
        "schema_version",
    );
}

#[test]
fn unknown_keys_and_tables_are_rejected() {
    assert_one(
        "schema_version = 1\nlog_level = \"debug\"\n",
        FindingCode::UnknownKey,
        "log_level",
    );
    assert_one(
        "schema_version = 1\n[cpu_guard]\nenabled = true\n",
        FindingCode::UnknownKey,
        "cpu_guard",
    );
    assert_one(
        &spec_with("[history]\n", "[history]\ncompress = true\n"),
        FindingCode::UnknownKey,
        "history.compress",
    );
    assert_one(
        &spec_with(
            "protect_archives = true\n",
            "protect_archives = true\nprotect_logs = true\n",
        ),
        FindingCode::UnknownKey,
        "disk_guard.exclusions.protect_logs",
    );
    assert_one(
        &spec_with(
            "restart = \"never\"\n",
            "restart = \"never\"\npriority = 1\n",
        ),
        FindingCode::UnknownKey,
        "memory_guard.app_budgets[0].priority",
    );
    // A key that is not a bare key is quoted and escaped in the path.
    assert_one(
        "schema_version = 1\n\"a key\\n\" = 1\n",
        FindingCode::UnknownKey,
        "\"a key\\n\"",
    );
}

#[test]
fn a_value_of_another_type_is_rejected() {
    assert_one(
        &spec_with("warn_below = \"20GiB\"", "warn_below = 20"),
        FindingCode::WrongType,
        "disk_guard.warn_below",
    );
    assert_one(
        &spec_with("telemetry = false", "telemetry = \"no\""),
        FindingCode::WrongType,
        "privacy.telemetry",
    );
    assert_one(
        &spec_with("batch_item_limit = 256", "batch_item_limit = \"256\""),
        FindingCode::WrongType,
        "disk_guard.batch_item_limit",
    );
    assert_one(
        &spec_with("volumes = [\"startup-data\"]", "volumes = \"startup-data\""),
        FindingCode::WrongType,
        "disk_guard.volumes",
    );
    assert_one(
        &spec_with(SPEC_EXCLUDED_PATHS, "excluded_paths = [\"~/a\", 5]"),
        FindingCode::WrongType,
        "protections.excluded_paths[1]",
    );
    assert_one(
        "schema_version = 1\nagent = 5\n",
        FindingCode::WrongType,
        "agent",
    );
    assert_one(
        "schema_version = 1\n[memory_guard]\napp_budgets = [1]\n",
        FindingCode::WrongType,
        "memory_guard.app_budgets[0]",
    );
}

#[test]
fn the_disk_thresholds_must_be_in_order() {
    // emergency_below < reclaim_below
    assert_one(
        &spec_with("emergency_below = \"2GiB\"", "emergency_below = \"10GiB\""),
        FindingCode::ThresholdOrder,
        "disk_guard.emergency_below",
    );
    // reclaim_below < warn_below
    assert_one(
        &spec_with("reclaim_below = \"10GiB\"", "reclaim_below = \"21GiB\""),
        FindingCode::ThresholdOrder,
        "disk_guard.reclaim_below",
    );
    // warn_below < recover_above; an equal value is not sufficient.
    assert_one(
        &spec_with("recover_above = \"25GiB\"", "recover_above = \"20GiB\""),
        FindingCode::ThresholdOrder,
        "disk_guard.warn_below",
    );
}

#[test]
fn a_zero_value_does_not_disable_a_protection() {
    for (old, new, path) in [
        (
            "sustain_for = \"30s\"",
            "sustain_for = \"0s\"",
            "disk_guard.sustain_for",
        ),
        (
            "pass_cooldown = \"5m\"",
            "pass_cooldown = \"0ms\"",
            "disk_guard.pass_cooldown",
        ),
        (
            "grace_period = \"10s\"",
            "grace_period = \"0s\"",
            "memory_guard.grace_period",
        ),
        (
            "cooldown = \"10m\"",
            "cooldown = \"0m\"",
            "memory_guard.app_budgets[0].cooldown",
        ),
        (
            "retention = \"30d\"",
            "retention = \"0d\"",
            "history.retention",
        ),
        (
            "emergency_below = \"2GiB\"",
            "emergency_below = \"0B\"",
            "disk_guard.emergency_below",
        ),
        (
            "batch_limit = \"1GiB\"",
            "batch_limit = \"0GiB\"",
            "disk_guard.batch_limit",
        ),
        (
            "max_database_size = \"256MiB\"",
            "max_database_size = \"0MiB\"",
            "history.max_database_size",
        ),
        (
            "batch_item_limit = 256",
            "batch_item_limit = 0",
            "disk_guard.batch_item_limit",
        ),
        (
            "max_passes_per_incident = 2",
            "max_passes_per_incident = 0",
            "disk_guard.max_passes_per_incident",
        ),
        (
            "max_applications_per_incident = 3",
            "max_applications_per_incident = -1",
            "memory_guard.max_applications_per_incident",
        ),
    ] {
        assert_one(&spec_with(old, new), FindingCode::NotPositive, path);
    }
}

#[test]
fn the_batch_and_pass_limits_must_be_in_order() {
    assert_one(
        &spec_with("batch_limit = \"1GiB\"", "batch_limit = \"9GiB\""),
        FindingCode::LimitOrder,
        "disk_guard.batch_limit",
    );
    assert_one(
        &spec_with("pass_limit = \"8GiB\"", "pass_limit = \"17GiB\""),
        FindingCode::LimitOrder,
        "disk_guard.pass_limit",
    );
    assert_one(
        &spec_with("batch_item_limit = 256", "batch_item_limit = 2049"),
        FindingCode::LimitOrder,
        "disk_guard.batch_item_limit",
    );
    assert_one(
        &spec_with("incident_item_limit = 4096", "incident_item_limit = 2047"),
        FindingCode::LimitOrder,
        "disk_guard.pass_item_limit",
    );
    // Equal ceilings are permitted.
    valid(&spec_with(
        "batch_limit = \"1GiB\"",
        "batch_limit = \"8GiB\"",
    ));
}

#[test]
fn a_count_must_fit_the_supported_range() {
    assert_one(
        &spec_with(
            "max_passes_per_incident = 2",
            "max_passes_per_incident = 4294967296",
        ),
        FindingCode::OutOfRange,
        "disk_guard.max_passes_per_incident",
    );
}

#[test]
fn the_timing_values_must_agree() {
    assert_one(
        &spec_with(
            "emergency_sustain_for = \"5s\"",
            "emergency_sustain_for = \"31s\"",
        ),
        FindingCode::TimingOrder,
        "disk_guard.emergency_sustain_for",
    );
    // The fast interval must fit the gap and the freshness limit.
    assert_eq!(
        findings(&spec_with(
            "pressure_sample_interval = \"5s\"",
            "pressure_sample_interval = \"11s\""
        )),
        [
            (
                FindingCode::TimingOrder,
                "agent.pressure_sample_interval".to_owned()
            ),
            (
                FindingCode::TimingOrder,
                "agent.pressure_sample_interval".to_owned()
            ),
        ]
    );
    // An automatic plan must allow the grace interval.
    assert_one(
        &spec_with("plan_ttl = \"30s\"", "plan_ttl = \"9s\""),
        FindingCode::TimingOrder,
        "memory_guard.grace_period",
    );
}

#[test]
fn a_relationship_uses_the_template_value_of_an_omitted_key() {
    // The document gives only `sustain_for`. The template value of
    // `emergency_sustain_for` is 5 s, and the finding is at the given key.
    let validation: Validation =
        parse_and_validate("schema_version = 1\n[disk_guard]\nsustain_for = \"3s\"\n");
    let all: &[Finding] = validation.findings();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].code, FindingCode::TimingOrder);
    assert_eq!(all[0].path, "disk_guard.sustain_for");
    assert!(all[0].message.contains("template"));
}

#[test]
fn the_footprint_thresholds_must_be_in_order() {
    assert_one(
        &spec_with("footprint_soft = \"4GiB\"", "footprint_soft = \"6GiB\""),
        FindingCode::ThresholdOrder,
        "memory_guard.app_budgets[0].footprint_soft",
    );
    assert_one(
        &spec_with(
            "footprint_recover = \"3GiB\"",
            "footprint_recover = \"5GiB\"",
        ),
        FindingCode::ThresholdOrder,
        "memory_guard.app_budgets[0].footprint_recover",
    );
    valid(&spec_with(
        "footprint_recover = \"3GiB\"",
        "footprint_recover = \"4GiB\"",
    ));
}

#[test]
fn an_application_budget_needs_its_required_keys() {
    let text: &str = "schema_version = 1\n[[memory_guard.app_budgets]]\nrestart = \"never\"\n";
    let paths: Vec<(FindingCode, String)> = findings(text);
    let expected: Vec<(FindingCode, String)> = [
        "id",
        "bundle_id",
        "footprint_soft",
        "footprint_stop",
        "over_limit_for",
        "cooldown",
    ]
    .iter()
    .map(|key| {
        (
            FindingCode::MissingKey,
            format!("memory_guard.app_budgets[0].{key}"),
        )
    })
    .collect();
    assert_eq!(paths, expected);
}

#[test]
fn an_unknown_enumeration_value_is_rejected() {
    for (old, new, path) in [
        (
            "profile = \"balanced\"",
            "profile = \"turbo\"",
            "agent.profile",
        ),
        (
            "global_trigger = \"critical\"",
            "global_trigger = \"warning\"",
            "memory_guard.global_trigger",
        ),
        (
            "automatic_mode = \"permanent\"",
            "automatic_mode = \"trash\"",
            "disk_guard.automatic_mode",
        ),
        (
            "restart = \"never\"",
            "restart = \"always\"",
            "memory_guard.app_budgets[0].restart",
        ),
        (
            "\"managed-jobs\"]",
            "\"all-applications\"]",
            "memory_guard.eligible_groups[1]",
        ),
        // The match is exact; another case is another value.
        (
            "profile = \"balanced\"",
            "profile = \"Balanced\"",
            "agent.profile",
        ),
    ] {
        assert_one(&spec_with(old, new), FindingCode::UnknownValue, path);
    }
}

#[test]
fn a_size_or_duration_outside_the_grammar_is_rejected() {
    for new in ["20GB", "20", "-5GiB", "1.5GiB", "020GiB", ""] {
        assert_one(
            &spec_with("warn_below = \"20GiB\"", &format!("warn_below = \"{new}\"")),
            FindingCode::InvalidSize,
            "disk_guard.warn_below",
        );
    }
    for new in ["60", "1.5m", "60 s", "-1s", "1h30m", ""] {
        assert_one(
            &spec_with(
                "sample_interval = \"60s\"",
                &format!("sample_interval = \"{new}\""),
            ),
            FindingCode::InvalidDuration,
            "agent.sample_interval",
        );
    }
    assert_one(
        &spec_with(
            "recover_above = \"25GiB\"",
            "recover_above = \"99999999999TiB\"",
        ),
        FindingCode::OutOfRange,
        "disk_guard.recover_above",
    );
    // 300 000 days do not fit 64-bit nanoseconds.
    assert_one(
        &spec_with("retention = \"30d\"", "retention = \"300000d\""),
        FindingCode::OutOfRange,
        "history.retention",
    );
}

#[test]
fn a_built_in_protection_cannot_be_set_to_false() {
    for key in [
        "protect_archives",
        "protect_backups",
        "protect_databases",
        "protect_model_weights",
    ] {
        assert_one(
            &spec_with(&format!("{key} = true"), &format!("{key} = false")),
            FindingCode::ProtectionDisabled,
            &format!("disk_guard.exclusions.{key}"),
        );
    }
}

#[test]
fn an_enabled_disk_guard_must_select_a_volume() {
    assert_one(
        &spec_with("volumes = [\"startup-data\"]", "volumes = []"),
        FindingCode::EmptySelection,
        "disk_guard.volumes",
    );
    valid("schema_version = 1\n[disk_guard]\nenabled = false\nvolumes = []\n");
}

#[test]
fn identifiers_are_validated_as_text() {
    assert_one(
        &spec_with("\"svalnir.expired-temporary\"", "\"~/Library/Caches/*\""),
        FindingCode::InvalidIdentifier,
        "disk_guard.approved_rules[0]",
    );
    assert_one(
        &spec_with(
            "volumes = [\"startup-data\"]",
            "volumes = [\"/Volumes/Data\"]",
        ),
        FindingCode::InvalidIdentifier,
        "disk_guard.volumes[0]",
    );
    assert_one(
        &spec_with(
            "bundle_id = \"com.example.BuildWorker\"",
            "bundle_id = \"Build Worker\"",
        ),
        FindingCode::InvalidIdentifier,
        "memory_guard.app_budgets[0].bundle_id",
    );
    assert_one(
        &spec_with("id = \"example-build-worker\"", "id = \"\""),
        FindingCode::InvalidIdentifier,
        "memory_guard.app_budgets[0].id",
    );
    assert_one(
        &spec_with(
            "protected_bundle_ids = []\nprotected_executable_paths = []\n\n[disk_guard]",
            "protected_bundle_ids = [\"com.example/app\"]\nprotected_executable_paths = []\n\n[disk_guard]",
        ),
        FindingCode::InvalidIdentifier,
        "protections.protected_bundle_ids[0]",
    );
}

#[test]
fn an_identifier_that_occurs_again_is_rejected() {
    assert_one(
        &spec_with(
            "\"xcode.inactive-derived-data\"",
            "\"svalnir.expired-temporary\"",
        ),
        FindingCode::DuplicateIdentifier,
        "disk_guard.approved_rules[1]",
    );
    // `~/Documents/` and `~/Documents` are the same path.
    assert_one(
        &spec_with(
            "\"~/Downloads\", \"~/Pictures\"",
            "\"~/Documents/\", \"~/Pictures\"",
        ),
        FindingCode::DuplicateIdentifier,
        "disk_guard.exclusions.paths[1]",
    );
    let second_budget: &str = "\n[[memory_guard.app_budgets]]\nid = \"example-build-worker\"\n\
        bundle_id = \"com.example.BuildWorker\"\nfootprint_soft = \"1GiB\"\n\
        footprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\ncooldown = \"10m\"\n\n[history]\n";
    assert_eq!(
        findings(&spec_with("\n[history]\n", second_budget)),
        [
            (
                FindingCode::DuplicateIdentifier,
                "memory_guard.app_budgets[1].id".to_owned()
            ),
            (
                FindingCode::DuplicateIdentifier,
                "memory_guard.app_budgets[1].bundle_id".to_owned()
            ),
        ]
    );
}

#[test]
fn a_path_has_no_shell_evaluation() {
    for path in [
        "Documents",
        "./Documents",
        "~user/Documents",
        "~",
        "$HOME/Documents",
        "~/$(whoami)",
        "~/`whoami`",
        "~/Library/Caches/*",
        "~/Projects/{a,b}",
        "~/file?.txt",
        "~/../other",
        "/usr/./bin",
        "",
    ] {
        assert_one(
            &spec_with(SPEC_EXCLUDED_PATHS, &format!("excluded_paths = ['{path}']")),
            FindingCode::InvalidPath,
            "protections.excluded_paths[0]",
        );
    }
    assert_eq!(
        ConfigPath::parse("$HOME/Documents"),
        Err(ConfigPathError::NotAnchored)
    );
    assert_eq!(
        ConfigPath::parse("~/${HOME}"),
        Err(ConfigPathError::EvaluationSyntax)
    );
    assert_eq!(
        ConfigPath::parse("/a/../b"),
        Err(ConfigPathError::RelativeComponent)
    );
    assert_eq!(
        ConfigPath::parse("~/a\u{0}b"),
        Err(ConfigPathError::ControlCharacter)
    );
    assert_eq!(
        ConfigPath::parse(&format!("/{}", "a".repeat(1024))),
        Err(ConfigPathError::TooLong)
    );
}

#[test]
fn the_home_expansion_is_explicit_and_pure() {
    let home: &Path = Path::new("/Users/example");
    let documents: ConfigPath = ConfigPath::parse("~/Documents//Work/").unwrap();
    assert_eq!(documents.base(), PathBase::Home);
    assert_eq!(
        documents.components().collect::<Vec<&str>>(),
        ["Documents", "Work"]
    );
    assert_eq!(documents.to_string(), "~/Documents/Work");
    assert_eq!(
        documents.expand(home),
        Ok(PathBuf::from("/Users/example/Documents/Work"))
    );
    // A bare `~` is not accepted: only an explicit leading `~/` is.
    assert_eq!(ConfigPath::parse("~"), Err(ConfigPathError::NotAnchored));
    assert_eq!(
        ConfigPath::parse("~/").unwrap().expand(home),
        Ok(PathBuf::from("/Users/example"))
    );
    // A path from the root does not use the home directory.
    let absolute: ConfigPath = ConfigPath::parse("/Applications/Example.app").unwrap();
    assert_eq!(absolute.base(), PathBase::Root);
    assert_eq!(
        absolute.expand(Path::new("relative")),
        Ok(PathBuf::from("/Applications/Example.app"))
    );
    assert_eq!(
        documents.expand(Path::new("relative")),
        Err(ExpandPathError::HomeNotAbsolute)
    );
    // The validation keeps the path as written; it does not expand it.
    let config: ValidatedConfig = valid(example(POLICY_SPEC));
    assert_eq!(
        config.disk_guard().exclusions.paths[0].to_string(),
        "~/Documents"
    );
}

#[test]
fn each_finding_of_a_document_is_reported() {
    let text: &str = r#"
schema_version = 1
surprise = true

[agent]
profile = "turbo"
sample_interval = "0s"

[disk_guard]
enabled = true
warn_below = "5GiB"
reclaim_below = "10GiB"
batch_limit = "20GB"
approved_rules = ["not a rule"]

[disk_guard.exclusions]
paths = ["Documents"]
protect_backups = false

[memory_guard]
grace_period = "45s"

[[memory_guard.app_budgets]]
id = "worker"
bundle_id = "com.example.Worker"
footprint_soft = "6GiB"
footprint_stop = "4GiB"
over_limit_for = "30s"
cooldown = "10m"
restart = "always"

[history]
retention = "forever"
"#;
    let mut found: Vec<(FindingCode, String)> = findings(text);
    found.sort();
    let mut expected: Vec<(FindingCode, String)> = [
        (FindingCode::UnknownKey, "surprise"),
        (FindingCode::UnknownValue, "agent.profile"),
        (FindingCode::NotPositive, "agent.sample_interval"),
        (FindingCode::ThresholdOrder, "disk_guard.reclaim_below"),
        (FindingCode::InvalidSize, "disk_guard.batch_limit"),
        (
            FindingCode::InvalidIdentifier,
            "disk_guard.approved_rules[0]",
        ),
        (FindingCode::InvalidPath, "disk_guard.exclusions.paths[0]"),
        (
            FindingCode::ProtectionDisabled,
            "disk_guard.exclusions.protect_backups",
        ),
        (FindingCode::TimingOrder, "memory_guard.grace_period"),
        (
            FindingCode::ThresholdOrder,
            "memory_guard.app_budgets[0].footprint_soft",
        ),
        (
            FindingCode::UnknownValue,
            "memory_guard.app_budgets[0].restart",
        ),
        (FindingCode::InvalidDuration, "history.retention"),
    ]
    .map(|(code, path)| (code, path.to_owned()))
    .to_vec();
    expected.sort();
    assert_eq!(found, expected);

    let validation: Validation = parse_and_validate(text);
    assert!(validation.config().is_none());
    assert_eq!(
        validation.checks.status(CheckId::Syntax),
        CheckStatus::Passed
    );
    assert_eq!(
        validation.checks.status(CheckId::Schema),
        CheckStatus::Failed
    );
    assert_eq!(
        validation.checks.status(CheckId::Relationships),
        CheckStatus::Failed
    );
}

#[test]
fn the_relationship_check_is_partial_after_a_schema_finding() {
    let validation: Validation = parse_and_validate(&spec_with(
        "warn_below = \"20GiB\"",
        "warn_below = \"20GB\"",
    ));
    assert_eq!(
        validation.checks.status(CheckId::Schema),
        CheckStatus::Failed
    );
    assert_eq!(
        validation.checks.status(CheckId::Relationships),
        CheckStatus::Partial
    );
}

#[test]
fn a_message_does_not_repeat_a_value_of_the_document() {
    let marker: &str = "MARKER-7f3a";
    let text: String = format!(
        "schema_version = 1\n[agent]\nprofile = \"{marker}\"\nsample_interval = \"{marker}\"\n\
         [disk_guard]\nwarn_below = \"{marker}\"\napproved_rules = [\"{marker} x\"]\n\
         volumes = [\"{marker}/\"]\n[protections]\nexcluded_paths = [\"{marker}\"]\n\
         protected_bundle_ids = [\"{marker} \"]\n"
    );
    let validation: Validation = parse_and_validate(&text);
    assert_eq!(validation.findings().len(), 7);
    for finding in validation.findings() {
        assert!(!finding.message.contains(marker), "{finding}");
        assert!(!finding.path.contains(marker), "{finding}");
    }
}

#[test]
fn the_number_of_findings_and_entries_is_bounded() {
    use std::fmt::Write as _;

    let mut text: String = String::from("schema_version = 1\n");
    for index in 0..(MAX_FINDINGS + 50) {
        writeln!(text, "unknown_{index} = 1").unwrap();
    }
    let validation: Validation = parse_and_validate(&text);
    let all: &[Finding] = validation.findings();
    assert_eq!(all.len(), MAX_FINDINGS + 1);
    assert_eq!(all[MAX_FINDINGS].code, FindingCode::TooManyFindings);

    let entries: Vec<String> = (0..=MAX_LIST_ENTRIES)
        .map(|index| format!("\"~/{index}\""))
        .collect();
    assert_one(
        &format!(
            "schema_version = 1\n[protections]\nexcluded_paths = [{}]\n",
            entries.join(",")
        ),
        FindingCode::TooManyEntries,
        "protections.excluded_paths",
    );
}

#[test]
fn the_codes_and_statuses_have_stable_text() {
    let codes: [(FindingCode, &str); 21] = [
        (FindingCode::Syntax, "syntax"),
        (FindingCode::DocumentTooLarge, "document_too_large"),
        (FindingCode::TooManyFindings, "too_many_findings"),
        (
            FindingCode::UnsupportedSchemaVersion,
            "unsupported_schema_version",
        ),
        (FindingCode::UnknownKey, "unknown_key"),
        (FindingCode::MissingKey, "missing_key"),
        (FindingCode::WrongType, "wrong_type"),
        (FindingCode::InvalidSize, "invalid_size"),
        (FindingCode::InvalidDuration, "invalid_duration"),
        (FindingCode::NotPositive, "not_positive"),
        (FindingCode::OutOfRange, "out_of_range"),
        (FindingCode::UnknownValue, "unknown_value"),
        (FindingCode::InvalidIdentifier, "invalid_identifier"),
        (FindingCode::DuplicateIdentifier, "duplicate_identifier"),
        (FindingCode::InvalidPath, "invalid_path"),
        (FindingCode::TooManyEntries, "too_many_entries"),
        (FindingCode::ProtectionDisabled, "protection_disabled"),
        (FindingCode::ThresholdOrder, "threshold_order"),
        (FindingCode::LimitOrder, "limit_order"),
        (FindingCode::TimingOrder, "timing_order"),
        (FindingCode::EmptySelection, "empty_selection"),
    ];
    for (code, text) in codes {
        assert_eq!(code.as_str(), text);
        assert_eq!(serde_json::to_value(code).unwrap(), text);
    }
    for check in CheckId::ALL {
        assert_eq!(serde_json::to_value(check).unwrap(), check.as_str());
    }
    for status in [
        CheckStatus::Passed,
        CheckStatus::Failed,
        CheckStatus::Partial,
        CheckStatus::NotRun,
        CheckStatus::RequiresAgent,
    ] {
        assert_eq!(serde_json::to_value(status).unwrap(), status.as_str());
    }

    let validation: Validation = parse_and_validate("schema_version = 1\nextra = 1\n");
    let json: serde_json::Value = serde_json::to_value(validation.findings()).unwrap();
    assert_eq!(
        json,
        serde_json::json!([{
            "code": "unknown_key",
            "path": "extra",
            "message": "the key is not in schema version 1",
        }])
    );
    let checks: serde_json::Value = serde_json::to_value(&validation.checks).unwrap();
    assert_eq!(
        checks[1],
        serde_json::json!({"check": "schema", "status": "failed"})
    );
    assert_eq!(
        checks[3],
        serde_json::json!({"check": "rule_registry", "status": "requires_agent"})
    );
}

#[test]
fn a_cut_list_does_not_blame_or_clear_a_check() {
    use std::fmt::Write as _;

    // 129 budgets, each with a wrong threshold order and no schema problem.
    let mut text: String = String::from("schema_version = 1\n");
    for index in 0..=MAX_FINDINGS {
        write!(
            text,
            "[[memory_guard.app_budgets]]\nid = \"b{index}\"\nbundle_id = \"com.example.b{index}\"\n\
             footprint_soft = \"6GiB\"\nfootprint_stop = \"4GiB\"\nover_limit_for = \"30s\"\n\
             cooldown = \"10m\"\n"
        )
        .unwrap();
    }
    let validation: Validation = parse_and_validate(&text);
    assert_eq!(validation.findings().len(), MAX_FINDINGS + 1);
    assert_eq!(
        validation.checks.status(CheckId::Schema),
        CheckStatus::Partial
    );
    assert_eq!(
        validation.checks.status(CheckId::Relationships),
        CheckStatus::Failed
    );
    assert_eq!(FindingCode::TooManyFindings.check(), None);
}

#[test]
fn a_duplicate_budget_is_reported_with_another_finding_in_the_first_budget() {
    let text: &str = "schema_version = 1\n\
        [[memory_guard.app_budgets]]\nid = \"a\"\nbundle_id = \"com.example.a\"\n\
        footprint_soft = \"1GiB\"\nfootprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\n\
        [[memory_guard.app_budgets]]\nid = \"a\"\nbundle_id = \"com.example.a\"\n\
        footprint_soft = \"1GiB\"\nfootprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\n\
        cooldown = \"10m\"\n";
    assert_eq!(
        findings(text),
        [
            (
                FindingCode::MissingKey,
                "memory_guard.app_budgets[0].cooldown".to_owned()
            ),
            (
                FindingCode::DuplicateIdentifier,
                "memory_guard.app_budgets[1].id".to_owned()
            ),
            (
                FindingCode::DuplicateIdentifier,
                "memory_guard.app_budgets[1].bundle_id".to_owned()
            ),
        ]
    );
}

#[test]
fn an_invalid_value_does_not_hide_the_order_of_its_neighbors() {
    let text: &str = "schema_version = 1\n[disk_guard]\nemergency_below = \"30GiB\"\n\
        reclaim_below = \"x\"\nwarn_below = \"20GiB\"\nrecover_above = \"40GiB\"\n\
        batch_limit = \"20GiB\"\npass_limit = \"0\"\n";
    assert_eq!(
        findings(text),
        [
            (
                FindingCode::InvalidSize,
                "disk_guard.reclaim_below".to_owned()
            ),
            (
                FindingCode::ThresholdOrder,
                "disk_guard.emergency_below".to_owned()
            ),
            (FindingCode::InvalidSize, "disk_guard.pass_limit".to_owned()),
            (FindingCode::LimitOrder, "disk_guard.batch_limit".to_owned()),
        ]
    );
}

#[test]
fn an_enabled_memory_guard_must_be_able_to_select_an_application() {
    assert_one(
        "schema_version = 1\n[memory_guard]\nenabled = true\n",
        FindingCode::EmptySelection,
        "memory_guard.eligible_groups",
    );
    valid(
        "schema_version = 1\n[memory_guard]\nenabled = true\neligible_groups = [\"managed-jobs\"]\n",
    );
    // A budget is sufficient without a group.
    valid(
        "schema_version = 1\n[memory_guard]\nenabled = true\n[[memory_guard.app_budgets]]\n\
         id = \"a\"\nbundle_id = \"com.example.a\"\nfootprint_soft = \"1GiB\"\n\
         footprint_stop = \"2GiB\"\nover_limit_for = \"30s\"\ncooldown = \"10m\"\n",
    );
}

#[test]
fn the_root_path_displays_as_a_path() {
    let root: ConfigPath = ConfigPath::parse("/").unwrap();
    assert_eq!(root.to_string(), "/");
    assert_eq!(ConfigPath::parse(&root.to_string()), Ok(root));
}

#[test]
fn a_rejected_budget_array_is_not_an_empty_selection() {
    assert_one(
        "schema_version = 1\n[memory_guard]\nenabled = true\napp_budgets = 5\n",
        FindingCode::WrongType,
        "memory_guard.app_budgets",
    );
}

/// An absent `excluded_paths` has the personal folders of the template. A
/// list in the document replaces them, and an empty list protects no path.
#[test]
fn the_personal_folders_are_the_default_of_the_protections_table() {
    let defaults: Vec<String> = valid("schema_version = 1\n")
        .protections()
        .excluded_paths
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(defaults, super::PERSONAL_FOLDERS);
    let replaced = valid("schema_version = 1\n[protections]\nexcluded_paths = [\"~/Work\"]\n");
    assert_eq!(
        replaced
            .protections()
            .excluded_paths
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>(),
        ["~/Work"]
    );
    let empty = valid("schema_version = 1\n[protections]\nexcluded_paths = []\n");
    assert_eq!(empty.protections().excluded_paths, Vec::<ConfigPath>::new());
}

/// A list that replaces the default names each personal folder that it
/// does not protect. A path protects the folder and each folder below it.
#[test]
fn a_replaced_protections_list_names_each_personal_folder_that_it_does_not_protect() {
    let home: &Path = Path::new("/Users/a");
    let of = |list: &str| {
        valid(&format!(
            "schema_version = 1\n[protections]\nexcluded_paths = {list}\n"
        ))
        .unprotected_personal_folders(Some(home))
    };
    assert_eq!(
        valid("schema_version = 1\n").unprotected_personal_folders(None),
        Vec::<&str>::new()
    );
    assert_eq!(of("[]"), super::PERSONAL_FOLDERS);
    assert_eq!(
        of("[\"~/Desktop\", \"~/documents\", \"~/Library\", \"/Users/a/Music\"]"),
        ["~/Downloads", "~/Movies", "~/Pictures", "~/Public"]
    );
    // A path inside a folder does not protect the whole folder.
    assert!(of("[\"~/Documents/taxes\"]").contains(&"~/Documents"));
    // A path that starts from `/` needs the home directory.
    let config = valid("schema_version = 1\n[protections]\nexcluded_paths = [\"/Users/a\"]\n");
    assert_eq!(
        config.unprotected_personal_folders(Some(home)),
        Vec::<&str>::new()
    );
    assert_eq!(
        config.unprotected_personal_folders(None),
        super::PERSONAL_FOLDERS
    );
}

#[test]
fn the_project_cleanup_settings_have_template_values_and_a_bounded_quiet_period() {
    let readme: ValidatedConfig = valid(example(README));
    // The README example omits the table; the template supplies it.
    assert_eq!(
        readme.cleanup().projects.quiet_period,
        Duration::from_hours(24)
    );
    assert!(!readme.cleanup().projects.paseo_agents);
    let spec: ValidatedConfig = valid(example(POLICY_SPEC));
    assert_eq!(spec.cleanup(), readme.cleanup());
    assert!(spec.is_explicit("cleanup.projects.quiet_period"));

    let changed: ValidatedConfig = valid(&spec_with(
        "quiet_period = \"24h\"\npaseo_agents = false",
        "quiet_period = \"90d\"\npaseo_agents = true",
    ));
    assert_eq!(
        changed.cleanup().projects.quiet_period,
        Duration::from_hours(90 * 24)
    );
    assert!(changed.cleanup().projects.paseo_agents);
    valid(&spec_with(
        "quiet_period = \"24h\"",
        "quiet_period = \"1h\"",
    ));

    for out_of_range in ["59m", "91d", "3599999ms"] {
        assert_one(
            &spec_with(
                "quiet_period = \"24h\"",
                &format!("quiet_period = \"{out_of_range}\""),
            ),
            FindingCode::OutOfRange,
            "cleanup.projects.quiet_period",
        );
    }
    assert_one(
        &spec_with("quiet_period = \"24h\"", "quiet_period = \"0h\""),
        FindingCode::NotPositive,
        "cleanup.projects.quiet_period",
    );
    assert_one(
        &spec_with("paseo_agents = false", "paseo_agents = \"no\""),
        FindingCode::WrongType,
        "cleanup.projects.paseo_agents",
    );
    assert_one(
        &spec_with(
            "paseo_agents = false",
            "paseo_agents = false\nquiet = \"1d\"",
        ),
        FindingCode::UnknownKey,
        "cleanup.projects.quiet",
    );
}

#[test]
fn the_search_roots_are_plain_relative_paths_below_the_home_directory() {
    let document =
        |value: &str| format!("schema_version = 1\n[cleanup.projects]\nsearch_roots = {value}\n");
    let template: ValidatedConfig = valid(example(README));
    assert_eq!(
        template.cleanup().projects.search_roots,
        Vec::<String>::new()
    );
    let config: ValidatedConfig = valid(&document("[\"Developer\", \"GitHub/work\"]"));
    assert_eq!(
        config.cleanup().projects.search_roots,
        ["Developer", "GitHub/work"]
    );
    assert!(config.is_explicit("cleanup.projects.search_roots"));
    for bad in [
        "/Users/me/Code",
        "../other",
        "Code/../..",
        "./Code",
        "~/Code",
        "",
        "Code//app",
    ] {
        assert_one(
            &document(&format!("[\"{bad}\"]")),
            FindingCode::InvalidPath,
            "cleanup.projects.search_roots[0]",
        );
    }
    assert_one(
        &document("[\"Code\", \"code\"]"),
        FindingCode::DuplicateIdentifier,
        "cleanup.projects.search_roots[1]",
    );
    let many: String = (0..17)
        .map(|index| format!("\"r{index}\""))
        .collect::<Vec<String>>()
        .join(", ");
    assert_one(
        &document(&format!("[{many}]")),
        FindingCode::TooManyEntries,
        "cleanup.projects.search_roots",
    );
}

/// A document with one `[[cleanup.projects.layouts]]` table with `body`.
fn layout_document(body: &str) -> String {
    format!("schema_version = 1\n\n[[cleanup.projects.layouts]]\n{body}\n")
}

#[test]
fn a_user_layout_is_read_with_each_field() {
    let config: ValidatedConfig = valid(&format!(
        "{}\n[[cleanup.projects.layouts]]\ndirectory = \"builddir2/cache\"\nmarkers = [\"Gemfile\"]\n",
        layout_document(
            "directory = \"builddir\"\nmarkers = [\"meson.build\", \"*.meson\"]\ninner_marker = \"meson-info.json\"\nprotected = [\"keep\", \"*/release\"]\nquiet_period = \"2h\""
        )
    ));
    let layouts = &config.cleanup().projects.layouts;
    assert_eq!(layouts.len(), 2);
    assert_eq!(layouts[0].directory, "builddir");
    assert_eq!(layouts[0].markers, ["meson.build", "*.meson"]);
    assert_eq!(layouts[0].inner_marker.as_deref(), Some("meson-info.json"));
    assert_eq!(layouts[0].protected, ["keep", "*/release"]);
    assert_eq!(layouts[0].quiet_period, Some(Duration::from_hours(2)));
    assert_eq!(layouts[1].directory, "builddir2/cache");
    assert_eq!(layouts[1].inner_marker, None);
    assert_eq!(layouts[1].protected, Vec::<String>::new());
    assert_eq!(layouts[1].quiet_period, None);
    assert!(config.is_explicit("cleanup.projects.layouts"));
    // The template has no layout.
    assert_eq!(
        valid(example(POLICY_SPEC)).cleanup().projects.layouts,
        Vec::new()
    );
}

#[test]
fn each_invalid_directory_of_a_user_layout_has_a_finding() {
    let directory = "cleanup.projects.layouts[0].directory";
    let cases: Vec<(&str, FindingCode, String)> = vec![
        (
            "directory = \"/abs\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"../up\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"a/../b\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"a/b/c/d\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"a//b\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"~/x\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \".git\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"x/.GIT\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \".cache\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \".jj\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"Documents\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"library/x\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"out/b*\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "directory = \"a\\\\b\"\nmarkers = [\"m\"]",
            FindingCode::InvalidPath,
            directory.to_owned(),
        ),
        (
            "markers = [\"m\"]",
            FindingCode::MissingKey,
            directory.to_owned(),
        ),
    ];
    for (body, code, path) in cases {
        assert_one(&layout_document(body), code, &path);
    }
}

#[test]
fn each_invalid_key_of_a_user_layout_has_a_finding() {
    let markers = "cleanup.projects.layouts[0].markers";
    let first = |key: &str| format!("cleanup.projects.layouts[0].{key}");
    let cases: Vec<(&str, FindingCode, String)> = vec![
        (
            "directory = \"builddir\"",
            FindingCode::MissingKey,
            markers.to_owned(),
        ),
        (
            "directory = \"builddir\"\nmarkers = []",
            FindingCode::InvalidPath,
            markers.to_owned(),
        ),
        (
            "directory = \"builddir\"\nmarkers = \"m\"",
            FindingCode::WrongType,
            markers.to_owned(),
        ),
        (
            "directory = \"out\"\nmarkers = [\"sub/*.m\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"out\"\nmarkers = [\"a/b/c/d/e\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"out\"\nmarkers = [\"/abs\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"out\"\nmarkers = [\"a//b\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"out\"\nmarkers = [\".git/HEAD\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"out\"\nmarkers = [\"x/.cache/\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"*\"]",
            FindingCode::InvalidPath,
            first("markers[0]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\", \"*?\"]",
            FindingCode::InvalidPath,
            first("markers[1]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\", \"m\", \"m\", \"m\", \"m\", \"m\", \"m\", \"m\", \"m\"]",
            FindingCode::TooManyEntries,
            markers.to_owned(),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\ninner_marker = \"a/b\"",
            FindingCode::InvalidPath,
            first("inner_marker"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\ninner_marker = \"*.tag\"",
            FindingCode::InvalidPath,
            first("inner_marker"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\nprotected = [\"a/../b\"]",
            FindingCode::InvalidPath,
            first("protected[0]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\nprotected = [\"a/b/c/d/e\"]",
            FindingCode::InvalidPath,
            first("protected[0]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\nprotected = [\"/abs\"]",
            FindingCode::InvalidPath,
            first("protected[0]"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\nquiet_period = \"30m\"",
            FindingCode::OutOfRange,
            first("quiet_period"),
        ),
        (
            "directory = \"builddir\"\nmarkers = [\"m\"]\nautomatic = true",
            FindingCode::UnknownKey,
            first("automatic"),
        ),
    ];
    for (body, code, path) in cases {
        assert_one(&layout_document(body), code, &path);
    }
}

#[test]
fn the_user_layouts_are_bounded_and_have_distinct_directories() {
    // A second layout with the same directory, in another case.
    assert_one(
        &format!(
            "{}\n[[cleanup.projects.layouts]]\ndirectory = \"BUILDDIR\"\nmarkers = [\"m\"]\n",
            layout_document("directory = \"builddir\"\nmarkers = [\"m\"]")
        ),
        FindingCode::DuplicateIdentifier,
        "cleanup.projects.layouts[1].directory",
    );
    // At most 16 layouts.
    let mut many: String = String::from("schema_version = 1\n");
    for index in 0..=super::MAX_USER_LAYOUTS {
        write!(
            many,
            "\n[[cleanup.projects.layouts]]\ndirectory = \"builddir{index}\"\nmarkers = [\"m\"]\n"
        )
        .unwrap();
    }
    assert_one(
        &many,
        FindingCode::TooManyEntries,
        "cleanup.projects.layouts",
    );
    // A value that is not an array of tables.
    assert_one(
        "schema_version = 1\n[cleanup.projects]\nlayouts = \"out\"\n",
        FindingCode::WrongType,
        "cleanup.projects.layouts",
    );
}

#[test]
fn the_user_layout_example_of_the_policy_spec_validates() {
    let block: &str = POLICY_SPEC
        .split("```toml\n")
        .skip(1)
        .filter_map(|rest| rest.split("\n```").next())
        .find(|block| block.starts_with("[[cleanup.projects.layouts]]"))
        .expect("the document has a layout example");
    let config: ValidatedConfig = valid(&format!("schema_version = 1\n\n{block}\n"));
    let layout = &config.cleanup().projects.layouts[0];
    assert_eq!(layout.directory, "builddir");
    assert_eq!(layout.quiet_period, Some(Duration::from_hours(72)));
}

#[test]
fn a_user_layout_can_use_a_built_in_name_but_not_a_kept_out_name() {
    let directory = "cleanup.projects.layouts[0].directory";
    // The names that the rule keeps out (owner decision of 2026-11-23).
    for name in [
        "Vendor/x",
        "vendor",
        "tmp",
        "tmp/sessions",
        "_build",
        "zig-out",
        "deps",
        "DEPS/x",
        ".terraform",
        ".terraform/providers",
        ".wrangler/state",
        "_opam",
        ".hypothesis",
        ".terragrunt-cache",
        "Saved/Logs",
        "UserSettings",
    ] {
        assert_one(
            &layout_document(&format!(
                "directory = \"{name}\"\nmarkers = [\"rebar.config\"]"
            )),
            FindingCode::InvalidPath,
            directory,
        );
    }
    // A first name of a layout of the table: the layouts of the table come
    // first, and `overlaps_unit` refuses a unit in or around a unit of the
    // table.
    for name in [
        "build",
        "target",
        "node_modules/foo",
        "build/cache",
        "out/build",
    ] {
        let config: ValidatedConfig = valid(&layout_document(&format!(
            "directory = \"{name}\"\nmarkers = [\"CMakeLists.txt\"]"
        )));
        assert_eq!(config.cleanup().projects.layouts[0].directory, name);
    }
}

#[test]
fn a_user_layout_has_three_names_at_most_and_a_pattern_in_its_first_name_only() {
    let directory = "cleanup.projects.layouts[0].directory";
    let config: ValidatedConfig = valid(&layout_document(
        "directory = \"storage/framework/cache\"\nmarkers = [\"artisan\"]",
    ));
    assert_eq!(
        config.cleanup().projects.layouts[0].directory,
        "storage/framework/cache"
    );
    for pattern in ["cmake-build-*", "*.egg-info", "out?/cache"] {
        valid(&layout_document(&format!(
            "directory = \"{pattern}\"\nmarkers = [\"CMakeLists.txt\"]"
        )));
    }
    // A pattern that matches each name, that has no specific literal part,
    // or that can match a name of the skip list, a kept-out name, or a
    // protected name. The comparison ignores the case of ASCII letters.
    for pattern in [
        "*", "**", "*.*", "?", "a*", "*e", ".c*", "*CACHE", "de*", "*mp", "zig-*", "_bu*", "VEND*",
        "Doc*", "*rary", "*.git",
    ] {
        assert_one(
            &layout_document(&format!(
                "directory = \"{pattern}\"\nmarkers = [\"CMakeLists.txt\"]"
            )),
            FindingCode::InvalidPath,
            directory,
        );
    }
}

#[test]
fn a_user_marker_can_be_a_directory_or_a_path_in_a_subdirectory() {
    let config: ValidatedConfig = valid(&layout_document(
        "directory = \"Library2\"\nmarkers = [\"ProjectSettings/ProjectVersion.txt\", \".storybook/\", \"Assets/Scenes/\", \"*.xcodeproj/\"]",
    ));
    assert_eq!(
        config.cleanup().projects.layouts[0].markers,
        [
            "ProjectSettings/ProjectVersion.txt",
            ".storybook/",
            "Assets/Scenes/",
            "*.xcodeproj/"
        ]
    );
}

#[test]
fn a_pattern_marker_needs_a_specific_literal_part() {
    let marker = "cleanup.projects.layouts[0].markers[0]";
    for pattern in ["*.*", "a*", ".*", "*e", "?.?", "*..*", "*", "**", "*.?s"] {
        assert_one(
            &layout_document(&format!(
                "directory = \"builddir\"\nmarkers = [\"{pattern}\"]"
            )),
            FindingCode::InvalidPath,
            marker,
        );
    }
    for pattern in ["*.csproj", "*.py", "ab*", "x"] {
        valid(&layout_document(&format!(
            "directory = \"builddir\"\nmarkers = [\"{pattern}\"]"
        )));
    }
}
