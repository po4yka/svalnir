use clap::CommandFactory;
use serde_json::Value;

use crate::cli::Cli;
use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::test_support::{TempDirectory, environment, request_id};

struct Outcome {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Outcome {
    fn envelope(&self) -> Value {
        assert_eq!(self.stdout.lines().count(), 1, "{}", self.stdout);
        serde_json::from_str(&self.stdout).unwrap()
    }
}

fn run_with(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let status = run_in(
        std::iter::once("svalnir").chain(arguments.iter().copied()),
        request_id(),
        environment,
        &mut stdout,
        &mut stderr,
    );
    Outcome {
        status,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// Runs one invocation in a new temporary environment.
fn svalnir(arguments: &[&str]) -> Outcome {
    let (environment, _directory) = environment();
    run_with(&environment, arguments)
}

fn fixture(name: &str) -> String {
    format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Whether the state directory of the environment exists.
fn state_directory_exists(directory: &TempDirectory) -> bool {
    directory.path().join("state").exists()
}

#[test]
fn command_definition_is_valid() {
    Cli::command().debug_assert();
}

/// The commands of README.md and docs/INTERFACES.md section 6 that change
/// the host, a policy, or the agent, or that need the agent.
const NOT_IMPLEMENTED_COMMANDS: &[&[&str]] = &[
    &[
        "clean",
        "plan",
        "--scan",
        "SCAN_ID",
        "--profile",
        "developer",
        "--mode",
        "trash",
    ],
    &["clean", "show", "--plan", "PLAN_ID"],
    &["clean", "apply", "--plan", "PLAN_ID"],
    &["clean", "apply", "--plan", "PLAN_ID", "--yes", "--no-wait"],
    &[
        "operations",
        "show",
        "--operation",
        "OPERATION_ID",
        "--format",
        "json",
    ],
    &[
        "operations",
        "wait",
        "--operation",
        "OPERATION_ID",
        "--timeout",
        "30s",
    ],
    &["operations", "cancel", "--operation", "OPERATION_ID"],
    &[
        "processes",
        "stop",
        "--target",
        "TARGET_ID",
        "--grace",
        "10s",
        "--force-after-timeout",
    ],
    &["processes", "stop", "--target", "TARGET_ID", "--force"],
    &["agent", "install"],
    &["agent", "status"],
    &["agent", "pause", "--for", "1h"],
    &["agent", "resume"],
    &["agent", "uninstall"],
    &[
        "policy",
        "enable",
        "disk-guard",
        "--accept-permanent-eviction",
    ],
    &["policy", "enable", "memory-guard", "--accept-force-quit"],
    &["policy", "disable", "memory-guard"],
    &[
        "policy",
        "rearm",
        "memory-guard",
        "--incident",
        "INCIDENT_ID",
        "--generation",
        "GENERATION",
    ],
    &[
        "config",
        "apply",
        "--config",
        "./config.toml",
        "--expected-revision",
        "POLICY_REVISION",
    ],
    &["history", "--limit", "20"],
];

#[test]
fn mutating_commands_report_not_implemented_and_write_nothing() {
    for arguments in NOT_IMPLEMENTED_COMMANDS {
        let (environment, directory) = environment();
        let mut machine: Vec<&str> = arguments.to_vec();
        if !machine.contains(&"--format") {
            machine.extend(["--format", "json"]);
        }
        let outcome = run_with(&environment, &machine);
        assert_eq!(
            outcome.status,
            ExitStatus::Unavailable,
            "{arguments:?}: {}",
            outcome.stderr
        );
        assert_eq!(outcome.envelope()["error"]["code"], "not_implemented");
        assert!(!state_directory_exists(&directory), "{arguments:?}");
    }
}

#[test]
fn text_mode_error_goes_to_stderr_only() {
    let outcome = svalnir(&["clean", "apply", "--plan", "PLAN_ID", "--yes"]);
    assert_eq!(outcome.status.code(), 3);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "error: `svalnir clean apply` is not implemented in this build; the command made no change\n"
    );
}

#[test]
fn json_mode_error_is_one_envelope_on_stdout() {
    let outcome = svalnir(&["agent", "status", "--format", "json"]);
    assert_eq!(outcome.status, ExitStatus::Unavailable);
    assert_eq!(outcome.stderr, "");
    assert!(outcome.stdout.ends_with('\n'));
    assert_eq!(outcome.stdout.lines().count(), 1);
    let envelope: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(
        envelope,
        serde_json::json!({
            "schema_version": 1,
            "request_id": "request_test",
            "kind": "error",
            "result": null,
            "error": {
                "code": "not_implemented",
                "family": "native",
                "stage": "dispatch",
                "message": "`svalnir agent status` is not implemented in this build; the command made no change",
                "fields": [],
                "operation_id": null,
                "plan_id": null,
                "next_action": "none"
            },
            "warnings": []
        })
    );
}

#[test]
fn warnings_survive_a_command_error() {
    let args = [
        "config",
        "validate",
        "--config",
        "missing.toml",
        "--timeout",
        "5s",
    ];
    let machine = svalnir(&[&args[..], &["--format", "json"]].concat());
    assert_eq!(machine.status, ExitStatus::Usage);
    let envelope = machine.envelope();
    assert_eq!(envelope["kind"], "error");
    assert_eq!(envelope["warnings"][0]["code"], "timeout_not_applied");
    let text = svalnir(&args);
    assert!(text.stderr.contains("warning: "), "{}", text.stderr);
    assert!(text.stderr.contains("error: "), "{}", text.stderr);
    assert_eq!(text.stdout, "");
}

#[test]
fn completions_print_warnings_on_stderr() {
    let outcome = svalnir(&["completions", "bash", "--timeout", "5s"]);
    assert_eq!(outcome.status, ExitStatus::Success);
    assert!(outcome.stderr.contains("timeout"), "{}", outcome.stderr);
}

#[test]
fn json_line_serializes_before_writing() {
    struct Bad;
    impl serde::Serialize for Bad {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("fails"))
        }
    }
    let mut out: Vec<u8> = Vec::new();
    assert!(crate::commands::write_json(&mut out, &Bad).is_err());
    assert_eq!(out, Vec::<u8>::new());
}

#[test]
fn ndjson_is_rejected_for_a_command_that_does_not_stream() {
    let outcome = svalnir(&["memory", "status", "--format", "ndjson"]);
    assert_eq!(outcome.status, ExitStatus::Usage);
    let envelope: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(envelope["error"]["code"], "unsupported_format");
    assert_eq!(envelope["error"]["fields"], serde_json::json!(["format"]));
}

#[test]
fn incompatible_arguments_fail_before_dispatch() {
    let rejected: &[&[&str]] = &[
        &[],
        &["status", "--unknown"],
        &["scan"],
        &["clean", "apply"],
        &["clean", "plan", "--scan", "SCAN_ID", "--mode", "evict"],
        &[
            "processes",
            "stop",
            "--target",
            "TARGET_ID",
            "--force",
            "--force-after-timeout",
        ],
        &[
            "processes",
            "stop",
            "--target",
            "TARGET_ID",
            "--grace",
            "10",
        ],
        &["status", "--timeout", "soon"],
        &["status", "--timeout", "0s"],
        &["agent", "pause", "--for", "0m"],
        &[
            "processes",
            "stop",
            "--target",
            "TARGET_ID",
            "--grace",
            "0s",
            "--force-after-timeout",
        ],
        &["history", "--limit", "0"],
        &["processes", "top", "--limit", "0"],
        &[
            "clean", "plan", "--scan", "SCAN_ID", "--mode", "trash", "--rule", "RULE_ID",
        ],
        &["policy", "show", "cpu-guard"],
        &["config", "apply", "--config", "./config.toml"],
        &["status", "--yes"],
        &["completions", "zsh", "--format", "json"],
        &["monitor", "--interval", "100ms"],
        &["monitor", "--interval", "2h"],
        &["monitor", "--format", "json"],
        &["processes", "top", "--sort", "name"],
        &["processes", "show", "--target", "not a target"],
        &["report", "--scan", "not a scan id"],
    ];
    for arguments in rejected {
        let outcome = svalnir(arguments);
        assert_eq!(outcome.status, ExitStatus::Usage, "{arguments:?}");
        assert!(!outcome.stderr.is_empty() || !outcome.stdout.is_empty());
    }
}

#[test]
fn rejected_arguments_in_a_machine_format_give_an_envelope() {
    for arguments in [
        &[
            "clean", "plan", "--scan", "S", "--mode", "evict", "--format", "json",
        ][..],
        &["status", "--unknown", "--format=json"],
        &["--format", "ndjson", "scan"],
    ] {
        let outcome = svalnir(arguments);
        assert_eq!(outcome.status, ExitStatus::Usage, "{arguments:?}");
        assert!(outcome.stderr.starts_with("error:"), "{arguments:?}");
        assert_eq!(outcome.stdout.lines().count(), 1, "{arguments:?}");
        let envelope: Value = serde_json::from_str(&outcome.stdout).unwrap();
        assert_eq!(envelope["kind"], "error");
        assert_eq!(envelope["error"]["code"], "invalid_arguments");
        assert_eq!(envelope["error"]["family"], "request");
    }
    let text_mode = svalnir(&["status", "--unknown"]);
    assert_eq!(text_mode.stdout, "");
    let help = svalnir(&["--help", "--format", "json"]);
    assert_eq!(help.status, ExitStatus::Success);
}

struct ClosedPipe;

impl std::io::Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn closed_pipe_is_quiet_and_keeps_the_success_status() {
    let mut stderr: Vec<u8> = Vec::new();
    let (environment, _directory) = environment();
    let status = run_in(
        ["svalnir", "license"],
        request_id(),
        &environment,
        &mut ClosedPipe,
        &mut stderr,
    );
    assert_eq!(status, ExitStatus::Success);
    assert_eq!(stderr, b"");
}

#[test]
fn evict_mode_accepts_a_rule() {
    let outcome = svalnir(&[
        "clean",
        "plan",
        "--scan",
        "SCAN_ID",
        "--mode",
        "evict",
        "--rule",
        "xcode.inactive-derived-data",
    ]);
    assert_eq!(outcome.status, ExitStatus::Unavailable);
}

#[test]
fn help_and_version_succeed_on_stdout() {
    for arguments in [&["--help"][..], &["--version"], &["clean", "--help"]] {
        let outcome = svalnir(arguments);
        assert_eq!(outcome.status, ExitStatus::Success, "{arguments:?}");
        assert!(outcome.stdout.contains("svalnir"), "{arguments:?}");
        assert_eq!(outcome.stderr, "");
    }
}

#[test]
fn completions_cover_the_command_surface() {
    for shell in ["bash", "zsh", "fish"] {
        let outcome = svalnir(&["completions", shell]);
        assert_eq!(outcome.status, ExitStatus::Success);
        assert!(outcome.stdout.contains("svalnir"));
        assert!(outcome.stdout.contains("force-after-timeout"));
        assert_eq!(outcome.stderr, "");
    }
}

#[test]
fn license_prints_the_notice_and_the_text() {
    let outcome = svalnir(&["license"]);
    assert_eq!(outcome.status, ExitStatus::Success);
    assert!(outcome.stdout.starts_with("Svalnir is licensed under"));
    assert!(outcome.stdout.contains("GNU GENERAL PUBLIC LICENSE"));
}

#[test]
fn license_in_json_is_a_report() {
    let outcome = svalnir(&["license", "--format", "json"]);
    assert_eq!(outcome.status, ExitStatus::Success);
    let envelope: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(envelope["kind"], "report");
    assert_eq!(envelope["result"]["spdx_id"], "GPL-3.0-only");
    assert_eq!(envelope["error"], Value::Null);
}

#[test]
fn exit_codes_follow_the_interface_contract() {
    let codes: Vec<u8> = [
        ExitStatus::Success,
        ExitStatus::Failure,
        ExitStatus::Usage,
        ExitStatus::Unavailable,
        ExitStatus::Partial,
        ExitStatus::Conflict,
        ExitStatus::Interrupted,
    ]
    .map(ExitStatus::code)
    .to_vec();
    assert_eq!(codes, [0, 1, 2, 3, 4, 5, 130]);
}

#[test]
fn a_read_only_command_does_not_create_the_state_directory() {
    let (environment, directory) = environment();
    for arguments in [
        &["config", "show"][..],
        &["policy", "list"],
        &["policy", "show", "disk-guard"],
        &["report", "--scan", "scan_absent"],
        &["config", "validate", "--config", &fixture("valid.toml")],
    ] {
        let outcome = run_with(&environment, arguments);
        assert!(outcome.status != ExitStatus::Failure, "{arguments:?}");
        assert!(!state_directory_exists(&directory), "{arguments:?}");
    }
}

#[test]
fn a_relative_state_directory_override_is_rejected() {
    let (mut environment, _directory) = environment();
    environment.state_directory_override = Some("relative/state".into());
    let outcome = run_with(&environment, &["policy", "list", "--format", "json"]);
    assert_eq!(outcome.status, ExitStatus::Usage);
    assert_eq!(
        outcome.envelope()["error"]["code"],
        "invalid_state_directory"
    );
}

#[test]
fn scan_and_report_work_end_to_end_on_a_temporary_directory() {
    let (environment, directory) = environment();
    let root = directory.path().join("tree");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("one.bin"), vec![7_u8; 100_000]).unwrap();
    std::fs::write(root.join("nested/two.txt"), b"two").unwrap();

    // A scan without `--save` writes nothing. The path is relative to the
    // invocation directory.
    let unsaved = run_with(&environment, &["scan", "tree", "--format", "json"]);
    assert_eq!(unsaved.status, ExitStatus::Success, "{}", unsaved.stdout);
    let envelope = unsaved.envelope();
    assert_eq!(envelope["kind"], "snapshot");
    assert_eq!(envelope["result"]["save"], "not_requested");
    assert_eq!(envelope["result"]["scan"]["coverage"], "complete");
    assert_eq!(envelope["result"]["scan"]["totals"]["files"], "2");
    assert_eq!(envelope["result"]["scan"]["totals"]["directories"], "1");
    assert_eq!(
        envelope["result"]["scan"]["totals"]["logical_bytes"],
        "100003"
    );
    assert_eq!(
        envelope["result"]["scan"]["root"]["value"],
        root.to_str().unwrap()
    );
    assert!(!state_directory_exists(&directory));

    // `--save` creates the state directory and records the result.
    let saved = run_with(
        &environment,
        &["scan", root.to_str().unwrap(), "--save", "--format", "json"],
    );
    assert_eq!(saved.status, ExitStatus::Success, "{}", saved.stdout);
    let envelope = saved.envelope();
    assert_eq!(envelope["result"]["save"], "saved");
    let scan_id: String = envelope["result"]["scan"]["scan_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(directory.path().join("state/catalog.sqlite").is_file());
    #[cfg(target_os = "macos")]
    {
        let observation = &envelope["result"]["observations"]["allocated_bytes"];
        assert_eq!(observation["metric_id"], "scan.allocated_bytes");
        assert_eq!(observation["scope"]["kind"], "scan");
        assert_eq!(observation["scope"]["identity_id"], scan_id.as_str());
        assert_eq!(
            envelope["result"]["observations"]["exclusive_bytes"]["reason"],
            "unsupported"
        );
    }

    let report = run_with(
        &environment,
        &["report", "--scan", &scan_id, "--format", "json"],
    );
    assert_eq!(report.status, ExitStatus::Success, "{}", report.stdout);
    let reported = report.envelope();
    assert_eq!(reported["kind"], "report");
    assert_eq!(reported["result"]["scan"], envelope["result"]["scan"]);

    let text = run_with(&environment, &["report", "--scan", &scan_id]);
    assert_eq!(text.status, ExitStatus::Success);
    assert!(
        text.stdout.starts_with(&format!("Scan {scan_id} of ")),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("one.bin"), "{}", text.stdout);
    assert!(text.stdout.contains("This is a saved record from "));
    assert_eq!(text.stderr, "");

    let missing = run_with(
        &environment,
        &["report", "--scan", "scan_absent", "--format", "json"],
    );
    assert_eq!(missing.status, ExitStatus::Conflict);
    assert_eq!(missing.envelope()["error"]["code"], "scan_not_found");
    assert_eq!(missing.envelope()["error"]["family"], "evidence");
}

#[cfg(unix)]
#[test]
fn a_scan_with_an_unreadable_directory_is_partial_with_status_4() {
    use std::os::unix::fs::PermissionsExt as _;

    let (environment, directory) = environment();
    let root = directory.path().join("tree");
    let locked = root.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(root.join("file"), b"data").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let outcome = run_with(
        &environment,
        &["scan", root.to_str().unwrap(), "--format", "json"],
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The superuser can read each directory, so the scan is then complete.
    if outcome.status == ExitStatus::Success {
        return;
    }
    assert_eq!(outcome.status, ExitStatus::Partial, "{}", outcome.stdout);
    let envelope = outcome.envelope();
    assert_eq!(envelope["kind"], "snapshot");
    assert_eq!(envelope["result"]["scan"]["coverage"], "partial");
    assert_eq!(
        envelope["result"]["scan"]["regions"][0]["cause"],
        "permission_denied"
    );
    assert_eq!(envelope["result"]["scan"]["totals"]["files"], "1");
}

#[test]
fn a_scan_of_a_missing_root_or_of_a_file_is_a_request_error() {
    let (environment, directory) = environment();
    std::fs::write(directory.path().join("file"), b"data").unwrap();
    for (path, code) in [
        ("absent", "scan_root_not_found"),
        ("file", "invalid_scan_root"),
    ] {
        let outcome = run_with(&environment, &["scan", path, "--save", "--format", "json"]);
        assert_eq!(
            outcome.status,
            ExitStatus::Usage,
            "{path}: {}",
            outcome.stdout
        );
        assert_eq!(outcome.envelope()["error"]["code"], code);
    }
    let text = run_with(&environment, &["scan", "absent"]);
    assert_eq!(text.status, ExitStatus::Usage);
    assert_eq!(text.stdout, "");
    assert!(
        text.stderr.starts_with("error: the scan did not start"),
        "{}",
        text.stderr
    );
}

#[test]
fn config_validate_reads_a_fixture_and_never_activates_it() {
    let valid = svalnir(&[
        "config",
        "validate",
        "--config",
        &fixture("valid.toml"),
        "--format",
        "json",
    ]);
    assert_eq!(valid.status, ExitStatus::Success, "{}", valid.stdout);
    let envelope = valid.envelope();
    assert_eq!(envelope["kind"], "report");
    assert_eq!(envelope["result"]["valid"], true);
    assert_eq!(envelope["result"]["active_configuration_changed"], false);
    assert_eq!(envelope["result"]["source"]["selected_by"], "option");
    assert_eq!(
        envelope["result"]["requires_agent"]
            .as_array()
            .unwrap()
            .len(),
        5
    );

    let invalid = svalnir(&[
        "config",
        "validate",
        "--config",
        &fixture("invalid.toml"),
        "--format",
        "json",
    ]);
    assert_eq!(invalid.status, ExitStatus::Usage, "{}", invalid.stdout);
    let envelope = invalid.envelope();
    assert_eq!(envelope["kind"], "report");
    assert_eq!(envelope["error"], Value::Null);
    assert_eq!(envelope["result"]["valid"], false);
    let codes: Vec<&str> = envelope["result"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["code"].as_str().unwrap())
        .collect();
    for code in ["threshold_order", "unknown_key", "invalid_size"] {
        assert!(codes.contains(&code), "{codes:?}");
    }

    let text = svalnir(&["config", "validate", "--config", &fixture("invalid.toml")]);
    assert_eq!(text.status, ExitStatus::Usage);
    assert!(text.stdout.contains("Result: not valid"), "{}", text.stdout);
    assert!(
        text.stdout.contains("disk_guard.no_such_key"),
        "{}",
        text.stdout
    );
}

#[test]
fn config_validate_needs_a_file() {
    let outcome = svalnir(&["config", "validate", "--format", "json"]);
    assert_eq!(outcome.status, ExitStatus::Usage);
    assert_eq!(outcome.envelope()["error"]["code"], "config_not_found");
    let missing = svalnir(&[
        "config",
        "validate",
        "--config",
        "absent.toml",
        "--format",
        "json",
    ]);
    assert_eq!(missing.status, ExitStatus::Usage);
    assert_eq!(missing.envelope()["error"]["stage"], "input");
}

#[test]
fn the_default_proposal_is_the_file_in_the_state_directory() {
    let (environment, directory) = environment();
    let state = directory.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::copy(fixture("valid.toml"), state.join("config.toml")).unwrap();
    let validated = run_with(&environment, &["config", "validate", "--format", "json"]);
    assert_eq!(
        validated.status,
        ExitStatus::Success,
        "{}",
        validated.stdout
    );
    assert_eq!(
        validated.envelope()["result"]["source"]["selected_by"],
        "default"
    );

    let shown = run_with(&environment, &["config", "show", "--format", "json"]);
    assert_eq!(shown.status, ExitStatus::Success);
    let envelope = shown.envelope();
    assert_eq!(envelope["result"]["active"], false);
    assert_eq!(envelope["result"]["profile"], "balanced");
    assert_eq!(envelope["result"]["source"]["kind"], "file");

    let listed = run_with(&environment, &["policy", "list", "--format", "json"]);
    assert_eq!(listed.envelope()["result"]["policies"][0]["enabled"], true);

    // A proposal that is not valid stops a command that needs its values.
    std::fs::copy(fixture("invalid.toml"), state.join("config.toml")).unwrap();
    let rejected = run_with(
        &environment,
        &["policy", "show", "disk-guard", "--format", "json"],
    );
    assert_eq!(rejected.status, ExitStatus::Usage);
    assert_eq!(
        rejected.envelope()["error"]["code"],
        "invalid_configuration"
    );
}

#[test]
fn without_a_file_the_proposal_is_the_built_in_template() {
    let shown = svalnir(&["config", "show", "--format", "json"]);
    assert_eq!(shown.status, ExitStatus::Success, "{}", shown.stdout);
    let envelope = shown.envelope();
    assert_eq!(envelope["kind"], "report");
    assert_eq!(envelope["result"]["source"]["kind"], "built_in_template");
    assert_eq!(envelope["result"]["active"], false);
    assert_eq!(
        envelope["result"]["explicit_keys"],
        serde_json::json!(["schema_version"])
    );

    let text = svalnir(&["policy", "show", "memory-guard"]);
    assert_eq!(text.status, ExitStatus::Success);
    assert!(
        text.stdout.starts_with("Policy (proposal, not active)\n"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("Source: built-in template"),
        "{}",
        text.stdout
    );
}

#[test]
fn the_effective_configuration_needs_the_agent() {
    let outcome = svalnir(&["config", "show", "--effective", "--format", "json"]);
    assert_eq!(outcome.status, ExitStatus::Unavailable);
    let envelope = outcome.envelope();
    assert_eq!(envelope["error"]["code"], "agent_unavailable");
    assert_eq!(envelope["error"]["family"], "native");
}

#[test]
fn a_timeout_on_an_in_process_command_is_a_warning() {
    let json = svalnir(&["policy", "list", "--timeout", "5s", "--format", "json"]);
    assert_eq!(json.status, ExitStatus::Success);
    assert_eq!(
        json.envelope()["warnings"][0]["code"],
        "timeout_not_applied"
    );
    let text = svalnir(&["policy", "list", "--timeout", "5s"]);
    assert!(text.stderr.starts_with("warning: "), "{}", text.stderr);
    assert!(!text.stdout.contains("warning"));
}

#[test]
fn a_target_that_is_not_valid_is_rejected_before_collection() {
    let outcome = svalnir(&[
        "processes",
        "show",
        "--target",
        "TARGET_ID",
        "--format",
        "json",
    ]);
    assert_eq!(outcome.status, ExitStatus::Usage);
    assert_eq!(outcome.envelope()["error"]["code"], "invalid_target");
    assert_eq!(
        outcome.envelope()["error"]["fields"],
        serde_json::json!(["target"])
    );
}

/// The commands that read the real host. They read only: memory statistics,
/// the capacity of the startup volume, and the processes of the current
/// user. The assertions do not depend on what the host runs.
#[cfg(target_os = "macos")]
mod host {
    use serde_json::Value;

    use super::{fixture, run_with, svalnir};
    use crate::output::ExitStatus;
    use crate::test_support::environment;

    fn assert_complete_or_partial(status: ExitStatus) {
        assert!(
            matches!(status, ExitStatus::Success | ExitStatus::Partial),
            "{status:?}"
        );
    }

    #[test]
    fn status_memory_and_swap_give_snapshots_with_canonical_observations() {
        let status = svalnir(&["status", "--format", "json"]);
        assert_complete_or_partial(status.status);
        assert_eq!(status.stderr, "");
        let envelope = status.envelope();
        assert_eq!(envelope["kind"], "snapshot");
        assert_eq!(envelope["schema_version"], 1);
        assert_eq!(envelope["request_id"], "request_test");
        assert_eq!(envelope["error"], Value::Null);
        let result = &envelope["result"];
        assert_eq!(result["memory"]["pressure"]["metric_id"], "memory.pressure");
        assert_eq!(result["memory"]["pressure"]["scope"]["kind"], "host");
        assert_eq!(result["memory"]["physical"]["unit"], "byte");
        assert!(result["memory"]["physical"]["value"].is_string());
        assert_eq!(
            result["swap"]["used"]["metric_id"],
            "memory.swap.used_bytes"
        );
        assert_eq!(result["agent"]["state"], "not_running");
        assert_eq!(result["policies"]["state"], "none_active");
        assert_eq!(
            status.status == ExitStatus::Partial,
            result["coverage"]["required_scope"] == "partial"
        );

        let memory = svalnir(&["memory", "status"]);
        assert_complete_or_partial(memory.status);
        assert!(memory.stdout.starts_with("Memory\n"), "{}", memory.stdout);
        assert!(!memory.stdout.contains('\x1b'));

        let swap = svalnir(&["swap", "status", "--format", "json"]);
        assert_complete_or_partial(swap.status);
        assert_eq!(swap.envelope()["kind"], "snapshot");
        assert_eq!(
            swap.envelope()["result"]["swap"]["activity"]["swapins"]["reason"],
            "not_initialized"
        );
    }

    #[test]
    fn doctor_is_a_successful_diagnostic_for_each_verdict() {
        let (environment, directory) = environment();
        let outcome = run_with(&environment, &["doctor", "--format", "json"]);
        assert_eq!(outcome.status, ExitStatus::Success);
        let envelope = outcome.envelope();
        assert_eq!(envelope["kind"], "report");
        assert_eq!(envelope["result"]["subject"]["role"], "cli");
        assert_eq!(
            envelope["result"]["capabilities"].as_array().unwrap().len(),
            13
        );
        // A diagnostic creates nothing.
        assert!(!directory.path().join("state").exists());
    }

    #[test]
    fn processes_top_lists_this_process_and_show_resolves_its_target() {
        let top = svalnir(&["processes", "top", "--limit", "100000", "--format", "json"]);
        assert_complete_or_partial(top.status);
        let envelope = top.envelope();
        assert_eq!(envelope["kind"], "snapshot");
        let own_pid = u64::from(std::process::id());
        let entries = envelope["result"]["entries"].as_array().unwrap();
        let own = entries
            .iter()
            .find(|entry| entry["pid"] == own_pid)
            .expect("the test process is a process of the current user");
        let target: &str = own["target_id"].as_str().unwrap();
        assert!(target.starts_with(&format!("pg-{own_pid}-")), "{target}");
        assert_eq!(own["footprint"]["metric_id"], "process.footprint_bytes");

        let limited = svalnir(&["processes", "top", "--limit", "1", "--sort", "rss"]);
        assert_complete_or_partial(limited.status);
        assert!(
            limited.stdout.contains("is not permission to act"),
            "{}",
            limited.stdout
        );

        let shown = svalnir(&["processes", "show", "--target", target, "--format", "json"]);
        assert_eq!(shown.status, ExitStatus::Success, "{}", shown.stdout);
        let result = &shown.envelope()["result"];
        assert_eq!(result["identity"]["pid"], own_pid);
        assert_eq!(result["policy_eligibility"]["evaluated"], false);

        // A generation that does not exist: PID 1 is not of this user.
        let gone = svalnir(&[
            "processes",
            "show",
            "--target",
            "pg-1-1",
            "--format",
            "json",
        ]);
        assert_eq!(gone.status, ExitStatus::Conflict);
        assert_eq!(gone.envelope()["error"]["code"], "target_not_found");
    }

    #[test]
    fn policy_simulate_evaluates_a_fixture_against_one_snapshot() {
        for policy in ["disk-guard", "memory-guard"] {
            let outcome = svalnir(&[
                "policy",
                "simulate",
                policy,
                "--config",
                &fixture("valid.toml"),
                "--format",
                "json",
            ]);
            assert_eq!(outcome.status, ExitStatus::Success, "{}", outcome.stdout);
            let envelope = outcome.envelope();
            assert_eq!(envelope["kind"], "report");
            let result = &envelope["result"];
            assert_eq!(result["active"], false);
            assert_eq!(result["source"]["selected_by"], "option");
            assert_eq!(result["simulation"]["policy"], policy);
            assert_eq!(result["simulation"]["enabled"], true);
            assert_eq!(result["simulation"]["revision"]["source"], "proposed");
            assert_eq!(result["simulation"]["assumed_grants"]["basis"], "recorded");
            assert_ne!(result["simulation"]["triggers"], serde_json::json!([]));
            // One snapshot cannot qualify a trigger, and no grant exists.
            for action in result["simulation"]["first_actions"].as_array().unwrap() {
                assert_eq!(action["admissible_now"], false);
            }
        }
        let text = svalnir(&["policy", "simulate", "disk-guard"]);
        assert_eq!(text.status, ExitStatus::Success);
        assert!(
            text.stdout
                .starts_with("Simulation of a proposal against one snapshot (not active)\n"),
            "{}",
            text.stdout
        );
    }
}
