use clap::CommandFactory;
use serde_json::Value;

use crate::cli::Cli;
use crate::output::{ExitStatus, RequestId};
use crate::run_with_request_id;

struct Outcome {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn svalnir(arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let status = run_with_request_id(
        std::iter::once("svalnir").chain(arguments.iter().copied()),
        RequestId::new("request_test").unwrap(),
        &mut stdout,
        &mut stderr,
    );
    Outcome {
        status,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

#[test]
fn command_definition_is_valid() {
    Cli::command().debug_assert();
}

/// The examples of README.md and docs/INTERFACES.md section 6.
const DOCUMENTED_AGENT_COMMANDS: &[&[&str]] = &[
    &["doctor"],
    &["status", "--format", "json"],
    &["scan", "/Users/example", "--save"],
    &["report", "--scan", "SCAN_ID"],
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
    &["memory", "status"],
    &["swap", "status"],
    &[
        "processes",
        "top",
        "--sort",
        "footprint",
        "--format",
        "json",
    ],
    &["processes", "show", "--target", "TARGET_ID"],
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
    &["monitor", "--format", "ndjson"],
    &["agent", "install"],
    &["agent", "status"],
    &["agent", "pause", "--for", "1h"],
    &["agent", "resume"],
    &["agent", "uninstall"],
    &["policy", "list"],
    &["policy", "show", "disk-guard"],
    &["policy", "show", "memory-guard"],
    &["policy", "simulate", "disk-guard"],
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
    &["config", "validate"],
    &["config", "validate", "--config", "./config.toml"],
    &["config", "show", "--effective", "--format", "json"],
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
fn documented_agent_commands_parse_and_report_not_implemented() {
    for arguments in DOCUMENTED_AGENT_COMMANDS {
        let outcome = svalnir(arguments);
        assert_eq!(
            outcome.status,
            ExitStatus::Unavailable,
            "{arguments:?}: {}",
            outcome.stderr
        );
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
    let outcome = svalnir(&["status", "--format", "json"]);
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
                "message": "`svalnir status` is not implemented in this build; the command made no change",
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
    let status = run_with_request_id(
        ["svalnir", "license"],
        RequestId::new("request_test").unwrap(),
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
