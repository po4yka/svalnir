//! Tests of `disk` and of the MCP server of `svalnir mcp`.
//!
//! `disk` reads the volume of a temporary home directory of the host. The
//! server reads a scripted stdin. The round trip of a plan uses the
//! fixture of `evict_tests`: a `DerivedData` root below a temporary home
//! directory, and a rule lifecycle state that only a test build can give.
//! A removal is only below the temporary directory.

use std::io::Cursor;

use serde_json::{Value, json};

use crate::environment::Environment;
use crate::output::ExitStatus;
use crate::run_in;
use crate::test_support::environment;

struct Outcome {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn run(environment: &Environment, arguments: &[&str]) -> Outcome {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let request_id = svalnir_core::id::RequestId::new(format!(
        "request_mcp_{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ))
    .unwrap();
    let status = run_in(
        std::iter::once("svalnir").chain(arguments.iter().copied()),
        request_id,
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

// `disk`

#[test]
fn disk_reports_the_volume_of_the_home_directory_in_text_and_json() {
    let (environment, _directory) = environment();
    let text = run(&environment, &["disk"]);
    assert!(
        matches!(text.status, ExitStatus::Success | ExitStatus::Partial),
        "{}",
        text.stderr
    );
    assert!(
        text.stdout.contains("Disk (volume of the home directory"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("Available"), "{}", text.stdout);
    let json = run(&environment, &["disk", "--format", "json"]);
    let envelope: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(envelope["kind"], "snapshot");
    let result = &envelope["result"];
    assert_eq!(result["disk"]["selector"], "home");
    assert!(result["disk"]["available"].is_object(), "{result}");
    assert!(result["threshold"].is_null());
    assert!(result["below_threshold"].is_null());
}

#[test]
fn disk_warns_only_below_the_threshold() {
    let (environment, _directory) = environment();
    // Each volume has more than one byte available: no output.
    let quiet = run(&environment, &["disk", "--warn-below", "1B"]);
    assert_eq!(quiet.status, ExitStatus::Success);
    assert_eq!(quiet.stdout, "");
    assert_eq!(quiet.stderr, "");
    // No volume has 8000000 TiB available: one warning line.
    let loud = run(&environment, &["disk", "--warn-below", "8000000TiB"]);
    assert_eq!(loud.status, ExitStatus::Success);
    assert_eq!(loud.stdout.lines().count(), 1, "{}", loud.stdout);
    assert!(
        loud.stdout.starts_with("Warning: only ") && loud.stdout.contains("below 7.6 EiB"),
        "{}",
        loud.stdout
    );
    // A machine format always has the report.
    let json = run(
        &environment,
        &["disk", "--warn-below", "1B", "--format", "json"],
    );
    let envelope: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(envelope["result"]["below_threshold"], false);
    assert_eq!(envelope["result"]["threshold"], "1");
}

#[test]
fn an_error_of_the_warning_mode_goes_to_stderr_with_exit_status_zero() {
    let (mut environment, _directory) = environment();
    // A decimal unit is not in the grammar of a size.
    let size = run(&environment, &["disk", "--warn-below", "20GB"]);
    assert_eq!(size.status, ExitStatus::Success);
    assert_eq!(size.stdout, "");
    assert!(
        size.stderr.starts_with("error: the value `20GB`"),
        "{}",
        size.stderr
    );
    let json = run(
        &environment,
        &["disk", "--warn-below", "20GB", "--format", "json"],
    );
    assert_eq!(json.status, ExitStatus::Success);
    assert_eq!(json.stdout, "");
    // With no home directory, the mode also ends with status 0; without
    // the mode, the error has its exit status.
    environment.home = None;
    let no_home = run(&environment, &["disk", "--warn-below", "20GiB"]);
    assert_eq!(no_home.status, ExitStatus::Success);
    assert_eq!(no_home.stdout, "");
    assert!(
        no_home.stderr.contains("`HOME` is not set"),
        "{}",
        no_home.stderr
    );
    let plain = run(&environment, &["disk", "--format", "json"]);
    assert_eq!(plain.status, ExitStatus::Unavailable);
    let envelope: Value = serde_json::from_str(&plain.stdout).unwrap();
    assert_eq!(envelope["error"]["code"], "home_not_set");
}

// The MCP server

struct Session {
    status: ExitStatus,
    responses: Vec<Value>,
    stderr: String,
}

fn serve_bytes(environment: &Environment, input: Vec<u8>) -> Session {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let status = crate::mcp::serve(
        environment,
        Box::new(Cursor::new(input)),
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    // Each line of stdout is one JSON-RPC response, and nothing else.
    let responses: Vec<Value> = stdout
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("not JSON ({error}): {line}"));
            assert_eq!(value["jsonrpc"], "2.0", "{line}");
            assert!(
                value.get("result").is_some() != value.get("error").is_some(),
                "{line}"
            );
            value
        })
        .collect();
    assert!(stdout.is_empty() || stdout.ends_with('\n'));
    Session {
        status,
        responses,
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn serve(environment: &Environment, messages: &[Value]) -> Session {
    let mut input: Vec<u8> = Vec::new();
    for message in messages {
        input.extend(serde_json::to_vec(message).unwrap());
        input.push(b'\n');
    }
    serve_bytes(environment, input)
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    }})
}

fn initialized() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
}

fn call(id: u64, name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": name,
        "arguments": arguments,
    }})
}

/// The response with the identity `id`.
fn response(session: &Session, id: u64) -> &Value {
    session
        .responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("no response {id}: {:?}", session.responses))
}

#[test]
fn the_handshake_lists_each_tool_with_a_closed_schema() {
    let (environment, _directory) = environment();
    let session = serve(
        &environment,
        &[
            initialize(),
            initialized(),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        ],
    );
    assert_eq!(session.status, ExitStatus::Success);
    // The notification has no response.
    assert_eq!(session.responses.len(), 3, "{:?}", session.responses);
    let init = &response(&session, 0)["result"];
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["serverInfo"]["name"], "svalnir");
    assert!(init["capabilities"]["tools"].is_object());
    assert!(
        init["instructions"]
            .as_str()
            .unwrap()
            .contains("cannot verify the approval")
    );
    let tools = response(&session, 1)["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "disk",
            "scan",
            "report",
            "inspect",
            "plan",
            "show",
            "apply",
            "operations"
        ]
    );
    for tool in tools {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "{tool}");
        assert_eq!(schema["additionalProperties"], false, "{tool}");
        for required in schema["required"].as_array().unwrap() {
            assert!(
                schema["properties"][required.as_str().unwrap()].is_object(),
                "{tool}"
            );
        }
        assert!(tool["description"].as_str().unwrap().len() > 40, "{tool}");
    }
    let apply = tools.iter().find(|tool| tool["name"] == "apply").unwrap();
    assert_eq!(
        apply["inputSchema"]["required"],
        json!(["plan_id", "digest"])
    );
    assert_eq!(apply["annotations"]["destructiveHint"], true);
    let description = apply["description"].as_str().unwrap();
    assert!(description.contains("the user approved this plan"));
    assert!(description.contains("cannot verify that approval"));
    let plan = tools.iter().find(|tool| tool["name"] == "plan").unwrap();
    assert_eq!(
        plan["inputSchema"]["properties"]["mode"]["enum"],
        json!(["evict", "trash"])
    );
    assert!(
        plan["description"]
            .as_str()
            .unwrap()
            .contains("ask the user to approve it")
    );
    assert_eq!(response(&session, 2)["result"], json!({}));
    // An unknown requested version gets the newest version with the
    // handshake.
    let other = serve(
        &environment,
        &[
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2024-01-01"}}),
        ],
    );
    assert_eq!(
        response(&other, 0)["result"]["protocolVersion"],
        "2025-11-25"
    );
}

#[test]
fn a_modern_request_has_its_version_in_meta() {
    let (environment, _directory) = environment();
    let meta = |version: &str| json!({"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientCapabilities": {}});
    let session = serve(
        &environment,
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta("2026-07-28")}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": meta("2026-07-28")}}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": meta("1900-01-01")}}),
            // No version and no handshake.
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}),
        ],
    );
    let discover = &response(&session, 1)["result"];
    assert_eq!(discover["resultType"], "complete");
    assert_eq!(discover["supportedVersions"], json!(["2026-07-28"]));
    assert_eq!(
        discover["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "svalnir"
    );
    let list = &response(&session, 2)["result"];
    assert_eq!(list["resultType"], "complete");
    assert_eq!(list["tools"].as_array().unwrap().len(), 8);
    for (id, requested) in [(3, json!("1900-01-01")), (4, Value::Null)] {
        let error = &response(&session, id)["error"];
        assert_eq!(error["code"], -32_022, "{error}");
        assert_eq!(error["data"]["requested"], requested);
        assert_eq!(error["data"]["supported"][0], "2026-07-28");
    }
}

#[test]
fn a_message_that_is_not_a_valid_request_gets_the_error_of_the_specification() {
    let (environment, _directory) = environment();
    let mut input: Vec<u8> = Vec::new();
    let mut line = |value: &[u8]| {
        input.extend_from_slice(value);
        input.push(b'\n');
    };
    line(&serde_json::to_vec(&initialize()).unwrap());
    line(b"{not json");
    line(b"[]");
    line(br#"{"jsonrpc": "2.0", "id": 5, "method": "resources/list"}"#);
    line(br#"{"jsonrpc": "2.0", "method": "notifications/unknown"}"#);
    line(br#"{"jsonrpc": "1.0", "id": 6, "method": "ping"}"#);
    line(br#"{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "rm"}}"#);
    line(br#"{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "disk", "arguments": {"path": "/"}}}"#);
    // A line longer than the limit, then a request that is answered.
    let mut long: Vec<u8> =
        br#"{"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {"x": ""#.to_vec();
    long.resize(crate::mcp::MAX_LINE_BYTES + 10, b'a');
    long.extend_from_slice(br#""}}"#);
    line(&long);
    line(br#"{"jsonrpc": "2.0", "id": 10, "method": "ping"}"#);
    line(b"");
    let session = serve_bytes(&environment, input);
    assert_eq!(session.status, ExitStatus::Success);
    let codes: Vec<(Value, Value)> = session
        .responses
        .iter()
        .skip(1)
        .map(|response| (response["id"].clone(), response["error"]["code"].clone()))
        .collect();
    assert_eq!(
        codes,
        [
            (Value::Null, json!(-32_700)),
            (Value::Null, json!(-32_600)),
            (json!(5), json!(-32_601)),
            (json!(6), json!(-32_600)),
            (json!(7), json!(-32_602)),
            // An unknown argument is an error of the tool.
            (json!(8), Value::Null),
            (Value::Null, json!(-32_600)),
            (json!(10), Value::Null),
        ]
    );
    let unknown_argument = &response(&session, 8)["result"];
    assert_eq!(unknown_argument["isError"], true);
    assert!(
        unknown_argument["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("has no argument `path`")
    );
    assert!(session.stderr.contains("longer than"), "{}", session.stderr);
}

#[test]
fn the_disk_tool_has_the_result_of_the_command() {
    let (environment, _directory) = environment();
    let session = serve(
        &environment,
        &[
            initialize(),
            call(1, "disk", &json!({})),
            call(2, "disk", &json!({"warn_below": "1B"})),
            call(3, "disk", &json!({"warn_below": "20GB"})),
            call(4, "plan", &json!({"mode": "permanent"})),
        ],
    );
    let plain = &response(&session, 1)["result"];
    assert_eq!(plain["isError"], false, "{plain}");
    let structured = &plain["structuredContent"];
    assert_eq!(structured["response"]["result"]["disk"]["selector"], "home");
    // The text block is the serialized structured content.
    let text: Value = serde_json::from_str(plain["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, structured);
    let threshold = &response(&session, 2)["result"]["structuredContent"];
    assert_eq!(threshold["response"]["result"]["below_threshold"], false);
    for id in [3, 4] {
        assert_eq!(response(&session, id)["result"]["isError"], true);
    }
}

#[cfg(debug_assertions)]
mod round_trip {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use serde_json::{Value, json};
    use svalnir_agent::rules::fixture::{
        FixtureEnvironment, derived_data_root, manual_action_validated, write_project,
        write_workspace,
    };

    use super::{call, initialize, response, run, serve};
    use crate::environment::Environment;
    use crate::output::ExitStatus;
    use crate::seams::TestEnvironment;
    use crate::test_support::{TempDirectory, environment};

    const RULE: &str = "xcode.inactive-derived-data";
    const UNITS: [&str; 3] = [
        "Build/Intermediates.noindex",
        "Build/Products",
        "Index.noindex",
    ];

    fn world() -> (Environment, TempDirectory, PathBuf) {
        let (mut environment, directory) = environment();
        let evidence = FixtureEnvironment::days_later(30);
        environment.seams.test.rule_lifecycle = Some(manual_action_validated());
        environment.seams.test.discovery_environment = Some(TestEnvironment(Arc::new(evidence)));
        let home: PathBuf = std::fs::canonicalize(environment.home.as_ref().unwrap()).unwrap();
        let root: PathBuf = derived_data_root(&home);
        std::fs::create_dir_all(&root).unwrap();
        let workspace: PathBuf = write_workspace(&directory.path().join("src"), "App").unwrap();
        let project: PathBuf =
            write_project(&root, "App-abcdefghijklmnopqrstuvwxyzab", &workspace).unwrap();
        let config: PathBuf = directory.path().join("config.toml");
        std::fs::write(&config, "schema_version = 1\n").unwrap();
        let activated = run(
            &environment,
            &[
                "config",
                "apply",
                "--config",
                config.to_str().unwrap(),
                "--expected-revision",
                "none",
                "--format",
                "json",
            ],
        );
        assert_eq!(
            activated.status,
            ExitStatus::Success,
            "{}",
            activated.stdout
        );
        (environment, directory, project)
    }

    fn remaining(project: &Path) -> usize {
        UNITS
            .iter()
            .filter(|unit| project.join(unit).exists())
            .count()
    }

    #[test]
    fn a_plan_is_applied_only_with_its_digest() {
        let (environment, _directory, project) = world();
        let planned = serve(
            &environment,
            &[
                initialize(),
                call(1, "inspect", &json!({"rule": "go.build-cache"})),
                call(2, "plan", &json!({"mode": "evict", "rule": RULE})),
            ],
        );
        let inspected = &response(&planned, 1)["result"];
        assert_eq!(inspected["isError"], false, "{inspected}");
        let plan = &response(&planned, 2)["result"];
        assert_eq!(plan["isError"], false, "{plan}");
        let structured = &plan["structuredContent"];
        let approval = &structured["approval"];
        let plan_id: &str = approval["plan_id"].as_str().unwrap();
        let digest: &str = approval["digest"].as_str().unwrap();
        assert!(
            approval["note"]
                .as_str()
                .unwrap()
                .contains("ask for approval")
        );
        let explanation = &structured["response"]["result"]["explanation"];
        assert_eq!(explanation["targets"].as_array().unwrap().len(), 3);
        assert_eq!(remaining(&project), 3);

        let applied = serve(
            &environment,
            &[
                initialize(),
                call(1, "show", &json!({"plan_id": plan_id})),
                // A wrong digest, and no digest, are refused.
                call(
                    2,
                    "apply",
                    &json!({"plan_id": plan_id, "digest": "sha256:0000"}),
                ),
                call(3, "apply", &json!({"plan_id": plan_id})),
            ],
        );
        let shown = &response(&applied, 1)["result"]["structuredContent"];
        assert_eq!(
            shown["response"]["result"]["explanation"]["plan"]["digest"],
            digest
        );
        let wrong = &response(&applied, 2)["result"];
        assert_eq!(wrong["isError"], true, "{wrong}");
        assert_eq!(
            wrong["structuredContent"]["response"]["error"]["code"],
            "plan_digest_mismatch"
        );
        assert_eq!(response(&applied, 3)["result"]["isError"], true);
        assert_eq!(remaining(&project), 3);

        let session = serve(
            &environment,
            &[
                initialize(),
                call(
                    1,
                    "apply",
                    &json!({"plan_id": plan_id, "digest": digest, "timeout": "1m"}),
                ),
            ],
        );
        let done = &response(&session, 1)["result"];
        assert_eq!(done["isError"], false, "{done}");
        assert_eq!(done["structuredContent"]["exit_status"], 0, "{done}");
        assert_eq!(remaining(&project), 0);
        let operation_id: String =
            done["structuredContent"]["response"]["result"]["operation"]["operation_id"]
                .as_str()
                .unwrap()
                .to_owned();
        // The operation, and a second apply that makes no second one.
        let after = serve(
            &environment,
            &[
                initialize(),
                call(
                    1,
                    "operations",
                    &json!({"action": "show", "operation_id": operation_id}),
                ),
                call(
                    2,
                    "operations",
                    &json!({"action": "wait", "operation_id": operation_id, "timeout": "10s"}),
                ),
                call(3, "apply", &json!({"plan_id": plan_id, "digest": digest})),
            ],
        );
        for id in [1, 2] {
            let result = &response(&after, id)["result"];
            assert_eq!(result["isError"], false, "{result}");
            assert_eq!(
                result["structuredContent"]["response"]["result"]["operation"]["operation_id"],
                Value::from(operation_id.as_str()),
                "{result}"
            );
        }
        let again = &response(&after, 3)["result"]["structuredContent"]["response"]["result"];
        assert_eq!(again["existing_operation"], true, "{again}");
    }
}

#[test]
fn the_server_ends_at_the_end_of_stdin_with_no_output() {
    let (environment, _directory) = environment();
    let session = serve_bytes(&environment, Vec::new());
    assert_eq!(session.status, ExitStatus::Success);
    assert_eq!(session.responses, Vec::<Value>::new());
    // `--format json` is refused before the server starts.
    let refused = run(&environment, &["mcp", "--format", "json"]);
    assert_eq!(refused.status, ExitStatus::Usage);
}

#[test]
fn a_stop_signal_ends_the_server_between_two_requests() {
    let (mut environment, _directory) = environment();
    let (interrupt, _flag, signal) = crate::interrupt::Interrupt::manual_with_stop_signal();
    environment.interrupt = interrupt;
    signal.store(15, std::sync::atomic::Ordering::SeqCst);
    let session = serve(&environment, &[initialize()]);
    assert_eq!(session.status, ExitStatus::Terminated);
    assert_eq!(session.responses, Vec::<Value>::new());
    assert!(
        session.stderr.contains("SIGTERM received"),
        "{}",
        session.stderr
    );
}
