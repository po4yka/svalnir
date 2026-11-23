//! `svalnir mcp`: a Model Context Protocol server on stdin and stdout.
//!
//! The server reads one JSON-RPC 2.0 message on each line of stdin and
//! writes one response on each line of stdout. Stdout has only these
//! responses; the log goes to stderr, with a bound on each line and on the
//! total. `docs/INTERFACES.md` section 17 owns the contract.
//!
//! Each tool call is one invocation of a CLI command through
//! [`crate::run_in`], with `--format json`, in this process. A tool has no
//! other path to the host: `apply` is `clean apply`, so the request queue
//! of the journal, the lifecycle gates, the protections, and the `HOME`
//! check are those of the CLI. `apply` adds `--require-agent`, so the
//! server is never a transient coordinator, and `--only-modes evict,trash`.
//! The server cannot verify that the user approved a plan
//! (`docs/THREAT_MODEL.md` section 7). `apply` requires the digest that
//! `plan` or `show` returned, and `clean apply --digest` refuses a
//! different stored plan.
//!
//! The server supports the protocol revision `2026-07-28`, with the
//! protocol version in the `_meta` of each request, and the revisions
//! with the `initialize` handshake, for an earlier client.

use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use serde_json::{Map, Value, json};
use svalnir_core::byte_size::parse_byte_size;
use svalnir_core::duration::parse_duration;

use crate::commands::{CommandFailure, Invocation, json_line, write_interruptible};
use crate::environment::Environment;
use crate::output::{ExitStatus, generate_request_id};
use crate::text::escape;

/// The protocol revision with the version in the `_meta` of each request.
pub(crate) const MODERN_VERSION: &str = "2026-07-28";

/// The revisions with the `initialize` handshake, the newest first.
pub(crate) const LEGACY_VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];

/// The `_meta` key of the protocol version of a request.
const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key of the client capabilities of a request.
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// The code, the message, and the data of an error response.
type ProtocolError = (i64, String, Option<Value>);

/// The longest line of stdin. A longer line is refused and not parsed.
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The longest text argument of a tool.
const MAX_TEXT_BYTES: usize = 4096;

/// The largest number of items of a list argument of a tool.
const MAX_LIST_ITEMS: usize = 64;

/// The largest tool result. A larger result is an error of the tool.
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// The largest response line. A response of a tool call is at most
/// [`MAX_RESULT_BYTES`] and a summary, so this bound is a last guard.
const MAX_RESPONSE_BYTES: usize = MAX_RESULT_BYTES + 64 * 1024;

/// The largest result that the text block of a tool result repeats.
const MAX_INLINE_TEXT_BYTES: usize = 64 * 1024;

/// The part of the stderr of a command that the server keeps.
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;

/// A sink that keeps at most `limit` bytes and records the overflow. A
/// write never fails, so the command runs as it does with a terminal.
struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room: usize = self.limit.saturating_sub(self.bytes.len());
        if data.len() > room {
            self.overflowed = true;
        }
        self.bytes.extend_from_slice(&data[..data.len().min(room)]);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The client wait of `apply` and of `operations` with `wait`, when the
/// call gives no `timeout`.
const DEFAULT_WAIT: &str = "5m";

/// The longest client wait that a tool call can give.
const MAX_WAIT: Duration = Duration::from_mins(30);

/// The interval at which the server reads the stop signals while no
/// request is pending.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The longest line of the log.
const MAX_LOG_LINE_BYTES: usize = 2048;

/// The total size of the log of one server process.
const MAX_LOG_BYTES: usize = 256 * 1024;

/// JSON-RPC and MCP error codes.
const PARSE_ERROR: i64 = -32_700;
const INVALID_REQUEST: i64 = -32_600;
const METHOD_NOT_FOUND: i64 = -32_601;
const INVALID_PARAMS: i64 = -32_602;
const INTERNAL_ERROR: i64 = -32_603;
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32_022;

const INSTRUCTIONS: &str = "Svalnir reads the disk capacity of this Mac and prepares bounded cleanup plans for regenerable data. Run `disk`, `inspect`, and `plan` first. Show each plan to the user: the targets, the size estimate, and the warnings. Call `apply` only after the user approved that plan. This server cannot verify the approval of the user.";

const APPROVAL_NOTE: &str = "Show this plan to the user and ask for approval. Give `plan_id` and `digest` to `apply` only after the user approved this plan. The server cannot verify the approval.";

/// One line of stdin, as the reader thread gives it.
enum Input {
    Line(Vec<u8>),
    /// A line longer than [`MAX_LINE_BYTES`]. Its bytes were discarded.
    TooLong,
    End,
    Failed(io::Error),
}

/// Reads one line of at most `limit` bytes, with no newline. The bytes of
/// a longer line are read to its end and discarded.
fn read_bounded_line(reader: &mut dyn BufRead, limit: usize) -> io::Result<Input> {
    let mut line: Vec<u8> = Vec::new();
    let mut too_long: bool = false;
    loop {
        let buffer: &[u8] = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if buffer.is_empty() {
            return Ok(if too_long {
                Input::TooLong
            } else if line.is_empty() {
                Input::End
            } else {
                Input::Line(line)
            });
        }
        let (part, consumed, complete): (&[u8], usize, bool) =
            match buffer.iter().position(|byte| *byte == b'\n') {
                Some(end) => (&buffer[..end], end + 1, true),
                None => (buffer, buffer.len(), false),
            };
        if !too_long {
            if line.len() + part.len() > limit {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(part);
            }
        }
        reader.consume(consumed);
        if complete {
            return Ok(if too_long {
                Input::TooLong
            } else {
                Input::Line(line)
            });
        }
    }
}

/// Starts the thread that reads stdin. The queue holds one line, so the
/// reader waits while the server handles a request.
fn spawn_reader(mut reader: Box<dyn BufRead + Send>) -> Receiver<Input> {
    let (sender, receiver): (SyncSender<Input>, Receiver<Input>) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        loop {
            let input: Input = match read_bounded_line(reader.as_mut(), MAX_LINE_BYTES) {
                Ok(input) => input,
                Err(error) => Input::Failed(error),
            };
            let last: bool = matches!(input, Input::End | Input::Failed(_));
            if sender.send(input).is_err() || last {
                return;
            }
        }
    });
    receiver
}

/// The log of the server on stderr, with a bound on each line and on the
/// total.
struct Log {
    remaining: usize,
}

impl Log {
    fn new() -> Self {
        Self {
            remaining: MAX_LOG_BYTES,
        }
    }

    fn write(&mut self, stderr: &mut dyn Write, message: &str) {
        if self.remaining == 0 {
            return;
        }
        let escaped: String = escape(message);
        let mut end: usize = escaped.len().min(MAX_LOG_LINE_BYTES);
        while !escaped.is_char_boundary(end) {
            end -= 1;
        }
        let line: String = format!("svalnir mcp: {}\n", &escaped[..end]);
        // No other stream is available if a write of the log fails.
        if line.len() > self.remaining {
            self.remaining = 0;
            drop(stderr.write_all(
                b"svalnir mcp: the log limit is reached; later messages are not written\n",
            ));
            return;
        }
        self.remaining -= line.len();
        drop(stderr.write_all(line.as_bytes()));
    }
}

/// Runs the server on the stdin of the process.
///
/// # Errors
///
/// Returns an output failure when stdout rejects a write.
pub(crate) fn serve_process(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    for warning in std::mem::take(&mut invocation.warnings) {
        writeln!(invocation.stderr, "warning: {}", warning.message)?;
    }
    let reader: Box<dyn BufRead + Send> = Box::new(io::BufReader::new(io::stdin()));
    Ok(serve(
        invocation.environment,
        reader,
        invocation.stdout,
        invocation.stderr,
    )?)
}

/// Serves the requests of `reader` until its end, or until a stop signal
/// or Ctrl+C. A stop signal ends the server after the current request.
///
/// # Errors
///
/// Returns the error of a write to stdout.
pub(crate) fn serve(
    environment: &Environment,
    reader: Box<dyn BufRead + Send>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<ExitStatus> {
    // `SIGTERM` and `SIGHUP` set a flag from now on, so the server can
    // end between two requests, and the client wait of `apply` and of
    // `operations` ends at once.
    environment.interrupt.arm_stop_signals();
    let input: Receiver<Input> = spawn_reader(reader);
    let mut server = Server {
        environment,
        legacy: None,
        log: Log::new(),
    };
    loop {
        if let Some(signal) = environment.interrupt.stop_signal() {
            server.log.write(
                stderr,
                &format!("{} received; the server ends", signal.name()),
            );
            return Ok(signal.exit_status());
        }
        if environment.interrupt.is_requested() {
            return Ok(ExitStatus::Interrupted);
        }
        let response: Option<Value> = match input.recv_timeout(POLL_INTERVAL) {
            Ok(Input::Line(line)) => server.handle(&line, stderr),
            Ok(Input::TooLong) => {
                server.log.write(
                    stderr,
                    &format!("a message is longer than {MAX_LINE_BYTES} bytes and was not read"),
                );
                Some(error_response(
                    Value::Null,
                    INVALID_REQUEST,
                    &format!("the message is longer than {MAX_LINE_BYTES} bytes"),
                    None,
                ))
            }
            Ok(Input::End) | Err(RecvTimeoutError::Disconnected) => return Ok(ExitStatus::Success),
            Ok(Input::Failed(error)) => {
                server
                    .log
                    .write(stderr, &format!("stdin cannot be read: {error}"));
                return Ok(ExitStatus::Failure);
            }
            Err(RecvTimeoutError::Timeout) => None,
        };
        if let Some(response) = response {
            let mut line: Vec<u8> = json_line(&response)?;
            if line.len() > MAX_RESPONSE_BYTES {
                server
                    .log
                    .write(stderr, "a response is too large and was not written");
                line = json_line(&error_response(
                    response.get("id").cloned().unwrap_or(Value::Null),
                    INTERNAL_ERROR,
                    "the response is too large",
                    None,
                ))?;
            }
            write_interruptible(stdout, &line, &environment.interrupt)?;
            stdout.flush()?;
        }
    }
}

/// The protocol era of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Era {
    /// The version is in the `_meta` of the request.
    Modern,
    /// The version came from `initialize`.
    Legacy,
}

struct Server<'a> {
    environment: &'a Environment,
    /// The version that `initialize` selected.
    legacy: Option<&'static str>,
    log: Log,
}

fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error: Map<String, Value> = Map::new();
    error.insert("code".to_owned(), Value::from(code));
    error.insert("message".to_owned(), Value::from(message));
    if let Some(data) = data {
        error.insert("data".to_owned(), data);
    }
    response(id, "error", Value::Object(error))
}

/// A response object. Its fields are moved in, not copied.
fn response(id: Value, field: &str, value: Value) -> Value {
    let mut message: Map<String, Value> = Map::new();
    message.insert("jsonrpc".to_owned(), Value::from("2.0"));
    message.insert("id".to_owned(), id);
    message.insert(field.to_owned(), value);
    Value::Object(message)
}

fn result_response(id: Value, era: Option<Era>, mut result: Map<String, Value>) -> Value {
    if era == Some(Era::Modern) {
        result.insert("resultType".to_owned(), Value::from("complete"));
    }
    response(id, "result", Value::Object(result))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn server_info() -> Value {
    json!({"name": "svalnir", "version": env!("CARGO_PKG_VERSION")})
}

fn supported_versions() -> Value {
    let mut versions: Vec<&str> = vec![MODERN_VERSION];
    versions.extend(LEGACY_VERSIONS);
    Value::from(versions)
}

impl Server<'_> {
    /// Handles one line. Returns the response, or nothing for a
    /// notification or for a response of the client.
    fn handle(&mut self, line: &[u8], stderr: &mut dyn Write) -> Option<Value> {
        let line: &[u8] = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let message: Value = match serde_json::from_slice(line) {
            Ok(message) => message,
            Err(error) => {
                self.log
                    .write(stderr, &format!("a message is not JSON: {error}"));
                return Some(error_response(
                    Value::Null,
                    PARSE_ERROR,
                    "the message is not JSON",
                    None,
                ));
            }
        };
        let Value::Object(message) = message else {
            return Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                "the message is not a JSON-RPC object; a batch is not supported",
                None,
            ));
        };
        let id: Option<Value> = message.get("id").cloned();
        let method: Option<&str> = message.get("method").and_then(Value::as_str);
        let Some(id) = id else {
            // A notification gets no response, also an unknown one. A
            // message with no method and no identity is not valid, and
            // it also gets none: it has no identity to answer.
            return None;
        };
        if !(id.is_string() || id.is_i64() || id.is_u64()) {
            return Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                "the identity of a request must be a string or an integer",
                None,
            ));
        }
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_response(
                id,
                INVALID_REQUEST,
                "the message must have `jsonrpc` with the value `2.0`",
                None,
            ));
        }
        let Some(method) = method else {
            // A response of the client to a request: this server sends
            // no request, so there is nothing to do.
            if message.contains_key("result") || message.contains_key("error") {
                return None;
            }
            return Some(error_response(
                id,
                INVALID_REQUEST,
                "the request has no method",
                None,
            ));
        };
        let params: Map<String, Value> = match message.get("params") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(params)) => params.clone(),
            Some(_) => {
                return Some(error_response(
                    id,
                    INVALID_PARAMS,
                    "`params` must be an object",
                    None,
                ));
            }
        };
        Some(self.dispatch(id, method, &params, stderr))
    }

    fn dispatch(
        &mut self,
        id: Value,
        method: &str,
        params: &Map<String, Value>,
        stderr: &mut dyn Write,
    ) -> Value {
        let requested: Option<&Value> = params.get("_meta").and_then(|meta| meta.get(VERSION_KEY));
        match method {
            "initialize" => self.initialize(id, params),
            "server/discover" => result_response(
                id,
                Some(Era::Modern),
                object(json!({
                    "supportedVersions": [MODERN_VERSION],
                    "capabilities": {"tools": {}},
                    "_meta": {"io.modelcontextprotocol/serverInfo": server_info()},
                    "instructions": INSTRUCTIONS,
                })),
            ),
            // The revision 2026-07-28 has no `ping`; the revisions with the
            // handshake have it.
            "ping" if requested.is_none() => result_response(id, Some(Era::Legacy), Map::new()),
            "tools/list" | "tools/call" => {
                let era: Era = match self.era(params) {
                    Ok(era) => era,
                    Err((code, message, data)) => {
                        return error_response(id, code, &message, data);
                    }
                };
                if method == "tools/list" {
                    let tools: Vec<Value> = TOOLS.iter().map(Tool::definition).collect();
                    result_response(id, Some(era), object(json!({"tools": tools})))
                } else {
                    self.call(id, era, params, stderr)
                }
            }
            _ => error_response(
                id,
                METHOD_NOT_FOUND,
                &format!("the method `{}` is not supported", escape(method)),
                None,
            ),
        }
    }

    /// The era of a request: modern with a supported version and the
    /// client capabilities in `_meta`, legacy after `initialize`. The
    /// error is the code, the message, and the data of the response.
    fn era(&self, params: &Map<String, Value>) -> Result<Era, ProtocolError> {
        let meta: Option<&Value> = params.get("_meta");
        let unsupported = |requested: Value| {
            (
                UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version".to_owned(),
                Some(json!({"supported": supported_versions(), "requested": requested})),
            )
        };
        match meta.and_then(|meta| meta.get(VERSION_KEY)) {
            Some(Value::String(version)) if version == MODERN_VERSION => {
                if meta
                    .and_then(|meta| meta.get(CAPABILITIES_KEY))
                    .is_none_or(|value| !value.is_object())
                {
                    return Err((
                        INVALID_PARAMS,
                        format!(
                            "a request of the revision {MODERN_VERSION} needs `{CAPABILITIES_KEY}` in `_meta`"
                        ),
                        None,
                    ));
                }
                Ok(Era::Modern)
            }
            Some(other) => Err(unsupported(other.clone())),
            None if self.legacy.is_some() => Ok(Era::Legacy),
            None => Err(unsupported(Value::Null)),
        }
    }

    fn initialize(&mut self, id: Value, params: &Map<String, Value>) -> Value {
        let requested: Option<&str> = params.get("protocolVersion").and_then(Value::as_str);
        // The requested version when this server supports it, and else
        // the newest version with the handshake.
        let version: &'static str = LEGACY_VERSIONS
            .iter()
            .copied()
            .find(|version| Some(*version) == requested)
            .unwrap_or(LEGACY_VERSIONS[0]);
        self.legacy = Some(version);
        result_response(
            id,
            Some(Era::Legacy),
            object(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": server_info(),
                "instructions": INSTRUCTIONS,
            })),
        )
    }

    fn call(
        &mut self,
        id: Value,
        era: Era,
        params: &Map<String, Value>,
        stderr: &mut dyn Write,
    ) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error_response(id, INVALID_PARAMS, "`name` must be a string", None);
        };
        let Some(tool) = TOOLS.iter().find(|tool| tool.name == name) else {
            return error_response(
                id,
                INVALID_PARAMS,
                &format!("Unknown tool: {}", escape(name)),
                None,
            );
        };
        let empty: Map<String, Value> = Map::new();
        let arguments: &Map<String, Value> = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => {
                return error_response(id, INVALID_PARAMS, "`arguments` must be an object", None);
            }
        };
        let result: Map<String, Value> = match tool.command(&Arguments { map: arguments }) {
            Ok(command) => self.run_tool(tool, command, stderr),
            // An argument that is not valid is an error of the tool, which
            // the model can correct.
            Err(message) => tool_error(&message),
        };
        result_response(id, Some(era), result)
    }

    /// Runs one CLI command and makes the tool result of its envelope.
    fn run_tool(
        &mut self,
        tool: &Tool,
        command: Vec<String>,
        stderr: &mut dyn Write,
    ) -> Map<String, Value> {
        let mut arguments: Vec<OsString> = vec!["svalnir".into(), "--format".into(), "json".into()];
        arguments.extend(command.into_iter().map(OsString::from));
        let mut out = BoundedBuffer::new(MAX_RESULT_BYTES);
        let mut err = BoundedBuffer::new(MAX_DIAGNOSTIC_BYTES);
        let status: ExitStatus = crate::run_in(
            arguments,
            generate_request_id(),
            self.environment,
            &mut out,
            &mut err,
        );
        if out.overflowed {
            self.log.write(
                stderr,
                &format!(
                    "tool `{}`: exit status {}; the result is too large",
                    tool.name,
                    status.code()
                ),
            );
            return tool_error(&format!(
                "the result is larger than {MAX_RESULT_BYTES} bytes; select a smaller scope (exit status {})",
                status.code()
            ));
        }
        let (out, err): (Vec<u8>, Vec<u8>) = (out.bytes, err.bytes);
        self.log.write(
            stderr,
            &format!("tool `{}`: exit status {}", tool.name, status.code()),
        );
        let diagnostics: String = String::from_utf8_lossy(&err).trim().to_owned();
        if !diagnostics.is_empty() {
            self.log.write(stderr, &diagnostics);
        }
        let envelope: Option<Value> = serde_json::from_slice::<Value>(&out)
            .ok()
            .filter(Value::is_object);
        let Some(envelope) = envelope else {
            let detail: &str = if diagnostics.is_empty() {
                "no detail"
            } else {
                &diagnostics
            };
            return tool_error(&format!(
                "the command gave no result (exit status {}): {detail}",
                status.code()
            ));
        };
        let failed: bool = !envelope["error"].is_null();
        let mut structured: Map<String, Value> = Map::new();
        structured.insert("exit_status".to_owned(), Value::from(status.code()));
        if tool.name == "plan" && !failed {
            let plan: &Value = &envelope["result"]["explanation"]["plan"];
            if let (Some(plan_id), Some(digest)) =
                (plan["plan_id"].as_str(), plan["digest"].as_str())
            {
                structured.insert(
                    "approval".to_owned(),
                    json!({"plan_id": plan_id, "digest": digest, "note": APPROVAL_NOTE}),
                );
            }
        }
        structured.insert("response".to_owned(), envelope);
        let summary: Option<Value> = structured.get("approval").cloned();
        let structured = Value::Object(structured);
        let mut text: String = structured.to_string();
        if text.len() > MAX_RESULT_BYTES {
            return tool_error(&format!(
                "the result is larger than {MAX_RESULT_BYTES} bytes; select a smaller scope"
            ));
        }
        // A large result is in `structuredContent` only, so the response
        // has it one time; the text has a summary.
        if text.len() > MAX_INLINE_TEXT_BYTES {
            text = json!({
                "exit_status": status.code(),
                "approval": summary,
                "error": structured["response"]["error"],
                "note": "The result is large; the full result is in `structuredContent`.",
            })
            .to_string();
        }
        object(json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
            "isError": failed,
        }))
    }
}

fn tool_error(message: &str) -> Map<String, Value> {
    object(json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    }))
}

/// The arguments of one tool call.
struct Arguments<'a> {
    map: &'a Map<String, Value>,
}

impl Arguments<'_> {
    fn text(&self, name: &str) -> Result<Option<&str>, String> {
        match self.map.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => checked_text(name, text).map(Some),
            Some(_) => Err(format!("`{name}` must be a string")),
        }
    }

    fn required_text(&self, name: &str) -> Result<&str, String> {
        self.text(name)?
            .ok_or_else(|| format!("`{name}` is required"))
    }

    fn flag(&self, name: &str) -> Result<bool, String> {
        match self.map.get(name) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(format!("`{name}` must be a boolean")),
        }
    }

    fn texts(&self, name: &str) -> Result<Vec<&str>, String> {
        match self.map.get(name) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => {
                if items.len() > MAX_LIST_ITEMS {
                    return Err(format!("`{name}` has more than {MAX_LIST_ITEMS} items"));
                }
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(text) => checked_text(name, text),
                        _ => Err(format!("each item of `{name}` must be a string")),
                    })
                    .collect()
            }
            Some(_) => Err(format!("`{name}` must be a list of strings")),
        }
    }
}

fn checked_text<'a>(name: &str, text: &'a str) -> Result<&'a str, String> {
    if text.is_empty() {
        return Err(format!("`{name}` must not be empty"));
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!("`{name}` is longer than {MAX_TEXT_BYTES} bytes"));
    }
    if text.contains('\0') {
        return Err(format!("`{name}` must not contain a NUL character"));
    }
    Ok(text)
}

/// Adds `--option=VALUE`. The `=` form keeps a value that starts with `-`
/// a value: it is never read as an option.
fn option(command: &mut Vec<String>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        command.push(format!("--{name}={value}"));
    }
}

fn switch(command: &mut Vec<String>, name: &str, on: bool) {
    if on {
        command.push(format!("--{name}"));
    }
}

/// The client wait of a call: `timeout`, or [`DEFAULT_WAIT`].
fn wait(arguments: &Arguments<'_>) -> Result<String, String> {
    let text: &str = arguments.text("timeout")?.unwrap_or(DEFAULT_WAIT);
    let duration: Duration = parse_duration(text).map_err(|error| error.to_string())?;
    if duration.is_zero() || duration > MAX_WAIT {
        return Err(format!(
            "`timeout` must be longer than zero and at most 30m, not `{}`",
            escape(text)
        ));
    }
    Ok(text.to_owned())
}

/// One tool: its definition and the CLI command of a call.
struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    /// The properties of the input schema, and the required ones.
    properties: fn() -> Value,
    required: &'static [&'static str],
    read_only: bool,
    destructive: bool,
    /// Whether a repeated call with the same arguments has no further
    /// effect.
    idempotent: bool,
    build: fn(&Arguments<'_>) -> Result<Vec<String>, String>,
}

impl Tool {
    fn definition(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": (self.properties)(),
                "required": self.required,
                "additionalProperties": false,
            },
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": false,
            },
        })
    }

    /// Checks the argument names against the schema, and builds the
    /// command.
    fn command(&self, arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
        let properties: Value = (self.properties)();
        if let Some(unknown) = arguments
            .map
            .keys()
            .find(|key| properties.get(key.as_str()).is_none())
        {
            return Err(format!(
                "the tool `{}` has no argument `{}`",
                self.name,
                escape(unknown)
            ));
        }
        for name in self.required {
            if arguments.map.get(*name).is_none_or(Value::is_null) {
                return Err(format!("`{name}` is required"));
            }
        }
        (self.build)(arguments)
    }
}

fn text_property(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn list_property(description: &str) -> Value {
    json!({"type": "array", "items": {"type": "string"}, "maxItems": MAX_LIST_ITEMS, "description": description})
}

fn flag_property(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}

const ROOT_DESCRIPTION: &str = "A search root of the project rules: an absolute path below the home directory. It adds to `[cleanup.projects].search_roots`.";

const TIMEOUT_DESCRIPTION: &str = "The longest client wait, for example `2m`; at most `30m`, default `5m`. The end of the wait cancels nothing.";

fn build_disk(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["disk".to_owned()];
    if let Some(text) = arguments.text("warn_below")? {
        // `disk --warn-below` reports an error on stderr only, so the size
        // is checked here, where the error reaches the model.
        parse_byte_size(text).map_err(|error| error.to_string())?;
        option(&mut command, "warn-below", Some(text));
    }
    Ok(command)
}

fn build_scan(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["scan".to_owned()];
    switch(&mut command, "save", arguments.flag("save")?);
    // `--` ends the options, so a path that starts with `-` is a path.
    let path: &str = arguments.required_text("path")?;
    if !std::path::Path::new(path).is_absolute() {
        return Err("`path` must be an absolute path".to_owned());
    }
    command.push("--".to_owned());
    command.push(path.to_owned());
    Ok(command)
}

fn build_report(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["report".to_owned()];
    option(&mut command, "scan", arguments.text("scan")?);
    option(&mut command, "window", arguments.text("window")?);
    option(&mut command, "threshold", arguments.text("threshold")?);
    Ok(command)
}

/// The description of the option `allow_unmarked` of `inspect` and `plan`.
const UNMARKED_DESCRIPTION: &str = "Also select a distinctive directory with no project marker of a layout that permits it, such as `.venv` with `pyvenv.cfg`, as a unit of its unmarked layout name (layout name with `+unmarked`). Each other check applies. Rule `project.dependency-directory` only, for a manual plan only; ask the user before you use it.";

fn project_roots(arguments: &Arguments<'_>, command: &mut Vec<String>) -> Result<(), String> {
    for root in arguments.texts("roots")? {
        option(command, "root", Some(root));
    }
    switch(command, "no-mise", arguments.flag("no_mise")?);
    Ok(())
}

fn build_inspect(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["clean".to_owned(), "inspect".to_owned()];
    option(&mut command, "rule", Some(arguments.required_text("rule")?));
    project_roots(arguments, &mut command)?;
    switch(
        &mut command,
        "allow-unmarked",
        arguments.flag("allow_unmarked")?,
    );
    Ok(command)
}

fn build_plan(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mode: &str = arguments.required_text("mode")?;
    // The permanent removal of named entries is not a mode of this tool.
    if !matches!(mode, "evict" | "trash") {
        return Err("`mode` must be `evict` or `trash`".to_owned());
    }
    let mut command: Vec<String> = vec!["clean".to_owned(), "plan".to_owned()];
    option(&mut command, "mode", Some(mode));
    option(&mut command, "rule", arguments.text("rule")?);
    option(&mut command, "scan", arguments.text("scan")?);
    for entry in arguments.texts("entries")? {
        option(&mut command, "entry", Some(entry));
    }
    option(&mut command, "profile", arguments.text("profile")?);
    project_roots(arguments, &mut command)?;
    switch(
        &mut command,
        "include-active",
        arguments.flag("include_active")?,
    );
    switch(
        &mut command,
        "allow-unmarked",
        arguments.flag("allow_unmarked")?,
    );
    option(&mut command, "min-size", arguments.text("min_size")?);
    Ok(command)
}

fn build_show(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["clean".to_owned(), "show".to_owned()];
    option(
        &mut command,
        "plan",
        Some(arguments.required_text("plan_id")?),
    );
    Ok(command)
}

fn build_apply(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let mut command: Vec<String> = vec!["clean".to_owned(), "apply".to_owned()];
    option(
        &mut command,
        "plan",
        Some(arguments.required_text("plan_id")?),
    );
    // The digest takes the place of the question of the terminal: the
    // command refuses a stored plan with a different digest.
    option(
        &mut command,
        "digest",
        Some(arguments.required_text("digest")?),
    );
    command.push("--yes".to_owned());
    // The server applies no `permanent` plan, also one that a terminal
    // prepared, and it is never a transient coordinator.
    command.push("--only-modes=evict,trash".to_owned());
    command.push("--require-agent".to_owned());
    if arguments.flag("no_wait")? {
        command.push("--no-wait".to_owned());
        if arguments.text("timeout")?.is_some() {
            return Err("`timeout` has no effect with `no_wait`".to_owned());
        }
    } else {
        option(&mut command, "timeout", Some(&wait(arguments)?));
    }
    Ok(command)
}

fn build_operations(arguments: &Arguments<'_>) -> Result<Vec<String>, String> {
    let action: &str = arguments.required_text("action")?;
    let mut command: Vec<String> = vec!["operations".to_owned(), action.to_owned()];
    match action {
        "show" => {
            if arguments.text("timeout")?.is_some() {
                return Err("`timeout` applies only to `wait`".to_owned());
            }
        }
        "wait" => option(&mut command, "timeout", Some(&wait(arguments)?)),
        _ => return Err("`action` must be `show` or `wait`".to_owned()),
    }
    option(
        &mut command,
        "operation",
        Some(arguments.required_text("operation_id")?),
    );
    Ok(command)
}

/// The tools of the server. Each is one CLI command.
static TOOLS: [Tool; 8] = [
    Tool {
        name: "disk",
        title: "Disk space",
        description: "Read the free and available space of the volume of the home directory. This tool changes nothing. With `warn_below`, the result has `below_threshold` and a warning text.",
        properties: || json!({"warn_below": text_property("A size such as `20GiB` (units B, KiB, MiB, GiB, TiB). The result tells whether the available capacity is below it.")}),
        required: &[],
        read_only: true,
        destructive: false,
        idempotent: true,
        build: build_disk,
    },
    Tool {
        name: "scan",
        title: "Scan a directory",
        description: "Measure a directory and report where the space goes. This tool changes no user file. With `save`, Svalnir keeps the scan record, and a `trash` plan can use its scan ID.",
        properties: || {
            json!({
                "path": text_property("The absolute path of the directory to scan."),
                "save": flag_property("Keep the scan record for a later report or plan."),
            })
        },
        required: &["path"],
        // `save` writes a scan record of Svalnir.
        read_only: false,
        destructive: false,
        idempotent: false,
        build: build_scan,
    },
    Tool {
        name: "report",
        title: "Capacity report",
        description: "Report a saved scan, and the capacity history of the startup data volume with an estimate of the time to a threshold. This tool changes nothing.",
        properties: || {
            json!({
                "scan": text_property("The ID of a saved scan. Default: the newest saved scan."),
                "window": text_property("The window of the capacity history, for example `24h`; at most `30d`."),
                "threshold": text_property("The available capacity of the estimate, for example `20GiB`."),
            })
        },
        required: &[],
        read_only: true,
        destructive: false,
        idempotent: true,
        build: build_report,
    },
    Tool {
        name: "inspect",
        title: "Inspect a cleanup rule",
        description: "Report what one reviewed cleanup rule finds, the sizes, and why. This tool changes no file. Use it before `plan`, and show the sizes to the user.",
        properties: || {
            json!({
                "rule": text_property("The ID of a reviewed rule with the inspection mode, for example `project.dependency-directory` or `go.build-cache`."),
                "roots": list_property(ROOT_DESCRIPTION),
                "no_mise": flag_property("Do not add the project roots that mise records."),
                "allow_unmarked": flag_property(UNMARKED_DESCRIPTION),
            })
        },
        required: &["rule"],
        read_only: true,
        destructive: false,
        idempotent: true,
        build: build_inspect,
    },
    Tool {
        name: "plan",
        title: "Prepare a cleanup plan",
        description: "Prepare a bounded cleanup plan. This tool changes no file. Mode `evict` removes the candidates of one reviewed rule permanently when the plan is applied; mode `trash` moves named entries of a saved scan to Trash. The result has the targets, the size estimate, the warnings, and `approval` with `plan_id` and `digest`. Show the plan to the user and ask the user to approve it. Call `apply` only after the user approved this plan. This server cannot verify that approval.",
        properties: || {
            json!({
                "mode": {"type": "string", "enum": ["evict", "trash"], "description": "`evict` for one reviewed rule, or `trash` for named entries of a saved scan."},
                "rule": text_property("The reviewed rule of mode `evict`."),
                "scan": text_property("The ID of the saved scan of mode `trash`."),
                "entries": list_property("The exact paths of the entries of the saved scan for mode `trash`. With none, the result lists the candidates and has no plan."),
                "profile": text_property("A selection preset, for example `developer`. It grants no authority."),
                "roots": list_property(ROOT_DESCRIPTION),
                "no_mise": flag_property("Do not add the project roots that mise records."),
                "include_active": flag_property("Also select the projects whose activity state is `active` (rule `project.dependency-directory` only)."),
                "allow_unmarked": flag_property(UNMARKED_DESCRIPTION),
                "min_size": text_property("Leave out each candidate smaller than this size, for example `100MiB` (rule `project.dependency-directory` only)."),
            })
        },
        required: &["mode"],
        read_only: false,
        destructive: false,
        idempotent: false,
        build: build_plan,
    },
    Tool {
        name: "show",
        title: "Show a cleanup plan",
        description: "Explain a prepared plan: the targets, the estimates, the exclusions, the expiry, and the digest. This tool changes nothing. Use it to show a plan to the user again before `apply`.",
        properties: || json!({"plan_id": text_property("The ID of a prepared plan.")}),
        required: &["plan_id"],
        read_only: true,
        destructive: false,
        idempotent: true,
        build: build_show,
    },
    Tool {
        name: "apply",
        title: "Apply a cleanup plan",
        description: "Apply a prepared cleanup plan. A plan of mode `evict` deletes files permanently; a plan of mode `trash` moves them to Trash. Call this tool only after you showed the plan to the user and the user approved this plan. This server cannot verify that approval. Give the `digest` that `plan` or `show` returned: a stored plan with a different digest is refused. The checks of `svalnir clean apply` stay in effect: the lifecycle state of the rule, the protections, the expiry of the plan, and the HOME check. This tool applies only `evict` and `trash` plans, and only a running Svalnir agent executes them: with no agent, the call is refused with `agent_not_running`.",
        properties: || {
            json!({
                "plan_id": text_property("The ID of the approved plan."),
                "digest": text_property("The digest of the approved plan, from `plan` or `show`."),
                "no_wait": flag_property("Return the admission and do not wait for the result."),
                "timeout": text_property(TIMEOUT_DESCRIPTION),
            })
        },
        required: &["plan_id", "digest"],
        read_only: false,
        destructive: true,
        idempotent: false,
        build: build_apply,
    },
    Tool {
        name: "operations",
        title: "Show an operation",
        description: "Show the recorded state of an operation that `apply` admitted, or wait for its result. This tool changes nothing.",
        properties: || {
            json!({
                "action": {"type": "string", "enum": ["show", "wait"], "description": "`show` reads the state; `wait` waits for the result."},
                "operation_id": text_property("The ID of the operation."),
                "timeout": text_property(TIMEOUT_DESCRIPTION),
            })
        },
        required: &["action", "operation_id"],
        read_only: true,
        destructive: false,
        idempotent: true,
        build: build_operations,
    },
];

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Input, MAX_LINE_BYTES, read_bounded_line};

    fn lines(bytes: &[u8], limit: usize) -> Vec<String> {
        let mut reader = Cursor::new(bytes.to_vec());
        let mut out: Vec<String> = Vec::new();
        loop {
            match read_bounded_line(&mut reader, limit).unwrap() {
                Input::Line(line) => out.push(String::from_utf8(line).unwrap()),
                Input::TooLong => out.push("<too long>".to_owned()),
                Input::End => return out,
                Input::Failed(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn a_line_longer_than_the_limit_is_discarded_to_its_end() {
        assert_eq!(
            lines(b"one\n0123456789\ntwo\nlast", 5),
            ["one", "<too long>", "two", "last"]
        );
        assert_eq!(lines(b"0123456789", 5), ["<too long>"]);
        assert_eq!(lines(b"", 5), Vec::<String>::new());
        let long: Vec<u8> = vec![b'a'; MAX_LINE_BYTES + 1];
        assert_eq!(lines(&long, MAX_LINE_BYTES), ["<too long>"]);
    }
}
