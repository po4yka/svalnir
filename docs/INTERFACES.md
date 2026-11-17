# Svalnir Interfaces

**Status:** Design specification. Commands, message shapes, limits, and version numbers below define the proposed first implementation; they are not a shipped API.  
**Interface baseline:** 1  
**Last reviewed:** 2026-11-16

This document connects CLI and GPUI requests to the shared agent and privileged helper. Metric semantics belong to [RESOURCE_MODEL.md](RESOURCE_MODEL.md), decisions to [POLICY_SPEC.md](POLICY_SPEC.md), and execution to [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md). Rule modes belong to [CLEANUP_RULES.md](CLEANUP_RULES.md). [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [VALIDATION.md](VALIDATION.md) define boundaries and required evidence.

## 1. Interface boundaries

| Boundary | Contract |
| --- | --- |
| User → CLI or GPUI | Explain scope, mode, current authority, estimates, and observed outcomes |
| Client → agent | Authenticated typed requests; shared policy and operation state |
| Agent → helper | Narrow delegated steps; independent helper authorization, limits, and journal |
| Collectors → core | Typed observations with source, scope, acquisition window, and quality |
| Agent → clients | Bounded snapshots/events with explicit gaps and reconnect behavior |
| Configuration → effective policy | Validated versioned activation; no implicit authority from file contents |

The first release exposes a local interface. It does not expose a network control server or arbitrary remote shell. Clients never execute a second deletion or signaling path behind the agent.

An unavailable agent produces a visible capability or connection result. A client must not fall back to direct destructive execution. Pure local commands such as help, license, completion generation, and syntactic configuration validation may operate without the agent. Live validation, observations, and mutation authority remain explicitly distinguished.

## 2. Versions and compatibility

Keep these versions independent:

- **IPC protocol major/minor:** connection and method compatibility.
- **JSON `schema_version`:** machine-readable envelope and serialized payload contracts.
- **Configuration `schema_version`:** accepted TOML structure.
- **Policy/grant revisions:** opaque identities for activated authority.
- **Rule revision:** exact immutable behavior selected by a plan.
- **State-store version:** persistence migration compatibility.

The initial proposed IPC major is 1 and JSON schema version is 1. Equal numbers across these systems do not imply compatibility.

A major protocol mismatch rejects normal methods before action admission. Minor additions may introduce optional read fields or negotiated capabilities. Unknown read fields may be ignored; an unknown state, unit, metric kind, or completion enum must remain unsupported/unknown rather than becoming zero, normal, or completed.

Mutation requests reject unknown action classes, authority-bearing fields, incompatible revisions, and unsupported options. Neither client nor helper may silently downgrade a requested protection to fit an older peer.

An existing plan executes its exact rule revision or is invalidated. An update cannot substitute a supposedly compatible new implementation under the old plan identity.

## 3. Scalar, identity, and path encoding

Rust domain types retain checked integer units and distinct identity types. JSON uses:

| Value | Encoding |
| --- | --- |
| Bytes, counters, exact durations, monotonic timestamps, stream sequence | Canonical base-10 strings |
| Signed capacity delta | Signed canonical base-10 string; no negative zero |
| Approximate rates/ratios | Finite JSON numbers, with defined unit and derivation |
| Small schema/protocol versions | JSON integers |
| Boolean setting | JSON boolean |
| Unavailable measurement | `null` plus an explicit reason in its observation |
| Entity, revision, epoch, plan, operation, and step IDs | Opaque strings |
| Wall-clock timestamp | RFC 3339 UTC string, separate from monotonic timing |

Unsigned quantity strings match `0|[1-9][0-9]*`; signed quantities additionally permit a leading minus on a nonzero value. No grouping separators, exponent notation, or implicit units are accepted. Decoding checks the field's numeric range.

This convention avoids relying on consumers preserving arbitrary wide JSON integers; [RFC 8259][json] describes interoperability limits for numeric precision. Do not serialize NaN or infinity. Available zero is a real value and remains distinguishable from unavailable data.

Observation payloads use the canonical `Observation<T>` contract in RESOURCE_MODEL unchanged, including `metric_id`, `scope`, `value`, `unit`, `kind`, `availability`, `reason`, `coverage`, `source`, and `sample`. Freshness is evaluated against the current consumer/policy context, not trusted as an eternal Boolean.

Monotonic timestamps are comparable only under the specified clock domain and boot identity. Collector epochs remain separate. Wall time orders human history; it does not establish qualification, cooldown expiry, or cross-process clock compatibility.

Enumeration values in this document's examples use the spellings of their source specifications: state and effect names from ACTION_CONTRACTS, decision reasons from POLICY_SPEC, and availability reasons from RESOURCE_MODEL. Those specifications mark the spellings as conceptual. The published schema must fix one serialized spelling for each enumeration before the interface is declared stable.

An opaque ID has 1 to 128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, and `-`. A wall-clock timestamp has the `Z` offset and a fraction of zero, three, six, or nine digits, whichever is the smallest exact one; a decoder accepts a fraction of one to nine digits and rejects another offset and a leap second.

Identity evidence uses these encodings. A process ID, a user ID, and a device number are JSON integers. A process start time is microseconds since the Unix epoch as a canonical base-10 string, and an inode number is a canonical base-10 string. A filesystem path in a response is a tagged object: `{"encoding": "utf8", "value": "..."}` for a path that is valid UTF-8, and `{"encoding": "hex", "value": "..."}` with lowercase hexadecimal bytes for another path. A decoder rejects an empty path, a NUL byte, an unknown encoding, and `hex` for bytes that are valid UTF-8.

An opaque target ID resolves to server-held identity evidence. It is not permission to inspect or modify that entity. A client cannot replace the owner, start time, mount generation, or rule scope in an apply request.

For discovery requests that accept a filesystem path, use a tagged UTF-8 path or an explicitly supported byte-preserving encoding. Reject NUL, malformed encoding, and ambiguous competing path representations. Keep an escaped display label separate. Relative CLI paths are resolved against the invocation directory before submission; the agent must not interpret them relative to its own working directory. Execution still revalidates the resolved identity and approved scope.

## 4. CLI structure

Use `clap` derive for typed arguments and generated help, with `clap_complete` for completions. Parsing is separate from domain evaluation and execution. The [clap documentation][clap] defines the library API; pin the actual dependency version during implementation.

The following preserves the README command families and adds operation/configuration inspection needed for recovery:

| Command family | Purpose |
| --- | --- |
| `status`, `memory status`, `swap status` | Current resource, capability, agent, and policy views |
| `scan PATH`, `report --scan ID` | Bounded analysis and scan inspection |
| `clean plan/show/apply` | Prepare, inspect, and apply an immutable removal plan |
| `monitor` | Subscribe to resource and selected operation updates |
| `processes top/show/stop` | Rank, inspect, and control verified application/process targets |
| `operations show/wait/cancel` | Query an admitted operation, await its result, or inhibit future steps |
| `agent install/status/pause/resume/uninstall` | Manage Svalnir's own background lifecycle |
| `policy list/show/enable/disable/simulate/rearm` | Inspect and amend standing behavior and incident allowance |
| `config validate/show/apply` | Validate proposals, inspect effective values, and activate a revision |
| `history`, `doctor` | Bounded historical queries and capability diagnostics |
| `completions SHELL`, `license` | Local completion generation and license/notices |

Optional future namespaces do not appear as functional commands until their adapters are implemented.

### Common options

- `--format text|json|ndjson`: text by default; JSON for snapshots/results; NDJSON only for streaming commands. `completions` accepts only text.
- `--config PATH`: choose a proposal for supported configuration/simulation operations (`config validate`, `config apply`, and `policy simulate`). It never silently activates that file or changes what a status query calls effective.
- `--timeout DURATION`: bound client waiting/transport behavior; not a cancellation guarantee for admitted work.
- `--yes`: permit a plan-bound noninteractive approval where supported; not an override for stale state or exclusions.
- `--no-wait`: return an admitted operation reference instead of waiting for completion, where supported.
- `--color auto|always|never`: affects human output only; machine output never contains ANSI decoration.

Unknown flags and incompatible combinations fail before mutation. A convenience flag must map to a typed contract field; it must not introduce an undocumented bypass.

### Scans and selection presets

Every admitted scan has a scan ID and bounded scope. `--save` retains its catalog under configured limits for later reports/plans; saving metadata does not authorize cleanup. Incomplete, inaccessible, canceled, and stale regions remain visible.

A cleanup selection preset such as `--profile developer` filters candidates. It is separate from the Observe/Balanced/Aggressive operating templates and cannot enable rules or grant authority.

The proposed manual cleanup modes are `trash`, `permanent`, and `evict`, mapping respectively to `MoveToTrash`, `DeleteSelectedFiles`, and rule-based `EvictRegenerableData`. The evict mode requires an exact supported rule selection, given as `--rule RULE_ID`. The policy's `automatic_mode = "permanent"` remains a separate configuration field.

## 5. Manual approval and standing authorization

Preparing or displaying a plan is observational. Applying it requires authorization bound to its immutable ID, digest/identity, mode, target set, expiry, and relevant revisions.

Interactive clients show that scope and the material consequence before recording approval. Noninteractive clients use `--yes` or an existing grant explicitly covering that application mode and scope. The client retrieves the server's immutable plan and binds the approval to it; a bare confirmation flag is not a substitute for the plan.

A standing grant may supply consent only within its defined scope. A guard's automatic incident authority cannot be repurposed into arbitrary manual deletion. Once a standing guard is enabled with its required grants, ordinary eligible incidents proceed without incident-by-incident prompts.

Code signing identifies the connecting executable; it does not prove human intent. A same-user process can invoke the genuine CLI. This interface therefore preserves helper ceilings and the threat model's explicit limitations rather than treating `--yes` as a protected human-consent channel.

`--force` in process control selects an explicit force strategy. It does not mean “ignore protection.” Hard protections, global/manual exclusions, target identity, and helper limits remain effective. Guard-specific automatic settings do not independently prohibit separately authorized manual actions.

The convenience command `processes stop --target ID` performs prepare, inspect/authorize, and apply through the same services. It retains its plan and operation identities through retries. A lost apply reply must never cause it to prepare a second plan and repeat termination automatically.

## 6. Proposed workflows

Uppercase IDs are placeholders for identifiers that Svalnir returns. The examples do not authorize a contributor, an automated agent, or a test runner to run them against a live host.

```sh
svalnir doctor
svalnir status --format json

svalnir scan "$HOME" --save
svalnir report --scan SCAN_ID
svalnir clean plan --scan SCAN_ID --profile developer --mode trash
svalnir clean show --plan PLAN_ID
svalnir clean apply --plan PLAN_ID --yes --no-wait
svalnir operations show --operation OPERATION_ID --format json
svalnir operations wait --operation OPERATION_ID --timeout 30s

svalnir processes show --target TARGET_ID
svalnir processes stop --target TARGET_ID --grace 10s --force-after-timeout
svalnir monitor --format ndjson
```

`--force` and `--force-after-timeout` are mutually exclusive. Grace and verification durations must fit admitted bounds; client waiting does not extend plan expiry. A manually prepared plan stays valid for the configured `manual_plan_ttl` in [POLICY_SPEC.md](POLICY_SPEC.md); after expiry, `clean apply` is rejected and a new plan is necessary.

Configuration and standing-policy changes remain explicit:

```sh
svalnir config validate --config ./config.toml
svalnir config show --effective --format json
svalnir policy simulate disk-guard
svalnir config apply --config ./config.toml --expected-revision POLICY_REVISION
svalnir policy enable disk-guard --accept-permanent-eviction
svalnir policy enable memory-guard --accept-force-quit
svalnir agent pause --for 1h
svalnir agent resume
```

Activation compares the expected revision. An interactive enable flow can fetch and present the current proposal before binding its request; a noninteractive mutation must bind the reviewed revision explicitly. A conflict requires renewed evaluation, not a silent overwrite.

A rearm request identifies the incident and current budget generation (`policy rearm POLICY --incident INCIDENT_ID --generation GENERATION`) and records the newly authorized generation. It does not erase history, bypass cooldowns, or resolve an unknown prior effect.

## 7. JSON response envelope

A normal JSON command emits one UTF-8 JSON value followed by a newline. The envelope is:

| Field | Meaning |
| --- | --- |
| `schema_version` | Machine-output schema major |
| `request_id` | Correlation identity for this invocation |
| `kind` | `snapshot` (resource or state view), `report` (plan, validation, simulation, history, or diagnostic result), `accepted`, `operation`, or `error` |
| `result` | Typed payload, or null when no result is available |
| `error` | Request/command error, otherwise null |
| `warnings` | Bounded structured advisory findings |

A domain operation can have a failed or incomplete outcome inside a successful status-query result. That is different from failure to execute the query.

Illustrative asynchronous admission:

```json
{
  "schema_version": 1,
  "request_id": "request_example_1",
  "kind": "accepted",
  "result": {
    "operation_id": "operation_example_1",
    "plan_id": "plan_example_1",
    "state": "Admitted",
    "dispatch": "not_submitted",
    "durability": "durable"
  },
  "error": null,
  "warnings": []
}
```

This reports state at response construction. It neither promises that dispatch will occur nor that work remains unsubmitted when the client reads it.

Illustrative settled process operation:

```json
{
  "schema_version": 1,
  "request_id": "request_example_2",
  "kind": "operation",
  "result": {
    "operation_id": "operation_example_1",
    "state": "Incomplete",
    "dispatch": "submitted",
    "stop_reason": "TRIGGER_CLEARED",
    "target_results": [
      {
        "target_id": "target_example_1",
        "effect": "StillRunning",
        "attribution": "not_applicable"
      }
    ],
    "resource_effects": []
  },
  "error": null,
  "warnings": []
}
```

Actual payload variants carry the relevant evidence and durability fields required by ACTION_CONTRACTS. These compact examples illustrate envelopes, not a complete JSON Schema.

Structured errors include a stable code, family, stage, safe message, field references where applicable, known operation/plan IDs, and the permitted next action. “Retryable” must distinguish retrying an observation from querying an operation or preparing a new plan after reconciliation.

## 8. Output and exit status

Diagnostics and progress go to stderr. Machine stdout contains no prompts, banners, tables, progress bars, or ANSI escapes. Escape control characters in labels and paths; never allow a filename to inject terminal commands or fake status lines.

Once machine mode is established, request errors use the structured envelope. A parse failure before the output mode can be determined may produce stderr only. Help/version requests complete locally and successfully.

| Exit code | Contract |
| --- | --- |
| `0` | Query succeeded; or waited mutation settled as Completed/NoAction; or explicitly asynchronous admission was accepted |
| `1` | Known operation failure or internal execution failure |
| `2` | Invalid arguments, configuration, or unsupported request shape |
| `3` | Required capability or authorization is unavailable/denied |
| `4` | Requested read scope is partial, or waited operation settled as Partial/Incomplete |
| `5` | Stale/conflicting state, UnknownOutcome, or waiting ended without a conclusive final result |
| `130` | Client interrupted by the user |

Exit 0 from `operations show` means that the query succeeded even if the returned operation failed. Exit 0 from `--no-wait` means admission, not completion. Consumers inspect the result variant and operation state.

A diagnostic query may successfully report denied capabilities. Optional unsupported metrics do not automatically make an otherwise complete request partial; required scope and coverage determine that classification.

For an operation-bearing response, unknown outcome takes precedence over partial completion. Otherwise use the settled domain outcome. For pre-admission failure, use its request/capability/state family. Do not collapse every native error into “permission denied.”

Ctrl+C disconnects the waiting/streaming client. It does not uninstall the agent, disable a guard, or cancel an admitted operation. Explicit operation cancellation has separate acknowledgement semantics.

## 9. Authenticated local protocol

The signed distribution uses local XPC with typed method interfaces and constrained decoded classes. JSON is the public machine-output representation; this document does not require sending arbitrary JSON dictionaries through the privileged boundary.

Authenticate both client and server with supported code-identity mechanisms appropriate to the deployment target. Require the expected product signing identity and permitted role, rather than accepting every executable from a signing team. Bind user/session identity from the live transport using supported platform metadata.

Apple's [NSXPC code-signing requirement API][xpc] requires setup before the connection is resumed. Requirements must come from reviewed product policy, not caller-provided expressions. Exact signing requirements, OS availability, failure behavior, and update compatibility remain native validation gates.

Authentication also protects observation and diagnostic methods carrying privacy-sensitive metadata. A signed client does not gain arbitrary file reads, cross-user inventory, or unrestricted history export.

### Handshake

Before normal requests, exchange the supported protocol range, required capabilities, and role. An accepted handshake returns:

- Selected protocol version and output schema capabilities.
- Agent/executor epoch and supported method/action classes.
- Applicable limits and whether required components are available.
- Rule-registry identity and policy-view revision where authorized.
- Stream/replay capabilities and their finite retention limits.

A capability declaration says that a method is supported; it is not a grant for a target. Clients still handle access denial and runtime degradation.

### Typed method families

| Family | Representative operations | Required boundary |
| --- | --- | --- |
| Resources | Snapshot, bounded process listing, scan start/status/page | Principal, scope, privacy, and resource limits |
| Planning | Prepare cleanup/application plan; inspect plan | Observation only; exact identities and supported modes |
| Execution | Apply plan; query/wait/cancel operation | Plan-bound authority and action contracts |
| Policy | Validate proposal; inspect/activate revision; simulate | Validation separated from activation and grant changes |
| Authorization | Establish/revoke supported scopes; inspect applicable grants | Correct user or administrative authority |
| Control | Pause/resume guard; explicitly rearm incident | Scoped state change with acknowledgement durability |
| Events | Snapshot-and-subscribe; resume or resynchronize | Authorized filter, bounded retention, continuity contract |
| Diagnostics | Probe component/resource capabilities | Actual worker identity; no unrestricted read endpoint |

These families guide the eventual IDL; they do not define a JSON-RPC or HTTP API.

### Proposed protocol limits

Version 1 begins with explicit reviewable guardrails:

| Limit | Proposed ceiling |
| --- | --- |
| Encoded request or individual response/event | 1 MiB |
| Nested decoded containers | 16 levels |
| Page entries | 128 |
| Explicit target references in one request | 128 |
| In-flight ordinary requests | 8 per connection; 32 per principal |
| Active subscriptions | 8 per principal |
| Buffered subscription data | 1,024 events or 4 MiB, whichever is reached first |

Decoded allocations, total clients, per-field lengths, scan concurrency, aggregate buffers, and helper concurrency also require finite release limits. The handshake advertises effective limits, bounded by compiled/server policy; clients cannot request an unlimited value.

Paginate or reject an oversized response instead of bypassing limits. Rate-limit repeated malformed requests and expensive diagnostics. Reserve control capacity so a full observation queue does not indefinitely prevent cancellation or revocation. Admission must fail before an effect if its required bounded state cannot be retained.

## 10. Helper boundary

The helper receives a supported delegated step with its parent operation, authenticated principal, exact action type, grant generation, resource scope, target evidence, deadline, and deduplication identity.

It independently resolves and validates the authority-bearing parts. Agent-supplied paths, measured pressure, rule labels, approval flags, catalog rows, and budget claims cannot widen a `PrivilegeGrant`.

No method accepts arbitrary shell text, script bodies, caller-chosen executables, unrestricted root paths, or an untrusted database as authoritative state. A denied user-level operation is not automatically retried as root.

Helper replies identify the delegated step, observed state, recording durability, native result/evidence, and remaining uncertainty. If the reply is lost, the agent queries that step's status. A new transport request ID does not make its external effect executable again.

Administrative enrollment/expansion is a distinct reviewed flow bound to concrete scopes and OS-backed authorization. Credentials and transient authorization material are not placed in user configuration, journals, or diagnostics.

Service installation/removal uses Svalnir's own supported registration path. It is not an arbitrary launchd editor. Client-local diagnostics can explain a missing agent, but cannot assert that a non-running worker successfully passed its resource-access probes.

## 11. Snapshots, pagination, and subscriptions

### Snapshot meaning

A snapshot is a consistent view of agent-published state at a publication boundary. It is not a simultaneous kernel-wide measurement. Individual observations retain their acquisition windows, sample IDs, scopes, and quality.

A paginated view binds its cursor to principal, filter, ordering, snapshot identity, and expiry. Pages cannot silently combine different snapshots. If retained state expires or cannot fit limits, return an explicit resnapshot requirement.

Process/file membership can change while a snapshot is displayed. A snapshot target remains subject to execution-time identity validation. Sorting by an unavailable metric must keep unavailable values distinguishable rather than ranking them as zero.

### Snapshot and stream continuity

The preferred subscription operation establishes a publication barrier and returns an initial snapshot followed by selected updates after that barrier. Register the subscription and capture the view consistently so no published update falls between an unrelated snapshot call and stream attachment.

An initial baseline must fit the advertised limits or use pages bound to the same snapshot identity and publication barrier. Clients assemble the complete baseline before applying subsequent deltas. Buffered updates remain bounded; baseline expiry or overflow invalidates bootstrap and requires resynchronization. A server may reject an oversized unfiltered subscription rather than allocate unbounded buffering.

Within a stream epoch, each emitted event has an exact monotonically increasing sequence. Filtering occurs before assigning that stream's sequence. A filtered-out unrelated publication is therefore not a missing event. Native observation sample IDs and timestamps are separate from delivery sequence.

The first snapshot establishes the baseline. Updates are applied only to that baseline and declared resource identities. A replacement snapshot or new stream epoch invalidates assumptions based on the previous sequence.

The conceptual NDJSON event envelope contains `schema_version`, `stream_id`, `stream_epoch`, `sequence`, `event_type`, `data`, and an optional opaque resume token. Event types include snapshot, observation update, operation update, capability change, gap, heartbeat, and terminal stream error.

Each line is one complete JSON object. Heartbeats establish connection liveness, not fresh resource evidence.

### Backpressure and gaps

Bound every subscription buffer. Coalescing before sequence assignment may publish the latest observation while retaining its real sample identity. Dropping already sequenced updates requires a gap indication identifying the lost interval.

After a gap, clients must resynchronize before treating deltas as a complete view. If congestion prevents delivery of a gap marker, close/invalidate the stream so reconnection requires a new snapshot. Silent loss is not acceptable.

Resume tokens bind the authorized principal, filter, stream context, and retained position. They confer no independent authority. Resume only when contiguous retained history is available; otherwise return a resnapshot requirement. A disconnected client must never assume continuity merely because it reconnects quickly.

Operation notifications may be missed; durable operation status is queried by operation ID. Telemetry history is reconstructible and may be shed. Neither a stream gap nor a missing notification permits mutation replay.

## 12. Request identity, deadlines, and retry

`request_id` correlates a transport exchange. `PlanId`, `OperationId`, and `StepId` identify domain work and deduplication boundaries. They are not interchangeable.

A duplicate apply of the same valid plan returns its admitted operation or known rejection. Different content under an existing operation/step identity is rejected. Consumption retention covers request validity; expired historical IDs are never accepted as fresh instructions.

On a lost reply:

1. Preserve the original plan/operation/step reference.
2. Reconnect and authenticate.
3. Query existing state or repeat the deduplicated request under its documented contract.
4. Reconcile uncertainty before any conflicting new plan is admitted.

Read-only requests may retry with bounded backoff. Mutation retries must not be driven by a generic HTTP-style retry wrapper or by “no response means not executed.”

Client deadlines, plan expiry, executor admission deadlines, grace periods, and outcome-observation windows have different meanings. The server enforces its own bounds; a client cannot extend them by reconnecting. A client timeout reports known IDs and uncertainty without claiming cancellation.

Explicit cancellation is scoped to an operation. Its acknowledgement distinguishes request receipt, an effective current-instance stop, a durable stop fence, and a settled result. Canceling after a submitted effect may produce Partial, Incomplete, or UnknownOutcome; it does not rewrite history as NoAction.

## 13. Configuration and control acknowledgements

`config validate` separates syntax/schema validation from live resolution of rules, worker capabilities, and target identities. It reports which checks ran and which require the agent or supported platform. A portable parser pass must not be presented as live native eligibility.

`config show --effective` reports resolved values, their template/override provenance, active revision, and pending/degraded capabilities. Selecting `--config` for a simulation labels the proposed policy; it does not replace the active revision.

Activation and grant changes use expected revisions and typed scope differences. Policy and helper storage do not form one atomic transaction. If required helper approval is pending, the response identifies the blocked subset rather than claiming a completed privilege expansion.

Control responses make acknowledgement durability explicit:

| Acknowledgement | Meaning |
| --- | --- |
| Validated proposal | Input was checked; active behavior did not change |
| Durably activated/revoked | Required authoritative state persisted before success |
| Current-instance inhibition | Dispatch is inhibited now, but persistence failed or was unavailable |
| Operation admitted | Work has an identity and reservations; no completion promise |
| Operation settled | Outcome is recorded with its actual durability and evidence |

A failed durable pause/revoke still inhibits current-instance work where possible. Return the persistence failure together with that limited effect; do not print a success message implying restart persistence.

An agent restart, configuration reload, or reconnect does not reset an incident budget. Rearm is an explicit authorized state transition and retains previous usage history.

## 14. GPUI parity and presentation

GPUI consumes the same authenticated services and typed outcomes as the CLI. It may cache view state but cannot own a different policy engine, grant interpretation, or mutation implementation. [DESIGN.md](../DESIGN.md) specifies the visual language that applies these requirements.

The application must:

- Keep scans, IPC waits, and native work off the rendering thread.
- Show stale/unavailable/partial measurements without converting them into empty charts or zero.
- Label physical footprint, RSS, compression, swap, and disk estimates with their actual semantics.
- Retain plan/operation IDs across navigation, reconnect, and window closure.
- Invalidate an approval view when its scope, revision, or expiry is no longer current.
- Show force escalation, partial effects, unknown outcomes, and volatile history explicitly.
- Distinguish pausing automation, canceling one operation, and closing a client window.
- Support keyboard navigation, accessible labels, focus recovery, and readable status/error states.

A disabled button is explanatory UI, not an authorization boundary. Server-side validation remains mandatory when an action is invoked through another client.

No screen may label an accepted request as reclaimed capacity or verified termination. Progress animation must not imply that an operation can be undone.

## 15. Privacy and diagnostics

Keep ordinary output and logs free of credentials, process environments, raw argument lists, file contents, and transient authorization material. Target names and paths can still be sensitive metadata.

History/export requests carry bounded scope and principal checks. A diagnostic export is a deliberate, reviewable local action with redaction and size limits. It is not an automatic upload. Exported IDs and redacted labels must preserve enough structure to explain outcomes without becoming reusable authorization tokens.

Error messages avoid copying entire hostile payloads or leaking another user's state. Human rendering escapes terminal controls; JSON strings use proper encoding. Resource identifiers, file paths, and localized labels remain separate fields.

Production endpoints do not accept synthetic pressure, injected identities, debug authorization bypasses, or executable cleanup rules. Validation harnesses belong to explicitly isolated test artifacts, with their differences recorded as required by VALIDATION.

## 16. Contract validation and release readiness

Before treating this interface as stable, validation must establish:

- Parser/help/completion behavior and CLI/GPUI mapping to the same service calls.
- Exact quantity round trips, unavailable states, unknown enums, and bounded decoding.
- Distinct query success, admission, domain completion, and exit-code semantics.
- Exact-plan approval and no widening through flags, revisions, or retries.
- Peer/principal/role isolation, including genuine CLI invocation by a same-user attacker.
- Snapshot-stream barriers, overflow, gap recovery, cursor expiry, and old-epoch rejection.
- Pause/revoke acknowledgement durability and restart behavior.
- Privacy, accessibility, signed installation, update compatibility, and headless operation.

Test actual artifacts and supported OS combinations. A successful pure serialization check does not validate XPC identity, native measurements, deletion, or signaling.

The implementation must publish complete request/response schemas, finite effective limits, compatibility policy, and evidence for the methods it enables.

## References

- [clap: Derive, validation, help, and command APIs][clap]
- [RFC 8259: JSON interoperability][json]
- [Apple: NSXPC peer code-signing requirements][xpc]

[clap]: https://docs.rs/clap/latest/clap/
[json]: https://www.rfc-editor.org/rfc/rfc8259
[xpc]: https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)
