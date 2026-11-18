# Svalnir Interfaces

**Status:** Design specification. Commands, message shapes, limits, and version numbers below define the proposed first implementation; they are not a shipped API. The current build implements the subset that section 4 names in "Milestone 1 in-process build" and "Milestone 2 build without a socket". It has no local protocol: sections 9 to 11 are planned behavior.  
**Interface baseline:** 1  
**Last reviewed:** 2026-11-17

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

The initial proposed IPC major is 1 and JSON schema version is 1. Equal numbers across these systems do not imply compatibility. The schema version of a sealed plan and of a request envelope is a separate number, which `docs/ACTION_CONTRACTS.md` section 3 owns; it is 2. A stored plan of an earlier plan schema version is refused and is not migrated.

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

Enumeration values in this document's examples use the spellings of their source specifications: state and effect names from ACTION_CONTRACTS, decision reasons from POLICY_SPEC, and availability reasons from RESOURCE_MODEL. ACTION_CONTRACTS fixes the serialized spellings of its enumerations: action classes, states, and effects have the names of that specification; dispatch state, durability, attribution, trigger class, force strategy, recording mode, error family, and permitted next step are lower-case snake case; a stop reason is upper-case snake case. CLEANUP_RULES fixes the spellings of its modes, lifecycle states, and evidence values. POLICY_SPEC and RESOURCE_MODEL mark their spellings as conceptual. The published schema must fix one serialized spelling for each enumeration before the interface is declared stable.

A reader keeps an enumeration value that it does not recognize as an explicit unrecognized value. It never reads that value as completed, normal, eligible, or zero. A record that needs a recognized value to be executable, such as a plan or a request envelope, is rejected.

An opaque ID has 1 to 128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, and `-`. A wall-clock timestamp has the `Z` offset and a fraction of zero, three, six, or nine digits, whichever is the smallest exact one; a decoder accepts a fraction of one to nine digits and rejects another offset and a leap second.

Identity evidence uses these encodings. A process ID, a user ID, and a device number are JSON integers. A process start time is microseconds since the Unix epoch as a canonical base-10 string, and an inode number is a canonical base-10 string. A filesystem path in a response is a tagged object: `{"encoding": "utf8", "value": "..."}` for a path that is valid UTF-8, and `{"encoding": "hex", "value": "..."}` with lowercase hexadecimal bytes for another path. A decoder rejects an empty path, a NUL byte, an unknown encoding, a field other than `encoding` and `value`, and `hex` for bytes that are valid UTF-8.

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
| `operations show/wait/cancel/acknowledge` | Query an admitted operation, await its result, inhibit future steps, or acknowledge an unknown outcome |
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

### Milestone 1 in-process build

The read-only commands have no local protocol behind them. The CLI links the agent library and runs each read-only command in its own process. The decisions in this subsection apply to the builds with no local protocol. A build with the protocol of section 9 replaces them.

| Subject | Decision |
| --- | --- |
| Commands that run | `status`, `memory status`, `swap status`, `monitor`, `processes top`, `processes show`, `scan`, `report`, `doctor`, `config validate`, `config show`, `policy list`, `policy show`, `policy simulate`, `completions`, and `license` |
| Commands that change state | See "Milestone 2 build without a socket". On a platform other than macOS, a command whose executor exists only for macOS reports `not_implemented` or `unsupported_platform` (exit `3`, no change) |
| Response `kind` | `snapshot` for `status`, `memory status`, `swap status`, `processes top`, `processes show`, and `scan`. `report` for `report`, `doctor`, `config validate`, `config show`, `policy list`, `policy show`, `policy simulate`, and `license` |
| State directory | `~/Library/Application Support/Svalnir/`. The environment variable `SVALNIR_STATE_DIR` replaces it with an absolute path; a value that is not absolute is a request error. Among the read-only commands, only `scan --save` creates the directory, with mode `0700`. "Milestone 2 build without a socket" names the other commands that create it |
| Catalog store | `catalog.sqlite` in the state directory holds the saved scan records. `scan --save` applies the `[history]` limits of the configuration template, because no effective revision exists. The `save` field of the result is `not_requested`, `saved`, `not_saved_interrupted`, or `removed_by_retention` |
| Configuration proposal | The file of `--config PATH`, or `config.toml` in the state directory. `config validate` needs a file. `config show`, `policy list`, `policy show`, and `policy simulate` use the built-in template when the default file does not exist, and the result names that source |
| `config show --effective` | The values of the revision in effect, from the operation journal, with `active` true and the revision record. With no revision in effect: the error `no_active_policy_revision`, exit `3` |
| Target ID | The process generation identity `pg-<pid>-<start time in microseconds>`. No server holds identity evidence, so each invocation resolves the ID against a new snapshot. A target that is not in the snapshot gives `target_not_found`, exit `5`. The ID is never permission to act |
| `processes top` | `--limit` has the default 20. `--sort growth` and `--sort cpu` compare two snapshots that are 1 second apart. The inventory has only the processes of the current user |
| `processes show` | The policy eligibility is not evaluated, and the result says so |
| `monitor` | `--interval DURATION` from 1 second to 1 hour, with the default 2 seconds. The formats are `text` and `ndjson`. The event types are `snapshot` for the first event and `observation_update` for each later event. `stream_id` is the request identity, and `stream_epoch` is the collector epoch. A collection failure gives one last event of the type `stream_error`, whose `data` is the structured error, and the exit status of the error family. The stream has no resume token, heartbeat, or gap event |
| `report` | Exit `0` when the record is read, also for a record with partial coverage; the coverage is in the result. A scan ID with no record gives `scan_not_found`, exit `5` |
| `policy simulate` | The grants are none, with the basis `recorded`. Only the `startup-data` selector is resolved. The snapshot has no cleanup candidate, because no rule registry exists. The product protection of each application comes from the catalog of hard protections in [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 8, with the CLI process and its ancestors as the control plane. No grant exists, so no action is admissible |
| Partial scope (exit `4`) | A required observation of the command has no value, a process identity query failed for a cause other than denial, or the coverage of the scan is partial. `status`, `memory status`, `swap status`, and `processes top` give `coverage.required_scope` and `coverage.missing_required`. `scan` gives `scan.coverage` and the list of regions |
| `--timeout` | It bounds the client wait of `clean apply`, `processes stop`, `operations wait`, `operations acknowledge`, and `policy rearm`. It has no effect on each other command, whose result has the warning `timeout_not_applied`: in `warnings` of the envelope, or on stderr for the text format and for `monitor`. An error response keeps it: in `warnings` of the error envelope, or on stderr before the error |
| Target ID | `processes show --target` accepts the form `pg-DIGITS-DIGITS` that `processes top` prints. Other text is an invalid argument (exit `2`) |
| Configuration file | The path must be a regular file. A directory, a FIFO, or a device is an invalid argument (exit `2`) |
| Save state | The scan result has `save` with one of `not_requested`, `saved`, `saved_readback_failed`, or `not_saved`. `save_detail` gives the reason for the last two |
| Interrupt | Ctrl+C ends `monitor` and `scan` with exit `130`, also when the reader of a pipe closes at the same time. An interrupted scan writes its partial result and does not save it. Ctrl+C ends each other command at once |

The error codes of this build and their families are:

| Family | Exit | Codes |
| --- | --- | --- |
| `request` | `2` | `invalid_arguments`, `unsupported_format`, `unsupported_rule_selection`, `invalid_state_directory`, `invocation_directory_unavailable`, `invalid_target`, `invalid_scan_id`, `invalid_scan_root`, `scan_root_not_found`, `config_not_found`, `invalid_configuration` |
| `evidence` | `5` | `target_not_found`, `scan_not_found` |
| `recording` | `1` | `state_directory_not_writable`, `state_store_unavailable`, `scan_record_not_encoded`, `scan_record_unreadable` |
| `native` | `3` | `not_implemented`, `collector_unavailable`, `unsupported_platform`, `state_directory_unavailable`, `scan_root_unavailable`, `scan_identity_unavailable`, `config_unreadable`, `simulation_input_too_large` |

`config validate` writes its report and then ends with exit `2` when the document is not valid. That response has `kind` `report` and no `error`.

### Milestone 2 build without a socket

The Milestone 2 build has no socket and no XPC service. A client and the agent share the operation journal `operations.sqlite` in the state directory. The decisions in this subsection apply to this build only. A build with the protocol of section 9 replaces them. The journal is same-user state: the principal of a request is a record, not an authentication.

| Subject | Decision |
| --- | --- |
| Executor of a request | The process that holds the coordinator lock of the journal. When an agent holds the lock, the client writes the request to the request queue of the journal and reads the result by its identity. When no process holds the lock, the client takes the lock and executes the request with the same coordinator code: a transient coordinator. A transient coordinator evaluates no guard and makes no automatic plan. The result names the executor as `transient_coordinator` or `queued_for_coordinator` |
| Authority record of a transient coordinator | The client reads the authority record before the approval question, and a different client can change the record while the question waits. A transient coordinator reads the record again when it holds the coordinator lock, before the admission, and before each step. A record that is absent or has a different user gives no authority. The coordinator runs no step while a read of the record fails. A record that cannot be read for 2 seconds gives no authority until a read has a result: each later step is refused |
| Lifetime of a transient coordinator | The client process is the executor of its operation. It continues to the end of the operation also after the client wait ended (`--no-wait`, `--timeout`, or Ctrl+C), and it exits after that. The response is complete and flushed before the remaining work, and a response that cannot be written does not stop the work. From the admission on, Ctrl+C does not end the process. A step of the coordinator also serves the request queue, so the process then executes each request that it claimed before it exits. The end of a wait cancels nothing |
| Policy revision of a manual plan | A manual plan binds the policy revision in effect, so `clean plan` and `processes stop` need one. With none: the error `no_active_policy_revision`, exit `3`. `config apply --config PATH` makes one; the command needs a file, and a file with the text of the built-in template is sufficient |
| `config apply` | `--expected-revision none` expects that no revision is in effect. The new revision has an identity that the client makes. The client records the configuration text of the revision in the journal and then writes the authority record with a compare-and-set on its record revision. An activation makes no grant |
| `policy enable` | `--accept-permanent-eviction` accepts `EvictRegenerableData`. `--accept-force-quit` accepts `RequestApplicationExit` and `ForceApplicationExit`. `policy enable memory-guard` with no flag accepts `RequestApplicationExit`. The accepted classes must be exactly those of the guard in the revision in effect, else `acceptance_mismatch`, exit `3`. Each enable request names the revision that the user reviewed, and the grant logic refuses a request that names none. With no `--expected-revision`, an interactive session answers a question that names the revision in effect, and the request binds that revision; a revision that became active while the question waited is not bound, and the command reports `authority_record_changed`, exit `5`. A session with no terminal gets `reviewed_revision_required`, exit `3` |
| `policy rearm` | The budget generation is state of the controller of the agent. When an agent holds the coordinator lock, the client writes a rearm request to the queue of the journal and waits for its completion (`--timeout`, else 30 seconds; then `rearm_pending`). The agent checks the request against the authority record of its tick and its controller record: the standing of the guard, the pause (a retained pause included), the generation, and the condition of the incident. It records the new generation in its controller record and completes the request with the previous and the new generation; when the journal does not take the controller record, the earlier record stays, and the request is rejected with `rearm_not_recorded`. A refusal of the standing has the code of the authorization, for example `guard_disabled`, `action_grant_revoked`, `action_grant_missing`, or `automation_paused` (`authority`, exit `3`). When no agent holds the lock, the command is refused with `agent_not_running`, exit `5`, and makes no state directory, no journal, and no request; a coordinator of a client that claims a rearm request rejects it with the same code |
| Control acknowledgement | Each result of `config apply`, `policy enable`, `policy disable`, `agent pause`, and `agent resume` has `acknowledgement` (`durably_applied`), `durable`, `record_changed`, and `coordinator` (`running`, `not_running`, or `unknown`). A change that the journal did not take is an error and is not in effect: a client has no running instance that it can inhibit, so it reports no `current_instance_inhibition`. A concurrent change of the record gives `authority_record_changed`, exit `5` |
| Candidates of `clean plan` | For the `trash` and `permanent` modes: the entries that the saved scan record names, which are its largest files and its largest directories below the scan root. Each entry is measured again; an entry that is absent, is a different object than at the scan, or has an unsupported type is in `stale_entries` and not in the plan. The scan root is the cleanup root and is never a target. The path `/` cannot be a cleanup root: the command refuses it with `plan_not_buildable` before it reads a candidate. An entry below a selected directory is left out with the reason `overlaps_selected_entry` |
| `--profile` | This build defines no selection preset: `selection_preset_not_available`, exit `3` |
| `--mode evict` | An unknown rule gives `unknown_rule`, exit `2`. Each reviewed rule is in the `proposed` lifecycle state, so each known rule gives `rule_mode_not_validated`, exit `3` |
| File protection of a manual plan | The hard protection of a file entry comes from the catalog of protected file locations of `svalnir-core` (`docs/CLEANUP_RULES.md` section 5): storage of the operating system, swap storage, the state directory of Svalnir, and the home directory with each directory that contains it. The client gives the catalog the home directory and the state directory with their symbolic links resolved, and two forms of the path of the entry: the directory of the entry with its symbolic links resolved plus the name of the entry, and the entry with each symbolic link resolved. The entry is protected when one form is protected, so a symbolic link in a protected location is protected, and so is a symbolic link whose target is a protected location, for example a link at the configured path of the state directory. An entry that does not resolve has an unknown protection. A state directory that does not resolve is not given, and an entry that no other rule protects has an unknown protection; an entry whose protection is not known is left out. The plan builder applies the `[protections]` table, and the filesystem executor refuses the home directory, its ancestors, and the cleanup root again |
| Plan document | The journal stores the sealed plan. The client keeps the size estimates, the entries that were left out, the record of each cleanup root with its volume, the operation identity, and the measurements of the operation in `plans/plan-PLAN_ID.json` of the state directory, with mode `0600`. A document gives no authority and gives the executor no cleanup root: the coordinator takes the approved roots of a manual operation from the sealed plan. The identity of a cleanup root is a digest of its path, its device and inode, its volume, and its mount generation, and the sealed plan binds that identity, the root path, and the device and inode of the root for each file target. A document is used only when its digest and its plan are those of the stored plan, its roots are exactly the roots that the file targets of the plan bind, each root has the path and the object that the sealed plan binds for it, and each root has the identity that its values give. The display path of a file target, in a plan view and in each result, is the root path and the relative entry that the plan binds, and `cleanup_roots` has the root paths that the plan binds; a client with no document has them also. The estimates, the work totals, and the paths of the entries that were left out are display data of the document with no check. The volumes of the capacity observations of a transient coordinator come from the sealed plan also: the client reads the volume at each root path that the plan binds and uses it only when its volume identity and its mount generation are those of the binding. The result of `clean plan` and `clean show` has `cleanup_roots` and `plan_document` (`used`, `absent`, `not_readable`, or `disagrees_with_plan`). A document that cannot be read or does not agree is not used and is not an error of `clean show`, of `operations show`, of `history`, or of the report of a plan that was applied before. `clean apply` of a plan with no document asks its question with each path and no estimate, and applies the plan. `clean apply` with a document that is present and not used reports `plan_document_not_usable`, exit `5`. A document is removed after 7 days |
| Approval | `clean apply` and `processes stop` ask one question on stderr that has the scope and the consequence of the plan: each target, with no limit on the length of the list, and each cleanup root. Only the answers `y` and `yes` approve. A session with no terminal needs `--yes`, else `approval_required`, exit `3`; a refusal gives `approval_declined`, exit `3`. An expired plan is refused before the question, with `plan_expired`, exit `5`. The approval names the plan identity and the digest of the stored plan |
| Duplicate apply | A second `clean apply` of a plan reports its operation with `existing_operation` true and `kind` `operation`, and makes no second operation. The journal has at most one operation for a plan. `wait` is `finished` for an operation that is settled or has an unknown outcome; for each other operation it is `not_waited`, and the command does not wait. The exit status is that of the operation, which is `5` for `not_waited`; with `--no-wait`, an operation in the `Admitted` state gives `0` |
| `--no-wait` | The response has `kind` `accepted` with `operation_id`, `plan_id`, `state`, `dispatch`, `durability`, `acknowledgement` (`operation_admitted` or `request_queued`), `executor`, and `request_id`. A queued request waits at most 10 seconds, or the `--timeout` value, for its admission; after that the state is `queued` and `operation_id` is null |
| Waited result | `kind` `operation`. `wait` is `finished`, `timed_out`, `interrupted`, or, for `operations wait`, `no_coordinator`. The exit status is that of section 8 for `finished`, `130` for `interrupted`, and `5` for the others. A result that cannot be written keeps this status: a closed pipe is silent, and each other write error has a diagnostic on stderr. A wait reads a busy journal again. A read that fails after the admission gives `operation_record_unavailable`, exit `5`, with the plan and the operation; a read that fails in `operations wait` gives the journal error with the operation |
| `processes stop` | The target ID names one process generation, and the plan has that one process and no other. A process with a verified membership in an application or a managed job is the only member of an application target. A process with no application or job evidence, for example a process that a shell started, is a target of one process (`docs/ACTION_CONTRACTS.md` section 3): the executor checks its identity evidence again and sends one signal to its process ID. A process with an association that this build does not recognize gives `target_not_eligible` with the reason `membership_not_verified`, exit `3`. `--grace` has the default 10 seconds and the maximum 5 minutes. With no force option, the grace period is the time in which the exit is observed. A stop record `plans/stop-TARGET_ID.json` binds the process generation to its plan, its strategy, its grace period, and its observation time. A repeated request with the same values reports the plan and the operation of the first one. A request with different values makes a new plan only when the earlier operation is settled, for example a force quit after a graceful request that the process ignored; else it gives `stop_plan_exists`, exit `5`. A stop record or a plan that cannot be read permits no new plan. A lock file `plans/stop-TARGET_ID.lock` makes two requests for one process generation make one plan; a lock file is not removed with the old documents. The wait for the lock is bounded by `--timeout`, or by 10 s when the option is absent; after that time the command gives `plan_document_unavailable` and no plan. The wait for the operation has its own time of `--timeout` after the lock |
| `operations cancel` | The client writes the stop fence of the operation in the journal. `acknowledgement` is `durable_stop_fence`, or `settled` when the operation has its final record. A client reports no `received` and no `current_instance` level. A fence that was not written is an error |
| `operations acknowledge` | The command is accepted only for an operation in `UnknownOutcome`. When an agent holds the coordinator lock, the client writes the request to the queue of the journal and waits for its completion (`--timeout`, else 30 seconds; then `acknowledgment_pending`). When no process holds the lock, the client reconciles the operations of an earlier lifetime as a transient coordinator and records the acknowledgment. The result has `acknowledged_at`, `repeated` (true for a repeated acknowledgment, which changes nothing), `executor`, and the operation, whose state stays `UnknownOutcome`. The acknowledgment releases the leases of the operation ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12). `operations show` and `history` give `acknowledged_at` for an acknowledged operation |
| `operations wait` | The client reads the journal until the operation is settled or has an unknown outcome. When no process holds the coordinator lock and the operation is not settled, the wait ends at once with `no_coordinator`, exit `5` |
| Measurements | The coordinator records the resource observations of a durable operation in the journal (table `operation_effect`), so `operations show`, `history`, and the result of a queued request have `resource_effects` for an operation that a different process executed. The record has the observations only. The work totals (`work`) are known to the process that executed the operation, which keeps them in its plan document; for each other client `work` is null. A volatile operation has no record. With no record that the client can read and no document, `resource_effects` is null and a note says so: a value that is not in the view is not a measurement of no change |
| `history` | `--limit` has the default 20 and the maximum 200. Each record has the target results by effect (`moved_to_trash`, `permanently_removed`, `exit_verified`, and the others), the estimate of the plan, the work that the executor measured, and the capacity observations, as separate fields |
| `status` | `agent.state` is `running`, `client_coordinator`, `not_running`, or `unknown`. `policies.state` is `none_active`, `active`, `paused`, or `unknown`, with the authority view. `latest_intervention` is the newest record of `history`, or null |
| `agent status` | `kind` `snapshot`. `coordinator` and `lock_holder` (`agent`, `client`, or `none`) come from the coordinator lock; the status record of the agent is not evidence that a process runs. The command makes no state directory, no journal, and no lock file |
| Coordinator lock | The holder of the lock writes its role (`agent` or `client`) in the lock file and clears it at its end; each other content is read as `client`. A query reads the state of the lock and does not take it. An agent that finds the lock of an agent exits with status `0`. An agent that finds the lock of a client exits with status `1`, so that the service manager starts it again after the client released the lock |
| Stop of the agent | At a stop signal the agent claims no further request of the queue, sets the stop of each operation that it executes, and ends each of them before its next step; a request that it did not claim stays in the queue for the next coordinator. An operation that cannot be settled keeps the registration of the coordinator, and the stop is then recorded as not clean. An agent whose service ended before a stop signal exits with status `1` |
| State directory of the agent | The agent makes the state directory with mode `0700` when it does not exist. It refuses a state directory that is a symbolic link, that is not a directory, that a different user owns, or that has a permission bit for the group or for other users, and exits with status `1` and no change |
| Journal versions | The journal has version 4 and no migration. A build makes the schema in a new journal. It refuses a journal of an earlier version with `journal_older_version` and a journal of a later version with `journal_newer_version`, and it changes neither file. A plan and a request envelope have schema version 2, and a stored plan of schema version 1 is not read (section 2) |
| Automatic plan from a client | An automatic plan is admitted only with the incident allowance of the controller of the agent ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 4). A request of the queue for an automatic plan, and an apply of a stored automatic plan by a client, are refused with `incident_allowance_missing` |
| Stop inside a directory target | A stop of an operation (a cancel, a pause, a changed revision or grant, or the stop of the agent) is also read between the entries of a directory target. The target then has `UnknownOutcome` with the stop reason, and the entries that were removed stay removed ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |
| Journal retention and open incidents | The journal has one usage row for each budget generation of an incident (table `incident_usage`), which the consumption of each dispatch of that generation changes in its transaction; the operation row has the generation that its plan binds. The retention of the agent removes the settled operations of an open incident and keeps each of its usage rows: the agent names the open incidents of its controller record to the prune. The usage rows of an incident that is not open go together when its latest operation is older than the retention cutoff. A restart reads the usage row of the current generation, so the budget of an open incident survives a prune and a restart, and a rearm before the restart gives the new generation its own allowance ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12) |
| Control changes between two reads of the agent | The agent reads the authority record one time for each tick. When the revision counter of the record shows a state that the agent did not read, for example a pause and its resume inside one tick, or when the read before this one failed, the agent takes the time of that tick as a measurement floor: a sample from before it supports no automatic action. The controller and the authorization use one rule for the floor (the latest of the durable resume floor of the record, of the resume of the instance, and of each expired pause, in the current boot and clock domain) |
| Durable resume floor | `agent resume` of a record with a pause writes `resume_floor` in the authority record: the monotonic time of the resume with its boot and clock domain. An agent that did not run at the resume, or that did not see the resume, reads it with the record, so a sample from before the resume supports no automatic action. The record has strict decoding and no version. A record of an earlier format, with no `resume_floor`, gives no authority: each command that reads it reports `authority_record_not_readable`, exit `1`, and the agent only observes. This build has no command that replaces such a record: the user stops the agent and removes the operation journal `operations.sqlite` of the state directory, and then activates a configuration and enables each guard again |
| `agent install`, `agent uninstall` | `--yes`, or a question in an interactive session. The service is a per-user `LaunchAgent` with the label `dev.svalnir.agent`, whose definition is `~/Library/LaunchAgents/dev.svalnir.agent.plist`. The program is the `svalnir-agent` executable beside the `svalnir` executable, as a path with no symbolic link; with none, `agent_program_not_found`, exit `3`. The executable and its directory must have this user or the superuser as owner and no write permission for the group or for other users, and each directory above must have this user or the superuser as owner and a write permission for other users only with the sticky bit, else `agent_program_not_trusted`, exit `3`. The definition has no configuration option and enables no guard. The agent acts on a guard that the authority record of the state directory has enabled: the question and the result of `agent install` name such guards (`mode` is `observation`, `standing_guards`, or `unknown` when the record cannot be read; `standing_guards` has the list), and the question says that a running agent of the service is stopped and started again. `agent install` writes the definition, then unloads an earlier registration of the label, then loads the definition, so a failed write changes no registration. Each of the two commands refuses the superuser with `superuser_not_supported`, exit `3`, and its result has `kind` `report`. `agent install` creates the state directory. `agent uninstall` keeps the state directory and its records |
| Commands that create the state directory | `config apply`, `clean plan`, `processes stop`, `policy disable`, `agent pause`, `agent resume`, and `agent install`, with mode `0700`. A state directory that exists, and its `plans` directory, must be a directory and not a symbolic link, have this user as owner, and permit no access to the group or to other users, else `state_directory_not_private`, exit `3`, or `plan_document_unavailable` for the `plans` directory |
| Queries on an absent journal | `operations show/wait/cancel/acknowledge`, `clean show`, `clean apply`, `history`, `agent status`, `policy enable`, and `policy rearm` make no state directory and no journal |
| Read-only policy commands | `policy list`, `policy show`, and `policy simulate` read the proposal, not the revision in effect, and use no grant of the authority record |

The error codes of this build, in addition to those of the Milestone 1 build and to the codes of the coordinator and of the authorization, are:

| Family | Exit | Codes |
| --- | --- | --- |
| `request` | `2` | `invalid_plan_id`, `invalid_operation_id`, `operation_not_unknown_outcome`, `invalid_revision`, `invalid_incident`, `invalid_generation`, `invalid_grace`, `invalid_duration`, `unknown_rule`, `not_a_cleanup_plan`, `plan_not_buildable`, `plan_not_executable` |
| `authority` | `3` | `no_active_policy_revision`, `approval_required`, `approval_declined`, `reviewed_revision_required`, `acceptance_mismatch`, `observe_profile`, `guard_not_requested`, `wrong_principal`, `authority_record_of_a_different_user`, `plan_authority_not_usable`, `disable_refused` |
| `eligibility` | `3` | `rule_mode_not_validated`, `target_protected`, `target_not_eligible` |
| `native` | `3` | `selection_preset_not_available`, `evict_discovery_not_available`, `agent_program_not_found`, `agent_program_not_trusted`, `state_directory_not_private`, `service_change_failed`, `superuser_not_supported`, `home_directory_unavailable`, `clock_unavailable`, `rule_registry_unavailable`, `identity_unavailable`, `filesystem_executor_unavailable`, `service_definition_not_renderable` |
| `evidence` | `5` | `plan_not_found`, `operation_not_found`, `scan_stale`, `volume_identity_unavailable`, `plan_document_not_usable`, `revision_conflict`, `authority_record_changed`, `stop_plan_exists`, `target_protection_unknown`, `coordinator_stopped`, `journal_conflict`, `record_not_found`, `agent_not_running`, `incident_not_found`, `generation_conflict`, `incident_record_not_usable` |
| `limits` | `5` | `plan_expired`, `queue_full`, `acknowledgment_pending`, `rearm_pending`, `incident_operation_unsettled`, `budget_generations_exhausted`, `selection_too_large`, `plan_limits_not_usable`, `stop_durations_not_usable` |
| `outcome` | `5` | `operation_record_unavailable`, `incident_outcome_unknown` |
| `recording` | `1` | `journal_unavailable`, `journal_busy`, `journal_full`, `journal_newer_version`, `journal_older_version`, `journal_not_recognized`, `authority_record_not_readable`, `plan_document_unavailable`, `policy_revision_source_not_usable`, `coordinator_unavailable` |

A refusal of the coordinator or of the authorization keeps its own code and family, for example `policy_revision_changed` (`authority`) and `lease_unavailable` (`limits`). These codes of the coordinator, of the request queue, and of the filesystem executor have a meaning that a client needs:

| Code | Family | Meaning |
| --- | --- | --- |
| `principal_mismatch` | `authority` | From the coordinator: a queued cancel is of a different user than the apply of the operation, and nothing is canceled. From the filesystem executor: the effective user of the executing process is not the principal of the request, and the target is skipped with no call |
| `request_not_decodable` | `request` | A row of the request queue cannot be decoded by this build, for example a request kind of a later build. The request is rejected with no call and no operation |
| `admission_not_recorded` | `recording` | The journal did not record the admission: a different process held its lock for longer than the bounded wait, or the storage failed and the critical-memory exception does not apply. Nothing was dispatched. A locked journal never starts the exception ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12) |
| `acknowledgment_not_recorded` | `recording` | The journal did not record the acknowledgment of an `UnknownOutcome` operation. The leases stay |
| `rearm_not_recorded` | `recording` | The agent did not record its controller record with the new budget generation. The earlier generation stays in effect |
| `agent_not_running` | `evidence` | A coordinator of a client claimed a rearm request. Only the controller of an agent records a budget generation |
| `incident_allowance_missing` | `limits` | An automatic plan has no incident allowance: it did not come from the controller of the agent |
| `reconcile_before_force` | `outcome` | The effect of the graceful step is not known, so no force step is dispatched before a reconciliation |
| `approved_root_mismatch` | `evidence` | A root record of the executing process has the identity of the root of a file target and a different path or object. The target is skipped with no call |

A plan explanation gives the reason `link_count_unknown` (family `evidence`) for an entry of a rule that skips hard-linked objects when the link count of the entry is not known. The `next_action` values of this build are `none`, `correct_request`, `refresh_observation`, `resolve_authority`, `respect_limits`, `prepare_new_plan`, `query_operation`, and `reconcile`.

These points are open in this build:

- The approved roots of a manual operation are the roots that its sealed plan binds, so an agent executes a manual cleanup plan of the request queue, and a transient coordinator executes a request of a different client. The coordinator does not apply the catalog of protected file locations to a root of a plan: the plan builder of the client does, and the filesystem executor refuses the home directory, its ancestors, and the cleanup root. A second check of the catalog at admission needs the home directory and the state directory in the coordinator. An automatic operation acts only under the roots of its process, and the agent has none in this build.
- The catalog of protected file locations of `svalnir-core` has the locations that `docs/CLEANUP_RULES.md` section 5 lists. It does not have each directory of OS-managed storage, for example the system databases below `/private/var/db`. A location that is not in the catalog has the protection of the `[protections]` table and of the filesystem executor only.
- The location of the `svalnir-agent` executable has no packaging contract. The service commands accept only an executable beside the `svalnir` executable.
- The reading of the coordinator lock that takes no lock uses a property of macOS: `fcntl` with `F_GETLK` reports a lock that `flock` holds. A test holds the property on the host of the build. On a system without it the reading gives "free", and a start then finds the lock held. A request that no process serves is reported with `coordinator_stopped`.
- A rearm is refused while the controller record shows an unknown outcome of the incident (`incident_outcome_unknown`), and an acknowledgment of the operation (`operations acknowledge`) does not change that record. Whether an acknowledgment resolves the unknown outcome for a rearm is a decision of the project owner ([POLICY_SPEC.md](POLICY_SPEC.md) section 14).
- The journal has no migration step for a stored plan of schema version 1: an operation with such a plan is reported as corrupt and cannot be read at recovery. No released build wrote such a row. The decision is necessary before the first packaged build.
- The process evidence of the rule `xcode.inactive-derived-data` has an observation time ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 11), and no command makes that evidence: the `evict` mode of `clean plan` runs no discovery in this build.
- A test build of the client has no service host of the system and no Trash of the system: a test that sets none gets a host and a Trash that refuse each call.
- The service manager calls of `agent install` and `agent uninstall` were not run on a host. The exit statuses that the client reads as "not loaded" (3 and 113) and the load that follows an unload at once are not verified.
- The graceful request of an application member goes through Launch Services. For a helper process of an application, which Launch Services does not register, the graceful step is skipped with `application_not_registered`.

## 5. Manual approval and standing authorization

Preparing or displaying a plan is observational. Applying it requires authorization bound to its immutable ID, digest/identity, mode, target set, expiry, and relevant revisions. The digest has the form `sha256:` and 64 lowercase hexadecimal digits; [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 2 defines its content. An apply request names the plan ID and the digest that the client reviewed.

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

A timed pause ends at its expiry on the monotonic clock of the boot and the clock domain in which it started; a change of the wall clock does not end it. After a reboot, or in a different clock domain, the end of the pause cannot be established, because the wall clock can be wrong after a boot. The pause then stays in effect until `agent resume` ([POLICY_SPEC.md](POLICY_SPEC.md) section 14), and the pause status has `status` `paused` and `basis` `retained`, with no `until` and no `remaining`.

Activation compares the expected revision. Each enable request binds the revision that the user reviewed: an interactive enable flow presents the revision in effect and binds the revision that it presented, and a noninteractive mutation must name the reviewed revision explicitly. A request that names no revision is refused; the revision in effect is never bound in its place. A conflict requires renewed evaluation, not a silent overwrite.

`--accept-force-quit` accepts the request for an application exit and the force quit. A memory guard whose revision does not permit a force quit needs the acceptance of the request for an application exit only. No flag of its own is specified for that acceptance: section 4 has the behavior of the Milestone 2 build, in which `policy enable memory-guard` with no acceptance flag gives it. Whether the acceptance gets a flag is open.

A rearm request identifies the incident and current budget generation (`policy rearm POLICY --incident INCIDENT_ID --generation GENERATION`) and records the newly authorized generation. It does not erase history, bypass cooldowns, or resolve an unknown prior effect. It is refused while the guard is disabled, its grant is revoked or absent, or a pause is in effect, and when no agent runs ([POLICY_SPEC.md](POLICY_SPEC.md) section 8).

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

For an operation-bearing response, unknown outcome takes precedence over partial completion. Otherwise use the settled domain outcome. For pre-admission failure, use its request/capability/state family; a recording failure is an internal execution failure. Do not collapse every native error into “permission denied.”

The exit status of a pre-admission error is the status of its error family:

| Family | Exit |
| --- | --- |
| `request` | `2` |
| `authority`, `eligibility`, `native` | `3` |
| `evidence`, `limits`, `outcome` | `5` |
| `recording` | `1` |

A family that the client does not recognize gives exit `5`: its permitted next step is `reconcile`, and the client has no conclusive result.

Ctrl+C disconnects the waiting/streaming client. It does not uninstall the agent, disable a guard, or cancel an admitted operation. Explicit operation cancellation has separate acknowledgement semantics.

## 9. Authenticated local protocol

The signed distribution uses local XPC with typed method interfaces and constrained decoded classes. JSON is the public machine-output representation; this document does not require sending arbitrary JSON dictionaries through the privileged boundary.

Authenticate both client and server with supported code-identity mechanisms appropriate to the deployment target. Require the expected product signing identity and permitted role, rather than accepting every executable from a signing team. Bind user/session identity from the live transport using supported platform metadata. At the helper boundary, the session is the login session of the peer: on macOS, the planned transport reads the audit session identifier of the connection. Section 10 binds each delegated step to it.

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

The helper binds each delegated step to the user and the login session of the caller that it accepted. Neither value is a field of the request; the transport supplies both from the live connection. The helper refuses a request with no login session (`helper_login_session_missing`). For a recorded step, a status query, a repeat, and a request with a different content from another login session of the same user get one refusal (`helper_login_session_mismatch`). The refusal has no state and no content of the step, and it is the same for a repeat and a different content. It is a refusal and not `helper_step_not_recorded`: the helper must refuse an eviction request for a recorded step identity in any case, so a "not recorded" answer to a query would hide nothing.

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
