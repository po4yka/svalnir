# Svalnir Interfaces

**Status:** Design specification. Commands, message shapes, limits, and version numbers below define the proposed first implementation; they are not a shipped API. The current build implements the subset that section 4 names in "Milestone 1 in-process build" and "Milestone 2 build without a socket". It has no local protocol: sections 9 to 11 are planned behavior.  
**Interface baseline:** 1  
**Last reviewed:** 2026-11-19

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

The initial proposed IPC major is 1 and JSON schema version is 1. Equal numbers across these systems do not imply compatibility. The schema version of a sealed plan and of a request envelope is a separate number, which `docs/ACTION_CONTRACTS.md` section 3 owns; it is 3. A development build has one present plan schema and one plan document format, and no migration: a stored plan or a plan document of a different version is refused with `plan_version_not_supported`, and the user makes a new plan.

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
| `scan PATH`, `report [--scan ID]` | Bounded analysis, scan inspection, and the capacity report of the startup data volume |
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

A cleanup selection preset such as `--profile developer` filters candidates. It is separate from the Observe/Balanced/Aggressive operating templates and cannot enable rules or grant authority. The `trash` and `permanent` modes take their candidates from a saved scan and need `--scan SCAN_ID`. The `evict` mode reads no scan.

The proposed manual cleanup modes are `trash`, `permanent`, and `evict`, mapping respectively to `MoveToTrash`, `DeleteSelectedFiles`, and rule-based `EvictRegenerableData`. The `trash` and `permanent` modes need an exact selection: the user names each entry with `--entry PATH`, once for each entry, and a named entry must be an entry of the saved scan. With no entry, the command lists the candidates of the scan for review and makes no plan. The evict mode requires an exact supported rule selection, given as `--rule RULE_ID`, and takes no entry: its candidates come from the rule. The policy's `automatic_mode = "permanent"` remains a separate configuration field.

### Milestone 1 in-process build

The read-only commands have no local protocol behind them. The CLI links the agent library and runs each read-only command in its own process. The decisions in this subsection apply to the builds with no local protocol. A build with the protocol of section 9 replaces them.

| Subject | Decision |
| --- | --- |
| Commands that run | `status`, `memory status`, `swap status`, `monitor`, `processes top`, `processes show`, `scan`, `report`, `doctor`, `config validate`, `config show`, `policy list`, `policy show`, `policy simulate`, `completions`, and `license` |
| Commands that change state | See "Milestone 2 build without a socket". On a platform other than macOS, a command whose executor exists only for macOS reports `not_implemented` or `unsupported_platform` (exit `3`, no change) |
| Response `kind` | `snapshot` for `status`, `memory status`, `swap status`, `processes top`, `processes show`, and `scan`. `report` for `report`, `doctor`, `config validate`, `config show`, `policy list`, `policy show`, `policy simulate`, and `license` |
| State directory | `~/Library/Application Support/Svalnir/`. The environment variable `SVALNIR_STATE_DIR` replaces it with an absolute path; a value that is not absolute is a request error. Among the read-only commands, only `scan --save` creates the directory, with mode `0700`. "Milestone 2 build without a socket" names the other commands that create it |
| Catalog store | `catalog.sqlite` in the state directory holds the saved scan records and the metric samples of the agent. `scan --save` applies the `[history]` limits of the configuration template, because no effective revision exists. The `save` field of the result is `not_requested`, `saved`, `not_saved_interrupted`, or `removed_by_retention` |
| Configuration proposal | The file of `--config PATH`, or `config.toml` in the state directory. `config validate` needs a file. `config show`, `policy list`, `policy show`, and `policy simulate` use the built-in template when the default file does not exist, and the result names that source |
| `config show --effective` | The values of the revision in effect, from the operation journal, with `active` true and the revision record. With no revision in effect: the error `no_active_policy_revision`, exit `3` |
| Target ID | The process generation identity `pg-<pid>-<start time in microseconds>`. No server holds identity evidence, so each invocation resolves the ID against a new snapshot. A target that is not in the snapshot gives `target_not_found`, exit `5`. The ID is never permission to act |
| `processes top` | `--limit` has the default 20. `--sort growth` and `--sort cpu` compare two snapshots that are 1 second apart. The inventory has only the processes of the current user |
| `processes show` | The policy eligibility is not evaluated, and the result says so |
| `monitor` | `--interval DURATION` from 1 second to 1 hour, with the default 2 seconds. The formats are `text` and `ndjson`. The event types are `snapshot` for the first event and `observation_update` for each later event. `stream_id` is the request identity, and `stream_epoch` is the collector epoch. A collection failure gives one last event of the type `stream_error`, whose `data` is the structured error, and the exit status of the error family. The stream has no resume token, heartbeat, or gap event |
| `report` | Exit `0` when the record is read, also for a record with partial coverage; the coverage is in the result. A scan ID with no record gives `scan_not_found`, exit `5`. Without `--scan`, `scan`, `recorded_started_at`, and `recorded_finished_at` are null. Each result has `capacity` ([RESOURCE_MODEL.md](RESOURCE_MODEL.md) section 7), with `schema_version` `1`: `report` with the four labeled entries `explained_by_scan`, `not_explained_by_scan`, `local_snapshots`, and `important_minus_available`, each an observation with `label` and `detail`; `history` with the `disk.available_bytes` samples of the window; and `time_to_threshold`, with `kind` `estimate`, `authorizes_action` false, `threshold_bytes`, and `result` (`outcome` `estimate` with `remaining_ns`, or `no_estimate` with `reason`). A part with no value is null, with `report_unavailable` or `history_unavailable` (`no_catalog_store`, `volume_not_resolved`, `catalog_store_error`, `collector_unavailable`, or `clock_unavailable`). `--window DURATION` (default `24h`, at most `30d`), `--limit COUNT` (default 2000, at most 10000), and `--threshold SIZE` (default `disk_guard.warn_below` of the configuration template, named in `threshold_source`). An entry with no value does not change the exit status. The command creates no catalog store when the file is absent; it opens an existing one with the same open as `report --scan`, which can migrate its schema |
| `policy simulate` | The grants are none, with the basis `recorded`. Only the `startup-data` selector is resolved. The snapshot has no cleanup candidate, because no rule registry exists. The product protection of each application comes from the catalog of hard protections in [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 8, with the CLI process and its ancestors as the control plane. No grant exists, so no action is admissible |
| Partial scope (exit `4`) | A required observation of the command has no value, a process identity query failed for a cause other than denial, or the coverage of the scan is partial. `status`, `memory status`, `swap status`, and `processes top` give `coverage.required_scope` and `coverage.missing_required`. `scan` gives `scan.coverage` and the list of regions |
| `--timeout` | It bounds the client wait of `clean apply`, `processes stop`, `operations wait`, `operations cancel`, `operations acknowledge`, and `policy rearm`. It has no effect on each other command, whose result has the warning `timeout_not_applied`: in `warnings` of the envelope, or on stderr for the text format and for `monitor`. An error response keeps it: in `warnings` of the error envelope, or on stderr before the error |
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

This build has no socket, and it registers no XPC service. A client and the agent share the operation journal `operations.sqlite` in the state directory. The decisions in this subsection apply to this build only. A build with the protocol of section 9 replaces them. The journal is same-user state: the principal of a request is a record, not an authentication.

| Subject | Decision |
| --- | --- |
| Executor of a request | The process that holds the coordinator lock of the journal. When an agent holds the lock, the client writes the request to the request queue of the journal and reads the result by its identity. When no process holds the lock, the client takes the lock and executes the request with the same coordinator code: a transient coordinator. A transient coordinator evaluates no guard and makes no automatic plan. The result names the executor as `transient_coordinator` or `queued_for_coordinator` |
| Authority record of a transient coordinator | The client reads the authority record before the approval question, and a different client can change the record while the question waits. A transient coordinator reads the record again when it holds the coordinator lock, before the admission, and before each step. A record that is absent or has a different user gives no authority. The coordinator runs no step while a read of the record fails. A record that cannot be read for 2 seconds gives no authority until a read has a result: each later step is refused |
| Lifetime of a transient coordinator | The client process is the executor of its operation. It continues to the end of the operation also after the client wait ended (`--no-wait`, `--timeout`, or Ctrl+C), and it exits after that. The response is complete and flushed before the remaining work, and a response that cannot be written does not stop the work. From the admission on, Ctrl+C does not end the process. A step of the coordinator also serves the request queue, so the process then executes each request that it claimed before it exits. The end of a wait cancels nothing. Ctrl+C ends only the wait (section 8); a stop signal stops the coordinator, as in the row "Stop signal of a transient coordinator" |
| Stop signal of a transient coordinator | A client that holds the coordinator lock (`clean apply`, `processes stop`, `operations acknowledge`) records `SIGTERM` and `SIGHUP` with a handler that only sets a flag, from the moment it holds the lock. It then stops as the agent does (row "Stop of the agent"): it claims no further request of the queue, gives each operation that it executes or that waits the stop request, so that the step in progress ends at its safe boundary and no later step, a force step included, is dispatched, and waits for them at most 10 seconds. It records the result in the journal, releases the coordinator (an operation that is not settled keeps the registration, and the next coordinator reconciles it), writes its response, and exits with `128` plus the number of the signal: `143` for `SIGTERM`, `129` for `SIGHUP`. A waited result has `wait` `stopped_by_sigterm` or `stopped_by_sighup`; a signal after the response (`--no-wait`, or after the end of the client wait) also gives the exit status of the signal. A signal that the client records after it holds the lock and before the admission (for example during the reconciliation of an earlier lifetime) admits no operation: `clean apply` and `processes stop` report `stopped_by_signal`, with the exit status of the signal, and the plan can be applied again. `operations acknowledge` that receives the signal before the acknowledgment records no acknowledgment and reports `stopped_by_signal`, with the exit status of the signal. Before the client holds the lock, and in a client whose request a different coordinator executes, the signal keeps its default action: it ends the client, and the operation continues in that coordinator |
| Policy revision of a manual plan | A manual plan binds the policy revision in effect, so `clean plan` and `processes stop` need one. With none: the error `no_active_policy_revision`, exit `3`. `config apply --config PATH` makes one; the command needs a file, and a file with the text of the built-in template is sufficient |
| `config apply` | `--expected-revision none` expects that no revision is in effect. The new revision has an identity that the client makes. The client records the configuration text of the revision in the journal and then writes the authority record with a compare-and-set on its record revision. An activation makes no grant |
| `policy enable` | `--accept-permanent-eviction` accepts `EvictRegenerableData`. `--accept-application-exit` accepts `RequestApplicationExit` only. `--accept-force-quit` accepts `RequestApplicationExit` and `ForceApplicationExit`; with `--accept-application-exit` also, the accepted classes are the same. With no flag, no class is accepted. The accepted classes must be exactly those of the guard in the revision in effect, else `acceptance_mismatch`, exit `3`, and no change: so `policy enable memory-guard` with no flag is refused, a guard that permits a force quit needs `--accept-force-quit`, and a guard that does not permit one needs `--accept-application-exit`. The result has `acceptances`: the acceptances of the recorded grant (`permanent_eviction`, `application_exit`, or `force_quit`); the text output shows them. Each enable request names the revision that the user reviewed, and the grant logic refuses a request that names none. With no `--expected-revision`, an interactive session answers a question that names the revision in effect, and the request binds that revision; a revision that became active while the question waited is not bound, and the command reports `authority_record_changed`, exit `5`. A session with no terminal gets `reviewed_revision_required`, exit `3` |
| `policy rearm` | The budget generation is state of the controller of the agent. When an agent holds the coordinator lock, the client writes a rearm request to the queue of the journal and waits for its completion (`--timeout`, else 30 seconds; then `rearm_pending`). The agent checks the request against the authority record that the journal has when the coordinator claimed the request (it reads the record again after the claim) and its controller record: the standing of the guard, the pause (a retained pause included), the generation, and the condition of the incident. It records the new generation in its controller record and completes the request with the previous and the new generation; when the journal does not take the controller record, the earlier record stays, and the request is rejected with `rearm_not_recorded`. A refusal of the standing has the code of the authorization, for example `guard_disabled`, `action_grant_revoked`, `action_grant_missing`, or `automation_paused` (`authority`, exit `3`). When no agent holds the lock, the command is refused with `agent_not_running`, exit `5`, and makes no state directory, no journal, and no request; a coordinator of a client that claims a rearm request rejects it with the same code |
| Control acknowledgement | Each result of `config apply`, `policy enable`, `policy disable`, `agent pause`, and `agent resume` has `acknowledgement` (`durably_applied`), `durable`, `record_changed`, and `coordinator` (`running`, `not_running`, or `unknown`). A change that the journal did not take is an error and is not in effect: a client has no running instance that it can inhibit, so it reports no `current_instance_inhibition`. A concurrent change of the record gives `authority_record_changed`, exit `5` |
| Candidates of `clean plan` | For the `trash` and `permanent` modes: the entries that the saved scan record names, which are its largest files and its largest directories below the scan root. The user names each entry of the plan with `--entry PATH`. A relative path is relative to the invocation directory. A named entry must be the path of an entry of the record: the comparison is exact, of the path text or of the directory of the entry with its symbolic links resolved and the name of the entry, the form that the protections use, with no glob and no prefix; the scan root is not an entry. A named entry that is not in the record gives `entry_not_in_scan`, exit `2`, and nothing is planned. With no `--entry`, the command makes no plan, no plan document, and no journal change: it writes a report with `mode`, `selection` (`entries_required`), `candidates` (each with `path`, `object_type`, `logical_bytes`, `allocated_bytes`, and `hard_protection`: `protected`, `not_protected`, or `unknown`), `stale_entries`, and a note that tells the user to name entries, and exits with `2`, as `config validate` does for a document that is not valid. The envelope `schema_version` versions the report. Each named entry is measured again; an entry that is absent, is a different object than at the scan, or has an unsupported type is in `stale_entries` and not in the plan. A named entry that a hard protection or a path of `[protections].excluded_paths` covers gives `target_protected`, exit `3`; the list applies to the path of the entry, to its location (the directory with its symbolic links resolved and the name), and to the entry with each symbolic link resolved, as the hard protection does, so a scan root with a symbolic-link component does not move an entry out of an excluded path; and an entry whose protection is not known gives `target_protection_unknown`, exit `5`; nothing is planned. The scan root is the cleanup root and is never a target. The path `/` cannot be a cleanup root: the command refuses it with `plan_not_buildable` before it reads a candidate. A named entry below a different named directory is left out with the reason `overlaps_selected_entry`. `--mode evict` with `--entry` gives `entry_not_accepted`, exit `2` |
| `--profile` | This build has one selection preset, `developer`: it includes the candidates that the rule `xcode.inactive-derived-data` found. A preset only filters: the plan builder leaves out each entry that the preset does not include, with the reason `not_in_preset`, and the explanation has `preset` with the name. An entry of a scan has no rule, so the preset leaves out each entry of a `trash` or `permanent` plan; the list of candidates of a scan with no `--entry` does not use the preset. A different name gives `unknown_profile`, exit `2` |
| `--mode evict` | `--rule RULE_ID` names the rule. An unknown rule gives `unknown_rule`, exit `2`. A rule with no layout that is validated for manual action gives `rule_mode_not_validated`, exit `3`, before a directory is read and with no state directory; each reviewed rule of this build is `proposed`, so each known rule gives this error. For a validated rule, the command needs a policy revision in effect, runs the discovery of the rule for manual eviction ([CLEANUP_RULES.md](CLEANUP_RULES.md) sections 4 and 6) with the paths of `[protections].excluded_paths` as exclusions, gives each candidate to the plan builder with the exact rule revision, and stores the sealed plan and the plan document as for a scan. The cleanup roots are the roots of the rule declaration. The work ceiling of the plan is one pass of the rule. The result is that of `clean plan` with `scan_id` null and with `discovery`: `rule`, `complete`, `candidates`, `conflicts`, `blocked` (each candidate whose age or inactivity the rule did not establish, with `relative_entry` and the `reasons` of the rule) with `blocked_omitted`, and `roots` (each with `path`, `result`: `examined`, `not_bound`, or `refused`, `reason`, `completion`, and `skipped`, to 64 units, with `skipped_omitted`). A candidate that a check leaves out is in the explanation with its reason. With no eligible candidate, no plan is made, and the exit status is `0`. A discovery that the user interrupts makes no plan: the result has the discovery, and the exit status is `130`. `--entry` gives `entry_not_accepted`, exit `2`. `--scan` is accepted and not read. `clean show` and `clean apply` of the plan are those of each cleanup plan; the result of `clean show` has no `discovery` |
| `--scan` | The `trash` and `permanent` modes need it: with none, `scan_required`, exit `2` |
| File protection of a manual plan | The hard protection of a file entry comes from the catalog of protected file locations of `svalnir-core` (`docs/CLEANUP_RULES.md` section 5): storage of the operating system, swap storage, the state directory of Svalnir, and the home directory with each directory that contains it. The client gives the catalog the home directory and the state directory with their symbolic links resolved, and two forms of the path of the entry: the directory of the entry with its symbolic links resolved plus the name of the entry, and the entry with each symbolic link resolved. The entry is protected when one form is protected, so a symbolic link in a protected location is protected, and so is a symbolic link whose target is a protected location, for example a link at the configured path of the state directory. An entry that does not resolve has an unknown protection. A state directory that does not resolve is not given, and an entry that no other rule protects has an unknown protection; an entry whose protection is not known is left out. The plan builder applies the `[protections]` table, and the filesystem executor refuses the home directory, its ancestors, and the cleanup root again |
| Plan document | The journal stores the sealed plan. The client keeps the size estimates, the entries that were left out, the record of each cleanup root with its volume, the operation identity, and the measurements of the operation in `plans/plan-PLAN_ID.json` of the state directory, with mode `0600`. A document gives no authority and gives the executor no cleanup root: the coordinator takes the approved roots of a manual operation from the sealed plan. The identity of a cleanup root is a digest of its path, its device and inode, its volume, and its mount generation, and the sealed plan binds that identity, the root path, and the device and inode of the root for each file target. A document is used only when its digest and its plan are those of the stored plan, its roots are exactly the roots that the file targets of the plan bind, each root has the path and the object that the sealed plan binds for it, and each root has the identity that its values give. The display path of a file target, in a plan view and in each result, is the root path and the relative entry that the plan binds, and `cleanup_roots` has the root paths that the plan binds; a client with no document has them also. The estimates, the work totals, and the paths of the entries that were left out are display data of the document with no check. The volumes of the capacity observations of a transient coordinator come from the sealed plan also: the client reads the volume at each root path that the plan binds and uses it only when its volume identity and its mount generation are those of the binding. The result of `clean plan` and `clean show` has `cleanup_roots` and `plan_document` (`used`, `absent`, `not_readable`, or `disagrees_with_plan`). A document that cannot be read or does not agree is not used and is not an error of `clean show`, of `operations show`, of `history`, or of the report of a plan that was applied before. `clean apply` of a plan with no document asks its question with each path and no estimate, and applies the plan. `clean apply` with a document that is present and not used reports `plan_document_not_usable`, exit `5`. A document has `schema_version` (3); `clean show` and `clean apply` refuse a document of a different version with `plan_version_not_supported`, exit `2`, before they read a field of it, and the user makes a new plan. A document is removed after 7 days |
| Approval | `clean apply` and `processes stop` ask one question on stderr that has the scope and the consequence of the plan: each target, with no limit on the length of the list, and each cleanup root. Only the answers `y` and `yes` approve. A session with no terminal needs `--yes`, else `approval_required`, exit `3`; a refusal gives `approval_declined`, exit `3`. An expired plan is refused before the question, with `plan_expired`, exit `5`. The approval names the plan identity and the digest of the stored plan |
| Duplicate apply | A second `clean apply` of a plan reports its operation with `existing_operation` true and `kind` `operation`, and makes no second operation. The journal has at most one operation for a plan. `wait` is `finished` for an operation that is settled or has an unknown outcome; for each other operation it is `not_waited`, and the command does not wait. The exit status is that of the operation, which is `5` for `not_waited`; with `--no-wait`, an operation in the `Admitted` state gives `0` |
| `--no-wait` | The response has `kind` `accepted` with `operation_id`, `plan_id`, `state`, `dispatch`, `durability`, `acknowledgement` (`operation_admitted` or `request_queued`), `executor`, and `request_id`. A queued request waits at most 10 seconds, or the `--timeout` value, for its admission; after that the state is `queued` and `operation_id` is null |
| Waited result | `kind` `operation`. `wait` is `finished`, `timed_out`, `interrupted`, for a transient coordinator `stopped_by_sigterm` or `stopped_by_sighup`, or, for `operations wait`, `no_coordinator`. The exit status is that of section 8 for `finished`, `130` for `interrupted`, `143` for `stopped_by_sigterm`, `129` for `stopped_by_sighup`, and `5` for the others. A result that cannot be written keeps this status: a closed pipe is silent, and each other write error has a diagnostic on stderr. A wait reads a busy journal again. A read that fails after the admission gives `operation_record_unavailable`, exit `5`, with the plan and the operation; a read that fails in `operations wait` gives the journal error with the operation |
| `processes stop` | `--target TARGET_ID` or `--group INSTANCE_ID`, exactly one. `--target` names one process generation, and the plan has that one process and no other. A process with a verified membership in an application or a managed job is the only member of an application target. A process with no application or job evidence, for example a process that a shell started, is a target of one process (`docs/ACTION_CONTRACTS.md` section 3): the executor checks its identity evidence again and sends one signal to its process ID. A process with an association that this build does not recognize gives `target_not_eligible` with the reason `membership_not_verified`, exit `3`. `--group` names one application or managed-job instance, the `Instance` field of `processes show`; text that is not an instance identity gives `invalid_group`, exit `2`. The plan binds each process with a verified membership in that instance (`client::group_candidate`), never a process only because it has the same name; an instance with no verified member gives `group_not_found`, exit `5`. One protected member protects the group (`target_protected` or `target_protection_unknown`). The question names the verified members of the instance and lists each target. The executor checks the identity of each member again before its call: a member whose generation changed is `Skipped` with `process_replaced`, and a member that exited is `AlreadyExited`. It does not check the membership again. The CLI builds each plan with `client::build_manual_stop`, with the identities, the revision binding, the lifetime, and the protections of the stop of the GPUI client. `--grace` has the default 10 seconds and the maximum 5 minutes. With no force option, the grace period is the time in which the exit is observed. A stop record `plans/stop-TARGET_ID.json`, or `plans/stop-group-INSTANCE_ID.json` for a group, binds the subject to its plan, its strategy, its grace period, and its observation time. A repeated request with the same values reports the plan and the operation of the first one; for a group, only while that operation is not settled: after it is settled, the command reads the group again and makes a new plan, because the members of an instance can change. A request with different values makes a new plan only when the earlier operation is settled, for example a force quit after a graceful request that the process ignored; else it gives `stop_plan_exists`, exit `5`. A stop record or a plan that cannot be read permits no new plan. A lock file `plans/stop-TARGET_ID.lock` (or `stop-group-INSTANCE_ID.lock`) makes two requests for one subject make one plan; a lock file is not removed with the old documents. The wait for the lock is bounded by `--timeout`, or by 10 s when the option is absent; after that time the command gives `plan_document_unavailable` and no plan. The wait for the operation has its own time of `--timeout` after the lock |
| `operations cancel` | A settled operation gets no request and no fence: `acknowledgement` is `settled`, and `path` is `none`. When an agent holds the coordinator lock, the client writes a `Cancel` request to the queue with the request identity of the invocation and waits for its completion (10 s, or `--timeout`); the agent checks the principal and stops the operation in its executor. A refusal of the agent is an error with its code, for example `principal_mismatch`, exit `3`, and no fence. When the agent does not answer in the wait, when it stops first, or when the queue cannot be read after the write, the client writes the stop fence itself, and the request stays in the queue; a note says so. With no agent, with a client as the holder of the lock, or with a lock that cannot be read, the client writes the stop fence itself and writes no request. `acknowledgement` is `durable_stop_fence`, `current_instance` (only from the agent: it stopped the operation, and the journal did not take the fence, so a restart of the agent does not keep the stop), or `settled`. `path` is `request_queue`, `stop_fence`, or `none`; `request_id` names the queued request; `fence_written` is true when this request or the agent for it wrote the fence. A fence that was not written is an error; when the request was queued first, the error says that the request stays in the queue, with its `request_id`. The wait for the operation to settle (at most 2 seconds) follows the wait for the agent and ends also at an unknown outcome. The exit status is `0` for each path that records a stop |
| `operations acknowledge` | The command is accepted only for an operation in `UnknownOutcome`. When a different process holds the coordinator lock, an agent or a client that is a transient coordinator, the client writes the request to the queue of the journal and waits for its completion; the holder serves the queue at its next step, and a holder that stops first leaves the request in the queue (`coordinator_stopped` when no process serves it) (`--timeout`, else 30 seconds; then `acknowledgment_pending`). When no process holds the lock, the client reconciles the operations of an earlier lifetime as a transient coordinator and records the acknowledgment. The result has `acknowledged_at`, `repeated` (true for a repeated acknowledgment, which changes nothing), `executor`, and the operation, whose state stays `UnknownOutcome`. The acknowledgment releases the leases of the operation ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12). `operations show` and `history` give `acknowledged_at` for an acknowledged operation |
| `operations wait` | The client reads the journal until the operation is settled or has an unknown outcome. When no process holds the coordinator lock and the operation is not settled, the wait ends at once with `no_coordinator`, exit `5` |
| Measurements | The coordinator records the resource observations of a durable operation in the journal (table `operation_effect`), so `operations show`, `history`, and the result of a queued request have `resource_effects` for an operation that a different process executed. The record has the observations only. The coordinator writes the steps, then the observations, then the settled operation record, so a client that reads a settled operation also reads its observations; a failed write of the observations makes only the recording degraded. A retry of a parked operation writes the observations again with no duplicate. The work totals (`work`) are known to the process that executed the operation, which keeps them in its plan document; for each other client `work` is null. A volatile operation has no record. With no record that the client can read and no document, `resource_effects` is null and the text output has the line `Resource observation: not recorded for this view`: a value that is not in the view is not a measurement of no change. The text output gives its statement about capacity only for a view with a capacity observation: a process stop has a memory-pressure observation and no capacity observation |
| `history` | `--limit` has the default 20 and the maximum 200. Each record has the target results by effect (`moved_to_trash`, `permanently_removed`, `exit_verified`, and the others), the estimate of the plan, the work that the executor measured, and the capacity observations, as separate fields |
| Removal attribution | Each target with the effect `Removed` has the attribution `possible` ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 9). `permanently_removed` counts such targets, and the removed counts of `work` are the sizes that the executor measured before each call. The text output of `clean apply`, `operations show`, and `history` names these counts an estimate. They are not reclaimed capacity |
| `status` | `agent.state` is `running`, `client_coordinator`, `not_running`, or `unknown`. `policies.state` is `none_active`, `active`, `paused`, or `unknown`, with the authority view. `latest_intervention` is the newest record of `history`, or null |
| `agent status` | `kind` `snapshot`. `coordinator` and `lock_holder` (`agent`, `client`, or `none`) come from the coordinator lock; the status record of the agent is not evidence that a process runs. `service.log` is the path of the log of the agent. The command makes no state directory, no journal, and no lock file |
| Coordinator lock | The holder of the lock writes its role (`agent` or `client`) in the lock file and clears it at its end; each other content is read as `client`. A query reads the state of the lock and does not take it. An agent that finds the lock of an agent exits with status `0`. An agent that finds the lock of a client exits with status `1`, so that the service manager starts it again after the client released the lock |
| Stop of the agent | At a stop signal the agent claims no further request of the queue, sets the stop of each operation that it executes, and ends each of them before its next step; a request that it did not claim stays in the queue for the next coordinator. An operation that cannot be settled keeps the registration of the coordinator, and the stop is then recorded as not clean. An agent whose service ended before a stop signal exits with status `1` |
| State directory of the agent | The agent makes the state directory with mode `0700` when it does not exist. It refuses a state directory that is a symbolic link, that is not a directory, that a different user owns, or that has a permission bit for the group or for other users, and makes no change. The refusal is a permanent start error with no start-failure record: the record would be in the refused directory, so the one line on the standard error stream is the report |
| Start errors of the agent | A start error is permanent when a new start with the same inputs fails again: `configuration_not_readable`, `configuration_invalid`, `home_not_set`, `home_account_unknown` (an account with no record that has a home directory), `home_not_resolvable` (also a canonical home directory that is not a journal path), `home_mismatch`, `state_directory_refused`, `journal_older_version`, `journal_newer_version`, `journal_not_recognized`, and `journal_corrupt`. The agent writes one line on the standard error stream with the code, writes the start-failure record (except for `state_directory_refused`), and exits with status `0`. When the record cannot be written, the agent still exits with status `0`, so that no restart loop follows; the line on the standard error stream is then the only report, and `agent status` and `doctor` show no start failure. The `LaunchAgent` definition has `KeepAlive` with `SuccessfulExit` false, and `launchd` starts the job again only after an exit status that is not `0`, so the agent stays stopped until the user corrects the cause and starts it again. Each other start error is transient, for example a busy journal, an input or output error, a lookup of the account record that failed (for example because the directory service is not ready at login), or a clock that gives no value: the agent exits with status `1`, and `launchd` starts it again after the throttle interval. A crash is not an exit with status `0` and is also started again. An agent that finds the lock of an agent also exits with status `0` |
| Start-failure record | The file `agent-start-failure.json` of the state directory, with mode `0600`, has `schema_version` (1), `reason` (the code), `message` (a fixed text with no path and no value of the environment), `failed_at`, and `agent_version`. The agent writes it to a temporary file and renames it, so it replaces the earlier record; the state directory has at most one. The agent removes it when a start takes the coordinator lock as the agent. The record needs no valid configuration and no journal. The record is in the state directory of `--state-dir`; a client reads it in its own state directory, so a client whose `HOME` or `SVALNIR_STATE_DIR` names a different directory does not see it |
| `agent status`, `doctor` | Each result has `agent_start_failure`, also when no agent runs and no journal exists: `state` is `none`, `recorded` (with `reason`, `message`, `failed_at`, and `agent_version`), `not_readable` (a record exists, and this build cannot read it), or `state_directory_unknown`. The text output has one line `Agent start failure:` with the state or the reason. The read makes no state directory |
| Capability summary of the agent | The status record of the agent has version 2. Its capability summary has the verdict, the required capabilities that are not available, `probed_at` (the agent probes once at its start), one line for each capability (`id`, `title`, `requirement`, `state`, `detail`, and `remediation`, with no evidence facts), and `notifications` (`state`, `authorization`, `detail`, and the counts of this agent lifetime). `doctor` shows the notification capability of the agent as the row `agent_notifications`, and Diagnostics shows its `detail` in the list of the agent. In this build the state is `available` with the detail "Dialog for urgent notices, no banner", and `unsupported` in a debug build with the feature `test-support` unless `SVALNIR_TEST_DIALOG_KIND` names an urgent kind. The state is `unknown` until the worker thread of the agent reads the center the first time (row "System notifications" below). The worker roles of the capability probes are `cli`, `window`, `agent`, and `helper`. The role `window` is a window process of the GPUI client, with the probes and the requirements of `cli`; only its scope note and its Full Disk Access remediation differ |
| State directory of `doctor` | `doctor` and the capability summary of the agent examine the state directory of their process: the directory of `SVALNIR_STATE_DIR`, or the default directory. The row `user.state_directory` describes that directory. The text output has the section `Examined directories` with the path of `user.state_directory` and of `user.log_directory`. An invalid `SVALNIR_STATE_DIR` gives a warning with its error code, and the row then describes the default directory |
| `HOME` check | The agent, before it opens the journal, and each command that changes state (`clean plan`, `clean apply`, `processes stop`, `operations cancel`, `operations acknowledge`, `config apply`, `policy enable`, `policy disable`, `policy rearm`, `agent pause`, `agent resume`, `agent install`, and `agent uninstall`), before it changes anything, compare `HOME` with the home directory of the account record of the effective user (`getpwuid_r` of `geteuid`). The comparison is of the two canonical paths, with each symbolic link resolved; two different paths to one directory are a difference. A command refuses with `home_not_set` (no `HOME`, or an empty one), `home_account_unknown` (no account record with a home directory, or a lookup that failed), `home_not_resolvable` (a path that does not resolve), or `home_mismatch`, exit `3`, and makes no state directory. For the agent each of these is a permanent start error, except a lookup that failed, which is transient (row "Start errors of the agent"). A read-only command, `scan` included, has no check. Only a debug build with the feature `test-support` can take the home directory of the account record from `SVALNIR_TEST_ACCOUNT_HOME` ([CONTRIBUTING.md](../CONTRIBUTING.md#fixtures-and-failure-paths)) |
| Journal versions | The journal has version 4 and no migration. A build makes the schema in a new journal. It refuses a journal of an earlier version with `journal_older_version` and a journal of a later version with `journal_newer_version`, and it changes neither file. A read-only open, which the GUI uses, makes no schema: it refuses a journal file with no schema with `journal_not_current`. A plan and a request envelope have schema version 3. A stored plan of a different schema version is refused with `plan_version_not_supported`, exit `2`, before a field of it is read; there is no migration and no compatibility default (section 2) |
| Automatic plan from a client | An automatic plan is admitted only with the incident allowance of the controller of the agent ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 4). A request of the queue for an automatic plan, and an apply of a stored automatic plan by a client, are refused with `incident_allowance_missing` |
| Stop inside a directory target | A stop of an operation (a cancel, a pause, a changed revision or grant, or the stop of the agent) is also read between the entries of a directory target. The target then has `UnknownOutcome` with the stop reason, and the entries that were removed stay removed ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |
| Journal retention and open incidents | The journal has one usage row for each budget generation of an incident (table `incident_usage`), which the consumption of each dispatch of that generation changes in its transaction; the operation row has the generation that its plan binds. The retention of the agent removes the settled operations of an open incident and keeps each of its usage rows: the agent names the open incidents of its controller record to the prune. The usage rows of an incident that is not open go together when its latest operation is older than the retention cutoff. A restart reads the usage row of the current generation, so the budget of an open incident survives a prune and a restart, and a rearm before the restart gives the new generation its own allowance ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12) |
| Control changes between two reads of the agent | The agent reads the authority record one time for each tick. When the revision counter of the record shows a state that the agent did not read, for example a pause and its resume inside one tick, or when the read before this one failed, the agent takes the time of that tick as a measurement floor: a sample from before it supports no automatic action. The controller and the authorization use one rule for the floor (the latest of the durable resume floor of the record, of the resume of the instance, and of each expired pause, in the current boot and clock domain) |
| Durable resume floor | `agent resume` of a record with a pause writes `resume_floor` in the authority record: the monotonic time of the resume with its boot and clock domain. An agent that did not run at the resume, or that did not see the resume, reads it with the record, so a sample from before the resume supports no automatic action. The record has strict decoding and no version. A record of an earlier format, with no `resume_floor`, gives no authority: each command that reads it reports `authority_record_not_readable`, exit `1`, and the agent only observes. This build has no command that replaces such a record: the user stops the agent and removes the operation journal `operations.sqlite` of the state directory, and then activates a configuration and enables each guard again |
| `agent install`, `agent uninstall` | `--yes`, or a question in an interactive session. The service is a per-user `LaunchAgent` with the label `dev.po4yka.svalnir.agent`, whose definition is `~/Library/LaunchAgents/dev.po4yka.svalnir.agent.plist`. The program is the `svalnir-agent` executable beside the `svalnir` executable, as a path with no symbolic link; with none, `agent_program_not_found`, exit `3`. The executable and its directory must have this user or the superuser as owner and no write permission for the group or for other users, and each directory above must have this user or the superuser as owner and a write permission for other users only with the sticky bit, else `agent_program_not_trusted`, exit `3`. The definition has no configuration option and enables no guard. The agent acts on a guard that the authority record of the state directory has enabled: the question and the result of `agent install` name such guards (`mode` is `observation`, `standing_guards`, or `unknown` when the record cannot be read; `standing_guards` has the list), and the question says that a running agent of the service is stopped and started again. `agent install` writes the definition, then unloads an earlier registration of the label, then loads the definition, so a failed write changes no registration. Before the load, the command asks the service manager (`launchctl print`) for the service until it is absent, with 100 ms between two queries and at most 50 queries (about 5 s): status `0` is loaded, status `3` or `113` is absent, and each other status is a failure of the query. When the service stays, the command reports `service_unload_timeout`, exit `3`, and does not load the definition; the definition that it wrote loads at the next login. Each of the two commands refuses the superuser with `superuser_not_supported`, exit `3`, and its result has `kind` `report`. The definition names `~/Library/Logs/Svalnir/agent.log` of the checked home directory as the standard error stream of the agent (`StandardErrorPath`); the log does not follow `SVALNIR_STATE_DIR`. Before it writes the definition, `agent install` makes the log directory with access for this user only, and refuses a path that is not a directory, a symbolic link, a directory of a different owner, a directory that this user cannot write and search, or a directory that a different user can write; then the command changes no registration. The agent cuts its log file to zero at 8 MiB and starts it again with one line that says so. `agent status` shows the path of the log. `agent install` creates the state directory. `agent uninstall` keeps the state directory, its records, and the log directory, and says so |
| Commands that create the state directory | `config apply`, `clean plan` with an `--entry`, `clean plan --mode evict` for a rule that is validated for manual action, `processes stop`, `policy disable`, `agent pause`, `agent resume`, and `agent install`, with mode `0700`. A state directory that exists, and its `plans` directory, must be a directory and not a symbolic link, have this user as owner, and permit no access to the group or to other users, else `state_directory_not_private`, exit `3`, or `plan_document_unavailable` for the `plans` directory |
| Queries on an absent journal | `operations show/wait/cancel/acknowledge`, `clean show`, `clean apply`, `clean plan` with no `--entry`, `history`, `agent status`, `policy enable`, and `policy rearm` make no state directory and no journal |
| Read-only policy commands | `policy list`, `policy show`, and `policy simulate` read the proposal, not the revision in effect, and use no grant of the authority record |

The error codes of this build, in addition to those of the Milestone 1 build and to the codes of the coordinator and of the authorization, are:

| Family | Exit | Codes |
| --- | --- | --- |
| `request` | `2` | `invalid_plan_id`, `invalid_operation_id`, `invalid_group`, `operation_not_unknown_outcome`, `invalid_revision`, `invalid_incident`, `invalid_generation`, `invalid_grace`, `invalid_duration`, `unknown_rule`, `unknown_profile`, `scan_required`, `not_a_cleanup_plan`, `plan_not_buildable`, `plan_not_executable`, `plan_version_not_supported`, `entry_not_in_scan`, `entry_not_accepted` |
| `authority` | `3` | `no_active_policy_revision`, `approval_required`, `approval_declined`, `reviewed_revision_required`, `acceptance_mismatch`, `observe_profile`, `guard_not_requested`, `wrong_principal`, `authority_record_of_a_different_user`, `plan_authority_not_usable`, `disable_refused` |
| `eligibility` | `3` | `rule_mode_not_validated`, `target_protected`, `target_not_eligible` |
| `native` | `3` | `agent_program_not_found`, `agent_program_not_trusted`, `state_directory_not_private`, `service_change_failed`, `service_unload_timeout`, `superuser_not_supported`, `home_not_set`, `home_account_unknown`, `home_not_resolvable`, `home_mismatch`, `home_directory_unavailable`, `clock_unavailable`, `rule_registry_unavailable`, `identity_unavailable`, `filesystem_executor_unavailable`, `service_definition_not_renderable` |
| `evidence` | `5` | `plan_not_found`, `operation_not_found`, `group_not_found`, `scan_stale`, `volume_identity_unavailable`, `plan_document_not_usable`, `revision_conflict`, `authority_record_changed`, `stop_plan_exists`, `target_protection_unknown`, `coordinator_stopped`, `journal_conflict`, `record_not_found`, `agent_not_running`, `incident_not_found`, `generation_conflict`, `incident_record_not_usable` |
| `limits` | `5` | `plan_expired`, `queue_full`, `acknowledgment_pending`, `rearm_pending`, `incident_operation_unsettled`, `budget_generations_exhausted`, `selection_too_large`, `plan_limits_not_usable`, `stop_durations_not_usable` |
| `outcome` | `5` | `operation_record_unavailable`, `incident_outcome_unknown`, `stopped_by_signal` (exit `143` or `129`: the status of the signal) |
| `recording` | `1` | `journal_unavailable`, `journal_busy`, `journal_full`, `journal_newer_version`, `journal_older_version`, `journal_not_current`, `journal_not_recognized`, `authority_record_not_readable`, `plan_document_unavailable`, `policy_revision_source_not_usable`, `coordinator_unavailable` |

A refusal of the coordinator or of the authorization keeps its own code and family, for example `policy_revision_changed` (`authority`) and `lease_unavailable` (`limits`). These codes of the coordinator, of the request queue, and of the filesystem executor have a meaning that a client needs:

| Code | Family | Meaning |
| --- | --- | --- |
| `principal_mismatch` | `authority` | From the coordinator: a queued cancel is of a different user than the apply of the operation, and nothing is canceled. From the filesystem executor: the effective user of the executing process is not the principal of the request, and the target is skipped with no call |
| `request_not_decodable` | `request` | A row of the request queue cannot be decoded by this build, for example a request kind of a later build. The request is rejected with no call and no operation |
| `admission_not_recorded` | `recording` | The journal did not record the admission: a different process held its lock for longer than the bounded wait (also at the write of the controller record before an automatic plan, or at the read of the usage of an incident), or the storage failed and the critical-memory exception does not apply. Nothing was dispatched. A locked journal never starts the exception ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12) |
| `acknowledgment_not_recorded` | `recording` | The journal did not record the acknowledgment of an `UnknownOutcome` operation. The leases stay |
| `rearm_not_recorded` | `recording` | The agent did not record its controller record with the new budget generation. The earlier generation stays in effect |
| `agent_not_running` | `evidence` | A coordinator of a client claimed a rearm request. Only the controller of an agent records a budget generation |
| `incident_allowance_missing` | `limits` | An automatic plan has no incident allowance: it did not come from the controller of the agent |
| `incident_mismatch` | `request` | The budget record or the incident allowance of an automatic plan is of a different incident or budget generation than the plan. Nothing is reserved |
| `reconcile_before_force` | `outcome` | The effect of the graceful step is not known, so no force step is dispatched before a reconciliation |
| `approved_root_mismatch` | `evidence` | A root record of the executing process has the identity of the root of a file target and a different path or object. The target is skipped with no call |
| `target_protected` | `eligibility` | From the coordinator: the catalog of protected file locations protects a file target of the plan, as the coordinator process resolves it at admission ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 4). The plan is refused, and nothing is dispatched. A client gives the same code for a named entry of `clean plan` |
| `target_protection_unknown` | `evidence` | From the coordinator: the protection of a file target is not known at admission, because the home directory or the state directory of the coordinator process is not known or a form of the entry cannot be read. The plan is refused |
| `producer_active` | `eligibility` | From the coordinator: at the fresh check before a step of an eviction, the producer of the data is active. The target is skipped with no call ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7). An operation whose targets are all skipped has the state `NoAction`, exit `0` |
| `producer_activity_unknown` | `evidence` | From the coordinator: the fresh check before a step of an eviction gave no evidence that the producer is inactive. The target is skipped with no call |
| `root_not_local` | `eligibility` | From the filesystem executor: the mount table reports the filesystem of the root of a file target as not local (a network filesystem or an automounter map). The target is skipped with no call ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |
| `root_locality_unknown` | `evidence` | From the filesystem executor: the mount table cannot be read, or it has no mount for the path or the device of the root of a file target. The target is skipped with no call |
| `dataless_object` | `eligibility` | From the filesystem executor: a regular file of a cleanup target is a cloud placeholder (`SF_DATALESS`). A file target is skipped with no call, also for `MoveToTrash` (a dataless directory target gets `dataless_directory`); a directory target with such a file is refused whole at its measurement, or keeps the file when it became dataless later ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |

A plan explanation gives the reason `link_count_unknown` (family `evidence`) for an entry of a rule that skips hard-linked objects when the link count of the entry is not known. The `next_action` values of this build are `none`, `correct_request`, `refresh_observation`, `resolve_authority`, `respect_limits`, `prepare_new_plan`, `query_operation`, and `reconcile`.

The project owner made these decisions on 2026-11-19:

| Subject | Decision |
| --- | --- |
| Transport of the first release | The state-changing actions of the GPUI client use the request queue of the journal, as the CLI does. The client then gets no second mutation path: the coordinator admits and executes each request. The XPC transport of section 9 and the helper transport come later, and they replace the decisions of this subsection when they exist |
| Developer ID | No Developer ID is available yet. A build has an ad-hoc signature only. Developer ID signing, notarization, and each check of a signed peer stay open work, and no document states them as verified |
| Identifier prefix | `dev.po4yka.svalnir` is the one identifier prefix of Svalnir: the bundle identifier of `Svalnir.app` is `dev.po4yka.svalnir`, the code identifiers of the other executables are `dev.po4yka.svalnir.cli`, `dev.po4yka.svalnir.agent`, and `dev.po4yka.svalnir.privileged`, the label of the `LaunchAgent` is `dev.po4yka.svalnir.agent`, and the Mach service of the helper is `dev.po4yka.svalnir.privileged`. A build from before this decision has the label `dev.svalnir.agent`. No compatibility code reads the old label: remove a registration of such a build with `agent uninstall` of that build |
| Milestone order | Milestone 4 starts after Milestone 3 |

The project owner made these decisions on 2026-11-19, after the build of `1ebd777`. Each row gives the decision and what this build does. The rows of the table below and the earlier subsections describe this build:

| Subject | Decision | This build |
| --- | --- | --- |
| Pause, resume, enable, disable with no agent | Both clients write the authority record directly with a compare-and-set, also when no agent holds the coordinator lock. The GUI gets the behavior of the CLI | As this decision. The CLI and the window make the private state directory and the journal for a pause, a resume, and a disable when they do not exist, with one function of `svalnir_agent::client` (`create_state_directory`). For an enable with no journal, both give `no_active_policy_revision` and make nothing. A request of the queue makes neither, and the window refuses each request of the queue with no agent |
| System notifications | The agent posts the system notifications, also while no window runs. The client posts none | The client posts none and has no launch option for them. The agent has the notification port, the rate gate, the bounded queue, and the capability row. The decision of 2026-11-20 below gives the agent a dialog for the urgent kinds (row "System notifications") |
| Privileged helper | The helper has no operation in the first release, and it moves to after the release. Its code stays, not registered and not called. The threats, the families, and the gates of the helper keep their identifiers | As this decision: nothing registers the Mach service, and no component calls the helper |
| Menu bar item | Planned. A research step first examines newer revisions of `gpui-kit` and GPUI for a status item API, with no change to the code; the result decides the method | The research step found no status item API in `gpui-kit` `0.10.0`, its GPUI, or newer revisions, and chose an `AppKit` `NSStatusItem` through `objc2` in the GUI process. The item is built and not validated: the inline capacity grid and the memory pressure state in the menu bar, and a menu with the used space, the pressure, the agent state, the pause state, the pause control of the Automation screen through the same path, Open Svalnir, and Quit Svalnir. With the item, the client continues to run when its last window closes, with no Dock icon while no window is open; `--no-status-item` removes it. Later owner decisions of 2026-11-19: the grid and a pressure dot are drawn in the tones of `DESIGN.md`, not as a template image, with a variant for the light and the dark menu bar and, for the grid, for Increase Contrast; the client leaves the Dock and the application switcher while no window is open; the item is on by default; the client does not start at login in the first release, and a login item is later work ([DESIGN.md](../DESIGN.md) "Implementation state") |
| Rearm control of the GUI | The control reads the open incidents from the controller reading of `observe` | As this decision (row "Rearm") |
| Stop confirmation of the GUI | The confirmation shows each bound target in a list that scrolls | As this decision (row "Stop of an application group") |
| Log location of the agent | `~/Library/Logs/Svalnir/` is the one log location. The `LaunchAgent` definition sends the standard error stream of the agent there | As this decision: the definition that `agent install` writes names `~/Library/Logs/Svalnir/agent.log` (subsection "Milestone 2 build without a socket") |
| Diagnostics | The screen shows two labeled lists: the capability summary of the agent from its status record, and the probes of the window process | As this decision. The list of the agent shows the verdict, the age of the status record, each required capability that the agent does not have, and the notification capability of the agent as one sentence. The probes of the window run with the worker role `window` |
| History in Milestone 3 | History gets a detail view, a filter, and a sort order | As this decision. A row opens a detail below it with the plan, the steps, and the target results. Three filters and a sort order of four columns apply to the read of at most 50 operations, and a caption says so |
| Process table interval | The Memory and Applications screens keep 2 s while the window is in front and 30 s while it is not active. The cost of one read is measured | The intervals are as this decision. The example `process_read_cost` of `svalnir-gui` measures the cost of one read. No measurement is recorded under [VALIDATION.md](VALIDATION.md) |
| Host case of the GUI actions | Authorized, with fixtures only, on the build that has the decisions of this table; the service is removed at the end | Run 3 of [VALIDATION.md](VALIDATION.md) section 14, on the artifacts of `186498a`: 13 cases `passed`, 0 `failed`, 2 `not_run` (enable and disable of a guard, and a stop that waits for admission), and the defects D-8 to D-11. Commit `2e3e6f9` corrects the four defects with regression tests. Run 4, on a debug build of `e02677c` with fixtures: 23 cases `passed`, 0 `failed`, 5 `not_run`, with the two cases that run 3 did not run and the corrections of D-8 to D-11, and the defects D-12 to D-17. Commits `23f9213` and `b7b5390` correct the six defects with regression tests; no host run examined those corrections. The records make no family and no gate pass |

The project owner made this decision on 2026-11-20, after the research step on the notification path of the agent:

| Subject | Decision | This build |
| --- | --- | --- |
| Native notification path of the agent | In the first release, the agent shows a system dialog (`CFUserNotification`) only for the urgent kinds `MemoryPressureCritical`, `IncidentBudgetExhausted`, and `AutomaticOperationNotCompleted`, with a timeout of 60 s. Banners through a nested application of the bundle come after the first release | As this decision, not validated: `notify::DialogCenter` with `CFUserNotificationDisplayNotice` (row "System notifications"). Host run 4 showed the dialog of each urgent kind from a debug build only ([VALIDATION.md](VALIDATION.md) section 14); no run examined an installed agent |

The GPUI client of this build changes state through the journal, on the path of the CLI. The client side is the `svalnir_agent::client` module, which the CLI and the GUI share:

| Subject | Behavior |
| --- | --- |
| Precondition of an action | Before each write, the client checks that `HOME` is the home directory of the account record. A request of the queue opens only an existing journal; a pause, a resume, and a disable make the private state directory and the journal when they do not exist (`client::create_state_directory`, mode `0700`, as the CLI does), and refuse an existing state directory that is a symbolic link, is not a directory, has a different owner, or is open to the group or to other users (`state_directory_not_private`, or `state_directory_not_writable` when it cannot be made). An enable with no journal is refused with `no_active_policy_revision` and makes nothing. It never takes the coordinator lock and is never a transient coordinator. A request of the queue (rearm, cancel, acknowledge, and stop) also needs an agent as the holder of the coordinator lock (`client::agent_presence`): with no agent or with a client as the holder of the lock, the request is not available. With no state directory or with no journal, a request of the queue and a stop plan are not available. An action that is not available writes nothing: no state directory, no journal, no record, and no plan. The principal of a request has the role `ClientRole::Gui` |
| Pause, resume, enable, disable | Automation. Pause for 1 hour, pause until resumed, and resume; enable and disable of a guard. The client makes each change with the grant logic and writes the authority record with a compare-and-set (`client::write_authority`), as `agent pause`, `agent resume`, `policy enable`, and `policy disable` do. The client writes the record also when no agent holds the coordinator lock; it reads the lock only to name the path in the state line: the agent reads the record at its next tick, or the window wrote the record directly. A change that needs no write writes nothing, and the state line says so. The enable confirmation shows the revision in effect and the action classes of the scope, and the request binds them |
| Rearm | Automation, on each open incident of the controller reading of `observe` (generation and usage of each budget). The control is on only while the reading of the window is not stale and the status record of the agent is current (at most 90 s old). Else the control is off, with a caption that names the reason: a stale reading, an old status record, a stopped agent, an unknown status, a failed read, or no rows. The client writes a rearm request to the queue and waits at most 30 s for its completion, as `policy rearm` does |
| Cancel, acknowledge | History. Cancel of an operation that is not settled, and acknowledge of an `UnknownOutcome` operation. The client writes a `Cancel` or an `Acknowledge` request to the queue and waits at most 30 s for its completion |
| Stop of an application group | Applications, on a group that the catalog of hard protections does not protect, as a quit or a force quit. From one process reading, the client makes the candidate of the group with the candidate builder of the memory guard and the stop plan with the plan builder, with the stop durations of `client::manual_stop`. The confirmation lists each process that the sealed plan binds, in a list that scrolls: the process ID, the name, the start time, the user ID, the executable path, the file object, and the signature. It also shows the expiry of the plan. On confirmation, an expired plan is refused and not recorded; else the client records the plan, writes an `Apply` request with the approval of the plan digest, waits at most 10 s for the admission, and then waits for the final record of the operation, at most 5 minutes. A request that the agent does not admit in the 10 s stays in the state Waiting for admission: the window reads the request at each poll, and an admission gives Waiting for exit and a refusal gives Refused. At 30 s after the expiry of the plan the state is Not answered, because the agent refuses an expired plan. The plan binds each verified member of the group, as `processes stop --group` does; the client builds the plan with the same shape as `client::build_manual_stop`. The window has at most one stop confirmation: while one is open, each stop control is off, and the row of its group says why. The state of the last stop shows in a row below the group, with a Details button that opens the full state line |
| States of a control | Sent, Accepted, Waiting for admission, Waiting for exit, the final state of the operation (Exited, Partial, Incomplete, No action, Failed, or Unknown outcome, with the operation-state name of the journal), Exit not confirmed, Not answered, Refused with the error code, and Unavailable with the cause |
| System notifications | The client posts no system notification and asks for no notification permission. The agent has a `Notifier` port (`svalnir_agent::notify`) for these notices: the memory pressure state becomes critical, a guard starts an automatic operation, an incident budget is exhausted, an automatic or a requested operation does not complete, and a requested application stop has its final record. A rate gate (one post for each tag in 15 minutes, six posts in 10 minutes) and a queue of eight notices bound the posts, and one worker thread calls the notification center. The center of the agent is `notify::DialogCenter` (decision of 2026-11-20): for the three urgent kinds only, it calls `CFUserNotificationDisplayNotice` on the worker thread with the note alert level and a timeout of 60 s. The call sends the request and returns at once; it does not wait for the user. The dialog has the header "Svalnir:" and the title of the notice, one sentence for the kind, and the default button; it has no path, no process argument, no process name, no environment value, and no secret. The service does not queue the other kinds: it counts them as `not_presented` before the rate gate, so they take no place of the gate or of the queue, and they are not posted. A native call that returns a value that is not 0 is counted as `failed` and is not tried again. The dialog needs no authorization and asks for none, so the notification capability is `available` with the detail "Dialog for urgent notices, no banner" in the status record, in the `doctor` row `agent_notifications`, and on Diagnostics. The agent shows no banner: the User Notifications framework does not deliver notifications for a launchd agent that runs from an executable inside the application bundle. A debug build with the feature `test-support` has no dialog, so that no test shows one, and its capability is `unsupported`; only when `SVALNIR_TEST_DIALOG_KIND` names an urgent kind does it have the dialog center and offer one fixture notice of that kind at its start, for a host check. Host run 4 showed the dialog of each urgent kind from the ad-hoc signed debug agent with that trigger, started directly, on one host; the dialog is not validated |

These points are open in this build:

- The approved roots of a manual operation are the roots that its sealed plan binds, so an agent executes a manual cleanup plan of the request queue, and a transient coordinator executes a request of a different client. The coordinator applies the catalog of protected file locations to each file target of a plan at admission, with the home directory and the state directory of its own process ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 4). An agent and a client with different state directories thus each protect their own. An automatic operation acts only under the roots of the rule declarations, which the agent resolves before it applies an automatic plan.
- Each reviewed rule is in the `proposed` lifecycle state, so no command and no guard evicts data under a rule: the `evict` mode refuses each rule, the candidate source of the agent examines no rule, and the agent has no approved root. The path from the discovery to the removal runs only in the fixture tests, with a lifecycle state that only a test build can give. A promotion needs the record and the host procedure of [VALIDATION.md](VALIDATION.md) section 13.
- The disk guard starts a discovery only in the warning band with no open disk incident. An agent that starts while a volume is below `reclaim_below` has no known candidate and evicts nothing until a sample is in the warning band ([POLICY_SPEC.md](POLICY_SPEC.md) section 9). Whether the guard starts one bounded discovery in that state is a decision of the project owner.
- This build reads no configuration of a producer. A custom DerivedData location of Xcode has no root, and the rule finds nothing for it ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 4).
- After the unit `Build/Intermediates.noindex` of a project is evicted, the other units of that project have an unknown activity and are not candidates until a build makes the build database again ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 11). Whether the revision keeps this property is a decision of its promotion.
- The fresh check before a step of an eviction reads the process evidence of the producer. It does not read the lock of the build database again, and the inventory does not see a process of the user whose identity query the system denies.
- `--scan` with the `evict` mode is accepted and not read. Whether the command refuses it is not decided.
- The catalog of protected file locations of `svalnir-core` has the locations that `docs/CLEANUP_RULES.md` section 5 lists. It does not have each directory of OS-managed storage, for example the system databases below `/private/var/db`. A location that is not in the catalog has the protection of the `[protections]` table and of the filesystem executor only.
- The `svalnir-agent` executable is beside the `svalnir` executable in each release artifact: in `bin/` of the binaries archive and in `Contents/MacOS` of `Svalnir.app`. `scripts/package-layout.sh` has this layout contract, `packaging/README.md` has its text, and `scripts/check-artifacts.sh` fails for an artifact that breaks the layout. The service commands accept only that location. A registration names the path of the executable with no symbolic link, so a moved installation needs `agent install` again. No command reports a definition that names a path with no file. No install, upgrade, or uninstall of an artifact was run on a host ([ARCHITECTURE.md](ARCHITECTURE.md) section 14).
- These points of the packaging are decisions of the project owner: whether the binaries archive keeps `svalnir-gui` and `svalnir-privileged`; whether the helper stays in `Contents/MacOS` when it gets a registration; whether a second job of the release workflow, with the certificate in a protected environment, signs the executables that the build job made; whether a command sets the state directory aside for a build that refuses its version, or the user moves it by hand; whether the first release has an installer package or a disk image; and whether a release has an Intel or a universal build.
- The reading of the coordinator lock that takes no lock uses a property of macOS: `fcntl` with `F_GETLK` reports a lock that `flock` holds. A test holds the property on the host of the build, and the host records of [VALIDATION.md](VALIDATION.md) section 14 have it on macOS 27.2.1. On a system without it the reading gives "free", and a start then finds the lock held. A request that no process serves is reported with `coordinator_stopped`.
- A rearm is refused while the controller record shows an unknown outcome of the incident (`incident_outcome_unknown`), and an acknowledgment of the operation (`operations acknowledge`) does not change that record. Whether an acknowledgment resolves the unknown outcome for a rearm is a decision of the project owner ([POLICY_SPEC.md](POLICY_SPEC.md) section 14).
- A step of an earlier lifetime whose dispatch was consumed and for which the reconciliation records no result holds the leases of its operation also when the operation is not `UnknownOutcome` ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 12). `operations acknowledge` refuses such an operation (`operation_not_unknown_outcome`), so only a reconciliation that settles it releases the leases. Whether an acknowledgment also covers it is not decided.
- A test build of the client has no service host of the system and no Trash of the system: a test that sets none gets a host and a Trash that refuse each call.
- The service manager calls of `agent install` and `agent uninstall` have the host records of [VALIDATION.md](VALIDATION.md) section 14, of one host with macOS 27.2.1. There, `launchctl bootout` of a service that is not loaded gave status 3, `launchctl print` gave status 113 for a service that is absent, and `launchctl bootstrap` directly after `bootout` gave status 5. On the build of `fe7e702`, the wait of `agent install` until a query reports the service as absent worked for three installs while the service was loaded. Status 3 of a query was not seen on a host. A service with the label `dev.svalnir.agent` of an earlier build stays registered after `agent uninstall` of this build.
- The screens of the GUI read the host in their own process. The client links the agent library and reads the host through the same `svalnir_agent::observe` functions as the CLI, the memory and process collectors, and the capability probes. It reads the authority record, the standing of each guard, the latest operations (at most 50) with their resource observations, the status record of the agent, and the size of the journal through a read-only open of an existing journal: that open runs no migration, sets no journal mode, and refuses a journal whose schema version is not the current one. It applies the page limit of the writer, which SQLite keeps for each connection and not in the file, so the size limit that Diagnostics shows is the limit of the agent. It changes no byte of the journal file and creates no state directory and no journal. SQLite can create the empty `-wal` and `-shm` files of a journal in WAL mode when they do not exist. Only an action writes to the journal (the table above).
- The screens do not read the coordinator lock; only an action reads it, before its write. The GUI shows the age of the status record of the agent in place of a running state: a record that is younger than three status intervals (90 s) is evidence of a recent agent, not proof that one runs now. A record with the run state stopped shows a stopped agent at each age.
- The actions of the GUI have the tests against a temporary journal with a test thread in the role of the agent, the fixture tests, and one host run with fixtures on the artifacts of `186498a` ([VALIDATION.md](VALIDATION.md) section 14, run 3). In that run, pause, resume, the stop of a fixture application, and the cancel of a stop ran against a running agent; enable and disable of a guard and a stop that waits for admission did not run, and the keyboard operation and the accessible labels were not examined. Run 4, on a debug build of `e02677c` with fixtures, ran enable and disable of a guard with no agent, a stop that waits for admission, and a cancel of a running stop with the agent running, and did not examine the keyboard operation and the accessible labels. In run 3, no system notification was posted: the client posts none, and the agent of that build had no native notification center. The window links the User Notifications framework through the GPUI platform crate and opens a client of the notification center at launch, which the system refused in that run; the window posts nothing.
- The urgent dialog of the agent was shown on one host only from a debug build: in run 4, the ad-hoc signed debug agent, started directly with `SVALNIR_TEST_DIALOG_KIND`, showed the dialog of each urgent kind within 1 s; it closed after 60 s with no click and before the timeout on OK. No run examined that a launchd agent of `Svalnir.app` or of the binaries archive shows it, a release build, an incident of the controller, or that a return value that is not 0 occurs. The Apple reference of `CFUserNotificationDisplayNotice` states that the function returns at once and states no thread requirement; the research step of 2026-11-19 found that a launchd agent can use it (Apple Developer Forums threads 804854 and 728836). A host run needs its own authorization of the project owner. The User Notifications framework does not deliver for a launchd agent, and a bare executable, as in the binaries archive, has no bundle for it, so the agent shows no banner and requests no notification permission. A nested `LSUIElement` application in `Svalnir.app/Contents/Library/`, with its own bundle identifier below `dev.po4yka.svalnir`, can post banners for the agent; it comes after the first release (decision of 2026-11-20), and whether it asks for the authorization with a prompt or uses a provisional authorization is not decided.
- The agent cuts its log file to zero at 8 MiB, so the records before a cut are lost. Whether the agent keeps them in a second file, which needs the agent to open the log file itself, is a decision of the project owner. The size bound was not examined under `launchd`.
- These points of the stop and the cancel are decisions of the project owner:
  - The executor checks the identity of each member of a group (process ID, start time, executable, and owner) again before its call, and not its membership in the instance. A member that leaves the instance and keeps its generation is still signaled. The GUI and the CLI have the same behavior. Whether a membership check at the signal is necessary is not decided.
  - When the agent does not answer a cancel in the wait, `operations cancel` writes the stop fence itself, and the GUI shows Not answered and writes nothing. Which of the two behaviors both clients have is not decided.
  - The cancel wait for the agent is 10 s in the CLI and 30 s in the GUI. One value for both is not decided.
  - `--timeout` of `operations cancel` bounds the wait for the agent, and the wait for the operation to settle (at most 2 s) follows it. Whether the contract of `--timeout` permits this is not decided.
  - The wait for the admission and the wait for the exit of a stop in the GUI use the wall clock, so a clock that is set back keeps the control busy longer. Whether these waits use a monotonic bound is not decided.
- The Memory, Applications, and Automation screens show the readings of the agent records for a client. The window reads them as one topic while one of these screens is in front: `observe::read_agent_records_at` reads, on a read-only open of the journal and with no query of the coordinator lock, the status record with its freshness, the controller state, and the pause. The status record is current when it is at most 90 s old (`observe::STATUS_MAX_AGE`, three status intervals); else the reading is stale, and the screens add a caption with the age and keep the rows. `observe::read_controller` gives the application budgets, each cooldown with its status at the clock of the client, and the usage of each budget generation of each open incident; the stored record has no live qualification window, and the trigger state of a budget comes only from the status record. `observe::pause_reading` gives the pause status of the grant logic at the clock of the client, which is the decision of the agent: both read the same system-wide monotonic clock and boot identity, and the agent keeps no pause outside the authority record. Whether the agent has a measurement that is newer than the end of a pause is not in the journal, and the reading gives it as not known (`PauseUnknown::FreshMeasurement`). In `svalnir-core`, `policy::explain_hard_protection` gives the catalog entry of a hard protection, which Applications shows below the protection, and `Threshold::typed_value` gives a threshold with the unit of its configuration field, which Automation shows. `policy::configured_protections` gives the entries of `[protections]` and `[memory_guard]` that match an instance; no screen shows them. No source exists for the growth of a footprint in the agent: the agent stores no series of process samples, and the window derives the growth from its previous and its current process snapshot (`platform::process::derive_between`), so the first reading and a new process have no value. No source exists for the restart history of an application: Svalnir does not start an application again, a relaunch is not recorded, and Applications says so. The tests of the mapping build a temporary journal with an authority record, a status record, a controller record, and an operation (`crates/svalnir-gui/src/data/live_records.rs`). The controller values `held_until_recovery`, the outstanding automatic plan, and `clean_stop` are not shown. Whether 90 s is the bound of a stale status record or a configuration value, whether Applications shows the stop history of the journal in place of a restart history, whether these values are shown, and whether the growth needs a longer window, which needs a stored series of process samples in the agent, are decisions of the project owner.
- The GUI starts a folder-size scan only on a request of the user, waits for the first memory pressure reading, refuses the scan while the state is not normal or the reading is stale, and writes no scan record to the catalog. The CLI and the GUI therefore do not share scan results.
- The build has no FSEvents consumer, and the first release has none (owner decision of 2026-11-20). [ARCHITECTURE.md](ARCHITECTURE.md) gives the discovery that the agent uses. The FSEvents invalidation is the first item of Milestone 4.
- [RESOURCE_MODEL.md](RESOURCE_MODEL.md) defines no storage categories, and the scanner reports none. A storage breakdown is by directory until the resource model defines them.
- The graceful request of an application member goes through Launch Services. For a helper process of an application, which Launch Services does not register, the graceful step is skipped with `application_not_registered`.
- The privileged helper has the helper side of the protocol of section 10 and no caller: no agent has an XPC client, nothing registers the Mach service, and no rule needs a root-executed step. The build has no team identifier, so the helper verifies no peer and refuses each message with `helper_peer_unverified`. It has no privilege grant and no durable record store, so it submits no removal call. Each behavior that needs a Developer ID signature, a registration as a launch daemon, or a run as user 0 is not verified.
- The helper has no operation in the first release (owner decision of 2026-11-19). No specification has the storage format of a `PrivilegeGrant`, the approved roots, or the administrative enrollment flow. These points of the helper are decisions of the project owner for the release that adds it:
  - Whether the helper boundary needs the handshake of section 9. The code has none: each request has its protocol version, and the role comes from the verified code identity.
  - The format and the path of the durable record store of the helper in root-owned storage.
  - Whether `svalnir-agent` depends on the `svalnir_privileged` library for the message types, or the `request` and `response` modules move to `svalnir-core`.
  - Whether the team identifier of the peer requirement is a compile-time environment value (`SVALNIR_TEAM_IDENTIFIER`, as the code has it) or a checked-in file.
  - Whether the limit of 16 penalized messages in 10 s for one user is accepted: a process of a user can stop the helper service for the agent of that same user for 10 s.
  - Whether one message at a time is accepted: a status query waits for a step in work, and section 9 asks for reserved control capacity.
  - Whether `fstatfs` on the open root is sufficient for the locality check of the helper, or the helper must compare the mount table before the open, as the filesystem executor of the agent does ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7).
  - Whether the fixed ownership rule of the helper executor is the intended rule, or the grant must state the owner ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7).

## 5. Manual approval and standing authorization

Preparing or displaying a plan is observational. Applying it requires authorization bound to its immutable ID, digest/identity, mode, target set, expiry, and relevant revisions. The digest has the form `sha256:` and 64 lowercase hexadecimal digits; [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 2 defines its content. An apply request names the plan ID and the digest that the client reviewed.

Interactive clients show that scope and the material consequence before recording approval. Noninteractive clients use `--yes` or an existing grant explicitly covering that application mode and scope. The client retrieves the server's immutable plan and binds the approval to it; a bare confirmation flag is not a substitute for the plan.

A standing grant may supply consent only within its defined scope. A guard's automatic incident authority cannot be repurposed into arbitrary manual deletion. Once a standing guard is enabled with its required grants, ordinary eligible incidents proceed without incident-by-incident prompts.

Code signing identifies the connecting executable; it does not prove human intent. A same-user process can invoke the genuine CLI. This interface therefore preserves helper ceilings and the threat model's explicit limitations rather than treating `--yes` as a protected human-consent channel.

`--force` in process control selects an explicit force strategy. It does not mean “ignore protection.” Hard protections, global/manual exclusions, target identity, and helper limits remain effective. Guard-specific automatic settings do not independently prohibit separately authorized manual actions.

The convenience command `processes stop --target ID`, or `processes stop --group INSTANCE_ID` for the verified members of one application or managed-job instance, performs prepare, inspect/authorize, and apply through the same services. It retains its plan and operation identities through retries. A lost apply reply must never cause it to prepare a second plan and repeat termination automatically.

## 6. Proposed workflows

Uppercase IDs are placeholders for identifiers that Svalnir returns. The examples do not authorize a contributor, an automated agent, or a test runner to run them against a live host.

```sh
svalnir doctor
svalnir status --format json

svalnir scan "$HOME" --save
svalnir report --scan SCAN_ID
svalnir clean plan --scan SCAN_ID --mode trash
svalnir clean plan --scan SCAN_ID --mode trash --entry ~/Library/Caches/com.example.app
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
svalnir policy enable memory-guard --accept-application-exit
svalnir agent pause --for 1h
svalnir agent resume
```

A timed pause ends at its expiry on the monotonic clock of the boot and the clock domain in which it started; a change of the wall clock does not end it. After a reboot, or in a different clock domain, the end of the pause cannot be established, because the wall clock can be wrong after a boot. The pause then stays in effect until `agent resume` ([POLICY_SPEC.md](POLICY_SPEC.md) section 14), and the pause status has `status` `paused` and `basis` `retained`, with no `until` and no `remaining`.

Activation compares the expected revision. Each enable request binds the revision that the user reviewed: an interactive enable flow presents the revision in effect and binds the revision that it presented, and a noninteractive mutation must name the reviewed revision explicitly. A request that names no revision is refused; the revision in effect is never bound in its place. A conflict requires renewed evaluation, not a silent overwrite.

`--accept-force-quit` accepts the request for an application exit and the force quit. A memory guard whose revision does not permit a force quit needs the acceptance of the request for an application exit only, which `--accept-application-exit` gives. An enable with no acceptance flag accepts no action class, so it is refused with `acceptance_mismatch`. The result of `policy enable` names the acceptances that the grant records (section 4, row `policy enable`). A stop result has no acceptance flag.

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
| `129`, `143` | A client that executed an operation as a transient coordinator stopped on `SIGHUP` or `SIGTERM` (section 4) |

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
| Live peer connections of the helper | 2 per user; 32 in all |
| Penalized messages of one user at the helper | 16 in 10 s |

Decoded allocations, total clients, per-field lengths, scan concurrency, aggregate buffers, and helper concurrency also require finite release limits. The handshake advertises effective limits, bounded by compiled/server policy; clients cannot request an unlimited value.

Paginate or reject an oversized response instead of bypassing limits. Rate-limit repeated malformed requests and expensive diagnostics. Reserve control capacity so a full observation queue does not indefinitely prevent cancellation or revocation. Admission must fail before an effect if its required bounded state cannot be retained.

## 10. Helper boundary

The first release has no privileged helper (owner decision of 2026-11-19, section 4). This section is the contract of the helper for the release that adds it. The code of the helper side exists, and nothing registers or calls it.

The helper receives a supported delegated step with its parent operation, authenticated principal, exact action type, grant generation, resource scope, target evidence, deadline, and deduplication identity.

The helper binds each delegated step to the user and the login session of the caller that it accepted. Neither value is a field of the request; the transport supplies both from the live connection. The helper refuses a request with no login session (`helper_login_session_missing`). For a recorded step, a status query, a repeat, and a request with a different content from another login session of the same user get one refusal (`helper_login_session_mismatch`). The refusal has no state and no content of the step, and it is the same for a repeat and a different content. It is a refusal and not `helper_step_not_recorded`: the helper must refuse an eviction request for a recorded step identity in any case, so a "not recorded" answer to a query would hide nothing. A step of an earlier login session, for example after a restart of the host or a logout, thus cannot be queried. The agent keeps such a step as `UnknownOutcome` with its leases, and `operations acknowledge` releases them ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) sections 11 and 12).

It independently resolves and validates the authority-bearing parts. Agent-supplied paths, measured pressure, rule labels, approval flags, catalog rows, and budget claims cannot widen a `PrivilegeGrant`.

No method accepts arbitrary shell text, script bodies, caller-chosen executables, unrestricted root paths, or an untrusted database as authoritative state. A denied user-level operation is not automatically retried as root.

Helper replies identify the delegated step, observed state, recording durability, native result/evidence, and remaining uncertainty. If the reply is lost, the agent queries that step's status. A new transport request ID does not make its external effect executable again.

Administrative enrollment/expansion is a distinct reviewed flow bound to concrete scopes and OS-backed authorization. Credentials and transient authorization material are not placed in user configuration, journals, or diagnostics.

Service installation/removal uses Svalnir's own supported registration path. It is not an arbitrary launchd editor. Client-local diagnostics can explain a missing agent, but cannot assert that a non-running worker successfully passed its resource-access probes.

The helper side of this boundary is in code, and it is not validated (section 4 has its open points). The helper has two operations: `evict_entries`, the permanent removal of listed entries below one approved root of the grant, and `query_step_status`, which has no effect. `MoveToTrash`, `DeleteSelectedFiles`, each process operation, and the grant enrollment are not operations of the helper.

The helper transport is a Mach service with the name `dev.po4yka.svalnir.privileged`. A request is one XPC dictionary with one entry: the key `request` and a data value with the JSON form of the request. The reply dictionary has one entry: the key `response` and a data value with the JSON form of the response. The decoder of the request is strict: it rejects an unknown field at each level and a value that is not in its canonical encoding. The helper boundary has no handshake in this build: each request has its protocol version, the helper has one caller role, and a peer has that role only when the platform verified its code identity as the identity of the agent.

A response has one of three bodies. `step` has the recorded state of the step, whether this request consumed it (`this_request`) or the record had it (`record`), the durability of the record, the result of each entry, and the error of the step as a whole. `refused` has the error of a request that the helper decoded and refused; such a request consumed no step. `rejected` has the error of a message that the helper did not decode or of a peer that the platform did not verify; it names no step. The result of an entry has the fields of a target record of [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 9 and the position of the entry in the request.

The helper refuses a peer whose code identity the platform did not verify (`helper_peer_unverified`) before it decodes the message. A build with no signing identity verifies no peer.

After 16 messages of one user in 10 s that are not requests or that come from a peer that is not verified, the helper handles no message of that user until the 10 s are complete. The limit is for a user and not for a connection, because an XPC client connects again after the helper closed its connection. The helper handles one message at a time.

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

A duplicate apply of the same valid plan returns its admitted operation or known rejection. Different content under an existing operation/step identity is rejected. At the helper boundary, the content of a delegated step is its correlation, its validity window, and its operation; the transport `request_id` is not a part. Only a repeat with the same content, and thus the same `issued_at` and `expires_at`, returns the recorded state of the step. A repeat of the same step with a different validity window is different content, and the helper refuses it with `helper_conflicting_duplicate`. After a lost reply, the agent thus repeats the original request unchanged or sends a status query (section 10). Consumption retention covers request validity; expired historical IDs are never accepted as fresh instructions.

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

A document whose `[protections].excluded_paths` list replaces the default gets one warning `personal_folder_not_protected` in the envelope `warnings` (on stderr in the text format) for each personal folder of the default list that the list does not protect ([POLICY_SPEC.md](POLICY_SPEC.md) section 12), from `config validate`, `config show`, and `config apply`. The comparison is of the path components, with ASCII case ignored; a path that starts from `/` is compared through the home directory of the client. A warning does not make the document invalid.

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
