# Svalnir Validation Plan

**Status:** Design specification. The repository contains the Milestone 1 build and the Milestone 2 libraries and commands, with the unit and fixture tests of their modules. Those tests are not recorded evidence for a validation family or a release gate, and no release is validated. Every release gate below is initially **unverified**.  
**Last reviewed:** 2026-11-16

This document defines the evidence required to implement, change, and release Svalnir. It connects the [resource model](RESOURCE_MODEL.md), [interfaces](INTERFACES.md), [policy specification](POLICY_SPEC.md), [action contracts](ACTION_CONTRACTS.md), and [cleanup rules](CLEANUP_RULES.md) to the boundaries in [ARCHITECTURE.md](ARCHITECTURE.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

A passing documentation review does not validate filesystem confinement, process targeting, XPC authentication, permissions, or crash recovery. Those claims require evidence from the relevant implementation and platform.

## 1. Validation objectives

Validation must establish that Svalnir:

- Reports measurements with correct units, scope, provenance, identity, and uncertainty.
- Admits an action only under the current applicable authority and policy.
- Keeps targets and effects within the approved scope and finite limits.
- Remains responsive while collecting data, waiting for applications, or handling faults.
- Distinguishes submitted work, verified effects, resource improvement, and incident recovery.
- Preserves consumed budgets and unknown outcomes across supported recovery paths.
- Exposes consistent behavior through CLI, GPUI, and background operation.
- Includes usable automatic cache eviction and authorized force termination in its first release.

These objectives require positive and negative cases. Demonstrating that a fixture disappears or a process exits is insufficient without also showing that excluded neighbors, replacement identities, and unauthorized callers remain unaffected.

## 2. Evidence status and scope

Use explicit result states in case records:

| Status | Meaning |
| --- | --- |
| `not_run` | No qualifying execution exists for the identified revision and environment |
| `passed` | Expected assertions passed, with recorded fixture, environment, and evidence |
| `failed` | An assertion failed or the observed behavior violated a contract |
| `blocked` | A missing environment, capability, dependency, or unresolved issue prevented the intended check |
| `excluded` | The combination is explicitly outside the declared release support scope |
| `waived` | A named owner accepted a specific nonessential gap, with rationale, limits, and expiry |

“Skipped” in a test runner must be classified; it is not a pass. A waiver records missing evidence and does not convert it into a demonstrated guarantee. Required first-release automatic eviction, application-budget intervention, force termination, and their safety boundaries cannot be waived away while describing the product as satisfying that release scope.

A release gate remains unverified until its required cases pass for the declared support matrix. An optional adapter may remain disabled or excluded. A known control failure blocks the affected feature or release; renaming it a residual risk is not a substitute for correcting a violated contract.

Results are scoped to the source revision, built artifact, configuration, adapter revision, and environment actually exercised. A pass on an unsigned development binary does not establish the behavior of a signed installed helper.

## 3. Layers and responsibilities

| Layer | Main purpose | Suitable environment |
| --- | --- | --- |
| Pure domain and policy | Types, arithmetic, decisions, incidents, ordering, and invariants | Portable Rust tests with injected inputs |
| Contract and persistence | Encoding, plan lifecycle, journal transitions, replay, and migration | Temporary state with deterministic failure hooks |
| Native adapter | Actual filesystem, process, collector, and callback semantics | Disposable fixtures on supported macOS |
| Signed integration | Peer identity, helper ceilings, permissions, service lifecycle, and packaging | Isolated macOS installation with release-like signing |
| Product workflow | CLI/GPUI parity, background behavior, accessibility, and outcomes | Installed application using controlled fixtures |
| Performance and endurance | Finite overhead, responsiveness, growth, and sustained stability | Recorded hardware/workload matrix |

Prefer the cheapest layer that can prove the changed behavior, then add higher layers for properties that mocks cannot establish. Native and signed integration remain necessary where the platform boundary is part of the claim.

Tests should target contracts rather than reproduce implementation steps. Use independent expected values, fixture manifests, model transitions, and recorded external effects. A test that calls the same helper twice to calculate its expected answer is weak evidence.

## 4. Fixture and harness requirements

Each mutating test owns a disposable root or application set. Its fixture manifest records root identity, mount context, created objects, expected protected objects, process generations, and cleanup responsibilities.

The harness must:

1. Establish containment and ownership before admitting an operation.
2. Reject missing, substituted, or unexpectedly broad fixture roots.
3. Track fixture processes by generation and direct ownership rather than display name.
4. Apply finite allocation, file-count, runtime, and subprocess limits.
5. Preserve useful failure artifacts without exposing real user data.
6. Remove only resources that the harness can still identify as its own.

A random directory name is not sufficient containment evidence. Harness cleanup must obey its own identity and scope checks; failed tests must not fall back to a broad recursive delete or name-based process kill.

Use injected observations for ordinary low-space and critical-memory tests. Simulate storage failures through the journal/backend boundary before using a bounded disposable volume in an isolated macOS environment. Never fill a developer's actual disk, exhaust the host's RAM, or terminate unrelated applications to generate pressure.

Actual volume-full tests require a bounded storage target and an independent host-capacity guard. A sparse image alone is not a guarantee that host storage cannot be exhausted. Host service registration, permission changes, cross-user tests, and privileged installations belong in explicitly controlled test environments.

Test fault hooks must not become production IPC methods or environment switches that bypass authentication. Validate that release artifacts exclude privileged test-only entry points.

## 5. Reproducible traces and state-model checks

Policy and coordinator tests should consume event traces with explicit identities, observations, clock advances, policy/grant revisions, dispatch results, and restart boundaries. Retain the random seed and minimized failing trace for generated tests.

Core invariants include:

- No external effect without applicable authority, valid target evidence, and sufficient admission capacity.
- No dispatched step is issued again through retry, reconnection, or another client.
- Consumed automatic incident usage never decreases through ordinary policy reload, trigger change, relaunch, or restart.
- A reservation is refunded only when trustworthy evidence establishes that no external submission occurred.
- A stale or missing measurement cannot clear an incident or authorize a dependent action.
- An open incident does not independently authorize its next step.
- New target members and rule revisions cannot enter an immutable plan.
- A settled result preserves known effects and uncertainty instead of manufacturing rollback.

Use scheduler barriers around admission, final validation, dispatch consumption, native submission, and result recording. Explore meaningful interleavings rather than relying only on long randomized sleeps. Repeat observed race failures deterministically where the backend permits it.

Model tests can establish consistency of the proposed state machine. They cannot prove that an OS operation atomically binds a previously checked file or process identity; document the actual native guarantee and remaining race window separately.

## 6. Stable validation families

The following IDs are stable traceability anchors, not existing Rust test names. Individual implemented cases may append a descriptive suffix, such as `VAL-03.lowered-ceiling`. Keep retired IDs reserved so historical evidence remains interpretable.

### VAL-01 — Resource representation and accounting

Cover every released metric against [RESOURCE_MODEL.md](RESOURCE_MODEL.md): source, unit, scope, quality, timestamp/epoch, aggregation basis, and unavailable reason. Validate checked conversions, boundary values, signed deltas, overflow, zero, and unavailable values separately.

Disk fixtures include hard links, sparse files, clones where supported, open-but-unlinked files, partial scans, and shared APFS capacity. Verify that logical size, allocated size, `work_bytes`, estimates, Trash bytes, and observed capacity are not conflated.

Memory fixtures distinguish RSS, attributed footprint, compression, swap occupancy, swap activity, and ordinary page activity. Counter reset, zero elapsed time, sleep/wake, process replacement, and missing members invalidate rates or qualification as specified.

Compare native results with an independent adapter or known fixture property using matched source semantics and timestamps. Activity Monitor is useful context, not a universal exact-value oracle. Do not require process totals to exactly equal system memory or infer memory reclaimed from a process's previous footprint.

### VAL-02 — Policy parsing, activation, and qualification

Parse valid and invalid configuration, checking units, overflow, duplicate IDs, unknown keys, unsupported schema versions, threshold ordering, finite limits, and template resolution. Test revision conflicts between CLI and GUI and failure to persist an expansion or restriction.

Exercise sampled qualification at exact threshold boundaries, one sample, repeated cached samples, excessive gaps, contradictory samples, and collector restarts. Confirm fast sampling begins for an application-budget episode even when global pressure is normal.

Disk continuation must use its recovery threshold after admission; interrupted continuation requalifies for the specified duration. Memory escalation must stop when its current critical or application-stop predicate clears, although the incident remains latched.

### VAL-03 — Incident budgets and cooldowns

Generate overlapping global-critical and application-budget episodes under one principal. Demonstrate one shared `MemoryIncident` allowance, one slot for a graceful-plus-force intervention, and another charge for a newly dispatched intervention.

Changing trigger, PID, profile, policy revision, or client cannot replenish consumption. Lowering a ceiling computes the new remaining allowance from consumed and reserved usage. Manual actions use separate finite limits and can influence recovery observations without spending or refunding automatic usage.

Exercise per-rule, batch, pass, and incident disk ceilings; oversized indivisible candidates; zero-byte entries; no-effect backoff; cache regrowth; and pass cooldowns. Rearm must be a recorded authorized budget-generation change, not an implicit retry path.

### VAL-04 — Plans, admission, and result aggregation

Use two clients to prepare/apply/query the same plan concurrently. Verify immutable targets and revisions, one admitted operation, single-use steps, payload mismatch rejection, expiry, bounded queues, and reservation release only when submission is disproved.

Cover every aggregate result: `Completed`, `NoAction`, `Partial`, `Incomplete`, `Failed`, and `UnknownOutcome`. Include verified effects mixed with already-satisfied targets, a submitted graceful request stopped while its target remains alive, and uncertainty mixed with known successful removals.

A lost reply must lead to a status query or reconciliation, not another effect. A convenience CLI command must retain its original plan identity across apply transport retries instead of silently preparing a second plan. A resource improvement does not establish that the planned operation completed.

### VAL-05 — Filesystem confinement and rule promotion

For each exact rule revision and supported layout, construct genuine disposable content beside excluded and misleading content. Exercise custom/shared roots, protected descendants, unknown types, unexpected symlinks, hard links, ancestor/final-entry replacement, mount changes, ownership changes, and concurrent growth.

Test producer activity and quiescence assumptions, including a writer that ignores cooperative locks. Svalnir's own sealing marker must not be treated as proof against another same-user process. Unsupported confinement conditions must inhibit unattended action.

Verify fixed candidate sets and exact revision binding. New entries cannot enter an admitted recursive operation. Failed Trash must not become permanent deletion. Permission denial must not trigger a root retry. Disabling an unsafe revision must inhibit its pending work while preserving history.

### VAL-06 — Process identity and escalation

Use disposable GUI applications and managed child processes that can exit, refuse graceful requests, delay exit, show a test save prompt, allocate bounded memory, spawn known members, and relaunch under a controlled supervisor.

Exercise already-exited targets, PID/generation replacement, ambiguous membership, shared services, foreground transitions, hard protections, grace deadlines, force authorization, and independent exit observation. No name/group wildcard may become the targeting boundary.

Inject pressure or pause changes during graceful wait. Check that later force dispatch stops when required, with an honest `Incomplete`, `Partial`, or unknown result. Reconnection cannot restart the grace timer. A native call's accepted return does not replace verified exit.

### VAL-07 — Persistence, crashes, and volatile recovery

Validate intent, consumption, budget, and outcome records in each executor's own journal. The agent's durable record cannot stand in for the helper's.

Inject failure before/after every persistence and dispatch boundary described in section 7. Cover database-full, temporary-storage-full, sync errors, corrupt/incompatible state, bounded WAL growth, checkpoint contention, and result-write failure.

The volatile exception must require pre-incident authorization, fresh sustained global critical pressure, eligible targets, remaining allowance, and independent helper permission where applicable. Reject it for filesystem work, manual operations, and an application-budget operation relabeled during execution.

Crash after volatile consumption; old-epoch requests remain rejected, and unknown incident usage remains exhausted until the specified observed recovery/new incident or authorized rearm.

### VAL-08 — IPC peer and principal isolation

Run actual signed client/server combinations: permitted product identity, wrong product identifier under the same signer, wrong signer, invalid/unsigned peer, wrong user/session, unsupported role, and wrong server identity. Test observation endpoints with privacy-bearing access as well as mutation endpoints.

Invoke the genuine signed CLI from an untrusted same-user process and demonstrate that it still cannot exceed helper ceilings. This validates the limited identity boundary rather than pretending executable signing proves human intent.

Verify failure paths of the selected supported peer API. Apple requires the NSXPC code-signing requirement to be set before connection resume and describes malformed-requirement failures; test those configuration paths in the actual native bridge. [Apple API contract][xpc]

### VAL-09 — Grants, protections, and revocation

User-writable configuration, catalogs, plans, and approval flags must not create or broaden `PrivilegeGrant`. Exercise concrete administrator-approved principal/scope binding, grant generations, expiry, and stale requests across an existing connection.

Test hard protections, global `[protections]`, automatic guard exclusions, mandatory rule exclusions, and manual plan authorization separately. An automatic-force preference cannot serve as manual force consent or accidentally prohibit an independently valid manual request.

Pause/revoke after intent but before native submission, during graceful wait, and between file units. Distinguish durable acknowledgement, non-durable current-instance inhibition, and already-issued effects. An unpersisted restriction must not be reported as surviving restart.

### VAL-10 — CLI, configuration, IPC, and GPUI contracts

Use the same fixture state to compare CLI JSON, GPUI views, local API results, policy reasons, and history. Presentation may differ; identity, authority, units, quality, and effects must agree.

Validate exact integer string encoding, null-plus-reason unavailability, bounded pages, unknown fields, schema/protocol negotiation, and rejection of incompatible mutation payloads. Unknown read enum/state/unit values remain unsupported or unknown; they must not map to zero, normal pressure, or completed execution. Read compatibility must not weaken strict handling of authority-bearing input.

Exercise NDJSON sequence/epoch continuity, slow consumers, explicit gaps, resynchronization, snapshot high-water boundaries, reconnect, and expired cursors. A publication snapshot/barrier concerns the agent's published state; it must not claim atomic sampling of all kernel resources. If overflow prevents delivering a trustworthy gap marker, invalidate or disconnect the stream rather than continuing with silent loss. Validate stdout/stderr separation and exit-status semantics in [INTERFACES.md](INTERFACES.md), including status-query success that contains a failed operation, accepted asynchronous work, unresolved waits, and client interruption without implicit cancellation.

GPUI checks include keyboard operation, accessible labels, focus, selection stability during updates, and loading/error/unavailable states. No native wait may block its event thread.

### VAL-11 — Lifecycle and permission degradation

Test clean start, agent-only operation with both clients closed, wake, logout/login, collector restart, helper interruption, disabled background items, and explicit uninstall. Verify backoff and that a user-disabled service is not silently re-enabled.

Grant and revoke permissions for the actual installed agent/helper identities. Terminal access is not a substitute. Exercise available, denied, unsupported, and unknown resource capabilities, including changes between a successful probe and action.

Record which OS/hardware combinations support each capability. Missing a particular optional metric must not crash unrelated observation; missing evidence required by an action must inhibit that action.

### VAL-12 — Multiuser coordination and leases

Run isolated user sessions against shared capacity with separate histories and policies. Verify principal isolation, no other-user inventory leakage, no cross-user process selection, and the required host lease broker for shared-resource automation.

Exercise simultaneous plans, broker loss, executor crash, lease expiry, and successor acquisition. Outstanding work must be reconciled before conflicting dispatch. Expiry or a fencing generation cannot be treated as canceling a native call already issued.

Test quota/reserve-aware trigger scope separately from shared APFS capacity. Cleaning another volume must not be reported as addressing a constrained metric without the required evidence.

### VAL-13 — Privacy and presentation

Seed fixtures with sensitive-looking filenames, control characters, unusual Unicode, long strings, and secret sentinels in process arguments/environment. Verify ordinary logs, history, JSON, notifications, and exports follow their documented collection and redaction scope.

Verify local/offline operation and absence of default telemetry using the built artifact's observable behavior. Diagnostic export must be explicit, bounded, and reviewable; redaction is not tested as a promise of anonymity.

Terminal escaping must not alter machine-readable identity data or allow names to inject output controls. Partial coverage, stale evidence, force escalation, and unknown outcomes must remain visible rather than disappearing behind a success label.

### VAL-14 — Parsing, concurrency, and native boundaries

Fuzz bounded IPC/configuration/state decoders, candidate metadata, path-display encoding, and arithmetic conversions. Combine malformed and oversized fields with partial records, unknown enums, version mismatches, duplicate identities, and adversarial collection counts.

Use structure-aware corpora and semantic oracles where plain byte fuzzing would rarely reach the boundary. Keep input/time/memory limits on fuzz harnesses themselves. The Rust Fuzz Book documents `cargo-fuzz`; any adoption must be pinned and integrated with reproducible corpora. [Tooling reference][fuzz]

Review every unsafe/FFI boundary for ownership, lifetimes, thread affinity, callback cancellation, exception/error translation, and resource release. Apply compatible dynamic tools to the code they can actually execute. A portable sanitizer or interpreter result is not proof that a macOS framework interaction was exercised.

### VAL-15 — Resource budgets and endurance

Measure the agent, helper, and GUI separately and together. Cover idle, ordinary collection, large inventory, fast sampling, simultaneous pressure, cancellation, slow subscribers, repeated reconnect, long-running history, and rule regrowth.

Assert configured caps on queues, work units, retained samples, database/WAL growth, and exports. Measure latency while an application waits to exit. Confirm that emergencies do not launch a full scan, hashing job, or compaction.

Numeric release budgets and measurement conditions must be approved before evaluating release results. Section 10 defines the required record; this document asserts no benchmark outcome.

### VAL-16 — Packaging, upgrades, and artifact integrity

Validate the installed signed artifacts, privileged paths, service registration, entitlements, protocol compatibility, and removal using release-like packaging. An unsigned developer run does not satisfy this family.

Exercise upgrades with pending plans, incomplete operations, reduced storage, revoked grants, and older binaries reading newer state. Preserve exclusions and consumed usage; reject incompatible state instead of discarding it or assuming rollback undid prior actions.

Verify build provenance, pinned dependencies/lockfile, required license/source/notice materials, and absence of test-only privileged APIs. Changed signing identities or helper interfaces require renewed affected integration evidence.

## 7. Crash-boundary matrix

A fault harness must distinguish whether external submission is known to have occurred. Crashing at an application-code checkpoint and cutting power exercise different failures; neither should be reported as the other.

| Injection boundary | Required observation after recovery |
| --- | --- |
| Before intent commits | No normal dispatch; no manufactured completed effect |
| After intent, before consumption | Reconcile reservations; do not assume old intent still authorizes execution |
| After consumption, before native call | Never replay automatically; release usage only with trustworthy proof of non-submission |
| During native call or before its return | Preserve unknown/partial effects; no blind timeout retry |
| After effect, before result commit | Recover available evidence or retain uncertainty; never target a replacement |
| After helper consumption, before agent receives reply | Query helper state; do not issue the step again |
| During policy/grant revoke persistence | Distinguish durable revocation from current-instance inhibition |
| During volatile intervention, then executor restart | Reject old epoch; unknown budget cannot replenish during continuing pressure |

SQLite settings, VFS behavior, and actual storage errors must be part of the persistence record. WAL `FULL` and `NORMAL` have different durability behavior; macOS sync configuration is a separate concern identified in the architecture. [SQLite WAL documentation][sqlite-wal]

A forced process exit tests process-crash recovery. Storage-fault injection tests the modeled fault. Any stronger power-loss claim needs corresponding controlled evidence and stated storage assumptions. Never report mock failures as an exhaustive proof of hardware durability.

## 8. Supported environment matrix

Before release, record the exact minimum and supported macOS versions, SDK, Rust toolchain, GPUI revision, CPU architectures, and distribution channel. Do not infer support from one API's availability or a successful cross-platform build.

Required dimensions include filesystem behavior, install/signing context, privilege availability, per-component permissions, multiple users where supported, and producer versions for promoted cleanup adapters. Distinguish dedicated APFS fixtures, ordinary user roots, protected resources, and explicitly unsupported/network filesystems.

Choose representative combinations for independent concerns and targeted combinations for interacting risks. Do not impose a full Cartesian product on every change. All declared supported combinations still need justified coverage for the features they expose; an untested architecture or layout must not inherit an automatic-rule promotion silently.

Use physical supported hardware for claims that virtualization cannot establish. Record virtualization when used, including its storage and timing limitations.

## 9. Release gates and traceability

Test-family coverage does not imply a gate has passed. These are the only release gates. Section 6 of [THREAT_MODEL.md](THREAT_MODEL.md) states the security evidence that the gates must contain and maps each security area to the families and gates below.

| Gate | Required evidence families | Threats addressed |
| --- | --- | --- |
| G-01 Resource and decision correctness | VAL-01, VAL-02, VAL-03 | T-07, T-08 |
| G-02 Bounded filesystem intervention | VAL-04, VAL-05, VAL-07 | T-03, T-04, T-05, T-10, T-11 |
| G-03 Application control and recovery | VAL-03, VAL-04, VAL-06, VAL-07 | T-06, T-07, T-08, T-10 |
| G-04 Authority and local isolation | VAL-08, VAL-09, VAL-12 | T-01, T-02, T-03, T-13, T-14 |
| G-05 Durable and degraded operation | VAL-07, VAL-11, VAL-12 | T-03, T-10, T-11, T-13, T-14 |
| G-06 Client parity and privacy | VAL-10, VAL-13 | T-09, T-12, T-14 |
| G-07 Native/input robustness | VAL-05, VAL-06, VAL-14 | T-04, T-06, T-09 |
| G-08 Bounded runtime overhead | VAL-03, VAL-10, VAL-15 | T-08, T-12 |
| G-09 Install and release integrity | VAL-11, VAL-16 | T-11, T-14, T-15 |

First-release acceptance additionally requires a complete installed workflow: enable standing policies, close both clients, observe continued monitoring, evict a verified disposable fixture under simulated pressure, enforce a fixture application's budget under normal global pressure, and demonstrate authorized graceful-to-force escalation. Verify history and client parity afterward.

Record any signed fixture build that substitutes observations as a distinct artifact from the shipped build. Its passing workflow validates the controlled decision/execution path, not native pressure detection. The shipped artifacts also require their actual collector, identity, permission, and executor checks; production must not expose a pressure-injection bypass to satisfy the test.

At least a useful reviewed automatic cleanup subset and a validated force backend must pass their applicable gates. An observation-only build is an internal milestone. Optional unvalidated integrations remain visibly disabled and do not borrow evidence from another adapter.

## 10. Performance evidence

Freeze numerical acceptance limits before the release measurement campaign. Every metric records its scope, unit, workload, statistic, duration, and hardware/build conditions.

| Measure | Required evaluation |
| --- | --- |
| Idle CPU and wake activity | Sustained agent/helper cost with clients closed |
| Memory overhead | Footprint/RSS separately, steady-state and peak scan/pressure conditions |
| Disk I/O and state growth | Collector/journal writes, WAL high-water, retention and bounded exports |
| Scan work | Throughput plus peak memory and cancellation latency on representative trees |
| Intervention latency | Trigger detection, qualification, admission, dispatch, and verification as separate intervals |
| Control responsiveness | Pause/query/revoke handling during waits, full queues, and storage faults |
| GPUI responsiveness | Event/render behavior during updates, scrolling, and reconnect |
| Endurance | Trends across repeated incidents, relaunches, idle periods, and history retention |

Record cold/warm conditions and background workload. Use distributions and worst observed relevant cases rather than a single favorable average. Qualification and grace periods are configured delays; do not hide them inside a claimed syscall latency.

A measurement without a predetermined limit is characterization, not a passed performance gate. Regressions require investigation against repeatability/noise; retries cannot discard unfavorable runs without a recorded reason.

## 11. Developer commands and change selection

The command menu is in [CONTRIBUTING.md](../CONTRIBUTING.md#command-menu). Inspect test targets for host mutations before running them; a broad `cargo test` is not permission to install helpers or exercise real cleanup. Cargo's test command can execute unit, integration, and documentation tests. [Cargo reference][cargo-test]

Documentation edits need relevant structural/consistency review. A parser change needs boundary and compatibility cases. Policy changes need deterministic traces; cleanup/process changes need affected native and failure cases; privilege or signing changes need signed integration. Broaden testing for a concrete shared risk or required release gate.

Do not add tests that merely assert the wording of this specification or duplicate an implementation's control flow. Add a regression when it can detect the underlying failure independently.

## 12. Evidence record and triage

Every case or gate record must identify:

```yaml
validation_id: VAL-07
case_id: dispatch_consumed_then_executor_crash
status: not_run
source_revision: null
artifact_digest: null
adapter_revision: null
environment_record: null
fixture_manifest: null
effective_policy_and_grants: null
seed_or_trace: null
expected_assertions: []
observed_results: []
evidence_paths: []
limitations: []
reviewer: null
run_started_at: null
```

Evidence references must resolve to retained logs, traces, artifacts, or reports with their access/retention scope.

On failure, preserve the smallest reproducible fixture and distinguish a product defect, harness defect, unsupported environment, and pre-existing failure. Verify the fix against the failing contract, then run affected neighboring gates. Record flakiness as a problem to explain; a later pass does not erase an earlier unexplained security failure.

Release approval names the artifact and supported scope, summarizes passed/failed/blocked/excluded evidence, and identifies accepted optional gaps. Keep security and performance claims proportional to what the recorded evidence actually demonstrates.

## References

- [Apple: NSXPC peer code-signing requirements][xpc]
- [SQLite: WAL and durability behavior][sqlite-wal]
- [Cargo: test command][cargo-test]
- [Rust Fuzz Book: cargo-fuzz][fuzz]

[xpc]: https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)
[sqlite-wal]: https://www.sqlite.org/wal.html
[cargo-test]: https://doc.rust-lang.org/cargo/commands/cargo-test.html
[fuzz]: https://rust-fuzz.github.io/book/cargo-fuzz.html
