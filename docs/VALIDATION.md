# Svalnir Validation Plan

**Status:** Design specification. The repository contains the Milestone 1 build and the Milestone 2 libraries and commands, with the unit and fixture tests of their modules. Those tests are not recorded evidence for a validation family or a release gate, and no release is validated. Section 14 has the case records of four host runs with fixtures; they make no family and no gate pass. Every release gate below is initially **unverified**.  
**Last reviewed:** 2026-11-19

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

The promotion of a rule layout needs the record of section 13. The fixture tests of the repository run the discovery and the removal with a fixture lifecycle state; no record exists, and each layout of each rule is `proposed`.

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

The nightly workflow runs the tests on GitHub-hosted virtual machines and writes the macOS version, the runner image, and the Xcode version to each job summary; see [CONTRIBUTING.md](../CONTRIBUTING.md#ci-and-releases). These runs are not evidence for a claim that needs physical hardware.

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

The first release has no privileged helper (owner decision of 2026-11-19). The cases of a family that need the helper, for example the helper ceilings of VAL-08 and the `PrivilegeGrant` cases of VAL-09, are `excluded` from the first-release scope and apply to the release that adds the helper. Each family and each gate keeps its identifier.

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

## 13. Rule promotion record and host procedure

[CLEANUP_RULES.md](CLEANUP_RULES.md) sections 2 and 15 own the lifecycle states and the gates of a rule. This section owns the content of a promotion record and the procedure that makes it. No promotion record exists: each layout of each rule is `proposed`.

### What the repository tests show, and what they do not show

The fixture tests of the repository run the path from the discovery of a rule to the removal, with a lifecycle state that only a test build can give: `crates/svalnir-agent/src/rules/eviction_tests.rs` (the discovery, the roots, and the process evidence), `crates/svalnir-agent/src/runtime/tests/eviction.rs` (the disk guard, the coordinator, and the filesystem executor), `crates/svalnir-agent/src/coordinator/tests/protection.rs` (the catalog at admission), and `crates/svalnir-cli/src/evict_tests.rs` (the `evict` mode and its apply). Each test writes its own files in a temporary directory, and its process evidence is a fixture.

These tests are evidence for `VAL-04` and `VAL-05` cases of the code. They are not a promotion record: no test runs a real producer, so no test shows the layout that a producer version makes, the lock behavior of its build system, or that the producer makes the data again.

### Promotion record

A promotion record is a case record of section 12 with `validation_id: VAL-05` and these fields in addition:

```yaml
rule_id: xcode.inactive-derived-data
rule_revision: r1
layout: derived-data-project-v1
lifecycle_target: manual_action_validated
record_id: VAL-05/xcode.inactive-derived-data/r1/derived-data-project-v1/manual
producer_versions: []
host_versions: []
filesystems: []
allow_list_observations: []
gate_results: []
fixture_test_revision: null
residual_risks: []
open_points_closed: []
owner_approval: null
```

| Field | Content |
| --- | --- |
| `record_id` | The text that the `PromotionEvidence` reference of the declaration has. A declaration with a reference that names no record of this document is not a promotion |
| `lifecycle_target` | `inspection_validated`, `manual_action_validated`, or `automatic_eviction_validated`. A record for a later stage has the cases of each earlier stage or names their record |
| `producer_versions`, `host_versions`, `filesystems` | Each producer version, macOS version and build, and filesystem that a case ran on. The promoted layout supports no other combination |
| `allow_list_observations` | For each producer version, the children of each unit that the producer made on the host, and the difference from the allow-list of the revision |
| `gate_results` | One result for each gate of [CLEANUP_RULES.md](CLEANUP_RULES.md) section 15 that applies, with its status of section 2 and its evidence paths |
| `fixture_test_revision` | The source revision at which `scripts/check.sh test` passed, with its exit status |
| `residual_risks` | Each risk that the owner accepts, in the words of the rule documentation |
| `open_points_closed` | Each open point of the rule documentation that the record decides |
| `owner_approval` | The name of the owner and the date. A record with no approval promotes nothing |

The record is a tracked file under `docs/validation/`, and its evidence files are beside it or at a retained location that the record names.

### Host procedure for `xcode.inactive-derived-data`

Only the project owner starts this procedure, on a host that the owner selects. It removes files on that host, so no contributor, automated agent, or test runner runs it without that decision. The procedure uses a dedicated user account, so that the `DerivedData` root has only disposable projects: the rule does not tell a disposable project from a real one.

**Preparation**

1. Make a standard user account for the validation, with no personal data. Log in as that user. Each later step runs as that user.
2. Install each Xcode version of the intended support matrix. Record the output of `sw_vers`, `xcodebuild -version`, `diskutil info /System/Volumes/Data`, and `git rev-parse HEAD`.
3. On a branch, set the lifecycle state of the layout in `crates/svalnir-agent/src/rules/xcode.rs` to the target state, with the `record_id` as its reference. Run `scripts/check.sh`; record its exit status. Build with `cargo build --release --locked --workspace --bins` and record `shasum -a 256` of the `svalnir` and `svalnir-agent` binaries. The branch is merged only with the approved record.
4. Select a state directory for the validation, and use it in each command: `export SVALNIR_STATE_DIR="$HOME/svalnir-validation-state"`.
5. Make two or more disposable Xcode projects outside the `DerivedData` root: an application for macOS and an application for an iOS simulator, each with a unit test target and a Swift package dependency. Do not set a custom DerivedData location.

**Layout record (the allow-list)**

6. For each Xcode version and each project, run a build, a test, and an index: `xcodebuild -scheme SCHEME -configuration Debug build`, the same for `Release`, `xcodebuild -scheme SCHEME test`, and open the project in Xcode until the indexing ends. Close Xcode.
7. Record the children of each unit: `find "$HOME/Library/Developer/Xcode/DerivedData" -mindepth 2 -maxdepth 4 -print`. Compare each child of `Build/Products`, `Build/Intermediates.noindex`, and `Index.noindex` with the allow-list of [CLEANUP_RULES.md](CLEANUP_RULES.md) section 11. A child that the list does not accept is a finding: the list changes in a new revision, or the layout stays `proposed`.
8. Record the content of `info.plist` of each project directory, and whether it is an XML property list with `WorkspacePath` and `LastAccessedDate`.

**Activity (the lock and the process evidence)**

9. With a build in progress (`xcodebuild ... build` of a project that takes more than one minute), run `svalnir clean plan --mode evict --rule xcode.inactive-derived-data --format json`. Expected: no plan, and each unit has `active_producer`. Record whether `build.db` has a `-wal`, `-shm`, or `-journal` file during the build, and whether the lock query finds a lock when no producer process is in the inventory (for this, examine the result with the process evidence of a build that an SSH session of a different user cannot give; record the limit when it cannot be examined).
10. With Xcode open and idle on a project, run the same command. Expected: no plan, `active_producer`.
11. With no producer process, run the same command at once after a build. Expected: no plan, `retention_not_elapsed` for each unit.

**Age**

12. The rule needs 14 days with no change. Use one of these, and record which: wait 14 days with no build; or set the times of the disposable projects back with `find PROJECT_DIRECTORY -exec touch -h -t YYYYMMDDhhmm {} +` and `plutil -replace LastAccessedDate -date DATE PROJECT_DIRECTORY/info.plist`, with a date that is more than 14 days before now. The second way is a fixture change of disposable data; it does not show how Xcode updates `LastAccessedDate`, which step 8 and a wait of one day record.

**Manual eviction (`manual_action_validated`)**

13. `svalnir config apply --config ./config.toml --expected-revision none` with a configuration of `schema_version = 1`.
14. `svalnir clean plan --mode evict --rule xcode.inactive-derived-data --format json`. Expected: one target for each unit of each project, the cleanup root `~/Library/Developer/Xcode/DerivedData`, `discovery.complete` true, and no target for `Logs`, `SourcePackages`, `info.plist`, `ModuleCache.noindex`, or a project directory. Keep the output.
15. Exclusions: put a `.dSYM` directory, an `.xcarchive` directory, a file with a name that the deny-list has, a symbolic link, and a hard-linked file in a unit of one project; make a second plan. Expected: that unit is not a target and has its reason; nothing in it is removed later.
16. Replacement: make a plan, then move one unit away and make a directory with one file at its name; `svalnir clean apply --plan PLAN_ID`. Expected: the question names permanent removal and each target; the replaced unit and its file stay; each other unit is removed.
17. Producer after the plan: make a plan, start a build, then apply. Expected: each target is skipped with `producer_active`, and the build is not stopped.
18. Apply of a plan with no change: `svalnir clean apply --plan PLAN_ID`, then `svalnir history --format json`. Expected: each unit is removed, `permanently_removed` has the count, `moved_to_trash` is 0, and `Logs`, `info.plist`, and the sources stay.
19. Regeneration: build and test each project again with each Xcode version. Expected: each succeeds with no manual step. Record the time of the first build and of the indexing: this is the rebuild cost of the declaration.

**Automatic eviction (`automatic_eviction_validated`)**

20. Read the available capacity of the data volume with `svalnir status --format json`. Write a configuration with the disk guard enabled, `volumes = ["startup-data"]`, `approved_rules = ["xcode.inactive-derived-data"]`, `warn_below` 10 GiB above the available capacity, `reclaim_below` 5 GiB below it, and the other thresholds in the relation that [POLICY_SPEC.md](POLICY_SPEC.md) section 3 gives. Apply it, and run `svalnir policy enable disk-guard --accept-permanent-eviction`.
21. Start the agent in a terminal, with no service: `svalnir-agent --foreground --state-dir "$SVALNIR_STATE_DIR"`. Do not run `agent install`. Expected, from `svalnir agent status --format json`: the disk guard is in the advisory band, and nothing is removed. Wait for two sample intervals, so that the discovery ran.
22. Without a stop of the agent, apply a second configuration whose `reclaim_below` is 5 GiB above the available capacity and whose `recover_above` is above it, and enable the disk guard again. Expected, after `sustain_for`: one automatic operation in `svalnir history --format json` with the disk trigger; the units are removed in the bounds of the batch; the capacity observation of the operation; a second batch only after a measurement.
23. Repeat step 22 with a build in progress. Expected: nothing is removed, and the status has the reason.
24. Stop the agent with Control-C. Expected: exit status 0, and `svalnir agent status` shows a clean stop. Remove the validation user account and its home directory after the record is complete.

**Not in this procedure**

The procedure does not fill a disk, does not change the clock of the host, registers no service, and needs no administrator right. The budget stop, the backoff after a removal with no gain, a restart during an operation, a full journal volume, and a permission failure are cases of the fixture tests; the record names the tests and the revision. A producer version, a macOS version, or a filesystem that no step ran on is `not_run` in the record and is outside the promoted support.

## 14. Host validation records

This section has the case records of four runs on one host of the project owner. Runs 1 to 3 were made under the owner authorization of 2026-11-19: fixtures only, the `LaunchAgent` of the build installed and removed, and only files that the run made moved to the Trash. That authorization excluded each grant, each enabled guard, and each other application. Run 4 was made under the owner decisions 21 to 24 of 2026-11-20: fixtures only, no service loaded, no host setting changed, and a guard enabled only on a fixture state directory where no agent ran. In each run, no automatic action was possible. The records follow section 12. The fields that each record of a run has are in the block of that run; a record of the table gives the fields that differ. A table also records each case of the run that did not run.

The evidence files are command records: the command, the UTC time, the standard output, the exit status, and the standard error. They are on the host of the owner, in the directory `.omc/handoffs/` of the main checkout, which Git ignores. The repository does not keep them, so a contributor cannot read them; each record names this limit. No record has a reviewer.

### Host run 1: build of `3d8d3bb`

```yaml
source_revision: 3d8d3bb3d1871ea1c576adea980c00da9b78e8e4
artifact_digest:
  svalnir: sha256:128d6093f431ee0030a50e1b06a000f03d6b61887c812bdd4c4911476db91b1e
  svalnir-agent: sha256:fe9883bcf261e8afbfc637e356bc6d3355f1bc24042b2be39e053033578443a6
adapter_revision: svalnir.process.darwin 1; svalnir.filesystem; macos.process
environment_record: macOS 27.2.1 (26B131), Mac16,7, Apple M4 Pro, 14 cores, 48 GiB, Aqua session, System Integrity Protection enabled; cargo build --locked, dev profile, not signed, not packaged; memory pressure warning and 43.9 GiB of used swap during the run
effective_policy_and_grants: built-in template (schema_version 1), activated only where a manual plan needed a revision; no grant; no guard enabled; default state directory for the installed agent
seed_or_trace: null
reviewer: null
run_started_at: 2026-11-19T04:32:11Z
evidence_paths: [.omc/handoffs/m3-host-validation-done.md, .omc/handoffs/m3-host-validation-evidence/]
limitations: [one host, one run, debug build, not signed, label dev.svalnir.agent of the build before the identifier decision, evidence not tracked]
```

| `validation_id` | `case_id` | Case of the run | Status | Observed results |
| --- | --- | --- | --- | --- |
| VAL-10 | `host_read_only_commands_no_state_directory` | 1 | `passed` | 7 read-only commands exit 0; growth `not_collected` and swap rates `not_initialized`, each with its reason; no state directory made |
| VAL-14 | `flock_reported_by_fcntl_getlk` | 2 | `passed` | 4 lock tests passed on the host; between two processes `F_GETLK` gave `F_WRLCK` with `l_pid` -1 while a child held `flock`, and `F_UNLCK` with no holder |
| VAL-11 | `launch_agent_install_observation_mode` | 3 | `passed` | Definition as rendered, bootstrap status 0, the agent holds the coordinator lock, `observation_only` true, no guard enabled |
| VAL-11 | `doctor_reports_installed_agent` | 3 | `failed` | Defect D-2: `service.background_agent` `unknown` while the service ran, because the probe used the prefix `dev.po4yka.svalnir` and the label was `dev.svalnir.agent` |
| VAL-11 | `agent_only_operation_pause_resume` | 4 | `passed` | 10 minutes with no client, `runs = 1`, never exited; pause and resume in the status record of the agent in 1 s |
| VAL-11 | `install_while_loaded_restarts_agent` | 4 | `failed` | Defect D-1: `bootout` 0, then `bootstrap` 5, and the service stayed unloaded; a `bootstrap` 0.34 s later gave 0 |
| VAL-11 | `permanent_start_error_record` | 5 | `passed` | Exit 0, one start-failure record `configuration_invalid` with mode `0600` after two starts; `agent status` and `doctor` show it |
| VAL-11 | `explicit_uninstall` | 9 | `passed` | `launchctl print` 113, no definition file, no agent process, clean stop recorded, state directory kept |
| VAL-11 | `sleep_wake` | S | `not_run` | Needs the owner |
| VAL-05 | `manual_trash_fixture_transient_and_agent_queue` | 6 | `passed` | Fixture manifest: `svalnir-m3-fixture-transient-A.bin` (1048576 bytes) and `svalnir-m3-fixture-agent-queue-A.bin` (2097152 bytes), each with neighbors that did not change. Only the named entry moved, into the Trash of the user; the Trash transfer was not reported as reclaimed capacity; a second apply made no second operation; `evict` was refused for a `proposed` rule. Both executors: a transient coordinator and the agent through the queue |
| VAL-05 | `root_not_local_refusal` | 8 | `blocked` | The autofs mounts were empty and not writable, so no fixture file could be made |
| VAL-06 | `stop_own_child_graceful_and_force` | 7 | `passed` | Fixture child of the run, plain and ignoring `SIGTERM`: wait status 143 for a graceful stop and 137 for a force step after the grace period with the option; `Incomplete`, exit 4, with no force option. A refusal of `/bin/sleep` with exit 3 was seen, and its command record was overwritten, so that assertion has no evidence file |
| VAL-15 | `agent_idle_cost_characterization` | 3 | `not_run` | Characterization only, with no approved limit (section 10): 16.5 s of CPU in 678 s, footprint 7.8 MiB to 20 MiB, RSS 16 MiB to 30 MiB, debug build |

The run found seven defects, D-1 to D-7, in its record. Run 2 shows the correction of each for the case that showed it.

### Host run 2: release artifacts of `fe7e702`

```yaml
source_revision: fe7e702f25ce080e17f9ce6a6e0baa89c4ca9246
artifact_digest:
  svalnir-0.0.0-aarch64-apple-darwin.tar.gz: sha256:6e99d005857d3d744113adfa40614ec0d336a6856d3ab6b23e29ddc1d83f083b
  svalnir: sha256:2bce2f6ba623d52c22ec4f381494e7a1fdbe4a842938fbfaf3d43eef9d2bda94
  svalnir-agent: sha256:9896cd9d6b65cf4468d05ab4ac08dd7233992800fccf36b744bc026ba0ff7983
adapter_revision: svalnir.process.darwin 1; svalnir.filesystem; macos.process
environment_record: macOS 27.2.1 (26B131), Mac16,7, Apple M4 Pro, 14 cores, 48 GiB, Aqua session, System Integrity Protection enabled; rustc 1.100.0; binaries archive of scripts/package.sh, release profile, aarch64-apple-darwin, ad-hoc signature with the hardened runtime, no Developer ID, not notarized; memory pressure normal, warning for some minutes in case 7
effective_policy_and_grants: built-in template (schema_version 1), activated only where a manual plan needed a revision; no grant; no guard enabled; a new state directory with no authority record for the installed agent (SVALNIR_STATE_DIR)
seed_or_trace: null
reviewer: null
run_started_at: 2026-11-19T09:52:09Z
evidence_paths: [.omc/handoffs/m3-host-validation-2-done.md, .omc/handoffs/m3-host-validation-2-evidence/]
limitations: [one host, one run, ad-hoc signature, not installed through an installer, Svalnir.app not used, evidence not tracked]
```

| `validation_id` | `case_id` | Case of the run | Status | Observed results |
| --- | --- | --- | --- | --- |
| VAL-10 | `host_read_only_commands_no_state_directory` | 1 | `passed` | 8 read-only commands exit 0; growth `not_collected` and swap rates `not_initialized`; no state directory made |
| VAL-14 | `flock_reported_by_fcntl_getlk` | 2 | `passed` | 4 lock tests passed; between two processes `F_WRLCK` with `l_pid` -1, and `F_UNLCK` with no holder |
| VAL-11 | `launch_agent_install_observation_mode` | 3, 10 | `passed` | Definition as rendered with the label `dev.po4yka.svalnir.agent`, service running, the agent holds the lock, `observation_only` true, no guard enabled; nothing with the label `dev.svalnir.agent` made |
| VAL-11 | `doctor_reports_installed_agent` | 3 | `passed` | `service.background_agent` "A registration file is present"; its state stays `unknown`, and the row gives the reason |
| VAL-11 | `install_while_loaded_restarts_agent` | 4 | `passed` | 3 installs while the service was loaded, each exit 0 with a new PID and a clean stop of the earlier agent; a direct `bootstrap` after `bootout` still gives 5 |
| VAL-11 | `agent_only_operation_pause_resume` | 4 | `passed` | 10.6 minutes with no client, `runs = 1`; pause and resume in the status record of the agent in 1 s |
| VAL-11 | `permanent_start_error_record` | 5 | `passed` | Exit 0, one record with mode `0600` after two starts; `agent status` and `doctor` show it; `doctor` examines the state directory of the invocation |
| VAL-11 | `explicit_uninstall` | 9 | `passed` | `launchctl print` 113 for both labels, no definition file, no agent process, clean stop recorded, state directory kept |
| VAL-11 | `sleep_wake` | S | `not_run` | Needs the owner |
| VAL-11 | `crash_restart_logout_disabled_item_installed_identity_access` | 13 | `not_run` | Crash and `KeepAlive` restart, logout and login, a login item that the user disabled, and Full Disk Access of the installed agent identity |
| VAL-13 | `agent_log_plain_text_under_launchd` | 3, 9 | `passed` | 48 lines, 0 with a terminal escape sequence, 0 `WARN` or `ERROR`; no secret and no process argument in the log |
| VAL-05 | `manual_trash_fixture_transient_and_agent_queue` | 6 | `passed` | Fixture manifest: `svalnir-m3v2-fixture-transient-A.bin` (1048576 bytes) and `svalnir-m3v2-fixture-agent-queue-A.bin` (2097152 bytes), with neighbors that did not change. Only the named entry moved; the Trash transfer was not reported as reclaimed capacity; a second apply made no second operation; `evict` was refused for a `proposed` rule |
| VAL-05 | `root_not_local_refusal` | 8 | `blocked` | No network filesystem, and the autofs maps had no fixture file |
| VAL-04 | `queued_request_result_has_recorded_observation` | 7 | `passed` | 7 of 7 waited results of queued requests have `resource_effects`; `Incomplete`, exit 4, for a graceful request that the process ignored; a repeated apply returns the first operation |
| VAL-06 | `stop_own_child_graceful_and_force` | 7 | `passed` | Fixture children of the run, plain and ignoring `SIGTERM`, through a transient coordinator and the agent queue: wait status 143 and 137; a force step only with the option and after the grace period; `Incomplete` with no force option; `/bin/sleep` refused with exit 3 and no signal |
| VAL-03 | `rearm_refused_with_no_incident` | 11 | `passed` | The queued request completed as rejected with `incident_not_found` at admission; no `incident_usage` row |
| VAL-10 | `history_and_result_views_agree_with_contract` | 6, 7 | `passed` | The note of `history` agrees with its output; no capacity note on a stop result; `work` null for a client that did not execute the operation |
| VAL-10 | `gui_state_changing_actions` | 12 | `not_run` | The run did not drive the GUI |
| VAL-15 | `agent_idle_cost_characterization` | 3, 4 | `not_run` | Characterization only, with no approved limit: 1.24 s of CPU in 611 s idle, footprint 6.1 MiB to 11 MiB, RSS 16.3 MiB to 25.7 MiB, release build |
| VAL-16 | `release_artifacts_layout_and_adhoc_signature` | Build | `not_run` | `scripts/package.sh` exit 0, and `scripts/check-artifacts.sh` passed. The family needs signed installed artifacts, so this run does not satisfy it |

The run found no new defect.

### Host run 3: GUI actions on the release artifacts of `186498a`

The run drove the window of `Svalnir.app` with fixtures only, under the owner answer "Yes, after the code changes" of 2026-11-19 for the host case of the GUI actions. The window, the CLI, and the agent came from the artifacts of one `scripts/package.sh` run. The fixture application `SvalnirHostFixture.app` (identifier `invalid.svalnir-m3gui.fixture`) was made, started, and waited for by the run, so each stopped process was a child of the run. The run applied the built-in template to a fixture state directory only, because the window builds a stop plan only with a revision in effect; the template enables no guard and gives no grant.

```yaml
source_revision: 186498a7a02a8b6ccad2447f09b0a2a8e23597da
artifact_digest:
  svalnir-0.0.0-aarch64-apple-darwin.tar.gz: sha256:b94218ca444bdda3c9f8c2c3afbddca604cb40267c437fac89adf31e65ab8f60
  svalnir-0.0.0-aarch64-apple-darwin-app.zip: sha256:b5232c4ed4cbf8669d5a57775b7d516ffdada54f97f4689095e98c3c72d9d8a0
adapter_revision: null
environment_record: macOS 27.2.1 (26B131), Mac16,7, Apple M4 Pro, 48 GiB, Aqua session, System Integrity Protection enabled; rustc 1.100.0; release artifacts of scripts/package.sh, ad-hoc signature with the hardened runtime, no Developer ID, not notarized; the window executable of Svalnir.app started directly with SVALNIR_STATE_DIR; memory pressure normal and warning, 57.7 GB of used swap
fixture_manifest: SvalnirHostFixture.app (invalid.svalnir-m3gui.fixture, LSUIElement, ad-hoc signature, 64 MiB of its own memory, option refuse-quit); a state directory with no agent and a new state directory for the installed agent, both in the scratchpad of the run
effective_policy_and_grants: built-in template (schema_version 1) applied to the fixture state directory of the agent; both guards not enabled; no grant; agent in observation mode
seed_or_trace: null
reviewer: null
run_started_at: 2026-11-19T12:35:18Z
evidence_paths: [.omc/handoffs/m3-host-gui-done.md, .omc/handoffs/m3-host-gui-evidence/]
limitations: [one host, one run, ad-hoc signature, not installed through an installer, input through a computer-use tool, keyboard operation and accessible labels not examined, evidence not tracked]
```

| `validation_id` | `case_id` | Case of the run | Status | Observed results |
| --- | --- | --- | --- | --- |
| VAL-10 | `gui_pause_refused_with_no_journal` | N2 | `passed` | With no state directory, the pause of Automation is refused as unavailable with the reason; no file is made |
| VAL-10 | `gui_direct_authority_write_with_no_agent` | N1 | `passed` | With a journal and no agent, pause and resume write the authority record directly; the state line names the path; the CLI reads the same record |
| VAL-10 | `gui_direct_authority_write_after_uninstall` | N3 | `passed` | The same on the journal of the agent after `agent uninstall` |
| VAL-10 | `gui_screens_show_live_data_with_agent` | a | `passed` | Each screen shows live data and no error state while the agent runs |
| VAL-10 | `gui_pause_resume_through_agent` | b | `passed` | Pause and resume from Automation with the path "agent holds the coordinator lock"; the window and the CLI agree on the authority record |
| VAL-06 | `gui_manual_stop_own_fixture_application` | c | `passed` | The dialog lists exactly the verified member of the instance of the fixture application and agrees with the sealed plan; the exit is verified (`ExitVerified`); History shows the detail |
| VAL-06 | `gui_cancel_during_graceful_wait` | d | `passed` | Third try. The fixture refuses the quit request; a cancel from History gives `Incomplete` with `StillRunning` and a durable stop fence |
| VAL-10 | `gui_rearm_control_with_no_incident` | e | `passed` | With no open incident, the rearm control is not offered |
| VAL-10 | `gui_diagnostics_two_lists` | f | `passed` | The "Agent" list comes from the status record and the "This window" list from the probes of the role `window`; defect D-8 |
| VAL-10 | `gui_history_filter_and_sort` | g | `passed` | Filter and sort order on the records of the run; defect D-10 |
| VAL-13 | `no_system_notification_posted` | h | `passed` | No system notification; the `doctor` row `agent_notifications` is `unsupported`. Observation O-5: the window links the User Notifications framework through the GPUI platform crate and opens a client at launch, which the system refuses; the window posts nothing |
| VAL-11 | `agent_log_location` | i | `passed` | The agent writes `~/Library/Logs/Svalnir/agent.log` in plain text with no terminal escape sequence |
| VAL-11 | `explicit_uninstall` | U | `passed` | `agent uninstall` exits 0; proof of removal as in runs 1 and 2 |
| VAL-10 | `gui_dark_theme_reduce_motion` | T | No status | Captured with `--appearance dark --reduce-motion`; only the History capture was examined, so the case has no result and is not in the count |
| VAL-10 | `gui_enable_disable_guard` | — | `not_run` | The revision gives each guard no action class, so the window offers no enable control |
| VAL-10 | `gui_stop_waiting_for_admission` | — | `not_run` | Needs an agent that does not serve the queue; outside the scope of the run |

The count is 13 `passed`, 0 `failed`, and 2 `not_run`; case T is captured only and has no status. No automatic action occurred: the journal of the agent has only the three stop operations and the four requests (three `Apply`, one `Cancel`) of the run. The record makes no family and no gate pass: each family above has required parts that the run did not exercise, for example keyboard operation, focus, and accessible labels for VAL-10, and process identity replacement and force escalation for VAL-06.

The run found four defects:

| ID | Defect |
| --- | --- |
| D-8 | Diagnostics showed the journal size limit as 17.6 TB, the SQLite default page limit of the read-only connection of the window, in place of the 64 MiB limit of the agent. The label "Size of limit" was not clear |
| D-9 | The button row of the stop confirmation was wider than the dialog with a long application name |
| D-10 | In History, the state line of a cancel overflowed the State column and covered the next column |
| D-11 | The sidebar and the status line said "Agent reporting" for up to 90 s after a clean stop of the agent, because the state came from the age of the status record only |

Commit `2e3e6f9` corrects the four defects, each with a regression test: the read-only open of the journal applies the page limit of the writer through one shared function, and the row has the label "Size and size limit" (D-8); a button that fits its container (`ActionButton::fit()`) and a dialog footer that wraps keep the button row inside the dialog ([DESIGN.md](../DESIGN.md) §7) (D-9); the state cell of History wraps inside its cell (D-10; a later change, not examined on a host, limits the row to two lines of the sentence and shows the full line in the detail view); a status record with the run state stopped gives `AgentState::Stopped` at each age, and a running record keeps the freshness rule (D-11). Run 4 examined the corrections.

### Host run 4: debug build of `e02677c` with fixtures

The run used the client, the CLI, and the agent of one debug build with the feature `test-support`, with fixtures only. Each process had a temporary home directory (`HOME` and `SVALNIR_TEST_ACCOUNT_HOME`) and a temporary state directory. No service was loaded and no host setting changed. The run had two passes. In the first, the request for screen control was refused, so the run used window captures, launch options, and the CLI, and nine cases were `blocked`. In the second, after the owner answer "Yes, rerun blocked", screen control was granted, and the run did the nine cases with input in the Svalnir window, the menu of its menu bar item, and its dialog only. The table gives the status of each case after both passes.

```yaml
source_revision: e02677c45139ee67886ff7c347571083ea0c1b22
artifact_digest: null
adapter_revision: null
environment_record: macOS 27.2.1 (26B131), Mac16,7; rustc 1.100.0; debug build of cargo build -p svalnir-agent -p svalnir-cli -p svalnir-gui --features svalnir-agent/test-support --locked (built twice, identical digests); the window executable in an ad-hoc signed bundle dev.po4yka.svalnir, the agent with its linker signature, both started directly; no Developer ID, not notarized; 79 GiB free on the startup volume
fixture_manifest: fourteen fixture roots, each with a home directory (mode 0700) and a state directory, in the scratchpad of the run; disk-requested.toml (profile balanced, disk guard requested with warn_below 2GiB, memory guard not requested) on roots where no agent ran; the template (schema_version 1) on the root of the stop cases; SvalnirRun4Fixture.app (invalid.svalnir-run4.fixture, LSUIElement, ad-hoc signature, 64 MiB of its own memory, option refuse-quit), started twice by the run
effective_policy_and_grants: a revision that requests the disk guard, enabled and disabled with no agent on that root; elsewhere no revision or the template with no guard enabled; no grant while an agent ran
seed_or_trace: SVALNIR_TEST_DIALOG_KIND, one urgent kind for each dialog agent
reviewer: null
run_started_at: 2026-11-20T05:20:05Z
evidence_paths: [.omc/handoffs/m3-host-run-4-done.md, .omc/handoffs/m3-host-run-4-evidence/]
limitations: [one host, one run in two passes, debug build, ad-hoc signature, input through a computer-use tool, fixture data for three rows, keyboard operation and accessible labels not examined, evidence not tracked]
```

| `validation_id` | `case_id` | Case of the run | Status | Observed results |
| --- | --- | --- | --- | --- |
| VAL-10 | `status_item_without_window` | R4-1 | `passed` | With no window, the item shows the capacity grid, the memory pressure, the agent state, and the pause state; the client has no Dock icon; Open Svalnir opens the window; Quit Svalnir ends the client |
| VAL-10 | `status_item_pause_resume` | R4-2a | `passed` | Pause and resume from the item menu with the agent running; the item, Automation, and `agent status` agree; defect D-13 |
| VAL-10 | `gui_and_cli_agree_on_pause_with_agent` | R4-2b | `passed` | A CLI pause and resume with the agent running: Automation and `agent status` show the same state |
| VAL-10 | `enable_refused_with_no_journal` | R4-3a | `passed` | `policy enable` with no state directory exits 3 with `no_active_policy_revision` and makes no file |
| VAL-10 | `gui_pause_with_no_state_directory` | R4-3b | `passed` | With no state directory and no agent, the window pause makes the state directory (mode 0700) and the journal and writes the record directly; resume the same; the CLI reads each state |
| VAL-10 | `private_state_directory_shared_reading` | R4-3c | `passed` | The CLI makes the state directory with mode 0700; the window shows the same pause at its next read |
| VAL-10 | `gui_enable_disable_guard` | R4-4a | `passed` | Enable with a confirmation that names the revision and the action class, and disable, from the window with no agent; the CLI reads each state |
| VAL-10 | `gui_guard_enable_control_and_reading` | R4-4b | `passed` | The window shows a CLI enable and disable at its next read |
| VAL-10 | `gui_stop_waiting_for_admission` | R4-5 | `passed` | With the agent held by `SIGSTOP`, the stop of the fixture application shows "Waiting for admission" with a counter; after `SIGCONT` the agent admits it and the exit is observed; defect D-14 |
| VAL-06 | `gui_cancel_during_graceful_wait_live` | R4-6a | `passed` | Cancel from History of a running stop: a durable stop fence, `Incomplete`; the row shows two lines with an ellipsis, the detail the full sentence; defects D-15 and D-16 seen on the way |
| VAL-10 | `gui_history_state_line_fixture` | R4-6b | `passed` | Fixture data: the same layout |
| VAL-10 | `gui_history_tooltip_on_cut_line` | R4-6c | `passed` | The cut line has a tooltip with the sentence; defect D-17 |
| VAL-10 | `gui_history_no_tooltip_on_short_line` | R4-6d | `not_run` | No line that fits was reachable |
| VAL-10 | `diagnostics_journal_size_label` | R4-7a | `passed` | "Size and size limit: 163.8 KB of 67.1 MB" (64 MiB) |
| VAL-10 | `stop_dialog_buttons_fit` | R4-7b | `passed` | Fixture data and live: the buttons stay inside the dialog |
| VAL-10 | `history_state_cell_fits` | R4-7c | `passed` | Fixture data and live: the state line stays in its column |
| VAL-10 | `agent_stopped_state` | R4-7d | `passed` | After a clean stop, the window shows "Agent stopped" at its next read |
| VAL-10 | `gui_diagnostics_notification_line` | R4-8 | `passed` | The agent list shows "Dialog for urgent notices, no banner"; the window list shows the probes |
| VAL-13 | `urgent_dialog_memory_pressure_critical` | R4-9a | `passed` | The dialog shows within 1 s from the ad-hoc signed debug agent, with the header and one sentence, no path; it closes after 60 s with no click; `doctor` 1 posted, 0 failed |
| VAL-13 | `urgent_dialog_incident_budget_exhausted` | R4-9b | `passed` | As R4-9a |
| VAL-13 | `urgent_dialog_automatic_operation_not_completed` | R4-9c | `passed` | As R4-9a |
| VAL-13 | `urgent_dialog_closes_on_ok` | R4-9d | `passed` | OK closes the dialog before the timeout; `doctor` 1 posted, 0 failed |
| VAL-10 | `gui_light_theme` | R4-10a | `passed` | Automation, Diagnostics, History, Applications, and the stop dialog |
| VAL-10 | `gui_dark_theme` | R4-10b | `passed` | The same screens with `--appearance dark`; the item in the dark menu bar not covered |
| VAL-10 | `gui_increase_contrast` | R4-11a | `not_run` | Needs a system setting |
| VAL-10 | `gui_voiceover` | R4-11b | `not_run` | Needs a system setting |
| VAL-10 | `gui_reduce_motion_system` | R4-11c | `not_run` | Needs a system setting; captures with `--reduce-motion` have no status |
| VAL-11 | `sleep_and_wake` | R4-11d | `not_run` | Needs a host sleep |

The count is 23 `passed`, 0 `failed`, and 5 `not_run` (R4-6d and R4-11a to R4-11d). The first pass alone had 14 `passed`, 9 `blocked`, and 4 `not_run`; the second pass did the nine `blocked` cases and added R4-6d. Three `passed` rows (R4-6b, R4-7b, R4-7c) use fixture data of the client. No automatic action occurred, each stopped process was a fixture application of the run, and no guard was enabled while an agent ran. The dialog `memory_pressure_critical` was shown three times, one more than the two shows that the cases needed, because one closed by its timeout while the access request was open.

The three urgent dialogs of the agent showed on this host from the ad-hoc signed debug agent with its linker signature, started directly with the trigger `SVALNIR_TEST_DIALOG_KIND` of a debug build with the feature `test-support`. The run did not examine the dialog of a release build, of an agent in `Svalnir.app`, of an agent under `launchd`, or of an incident of the controller. The menu bar item was examined on this host in the light menu bar with a debug build of the client in an ad-hoc signed bundle; the dark menu bar, Increase Contrast, and VoiceOver were not examined.

The record makes no family and no gate pass: each family above has required parts that the run did not exercise, for example keyboard operation, focus, and accessible labels for VAL-10, process identity replacement and force escalation for VAL-06, and the dialog of an installed signed agent for VAL-13.

The run found six defects:

| ID | Defect |
| --- | --- |
| D-12 | The sidebar and the status line show "Agent no journal" and "Agent no status", because they join "Agent" and a noun label |
| D-13 | After a resume from the menu bar item, its menu says "Pause request: Accepted" |
| D-14 | In Applications, the state of a stop action ("Waiting for admission" and its sentence) is cut at the right edge of the table |
| D-15 | "Stop…" stays active while its confirmation is open, so a second press opens a second confirmation of the same group |
| D-16 | The Applications row says an operation "ended in the state Partial" when the journal state is `Incomplete` |
| D-17 | The tooltip of a cut History state line is one line and is cut at the right edge of the window |

The run shows the corrected behavior of D-8 to D-11 of commit `2e3e6f9`: D-8 (live), D-9 (fixture data), D-10 (fixture data and live), and D-11 (live).

Commits `23f9213` and `b7b5390` correct D-12 to D-17, each with a regression test, and no host run examined the corrections: the sidebar and the status line show "Agent has no journal" and "Agent has no status record", and the menu bar item keeps its "Agent: VALUE" line (D-12); the line of the last request of the item is named after the last command, for example "Resume request: Accepted" (D-13); the state of a stop is a short state line in a row below the group that spans the table, with a Details button that opens the full line (D-14); the window has at most one stop confirmation, and each stop control is off while one is open, with the reason in the row of the group (D-15); a settled stop names the operation state of the journal, for example `Incomplete` (D-16); and the tooltip of a cut state line has a maximum width of 320 px, and its text wraps (D-17).

### What the records support

Each gate of section 9 stays unverified. A record with `passed` is evidence for its case only, on one host, one macOS version, and one build. The cases are partial evidence for:

- G-02 through VAL-04 and VAL-05: the manual Trash path of the two executors, with no permanent removal and no eviction.
- G-03 through VAL-03, VAL-04, and VAL-06: the stop of a fixture child, the stop and the cancel of a fixture application from the window (also live with the agent running, run 4), and one refused rearm.
- G-05 and G-09 through VAL-11: install, agent-only operation, pause and resume, a permanent start error, the log location, and uninstall.
- G-06 through VAL-10 and VAL-13: the read-only commands, the result views, the log of the agent, and the agreement of the window and the CLI on the authority record and the operations of runs 3 and 4; the menu bar item with no window, its pause and resume, and Quit Svalnir (light menu bar, debug build); the enable and disable of a guard from the window with no agent; a stop that waits for admission; the light theme, and the dark theme by the launch option `--appearance`; the corrections of D-8 to D-11; and the three urgent dialogs of the agent and the close by OK (VAL-13, in part: the ad-hoc signed debug agent with the fixture trigger, started directly).
- G-07 through VAL-14: the reading of the lock only. No fuzzing ran.

They are not evidence for:

- G-01: no policy decision ran against a host incident.
- G-04 (VAL-08, VAL-09, VAL-12): no signed peer, no grant, and one user.
- G-08 and VAL-15: no budget is approved, so the measurements are characterization.
- VAL-07: no crash at a journal or action boundary.
- VAL-16: no signed installed artifact.
- Automatic eviction or automatic application control: no grant existed and each rule is `proposed`.
- The keyboard operation, the focus, the accessible labels, Increase Contrast, VoiceOver, and Reduce Motion as a system setting of the GPUI client; the menu bar item in the dark menu bar and with Increase Contrast; the urgent dialog of a release build, of an installed agent, or of an incident of the controller; and the corrections of D-12 to D-17.
- Sleep and wake, a crash and restart, a disabled login item, and a non-local root.

The evidence files are not tracked. Whether a record with untracked evidence meets section 12 ("Evidence references must resolve to retained logs") is a decision of the project owner.

## References

- [Apple: NSXPC peer code-signing requirements][xpc]
- [SQLite: WAL and durability behavior][sqlite-wal]
- [Cargo: test command][cargo-test]
- [Rust Fuzz Book: cargo-fuzz][fuzz]

[xpc]: https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)
[sqlite-wal]: https://www.sqlite.org/wal.html
[cargo-test]: https://doc.rust-lang.org/cargo/commands/cargo-test.html
[fuzz]: https://rust-fuzz.github.io/book/cargo-fuzz.html
