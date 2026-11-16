# Svalnir Action Contracts

**Status:** Design specification. This document defines required behavior for the first implementation; the types and examples are conceptual, not a shipped API or evidence of runtime validation.

**Last reviewed:** 2026-11-16

These contracts connect [policy decisions](POLICY_SPEC.md) and [cleanup rules](CLEANUP_RULES.md) to observable effects. They refine the component boundaries in [ARCHITECTURE.md](ARCHITECTURE.md) and address the threats in [THREAT_MODEL.md](THREAT_MODEL.md). [RESOURCE_MODEL.md](RESOURCE_MODEL.md) defines the identities and resource observations used here, [INTERFACES.md](INTERFACES.md) defines how clients see these states, and [VALIDATION.md](VALIDATION.md) owns the release evidence. A contract applies equally to CLI, GPUI, and background requests.

## 1. Scope and mandatory properties

The initial action surface contains five classes:

| Action class | Intended effect | Normal authority |
| --- | --- | --- |
| `MoveToTrash` | Move explicitly selected filesystem entries through a supported Trash operation | Plan-bound manual authorization |
| `DeleteSelectedFiles` | Permanently remove explicitly selected user-owned entries | Separate plan-bound manual authorization for permanent deletion |
| `EvictRegenerableData` | Permanently remove candidates selected by a reviewed cleanup rule | Manual authorization or an applicable standing automatic grant |
| `RequestApplicationExit` | Ask a verified application or managed job to exit gracefully | Manual authorization or an applicable standing automatic grant |
| `ForceApplicationExit` | Escalate termination, or force an explicitly approved disposable target immediately | Explicit force permission within the applicable authorization |

Graceful and forced termination are separate steps of one application intervention. A cooperative operation that unloads a model or releases another application-owned resource needs a typed adapter and its own completion predicate; it must not be mislabeled as application exit.

Every mutation must bind a concrete target to current authority, reserve its budget, record intent and dispatch consumption, execute a bounded step, and report what was observed. A successful native call, an accepted IPC request, and improved system pressure are different facts.

No action class accepts arbitrary shell text, arbitrary privileged executables, unrestricted recursive-delete paths, or process-name kill selectors. There is no automatic fallback from a narrow operation to a broader one.

## 2. Plans, operations, steps, and epochs

| Identifier | Meaning |
| --- | --- |
| `PlanId` | Server-owned immutable description of the requested effect, its targets, preconditions, estimates, and limits |
| `OperationId` | One admitted application of a plan, including execution, cancellation, history, and reconciliation |
| `StepId` | One bounded executable unit with its own target, dispatch consumption, and outcome |
| `IncidentId` | Policy incident whose budgets and stop conditions govern automatic work |
| `ExecutorEpoch` | One executor lifetime; distinguishes stale in-memory requests and volatile consumption records |

A cleanup operation may contain several bounded candidate steps. An application intervention contains a graceful step and, if authorized, a force step. Neither hierarchy permits silently adding targets.

Plan creation is observational. It does not reserve the target, consume an intervention budget, or authorize execution. A displayed preview may become stale immediately.

A plan can produce at most one admitted operation. Repeating its application returns the existing operation or a rejection; preparing a new plan is an explicit new evaluation, not a retry loophole. A rejected pre-admission request does not make a plan executable after its expiry or invalidation.

Executor restarts invalidate ephemeral prepared requests. An admitted durable operation remains queryable and reconcilable by its recorded identity; it is not executable again simply because a new executor started.

## 3. Immutable request envelope

The executor resolves plan content from trusted local state. A client submits references and expected revisions rather than replacements for paths or target identities.

The conceptual envelope contains:

| Field group | Required contents |
| --- | --- |
| Contract | Schema version, action class, supported adapter/rule version |
| Correlation | Plan, operation, and step IDs; parent operation where applicable |
| Principal | Authenticated user/session and client role derived from the live transport |
| Authority | Effective `PolicyRevision`, `ActionGrant` references/generations, and applicable `PrivilegeGrant` |
| Trigger | Manual plan approval or automatic incident/decision identity; original trigger class |
| Target | Verified file, application, or process identity and exact scope |
| Evidence | Observation provenance, timestamps, validity limits, and relevant boot/mount/executor epochs |
| Limits | Budget reservation, deadline, candidate bounds, grace/verification windows, and allowed escalation |
| Coordination | Required resource domains and current lease ownership |
| Recording | Required durability and whether the critical-memory exception was explicitly admitted |

The authenticated principal cannot be replaced by a UID supplied in a payload. Opaque identifiers correlate records; possession alone does not authorize access.

File bindings include approved root identity, relative entry, volume/mount identity, object type and owner, and available native object identifiers. Process bindings include PID, start identity, UID, executable identity, application/job association, and explicitly attributed members.

Absent native evidence is represented as absent. A path string, bundle name, parent PID, or previously successful probe must not substitute for missing evidence required by the adapter.

## 4. Admission and authorization

Admission is the boundary between a prepared plan and scheduled mutation.

The coordinator must establish all of the following:

1. The client and principal may request this operation and inspect its result.
2. The plan exists, matches the request, is unconsumed, and has not expired.
3. Policy, adapter versions, action grants, and any privilege grant still match.
4. Required capabilities and identity evidence are current.
5. Targets pass hard protections and the applicable manual or automatic eligibility rules.
6. The original trigger remains valid for automatic work.
7. Required budgets, leases, queue capacity, and recording capacity are available.
8. A finite deadline and cancellation path exist.

Manual execution requires authorization bound to the reviewed plan and consequences. An earlier preview or a generic confirmation flag is insufficient. Standing authorization permits eligible automatic intervention without prompting at every incident, but does not make an incompatible rule or broader target valid.

Hard OS and control-plane protections are never overridden. Generic personal-data exclusions govern automatic eviction; deliberate manual selection can address appropriate user-owned files. User exclusions apply in their declared scope: `[protections]` covers manual and automatic actions, guard-specific controls govern their automatic guard, and mandatory rule exclusions apply whenever that rule executes. Changing an applicable exclusion requires a separate policy change. A force flag or applying an automatic preview cannot change these boundaries or switch the action class.

`PolicyRevision` describes behavior; `ActionGrant` authorizes product actions; `PrivilegeGrant` limits helper authority independently. Same-user state is not a protected human-consent channel. The helper must retain its own constraints even when a legitimate signed client submits an undesirable request.

Failed admission returns reasons and issues no external mutation. Transient failure may justify preparing or admitting a later operation; it never converts an expired plan into current authority.

## 5. Budgets and resource leases

Reserve budgets when an operation is admitted. Queued or waiting work holds its reservation so two clients cannot independently spend the same remaining allowance.

An application slot is charged together with the dispatch consumption of the first termination step, before the external call (section 6). Graceful and force steps share that slot; a submitted attempt that fails, times out, or becomes uncertain still consumes it. Reconnecting or escalating does not create another slot. A replacement application generation needs new eligibility evaluation and remains subject to restart cooldowns and incident limits. Automatic global-critical and application-budget interventions share the principal's `MemoryIncident` accounting, so changing triggers cannot reset the allowance. Manual operations use separate finite one-shot limits; they neither spend nor reset automated incident counters.

A reservation may be released when the executor establishes that no external operation was submitted. Once submitted, a native failure or lack of resource improvement does not automatically refund the intervention budget.

Filesystem steps carry `work_bytes`, a known conservative charge or bound supplied by the rule under the accounting convention in [POLICY_SPEC.md](POLICY_SPEC.md). That charge bounds admitted disposal work; it is not physical I/O, estimated reclaimable bytes, or guaranteed capacity gain. Unknown or unbounded work rejects unattended dispatch. Oversized indivisible candidates cannot consume an unbounded remainder. Revalidate changed candidate size before dispatch and skip candidates that no longer fit. Item and time limits apply independently.

Budget consumption and dispatch consumption must be committed consistently within the responsible executor's journal. A helper also enforces its own grant ceilings. Agent counters cannot authorize an over-budget helper action.

Acquire conflict leases for the application generation, cleanup root, and shared capacity domain as appropriate. The host broker coordinates cooperating Svalnir sessions. Leases do not prevent external writers or application relaunch.

Loss of a lease blocks the next step. Lease expiry does not prove an already submitted effect stopped. A successor owner must reconcile unresolved work before conflicting dispatch; it must not rely on a fencing number to cancel an OS call already in progress.

## 6. Execution lifecycle

Use a durable normal path for all initial filesystem mutations, including Trash, and for process intervention by default.

| State | Required meaning |
| --- | --- |
| `Prepared` | Immutable plan exists; no mutation authority has been consumed |
| `Admitted` | Operation, reservations, and executor ownership established |
| `IntentCommitted` | Required intent and budget context are durably recorded |
| `DispatchConsumed` | This exact step is single-use and cannot be submitted by another request |
| `Verifying` | External call was submitted; observe its actual outcome |
| `Completed` / `Partial` / `Incomplete` / `NoAction` / `Failed` | Settled result with per-target evidence |
| `UnknownOutcome` | Evidence cannot establish the effect; reconciliation is required before conflicting retry |

`Prepared` describes a plan and `Admitted` describes an operation. `IntentCommitted`, `DispatchConsumed`, and `Verifying` apply to each step. The settled states apply to a step and, through the aggregation rules in section 9, to its operation. A request that fails admission creates no operation. It is reported as a rejection with reasons (section 4), not as an operation state.

After recording intent and before the external call, consume the step and its applicable budget charge. Immediately before submission, check cancellation, revisions, grant generation, deadline, target identity, protection state, and trigger continuity again.

An open incident does not alone authorize the next step. A latched disk incident may continue bounded eviction toward its recovery threshold while its fresh continuation predicate holds. Memory steps, including force escalation, require the current qualified critical-pressure or application-stop predicate; remaining in an incident's hysteresis band is insufficient. Evidence gaps or wake require requalification without resetting consumed budgets. Plan expiry or a deadline blocks a later step; waiting for graceful exit does not extend either.

If that final check fails, record that no external call was issued. The consumed step remains consumed; releasing a provably unused budget reservation does not reactivate it.

Never hold scheduling locks while awaiting an application, native callback, or storage transaction. Collectors, pause/revoke handling, and operation queries must remain responsive.

The critical-memory exception in section 12 uses explicitly marked volatile intent and consumption. It must never label those records `IntentCommitted` with durable status.

## 7. Filesystem execution

### Shared preconditions

All filesystem action classes require anchored roots, valid object/volume identity, supported file types, applicable ownership, and an adapter whose namespace assumptions are satisfied. The automatic path additionally requires a reviewed regenerable-data rule, minimum age, activity checks, exclusions, supported layout, and rebuilding consequences.

Resolve paths without shell expansion. A display path is not a deletion capability. Avoid following unexpected symlinks, crossing unapproved mounts, or trusting a string-prefix scope check.

Descriptor-relative traversal and identity checks reduce substitution risk; they do not make a later name-based unlink conditional on the previously inspected inode. A rename into quarantine also changes the source before post-move inspection. Unattended mutation requires the tested confinement argument specified in [CLEANUP_RULES.md](CLEANUP_RULES.md), including explicitly accepted residual risks where applicable.

Ordinary user-cache mutation runs as its owner. Initial root deletion is limited to helper-owned data or reviewed administrator-controlled disposable namespaces. A denied user-scope action must not be retried automatically as root.

### MoveToTrash

The plan lists exact selected entries, supported Trash behavior, and the effect to be confirmed. Generic automatic exclusions do not turn a deliberate manual selection of an ordinary personal file into an automatic rule; manual selection remains separately scoped and reviewed.

Use a supported operation and retain its result or resulting item reference when available. If the backend cannot support the target, return an unsupported result. Do not silently permanently delete, copy to an arbitrary fallback location, empty Trash, or expand selection.

Record source and destination evidence without promising automatic restoration. Destination names may differ because of collisions. Moving bytes to Trash must not be counted as reclaimed capacity.

### DeleteSelectedFiles

This manual-only class requires an immutable plan that identifies the exact selected entries and explicitly presents permanent deletion. It does not require personal files to be classified as regenerable, but it still enforces supported namespaces, applicable global/manual exclusions, identity checks, finite work/item/time limits, and durable recording. The executor uses the owning user's privileges; the helper provides no generic root deletion override.

A selected directory must be represented by a bounded, reviewed enumeration protocol. The selection does not authorize newly appearing entries, traversal outside the selected scope, or indiscriminate recursive deletion. Unsupported application-managed data may still require a dedicated lifecycle adapter. Neither an automatic incident nor a failed Trash operation can select this class.

### EvictRegenerableData

The rule defines the smallest supported candidate and executable unit. A folder candidate is not permission to run an unrestricted recursive deletion that discovers new children during execution.

Enumerate bounded units under the approved protocol; revalidate before each unit or specifically justified batch. Skip newly appearing or changed entries. If a rule requires an indivisible native lifecycle operation, the entire operation must fit its bounds before submission.

Record each confirmed removal, skipped item, or uncertain effect. Successful unlink removes a directory entry; storage reclamation can wait for open references. [Apple documents this behavior][unlink]. Capacity measurements remain separate.

Stop before the next unit if the deadline, policy, activity evidence, namespace condition, lease, or budget is invalid. Earlier removals remain performed; the contract provides no transactional rollback.

## 8. Application intervention

An application plan freezes the verified application instance and members to which its selected backend applies. Descendants, similarly named executables, shared services, and process groups are not automatically included.

Hard protected identities include essential system processes and Svalnir's control plane. The initial process-control surface excludes other-user, root, and system targets. Automatic foreground protection is evaluated at each automatic termination boundary. Manual requests enforce their own exact authorization and applicable global/manual protections; `memory_guard.allow_force_quit` neither grants nor independently prohibits manual force quit.

The normal sequence is:

1. Revalidate identity, owner, protection, trigger, grants, and limits.
2. Record and submit one graceful-exit request through the supported backend.
3. Start the configured grace deadline from that submission and observe asynchronously.
4. If the target exits, record the observation and do not escalate.
5. If it remains and the deadline expires, revalidate every force precondition.
6. Submit at most one admitted force step, then observe within the verification window.

Reconnection, unrelated events, or repeated queries must not restart the grace period. An immediate-force disposable-job policy skips the graceful step only when that consequence and target are separately authorized.

An application may decline graceful termination or show a save dialog. Neither response authorizes bypassing the current foreground rule or force policy. If global pressure recovers, an application budget is no longer violated, or required evidence becomes unavailable before escalation, stop further automatic steps according to [POLICY_SPEC.md](POLICY_SPEC.md). An already issued graceful request may still complete.

AppKit's `forceTerminate()` may return before exit and can return false for an already-exited application. Observe exit independently. [Apple's API documentation][force-terminate] therefore supports separate submission, already-exited, and verified-exit outcomes.

For PID-based control, use positive individual PIDs and revalidate start/owner/executable evidence immediately before submission. The documented `kill` interface addresses PIDs and also has broad group forms that these contracts forbid. A preceding check does not produce an atomic signal-to-generation operation. [Source][kill]

Do not chase replacement generations or newly discovered helpers under the old operation. Verify the intended application instance and required members; retain partial or uncertain membership results rather than claiming the entire application tree stopped.

## 9. Outcomes and aggregation

Expose dispatch, target effect, aggregate completion, and resource observation separately.

A target record includes:

| Field | Meaning |
| --- | --- |
| `dispatch` | Not submitted, submitted, or submission uncertain |
| `effect` | Action-specific observed result |
| `evidence` | Native result and observation source/time, including unavailable evidence |
| `attribution` | Whether Svalnir's action is established, merely possible, or not applicable |
| `durability` | Durable, volatile, or persistence failed after an earlier durable boundary |
| `stop_reason` | Cancellation, pause, policy change, cleared trigger, deadline, missing authority, failure, or normal completion |

Action-specific effects include `Trashed`, `Removed`, `ExitVerified`, `AlreadyAbsent`, `AlreadyExited`, `Skipped`, `Refused`, `StillRunning`, and `UnknownOutcome`. These are conceptual variants, not final serialization spellings.

A pre-dispatch already-absent/exited result is a no-op. After a crash, finding the target absent may establish current state without establishing who removed or stopped it. Preserve that attribution uncertainty.

Aggregate as follows:

- **Completed:** at least one step was submitted, all requested final target conditions are verified, and every submitted effect is settled. A mixture of verified actions and already-satisfied no-op targets is allowed; per-target attribution and counts remain explicit.
- **NoAction:** no external mutation was submitted and no execution error needs a failed result; targets were already absent, skipped, or canceled before dispatch.
- **Partial:** some effects were verified but other requested work was skipped, refused, or failed.
- **Incomplete:** work was submitted, no requested effect was verified, and a known intentional stop leaves the target condition unmet without an execution error; for example, an application remains running when cleared pressure prevents force escalation.
- **Failed:** no requested effect was verified and a known failure prevents completion.
- **UnknownOutcome:** at least one submitted or possibly submitted step has an indeterminate effect; retain all known per-target results.

A submitted graceful request that leaves an application running is not `NoAction`. An intentional stop with a known still-running target is `Incomplete`; a verified exit followed by incomplete work on another required member is `Partial`. All pre-dispatch already-satisfied targets produce `NoAction`. Cancellation after a verified removal produces partial completion with a cancellation reason, not a claim of zero effects. Unknown effects take precedence over aggregate completion; a settled error without verified effects takes precedence over `Incomplete` or `NoAction`.

Report resource effects as before/after observations with source, scope, time window, signed capacity delta, pressure state, and quality. A negative delta is valid. Concurrent workloads prevent treating an observed improvement as exact causal reclamation. A completed operation may yield no resource improvement.

## 10. Error and retry taxonomy

Errors describe the failed contract boundary, whether submission occurred, and how to proceed. They must not be reduced to a generic permission failure.

| Error family | Examples | Permitted next step |
| --- | --- | --- |
| Request | Malformed schema, conflicting duplicate ID, unsupported action/version | Correct request; do not mutate |
| Authority | Wrong principal, missing/revoked grant, policy revision mismatch | Resolve authority; prepare a current plan |
| Evidence | Stale sample, unsupported identity, changed target, ambiguous membership | Refresh or inspect; no stale-target retry |
| Eligibility | Protected target, active cache, unsupported layout | Skip; no broader fallback |
| Limits | Budget exhausted, deadline expired, queue full, lease unavailable | Respect cooldown/admission policy |
| Recording | Full database, sync failure, unavailable journal | Stop normal mutation; consider only the exact critical exception |
| Native | Refusal, access denied, unsupported backend, definite no-effect failure | Report; retry only after fresh admission if safe |
| Outcome | Lost reply, interrupted execution, unverifiable effect | Reconcile before any conflicting action |

A native error is not universally proof of no effect. Map each backend's actual semantics; do not automatically retry `EINTR`, timeouts, or connection resets as if nothing happened.

Read-only observations may be retried with bounded backoff. A mutation retry needs either proof of no submission or a new plan after reconciliation, current eligibility, and remaining budget. The new plan cannot be used to evade a cooldown or consume the same approved target indefinitely.

## 11. Deduplication, cancellation, and revocation

### Deduplication and replay

Deduplicate by principal, operation/step identity, and executor context. The same identifier with different action content is an invalid request, not an update.

Record durable dispatch consumption before normal external submission. Duplicate apply/dispatch messages return status and must not create a second native call. Keep consumption records for at least the request's full validity window; after retention expires, reject an old request rather than treating it as new.

Agent and helper maintain their own consumption state. The helper associates a delegated step with its authenticated principal and parent operation. A missing helper reply causes a status query and reconciliation, not a second deletion or signal.

### Cancellation

Cancellation is an operation-scoped request to inhibit future dispatch. The acknowledgement must distinguish:

- A stop request accepted for current-instance processing.
- A persistent stop fence that survives restart.
- A settled result with no step still executing.

A settled canceled result does not imply no earlier effects. A client timeout or disconnect is not cancellation.

Once the executor observes a stop fence, it must not dispatch the next unit or force escalation. An OS call already issued cannot be recalled. Native work may complete after a cancellation request; record its actual outcome.

### Pause, revision changes, and revocation

Pause or revocation invalidates affected future dispatch at the next boundary, including a force step after a graceful wait. Re-enabling a policy does not revive an old consumed step or bypass a new evaluation.

A durable-success acknowledgement requires persistent state first. If persistence fails, inhibit current-instance dispatch and return an explicit non-durable/degraded status. After restart, older durable settings may return; do not claim otherwise.

## 12. Durability, the critical exception, and recovery

### Normal path

Journal records cover principal, authority generations, target evidence, budget reservation/consumption, lease context, dispatch state, native response, and observed outcome. Do not store unnecessary file contents, process arguments, environments, or credentials.

The user executor and privileged helper each persist their own authoritative action records. The agent cannot treat its journal as proof that the helper recorded an intent. If either required recording boundary fails, do not issue the associated external operation.

SQLite WAL with `synchronous=FULL` is the architectural baseline; the actual build, VFS, sync options, and storage-error behavior require validation. WAL with `NORMAL` can lose committed transactions after power failure. [SQLite's WAL documentation][sqlite-wal] describes that distinction.

A database transaction cannot atomically include an external unlink or signal. The journal is evidence for recovery, not an undo log for operating-system effects.

### Explicit critical-memory exception

`allow_volatile_journal_on_critical` is the only planned exception. Admission requires all of the following:

- The option and applicable action/escalation grant were enabled before the incident.
- Fresh sustained global critical-memory pressure satisfies the policy.
- The target remains otherwise eligible and within its budget.
- Durable recording is unavailable and bounded volatile recording is available.
- Any participating helper independently permits the same exception within its own ceiling.

The exception never applies to any filesystem mutation, manual process control, or an operation admitted solely through an application-budget violation. A budget-triggered operation cannot relabel itself critical during execution. Settle the old operation before admitting a fresh critical-trigger plan under the same memory incident; preserve its consumed charge and charge a newly dispatched intervention another slot. Current grants, cooldowns, and the remaining incident allowance still apply.

Record intent, dispatch consumption, and budget consumption together in bounded volatile state before submission. Duplicates remain consumed within that executor epoch; earlier-epoch requests cannot be replayed.

Mark all resulting history as volatile/degraded, and persist it later when possible. If a restart cannot establish that prior incident and budget state were preserved, treat the affected budget as exhausted until fresh observations establish sustained recovery and a new incident, or the user explicitly rearms it. Restart must not replenish an unknown budget during continuing pressure.

### Recovery matrix

| Last trustworthy state | Recovery behavior |
| --- | --- |
| Prepared/admitted, no consumed dispatch | Invalidate stale execution; release only provably unused reservations |
| Durable intent, no consumed dispatch | Inspect consistency; no automatic assumption that execution is still desired |
| Dispatch consumed, no conclusive outcome | Mark unknown; inspect current identity and effects |
| Verified result, result commit failed | Recover available executor evidence; retain uncertainty if evidence was lost |
| Helper reply lost | Query the helper's operation state; do not resubmit the effect |
| Volatile history possibly lost | Reject old-epoch execution and preserve the conservative budget rule |

Reconciliation is observational. A same-path replacement or reused PID is a different target. Never delete or terminate it merely to complete an old operation. Preserve unknown attribution and incomplete history when available evidence cannot settle them.

## 13. Required acceptance scenarios

| Scenario | Required result |
| --- | --- |
| Two clients apply the same plan concurrently | One operation; one dispatch per consumed step |
| Duplicate ID carries different targets | Rejected without mutation |
| Policy/grant changes after intent but before native call | No new submission; accurate unused-reservation handling |
| Pause arrives during graceful wait | No later force dispatch once the pause is observed |
| File entry, parent, owner, or mount changes | Affected step rejected or stopped under the adapter protocol |
| Recursive candidate gains new entries | New entries remain outside the admitted operation |
| Trash is unsupported or fails | No silent permanent deletion |
| Unlink succeeds but capacity is unchanged | Removal recorded; zero/unknown improvement reported separately |
| Target exits before submission or PID is reused | Already-exited/no-op or identity rejection; no replacement target |
| AppKit returns before exit | Submission recorded; completion waits for observation |
| Target becomes foreground or trigger clears before force | Reevaluate and stop escalation where policy requires |
| Graceful request was submitted, target remains alive, and pause stops force | Settled `Incomplete` with known still-running state and pause reason; no false failure or zero-dispatch claim |
| Native call or helper reply times out | No blind mutation retry; reconcile |
| Journal fails before consumption | No normal mutation; only the exact critical exception may be admitted |
| Crash follows consumed dispatch | Unknown outcome handled without replay |
| Repeated restart loses volatile counts | No silent budget reset during continuing pressure |
| Client or subscriber is slow | Bounded delivery; observation and cancellation remain responsive |
| Shared-domain broker disappears | Block future conflicting steps; reconcile outstanding work |

Use disposable filesystem fixtures and child applications, injected clocks and pressure observations, and isolated privileged environments. Runtime validation must establish actual backend semantics, including remaining identity race windows. No test requires destructive operation against the developer's real caches or unrelated applications.

## References

- [Apple: unlink semantics][unlink]
- [Apple: process signaling][kill]
- [Apple: application force termination][force-terminate]
- [SQLite: write-ahead logging and durability][sqlite-wal]

[unlink]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/unlink.2.html
[kill]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kill.2.html
[force-terminate]: https://developer.apple.com/documentation/appkit/nsrunningapplication/forceterminate()
[sqlite-wal]: https://www.sqlite.org/wal.html
