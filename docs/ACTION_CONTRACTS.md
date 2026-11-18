# Svalnir Action Contracts

**Status:** Design specification. This document defines required behavior for the first implementation; the examples are conceptual, and the types are not a shipped API or evidence of runtime validation. The `action` module of `svalnir-core` has the types of this contract and the serialized spellings that this document fixes. No executor, journal, or coordinator is implemented.

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

The serialized spelling of an action class is its name in this table. The trigger class of a plan is `manual`, `disk_pressure`, `global_critical_memory`, or `application_budget`. `MoveToTrash` and `DeleteSelectedFiles` accept only the `manual` trigger. A `disk_pressure` trigger selects only `EvictRegenerableData`, and the two memory triggers select only the two application classes.

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

One plan has the steps of one filesystem action class, with one step for each target, or it has application steps only. The force strategy of an application plan is `none`, `force_after_grace`, or `immediate_force`. For each application target the steps are, in that sequence of strategies: one graceful step; one graceful step and then one force step; or one force step.

A plan has a content digest: the text `sha256:` and the lowercase hexadecimal SHA-256 of the JSON encoding of the plan content. The JSON encoding is the one that `svalnir-core` writes: the fields in their declared sequence and no insignificant white space. It is a part of the schema version of the plan. The digest covers the action classes, the trigger, the target bindings, the limits with the force strategy and the grace period, the expiry, and the policy, grant, and rule revisions. An approval names the `PlanId` and the digest. A plan whose content does not agree with its digest is rejected.

The expiry of a plan is a monotonic time in one clock domain and one boot. The plan is expired at that time. It is also expired when the clock of the check is in a different clock domain or boot, or is before the time at which the plan was built.

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
| Trigger | Manual plan approval or automatic incident/decision identity and the budget generation of the incident; original trigger class |
| Target | Verified file, application, or process identity and exact scope |
| Evidence | Observation provenance, timestamps, validity limits, and relevant boot/mount/executor epochs |
| Limits | Budget reservation, deadline, candidate bounds, grace/verification windows, and allowed escalation |
| Coordination | Required resource domains and current lease ownership |
| Recording | Required durability and whether the critical-memory exception was explicitly admitted |

The authenticated principal cannot be replaced by a UID supplied in a payload. Opaque identifiers correlate records; possession alone does not authorize access.

File bindings include approved root identity, the absolute path and the native object identifiers of that root, relative entry, volume/mount identity, object type and owner, and available native object identifiers. A file binding of a target that a rule selected also has the rule revision and the producer layout that the rule found for the target; a target with no rule has neither. The plan digest covers each of these values. Thus an approval of a plan is for one place, and the authorization reads the layout of a rule target from the sealed plan and not from its caller. A root path is absolute, has at least one component, and has no empty, `.`, or `..` component: the path `/`, a path that ends with `/`, and a path with `//` are refused when the plan is sealed, as the filesystem executor refuses them. One root identity of a plan has one root path and one root object. An executor acts under a root record only when that record has the root path and the root object of the binding; a different record gives the evidence error `approved_root_mismatch`, and no call is issued.

The schema version of a plan and of a request envelope is 2. Version 2 added the root path, the root object, and the layout to the file binding. A stored plan or envelope of version 1 is refused: it is not decoded, and no absent field gets a default value. A plan is valid for a short time in one boot, so there is no migration. In the serialized form of a file binding, a field with no value is `null`, and a binding with an absent key is not decoded.

Process bindings include PID, start identity, UID, executable identity, application/job association, and explicitly attributed members.

A target has one of three bindings: a file, an application or managed-job instance with its members, or one process. The binding of one process is for a process for which no application or job evidence was found. It has the identity evidence of that process and no member list: a child, a process with a similar name, and a process group are not targets. These rules apply to it in the sealed plan and again in the envelope of each step:

- Only a manual plan has it. A guard selects an application or a job instance and never one process.
- The executor is the user executor.
- No application or job evidence was found for the process. A member of an application or of a job is a target only through its instance, so that the member rules of section 8 apply to it. A process with an association kind or an attribution method that the build does not recognize is not a target of this binding: a different build can know it as a member of an instance.
- The process is a process of the principal, is not a process of root, and is not `launchd`.
- The process has executable evidence, so that an executor can revalidate its identity.
- One process generation is one target: it is not a second target of the plan and not a member of an application target of the plan.

The hard protections of section 8 apply to the one process as they apply to an instance with one member, and only a process with no protection is a target. In the serialized form the kind of this binding is `process`. A reader that does not know a binding kind rejects the plan and does not read the target as a different kind. The plan builder of a manual stop makes this binding only for a candidate of exactly one such process. The step of this binding is one signal to the process ID of the one process, after the revalidation of section 8 for PID-based control; the process has no application request and no helper. Its target result names the process generation as its member.

The envelope of a step repeats the checks of its plan, because it has its own copy of the target: the binding of the target, the trigger identities, and the agreement of the action class with the force strategy and the grace period. An automatic trigger has an incident identity and a decision identity, and a manual trigger has none. The application slot of an automatic step is a slot of the incident of its trigger. A plan or an envelope of the helper executor names a `PrivilegeGrant`, and one of the user executor names none. The initial process-control surface has the user executor only, so an application plan with the helper executor is rejected. The helper condition of the critical-memory exception in section 12 applies when a later surface gives the helper a step of an application intervention.

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

An automatic plan is admitted only with the incident allowance that the controller of the agent holds for the incident of the plan. The allowance is not in the journal and not in a request. Thus an automatic plan that arrives through the request queue of the journal, or that a client applies from a stored plan, has no allowance and is refused with `incident_allowance_missing` (family `limits`). A stored automatic plan gives a client no way to use the standing authorization of a guard.

Failed admission returns reasons and issues no external mutation. Transient failure may justify preparing or admitting a later operation; it never converts an expired plan into current authority.

## 5. Budgets and resource leases

Reserve budgets when an operation is admitted. Queued or waiting work holds its reservation so two clients cannot independently spend the same remaining allowance.

An application slot is charged together with the dispatch consumption of the first termination step, before the external call (section 6). Graceful and force steps share that slot; a submitted attempt that fails, times out, or becomes uncertain still consumes it. Reconnecting or escalating does not create another slot. A replacement application generation needs new eligibility evaluation and remains subject to restart cooldowns and incident limits. Automatic global-critical and application-budget interventions share the principal's `MemoryIncident` accounting, so changing triggers cannot reset the allowance. Manual operations use separate finite one-shot limits; they neither spend nor reset automated incident counters.

A reservation may be released when the executor establishes that no external operation was submitted. Once submitted, a native failure or lack of resource improvement does not automatically refund the intervention budget.

Filesystem steps carry `work_bytes`, a known conservative charge or bound supplied by the rule under the accounting convention in [POLICY_SPEC.md](POLICY_SPEC.md). That charge bounds admitted disposal work; it is not physical I/O, estimated reclaimable bytes, or guaranteed capacity gain. Unknown or unbounded work rejects unattended dispatch. Oversized indivisible candidates cannot consume an unbounded remainder. Revalidate changed candidate size before dispatch and skip candidates that no longer fit. Item and time limits apply independently.

Budget consumption and dispatch consumption must be committed consistently within the responsible executor's journal. A helper also enforces its own grant ceilings. Agent counters cannot authorize an over-budget helper action.

Acquire conflict leases for the application generation, cleanup root, and shared capacity domain as appropriate. The host broker coordinates cooperating Svalnir sessions. Leases do not prevent external writers or application relaunch.

A lease names one conflict domain: a process generation of an application, a cleanup root, a shared capacity domain, or a volume with exclusive free space. A request envelope of an application target has one lease for the process generation of each member; a lease for one member does not cover the envelope.

Budget arithmetic is checked. A reservation, a consumption, or a release that does not fit or that overflows is an error and changes no allowance. A budget change applies at each level (batch, pass, rule, incident, grant, executor) or at no level.

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

A step that has no intent record has the state of its operation, `Admitted`. An operation stays `Admitted` until its target results aggregate to a result state. The serialized spelling of a state is its name in the table. The permitted step transitions are:

| From | To |
| --- | --- |
| `Admitted` | `IntentCommitted`; `NoAction` (canceled or already satisfied); `Failed` (the intent cannot be recorded); `DispatchConsumed`, only for the critical-memory exception of section 12, with the durability `volatile` |
| `IntentCommitted` | `DispatchConsumed`; `NoAction` (stopped before the dispatch is consumed); `Failed` (the dispatch consumption cannot be recorded) |
| `DispatchConsumed` | `Verifying`; `NoAction` (the final check fails and no call is issued); `UnknownOutcome` (a crash or lost evidence) |
| `Verifying` | `Completed`, `Partial`, `Incomplete`, `Failed`, `UnknownOutcome` |
| `UnknownOutcome` | `Completed`, `Partial`, `Incomplete`, `Failed`, only when reconciliation establishes the result; `NoAction`, only for a step whose dispatch state is `submission_uncertain` and for which reconciliation proves that no call was submitted |

Each other step transition is rejected, and a settled state does not change. An operation goes from `Admitted` to each result state, and from `UnknownOutcome` to a settled state through reconciliation.

A state is reported with two more values. The dispatch state is `not_submitted`, `submitted`, or `submission_uncertain`. The durability is `durable`, `volatile`, or `persistence_failed`. `Admitted`, `IntentCommitted`, `DispatchConsumed`, and `NoAction` are `not_submitted`. `Verifying` is `submitted`. `Completed`, `Partial`, `Incomplete`, and `UnknownOutcome` are `submitted` or `submission_uncertain`; a settled state is `submission_uncertain` only when reconciliation settles a step whose submission stays uncertain. `Failed` is `not_submitted` or `submitted`. A submission is recorded only for a step whose dispatch was consumed, so a step that fails before that boundary is `not_submitted`. A recorded submission is not removed; only reconciliation can change `submission_uncertain` to `not_submitted`. `Admitted` is `durable` or `volatile`. A `volatile` or `persistence_failed` record does not become `durable`, and a `durable` record does not become `volatile`. A record that was `volatile` keeps that value when it is written to the durable journal later.

A step with a result state has a minimum of one target result, and the state is the aggregate of those results (section 9). No component writes a result state directly.

The journal records an intent only for a request envelope that agrees with the stored plan of the operation: the target binding, the principal, the trigger, the authority, the executor, and the escalation and grace limits. An envelope that differs in one of them is a conflict and records nothing. A rejection is recorded only for the digest of the stored plan.

After recording intent and before the external call, consume the step and its applicable budget charge. Immediately before submission, check cancellation, revisions, grant generation, deadline, target identity, protection state, and trigger continuity again.

An open incident does not alone authorize the next step. A latched disk incident may continue bounded eviction toward its recovery threshold while its fresh continuation predicate holds. Memory steps, including force escalation, require the current qualified critical-pressure or application-stop predicate; remaining in an incident's hysteresis band is insufficient. Evidence gaps or wake require requalification without resetting consumed budgets. Plan expiry or a deadline blocks a later step; waiting for graceful exit does not extend either.

An executor result whose dispatch state is `submission_uncertain` has no recorded submission, so its step has no `Verifying` record. The coordinator records such a result as `UnknownOutcome` (`effect_not_established`), also when the executor observed a final condition, for example an absent entry. The step goes from `DispatchConsumed` to `UnknownOutcome`, the operation settles to `UnknownOutcome`, and reconciliation can later establish the result.

If that final check fails, record that no external call was issued. The consumed step remains consumed; releasing a provably unused budget reservation does not reactivate it.

Never hold scheduling locks while awaiting an application, native callback, or storage transaction. Collectors, pause/revoke handling, and operation queries must remain responsive.

The critical-memory exception in section 12 uses explicitly marked volatile intent and consumption. It must never label those records `IntentCommitted` with durable status. A step of that exception goes from `Admitted` to `DispatchConsumed` with the durability `volatile`. It does not have the state `IntentCommitted`, which is always `durable`.

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

A file target is one unit: one call removes it, and the executor reads no stop condition during that call. A directory target is one target of the plan and more than one unit of execution: each entry below it is one call. The executor reads the stop conditions (a stop fence, a pause, a changed policy revision or grant, an expired lease or deadline) before each directory below the target and at intervals between the other entries. After a stop it issues no further call. The entries that were removed stay removed, the directory of the target stays, and the result of the target is `UnknownOutcome` with the stop reason of the condition and with the counts of the removed entries and bytes. A stop before the first call of the target gives `Skipped`. The removal of a directory target is thus not atomic, and a stop inside it leaves a part of the tree.

### EvictRegenerableData

The rule defines the smallest supported candidate and executable unit. A folder candidate is not permission to run an unrestricted recursive deletion that discovers new children during execution.

Enumerate bounded units under the approved protocol; revalidate before each unit or specifically justified batch. Skip newly appearing or changed entries. If a rule requires an indivisible native lifecycle operation, the entire operation must fit its bounds before submission.

Record each confirmed removal, skipped item, or uncertain effect. Successful unlink removes a directory entry; storage reclamation can wait for open references. [Apple documents this behavior][unlink]. Capacity measurements remain separate.

Stop before the next unit if the deadline, policy, activity evidence, namespace condition, lease, or budget is invalid. Earlier removals remain performed; the contract provides no transactional rollback. A unit that is a directory is removed entry by entry, with the stop rule of a directory target of `DeleteSelectedFiles`.

## 8. Application intervention

An application plan freezes the verified application instance and members to which its selected backend applies. Descendants, similarly named executables, shared services, and process groups are not automatically included.

Hard protected identities include essential system processes and Svalnir's control plane. The initial process-control surface excludes other-user, root, and system targets.

The catalog of hard protections gives one fact for each application or job instance, and for the one process of a process target (section 3), which is evaluated as an instance with that one member: protected, not protected, or unknown. An instance is protected when one of its members agrees with one of these rules:

| Rule | A member is protected when |
| --- | --- |
| Owner | Its owner is not the principal of the evaluation, or is root |
| `launchd` | Its process ID is 1 |
| Control plane | It is the evaluating Svalnir process or one of its ancestors. An ancestor is identified by its process ID together with its start time |
| Session application | Its bundle identifier is one of `com.apple.finder`, `com.apple.dock`, `com.apple.loginwindow`, `com.apple.systemuiserver`, `com.apple.controlcenter`, `com.apple.notificationcenterui`, `com.apple.WindowManager`, `com.apple.Spotlight`, `com.apple.SecurityAgent`, and `com.apple.coreservices.uiagent`. The comparison ignores ASCII case |
| Svalnir component | Its bundle identifier is `dev.svalnir` or starts with `dev.svalnir.`, or its executable has the file name `svalnir`, `svalnir-agent`, `svalnir-privileged`, or `svalnir-gui`. The comparison ignores ASCII case |
| System executable | Its executable is below `/System/`, `/usr/`, `/bin/`, `/sbin/`, or `/Library/Apple/`, and not below `/usr/local/`. The comparison ignores ASCII case |

A rule can only add a protection. A name, a path, or a bundle identifier never selects a target. A bundle identifier protects also when the membership of the process is not verified.

The application target of a plan is the membership snapshot that the policy candidate has: the same processes and the same membership identity. A candidate whose fact is protected or unknown gives no target, for a manual plan and for an automatic plan. The check of a plan and of a request envelope also rejects a member of another user; that check repeats the owner rule and does not replace the catalog, which needs the control plane of the evaluating process. The executor asks the catalog again for the members of the target at each later boundary. The catalog has application and job instances and the one process of a process target, and no file. The hard protection of a file candidate is a fact that its cleanup rule establishes ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 6).

With no protected member, the fact is unknown when the instance has no member, a member has no executable evidence, an executable path is relative or has an empty, `.`, or `..` component, or the control plane is not known. An evaluation skips an instance of unknown protection. No profile, policy, or grant changes the catalog; a user protection in the configuration is a separate exclusion. Automatic foreground protection is evaluated at each automatic termination boundary. Manual requests enforce their own exact authorization and applicable global/manual protections; `memory_guard.allow_force_quit` neither grants nor independently prohibits manual force quit.

The normal sequence is:

1. Revalidate identity, owner, protection, trigger, grants, and limits.
2. Record and submit one graceful-exit request through the supported backend.
3. Start the configured grace deadline from that submission and observe asynchronously.
4. If the target exits, record the observation and do not escalate.
5. If it remains and the deadline expires, revalidate every force precondition.
6. Submit at most one admitted force step, then observe within the verification window.

In the `force_after_grace` strategy, a force step follows only a graceful step that was submitted and that left the target running: the state of the graceful step is `Incomplete`, `Partial`, or `Failed`, and its dispatch state is `submitted`. A graceful step that is `Completed`, `NoAction`, `UnknownOutcome`, not settled, or `Failed` with no submitted call permits no force step.

Reconnection, unrelated events, or repeated queries must not restart the grace period. A sleep of the host is the one event that starts it again: the time of a sleep gave the application no time to exit, so when the clock continuity changed after the dispatch of the graceful step, the grace period starts at the wake. The force step is thus never earlier than without the sleep. An immediate-force disposable-job policy skips the graceful step only when that consequence and target are separately authorized.

The record of the graceful request that permits a force step is the record of the same operation and of its graceful step. A record of a different operation, or of a different step, on the same target identity permits no force step. A graceful step whose effect is not known needs a reconciliation first: the force step is refused with `reconcile_before_force` and no dispatch is consumed for it.

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
| `stop_reason` | Cancellation, pause, policy change, cleared trigger, deadline, missing authority, skipped target, failure, or normal completion |

A target record of an application can name one member. A record with no member is for the target as a whole.

The action-specific effects are `Trashed`, `Removed`, `ExitVerified`, `AlreadyAbsent`, `AlreadyExited`, `Skipped`, `Refused`, `StillRunning`, and `UnknownOutcome`. The serialized spelling of an effect is its name. `attribution` is `established`, `possible`, or `not_applicable`. `stop_reason` is `COMPLETED`, `CANCELED`, `PAUSED`, `POLICY_CHANGED`, `TRIGGER_CLEARED`, `DEADLINE_EXPIRED`, `AUTHORITY_MISSING`, `TARGET_SKIPPED`, or `FAILED`.

`TARGET_SKIPPED` means that the fresh check before dispatch did not permit this target because of its evidence, its eligibility, or a limit. It is not an execution error. A record with `TARGET_SKIPPED` or `FAILED` has the error of section 10, and no other record has one.

The fields of a record agree with each other. `Trashed`, `Removed`, `ExitVerified`, `Refused`, and `StillRunning` need a `submitted` call. `Skipped` needs `not_submitted`. A verified effect has the attribution `established` or `possible`, and its evidence names the observation source: a verified effect with no observation is rejected. `AlreadyAbsent` and `AlreadyExited` have `not_applicable` before a call and `possible` after a submitted or possibly submitted call. `UnknownOutcome` has `possible`. `Skipped`, `Refused`, and `StillRunning` have `not_applicable`. `Refused` has the stop reason `FAILED`. A target in its final condition (a verified effect, `AlreadyAbsent`, or `AlreadyExited`) does not have the stop reason `FAILED` or `TARGET_SKIPPED`. A record that does not agree with these rules is rejected.

The native result of a record is `not_called`, `succeeded`, `errno` with the error number, `refused`, `unavailable`, or `covered_by_application_request`. A record with `not_submitted` has `not_called`, and each other record has a different value. `covered_by_application_request` is for one member of an application target: no call was issued for that member, because the request to its application covers it. Such a record names its member and has the dispatch state `submitted`. The value states that no native call was issued to the member itself. The request to the application is the graceful request for the member also, so a force step can follow for a covered member that is still running. The value was added after the first form of the record. The record has no schema version of its own: a reader that does not know the value applies the rule for a field value that it does not recognize, and a record with one of the other values is read unchanged.

No effect names a directory target that was removed in part. Such a target has `UnknownOutcome`, the attribution `possible`, and the stop reason of the condition that stopped it (section 7); the entry and byte counts of the removed part are in the work totals of the operation, not in the target record. An effect of its own for a partial removal is not defined: it would be a new value of a serialized field, and a reader that does not know the value reads the record as an indeterminate effect.

A pre-dispatch already-absent/exited result is a no-op. After a crash, finding the target absent may establish current state without establishing who removed or stopped it. Preserve that attribution uncertainty.

Aggregate as follows:

- **Completed:** at least one step was submitted, all requested final target conditions are verified, and every submitted effect is settled. A mixture of verified actions and already-satisfied no-op targets is allowed; per-target attribution and counts remain explicit.
- **NoAction:** no external mutation was submitted and no execution error needs a failed result; targets were already absent, skipped, or canceled before dispatch.
- **Partial:** some effects were verified but other requested work was skipped, refused, or failed.
- **Incomplete:** work was submitted, no requested effect was verified, and a known intentional stop leaves the target condition unmet without an execution error; for example, an application remains running when cleared pressure prevents force escalation.
- **Failed:** no requested effect was verified and a known failure prevents completion.
- **UnknownOutcome:** at least one submitted or possibly submitted step has an indeterminate effect; retain all known per-target results.

A submitted graceful request that leaves an application running is not `NoAction`. An intentional stop with a known still-running target is `Incomplete`; a verified exit followed by incomplete work on another required member is `Partial`. All pre-dispatch already-satisfied targets produce `NoAction`. Cancellation after a verified removal produces partial completion with a cancellation reason, not a claim of zero effects. Unknown effects take precedence over aggregate completion; a settled error without verified effects takes precedence over `Incomplete` or `NoAction`.

These rules decide the cases that the list leaves open:

- When more than one step has a result for one target, or for one member of an application, the last result is the final condition of that target or member. A later record for the target as a whole replaces each earlier record of the target and of its members, and a later record for one member replaces the earlier record for the target as a whole. A force step that is not necessary because the target exited records `AlreadyExited` with no submission.
- A possibly submitted call counts as a submitted call.
- A record with the stop reason `FAILED` is the known failure of the `Failed` rule. A record with `TARGET_SKIPPED` is not: an operation whose targets were all skipped is `NoAction`.
- A record with a field value that the reader does not recognize (effect, dispatch state, attribution, durability, stop reason, or native result) is an indeterminate effect. It is never read as a known result.
- An operation has a minimum of one target record. An operation that stops before its first target records `Skipped` for each target.

Report resource effects as before/after observations with source, scope, time window, signed capacity delta, pressure state, and quality. The capacity delta is the later value minus the earlier value. It has a value only when the two observations have a value and the same scope; an unavailable observation gives no delta, not zero. A negative delta is valid. Concurrent workloads prevent treating an observed improvement as exact causal reclamation. A completed operation may yield no resource improvement.

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

The serialized family names are `request`, `authority`, `evidence`, `eligibility`, `limits`, `recording`, `native`, and `outcome`. The permitted next steps are, in the same sequence, `correct_request`, `resolve_authority`, `refresh_observation`, `skip_target`, `respect_limits`, `stop_mutation`, `report_and_readmit`, and `reconcile`. The next step of a family applies only when no call was submitted. After a submitted or possibly submitted call, the next step is `reconcile` in each family. A family that the reader does not recognize also needs `reconcile`. An error code has lower-case letters, digits, and `_`.

A native error is not universally proof of no effect. Map each backend's actual semantics; do not automatically retry `EINTR`, timeouts, or connection resets as if nothing happened.

Read-only observations may be retried with bounded backoff. A mutation retry needs either proof of no submission or a new plan after reconciliation, current eligibility, and remaining budget. The new plan cannot be used to evade a cooldown or consume the same approved target indefinitely.

## 11. Deduplication, cancellation, and revocation

### Deduplication and replay

Deduplicate by principal, operation/step identity, and executor context. The same identifier with different action content is an invalid request, not an update. For a helper step, the validity window of the request is a part of its content: a repeat with a new validity window is refused as a conflicting duplicate ([INTERFACES.md](INTERFACES.md) section 12).

Record durable dispatch consumption before normal external submission. Duplicate apply/dispatch messages return status and must not create a second native call. Keep consumption records for at least the request's full validity window; after retention expires, reject an old request rather than treating it as new.

Agent and helper maintain their own consumption state. The helper associates a delegated step with its authenticated principal, the login session of its caller, and its parent operation. A request for that step from another login session of the same user is refused, and it gets no state of the step ([INTERFACES.md](INTERFACES.md) section 10). A missing helper reply causes a status query and reconciliation, not a second deletion or signal. When the helper starts again, a delegated step that its earlier lifetime consumed and did not settle has an unknown outcome: the call was possibly submitted, and no executor has the step now. The helper records that state for the step, and its storage layer writes the changed record back. The step stays consumed, so the same request gets the recorded state and no second acceptance. The agent thus expects `unknown_outcome` from a status query after a restart of the helper, and it reconciles the step before it reports a result.

The helper accepts a delegated step only when its privilege grant applies until the expiry of the request. The executor can submit a call until that expiry, so a grant that expires earlier would permit a call after its own end. The helper adds the time that remains of the request to the wall-clock time of its check and refuses the request when the result is after the expiry of the grant. This check covers the expiry of a grant only. A grant that is revoked after the helper accepted a step is not covered by it: the revocation rule of this section applies at the next dispatch boundary of the helper.

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

The journal interface has this contract. A call of the durable journal returns success only after its record is durable. The bounded record of the critical-memory exception returns success with the durability `volatile`. The consumption of a plan and its operation are one transaction. A plan is consumed one time for its plan identity; a repeated apply of the same principal returns the operation or the recorded rejection of the first apply, and an apply of a different principal is a conflict. The consumption of a dispatch tells the caller whether this call consumed the step; only that caller submits the external call. The same transaction reads the stop fence of the operation, and a fenced operation consumes no dispatch. The result of a consumption states the durability of its record, and the dispatch check uses that value. The recording mode of a step is `durable` or `volatile_critical_exception`. A step with a `volatile` record is dispatched only when its mode is `volatile_critical_exception`, its action class is an application class, and its original trigger is `global_critical_memory`.

### Explicit critical-memory exception

`allow_volatile_journal_on_critical` is the only planned exception. Admission requires all of the following:

- The option and applicable action/escalation grant were enabled before the incident.
- Fresh sustained global critical-memory pressure satisfies the policy.
- The target remains otherwise eligible and within its budget.
- Durable recording is unavailable because the storage of the journal failed, and bounded volatile recording is available.
- Any participating helper independently permits the same exception within its own ceiling.

A locked journal is not a storage failure. When a different process holds the lock of the journal for longer than the bounded wait of a write, the write records nothing and the admission is refused with `admission_not_recorded`. No volatile record is made, and the controller evaluates again at its next evaluation with no pacing wait. Only a failure of the storage, for example a full volume, a failed synchronization, or a damaged file, permits the exception.

The exception never applies to any filesystem mutation, manual process control, or an operation admitted solely through an application-budget violation. A budget-triggered operation cannot relabel itself critical during execution. Settle the old operation before admitting a fresh critical-trigger plan under the same memory incident; preserve its consumed charge and charge a newly dispatched intervention another slot. Current grants, cooldowns, and the remaining incident allowance still apply.

Record intent, dispatch consumption, and budget consumption together in bounded volatile state before submission. Duplicates remain consumed within that executor epoch; earlier-epoch requests cannot be replayed.

Mark all resulting history as volatile/degraded, and persist it later when possible. If a restart cannot establish that prior incident and budget state were preserved, treat the affected budget as exhausted until fresh observations establish sustained recovery and a new incident, or the user explicitly rearms it. Restart must not replenish an unknown budget during continuing pressure.

The journal keeps one usage record for each budget generation of an incident: the number of operations with a consumed application step, where a graceful step and its force step use one slot, and the sum of the work charges of the consumed filesystem steps. An automatic plan binds the incident and its budget generation, and the operation records them at admission. The consumption of a dispatch changes the usage record of that generation in the same transaction, so the record and the consumed steps agree; a consumption whose generation is not known fails closed and records nothing. A restart reads the usage record of the current generation to know the usage that counts against the allowance: after a rearm, the usage of an earlier generation does not count against the new generation, and it stays recorded in its own record. With no rearm, the current generation is the generation of the earlier usage, so a restart does not replenish the allowance. The retention can remove the settled operations of an open incident; it keeps each usage record of each incident that the controller names as open. It removes all usage records of an incident that is not open when the latest operation of the incident was admitted before the retention cutoff. The budget of an open incident thus does not depend on the retention cutoff, the start time of the incident, or the wall clock.

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

An operation that stays `UnknownOutcome` after the reconciliation of a restart holds the leases of its targets (section 5): the coordinator restores them from the stored plan, so a conflicting plan is refused or waits as for a live lease. The coordinator reconciles such an operation again at a bounded interval, from fresh evidence and with no executor call. A reconciliation that settles the operation releases the leases. For a target that no evidence can settle, the user acknowledges the operation (`svalnir operations acknowledge`). The acknowledgment is accepted only for an `UnknownOutcome` operation; it is a durable record with its time and its principal, it releases the leases, and it does not change the recorded result: the history shows `UnknownOutcome` with the acknowledgment. A repeated acknowledgment returns the first one and changes nothing. A restart does not restore the leases of an acknowledged operation. An `UnknownOutcome` operation of the current executor lifetime keeps its leases in the same way, and an acknowledgment releases them.

One reconciliation attempt of a step has one of three results:

| Result | Meaning | Reconciliation of the step |
| --- | --- | --- |
| Recorded | The journal has what the evidence establishes, which can be `UnknownOutcome` | Complete |
| Not recorded | A write of the journal failed, and the record is as it was | Pending: a later attempt reads the step again |
| Not settled, inspected | The result check or the state machine refused the result that the evidence gave. A step whose dispatch was consumed is recorded as `UnknownOutcome`; a step that issued no call keeps its record | Complete: a later write cannot change a record that the state machine refuses |

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
