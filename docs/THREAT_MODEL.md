# Svalnir Threat Model

**Last reviewed:** 2026-11-19

> **Status:** Design specification. Controls described as requirements are not claims that an implementation, security audit, or release validation already exists.
>
> **Scope:** Svalnir's initial macOS release: Rust core, `clap` CLI, GPUI application, and persistent per-user agent. Automatic cache eviction and automatic application termination, including force quit, are included. The initial release has no privileged helper (owner decision of 2026-11-19): its code is not registered and not called. The threats and the controls of the narrow privileged helper stay in this model for the release that adds it, and each threat identifier keeps its number.
>
> **Related documents:** [README](../README.md) and [Architecture](ARCHITECTURE.md) define the product and component baseline. [Policy specification](POLICY_SPEC.md), [action contracts](ACTION_CONTRACTS.md), [cleanup rules](CLEANUP_RULES.md), [resource model](RESOURCE_MODEL.md), and [interfaces](INTERFACES.md) specify the controls named here. [Validation plan](VALIDATION.md) owns the release gates. [CONTRIBUTING](../CONTRIBUTING.md) and [AGENTS](../AGENTS.md) give working instructions.

## 1. Security objectives

Svalnir deliberately performs actions that can destroy data or interrupt work. Security therefore includes preventing an otherwise legitimate feature from selecting the wrong target, exceeding its authorization, or continuing after its authority has changed.

The design must:

- Limit every action to its authorized identity, scope, policy revision, and budget.
- Preserve personal data and protected processes through explicit exclusions and conservative eligibility checks.
- Prevent the agent's Full Disk Access or the helper's administrative privileges from becoming general capabilities for local clients.
- Keep monitoring, cancellation, and permission diagnostics responsive during pressure and bounded interventions.
- Record intent and outcomes honestly, including partial completion and uncertainty.
- Keep local observations private and make disabled or revoked behavior observable.

Automatic intervention requires a standing action policy. Access granted by macOS, helper installation, or membership in an administrator group does not independently authorize deletion or force quit. Conversely, enabled standing policies permit eligible interventions without an incident-by-incident prompt.

Force quit can lose unsaved work. Permanent cache eviction is not reversible through the operation journal. These are disclosed consequences of authorized behavior, not defects that logging or code signing can eliminate.

## 2. Assets and security properties

| Asset | Required protection |
| --- | --- |
| Documents, source code, photos, backups, application databases, credentials, and other personal data | Exclusion from generic automated cleanup; no unnecessary content reads, uploads, or privilege-assisted modification |
| Running applications, jobs, and unsaved work | Correct ownership and instance identity; explicit eligibility; bounded termination and restart behavior |
| System availability and storage capacity | Bounded resource use; no intervention loops that amplify pressure or disrupt essential services |
| Policy, action grants, and privilege grants | Distinct authority, validated revisions, constrained amendment, revocation, and replay handling |
| File and process inventories | Access controls, bounded retention, redacted diagnostics, and no collection of unnecessary secrets |
| Operation history and recovery state | Durable intent where required; accurate partial or unknown outcomes; resistance to substitution and corruption |
| Signed executables, service registrations, adapters, and release artifacts | Trusted provenance, protected installation, compatible protocols, and no executable configuration |
| Other users' sessions and shared volume resources | Principal isolation and coordinated Svalnir mutations without exposing another user's inventory |

A path, application name, environment variable, or command argument may contain confidential information. Metadata is sensitive even when file contents are never collected.

## 3. Actors, assumptions, and limits

| Actor or condition | Capability considered |
| --- | --- |
| Ordinary user or administrator | May enable an overbroad policy, misunderstand an estimate, revoke access, or interrupt an operation |
| Untrusted application running as the current user | May alter user-writable directories, spawn processes, consume resources, invoke the genuine Svalnir CLI, and modify user-owned configuration |
| Other local user | May connect to exposed services, contend for shared capacity, and attempt cross-user observation or action |
| Malicious or malformed filesystem content | May contain symlinks, mount changes, unusual names, oversized metadata, and adversarial directory structures |
| Compromised dependency, adapter, or update | May introduce code execution or change eligibility semantics inside a trusted component |
| Operating-system, storage, or power failure | May interrupt any step, deny access, lose unflushed state, or leave an action's outcome uncertain |

The baseline trusts the supported macOS kernel, code-signing machinery, and authorization services. A hostile kernel or unrestricted hostile root is outside the protection claim. Complete agent compromise defeats its user-side policy checks; a still-trusted helper must continue enforcing its independent privilege ceiling. Complete helper compromise defeats the boundary it implements. Preventing these compromises through IPC, parsing, and native-boundary controls remains in scope.

An attacker with the same user identity may already be able to destroy that user's writable data. Svalnir cannot make that session trustworthy. Its objective is to avoid amplifying that access into root or additional privacy authority, constrain its own destructive behavior, and accurately report its limitations. Root-owned helper policy remains a separate boundary against an ordinary same-user attacker.

The environment of a process is not evidence of the identity of its user. A wrapper script, an edited service definition, or `sudo -E` can give the agent or the CLI a `HOME` of a different directory tree, and the home directory decides the home protections, the Trash, and the default state directory. The agent, before it starts, and each CLI command that changes state, before it changes anything, compare the canonical path of `HOME` with the canonical path of the home directory in the account record of the effective user (`getpwuid_r`), and refuse a difference, an absent `HOME`, and an absent account record ([INTERFACES.md](INTERFACES.md) section 4). A read-only command does not make the check. Only a test build can replace the account record ([CONTRIBUTING.md](../CONTRIBUTING.md)).

Code identity is not evidence of human intent. A malicious process can launch a legitimate signed CLI. Therefore neither a valid signature nor an accepted CLI flag proves that the human approved a new action. The initial design does not claim a protected human-consent channel against a fully hostile user session.

## 4. Trust boundaries and authorization

### 4.1 Component boundaries

| Boundary | Required treatment |
| --- | --- |
| CLI or GPUI client → per-user agent | Authenticate the live peer and principal; validate bounded typed requests; apply the same policy and target checks for both clients |
| Agent → macOS observation APIs | Treat missing, denied, stale, or inconsistent observations as distinct states; never replace failure with zero |
| Agent → user-owned files or applications | Use the requesting user's privileges; enforce action grants, target identity, exclusions, and budgets |
| Agent → privileged helper (after the initial release) | Authenticate the specific permitted client identity and session; independently enforce helper-owned privilege grants |
| Agent → catalog and journal | Treat stored plans as stale observations; protect state files and validate decoded records |
| Helper → its own state and host coordination (after the initial release) | Use root-owned storage and scoped leases; never trust user storage as administrative authority |
| Release artifacts → installed services | Verify signed artifacts and compatibility before enabling mutation; protect privileged executable locations |

Apple supplies native XPC peer code-signing requirement APIs. The implementation must use supported APIs appropriate to the selected deployment target and verify their failure behavior; executable paths, process names, or a Team ID alone are insufficient identity policy. See [Apple's XPC API][xpc-requirement].

Full Disk Access-bearing read endpoints need authorization too. They must not provide arbitrary file reads, content searches, or unrestricted inventory exports merely because the requesting executable is signed.

### 4.2 Three distinct policy objects

| Object | Meaning and authority |
| --- | --- |
| `PolicyRevision` | Versioned desired and effective user policy: thresholds, selected reviewed rules, exclusions, budgets, and operating profile |
| `ActionGrant` | Standing product authorization for specified action classes and scopes; checked by the agent before dispatch; user-session state, not an independent defense against same-UID compromise |
| `PrivilegeGrant` | Helper-owned, administrator-approved ceiling for privileged operations: requesting principal, supported actions and roots, target ownership, limits, expiry where applicable, and revocation generation |

Configuration proposes behavior. It cannot create a privilege grant. A user-writable catalog, rule identifier, approval boolean, or path is never sufficient administrative authorization. Root-owned grant storage alone is also insufficient: creation and amendment require an OS-backed administrative authorization flow bound to the concrete proposed scope. The exact authorization mechanism and rights definition are implementation review gates.

The helper accepts only compiled, reviewed operation types and supported adapter versions. It independently checks its current grant, target constraints, request freshness, and limits. It binds each delegated step to the user and the login session of the caller that it accepted, and it refuses a request with no login session and each request for that step from another login session ([INTERFACES.md](INTERFACES.md) section 10). It accepts a request only when the grant applies until the expiry of the request, so no accepted step is executed after the expiry of its grant; a step that was in work when the helper stopped has an unknown outcome and is not accepted a second time ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 11). It does not load executable rules from a user directory, open the user's catalog as authoritative policy, run caller-provided shell commands, or implement unrestricted recursive deletion.

Ordinary cache eviction runs with the owning user's privileges, including separately granted privacy access. The initial release has no privileged filesystem mutation. When the helper is added, its first privileged filesystem mutation is restricted to helper-owned data or specifically reviewed administrator-controlled disposable namespaces. User-writable cache trees do not gain a generic root override. Privileged process control defaults to the requesting user's verified eligible applications or managed jobs. Root, system, and other-user processes remain protected unless a separately designed administrative integration supports them.

## 5. Threat catalogue

Threat IDs are stable references for design reviews, tests, and incident reports.

### T-01 — Confused deputy through local IPC

**Scenario:** An unauthorized client uses the agent's privacy access or the helper's root privileges to inspect data, delete files, or stop processes beyond its own authority.

**Controls:** Authenticate each live connection with OS-supported peer identity checks and principal/session binding. Use explicit signer and executable requirements, typed method allowlists, per-method authorization, bounded results, and independent helper checks. Reject incompatible protocols before dispatch. Keep privacy-bearing queries scoped as carefully as mutation requests.

**Residual risk:** A genuine CLI launched by same-user malware can satisfy executable authentication. Client authentication narrows callers; it does not establish human intent or rescue compromised user-session grants. A process of a user can make the helper stop the handling of the messages of that same user for 10 s with repeated malformed messages ([INTERFACES.md](INTERFACES.md) section 10). It cannot do that for another user. Until the XPC transport exists, the CLI, the GPUI client, and the agent share the operation journal: a client writes a request to its queue or the authority record with a compare-and-set, and neither authenticates a peer (owner decision of 2026-11-19, [INTERFACES.md](INTERFACES.md) section 4).

### T-02 — Configuration becomes administrative authority

**Scenario:** An attacker edits TOML, a catalog row, an adapter path, or a serialized plan to expand cleanup roots, remove protections, or authorize another user's process.

**Controls:** Separate `PolicyRevision`, `ActionGrant`, and `PrivilegeGrant`; validate schemas and rule versions; reject unsupported adapters and unconstrained globs. Maintain immutable hard protections outside editable policy. Protect helper grants and their parent directories from user writes. Bind administrative approval to the exact principal, operation scope, and ceilings being installed.

**Residual risk:** The current user can alter user-owned policy state. The design must report that limitation rather than describe file permissions or a signed CLI as a complete same-user authorization boundary.

### T-03 — Replay and stale authority

**Scenario:** An old plan, retried request, expired grant, or pre-revocation connection causes an action after its original context is gone.

**Controls:** Bind prepared requests to operation IDs, principals, policy and grant generations, target identities, expiry, and relevant boot/session context. Consume prepared requests at dispatch and retain bounded deduplication state. Revalidate before each batch and escalation step. A repeated operation ID queries or returns its recorded state; it does not blindly issue the side effect again. Requests outside the retained validity window are rejected.

**Residual risk:** Recording consumption and invoking an external OS operation are not a single atomic transaction. Recovery may produce `UnknownOutcome`, not an exactly-once guarantee.

### T-04 — Filesystem replacement and traversal races

**Scenario:** A directory, final filename, symlink, mount, or ownership relationship changes between inspection and removal, redirecting an otherwise authorized operation.

**Controls:** Anchor traversal to verified directory handles; reject symlink traversal; validate ownership, object and volume identity; constrain mount crossings; use descriptor-relative operations and bounded batches. Do not rely on string prefixes or one-time canonicalization. Detect unsupported hard-link and namespace conditions and skip them. The privileged helper requires that only the helper user and user 0 can write to the approved root and to each directory between the root and the object ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7).

These defenses reduce race exposure but do not make a final name check followed by `unlinkat` atomic. An active or adversarial owner-controlled namespace is ineligible for unattended deletion unless an explicitly risk-accepted disposable root and a reviewed protocol demonstrate confinement. Advisory locks and an idle process observation do not constrain a malicious writer. The use check of [CLEANUP_RULES.md](CLEANUP_RULES.md) section 6 (open files, mapped files, working directories, executables, and arguments of the processes of the user, read again before each step) blocks a target that a visible process uses now; it does not see a process of a different user, a process that starts after the check, or a scheduled job, and an inventory that is not complete blocks the target. An Apple platform process on the sealed system volume that refuses a query with `EPERM` does not block a target (owner decision of 2026-11-22); its uses are a residual risk. Each other process that refuses or fails a query blocks the target, and so does a path from the kernel that the check cannot verify by its device and inode. Apple's secure-coding guidance describes these TOCTOU limitations and the limits of cooperative locking. [Source][file-races]

**Residual risk:** A path's semantic value cannot be proven from its spelling. Rules must state their concurrency assumptions; root must not traverse an untrusted writable tree under a claim that descriptor checks solve all races.

### T-05 — Valuable data classified as disposable

**Scenario:** A cache adapter mistakes a database, unique build artifact, offline asset, or changed application layout for regenerable data.

**Controls:** Require versioned reviewed adapters with ownership, supported versions, minimum age, activity checks, exclusions, rebuild cost, and bounded deletion methods. A directory named `Caches`, an old timestamp, or a large size is insufficient. Unsupported layouts produce a skip. Protect documents, downloads, photos, backups, application databases, whole containers, model weights, virtual disks, and system-managed storage by default.

Manual cleanup defaults to Trash where supported. Automatic permanent eviction needs its own standing grant. Never empty the entire user Trash as an implied cleanup step.

**Residual risk:** Applications can change semantics without changing a path. Even valid cache eviction may trigger expensive rebuilds or downloads; adapter eligibility is a reviewed assumption, not proof of zero user impact.

### T-06 — Wrong process or overly broad termination

**Scenario:** PID reuse, ambiguous app attribution, a shared service, or an expanding process group causes an unrelated process to receive termination.

**Controls:** Bind targets to PID, start time, UID, executable identity, and application or managed-job context. Revalidate immediately before every termination step. Never use a display name or shared signer as the kill boundary. Treat descendants and shared services explicitly; reject ambiguous ownership. Preserve hard protected identities and apply foreground policy separately. Observe actual exit before choosing another target; AppKit force termination can return before exit. [Source][force-terminate]

**Residual risk:** Rechecking a PID and later signaling it does not universally eliminate the intervening race. Each native backend needs documented identity behavior and a reviewed residual-risk decision; unsupported or ambiguous cases remain observation-only.

### T-07 — Incorrect pressure, accounting, or time

**Scenario:** Stale samples, missing permissions, changed volumes, clock jumps, or misleading accounting trigger an unnecessary action or hide continuing pressure.

**Controls:** Attach freshness, provenance, scope, and validity to observations. Use monotonic durations for sustained pressure and cooldowns; refresh after wake and identity changes. Separate logical size, allocated storage, estimated reclaimability, and observed capacity. Invalidate affected catalog regions after event loss; FSEvents reports conditions that require rescanning. [Source][fsevents]

Critical system pressure and application-budget enforcement remain separate triggers. Nonzero swap, high CPU alone, or an unverified growth trend does not independently authorize termination.

**Residual risk:** Sampling can miss short-lived changes. Forecasts and estimates prepare work but never replace a current action authorization or target validation.

### T-08 — Pressure amplification and intervention loops

**Scenario:** A workload repeatedly fills storage, recreates caches, relaunches terminated processes, or floods the service, causing Svalnir to become another source of exhaustion.

**Controls:** Bound queue length, traversal work, memory, retained history, concurrent requests, and response size. Use hysteresis, sustained triggers, cooldowns, per-rule and per-incident budgets, and no-effect backoff. Perform one bounded conflicting action at a time while retaining responsive monitoring and cancellation. Observe the previous outcome and remeasure pressure before another termination; continue only while an authorized trigger persists and incident budgets allow. Track restarts through known supervisors rather than assuming a successful signal permanently stops a job.

**Residual risk:** Another application can consume resources faster than Svalnir can safely reclaim them. Exhausted budgets result in a visible degraded state, not broader cleanup or an unbounded kill loop.

### T-09 — Malformed input and native boundary compromise

**Scenario:** Hostile IPC payloads, metadata, filenames, database records, or native callbacks exploit parsing, memory safety, or command construction.

**Controls:** Use typed versioned schemas with size and nesting limits, checked numeric conversions, bounded collections, and strict enum validation. Keep unsafe Rust and Objective-C/C interop small, documented, and reviewed. Validate lifetimes, ownership, thread/run-loop requirements, and error paths. Avoid shell interpretation; supported tool integrations use fixed executables and structured arguments with independently constrained targets.

A producer command of an owner operation ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) starts by an absolute path with no shell and no `PATH` lookup, with the argument vector and the environment that the coordinator makes again from the reviewed declaration at admission, the home directory as its working directory, an empty standard input, no other inherited descriptor, and a process group of its own. A name that changes the loading of code (`DYLD_*`, `LD_*`, `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHON*`, `RUBYOPT`, `PERL5OPT`) is refused. As the last check before the start, the executor compares the device, the inode, the change and modification times, the owner, the mode, the size, and the SHA-256 digest of the executable, and of the interpreter of a script (owner decision D2 of 2026-11-22), with the plan, and the owner and the mode of each directory above them. It starts the process suspended, requires the executable regions of the process to be the bound Mach-O file and `/usr/lib/dyld` only, records the process in the journal, and resumes it only after that record. An interpreter argument of a script is a declared value, and the executor reads the `#!` line again before the start, so a plan cannot give an interpreter an option such as `--eval`. The command starts with the responsibility disclaim of the system, so it is its own responsible process and gets no privacy (TCC) permission of Svalnir (owner decision D1 of 2026-11-22); with no disclaim, no command starts. A deadline and each stop condition stop the process group, each tracked descendant, and each process whose responsible process is the command. The output is kept only as a bounded tail with control characters, bytes that are not UTF-8, the home directory path, URL user information, and token values replaced, and no value of the environment is written to a record.

**Residual risk:** Rust does not make native frameworks, dependencies, or unsafe code infallible. User-owned producer executables are permitted (D2). A process of the same user that can write to a user-owned script can replace its content between the comparison and the read by its interpreter; the digest does not cover a library or a configuration file of the producer that the command reads; and the private responsibility functions of D1 can change in a release of macOS, which then refuses each command. A process that leaves the process group, and whose parent exits within one reading interval (10 ms) before the exit of the command, is not seen: the system gives the responsibility of the command only while the command lives. A different process of the same user can resume the suspended command before Svalnir records it. Each rule with an owner operation of this build is `proposed` ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 9), and a promotion record of a rule states which of these risks it accepts, with the code that the bound files load or start: the modules of a Node.js or Python producer, and the Ruby code that `brew` starts. A compromise inside the helper is especially severe, which justifies its narrow operation surface and limited parser exposure.

### T-10 — Journal failure and uncertain outcomes

**Scenario:** Disk exhaustion, corruption, a crash, or an IPC timeout occurs before or after an irreversible OS operation, making history incomplete or causing unsafe replay.

**Controls:** Persist intent before every filesystem mutation, including Trash moves, and, by default, before process termination. Test the selected SQLite durability settings and storage-error paths. SQLite's transactional guarantees concern database state and depend on storage behavior; they do not extend to an external deletion or termination. Handle full-storage and I/O failures explicitly. [Atomic commit][sqlite-atomic]; [result codes][sqlite-errors].

If durable intent fails, stop further filesystem mutation. A reserve improves availability but cannot guarantee a write. Only explicitly enabled `allow_volatile_journal_on_critical` permits a previously authorized automatic critical-pressure termination with a bounded volatile record. It never covers ordinary app-budget enforcement, manual process control, or filesystem cleanup. Report incomplete history and attempt persistence after recovery.

Volatile intent and dispatch consumption must be recorded together before submission. Deduplication holds within that executor epoch; earlier-epoch requests cannot be replayed. If a restart cannot establish that prior incident and budget state were preserved, treat the affected budget as exhausted until fresh observations establish sustained recovery and a new incident, or the user explicitly rearms it. Restart must not silently replenish an unknown budget during continuing pressure.

**Residual risk:** A crash may lose volatile records, including incident counts held only in memory; this exception does not promise complete accounting across crashes. Intent can exist without an action, and an action can complete without its outcome record. Reconcile partial or unknown outcomes; never silently retarget a reused identity or claim atomic batches, rollback, or exactly-once effects.

### T-11 — State-file substitution and recovery poisoning

**Scenario:** An attacker substitutes a journal, state directory, lock file, or migration input, redirecting privileged writes or making stale data appear authoritative.

**Controls:** Verify state-directory ownership and permissions, securely create files, reject unexpected links, and prevent privileged state paths from depending on user-controlled environment variables. Accept `HOME` only when it is the home directory of the account record of the effective user (section 3). Keep user databases separate from helper state. Do not parse an arbitrary user-provided database inside the root helper. Bound migrations and treat malformed or incompatible recovery records as unavailable authority. Keep a local diagnostic path that does not require a successful database write.

**Residual risk:** Ordinary user-owned history is not tamper-proof against that same user. It is operational evidence, not a forensic guarantee against root or a compromised session.

### T-12 — Disclosure and misleading presentation

**Scenario:** Diagnostics, exports, IPC responses, terminal escapes, or misleading filenames expose secrets or trick the user into approving a different target.

**Controls:** Avoid collecting process environments, raw command lines, file contents, credentials, or memory contents by default. Keep telemetry local with no default upload. Redact paths and identifiers in shareable diagnostics; require an explicit export and reviewable scope. Escape control characters in terminal output, encode structured output correctly, and show stable target identity alongside human-readable names. Apply retention limits and restrictive local access controls.

**Residual risk:** User-approved exports can still reveal usage patterns. Redaction is not a guarantee of anonymity, and local metadata remains accessible to sufficiently privileged attackers.

### T-13 — Cross-user actions and shared-capacity conflicts

**Scenario:** Fast user switching, multiple agents, or shared APFS capacity causes duplicate reclamation, another user's process selection, or inventory disclosure.

**Controls:** Partition user state and bind requests to the authenticated principal. Require the helper's host lease broker for concurrent cross-user Svalnir mutation of shared storage resources; without it, explicitly restrict operation to a supported single-user mutation mode or observation. Lease keys reflect the actual shared resource, with bounded ownership and recovery rules. Revalidate after lease acquisition; aggregate capacity reporting does not authorize another user's files.

**Residual risk:** Leases coordinate cooperating Svalnir instances, not arbitrary applications or the kernel. External activity can invalidate estimates immediately; capacity improvements must be observed rather than attributed solely to Svalnir.

### T-14 — Revocation, pause, and lifecycle races

**Scenario:** The user pauses protection or revokes a grant while an action is queued, during a graceful-quit delay, or before sleep, restart, or an upgrade.

**Controls:** Observe pause and revocation before new dispatch and at the next batch or escalation boundary. Invalidate old generations and pending plans on relevant lifecycle changes; refresh observations after wake. Acknowledge durable revocation only after persistence succeeds. If persistence fails, inhibit current-instance dispatch and return an explicit non-durable/degraded status. Never silently re-enable a system-disabled background item. Apple exposes registration and unregistration through `SMAppService`, subject to the platform's approval lifecycle. [Source][smappservice]

**Residual risk:** An already-issued syscall cannot be recalled. A non-durable revocation may be lost on restart, restoring previously durable configuration. Connection loss or request timeout is not proof that a dispatched action was cancelled.

### T-15 — Compromised release or unsafe service installation

**Scenario:** A substituted helper, dependency, adapter, update, or writable installation path gains trusted execution or silently widens policy.

**Controls:** Distribute verified signed artifacts; protect privileged executable and state locations; pin and review dependencies and lockfiles; record release provenance. Do not load unsigned runtime plugins or download executable cleanup rules in the initial release. Validate agent/helper protocol and adapter versions before mutation. Updates and migrations must preserve exclusions and grant ceilings; new action classes or expanded privileged scope require their corresponding authorization.

**Residual risk:** Signing identifies a publisher and protects artifact identity; it does not prove benign behavior. A compromised release pipeline can produce trusted malicious code. Notarization does not replace source review, reproducible verification where feasible, or controlled release credentials.

## 6. Required security verification

Every area below starts **unverified**. A release record must identify the implementation revision, supported macOS versions, fixtures, expected outcomes, observed results, and unresolved limitations. Documentation-only review does not satisfy runtime gates.

[VALIDATION.md](VALIDATION.md) owns the release gates (`G-01` to `G-09`), the validation families (`VAL-01` to `VAL-16`), and the evidence record format. This table states the security evidence that those gates must contain. It does not define a second set of gates. A security area is verified only when its listed families pass for the declared release scope.

| Security evidence area | Threats | Required evidence | Validation families and gates |
| --- | --- | --- | --- |
| Peer and principal isolation | T-01, T-02, T-13 | Reject wrong identities, signers, sessions, and users; verify read endpoints; demonstrate that invoking the genuine CLI does not bypass helper ceilings | VAL-08, VAL-12 (G-04) |
| Grant creation and amendment | T-02, T-03 | User edits cannot create root authority; concrete administrative scope approval, generation changes, expiry, and replay rejection are exercised | VAL-09 (G-04) |
| Filesystem confinement | T-04, T-05, T-11 | Disposable fixtures cover symlink/rename/mount substitution, hard links, permission changes, activity, and unsupported layouts; adversarial writable namespaces fail eligibility unless a separately reviewed protocol is accepted | VAL-05 (G-02, G-07) |
| Process identity and escalation | T-06, T-07 | Disposable child processes cover exit/reuse, ambiguous grouping, protected targets, foreground changes, graceful timeout, and actual-exit verification | VAL-06 (G-03, G-07) |
| Pressure and bounded execution | T-07, T-08 | Injected samples and clocks cover stale data, sustained thresholds, hysteresis, cooldowns, restart loops, no-effect budgets, and monitor responsiveness | VAL-01, VAL-02, VAL-03, VAL-15 (G-01, G-08) |
| Crash and logging recovery | T-03, T-08, T-10, T-11 | Fault injection around each persistence/dispatch/outcome boundary produces honest partial or unknown results; disk-full cases obey the default and explicit volatile exception; restart cannot replenish a lost intervention budget during unrecovered pressure | VAL-07 (G-02, G-03, G-05) |
| Lifecycle and coordination | T-13, T-14 | Exercise concurrent agents, broker failure, lease recovery, pause during escalation, durable/non-durable revoke, wake, logout, reconnect, and incompatible upgrades | VAL-09, VAL-11, VAL-12 (G-04, G-05) |
| Input and privacy review | T-09, T-12 | Fuzz bounded parsers; review unsafe/native boundaries; verify sanitized output, redacted exports, retention, and absence of default telemetry | VAL-10, VAL-13, VAL-14 (G-06, G-07) |
| Release integrity | T-15 | Verify actual installed executable identities, writable-path resistance, service registration, compatibility, and migration behavior | VAL-16 (G-09) |

Use temporary directories, disposable processes, injected observations, and controlled clocks. Privileged integration tests require an isolated macOS test environment. Tests must not clean a developer's real caches or terminate unrelated applications merely to demonstrate functionality. The owner host procedure of [VALIDATION.md](VALIDATION.md) section 13 is not a test of this kind: it removes the output of a real producer for disposable projects only, in a dedicated user account, and only the project owner starts it.

An adapter or native backend that has not passed its applicable gates may provide inspection and planning but must not enable automatic mutation. The first usable release still requires verified automatic cache eviction and force termination; leaving all intervention disabled does not satisfy the product scope.

## 7. Residual risks and review triggers

Even after controls are verified, Svalnir cannot guarantee recovery from exhaustion, preserve unsaved work during force quit, prove every cache is regenerable, eliminate every target race, or provide a complete durable history after an explicitly allowed volatile action. Application supervisors can restart terminated workloads. External writers can consume reclaimed capacity. Operator mistakes inside valid authorization remain possible.

Svalnir must not manipulate swapfiles, disable virtual memory, perform generic RAM purges, or use process suspension as a claim of memory reclamation. System permissions remain independent capabilities; the product must diagnose access denial rather than attempt to bypass platform protections.

The following changes require updating this model and the applicable release gates before enabling them:

- A new privileged method, cleanup namespace, cross-user action, or change to grant enrollment.
- A new cache adapter, broadened application version range, or changed data ownership assumptions.
- A different process-control backend, grouping rule, or foreground/essential-process exception.
- Changes to journaling, durability, retention, pause acknowledgement, or replay handling.
- An updater, remote control, cloud synchronization, third-party plugin, or remote rule distribution.
- Endpoint Security or Network Extension integration, which are outside the initial trust surface and require their own permissions, boundaries, data-flow analysis, and review.

Record accepted residual risks with the affected scope, rationale, owner, and verification evidence. Approval of one disposable namespace or backend does not automatically approve another. Security claims should describe demonstrated boundaries and remaining uncertainty, rather than equating broad OS access with unlimited product authority.

## References

- [Apple: XPC peer code-signing requirements][xpc-requirement]
- [Apple: Race Conditions and Secure File Operations][file-races]
- [Apple: `NSRunningApplication.forceTerminate()`][force-terminate]
- [Apple: Using the File System Events API][fsevents]
- [Apple: `SMAppService`][smappservice]
- [SQLite: Atomic Commit][sqlite-atomic]
- [SQLite: Result and Error Codes][sqlite-errors]

[xpc-requirement]: https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_code_signing_requirement(_:_:)
[file-races]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html
[force-terminate]: https://developer.apple.com/documentation/appkit/nsrunningapplication/forceterminate()
[fsevents]: https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html
[smappservice]: https://developer.apple.com/documentation/servicemanagement/smappservice
[sqlite-atomic]: https://www.sqlite.org/atomiccommit.html
[sqlite-errors]: https://www.sqlite.org/rescode.html
