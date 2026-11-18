# Svalnir Cleanup Rules

**Status:** Design specification. The registry below contains proposed integrations, not implemented adapters or verified claims that a directory is safe to delete. The `rule` module of `svalnir-core` has the declaration types, the registry interface, and the eligibility evidence of sections 2 to 9. No rule is implemented.

**Last reviewed:** 2026-11-16

This document defines which filesystem data Svalnir may classify as disposable, the evidence required to select it, and the contract each cleanup adapter must satisfy. [POLICY_SPEC.md](POLICY_SPEC.md) controls when authorized cleanup is admitted. [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) controls dispatch, cancellation, journaling, and outcomes. The component and security boundaries remain those in [ARCHITECTURE.md](ARCHITECTURE.md) and [THREAT_MODEL.md](THREAT_MODEL.md). [RESOURCE_MODEL.md](RESOURCE_MODEL.md) defines the size and capacity measurements, and [VALIDATION.md](VALIDATION.md) owns the release evidence for rule promotion (`VAL-05`).

Automatic eviction of approved regenerable data is a first-release requirement. The current absence of implemented adapters must remain visible. Implementation must graduate a useful reviewed rule set through the gates below; treating every integration as permanently observation-only would not satisfy the product.

## 1. What a rule authorizes

A rule is a versioned, reviewed classifier and execution adapter for a specific data lifecycle. It is not a list of path globs.

The rule answers:

- Which producer owns this data, and which layouts are understood?
- Why can this particular item be recreated or discarded?
- Which identities, activity conditions, and namespace constraints must hold?
- Which action modes and execution principal are supported?
- What are the bounds, rebuild consequences, and observable outcomes?
- When must the adapter skip an item or stop a batch?

A valid rule does not itself grant permission to act. Execution also requires an applicable `PolicyRevision`, `ActionGrant`, current OS access, and, where relevant, a helper-enforced `PrivilegeGrant`. Selecting an ID in `approved_rules` cannot bypass any of these checks.

Inspection, manual Trash, manual rule-based permanent eviction, and automatic permanent eviction are separate modes, with the serialized names `inspection`, `manual_trash`, `manual_eviction`, and `automatic_eviction`. A rule may support inspection only or any validated subset of the action modes. Approval for one mode must not imply approval for another.

## 2. Identity, versions, and lifecycle

A rule reference is an immutable pair of rule ID and implementation revision. Plans and authorizations bind the reviewed revision; display names and mutable aliases are not execution identities.

IDs use a stable producer/category namespace, such as `svalnir.expired-temporary`. A revision changes when eligibility, scope, supported layouts, exclusions, execution methods, or consequences change. A new revision is not silently substituted into an existing plan.

| Lifecycle state | Permitted behavior |
| --- | --- |
| Proposed | Documentation and fixture design; no production execution |
| Inspection validated | Bounded discovery and qualified estimates for the tested layouts |
| Manual action validated | Explicitly selected, bounded actions after applicable execution gates |
| Automatic eviction validated | Unattended permanent eviction under standing grants and policy |
| Disabled | No new dispatch; inspect only if the reason for disabling still permits it |
| Retired | Existing history remains interpretable; new plans are rejected |

Promotion requires recorded evidence, not merely changing a registry flag. An implementation can support different lifecycle states for different owner versions or layouts. The sealed plan binds the layout that the rule found for each of its targets ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 3), and the lifecycle state that permits a step is the state of that layout. A target of a `proposed` layout is thus not removed under a validated layout of the same rule revision.

The serialized lifecycle states are `proposed`, `inspection_validated`, `manual_action_validated`, `automatic_eviction_validated`, `disabled`, and `retired`. A declaration gives one state for each supported layout. Each validated state has a reference to its validation record under [VALIDATION.md](VALIDATION.md); a validated state with no reference is not a valid declaration. A `disabled` state says whether inspection stays permitted. A state that the reader does not recognize permits no mode.

Changes that broaden roots, ownership, action modes, or consequences require corresponding grant review. An existing plan executes only its exact original revision while that revision remains registered, supported, and authorized; even a narrower replacement requires a new plan. A safety fix may revoke the old revision and inhibit its pending work. Unknown IDs, revisions, or layouts cannot fall back to a generic cleaner.

Rules ship with reviewed application code in the initial release. User configuration supplies allowed parameters and exclusions; it does not supply shell commands, executable plugins, or arbitrary deletion programs.

## 3. Rule declaration

The following is the logical declaration contract.

| Field | Required content |
| --- | --- |
| `id`, `revision` | Stable identity and immutable behavior revision |
| `owner` | Producer/application identity and attribution method |
| `support_matrix` | Tested macOS, producer, layout, and filesystem conditions |
| `lifecycle_state` | Validated modes for each supported combination |
| `root_resolver` | Approved root discovery and identity verification |
| `candidate_unit` | The smallest indivisible selectable object or fixed object set |
| `regenerability` | Evidence, prerequisites, exceptions, and expected rebuild impact |
| `retention` | Age basis, minimum retention, timestamp uncertainty treatment |
| `activity_protocol` | Producer activity evidence, quiescence requirements, and expiry |
| `namespace_protocol` | Traversal, ownership, replacement-race assumptions, and confinement evidence |
| `exclusions` | Additional protected descendants and unsupported object types |
| `modes` | Inspection, supported manual actions, and automatic eviction capability |
| `executor` | Owning-user adapter or narrowly supported privileged adapter |
| `work_charge` | Basis for `work_bytes`, entry counts, and execution bounds |
| `failure_policy` | Skip/stop conditions and which evidence may be refreshed |
| `verification` | Observable effects and remaining uncertainty |
| `provenance` | Primary documentation, relevant source revisions, and review evidence |

The declaration type of `svalnir-core` has these parts of the contract: `id` and `revision`, `owner`, the supported layouts with their lifecycle states, the approved roots, `retention`, the checks and the windows of `activity_protocol`, `exclusions`, `modes`, the deletion method, `executor`, the rebuild cost, and the candidate and pass ceilings of `work_charge`. An approved root is relative to the home directory of the user, to the state directory of Svalnir, or to the location that the configuration of the producer names; it is never an absolute path from user input. `candidate_unit`, `regenerability`, `namespace_protocol`, `failure_policy`, `verification`, and `provenance` have no field in that type yet. A rule that needs one of them for a validated mode adds the field with its implementation.

A missing support range, age policy, concurrency argument, or work bound is an incomplete rule. A declaration with no layout, no root, no activity check, a zero minimum age, a work ceiling with a zero part, or an unknown rebuild cost is rejected. So is a root path that is absolute or that has an empty, `.`, or `..` component, and a layout that is validated for a manual action or for automatic eviction when the implementation has no such mode. Each implementation has the inspection mode. No universal minimum age or cache-retention default is established here; each released revision must supply concrete validated values.

Rule parameters may tighten approved scope. A parameter that expands it must be constrained by the rule and the corresponding grants. The most restrictive applicable exclusion, grant, and resource limit wins.

## 4. Roots and ownership

Discover a producer's configured storage location when supported; a commonly used default is only a discovery hint. Resolve `~/` using the authenticated user's home context without shell expansion. Do not evaluate substitutions, scripts, or arbitrary environment expressions.

Bind a discovered root to filesystem identity, mount generation, ownership, and the adapter's expected layout. Retain a display path separately. Reject a root whose ancestor or final component violates the reviewed traversal protocol.

Custom roots require positive classification. A user-selected project directory does not become disposable merely because it was entered as a cache path. Detect overlapping protected locations, mixed-use roots, unexpected mount crossings, and shared ownership.

Ordinary user caches are mutated as their owning user. Full Disk Access is an independent capability and does not turn the adapter into a general privacy-data service. Initial root-executed cleanup is restricted to helper-owned data or specifically reviewed administrator-controlled disposable namespaces. Root must not be used to force deletion through an arbitrary user-writable tree.

A shared cache needs an explicit multi-owner protocol. Shared capacity does not authorize another user's files. Acquire the required Svalnir resource leases, including host coordination for supported multiuser shared-domain automation, without pretending that these leases stop other applications from writing.

## 5. Common exclusions

The following families are outside generic automatic cache eviction:

| Family | Required treatment |
| --- | --- |
| Documents, Downloads, source repositories, user exports, photos, videos, and media libraries | Preserve; any manual removal uses a separately selected action |
| Backups, Time Machine data and snapshots, recovery copies | No automatic eviction through cache rules |
| Xcode archives, dSYM bundles, release artifacts, signing material | Preserve even when nested within a candidate build tree |
| Application databases, credential stores, browser profiles, and session state | Preserve; a future lifecycle integration requires its own contract |
| Whole app containers, application bundles, simulator devices/data, VM disks | No generic recursive removal |
| Persistent container volumes and database storage | Preserve regardless of apparent inactivity |
| Local model weights and user-curated offline assets | Preserve; memory unloading is a different action |
| Swapfiles and system-managed virtual-memory storage | Never cleanup candidates |
| Svalnir policy, grants, operation journals, and recovery state | Never selected by Svalnir's temporary-data rule |
| Unknown objects, special files, links, and unsupported filesystem behavior | Skip unless a specific reviewed rule supports them |

A path exclusion applies to the object selected and its descendants. Parent-directory deletion must not erase an excluded child. The adapter must select disjoint supported children or skip the indivisible parent.

These exclusions have two levels. OS-managed protected storage, swapfiles, and Svalnir's control-plane/recovery roots are hard exclusions for cleanup actions. Personal documents, media, archives, and similar user data are excluded from rule-mediated automatic eviction; a user may separately select eligible user-owned files for a manual Trash or explicitly authorized permanent-removal action under [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md). That manual selection is outside this automatic rule catalog. User-configured protections apply in their declared scope: global `[protections]` includes manual actions, while `[disk_guard.exclusions]` governs automatic disk-guard work. Mandatory exclusions of a particular rule apply whenever that rule executes. A cleanup-rule grant or force flag cannot override the rule's exclusions or hard protected roots.

The catalog of protected file locations in `svalnir-core` has the hard exclusions that a path can establish. An entry is protected when it is one of these locations, is inside one, or contains one:

- The directories of the operating system: `/System`, `/usr` (not `/usr/local`), `/bin`, `/sbin`, and `/Library/Apple`.
- The virtual-memory storage: `/private/var/vm`, also with the spelling `/var/vm`.
- The state directory of Svalnir.

An entry is also protected when it is the home directory of the user or a directory that contains the home directory. An entry that contains a protected location is protected because its removal removes that location. The comparison ignores case, and it treats two different names as equal when one of them is not ASCII, so that a name in a different Unicode normalization form stays protected. The caller resolves symbolic links before it asks the catalog. An entry whose path the catalog cannot classify, or an entry for which the home directory or the state directory is not known, has an unknown protection and is not in a plan. The catalog can only add a protection. A location that is not in the catalog is not approved by that fact: the other exclusions of this section and the eligibility rules of section 6 apply.

Extensions and names are useful rejection hints, not complete semantic detection. A database without a familiar suffix remains a database; a directory named `Caches` may contain valuable data. Mixed or ambiguous content stays ineligible.

A new integration that needs to retire one of these protected families is a separately reviewed product capability. It cannot be introduced by weakening this table through ordinary cleanup parameters.

## 6. Candidate eligibility

A candidate is eligible only when every required predicate is satisfied:

1. The exact rule revision supports the observed producer and layout.
2. The root, volume, object identity, type, and owner match the rule.
3. The candidate is within the effective authorized scope.
4. The data's lifecycle establishes regenerability or intentional expiry.
5. Minimum age and required inactivity are established.
6. The activity and namespace protocols remain valid.
7. No hard or user exclusion overlaps the candidate.
8. The complete candidate unit and its work charge are known.
9. Capabilities, leases, durable recording, and execution budgets are available.
10. A fresh check immediately before the step still permits dispatch.

Use three-valued evidence: satisfied, not satisfied, and unknown. Unknown activity, ownership, cost, or classification cannot be treated as an affirmative result. The serialized values are `satisfied`, `not_satisfied`, and `unknown`. A candidate has one value for each of the ten predicates, and it is eligible only when each value is `satisfied`. A value that the reader does not recognize is not `satisfied`.

The candidate that the disk policy evaluates carries facts that derive from this evidence. Such a fact is affirmative only when its predicate is `satisfied`: a rule that is ready needs predicate 1, an owner that is the requesting user needs predicate 2, a target with no protected data class needs predicates 4 and 7, a known rebuild cost needs predicate 4, an inactive target needs predicate 5, a target with no product protection needs predicate 7, and a known work charge needs predicate 8. A fact also claims no more than the declaration of the exact rule revision: a rule is ready only for a layout that is validated for automatic eviction, a known rebuild cost is the cost of the declaration, an inactive time is not shorter than the quiescence time, and a known charge fits the candidate ceiling.

### Age and use

File timestamps are observations, not ownership records or proof that data is unused. Atime alone is insufficient. Modification time alone does not establish whether a producer has an item open or intends to reuse it.

A rule declares whether its age derives from a producer index, Svalnir's own lifecycle record, or validated filesystem metadata. Record the source and uncertainty. Future timestamps, implausible clock shifts, or incomplete history must not prematurely expire a candidate. Monotonic time controls observation windows within the current epoch; persisted wall-clock dates require explicit restart handling.

### Activity and namespace safety

Prefer producer-supported lifecycle operations or a verified quiescence protocol. Process-name absence, one open-file scan, or a lock probe alone is not universal proof that no writer exists.

Descriptor-relative traversal, no-follow checks, identity comparison, and constrained mounts reduce substitution risk. They do not make a name check followed by unlink atomic. Moving an entry into quarantine also changes the source before any later check. Apple documents the general TOCTOU and cooperative-locking limitations in its [secure file-operation guidance][apple-races].

Before automatic mutation, the rule must document and test confinement. A deliberately disposable namespace may accept a documented residual race within that confinement; authorization alone does not establish it. An active or adversarial writable namespace without that evidence remains ineligible.

New entries discovered during execution are not silently added to a fixed plan. Unexpected replacement or growth invalidates the affected unit. Any protocol that can select the wrong entry despite its checks must state that residual risk in its promotion evidence.

## 7. Accounting and budgets

Each candidate carries separate measurements:

| Measurement | Meaning |
| --- | --- |
| Logical bytes | File content length under the stated counting convention |
| Allocated bytes | Reported storage allocation under the stated filesystem convention |
| Estimated reclaimable bytes | Qualified prediction, including confidence and known retention effects |
| `work_bytes` | Conservative admission charge for the bounded candidate |
| Entries and units | Traversal/action counts, including zero-byte objects |
| Observed capacity delta | Post-action change in the relevant capacity domain |
| Trash bytes | Content moved to Trash, separately reported from capacity recovery |

`work_bytes` is a policy accounting unit, not a claim about physical I/O or exactly reclaimed storage. For a supported ordinary file, a rule may use the checked maximum of logical and allocated bytes. For a fixed set, use a checked sum under its documented deduplication rules, with entry-count and time limits alongside it.

A preflight stat does not prove the object cannot grow. The namespace/activity protocol must justify the bound through dispatch; otherwise automatic execution is unavailable. Sparse files, compression, clones, hard links, and directories need explicit treatment. Conservative overcharging is acceptable; silently charging unknown work as zero is not.

The effective limit is the minimum remaining batch, pass, per-rule, incident, grant, and executor ceiling. Reserve a candidate's full indivisible charge before dispatch. Skip a candidate that cannot fit; do not silently raise a limit or split a consistency unit.

A producer command that can discover additional targets after planning has no fixed-set bound merely because its current cache was measured. Such a command cannot implement unattended cleanup under a smaller advertised limit.

Unknown or unbounded charge blocks unattended mutation. Bounded discovery may continue later under ordinary resource conditions. An emergency must not trigger a deep rescan or whole-cache verification simply to make a candidate fit.

## 8. Overlap and deduplication

Catalogs may attribute one object to several rules or expose nested candidate roots. Resolve conflicts before admission:

- Associate a candidate with one execution rule revision.
- Reject ambiguous competing ownership instead of selecting the most permissive rule.
- Do not schedule a parent and descendant as separate deletions.
- Apply all relevant exclusions before choosing a disjoint candidate set.
- Use file/volume identity to detect repeated objects where supported.
- Skip hard-linked objects for automatic deletion unless the specific rule has a tested link-accounting and confinement contract. The plan builder applies the same exclusion to the `evict` mode: for a rule that skips hard-linked objects, an entry that is not a directory is in the plan only when its link count is known and is one. An entry with more than one name is left out as a rule exclusion, and an entry with an unknown link count is left out because that fact is not known. A directory is not examined: its link count is the number of its subdirectories.
- Never sum available capacity independently for volumes sharing the same APFS capacity domain.

Deduplicated reporting is not permission to remove every link. Removing one directory entry does not necessarily free its object's blocks. Apple describes delayed reclamation for still-open files in [unlink semantics][unlink]; APFS also supports volumes sharing container space, as described in [Disk Utility guidance][apfs].

The final capacity sample is an observed delta during concurrent system activity. Keep it separate from estimates and do not attribute all changes to Svalnir.

## 9. Modes and execution methods

### Manual Trash

Where supported, a manual removal defaults to Trash with its destination and outcome reported. A failed move does not fall back to permanent deletion. Cross-volume movement, copying, or unavailable Trash support may require different resource bounds; do not conceal those differences.

Moving data into Trash or same-volume quarantine does not satisfy the disk guard's reclamation goal. Automatic cleanup never interprets a grant as permission to empty the user's entire Trash.

### Manual rule-based eviction

A user can select a rule's candidates for permanent eviction through a plan (`EvictRegenerableData` with manual authorization). The rule revision must be in the "Manual action validated" state for this mode and layout. The plan-bound approval presents permanent deletion and the rebuild consequences. The rule's mandatory exclusions, eligibility predicates, finite bounds, and durable recording apply unchanged. This mode does not need a standing automatic grant, does not create one, and does not spend or reset automatic incident budgets.

### Automatic permanent eviction

Only a rule revision in the "Automatic eviction validated" state, with standing authorization, may permanently evict eligible candidates without a prompt. Permanent removal requires durable intent and consumed-dispatch recording under the action contract. The critical-memory volatile-journal exception never applies to filesystem cleanup.

Cancellation, policy changes, pressure recovery, or invalid evidence stop subsequent dispatch. Completed effects remain recorded. Partial failure is not rolled back by pretending the original data can always be reconstructed.

### Producer-supported operations

An owner-provided cleanup operation may preserve internal consistency better than deleting undocumented files. It still needs verified scope, bounds, activity handling, and outcome semantics.

Do not run an apparently diagnostic command before determining whether it mutates. For example, npm documents that `npm cache verify` performs garbage collection as well as integrity checks. It therefore cannot run inside a read-only scan or preview. [npm documentation][npm-cache]

If a future adapter invokes a producer tool, it must verify the executable and loaded implementation, use fixed structured arguments, constrain configuration and environment, and avoid project hooks or command substitution. An interpreter's identity alone does not authenticate user-writable scripts it loads. Never run such tools as a general privileged helper command.

Stopping a tool after a deadline does not undo its deletions or prove that child work ended. Reconcile its effects and retain a conflict lease until the supported protocol establishes completion. Commands whose effects cannot be bounded remain manual owner workflows outside Svalnir's mutation API: instructions for the user to perform through the producer tool, not an unbounded Svalnir action. Any later in-app invocation must satisfy the same finite action contracts before it is exposed.

## 10. Proposed registry

Every entry is currently **proposed and unimplemented**. The “Initial development target” column is implementation priority, not present eligibility or a shipped default.

| Rule ID | Intended unit | Initial development target |
| --- | --- | --- |
| `svalnir.expired-temporary` | One Svalnir-created disposable item or sealed generation | Automatic eviction after gates |
| `xcode.inactive-derived-data` | A reviewed generated subset for one identified project/layout | Automatic eviction after gates |
| `npm.content-cache` | Precisely scoped package-cache entries or an explicitly selected owner operation | Inspection and manual workflow first |
| `pip.cache` | Verified producer cache scope or selected supported entries | Inspection and manual workflow first |
| `cargo.build-output` | Explicitly selected generated output set for one workspace | Inspection and manual workflow first |
| `gradle.cache-inventory` | Attributed cache families and owner-retention information | Inspection and recommendations |

The registry deliberately omits a universal “all application caches” rule. More adapters can be added when their ownership, lifecycle, and concurrency contracts are known.

## 11. Initial automatic targets

### `svalnir.expired-temporary`

**Purpose:** Retire Svalnir's own explicitly disposable intermediate data without risking policy or recovery state.

**Roots:** A dedicated per-user temporary-cache namespace, proposed as `~/Library/Caches/Svalnir/Temporary/`. The final path is a packaging decision; the rule binds the actual verified root identity.

**Candidate:** A generation or item created by Svalnir with an internal lifecycle identity, purpose, expiry, and owner record. It must contain only regenerable intermediate material. User-provided originals, completed exports, credentials, grants, catalogs requiring recovery, and operation journals never enter this namespace.

**Admission:** No live operation holds a use lease. The producer has sealed the unit against further writes under Svalnir's internal protocol, required retention has elapsed, and the complete target set is bounded. An orphan requires reconciliation with operation state before eligibility; a filename alone cannot establish that it is abandoned.

Sealing coordinates Svalnir's writers; it does not prevent another same-user process from modifying user-writable storage. The adapter still needs a tested confinement protocol and fresh identity checks within the specifically disposable namespace. A lifecycle marker or cooperative lease is not proof against an adversarial writer.

**Action:** User-scope permanent eviction under the corresponding grant, or supported manual Trash. Deleting old temporary data must not require destroying the journal needed to record that deletion.

**Charge and result:** Checked `work_bytes` sum for the sealed verified set, plus entry/time ceilings. Record individual removal effects and remeasure capacity. Rebuild or recreation cost depends on the intermediate purpose and is shown before authorization.

**Required evidence:** Active-use exclusion, crashes before sealing, substituted lifecycle records, reused filenames, zero-space journal failure, partial cleanup, and recovery without deleting an active generation. A helper-owned temporary namespace, if introduced, is a separately scoped root with its own grant and evidence.

### `xcode.inactive-derived-data`

**Purpose:** Retire selected reproducible developer output while preserving unique artifacts and ongoing work.

Apple documents the default DerivedData location as `~/Library/Developer/Xcode/DerivedData`, with indexes, logs, and build products; locations can be customized or shared. Archives have a separate default location. These facts justify discovery, not deletion of every descendant. [Xcode location guidance][xcode-locations]

**Roots:** Verified configured locations with positive project/layout attribution. The default path is a hint. Custom paths overlapping source, archives, or mixed-use directories fail eligibility.

**Candidate:** A fixed supported generated subset belonging to one identified workspace and producer/layout version. Do not recursively remove the entire DerivedData root or assume every child is disposable. Retain dSYM bundles, archives, signing material, user-added files, databases, and unknown subtrees; if a unit cannot preserve exclusions, skip it.

**Admission:** The supported activity protocol must cover Xcode, command-line builds, indexing, tests, and relevant shared consumers. An old directory or absent IDE window is insufficient. Shared module or compilation caches are not implicitly owned by one project. Producer versions and concrete generated subsets remain unvalidated until recorded in the adapter's support matrix.

**Action and charge:** User-scope bounded eviction of the fixed eligible set, never a root override. Use conservative per-object `work_bytes` and entry limits; large indivisible outputs do not bypass batch limits.

**Impact:** The user accepts indexing/build latency and possible restoration of dependencies only where the approved subset requires it. Missing sources or uncertain rebuild prerequisites disqualify a candidate. First-release implementation must establish a useful tested subset rather than claim universal DerivedData safety.

## 12. Additional developer integrations

### `npm.content-cache`

npm documents a configurable cache containing an opaque content-addressed area, and describes cleanup and verification operations. Its cache is not promised as permanent package storage. [npm cache contract][npm-cache]

Discovery must identify the configured root and exact implementation version. Keep project `node_modules`, source, lockfiles, credentials, npm configuration, and separate execution caches outside this rule.

Initial support should explain and preview the owner workflow. Broad `npm cache clean --force` or `npm cache verify` must not be disguised as a fixed list of old files. A later automatic adapter needs bounded entry selection, consistency and concurrency evidence, protected-target exclusion, and a reliable work charge. Lack of those properties keeps the integration manual.

Eviction may require future downloads, credentials, or a still-available registry. Show that rebuild dependency instead of equating “cached” with “recoverable offline.”

### `pip.cache`

pip provides `pip cache dir` for its configured location and states that the internal cache layout is an implementation detail. Its package-removal operation affects cached wheels; `pip cache purge` removes wheel and HTTP-cache contents. [pip caching documentation][pip-cache]

Discover the specific registered Python/pip installation and resolved cache, accounting for supported configuration. Do not select virtual environments, installed packages, source distributions retained by the user, wheelhouses, or arbitrary directories with “pip” in their name.

An owner-level purge is a separately selected broad operation, not a bounded HTTP-only candidate. Direct traversal requires a tested format-specific adapter; unknown formats are inspection-only. Preserve offline workflows and disclose download/build consequences. Do not disable caching globally as an emergency workaround.

### `cargo.build-output`

Cargo documents that `cargo clean` removes generated artifacts and, without options, removes the entire target directory. The target directory is configurable. [Cargo clean documentation][cargo-clean]

The candidate must bind a workspace and positively identified output location. A directory named `target` is insufficient, and a shared target directory must not be treated as exclusive to one workspace. Preserve source, manifests, lockfiles, package credentials, installed tools, archives, dSYMs, and unique release outputs.

Initial support is inspection and explicit manual selection. An owner command's package/profile options are not a general proof that its entire effect respects Svalnir exclusions and budgets. Automatic support requires a reviewed fixed subset and concurrency protocol; a pre-command dry run alone does not establish either.

### `gradle.cache-inventory`

Gradle documents separate cache families, global configuration and initialization scripts in Gradle User Home, and built-in cleanup policies. [Gradle directory and cache guidance][gradle-caches]

The initial integration attributes these categories and explains owner-managed retention. It does not recursively remove Gradle User Home or run arbitrary project cleanup tasks.

Changing Gradle retention is a separate, user-approved configuration action. It is not an implicit side effect of enabling Svalnir cleanup. Shared caches and multiple Gradle versions require producer-aware coordination; daemon absence or an old directory suffix is insufficient permission. A future eviction rule must receive its own identity, support matrix, and action gates.

## 13. Preview and explainability

A scan may report a potential candidate without declaring it executable. Every preview distinguishes:

- Observed identity and attribution from inferred ownership.
- Inspection support from validated action modes.
- Current eligibility from missing or stale evidence.
- Logical/allocated size from reclaim estimates and admission charge.
- Expected rebuild cost from a guaranteed outcome.
- Existing authorization from an action that would require a new grant.

A dry run performs no deletion, Trash movement, producer garbage collection, permission changes, or cache repair. It may perform bounded read-only metadata queries whose privacy and cost are part of the scan contract.

Prepared plans expire and require fresh execution checks. They do not lock the filesystem. A later scan must not replace a rejected target silently while keeping the original plan ID.

Explain skipped candidates with stable reason categories, not only free-form errors: unsupported version/layout, protected data, unknown ownership, active producer, missing quiescence, unsafe namespace, stale identity, unknown link count, unknown work charge, budget exhaustion, missing access, missing authorization, or unavailable journal.

## 14. Outcomes, failure, and backoff

Use the common operation states from [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md). Rule-specific evidence enriches those states rather than creating incompatible definitions of success.

| Observation | Rule behavior |
| --- | --- |
| Candidate vanished before dispatch | Record no Svalnir deletion; do not charge it as reclaimed |
| Identity, mount, owner, or content class changed | Stop the unit; require new discovery/plan |
| Producer becomes active | Inhibit the next step; never terminate it implicitly to make cleanup possible |
| Permission denied or revoked | Report the denied capability; no automatic root retry |
| New excluded or unknown descendant appears | Preserve it and invalidate the affected unit |
| Durable recording fails | Start no permanent deletion |
| Some entries removed before failure | Report partial effects; retain remaining work as unexecuted or uncertain |
| Timeout or crash obscures an effect | Reconcile; preserve unknown outcome; no blind retry |
| Removal succeeds but capacity stays low | Record the distinction and apply no-effect backoff |
| Cache immediately regrows | Apply rule/incident cooldown; do not repeatedly evict without limits |

The executor may refresh read-only evidence within its bounds. Refreshing evidence cannot expand authority, alter the candidate set, or turn a consumed step into a retryable new deletion.

## 15. Verification and promotion

Each promoted revision needs a review record containing its sources, supported producer/layout versions, fixture definitions, namespace assumptions, tested exclusions, budgets, native behavior, and accepted residual risks.

| Gate | Required cases |
| --- | --- |
| Classification | Genuine disposable items, mixed content, unique artifacts, unknown layouts, misleading names |
| Ownership and roots | Custom/shared paths, wrong owner, protected-root overlap, symlinks, mount replacement |
| Activity | Active builds/writers, concurrent creation, stale locks, owner restart, failed quiescence |
| Identity and confinement | Entry replacement, rename races, inode reuse where testable, untrusted descendants |
| Accounting | Sparse/compressed files, hard links, clones, zero-byte trees, overflow, growth after planning |
| Bounds | Candidate larger than remaining limits, unbounded producer command, cancellation between steps |
| Persistence | Full journal volume, intent/dispatch/result crashes, partial effects, safe reconciliation |
| Outcomes | Trash versus eviction, open-file retention, no observed reclaim, rapid regrowth |
| Privacy and presentation | Sensitive names, control characters, redacted exports, no content collection by default |

Use disposable fixtures and controlled writers on the supported macOS matrix. Do not validate rules by deleting real developer caches. Fixtures must exercise what can go wrong, not merely demonstrate that a directory disappears.

Automatic promotion requires all applicable gates plus compatible policy and action contracts. A regression disables the affected rule revision or supported combination while preserving history. Never respond to a failed gate by loosening exclusions or quietly switching to a broader deletion command.

## References

- [Apple: Race Conditions and Secure File Operations][apple-races]
- [Apple: unlink semantics][unlink]
- [Apple: APFS volume management][apfs]
- [Apple: Xcode project-generated file locations][xcode-locations]
- [npm: Cache commands and data model][npm-cache]
- [pip: Caching and supported cache operations][pip-cache]
- [Cargo: clean command][cargo-clean]
- [Gradle: Managed directories and caches][gradle-caches]

[apple-races]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html
[unlink]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/unlink.2.html
[apfs]: https://support.apple.com/en-ie/guide/disk-utility/dskua9e6a110/mac
[xcode-locations]: https://help.apple.com/xcode/mac/current/en.lproj/deva52afe8a4.html
[npm-cache]: https://docs.npmjs.com/cli/v11/commands/npm-cache/
[pip-cache]: https://pip.pypa.io/en/stable/topics/caching/
[cargo-clean]: https://doc.rust-lang.org/cargo/commands/cargo-clean.html
[gradle-caches]: https://docs.gradle.org/current/userguide/directory_layout.html
