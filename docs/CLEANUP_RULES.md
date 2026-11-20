# Svalnir Cleanup Rules

**Status:** Design specification. The registry below contains proposed integrations, not implemented adapters or verified claims that a directory is safe to delete. The `rule` module of `svalnir-core` has the declaration types, the registry interface, and the eligibility evidence of sections 2 to 9. The `rules` module of `svalnir-agent` has the registry, the discovery of `svalnir.expired-temporary` and of `xcode.inactive-derived-data`, the discovery for an eviction (root resolution, process evidence, overlap resolution, and the facts of admission), and the inspection of the rules of section 10 that have the inspection mode only. Each layout of each rule is `proposed`: no rule has a validation record, so no build evicts data under a rule.

**Last reviewed:** 2026-11-20

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

The lifecycle state of a layout is a constant of the rule declaration in the source code (`crates/svalnir-agent/src/rules/`). A promotion is a reviewed change of that constant, together with its validation record ([VALIDATION.md](VALIDATION.md) section 13), in a new build. No command, configuration key, environment variable, or record of the state directory changes a lifecycle state, and a released build has no function that does. Only a test build (a unit test, or a debug build with the Cargo feature `test-support`) can make a registry with a different state for a fixture test; its reference text starts with `test-fixture/` and names no validation record.

The stages of a promotion are in sequence, and each one needs its record: `inspection_validated`, then `manual_action_validated`, then `automatic_eviction_validated`. One record can cover more than one stage when it has the cases of each stage.

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

The declaration type of `svalnir-core` has these parts of the contract: `id` and `revision`, `owner`, the supported layouts with their lifecycle states, the approved roots, `retention`, the checks and the windows of `activity_protocol`, `exclusions`, `modes`, the deletion method, `executor`, the rebuild cost, and the candidate and pass ceilings and the measurement expiry of `work_charge`. An approved root is relative to the home directory of the user, to the state directory of Svalnir, to the location that the configuration of the producer names, or, for the base `user_selected`, to a project directory that a discovery finds below a directory that the user names for the rule (section 12, `project.dependency-directory`); it is never an absolute path from user input. A root of the base `user_selected` has no default location, and the discovery for an eviction gives it no path. `candidate_unit`, `regenerability`, `namespace_protocol`, `failure_policy`, `verification`, and `provenance` have no field in that type yet. A rule that needs one of them for a validated mode adds the field with its implementation.

A missing support range, age policy, concurrency argument, or work bound is an incomplete rule. A declaration with no layout, no root, no activity check, a zero minimum age, a work ceiling with a zero part, a zero measurement expiry, or an unknown rebuild cost is rejected. So is a root path that is absolute or that has an empty, `.`, or `..` component, and a layout that is validated for a manual action or for automatic eviction when the implementation has no such mode. Each implementation has the inspection mode. No universal minimum age or cache-retention default is established here; each released revision must supply concrete validated values.

Rule parameters may tighten approved scope. A parameter that expands it must be constrained by the rule and the corresponding grants. The most restrictive applicable exclusion, grant, and resource limit wins.

## 4. Roots and ownership

Discover a producer's configured storage location when supported; a commonly used default is only a discovery hint. Resolve `~/` using the authenticated user's home context without shell expansion. Do not evaluate substitutions, scripts, or arbitrary environment expressions.

Bind a discovered root to filesystem identity, mount generation, ownership, and the adapter's expected layout. Retain a display path separately. Reject a root whose ancestor or final component violates the reviewed traversal protocol.

A root must be on a filesystem that the mount flags report as local (`MNT_LOCAL`). A local external disk is local; a network filesystem and an automounter map (`autofs`, for example below `/net`) are not. The check reads the mount table with `getfsstat` and `MNT_NOWAIT`, which does not wait for a filesystem that does not answer. It compares the text of the root path with the mount points before the first call that uses the path, each mount point also at its second path through a firmlink of the data volume (a mount point below `/System/Volumes/Data` also below `/`, and a mount point below `/` also below `/System/Volumes/Data`), then examines each component from `/` with `lstat` and compares the device of each object with the table; a directory above the root must not be a symbolic link. A call is thus made only for a name in a directory on a local filesystem, so the check cannot start an automount or wait on a remote filesystem. A discovery refuses a root on a filesystem that is not local (`root_not_local`), and a root for which the table has no mount or cannot be read; the filesystem executor refuses such a root with the codes of [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7. A path that a rule takes from a producer record, such as the project path of `xcode.inactive-derived-data` (section 11), has the same check before the rule examines it. A protected path and a user exclusion are compared also in their resolved form only when the text check shows them on a local filesystem; each other one is compared as given, with no call on it.

This build resolves an approved root of a declaration in this way. A root of the base `user_home` is below the home directory of the account record of the user, and a root of the base `svalnir_state` is below the state directory; each of the two has its symbolic links resolved first. For a root of the base `producer_configuration`, the discovery for an eviction reads no configuration of the producer: the root is the default location of the declaration below the home directory. A producer that is configured for a different location, for example Xcode with a custom DerivedData location, thus has no root, and the rule finds nothing for it. A root that does not exist gives no candidate and is not an error. A root that is a symbolic link, that is not a directory, or whose volume has no identity is not bound. The identity of a bound root is a digest of its path, its device and inode, its volume, and its mount generation, so a root that was replaced or mounted again has a different identity.

The inspection of a cache rule of section 10, from `pnpm.content-store` to `cocoapods.cache`, resolves its root of the base `producer_configuration` from the configuration files of the producer below the home directory. It reads one fixed top-level key of each file as text, for example `store-dir` of `~/.npmrc` and `GOCACHE` of the `env` file of Go. Only files below the home directory are read; a system file such as `/etc/homebrew/brew.env` is not. Before the read, the path of the file has the check of the local filesystem of this section, and a directory above the file must not be a symbolic link. The file must be a plain file with one name and the user as owner, of no more than 64 KiB, so a configuration file that is a symbolic link, or that is below one, is not read. A value must be an absolute path, or a path that starts with `~/` for a producer that expands it. A value with `$`, `` ` ``, or `%`, a relative path, a file that cannot be read, a key with two different values in one file, and two files that name different locations give no root, and the default location is not used in its place. When no file names a location, the root is the default location of the declaration. The inspection runs no producer tool and reads no environment variable: the environment of the agent or of a client is not the environment of the shell of the user, so a location that only an environment variable of that shell names is not seen. A resolved root is refused when the catalog of protected file locations protects it, when it overlaps a location that section 12 puts outside the rule (for example `GOMODCACHE` and the Homebrew Cellar), and when it or a directory above it below the home directory has a project marker such as `package.json` or `.git`. A unit is measured only when its layout marker is present, for example the file `CACHEDIR.TAG` of a uv cache. The discovery for an eviction does not use this resolution.

The inspection of `project.dependency-directory` (section 12) has no default location. It examines only the search roots that its caller gives: at most 16 paths, each a plain relative path below the home directory, with no empty, `.`, or `..` component, so the home directory itself is never a search root. A search root has the check of the local filesystem of this section, must be a directory with the user as owner, and is refused when the catalog of protected file locations protects it (for example `Library`, which contains the state directory) or a user exclusion contains it. The walk reads the directories below a search root breadth first, to a depth of 6, at most 50 000 directories, and for at most 60 seconds; it follows no symbolic link, does not enter another device, a directory of another owner, a protected or excluded directory, `.git`, or a generated directory of a layout. The result names the bound that ended the walk. This build has no configuration key and no command for the search roots: the library function takes them from its caller.

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

A dataless object, a cloud placeholder whose content is not on the disk, is an unsupported filesystem behavior of the last row: the filesystem executor removes no dataless file or directory, as a target or in a tree, and moves no dataless target to the Trash ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7), and the scanner reads only its metadata.

A path exclusion applies to the object selected and its descendants. Parent-directory deletion must not erase an excluded child. The adapter must select disjoint supported children or skip the indivisible parent.

These exclusions have two levels. OS-managed protected storage, swapfiles, and Svalnir's control-plane/recovery roots are hard exclusions for cleanup actions. Personal documents, media, archives, and similar user data are excluded from rule-mediated automatic eviction; a user may separately select eligible user-owned files for a manual Trash or explicitly authorized permanent-removal action under [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md). That manual selection is outside this automatic rule catalog. User-configured protections apply in their declared scope: global `[protections]` includes manual actions, while `[disk_guard.exclusions]` governs automatic disk-guard work. The default `[protections].excluded_paths` has the personal folders of the home directory, so a manual selection inside one of them needs a configuration that permits it ([POLICY_SPEC.md](POLICY_SPEC.md) section 12). Mandatory exclusions of a particular rule apply whenever that rule executes. A cleanup-rule grant or force flag cannot override the rule's exclusions or hard protected roots.

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

A rule establishes predicates 1, 2, 4, 5, 6, 7, and 8. The discovery for an eviction, which the agent and a client share, sets the three others for each candidate that the overlap resolution keeps:

| Predicate | Evidence of this build |
| --- | --- |
| 3 | `satisfied` when the catalog of protected file locations (section 5) gives `not_protected` for the unit. The discovery examines only a rule that the request selects (the approved rules of the disk guard, or the rule that the user names), under a root of its declaration. A protected unit gives `not_satisfied`; an unknown protection gives `unknown` |
| 9 | `satisfied`: the discovery read the root and the mount table. The coordinator reserves the budget, takes the leases, and records the admission before a step, and refuses the plan when one of them is not available |
| 10 | `satisfied`: the discovery examined the identity, the records, and the activity of the unit in this call. The coordinator reads the activity of the producer again before each step ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7), and the executor compares the object with the plan before its call |

With no state directory, the hard exclusion of the control-plane state has no path: the discovery examines no rule, and its result is not complete.

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

A discovery that examines only the known candidates of an earlier discovery, as in a resource emergency, measures no tree again. It uses the earlier measurement as the charge of a unit only when the unit directory has the same identity, owner, link count, and times, and when the measurement is not older than the measurement expiry of the rule declaration. That expiry is separate from the evidence expiry of the activity protocol: process evidence changes in seconds, and the expiry of a measurement bounds how much a unit can have grown since its measurement. A measurement that is older than the expiry, that has a time after the time now, or whose age the clock cannot give (no wall-clock time) gives no charge: predicate 8 is `unknown`, the reason is `measurement_expired` in the category unknown work charge, and the unit is not a candidate. A unit that changed has the reason `measurement_stale`. Neither case starts a new measurement. The two rules of this build declare an expiry of ten minutes; that value is a first value of a `proposed` rule.

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

Every entry is currently **proposed**. The first two entries have a discovery in `svalnir-agent`. `project.dependency-directory` has a declaration with the inspection mode only and an inspection in `svalnir-agent` (`rules::projects`, section 12); it gives no candidate, and the `evict` mode refuses it also in a test build with a fixture lifecycle state. The six entries from `pnpm.content-store` to `cocoapods.cache` have a declaration with the inspection mode only and an inspection in `svalnir-agent` (`rules::caches`): it reports the resolved root (section 4), the measured size of each unit, and the owner workflow of section 12, and it gives no candidate. For `pnpm.content-store` and `uv.cache` the inspection gives no reclaim figure; for the other four the figure is the allocated size, which is not exclusive storage. A layout of these six rules stays `proposed` also in a test build with a fixture lifecycle state, so the `evict` mode refuses each of them. The other entries have no implementation. The “Initial development target” column is implementation priority, not present eligibility or a shipped default.

| Rule ID | Intended unit | Initial development target |
| --- | --- | --- |
| `svalnir.expired-temporary` | One Svalnir-created disposable item or sealed generation | Automatic eviction after gates |
| `xcode.inactive-derived-data` | A reviewed generated subset for one identified project/layout | Automatic eviction after gates |
| `npm.content-cache` | Precisely scoped package-cache entries or an explicitly selected owner operation | Inspection and manual workflow first |
| `pip.cache` | Verified producer cache scope or selected supported entries | Inspection and manual workflow first |
| `cargo.build-output` | Explicitly selected generated output set for one workspace | Inspection and manual workflow first |
| `gradle.cache-inventory` | Attributed cache families and owner-retention information | Inspection and recommendations |
| `pnpm.content-store` | The content-addressed store of one resolved store path, through the owner operation | Inspection and manual workflow first |
| `yarn.cache` | The resolved global cache of one Yarn installation | Inspection and manual workflow first |
| `go.build-cache` | The resolved `GOCACHE` directory of one Go installation | Inspection and manual workflow first |
| `uv.cache` | The resolved cache directory of one uv installation, through the owner operation | Inspection and manual workflow first |
| `homebrew.download-cache` | The downloads of the resolved Homebrew cache | Inspection and manual workflow first |
| `cocoapods.cache` | The resolved download cache of one CocoaPods installation | Inspection and manual workflow first |
| `project.dependency-directory` | One generated directory (`node_modules`, `.venv`, or `Pods`) of one identified project below a directory that the user names | Inspection, then manual selection; never automatic in Milestone 4 |

The six entries from `pnpm.content-store` to `cocoapods.cache` are package and build caches of the same class as `npm.content-cache` (owner decision of 2026-11-20). They widen the developer coverage of the first release. Each one stays `proposed` until it has its own promotion evidence (section 15).

The registry deliberately omits a universal “all application caches” rule. More adapters can be added when their ownership, lifecycle, and concurrency contracts are known.

### Rule families after the first release

These families are planned for Milestone 4 (owner decision of 2026-11-20). They have no rule ID, no declaration, and no implementation. Each one needs its own rule identity, support matrix, and action gates before it enters the registry. The family of project dependency and build directories entered the registry as `project.dependency-directory`.

| Family | Planned unit | Planned limit |
| --- | --- | --- |
| Simulator devices and runtimes | One device or runtime that the owner tool lists | Removal only through the owner tool as a producer-supported operation (section 9). Simulator contents stay outside generic eviction |
| Container build cache | The build cache that the container tool reports | Removal only through the owner tool as a producer-supported operation. Persistent volumes, images in use, and databases stay protected |
| Homebrew cleanup | The old versions and downloads that the owner tool reports | Removal only through the owner tool as a producer-supported operation |
| Git worktrees | One linked worktree of one identified repository | Manual only, never automatic. A worktree can hold work that exists nowhere else: the plan must show uncommitted changes, files that are not tracked, and commits that no branch has, and must preserve them before the removal or refuse the worktree |

## 11. Initial automatic targets

### `svalnir.expired-temporary`

**Purpose:** Retire Svalnir's own explicitly disposable intermediate data without risking policy or recovery state.

**Roots:** A dedicated per-user temporary-cache namespace, proposed as `~/Library/Caches/Svalnir/Temporary/`. The final path is a packaging decision; the rule binds the actual verified root identity.

**Candidate:** A generation or item created by Svalnir with an internal lifecycle identity, purpose, expiry, and owner record. It must contain only regenerable intermediate material. User-provided originals, completed exports, credentials, grants, catalogs requiring recovery, and operation journals never enter this namespace.

**Admission:** No live operation holds a use lease. The producer has sealed the unit against further writes under Svalnir's internal protocol, required retention has elapsed, and the complete target set is bounded. An orphan requires reconciliation with operation state before eligibility; a filename alone cannot establish that it is abandoned.

This build has no producer of temporary items and no record of their use leases. The discovery for an eviction thus gives the rule a lease state that is not known, which blocks each item, and the fresh check before a step gives an unknown activity. The rule has no candidate that can be evicted until a build has the producer and the lease record.

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

The evidence that no producer process runs is a process inventory of the caller, with the monotonic time of the inventory. The rule compares that time with the time of the assessment of each unit. An inventory that is older than the evidence expiry of the activity protocol, that has a time after the assessment, or that cannot be compared with a monotonic time does not show inactivity: the activity of the unit is unknown, and the unit is not a candidate. Evidence that a producer process runs blocks a unit at each age.

The caller makes the inventory from the process table immediately before the discovery of the root: the executable name of each process whose effective or real user is the user of the discovery. A process that exited during the reading is not in the inventory, and a denied identity query is a process of a different user. The inventory is complete only when each other process gave its user and its executable path; a query that failed for a different cause, a process list that cannot be read, a list with no process, or a clock that gives no time makes the evidence unknown. The observation time is the time before the first query.

The rule examines the lock of the build database of a project (`Build/Intermediates.noindex/XCBuildData/build.db`) for each unit of that project. A project with no build database has no lock evidence, so each of its units has an unknown activity. Thus, after the unit `Build/Intermediates.noindex` of a project is evicted, the units `Build/Products` and `Index.noindex` of that project are not candidates until a build makes the database again. The three units of a project are evicted together only when one batch has them. Whether the revision keeps this property is an open point of its promotion (section 15).

The project that owns a unit comes from the `WorkspacePath` value of the `info.plist` file of its DerivedData directory. The user can write that file, so the value is attribution evidence of the same user and not a protected record: a same-user process that changes it can change which project the rule examines. It cannot move a unit out of the verified root, and it gives no access to the data of a different user. The value can also name a network volume or an automounter path. The rule examines it only with the local check of section 4: a project path on a filesystem that is not local, or for which the mount table has no mount, makes predicate 4 `unknown` with the reason `source_not_local`, and the rule makes no call on that path. A project path with a symbolic link also makes predicate 4 `unknown`, because the rule does not follow it, and makes predicate 7 `unknown`, because the text of the path then does not show whether the project overlaps the root. The rule does not compare the name hash of the project directory with `WorkspacePath`.

Each child of a unit must be on a fixed allow-list of the children that the build system makes. A unit with a child that the list does not accept is skipped whole with the reason `unsupported_layout`: no part of it is a candidate, and nothing in it is removed. The comparison is exact, so a name in another case or another spelling is not accepted. The list of this revision is:

| Unit | Accepted children |
| --- | --- |
| `Build/Products` | A directory `CONFIGURATION` or `CONFIGURATION-PLATFORM`, where `CONFIGURATION` is `Debug` or `Release` and `-PLATFORM` is one of `-iphoneos`, `-iphonesimulator`, `-appletvos`, `-appletvsimulator`, `-watchos`, `-watchsimulator`, `-xros`, `-xrsimulator`, `-maccatalyst`, or `-driverkit` |
| `Build/Intermediates.noindex` | A directory `NAME.build` with a name that is not empty; the directories `XCBuildData`, `PrecompiledHeaders`, `ExplicitPrecompiledModules`, and `SwiftExplicitPrecompiledModules`; a directory `GeneratedModuleMaps` or `GeneratedModuleMaps-PLATFORM` with a suffix of the first row |
| `Index.noindex` | The directories `DataStore`, `Build`, and `PrecompiledHeaders` |
| Each unit | The regular file `.DS_Store`, the view settings that Finder writes in a directory that a person opened |

The deny-list of the candidate paragraph is a second check. It applies to each entry at each depth, also below an accepted child, and its reason is `protected_data`. The allow-list examines the children of a unit only, so a file that a person puts below an accepted child with a name that the deny-list does not have stays a residual risk of the revision.

This list is a first list from the public knowledge of the Xcode build output. It is not verified. A configuration name is free text in a project, so a project with another configuration, or a producer version with another child, has units that the rule skips; that is the safe failure. Promotion evidence from real Xcode installations of each supported producer version must confirm the list, or change it in a new revision, before the layout leaves `proposed` (section 15).

**Action and charge:** User-scope bounded eviction of the fixed eligible set, never a root override. Use conservative per-object `work_bytes` and entry limits; large indivisible outputs do not bypass batch limits.

**Impact:** The user accepts indexing/build latency and possible restoration of dependencies only where the approved subset requires it. Missing sources or uncertain rebuild prerequisites disqualify a candidate. First-release implementation must establish a useful tested subset rather than claim universal DerivedData safety.

## 12. Additional developer integrations

### `project.dependency-directory`

**Purpose:** Show the generated dependency directories of the projects of the user, which a package manager makes again from the files of the project, with the evidence that a later manual removal needs.

**Roots:** The search roots that the user names (section 4). The rule has no default location and never walks the whole home directory. The approved root of a unit is the generated directory of one project directory that the walk finds (the base `user_selected`, section 3).

**Candidate:** One generated directory of one project, in a layout of this table. The name of a directory is never sufficient: the parent must have a project marker of the layout as a regular file, and the unit must have the inner marker of the layout when the layout has one.

| Layout | Directory | Project marker in the parent | Inner marker | Reclaim figure |
| --- | --- | --- | --- | --- |
| `node-modules` | `node_modules` | `package.json` | None | None: pnpm and Bun link package files from a store with hard links or clones |
| `python-venv` | `.venv` | `pyproject.toml` | `pyvenv.cfg` | None: uv can link files from its cache with clones or hard links |
| `cocoapods-pods` | `Pods` | `Podfile` | `Manifest.lock` | The allocated size, which is not exclusive storage |

A Cargo `target` directory next to `Cargo.toml` belongs to `cargo.build-output` (section 8): the inspection names that rule for it and does not measure it. The walk does not enter a generated directory, so a nested `node_modules` is part of its unit and is never a unit of its own.

**Version-control evidence:** A unit is a candidate of a future manual mode only when Git ignores it and the index of its repository has no path in it. The repository is the nearest directory from the project directory up to the search root with `.git`: a directory with the user as owner, or a file of at most 4 KiB that names a Git directory on a local filesystem, as for a linked worktree. A `.git` that is a symbolic link is not followed. A project with no repository below the search root has no evidence and is not a candidate (`no_repository`), also when its repository is above the search root.

The inspection asks Git, because Git owns the semantics of the ignore files of each level, the sparse index, and the split index. It runs two built-in commands of one executable that it verifies, each with a fixed argument list: `ls-files -z --cached -- ':(literal)PATH'` (a path in the unit is tracked, `tracked_files`) and `check-ignore -q --no-index -- PATH` (exit 0 is ignored; exit 1 is `not_ignored`). The executable is the first of `/Library/Developer/CommandLineTools/usr/bin/git` and `/Applications/Xcode.app/Contents/Developer/usr/bin/git` whose resolved file, and each directory above it, has the superuser as owner and permits no write by the group or by others; the shim `/usr/bin/git` and a Git of Homebrew are not used. The process starts with an empty environment and fixed variables (no system or global configuration file, no terminal prompt, no optional lock, no lazy fetch, no replacement object), with the Git directory and the work tree as explicit arguments, and with `--no-optional-locks`, `core.fsmonitor=false`, `core.hooksPath=/dev/null`, and `protocol.allow=never` on the command line, which have precedence over the configuration of the repository. Neither command runs a hook, writes the index, reads the content of a work-tree file, or runs a filter. Each query has a deadline of 10 seconds and an output bound; a query that fails gives `version_control_unknown`, and with no executable that passes the checks each unit has that result. A user setting `core.excludesFile` is not read, so a directory that only that file ignores is `not_ignored`, the safe failure. A file that the last commit has and that the index does not have (a staged removal) is not seen.

**Admission:** A build or package-manager process of the user (for example `node`, `pnpm`, `python3`, `uv`, or `pod`; a name never makes a process a target) whose working directory is in the project directory blocks the unit (`producer_active`), and so does each process of the user whose executable is in the project directory, such as `.venv/bin/python`. The inventory reads the process table, the executable of each process of the user, and the working directory of each build process (`proc_pidinfo` with `PROC_PIDVNODEPATHINFO`). A blocking process blocks the unit also when the inventory is not complete. Only a complete inventory that is not older than the evidence expiry of the rule shows that no process blocks it; an inventory that is not complete, or whose age the clock cannot give, makes the activity unknown (`activity_unknown`), and the unit is not a candidate. A process with a different working directory that uses the unit, such as a language server of an editor, is not seen; that is a residual risk of the revision. The admission of a future manual mode also needs the minimum age of the declaration and a fresh check before the step (section 6).

**Exclusions:** Source, project files, lockfiles, a committed or tracked dependency directory, a directory that Git does not ignore, a directory with no project marker, and a symbolic link stay outside the rule. The catalog of protected file locations and the user exclusions apply to each unit and to each directory that the walk enters.

**Impact:** The next install or sync makes the directory again; it can need a network, a registry that is still available, and the install scripts of the packages. A package that a person installed by hand in an environment is not in the project files and is lost. The report gives the owner workflow of each layout, for example the install command of the package manager.

**Required evidence:** Projects with each layout and each package manager of the support matrix, monorepos with nested projects, a committed dependency directory, ignore rules at each level and with negation, a sparse and a split index, linked worktrees, a build or a test that runs during the inspection, hard links and clones from a store, and the work charge of large directories.

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

### `pnpm.content-store`

pnpm documents a content-addressable store, `pnpm store path` for its location, and `pnpm store prune` to remove the packages that no project refers to. [pnpm store documentation][pnpm-store]

Discovery must resolve the store path of the specific pnpm installation and its store version. Keep project `node_modules`, source, lockfiles, credentials, and pnpm configuration outside this rule.

pnpm links files from the store into the `node_modules` directories of projects with hard links or clones. The removal of a store file whose content a project still has thus reclaims no capacity for that file. The reclaim estimate must not be the logical size of the store, and the result is the observed capacity change.

Initial support explains and previews the owner workflow. A direct traversal of the store needs a tested adapter for the store version, with consistency and concurrency evidence.

### `yarn.cache`

Yarn documents a cache with `yarn cache clean`, and a configurable cache folder. The cache of a project and the global mirror are different locations. [Yarn cache documentation][yarn-cache]

Discovery must identify the Yarn major version and resolve the global cache folder from its configuration. A cache inside a project is outside this rule: a project can commit it as its offline store, so it can be data that no registry gives again. Keep source, lockfiles, credentials, and Yarn configuration outside this rule.

Initial support explains and previews the owner workflow. Eviction may require future downloads and a registry that is still available.

### `go.build-cache`

Go documents a build cache at the location that `go env GOCACHE` reports, removes cache entries that are not recently used automatically, and gives `go clean -cache` to remove the cache. [Go build and test caching][go-cache]

Discovery must resolve `GOCACHE` for the specific Go installation. The module cache (`GOMODCACHE`) is a different location with downloaded module source and is outside this rule. Keep `GOPATH` source, installed binaries, and workspaces outside this rule.

An active build or test reads and writes the cache. Admission needs activity evidence for the Go toolchain processes of the user. Initial support explains and previews the owner workflow. The impact is a full rebuild and a rerun of cached tests.

### `uv.cache`

uv documents a cache at the location that `uv cache dir` reports, `uv cache clean` to remove entries, and `uv cache prune` to remove the entries that are not used. [uv cache documentation][uv-cache]

Discovery must resolve the cache directory of the specific uv installation. Keep virtual environments, installed tools, managed Python installations, source, and lockfiles outside this rule.

uv can link files from the cache into virtual environments with clones or hard links. As for `pnpm.content-store`, the reclaim estimate must not be the logical size of the cache. Initial support explains and previews the owner workflow; a running uv process blocks admission.

### `homebrew.download-cache`

Homebrew documents `brew --cache` for the location of its downloads and `brew cleanup` to remove old downloads and old versions. [Homebrew manual][homebrew-manual]

The candidate is a download in the resolved cache directory only. Installed kegs, the Cellar, the Caskroom, taps, and the Homebrew repository are outside this rule. The removal of old installed versions is the separate "Homebrew cleanup" family of section 10.

Initial support explains and previews the owner workflow. A running `brew` process blocks admission. The impact is a new download for a reinstall, which needs a network and a source that is still available.

### `cocoapods.cache`

CocoaPods documents `pod cache list` and `pod cache clean` for its download cache. [CocoaPods command reference][cocoapods-cache]

Discovery must resolve the cache of the specific CocoaPods installation. The `Pods` directory of a project, `Podfile`, `Podfile.lock`, the spec repositories, and credentials are outside this rule.

Initial support explains and previews the owner workflow. A running `pod` process blocks admission. Eviction may require future downloads and sources that are still available.

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

Two conditions have no category of their own. A lifecycle record or a producer record that is absent, is not a plain file, is too large, or cannot be decoded is in the category unsupported version/layout. A name below a unit that is not valid UTF-8 is in the category protected data: a rule preserves content that it cannot classify, and the unit is skipped. Process evidence that is older than its expiry is in the category missing quiescence. A source of the data that is not on a local filesystem (`source_not_local`) is in the category protected data, with the other reasons of predicate 4.

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

A rule with a content allow-list, such as the children of a unit of `xcode.inactive-derived-data` (section 11), records in its promotion evidence the children that each supported producer version makes on real installations, and the list of the promoted revision agrees with that record. A list that was written without that record keeps the layout `proposed`.

Use disposable fixtures and controlled writers on the supported macOS matrix. Do not validate rules by deleting real developer caches. The one exception is the owner host procedure of [VALIDATION.md](VALIDATION.md) section 13: it removes the output that a real producer made for disposable projects, in a dedicated user account with no personal data, and only the project owner starts it. Fixtures must exercise what can go wrong, not merely demonstrate that a directory disappears.

[VALIDATION.md](VALIDATION.md) section 13 has the content of a promotion record and the host procedure for `xcode.inactive-derived-data`. The fixture tests of the repository run the path from the discovery to the removal with a fixture lifecycle state; they are not a promotion record, because no test of the repository runs a real producer.

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
- [pnpm: Store commands][pnpm-store]
- [Yarn: Cache clean command][yarn-cache]
- [Go: Build and test caching][go-cache]
- [uv: Cache concepts][uv-cache]
- [Homebrew: Manual][homebrew-manual]
- [CocoaPods: Command reference][cocoapods-cache]

[apple-races]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html
[unlink]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/unlink.2.html
[apfs]: https://support.apple.com/en-ie/guide/disk-utility/dskua9e6a110/mac
[xcode-locations]: https://help.apple.com/xcode/mac/current/en.lproj/deva52afe8a4.html
[npm-cache]: https://docs.npmjs.com/cli/v11/commands/npm-cache/
[pip-cache]: https://pip.pypa.io/en/stable/topics/caching/
[cargo-clean]: https://doc.rust-lang.org/cargo/commands/cargo-clean.html
[gradle-caches]: https://docs.gradle.org/current/userguide/directory_layout.html
[pnpm-store]: https://pnpm.io/cli/store
[yarn-cache]: https://yarnpkg.com/cli/cache/clean
[go-cache]: https://pkg.go.dev/cmd/go#hdr-Build_and_test_caching
[uv-cache]: https://docs.astral.sh/uv/concepts/cache/
[homebrew-manual]: https://docs.brew.sh/Manpage
[cocoapods-cache]: https://guides.cocoapods.org/terminal/commands.html
