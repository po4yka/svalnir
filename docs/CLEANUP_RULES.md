# Svalnir Cleanup Rules

**Status:** Design specification. The registry below contains proposed integrations, not implemented adapters or verified claims that a directory is safe to delete. The `rule` module of `svalnir-core` has the declaration types, the registry interface, and the eligibility evidence of sections 2 to 9. The `rules` module of `svalnir-agent` has the registry, the discovery of `svalnir.expired-temporary` and of `xcode.inactive-derived-data`, the discovery for an eviction (root resolution, process evidence, overlap resolution, and the facts of admission), the discovery of `project.dependency-directory` for a manual eviction, and the inspection of the rules of section 10 that have an inspection. Each layout of each rule is `proposed`: no rule has a validation record, so no build evicts data under a rule.

**Last reviewed:** 2026-11-22

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

The declaration type of `svalnir-core` has these parts of the contract: `id` and `revision`, `owner`, the supported layouts with their lifecycle states, the approved roots, `retention`, the checks and the windows of `activity_protocol`, `exclusions`, `modes`, the deletion method, `executor`, the rebuild cost, and the candidate and pass ceilings and the measurement expiry of `work_charge`. An approved root is relative to the home directory of the user, to the state directory of Svalnir, to the location that the configuration of the producer names, or, for the base `user_selected`, to a project directory that a discovery finds below a directory that the user names for the rule (section 12, `project.dependency-directory`); it is never an absolute path from user input. A root of the base `user_selected` has no default location, and the discovery for an eviction gives it no path. A root of the base `producer_installation` is below the documented absolute prefix of an installation of the producer, such as `/opt/homebrew` (section 12, `homebrew.cleanup`), or below a system location of the producer; the discovery for an eviction gives it no path either. `candidate_unit`, `regenerability`, `namespace_protocol`, `failure_policy`, `verification`, and `provenance` have no field in that type yet. A rule that needs one of them for a validated mode adds the field with its implementation.

A missing support range, age policy, concurrency argument, or work bound is an incomplete rule. A declaration with no layout, no root, no activity check, a zero minimum age, a work ceiling with a zero part, a zero measurement expiry, or an unknown rebuild cost is rejected. So is a root path that is absolute or that has an empty, `.`, or `..` component, and a layout that is validated for a manual action or for automatic eviction when the implementation has no such mode. Each implementation has the inspection mode. No universal minimum age or cache-retention default is established here; each released revision must supply concrete validated values.

Rule parameters may tighten approved scope. A parameter that expands it must be constrained by the rule and the corresponding grants. The most restrictive applicable exclusion, grant, and resource limit wins.

## 4. Roots and ownership

Discover a producer's configured storage location when supported; a commonly used default is only a discovery hint. Resolve `~/` using the authenticated user's home context without shell expansion. Do not evaluate substitutions, scripts, or arbitrary environment expressions.

Bind a discovered root to filesystem identity, mount generation, ownership, and the adapter's expected layout. Retain a display path separately. Reject a root whose ancestor or final component violates the reviewed traversal protocol.

A root must be on a filesystem that the mount flags report as local (`MNT_LOCAL`). A local external disk is local; a network filesystem and an automounter map (`autofs`, for example below `/net`) are not. The check reads the mount table with `getfsstat` and `MNT_NOWAIT`, which does not wait for a filesystem that does not answer. It compares the text of the root path with the mount points before the first call that uses the path, each mount point also at its second path through a firmlink of the data volume (a mount point below `/System/Volumes/Data` also below `/`, and a mount point below `/` also below `/System/Volumes/Data`), then examines each component from `/` with `lstat` and compares the device of each object with the table; a directory above the root must not be a symbolic link. A call is thus made only for a name in a directory on a local filesystem, so the check cannot start an automount or wait on a remote filesystem. A discovery refuses a root on a filesystem that is not local (`root_not_local`), and a root for which the table has no mount or cannot be read; the filesystem executor refuses such a root with the codes of [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7. A path that a rule takes from a producer record, such as the project path of `xcode.inactive-derived-data` (section 11), has the same check before the rule examines it. A protected path and a user exclusion are compared also in their resolved form only when the text check shows them on a local filesystem; each other one is compared as given, with no call on it.

This build resolves an approved root of a declaration in this way. A root of the base `user_home` is below the home directory of the account record of the user, and a root of the base `svalnir_state` is below the state directory; each of the two has its symbolic links resolved first. For a root of the base `producer_configuration`, the discovery for an eviction reads no configuration of the producer: the root is the default location of the declaration below the home directory. A producer that is configured for a different location, for example Xcode with a custom DerivedData location, thus has no root, and the rule finds nothing for it. A root that does not exist gives no candidate and is not an error. A root that is a symbolic link, that is not a directory, or whose volume has no identity is not bound. The identity of a bound root is a digest of its path, its device and inode, its volume, and its mount generation, so a root that was replaced or mounted again has a different identity.

The inspection of a cache rule of section 10, from `pnpm.content-store` to `cocoapods.cache`, resolves its root of the base `producer_configuration` from the configuration files of the producer below the home directory. It reads one fixed top-level key of each file as text, for example `store-dir` of `~/.npmrc` and `GOCACHE` of the `env` file of Go. Only files below the home directory are read; a system file such as `/etc/homebrew/brew.env` is not. Before the read, the path of the file has the check of the local filesystem of this section, and a directory above the file must not be a symbolic link. The file must be a plain file with one name and the user as owner, of no more than 64 KiB, so a configuration file that is a symbolic link, or that is below one, is not read. A value must be an absolute path, or a path that starts with `~/` for a producer that expands it. A value with `$`, `` ` ``, or `%`, a relative path, a file that cannot be read, a key with two different values in one file, and two files that name different locations give no root, and the default location is not used in its place. When no file names a location, the root is the default location of the declaration. The inspection runs no producer tool and reads no environment variable: the environment of the agent or of a client is not the environment of the shell of the user, so a location that only an environment variable of that shell names is not seen. A resolved root is refused when the catalog of protected file locations protects it, when it overlaps a location that section 12 puts outside the rule (for example `GOMODCACHE` and the Homebrew Cellar), and when it or a directory above it below the home directory has a project marker such as `package.json` or `.git`. A unit is measured only when its layout marker is present, for example the file `CACHEDIR.TAG` of a uv cache. The discovery for an eviction does not use this resolution.

The inspections of `project.dependency-directory` and of `git.linked-worktree` (section 12) have no default location. It examines only the search roots that its caller gives: at most 16 paths, each a plain relative path below the home directory, with no empty, `.`, or `..` component, so the home directory itself is never a search root. A search root has the check of the local filesystem of this section, must be a directory with the user as owner, and is refused when the catalog of protected file locations protects it (for example `Library`, which contains the state directory) or a user exclusion contains it. The walk reads the directories below a search root breadth first, to a depth of 6, at most 50 000 directories and 100 000 entries of one directory, and for at most 60 seconds (120 seconds for the worktrees, with their queries); it follows no symbolic link, does not enter another device, a directory of another owner, or a protected or excluded directory. The walk of `project.dependency-directory` also does not enter a directory of its skip list (`.git`, `.hg`, `.jj`, `.svn`, and `.cache`) or a unit of a layout (section 12). The result names the bound that ended the walk. The walk examines a directory with `lstat` and reads it later by its path, so a directory that a same-user process replaces with a symbolic link between the two calls is read through the link. The walk only reads; the filesystem executor removes a unit with its traversal relative to open descriptors from the bound root ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7).

The roots of one request come from three sources, and the report of each root names its source:

- `[cleanup.projects].search_roots` ([POLICY_SPEC.md](POLICY_SPEC.md) section 3): plain relative paths below the home directory.
- `--root PATH` of `clean inspect` and of `clean plan --mode evict` ([INTERFACES.md](INTERFACES.md) section 4): an absolute path, or a path relative to the invocation directory. The client removes each `.` component and refuses a path with a `..` component (`invalid_search_root`): after a symbolic link, `..` names a different directory than the text shows, so the text is not resolved. The path must be an existing directory below the home directory and not the home directory; a path whose text is not below the home directory is compared again in its resolved form, so that `/var` and `/private/var` name one directory. A root that is not accepted gives `invalid_search_root` or `search_root_not_found`, and the command reads no directory. Each root then has the checks of a search root above. The root does not need to be in a Git work tree; each unit needs its repository (section 12, "Version-control evidence").
- The project roots that mise records, for `project.dependency-directory` only, unless the command has `--no-mise`. mise makes a symbolic link in `$XDG_STATE_HOME/mise/tracked-configs` (else `~/.local/state/mise/tracked-configs`) for each configuration file that it loads. The client reads the targets of at most 1,024 links and runs no mise command, reads no configuration file, and follows no link. The directory must be a directory with the user as owner, not a symbolic link. A link gives a project root only when its target is a plain absolute path (a relative target is relative to the directory of the link) below the home directory to a regular file. The project root is the directory of the file, as mise defines it: a file in `.config`, `.config/mise`, `.config/mise/conf.d`, `mise`, or `.mise` belongs to the directory above those directories. A global configuration gives no project root: a file below `$XDG_CONFIG_HOME/mise` (else `~/.config/mise`), and a file whose project root is the home directory. A dangling link (`target_absent`), a target outside the home directory (`target_outside_home`), an entry that is not a link (`not_a_link`), and a target with `.` or `..` (`target_not_plain`) give no project root, and the report names each such link.

A project root is a project directory, not a search root: the inspection examines the units of that directory only, and the walk reads no directory below it. Its repository must be the project directory itself, because the repository lookup stops at the root. So that no directory is walked twice, the request leaves out a root with the path of an earlier root (`repeated_root`), a search root below another search root, and a project root that is a search root or is below one (`in_search_root`); the comparisons ignore the case of ASCII letters. The report has each root that was left out, with the outcome `covered` and its reason, and the walk of the other root examines its units. The comparison of a root with the user exclusions ignores the case of ASCII letters too, and it is made again with the names that the filesystem stores, so that `--root ~/documents` is refused on a volume that ignores case when `~/Documents` is excluded (`root_excluded`). The request has at most 16 search roots and at most 256 project roots, else the command refuses it with `too_many_search_roots`. A request with no root gives `no_search_roots`.

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
| 10 | `satisfied`: the discovery examined the identity, the records, and the activity of the unit in this call. The coordinator reads the activity of the producer and makes the use check of section 6 again before each step ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7), and the executor compares the object with the plan before its call |

With no state directory, the hard exclusion of the control-plane state has no path: the discovery examines no rule, and its result is not complete.

### Age and use

File timestamps are observations, not ownership records or proof that data is unused. Atime alone is insufficient. Modification time alone does not establish whether a producer has an item open or intends to reuse it.

A rule declares whether its age derives from a producer index, Svalnir's own lifecycle record, or validated filesystem metadata. Record the source and uncertainty. Future timestamps, implausible clock shifts, or incomplete history must not prematurely expire a candidate. Monotonic time controls observation windows within the current epoch; persisted wall-clock dates require explicit restart handling.

### Activity and namespace safety

Prefer producer-supported lifecycle operations or a verified quiescence protocol. Process-name absence, one open-file scan, or a lock probe alone is not universal proof that no writer exists.

Descriptor-relative traversal, no-follow checks, identity comparison, and constrained mounts reduce substitution risk. They do not make a name check followed by unlink atomic. Moving an entry into quarantine also changes the source before any later check. Apple documents the general TOCTOU and cooperative-locking limitations in its [secure file-operation guidance][apple-races].

Before automatic mutation, the rule must document and test confinement. A deliberately disposable namespace may accept a documented residual race within that confinement; authorization alone does not establish it. An active or adversarial writable namespace without that evidence remains ineligible.

New entries discovered during execution are not silently added to a fixed plan. Unexpected replacement or growth invalidates the affected unit. Any protocol that can select the wrong entry despite its checks must state that residual risk in its promotion evidence.

### Use by a running process

The use check is a part of predicate 6 for each file rule. It is in addition to the producer evidence of the rule; it does not replace that evidence. A unit is in use when a process of the user does one of these:

| Kind of use | Evidence | Serialized value |
| --- | --- | --- |
| Open file | A file descriptor of the process refers to a vnode at or below the unit (`proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`) | `open_file` |
| Mapped file | A memory region of the process maps a file at or below the unit (`proc_pidinfo` with the flavor `PROC_PIDREGIONPATHINFO2` of the kernel, which gives only the regions that map a file; a call that fails or finds no file is made again with the public flavor `PROC_PIDREGIONPATHINFO`. The private flavor is kept for its speed, owner decision of 2026-11-22: on one host it read the regions of 1079 processes in 0.3 s, where the public flavor needed 9 s, with the same paths. The fallback makes sure that it can add no miss) | `mapped_file` |
| Working directory | The working directory of the process is at or below the unit (`proc_pidinfo(PROC_PIDVNODEPATHINFO)`) | `working_directory` |
| Executable | The executable of the process is at or below the unit (`proc_pidpath`) | `executable` |
| Argument | An argument of the command line names a path at or below the unit (`sysctl` `KERN_PROCARGS2`) | `argument` |

A process of the user is a process whose effective or real user is the user of the discovery. The process that makes the check is not examined. The check compares paths by component and ignores the case of ASCII letters, so a difference of case gives a use and not a miss. It compares each path with the unit path as the discovery found it, with the unit path with its symbolic links resolved, and with the form of each of them below `/System/Volumes/Data`.

A path from the kernel is evidence only when the check can verify it. The kernel gives, with each open file, each mapped file, and the working directory, the device, the inode, and the link count of the vnode. It can also give a path that is not complete with a success status, for example for a path that is longer than `MAXPATHLEN`. A path that is in a scope of the check is a use, with no other check. The kernel builds a path from its last component to the root, and it stops at the first component that does not fit into the buffer of `MAXPATHLEN` (1024) bytes. A cut path thus starts with a component from the middle of the path. One component can have 255 UTF-16 units; on APFS that is at most 765 bytes in UTF-8 (255 characters of three bytes, measured: a name of 255 four-byte characters is refused, and 127 is the most). A cut result therefore has at least 1024 − 1 − (765 + 1) = 257 bytes. On the measured host, a file below a component of 765 bytes and one of 250 bytes gave a cut path of 266 bytes for an open file, of 264 bytes for the working directory, and of 270 bytes for a mapped region, each with a success status. A path that is not in a scope and is shorter than 257 bytes is complete, and it is evidence that the object was not in a unit at the time of the query. A later move of that object into a unit is a use that starts after the check. For a path of 257 bytes or more, the check reads the entries of `/` one time for each inventory. When the first component of the path is not an entry of `/`, the path is cut, and the process is unknown with no file query. Otherwise the path is evidence only when the file at that path now has the device and the inode of the vnode, with or without the resolution of a symbolic link at its end (`stat` or `lstat`). When the entries of `/` cannot be read, each such path is not verified. A vnode with no link (a file that was removed while it was open) is not in a unit. Each other path, and each vnode of an open descriptor or of a mapped region that has links and no path, makes the process unknown with the reason `path_not_verified`. The bound comes from the order in which the kernel builds a path, the size of the buffer, and the longest name of APFS; it is not a documented contract of the kernel. Promotion evidence must confirm it on each supported macOS version and for each filesystem of a root.

An argument names a path in these forms. The check does not follow a symbolic link in an argument.

- An absolute path, and a relative path when the working directory of the process is known; a relative path is joined to that working directory.
- The part after the first `=`, as in `NAME=PATH` or `--option=PATH`.
- The part after an option prefix of one or two characters after `-`, when that part is an absolute path, as in `-I/path` or `-o/path`.
- Each part of a list that `:` separates, as in `PATH=/a:/b`.
- The path of a `file://` URL, with the percent encoding decoded.

The check does not resolve `..` in an argument, because the directory before `..` can be a symbolic link. A path with `..` is a use of each unit that contains the part before its first `..`, and also of each unit that contains its form with each `..` applied to the component before it. A symbolic link before `..` that leads into a unit is a case of the blind spot of a symbolic link in an argument.

The check reads the arguments in memory only to compare them with the unit paths. It keeps no argument that does not name a path in a scope of the check, and it never stores, logs, or prints a command line. A use record has the PID, the executable name, the kind of use, and the path relative to the unit; for an argument, the record has only the first component of that relative path. It has no other part of the command line.

A process of the user has one of three states in the inventory. A process whose queries answer is examined. A process that refuses or fails a query, or that passes a bound of one process (its file descriptors, its memory regions, or the size of its arguments), is an unknown process. An unknown process can use each unit. A process that exits during the reading is not in the inventory; it uses nothing after it exits (owner decision of 2026-11-22). The check reads the start time of the process before and after its queries. When the process exited, it is not in the inventory. When the PID names a different process, the check examines the new process once more, and a second change makes it unknown.

A process is not visible, and does not block a unit, only when all of these are true (owner decision of 2026-11-22):

- Each failure of its queries is a refusal with `EPERM`; `EACCES` and each other failure keep it unknown. The refusal can be of the identity query, for example of a set-user-ID process such as `login`, or of a use query.
- No bound of one process was reached.
- Its executable (`proc_pidpath`) is on the sealed system volume: below `/System` but not below `/System/Volumes`, or below `/usr/libexec`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`.
- Its running code is an Apple platform binary. The check finds the code of the process by its PID (`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributePid`). It validates the dynamic signature against the requirement `anchor apple`, which only code that Apple signs satisfies, and it requires the platform identifier of the signing information (`kSecCodeInfoPlatformIdentifier`), which only code signed as part of an operating system release has. The check uses these documented Security framework calls and not the private `csops` call. A failed signature check keeps the process unknown.

A use that such a process gave before the refusal still blocks. The owner query comes before each use query, so the check makes no use query of a process of a different user.

The executable of a process can have no current name: `proc_pidpath` fails with `ENOENT` when the file was removed or replaced after the process started, for example by an update of its application. Such a process is known, with no executable use, when each other query of it answered and each of its paths passed the verification above; its mapped regions and its working directory stay evidence. Each other failure of `proc_pidpath` keeps the process unknown.

The inventory as a whole is not complete when the process list cannot be read, when the list has no process of the user, when the clock gives no time, or when the inventory passes its bound of processes or of time.

The check has three results:

- `in_use`: the inventory has one use of the unit. This applies also when the inventory is not complete or has an unknown process.
- `not_in_use`: the inventory is complete, has no unknown process, and has no use of the unit.
- Unknown: each other case. The reason is the name of the gap of the inventory, or `process_not_readable` with the PID, the executable name, and the failed query of each unknown process. The unit is not a candidate.

The inventory is read one time for each discovery, after the walk of the roots and before the facts of admission, with the bound roots as its scope. The coordinator makes the check again for the unit of each step of an eviction, immediately before the call ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7). A unit that is in use is skipped with the reason `unit_in_use`, and a unit whose use is unknown is skipped with the reason `unit_use_unknown`.

The check has these known blind spots. Each one is a residual risk of each rule that uses the check, and a rule needs other evidence for it:

- A process that starts to use the unit after the check. The check before each step makes the window short; it does not close it.
- A service that is stopped now and uses the unit when it starts again, and a job that `launchd`, `cron`, or a different scheduler starts at a later time.
- A process of a different user. The check does not see it.
- An Apple platform process on the sealed system volume that refuses a query, for example `login` or a hardened agent of the user such as `routined` or `com.apple.quicklook.ThumbnailsAgent` (owner decision of 2026-11-22). Such a process can read a unit, for example to make a thumbnail, and the check does not see that use. The code is part of the operating system, so the risk is that the process reads a file that a removal then deletes, not that unknown code writes the unit. The code is found by its PID: a process that exits, and whose PID a new process takes before the use queries, is examined as the new process; the new process must also pass both conditions.
- A use with no open descriptor, no mapping, no working directory, no executable, and no argument at the time of the check: for example a tool that opens a file only for a short time, or a path in a configuration file or in an environment variable.
- An argument that names the unit through a symbolic link, also before a `..`.

### Repositories in a unit

A directory that a tool makes, or that Git ignores, can hold a dependency that a person cloned with Git. The commits, the stash, and the changed files of that clone can exist only in that clone, and the enclosing repository does not show them. Thus a unit that holds a Git repository at any depth does not satisfy predicate 4.

- A unit holds a repository when an object with the name `.git` is at some depth below it, or is in it: a directory, a file that names the Git directory of a submodule or of a linked worktree, or an object of another kind. A unit also holds a repository when a directory in it, or the unit itself, is a Git directory with no `.git` name, as of a bare repository, a mirror, or a separate Git directory: it has `HEAD` as a file or a symbolic link, and `objects` and `refs` as directories. That is the test of Git for a Git directory, with no check of the content of `HEAD`. Each comparison of a name ignores the case of ASCII letters. The skip reason is `nested_repository` (category `protected_data`), and the skip names the first `.git` object or Git directory, relative to the unit.
- A directory that the check cannot read, a directory on another device, and a check that stops at a bound also refuse the unit, because such a directory can hold a repository.
- A check is a check of names at one time: a repository that a process makes in a directory after the last check of that directory is not seen. A Git directory outside the unit whose `core.worktree` names a directory in the unit leaves no Git object in the unit, so no check finds that work tree. Each is a residual risk of each revision.

| Point | Check |
| --- | --- |
| The measurement of a unit in a discovery (`svalnir.expired-temporary`, `xcode.inactive-derived-data`) | The scanner reads each entry of the unit. A `.git` entry or a Git directory adds `nested_repository` and makes predicate 4 `not_satisfied`. A discovery that examines only the known candidates measures no tree again (section 7), so it does not do the check again; the executor does |
| The inspection of `project.dependency-directory` (section 12) | The measurement of the unit with the scanner does the check, with no second walk. A repository, a region that the scan could not read, a mount boundary, and a scan that is not complete refuse the unit: the outcome is `repository_refused` with the reason and the path relative to the unit, and no size is reported. For a unit of `swiftpm-build` or `xcode-project-derived-data` with a repository, the walk below examines the unit again with the exception for the checkouts of Swift Package Manager |
| The filesystem executor, for a directory target of `EvictRegenerableData` | The measurement of the tree, before the first removal call, refuses the whole tree with `nested_repository` (family `eligibility`), and nothing is removed. The removal pass then reads the names of each directory again immediately before it removes the entries of that directory. When a `.git` name or a Git directory appeared there after the measurement, it removes no further entry of the tree: the entries that it removed before stay removed, the new repository and the directories above it stay, and the result has `nested_repository` ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |
| `clean plan` in the `trash` and `permanent` modes | A target of `DeleteSelectedFiles` or `MoveToTrash` is not refused: the user selected that entry. `clean plan` walks each selected directory (at most 256) and lists each one that holds a repository, or that the walk could not examine completely, in `repository_warnings` with the code and the path relative to the entry; the text output shows a warning ([INTERFACES.md](INTERFACES.md) section 4) |

The walk of `clean plan` and of the exception below has a depth bound of 64, an entry bound of 2,000,000, and a time bound (10 s for `clean plan`, 60 s otherwise). It follows no symbolic link, does not enter another device, does not enter a Git directory, and reads each name relative to an open directory. It opens the unit from `/` one component at a time, so a unit path with a symbolic link is refused (`repository_check_unit_unavailable`); `clean plan` walks the selected entry with its symbolic links resolved, because its result is a warning only.

**Checkouts of Swift Package Manager.** Swift Package Manager keeps a clone of each remote dependency in `checkouts/IDENTITY` of its build directory and a bare mirror in `repositories/NAME`, and it makes both again from the pins of `Package.resolved`. For a unit with that layout, a repository with a `.git` directory directly in the `checkouts` directory does not refuse the unit when each of these is true:

1. Its `.git` directory, read with no symbolic link followed, is the object that the walk measured (else `repository_identity_changed`).
2. A pin of `Package.resolved` has the identity of the checkout: the name of its directory in lower case. The check reads versions 1, 2, and 3 of the file, from a regular file of no more than 1 MiB.
3. `HEAD` is the revision of the pin.
4. The configuration of the repository names no filter driver (`filter.*`). No command-line value turns off a filter driver, and `git status` can run it on a changed file. The other keys that can run a program for the queries are turned off on the command line of each query: `core.fsmonitor`, `core.hooksPath`, `log.showSignature`, `gpg.program`, `gpg.ssh.program`, `gpg.x509.program`, `credential.helper`, and `protocol.allow`; the environment permits no transport and no pager. The filter check is thus one of two controls, not the only one.
5. The one remote of the checkout, `origin`, is the location of the pin, or is a mirror directly in the `repositories` directory beside `checkouts` that the mirror conditions below accept for that pin. Two absolute paths must name the same directory; two URLs must be equal, apart from one trailing slash.
6. The checkout has no stash and no linked worktree.
7. `git status` reports no changed, untracked, or ignored file, and no file has the `assume-unchanged` or the `skip-worktree` flag.
8. `core.logAllRefUpdates` is not false, and each entry of the reflogs of the remote-tracking references of `origin` is a fetch or a clone: a push from the checkout leaves another entry.
9. Each commit of its references and reflogs is reachable from a remote-tracking reference of `origin`, from `HEAD`, or from a tag that the mirror has with the same object.

A Git directory directly in the `repositories` directory, a mirror, does not refuse the unit when its Git directory is the object that the walk measured, it is bare, its one remote is the location of a pin, no commit is only in its reflogs, and each entry of its reflogs is a fetch or a clone. A bare repository records no reflog by default, so a push into a mirror from another repository leaves no record: that is a residual risk of the exception.

Each other repository refuses the unit. The refusal gives a stable reason, for example `swiftpm_revision_not_pinned`, `swiftpm_checkout_changed`, or `swiftpm_reflog_not_fetch`, and the path of the repository relative to the unit. The checks use the trusted Git executable and the fixed environment of the read-only queries of section 12; without that executable, each checkout and each mirror is refused (`swiftpm_git_unavailable`). For `.build` beside `Package.swift`, the pins are in `Package.resolved` beside `Package.swift`. For a project directory of `DerivedData`, the checkouts are in `SourcePackages/checkouts`, and the pins are in the workspace that `WorkspacePath` names: `xcshareddata/swiftpm/Package.resolved` of a workspace, `project.xcworkspace/xcshareddata/swiftpm/Package.resolved` of a project, or `Package.resolved` of a package directory.

The units of `xcode.inactive-derived-data` are below `Build` and `Index.noindex` and never include `SourcePackages` (section 11), so its discovery and the executor refuse each repository. The inspection of `project.dependency-directory` applies the exception to the units of its layouts `swiftpm-build` and `xcode-project-derived-data` (section 12): when the measurement finds a repository in such a unit, the walk of this section examines the unit again with the checkouts and the pins of its layout. The discovery of that rule for an eviction applies no exception: the filesystem executor of an eviction refuses each repository, so a unit with checkouts is skipped with `nested_repository`. The exception has fixture tests only.

### Project activity

A rule for the generated data of a project (section 12) uses the project activity as a part of predicate 5. The project activity tells when a person or a coding agent last worked in the project. A rule prefers a project that nobody worked on for the quiet period. The project root is the top directory of the work tree of the repository of the unit (section 12, "Version-control evidence").

The project activity has three sources:

| Source | Evidence | Serialized value |
| --- | --- | --- |
| Git | The newest modification time of the two files that `git rev-parse --git-path logs/HEAD --git-path HEAD` names: the reflog of `HEAD` and `HEAD`. A commit, a checkout, a reset, a rebase, and a merge change these files. The index is not used, because `git status` writes it | `git_head` |
| Claude Code transcripts | The newest modification time of a `.jsonl` file in a folder of `~/.claude/projects` whose name matches the encoded project root (see below), and in the subfolders of that folder to a depth of two | `claude_code_transcripts` |
| Paseo agents | The status of each agent that `paseo ls --json --global --background` lists | `paseo_agents` |

The Git query is a built-in command of the verified Git executable of section 12. It runs with the fixed environment and arguments of that section, so it runs no program from the configuration of the repository. A relative path of the output is relative to the work tree. The source reads the metadata of each of the two files, and does not follow a symbolic link at the end of a path. When one file exists and the other does not, the time of the file that exists applies. When neither file exists, the source fails with `git_head_missing`: a repository with no `HEAD` gives no evidence of quiet. A file whose metadata cannot be read makes the source fail with `git_head_not_readable`. The Git source thus always gives a time or a failure, never "no evidence".

The encoded name of a directory is its absolute path with each UTF-16 code unit that is not an ASCII letter or an ASCII digit replaced by `-`. A character outside the Basic Multilingual Plane, for example an emoji, has two code units and thus gives `--`. Claude Code 2.1.330 keeps an encoded name of at most 200 code units. It cuts a longer name to its first 200 code units and adds `-` and a hash of the path. On the measured host (owner observation of 2026-11-22), the folder of `/Users/NAME/GitHub/svalnir` is `-Users-NAME-GitHub-svalnir`, and the folder of `/Users/NAME/GitHub/svalnir/.claude/worktrees/W` is `-Users-NAME-GitHub-svalnir--claude-worktrees-W`.

A folder matches the project root when its name, with the case of ASCII letters ignored, is the encoded root or starts with the encoded root and `-`. For an encoded root of more than 200 code units, the source uses its first 200 code units in place of the encoded root, so a folder that Claude Code cut matches. The source does not compute the hash: each root with the same first 200 code units matches the folder. The source encodes the root as the walk found it and in its resolved form. When the Unicode NFC and NFD forms of a path differ, the source encodes each form too, because the spelling that Claude Code received is not known. The encoding is not reversible. A sibling such as `app-two` thus matches the root `app`. Each of these rules can only make a root more active, never more quiet. A transcript folder that has no transcript gives no evidence; that is the only source that can give "no evidence". The source reads only the names of directory entries and their metadata. It never opens a transcript and never reads its content. It reads the folder of the home directory of the user only; it does not read the variable `CLAUDE_CONFIG_DIR`, because the environment of the agent or of a client is not the environment of the shell in which the user runs Claude Code. The package cache rules of section 12 read no environment variable for the same reason. A different configuration folder of Claude Code is not seen. The read has a bound of entries and does not follow a symbolic link.

The Paseo source is off unless the configuration turns it on (`[cleanup.projects].paseo_agents`, [POLICY_SPEC.md](POLICY_SPEC.md) section 3). When it is on, the source runs `paseo` only from a fixed list of paths, and only when the resolved file and each directory above it have the superuser as owner and permit no write by the group or by others, as for Git. It never takes `paseo` from `PATH`. The command has fixed arguments, an empty environment with `HOME`, `PATH=/usr/bin:/bin`, `LC_ALL=C`, and `NO_COLOR=1`, a deadline of 15 seconds, a process group of its own that the source stops at the deadline, and an output bound of 1 MiB. The output must be a JSON array of objects. Each object must have a `status` of `initializing`, `running`, `idle`, `error`, or `closed`, and a `cwd` that is a string, `null`, or absent. A `cwd` that starts with `~/` is relative to the home directory. A `running` or `initializing` agent whose working directory is the project root or below it makes the project busy. An `idle`, `error`, or `closed` agent does not. If Paseo is a script, the check of the file does not authenticate the interpreter or the modules that it loads; that is a residual risk of the source.

A project is in one of three states:

| State | Condition | Predicate 5 |
| --- | --- | --- |
| `busy` | The Paseo source is on, and it lists a `running` or `initializing` agent in the project, or it fails | `not_satisfied` |
| `quiet` | The project is not busy, the newest time of the sources is known, each source that ran gave a result, and the newest time is at least the quiet period before the wall-clock time of the assessment | `satisfied` |
| `active` | Each other case | See the next table |

A project that is not `busy` is `active` in these cases, which the assessment examines in this sequence. The first case that applies gives the reason:

| Reason | Condition | Predicate 5 |
| --- | --- | --- |
| `clock_unknown` | The clock gives no wall-clock time | `unknown`, also when a source gives a time |
| `recent_activity` | A source gives a time that is less than the quiet period before the assessment. A time after the assessment, for example from a clock change, is also in this case | `not_satisfied` |
| `activity_source_failed` | A source failed: the Git query failed, its output is not usable, or neither file exists; the transcript folder exists and cannot be read; or the read of the transcripts passed its bound | `unknown`, also when the other source gives a time that is older than the quiet period |
| `no_activity_evidence` | No source gives a time. An unknown last activity is never a quiet project | `unknown` |

The Paseo source fails, and makes each project `busy`, when it is on and one of these is true. The reason of the failure is the reason of the state of each project, so the report of each unit shows why each project is busy:

| Reason | Condition |
| --- | --- |
| `paseo_not_installed` | No path of the list has an executable |
| `paseo_not_trusted` | An executable exists, and it or a directory above it fails the ownership and permission checks |
| `paseo_not_started`, `paseo_timeout`, `paseo_signaled`, `paseo_read_failed` | The command does not start, passes its deadline, ends with a signal, or its output cannot be read |
| `paseo_failed` | The command ends with a status that is not 0 |
| `paseo_output_too_long` | The output is longer than 1 MiB |
| `paseo_output_not_array`, `paseo_entry_not_object`, `paseo_entry_status`, `paseo_entry_cwd` | The output is not a JSON array, or an entry has the wrong form |
| `paseo_agent_without_directory` | A `running` or `initializing` agent has no absolute working directory, so the source cannot tell in which project the agent works |
| `home_unknown` | The home directory is not known |

A project that the source lists as running is `busy` with the reason `agent_running`. Fail closed: an agent can work in each project. A `busy` project is never a candidate, also when a later mode permits a selection of an `active` project.

A project with no transcript folder has no transcript evidence. The Git source then decides alone.

The project activity does not show these. Each one is a residual risk of a rule that uses it. The use check ("Use by a running process") sees a running process only:

- An edit of the files of the work tree that is not committed.
- A build, a test, or an install. These do not change `HEAD` or its reflog.
- An editor, an IDE, or a coding agent other than Claude Code and Paseo.
- A service or a scheduled job that uses the project.
- A Claude Code session or a Paseo agent whose working directory is above the project root, for example a session in the directory of all the projects of the user. It does not mark the project, also when it works in it.
- A Claude Code folder whose name a later version of Claude Code encodes or cuts in a different way. Promotion evidence must confirm the encoding on each supported version of Claude Code.

A quiet project is a preference, not proof that the data is not used. The other predicates, the use check, and the fresh check before each step still apply.

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

Every entry is currently **proposed**. The first two entries have a discovery in `svalnir-agent`. `project.dependency-directory` has a declaration with the inspection mode and the manual eviction, and no automatic mode, with an inspection and a discovery for a manual eviction in `svalnir-agent` (`rules::projects`, section 12), with the layout catalog of section 12 and the layouts of the configuration. Its layouts are `proposed`, so the `evict` mode refuses it in a released build; a test build with a fixture lifecycle state gives it at most `manual_action_validated`. `cargo.build-output` is retired: the layout `cargo-target` of `project.dependency-directory` takes its place, and its identity stays reserved. `simulator.devices`, `container.build-cache`, and `homebrew.cleanup` have the same status (`rules::owner_tools`): their inspection attributes the data from the documented on-disk layout and gives the command of the owner tool, as section 9 requires for a command whose effect Svalnir cannot bound, and this build runs no command of their owner tools. `git.linked-worktree` has a declaration with the inspection mode only and an inspection in `svalnir-agent` (`rules::worktrees`, section 12) that reports the work of each linked worktree; this build has no removal of a worktree. The six entries from `pnpm.content-store` to `cocoapods.cache` have a declaration with the inspection mode only and an inspection in `svalnir-agent` (`rules::caches`): it reports the resolved root (section 4), the measured size of each unit, and the owner workflow of section 12, and it gives no candidate. For `pnpm.content-store` and `uv.cache` the inspection gives no reclaim figure; for the other four the figure is the allocated size, which is not exclusive storage. A layout of these six rules stays `proposed` also in a test build with a fixture lifecycle state, so the `evict` mode refuses each of them. The other entries have no implementation. The “Initial development target” column is implementation priority, not present eligibility or a shipped default.

| Rule ID | Intended unit | Initial development target |
| --- | --- | --- |
| `svalnir.expired-temporary` | One Svalnir-created disposable item or sealed generation | Automatic eviction after gates |
| `xcode.inactive-derived-data` | A reviewed generated subset for one identified project/layout | Automatic eviction after gates |
| `npm.content-cache` | Precisely scoped package-cache entries or an explicitly selected owner operation | Inspection and manual workflow first |
| `pip.cache` | Verified producer cache scope or selected supported entries | Inspection and manual workflow first |
| `cargo.build-output` | Retired and reserved: the layout `cargo-target` of `project.dependency-directory` | None |
| `gradle.cache-inventory` | Attributed cache families and owner-retention information | Inspection and recommendations |
| `pnpm.content-store` | The content-addressed store of one resolved store path, through the owner operation | Inspection and manual workflow first |
| `yarn.cache` | The resolved global cache of one Yarn installation | Inspection and manual workflow first |
| `go.build-cache` | The resolved `GOCACHE` directory of one Go installation | Inspection and manual workflow first |
| `uv.cache` | The resolved cache directory of one uv installation, through the owner operation | Inspection and manual workflow first |
| `homebrew.download-cache` | The downloads of the resolved Homebrew cache | Inspection and manual workflow first |
| `cocoapods.cache` | The resolved download cache of one CocoaPods installation | Inspection and manual workflow first |
| `project.dependency-directory` | One generated directory of one identified project below a directory that the user names, in a layout of the catalog of section 12 or of the configuration | Inspection, then manual selection; never automatic in Milestone 4, and never automatic for a user-configured layout |
| `simulator.devices` | One simulator device or runtime, through the owner tool | Inspection and manual owner workflow |
| `container.build-cache` | The build cache that the container engine reports, through the owner tool | Inspection and manual owner workflow |
| `homebrew.cleanup` | The old kegs of the formulae of one Homebrew prefix, through the owner tool | Inspection and manual owner workflow |
| `git.linked-worktree` | One linked worktree of one identified repository below a directory that the user names | Inspection; a later removal is manual only, never automatic, and needs the preservation of its work |

The six entries from `pnpm.content-store` to `cocoapods.cache` are package and build caches of the same class as `npm.content-cache` (owner decision of 2026-11-20). They widen the developer coverage of the first release. Each one stays `proposed` until it has its own promotion evidence (section 15).

The registry deliberately omits a universal “all application caches” rule. More adapters can be added when their ownership, lifecycle, and concurrency contracts are known.

### Rule families after the first release

The families of Milestone 4 (owner decision of 2026-11-20) are in the registry: the project dependency and build directories as `project.dependency-directory`, the simulator devices and runtimes as `simulator.devices`, the container build cache as `container.build-cache`, Homebrew cleanup as `homebrew.cleanup`, and Git worktrees as `git.linked-worktree`. Each one is `proposed`. `project.dependency-directory` also has the manual eviction in code (owner decision of 2026-11-22), and the others have the inspection mode only; a mode beyond inspection needs its own support matrix, action gates, and promotion evidence (section 15).

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

The caller makes the inventory from the process table immediately before the discovery of the root: the executable name of each process whose effective or real user is the user of the discovery. A process that exited during the reading is not in the inventory. For a denied identity query, the owner query decides: a process of a different user is out of the scope; a process of the user is not in the inventory only when it passes the platform gate of section 6 (a refusal with `EPERM`, an executable on the sealed system volume, and Apple platform code); each other such process makes the evidence unknown. The inventory is complete only when each other process gave its user and its executable path; a query that failed for a different cause, a process list that cannot be read, a list with no process, or a clock that gives no time makes the evidence unknown. The observation time is the time before the first query.

The rule examines the lock of the build database of a project (`Build/Intermediates.noindex/XCBuildData/build.db`) for each unit of that project. A project with no build database has no lock evidence, so each of its units has an unknown activity. Thus, after the unit `Build/Intermediates.noindex` of a project is evicted, the units `Build/Products` and `Index.noindex` of that project are not candidates until a build makes the database again. The three units of a project are evicted together only when one batch has them. Whether the revision keeps this property is an open point of its promotion (section 15).

The project that owns a unit comes from the `WorkspacePath` value of the `info.plist` file of its DerivedData directory. The user can write that file, so the value is attribution evidence of the same user and not a protected record: a same-user process that changes it can change which project the rule examines. It cannot move a unit out of the verified root, and it gives no access to the data of a different user. The value can also name a network volume or an automounter path. The rule examines it only with the local check of section 4: a project path on a filesystem that is not local, or for which the mount table has no mount, makes predicate 4 `unknown` with the reason `source_not_local`, and the rule makes no call on that path. A project path with a symbolic link also makes predicate 4 `unknown`, because the rule does not follow it, and makes predicate 7 `unknown`, because the text of the path then does not show whether the project overlaps the root. The rule does not compare the name hash of the project directory with `WorkspacePath`.

Each child of a unit must be on a fixed allow-list of the children that the build system makes. A unit with a child that the list does not accept is skipped whole with the reason `unsupported_layout`: no part of it is a candidate, and nothing in it is removed. The comparison is exact, so a name in another case or another spelling is not accepted. The list of this revision is:

| Unit | Accepted children |
| --- | --- |
| `Build/Products` | A directory `CONFIGURATION` or `CONFIGURATION-PLATFORM`, where `CONFIGURATION` is `Debug` or `Release` and `-PLATFORM` is one of `-iphoneos`, `-iphonesimulator`, `-appletvos`, `-appletvsimulator`, `-watchos`, `-watchsimulator`, `-xros`, `-xrsimulator`, `-maccatalyst`, or `-driverkit` |
| `Build/Intermediates.noindex` | A directory `NAME.build` with a name that is not empty; the directories `XCBuildData`, `PrecompiledHeaders`, `ExplicitPrecompiledModules`, and `SwiftExplicitPrecompiledModules`; a directory `GeneratedModuleMaps` or `GeneratedModuleMaps-PLATFORM` with a suffix of the first row |
| `Index.noindex` | The directories `DataStore`, `Build`, and `PrecompiledHeaders` |
| Each unit | The regular file `.DS_Store`, the view settings that Finder writes in a directory that a person opened |

The deny-list of the candidate paragraph is a second check. It applies to each entry at each depth, also below an accepted child, and its reason is `protected_data`. The allow-list examines the children of a unit only, so a file that a person puts below an accepted child with a name that the deny-list does not have stays a residual risk of the revision. A unit with a `.git` object or a Git directory at any depth is skipped with `nested_repository` (section 6, "Repositories in a unit"). The package checkouts of a project directory are in `SourcePackages`, which is not a unit, so the exception for the checkouts of Swift Package Manager applies to no unit of this rule.

This list is a first list from the public knowledge of the Xcode build output. It is not verified. A configuration name is free text in a project, so a project with another configuration, or a producer version with another child, has units that the rule skips; that is the safe failure. Promotion evidence from real Xcode installations of each supported producer version must confirm the list, or change it in a new revision, before the layout leaves `proposed` (section 15).

**Action and charge:** User-scope bounded eviction of the fixed eligible set, never a root override. Use conservative per-object `work_bytes` and entry limits; large indivisible outputs do not bypass batch limits.

**Impact:** The user accepts indexing/build latency and possible restoration of dependencies only where the approved subset requires it. Missing sources or uncertain rebuild prerequisites disqualify a candidate. First-release implementation must establish a useful tested subset rather than claim universal DerivedData safety.

## 12. Additional developer integrations

### `project.dependency-directory`

**Purpose:** Show the generated dependency, build, and cache directories of the projects of the user, which a package manager or a build tool makes again from the files of the project, with the evidence that a later manual removal needs.

**Roots:** The roots of the request (section 4): the search roots that the user names in the configuration or with `--root`, and the project roots that mise records. The rule has no default location and never walks the whole home directory. The declaration gives the base `user_selected` (section 3) as a hint; "Approved roots" below gives the root that a plan binds.

**Candidate:** One generated directory of one project, in a layout of the table "Layouts" or of the configuration ("User-configured layouts" below). The name of a directory is never sufficient: the directory that holds the first name of the layout must have a project marker of the layout, the unit must have the inner marker of the layout when the layout has one, and the unit must have no entry at a protected path of the layout.

**Layouts:** Each layout is data in the rule: a stable layout name, the directory, the project markers, an inner marker, the protected paths, the owner workflow that the report shows, and the consequence of a removal. Each layout of this table has the lifecycle state `proposed` (section 2). The coverage follows the project rules of a reference tool that the untracked file PROJECT_REFERENCES.md names, with a project marker for each name: the reference matches some names with no marker, and this rule does not.

| Layout | Directory | Project marker beside it | Inner marker | Protected paths | Owner workflow | Reclaim figure |
| --- | --- | --- | --- | --- | --- | --- |
| `node-modules` | `node_modules` | `package.json` | None | None | The install command of the package manager | None: pnpm and Bun link package files from a store with hard links or clones |
| `python-venv` | `.venv` | `pyproject.toml`, `requirements.txt`, `setup.py`, or `Pipfile` | `pyvenv.cfg` | None | `uv sync`, or `python3 -m venv` and an install | None: uv can link files from its cache with clones or hard links |
| `python-venv-plain` | `venv` | As `python-venv` | `pyvenv.cfg` | None | As `python-venv` | As `python-venv` |
| `cocoapods-pods` | `Pods` | `Podfile` | `Manifest.lock` | None | `pod install` | The allocated size |
| `cargo-target` | `target` | `Cargo.toml` | `CACHEDIR.TAG` | None | `cargo clean` | The allocated size |
| `maven-target` | `target` | `pom.xml` | None | None | `mvn clean` | The allocated size |
| `next-build` | `.next` | `package.json` | None | None | `next build` or the development server | The allocated size |
| `turbo-cache` | `.turbo` | `turbo.json` or `package.json` | None | None | The next `turbo run` | The allocated size |
| `svelte-kit` | `.svelte-kit` | `package.json` | None | None | `svelte-kit sync`, a build, or the development server | The allocated size |
| `astro` | `.astro` | `package.json` | None | None | `astro sync` or the development server | The allocated size |
| `parcel-cache` | `.parcel-cache` | `package.json` | None | None | The next build of Parcel | The allocated size |
| `node-dist` | `dist` | `package.json` | None | None | The build script of the project | The allocated size |
| `python-dist` | `dist` | `pyproject.toml` or `setup.py` | None | None | `python3 -m build` | The allocated size |
| `pycache` | `__pycache__` | A file `*.py` | None | None | The next import of the modules | The allocated size |
| `pytest-cache` | `.pytest_cache` | `pyproject.toml`, `pytest.ini`, `setup.cfg`, `tox.ini`, `setup.py`, or `conftest.py` | `CACHEDIR.TAG` | None | `pytest --cache-clear` | The allocated size |
| `mypy-cache` | `.mypy_cache` | `pyproject.toml`, `mypy.ini`, `.mypy.ini`, `setup.cfg`, or `setup.py` | `CACHEDIR.TAG` | None | The next run of mypy | The allocated size |
| `ruff-cache` | `.ruff_cache` | `pyproject.toml`, `ruff.toml`, or `.ruff.toml` | `CACHEDIR.TAG` | None | `ruff clean` | The allocated size |
| `tox` | `.tox` | `tox.ini`, `pyproject.toml`, or `setup.cfg` | None | None | `tox --recreate` | None, as `python-venv` |
| `nox` | `.nox` | `noxfile.py` | None | None | The next run of `nox` | None, as `python-venv` |
| `gradle-project-cache` | `.gradle` | `build.gradle`, `build.gradle.kts`, `settings.gradle`, or `settings.gradle.kts` | None | None | `gradle --stop`, then a removal | The allocated size |
| `gradle-build` | `build` | As `gradle-project-cache` | None | None | `gradle clean` | The allocated size |
| `setuptools-build` | `build` | `pyproject.toml` or `setup.py` | None | None | The next build of the package | The allocated size |
| `mix-build` | `_build` | `mix.exs` | None | `*/rel`, `*/lib/*/src` | `mix clean --deps`, then `mix compile` | The allocated size |
| `dotnet-obj` | `obj` | A file `*.csproj`, `*.fsproj`, or `*.vbproj` | `project.assets.json` | None | `dotnet clean`, then `dotnet restore` | The allocated size |
| `dotnet-bin` | `bin` | As `dotnet-obj` | None; the project must have the file `obj/project.assets.json` | None | `dotnet clean` | The allocated size |
| `swiftpm-build` | `.build` | `Package.swift` | `workspace-state.json` | None | `swift package reset`, or `swift package clean` to keep the checkouts | The allocated size |
| `xcode-project-derived-data` | `DerivedData` | A directory `*.xcworkspace` or `*.xcodeproj`, or the file `Package.swift` | None | None | A build in Xcode or with `xcodebuild -derivedDataPath DerivedData` | The allocated size |
| `zig-cache` | `.zig-cache` | `build.zig` | None | None | The next `zig build` | The allocated size |
| `zig-cache-legacy` | `zig-cache` | `build.zig` | None | None | The next `zig build` of Zig before 0.13 | The allocated size |
| `bundler-vendor` | `vendor/bundle` | `Gemfile` or `gems.rb` | None | None | `bundle install` | The allocated size |
| `rails-tmp-cache` | `tmp/cache` | `config.ru` | None | None | `bin/rails tmp:cache:clear` | The allocated size |

The allocated size is not exclusive storage (section 7). The rules of the table:

- A project marker is a regular file, except the bundles `*.xcworkspace` and `*.xcodeproj` of `xcode-project-derived-data`, which are directories. A marker with `*` or `?` is a pattern: `*` matches each sequence of bytes, `?` matches one byte, and the comparison keeps the case of the letters. A marker that is a symbolic link is not a marker.
- For a directory of two names, such as `vendor/bundle`, the project marker is in the directory that holds the first name, and the first name must be a directory of the user on the same device, not a symbolic link (else `unit_path_not_plain`). The first name, for example `vendor`, is not a unit.
- When two layouts have the same directory, such as `target` or `build`, the first layout in the sequence of the table whose marker is present gives the unit. A layout of the configuration comes after each layout of the table.
- A distinctive name, such as `node_modules`, `.next`, or `__pycache__`, with no project marker of its layout is listed as `project_marker_missing`, and the walk does not enter it. A generic name, such as `venv`, `target`, `dist`, `build`, `_build`, `obj`, `bin`, `vendor/bundle`, or `tmp/cache`, with no marker is an ordinary directory: the report does not list it, and the walk enters it.
- A unit with no inner marker of its layout is refused with `unsupported_layout`. A unit of `dotnet-bin` is also refused with `unsupported_layout` when the project has no regular file `obj/project.assets.json`, reached through directories that are not symbolic links: `bin` is a generic name, and that restore output shows that the .NET SDK builds the project. Cargo, pytest, mypy, and Ruff write `CACHEDIR.TAG` in the directories that they make; a restore of a .NET SDK project writes `obj/project.assets.json`; Swift Package Manager writes `.build/workspace-state.json`.
- A protected path is relative to the unit, and each of its components is a name or a pattern. The search reads the entries of each directory on the way, enters only a directory (never a symbolic link), compares the names with the case of ASCII letters ignored, and matches an entry of each type with the last component. A unit with an entry at a protected path is refused with `protected_child`, and the report names that entry; a directory on the way that cannot be read completely, or a search that passes its bound of 4,096 directories, refuses the unit with `protected_child_unknown`. A release of Mix in `_build/ENV/rel` can hold a generated Erlang cookie and the earlier versions that an upgrade needs, which a new build does not make again, and `_build/PROFILE/lib/DEP/src` holds dependency sources with no Git data.
- One directory is never in two units. A unit that is, holds, or is in an earlier unit of the same project is refused with `overlaps_unit`, and the report names the layout of the earlier unit; only the earlier unit has the checks and is measured.
- The walk never enters a directory of the skip list `.git`, `.hg`, `.jj`, `.svn`, and `.cache` (the comparison ignores the case of ASCII letters), or a unit. A unit thus holds its nested generated directories, for example a nested `node_modules`, and a cache of a tool in `.cache` is never a unit.
- The units of `swiftpm-build` and `xcode-project-derived-data` have the exception for the checkouts of Swift Package Manager of section 6. The pins of `.build` are in `Package.resolved` beside `Package.swift`. The checkouts of a `DerivedData` directory of a project are in `SourcePackages/checkouts`; the pins are those of `Package.swift` beside it, else of the one workspace beside it, else of the one project beside it. With two workspaces, or no workspace and two projects, no pins apply, and each repository refuses the unit.

**Names that stay outside the rule:** Each of these names has no layout, so no unit of this rule has it, and the validation of the configuration refuses a user-configured layout whose first name is `zig-out`, `deps`, `vendor`, `tmp`, or `_build` ([POLICY_SPEC.md](POLICY_SPEC.md) section 3):

| Name | Reason |
| --- | --- |
| `zig-out` | It is the install output of Zig, not a cache: it can hold programs and libraries that a person runs or links from it |
| `deps` of Mix | It holds the dependency sources. An edited Hex package there has no Git data that a check can examine, so its loss cannot be detected |
| `_build` beside `rebar.config` | Rebar3 puts dependency sources in `_build/PROFILE/lib`, with no Git data |
| `vendor/cache` | `bundle cache` puts gems there on purpose for an install with no network, and a gem from a source that is not available now cannot be downloaded again |
| The other entries of `tmp` of Rails | They hold process identifier files, sockets, and, in development, the local secret key base |
| `vendor` of Go | `go mod vendor` output is frequently committed or patched by hand, and the reference has no layout for it |
| `.build` with no `Package.swift`, and `DerivedData` with no project marker | The reference matches these names alone; this rule needs a project marker for each name |
| `target` of Cargo outside the workspace (`CARGO_TARGET_DIR` or `build.target-dir`) | Only a `target` beside `Cargo.toml` is found. A target directory at another location can be shared by more than one workspace |

**Residual risks of the generic names:** A layout with a generic name relies on its project marker, on Git, and on the other checks. A directory such as `dist` or `bin` can still hold a file that a person put there on purpose and that Git ignores: the checks cannot tell it from a generated file, and the report gives the consequence of the layout. `target` of Cargo and `build` of Gradle can hold a release program or an application package that a person did not copy to another location. `build` beside `pyproject.toml` can belong to a build back end other than setuptools. A `target` directory that the configuration of another workspace names as its target directory is not exclusive to the workspace beside it; its removal costs only a build. A build daemon, such as the Gradle daemon, the Kotlin daemon, or the MSBuild and `dotnet build-server` nodes, keeps its working directory outside the project, so the producer evidence does not see it; only the use check sees it, and only while it has a file of the unit open, maps one, or names it in an argument. Each of these is a residual risk of the revision, and a manual mode shows it before the approval.

**Cargo output:** The layout `cargo-target` takes the place of the rule `cargo.build-output`, which is retired (section 10). One rule with layouts gives each generated directory of a project the same walk, the same checks, the same budget, and one report, and `cargo.build-output` had no implementation. The identity `cargo.build-output` stays reserved and is never used for another rule.

**User-configured layouts:** The table `[[cleanup.projects.layouts]]` ([POLICY_SPEC.md](POLICY_SPEC.md) section 3) supplies more layouts as parameters of this rule (owner decision of 2026-11-22). A user-configured layout is not a rule and adds no rule identity:

- Its first name is not the directory, or the first name of a directory of two names, of a layout of the table, and is not a name that stays outside the rule, so a unit of a user-configured layout never is, holds, or is in a unit of a layout of the table. Two user-configured layouts can still overlap, for example `gen` and `gen/cache`; the rule `overlaps_unit` above applies.
- Each one has the layout name `user-configured`. Its lifecycle state is a constant of the source, as for each other layout, and it is `proposed` in this build; a promotion of `user-configured` validates the mechanism, not each layout of a configuration.
- It is for a manual mode only: no lifecycle state lets `user-configured` permit `automatic_eviction`. The declaration check refuses the state "Automatic eviction validated" for it, and each place that asks whether a layout permits a mode applies that limit (the registry, the discovery, the readiness of a candidate, the controller, the authority checks, and the `evict` mode). An automatic plan can thus never bind a unit of a user-configured layout.
- Each check of this section applies unchanged: the project marker, the inner marker, the protected paths, Git ignore and an index with no path in the unit, the repository check, the use check, the producer evidence, the project activity, the catalog of protected file locations, and the user exclusions. A user-configured layout has no exception for the checkouts of Swift Package Manager, and its name is generic. Its markers are regular files.
- The report gives no regeneration command for it: the consequence of a removal is not known to Svalnir.
- When the table gives `quiet_period`, the project activity of its units uses that period in place of `[cleanup.projects].quiet_period`.

**Approved roots:** The declaration has one root of the base `user_selected` for each directory of the table, as a hint; the root resolution of the declarations gives such a root no path (section 3). The approved root of a unit of a manual plan is the root of the request whose walk found the unit: a search root or a project root. The discovery binds that root as it binds a root of a declaration (section 4): its device and inode, its volume, and its mount generation, with an identity that is a digest of these values and of its path. The plan target binds the root and the unit relative to it, for each layout and also for `user-configured`, whose directory is known only from the configuration. The coordinator gives the executor the roots that the sealed plan binds, so a root that was replaced or mounted again after the plan is not the approved root of the step.

**Manual eviction:** The discovery for a manual eviction runs the walk and each check of the inspection on the roots of the request, with no measurement in the walk. A unit that passes each check is then measured with the measurement of the other rules (section 7), which refuses a Git repository at each depth with no exception for the checkouts of Swift Package Manager (section 6), a hard-linked file, an entry on another device, and an object that the rule does not support. A symbolic link below a unit is supported from revision `r3`: the measurement does not follow it, and the executor removes the link and not its target. The predicates of section 6 for a unit:

- Predicate 1 (layout): the project marker, the inner marker, the project file, and no protected child of the layout.
- Predicate 2 (identity): the unit and each directory on its way have the user as owner and are on the device of the root.
- Predicate 4 (regenerable): Git ignores the unit, and the index has no path in it.
- Predicate 5 (age and inactivity): the newest modification or status change of the unit and of each object below it is at least the minimum age of the declaration (7 days) before the time of the discovery, and the project activity is `quiet`. With `--include-active`, the state `active` is also accepted; the minimum age stays. A `busy` project never gives a candidate. A recent activity blocks the candidate with `retention_not_elapsed`, and an activity that is not known blocks it with `activity_unknown`.
- Predicate 6 (protocols): the producer evidence and the use check of "Admission" gave a result that permits the unit. The discovery for an eviction makes the use check again with one inventory for all its roots (section 6).
- Predicate 7 (exclusions): the catalog of protected file locations, the hard exclusions, and the user exclusions.
- Predicate 8 (charge): a complete measurement within the candidate ceiling of the declaration.

Each refusal of the inspection is a skipped unit of the discovery with a reason of section 13: for example `not_ignored` and `tracked_files` give `not_regenerable`, `no_repository` gives `regenerability_unknown`, `protected_child` gives `protected_data`, `project_marker_missing` gives `unsupported_layout`, and `producer_active` and `project_busy` give `active_producer`. `--min-size SIZE` only filters: a candidate whose estimate is smaller than the size is not given to the plan builder, and the result names it. The rule is never examined for an automatic eviction or for a discovery of known candidates, whatever its lifecycle state: the discovery leaves it out, its roots are never approved roots of an automatic operation, and the declaration has no automatic mode. A test build gives the rule at most `manual_action_validated`.

**Check before a step:** Immediately before the step of each unit, after the producer reading and the use check ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7), the coordinator makes these checks of the unit again: the project directory still has the project marker of the layout that the sealed plan binds, with no earlier layout of the same directory whose marker is now present (`unit_layout_changed`); the unit still has its inner marker and the project its project file (`unsupported_layout`); the unit has no entry at a protected path of the layout (`protected_child`); the directories on the way and the unit are directories of the user on one device (`unit_path_not_plain`, `unit_symbolic_link`, `unit_owner`, `unit_device`); and no build process of the user works in the project (`producer_active`). A build process above the project gives `build_process_above_project`, and an inventory that is not complete or not current gives `activity_unknown`. A unit of `user-configured` is checked with the layouts of the configuration in effect of the coordinator; a layout that the configuration no longer has gives `unit_layout_unknown`. A unit that is gone at the check has the result `AlreadyAbsent` with no call, as a target that the executor finds absent, and it is not a skipped target. A unit that is no longer a directory is refused with `unit_not_directory`. A refusal skips the target with no call and releases its charge; a check whose evidence is not known has the family `evidence`, and each other refusal the family `eligibility`. The Git evidence and the project activity are not read again at the step: the plan has a short lifetime, the use check sees a process in the unit, and the executor examines each entry again during the removal.

**Version-control evidence:** A unit is a candidate of the manual mode only when Git ignores it and the index of its repository has no path in it. The repository is the nearest directory from the project directory up to the search root with `.git`: a directory with the user as owner, or a file of at most 4 KiB that names a Git directory on a local filesystem, as for a linked worktree. A `.git` that is a symbolic link is not followed. A project with no repository below the search root has no evidence and is not a candidate (`no_repository`), also when its repository is above the search root.

The inspection asks Git, because Git owns the semantics of the ignore files of each level, the sparse index, and the split index. It runs two built-in commands of one executable that it verifies, each with a fixed argument list: `ls-files -z --cached -- ':(literal)PATH'` (a path in the unit is tracked, `tracked_files`) and `check-ignore -q --no-index -- PATH` (exit 0 is ignored; exit 1 is `not_ignored`). The executable is `/Library/Developer/CommandLineTools/usr/bin/git` when its resolved file, and each directory above it, has the superuser as owner and permits no write by the group or by others; the check reads the owner and the mode bits, not access control lists or file flags. The shim `/usr/bin/git`, the Git of Xcode (`/Applications` permits a write by the `admin` group on a standard host), and a Git of Homebrew are not used. The process starts with an empty environment and fixed variables (no system or global configuration file, no terminal prompt, no optional lock, no lazy fetch, no replacement object), with the Git directory and the work tree as explicit arguments, and with `--no-optional-locks`, `core.fsmonitor=false`, and `core.hooksPath=/dev/null` on the command line, which have precedence over the configuration of the repository. A key `protocol.NAME.allow` of the repository has precedence over `protocol.allow`, so the variable `GIT_ALLOW_PROTOCOL` with a list that names no protocol is the control that permits no transport, also for a lazy fetch of a partial clone; Git then ignores each `protocol.*` key. Git has that variable since 2.6.1; `GIT_NO_LAZY_FETCH` has an effect only from the releases of May 2024 (2.45.1, and 2.39.4 to 2.44.1), so in an older Git a lazy fetch starts and fails at the transport. The process runs in a process group of its own; at the deadline, or when a child of Git keeps the output open after the deadline, the whole group is stopped, and a read error of the output is a failure, never an empty output. Neither command runs a hook, writes the index, reads the content of a work-tree file, or runs a filter. Each query has a deadline of 10 seconds and an output bound; a query that fails gives `version_control_unknown`, and with no executable that passes the checks each unit has that result. With no `HOME` and no global configuration, the global ignore file of the user (`core.excludesFile` or `~/.config/git/ignore`) is not read, so a directory that only that file ignores is `not_ignored`, the safe failure. The Xcode path fails the check on a standard host, because `/Applications` permits a write by the `admin` group, so a host with Xcode and no command-line tools has no Git evidence; that is also the safe failure. A file that the last commit has and that the index does not have (a staged removal) is not seen.

**Admission:** A build or package-manager process of the user (for example `node`, `pnpm`, `python3`, `uv`, `pod`, `cargo`, `java` for Gradle and Maven, `beam.smp` for Mix, `dotnet`, `swift-build`, or `zig`; a name never makes a process a target) whose working directory is in the project directory blocks the unit (`producer_active`), and so does each process of the user whose executable is in the project directory, such as `.venv/bin/python`. The inventory reads the process table, the executable of each process of the user, and the working directory of each build process (`proc_pidinfo` with `PROC_PIDVNODEPATHINFO`). A build process whose working directory is above the project directory and in the same search root, such as `pnpm install -r` at the root of a monorepo, `make -C app`, or `npm --prefix app install`, makes the activity unknown (`build_process_above_project`), because its working directory does not show which project it writes. A blocking process blocks the unit also when the inventory is not complete. Only a complete inventory that is not older than the evidence expiry of the rule shows that no process blocks it; an inventory that is not complete, or whose age the clock cannot give, makes the activity unknown (`activity_unknown`), and the unit is not a candidate. The producer evidence does not see a process with a working directory above the search root or outside it that uses the unit (for example `npm --prefix` from the home directory), or a process that is not a build process, such as a language server of an editor. The use check of section 6 runs after the producer evidence, with one inventory for each search root, and sees such a process when it has a file of the unit open, maps a file of the unit, has its working directory in the unit, runs an executable from it, or names it in an argument: the unit is then refused with `unit_in_use`, and a unit whose use is not known is refused with `unit_use_unknown`. The report of the unit has the result of the check. A process that uses the unit in no such way at the time of the check is a residual risk of the revision. A process whose identity query the system denies is examined with the short query of its owner (`PROC_PIDT_SHORTBSDINFO`): a process of a different user is out of the scope, and a process of the user or with no owner makes the inventory not complete. The queries name a process by its identifier and do not compare its identity between them; an identifier that a process of a different user takes between the two owner queries makes the inventory drop the first process, a residual risk. The root of a search keeps the case of the names on the disk, so a root that the caller names as `code` matches the working directory `~/Code/app` that the kernel gives. The manual eviction also needs the minimum age of the declaration and the check before the step ("Manual eviction" and "Check before a step" above).

**Project activity:** The inspection assesses the project activity of section 6 ("Project activity") for each unit whose version-control evidence is `ignored`, with the work tree of its repository as the project root. The quiet period is `[cleanup.projects].quiet_period` ([POLICY_SPEC.md](POLICY_SPEC.md) section 3), 24 hours by default. The report of the unit has the state (`quiet`, `active`, or `busy`), the newest time and its source when they are known, the result of each source, and a stable reason; for a failed Paseo listing, the reason is the reason of the failure, for example `paseo_not_trusted`. The inspection reads the Git source one time for each Git directory. A `busy` project refuses the unit with `project_busy`. An `active` project does not refuse the unit in the inspection: the state is evidence for the selection, and a project with recent activity can still have a large directory that the user wants to see. The inspection reads the Paseo listing one time. The discovery for a manual eviction uses the state as a part of predicate 5: only a `quiet` project gives `satisfied`, or an `active` project with `--include-active` ("Manual eviction" above).

**Exclusions:** Source, project files, lockfiles, a committed or tracked generated directory, a directory that Git does not ignore, a directory with no project marker, a unit with an entry at a protected path of its layout, the names of the table "Names that stay outside the rule", and a symbolic link stay outside the rule. A unit that holds a Git repository at any depth, for example a dependency that a person cloned into `node_modules`, is refused with `repository_refused`, and no size is reported (section 6, "Repositories in a unit"). The catalog of protected file locations and the user exclusions apply to each unit and to each directory that the walk enters.

**Impact:** The next install, sync, or build makes the directory again; it can need a network, a registry that is still available, the install scripts of the packages, and the time of a full build. A package that a person installed by hand in an environment is not in the project files and is lost. The report gives the owner workflow and the consequence of each layout, for example the install command of the package manager; for a user-configured layout the consequence is not known.

**Required evidence:** Projects with each layout of the table and each package manager or build tool of the support matrix, a marker that is a pattern, a directory of two names, two layouts with the same directory, a protected path, the checkouts of Swift Package Manager in `.build` and in `DerivedData`, monorepos with nested projects, a committed generated directory, ignore rules at each level and with negation, a sparse and a split index, linked worktrees, a build or a test that runs during the inspection, hard links and clones from a store, the work charge of large directories, and user-configured layouts with each check. The promotion of `user-configured` (section 15) records evidence for the mechanism and permits at most a manual mode.

### `simulator.devices`

**Purpose:** Show the simulator devices and runtimes of the user, which can use many gigabytes, with the commands of the owner tool that remove them.

Apple documents `xcrun simctl delete` and `xcrun simctl erase` for devices and `xcrun simctl runtime delete` for runtimes. A device has apps, data, and settings that a person made, so its removal is a decision of the user and not a regeneration: simulator contents stay outside each candidate (section 5).

**Roots:** The devices of the user in `~/Library/Developer/CoreSimulator/Devices` (layout `coresimulator-device`), and the runtime bundles in `/Library/Developer/CoreSimulator/Profiles/Runtimes` and in the mounted runtime volumes below `/Library/Developer/CoreSimulator/Volumes` (layout `coresimulator-runtime`, the base `producer_installation`). Each directory has the check of the local filesystem of section 4.

**Candidate:** None in this build. The inspection lists each directory whose name has the form of a device identity (at most 512, from at most 100 000 entries, and the list is marked as cut when a bound or a cancellation stops it), reads its `device.plist` (an XML property list with a root dictionary of scalar values, or the binary form, of at most 64 KiB, with the user as owner and one name), and reports the values `name`, `runtime`, `deviceType`, and `state` (1 is shut down, 3 is booted). A file that is absent, that does not name the identity of its directory, or that has another form gives `unsupported_layout`; a file that the system denies gives `device_plist_denied`, and a file that is not a plain file of the user or that changes during the read gives `device_plist_not_readable`. A device directory that is a symbolic link is not followed. The inspection measures each device for information and gives no reclaim figure, because a device that `simctl clone` made shares its blocks with its source through APFS clones. It lists the runtime bundles by name and does not measure them. Each location of runtime bundles has its result: `read`, `absent`, or refused with a reason (`location_not_directory` for a symbolic link, which is not followed, `location_not_local`, or `location_not_readable`), so an empty list is never a silent failure.

**Owner workflow:** For each device, `xcrun simctl delete UDID`, or `xcrun simctl erase UDID` to keep the device and remove its contents, after `xcrun simctl shutdown UDID` for a booted device; `xcrun simctl delete unavailable` for the devices whose runtime is not installed. For the runtimes, `xcrun simctl runtime list`, then `xcrun simctl runtime delete IDENTIFIER`. Svalnir runs none of them. It also runs no read-only query: `simctl list` starts the simulator service of the user, which is more than a read of the disk.

**Impact:** A deleted device loses its apps, data, and settings. A deleted runtime makes each device of that runtime unavailable and needs a new download to use again.

**Required evidence:** The `device.plist` of each supported Xcode version, devices that boot, clones and their shared blocks, runtimes in volumes and in bundles, and the result of the owner tool on each one.

### `container.build-cache`

**Purpose:** Attribute the storage of a container engine and show the owner command that removes its build cache.

On macOS a container engine runs its images, containers, volumes, and build cache in a virtual machine, and keeps them in one disk image. The build cache is not a set of files that Svalnir can see or measure: only the engine reports it (`docker buildx du`) and removes it (`docker builder prune`).

**Roots:** The documented disk image of each known engine below the home directory (the catalog of protected file locations does not protect `~/Library/Containers`, so the image is read; the object of a unit of this rule would be a regular file): `Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw` of Docker Desktop (layout `docker-desktop-disk`) and `.colima/_lima/colima/diffdisk` of Colima (layout `colima-disk`). A disk image at another location is not seen. These two paths are a first list from public knowledge of the engines and are not verified.

**Candidate:** None, now and in a later revision of this rule: the disk image is a VM disk with persistent volumes and the images in use (section 5), and it is never a unit. The inspection reads the metadata of the image only: its logical size, which is the size that the virtual machine sees, and its allocated size. A sparse image is much larger than its storage, so the inspection gives no reclaim figure. An image that is a symbolic link is not followed.

**Owner workflow:** `docker buildx du` to see the build cache, then `docker builder prune` to remove the build cache that no build uses now; it keeps images, containers, and volumes. `docker system prune --volumes` is not the workflow of this rule, because it removes volumes. The disk image becomes smaller only when the engine reclaims the free space. Svalnir runs no `docker` command: the executable and its plug-ins are in directories that the user can change, and the command talks to the engine.

**Impact:** The next build makes each removed layer again and can need a network and the base images.

**Required evidence:** The disk image paths of each supported engine and version, the effect of the owner command on the allocated size of the image, and engines that keep the image at another location.

### `homebrew.cleanup`

**Purpose:** Show the old versions of the formulae of a Homebrew installation, which `brew cleanup` removes.

**Roots:** The Cellar of each documented Homebrew prefix, `/opt/homebrew` and `/usr/local` (the base `producer_installation`). The Cellar must be a directory on a local filesystem with the user as owner, as Homebrew installs it; a Cellar of another owner or that is a symbolic link is refused.

**Candidate:** None in this build. The inspection reads the names of the kegs `PREFIX/Cellar/FORMULA/VERSION` (at most 10 000 formulae and 64 kegs of each) and the link `PREFIX/opt/FORMULA`, which it reads and does not follow. The inspection reads at most 100 000 entries of one directory and stops at a cancellation; a formula with more kegs than it reads is listed as cut. For a formula with more than one keg it reports each keg, in this sequence of checks: a keg of another owner or on another filesystem than the Cellar is refused (`keg_owner`, `keg_device`); each keg of a formula with an entry in `PREFIX/var/homebrew/pinned` is `pinned`, the current one too; a pin entry that cannot be read (another error than an absent entry) refuses each keg (`pin_state_unknown`); with no link to a keg of the formula, each keg is `current_version_unknown`; the keg that `opt` links is `current`; a keg with an executable that a process of the user runs is `in_use`; with a process inventory that is not complete, an old keg has an unknown activity. Each other keg is an old version and is measured, with the allocated size as an upper estimate. The current keg, the Caskroom, taps, and the Homebrew repository are never a unit; the downloads are `homebrew.download-cache`.

**Owner workflow:** `brew cleanup --dry-run` to see what `brew cleanup` removes, then `brew cleanup FORMULA` or `brew cleanup`; it keeps the current version and the pinned formulae. Svalnir runs no `brew` command: the executable and the Ruby code that it loads are in the prefix, which the user can change.

**Impact:** A removed old version cannot be used again without a reinstall of that version, which needs a source that is still available.

**Required evidence:** The layout of the Cellar and of `opt` for each supported Homebrew version, keg-only formulae, pinned formulae, versions that a service runs, and the result of `brew cleanup` on each one.

### `git.linked-worktree`

**Purpose:** Show the linked worktrees of the repositories of the user, with the work in each one that exists nowhere else, before a person removes a worktree.

**Roots:** The search roots that the user names (section 4). The walk finds each directory with a `.git` directory with the user as owner, does not enter its work tree, and reads its records in `.git/worktrees` (at most 256 for each repository). A `.git` file is a linked worktree or a submodule; its repository has its record. A repository outside the search roots, a bare repository, and a repository in the work tree of another repository are not seen.

**Unit:** One linked worktree: the record `.git/worktrees/NAME` and the directory that its `gitdir` file names. The directory is present only when its `.git` file names the record again; a directory that is absent is `missing`, and a directory whose `.git` file is absent or names another record is `not_matching`.

**Evidence:** For each worktree the report gives:

| Fact | Source |
| --- | --- |
| Branch or detached state | The `HEAD` file of the record: `ref: refs/heads/NAME`, or a commit |
| Locked | The file `locked` of the record |
| Staged changes | `diff-index --cached --quiet HEAD --`: the index against the commit, with no read of the work tree |
| Changed tracked files | The index file of the record, read by Svalnir (versions 2, 3, and 4, SHA-1 object names, no split index, at most 4096 bytes in one path and path bytes of at most four times the file size), compared by metadata with the work tree; an entry with the flag skip-worktree is compared when its file exists, because that flag can hide a local edit from Git: an absent file, another kind, size, inode, modification or change time, or executable bit is a change, and so is a file of an entry with no nanoseconds that is not older than the index. No file content is read, so no clean filter runs; a file with the same content and other metadata is counted, the safe failure |
| Files that Git does not track | `ls-files -z --others --exclude-standard`, with the ignore files of each level of the repository; the list has a bound of 256 KiB, and a longer list is reported as more |
| Entries that Git ignores | `ls-files -z --others --ignored --exclude-standard --directory`, with the same bound. They are reported apart and are not in the verdict, because a build output is ignored too; `git worktree remove` deletes them with no `--force`, for example a local `.env` file |
| Commits that no branch has | `rev-list --count HEAD --not --branches --`: the commits of the `HEAD` of the worktree that no local branch has. A commit that only a tag or a remote-tracking branch has is counted |

The three queries use the Git executable and the constraints of `project.dependency-directory`, with the record as the Git directory and the worktree as the work tree; none of them reads the content of a work-tree file, runs a hook or a filter, or writes the index. A fact that cannot be read is `unknown` with its reason, and an unknown fact is never the absence of work. The verdict of a worktree is `has_work` when a fact shows a change that no commit has, a file that Git does not track, or a commit that no branch has, `no_work_seen` only when each of these facts is known and none shows such work, and `not_known` otherwise; the entries that Git ignores are not in the verdict, and the workflow of a `no_work_seen` worktree names them. A worktree whose directory a user exclusion contains is `excluded`, and the inspection reads nothing in it. A worktree with an absent directory has only the fact of its commits.

**Removal:** Manual only, never automatic. This build has no removal. The report gives the owner workflow: keep the work first (commit or stash the changes, move the files that Git does not track, and give each commit that no branch has a branch), then `git worktree remove PATH`, after `git worktree unlock PATH` for a locked worktree; `git worktree prune` for a record whose directory is absent. A later removal mode needs its own action class, and the durable record of the preservation of the work before the removal; both are open points of the promotion of this rule.

**Required evidence:** Worktrees with each kind of work of the table, locked and missing worktrees, sparse checkouts, submodules in a worktree, repositories with SHA-256 object names and with a split index, worktrees with relative paths in their records, and the result of each owner command.

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

**Retired.** The layout `cargo-target` of `project.dependency-directory` takes the place of this rule (section 12, "Cargo output"). The identity `cargo.build-output` stays reserved: no other rule uses it, and no revision of it is registered.

Cargo documents that `cargo clean` removes generated artifacts and, without options, removes the entire target directory. The target directory is configurable. [Cargo clean documentation][cargo-clean] The layout binds a `target` directory beside `Cargo.toml` with the tag `CACHEDIR.TAG` that Cargo writes; a target directory at another location is not found, and the residual risks of section 12 apply to a shared target directory and to a release program.

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

The candidate is a download in the resolved cache directory only. Installed kegs, the Cellar, the Caskroom, taps, and the Homebrew repository are outside this rule. The removal of old installed versions is the separate rule `homebrew.cleanup`.

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
| Each step skipped, so no call was submitted | Apply no-effect backoff and end the pass; a capacity increase in the window is not a benefit of the operation |
| Target larger than its planned charge, locked, or (for an eviction) hard-linked at dispatch | Skip the target with no call ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 7) |
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
