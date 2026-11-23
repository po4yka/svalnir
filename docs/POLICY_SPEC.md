# Svalnir Policy Specification

**Status:** Design specification. `svalnir-core` has the configuration parser and the pure evaluation and simulation functions of this specification. No agent runs them, and no policy can become active.  
**Specification revision:** 1  
**Last reviewed:** 2026-11-19

This document defines when Svalnir may propose and continue a resource intervention. [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) defines execution and recovery. [CLEANUP_RULES.md](CLEANUP_RULES.md) defines filesystem eligibility and rule review. [RESOURCE_MODEL.md](RESOURCE_MODEL.md) defines the observations that policy consumes, [INTERFACES.md](INTERFACES.md) defines the configuration and control commands, and [VALIDATION.md](VALIDATION.md) owns the release evidence. The [architecture](ARCHITECTURE.md), [threat model](THREAT_MODEL.md), and [README](../README.md) establish the product baseline.

## 1. Scope

The initial policy engine supports:

- Disk-pressure protection through permanent eviction of approved regenerable data.
- Global memory-pressure protection through authorized application termination.
- Independent application-footprint budgets, including action when global pressure is normal.
- Standing authorization, protected identities, foreground preferences, limits, cooldowns, and observable recovery.
- Manual plans using the same target protections and execution authority.

Automatic eviction and authorized force quit are first-release requirements. CPU use, swap occupancy, growth forecasts, or file age alone do not authorize a destructive action. CPU-only control, arbitrary service management, swap manipulation, and remote policy distribution are outside this specification.

The policy engine is a deterministic function of supplied policy, grants, observations, identities, clock values, and incident history. It produces decisions and explanations. Native operations belong to executors.

## 2. Authority and effective policy

Three objects must remain separate:

| Object | Purpose | Cannot do |
| --- | --- | --- |
| `PolicyRevision` | Desired and effective thresholds, selectors, rules, exclusions, timing, and budgets | Create OS permissions or root authority |
| `ActionGrant` | Standing consent for specified action classes, rules/versions, targets, escalation, and bounds | Prove human intent against a compromised same-user session |
| `PrivilegeGrant` | Helper-owned administrator-approved ceiling for supported operations and principals | Be expanded by an agent-supplied metric, path, or approval flag |

Effective authority is the intersection of current policy, applicable grants, supported adapter capability, and hard product protections. For a manual operation, exact plan-bound authorization replaces the automatic-trigger requirement; it does not remove executor or privilege constraints.

Profiles supply versioned starting values. `observe` permits collection and explanation but no automatic resource intervention. `balanced` starts with foreground protection and ordinary grace periods. `aggressive` can propose shorter configured waits and foreground eligibility. Selecting a profile does not create an action grant. Show explicit overrides and the resulting effective values; do not retain an unqualified profile label when its significant behavior has been customized.

A first-time action-class or scope expansion requires its corresponding authorization. Once established, eligible recurring incidents do not need another prompt. Signed CLI identity is not proof that a human initiated an invocation; the same-user and helper boundaries in the threat model remain applicable.

## 3. Configuration types and validation

The user configuration path is `~/Library/Application Support/Svalnir/config.toml`. It proposes a revision; an effective revision is a separately validated and recorded state.

### Scalar and selector rules

- Sizes use nonnegative integer quantities with explicit units: `B`, `KiB`, `MiB`, `GiB`, or `TiB`. Conversion is checked integer arithmetic. Ambiguous units, negative values, overflow, and fractional byte results are rejected.
- Durations use an integer and one explicit unit: `ms`, `s`, `m`, `h`, or `d`. Qualification, freshness, and budget windows must be positive. Zero must not silently disable a protection.
- Counts and ceilings are finite positive integers. Omitted values resolve through a versioned, bounded template; omission never means unlimited.
- Paths support explicit leading `~/` expansion for the relevant user. A bare `~` is not accepted. No shell evaluation, command substitution, environment-driven root authority, or cleanup-root globs are allowed.
- A home directory that is not a canonical absolute path is unresolved, and a `~/` path then protects by making the affected candidates ineligible. Path components are compared after Unicode lowercase. Two components that still differ and have a non-ASCII character count as a match for protection, because the default APFS volume ignores case and normalization. This rule can protect too much; it must not protect too little.
- Logical selectors such as `startup-data` resolve to current volume identities. A mount path is not a persistent identity.
- Application selectors resolve through verified application/job identity. Names and a bundle identifier supplied without identity validation are insufficient.
- Rule IDs resolve through the compiled reviewed registry. Unsupported versions or missing automatic eligibility cannot become active automatic rules.
- Unknown keys, duplicate identifiers, unknown enum values, and unsupported schema versions fail activation with field-specific errors.

An empty user protection list does not disable built-in protections. The automatic-cleanup protection fields for archives, backups, databases, and model weights make the effective protection visible. In schema version 1, a `false` value fails activation with a field-specific error; it is not ignored and it cannot make that data eligible. A reviewed integration that needs such data uses its own contract under [CLEANUP_RULES.md](CLEANUP_RULES.md).

### Required relationships

For a disk policy:

```text
0 < emergency_below < reclaim_below < warn_below < recover_above
0 < emergency_sustain_for <= sustain_for
0 < batch_limit <= pass_limit <= incident_limit
0 < batch_item_limit <= pass_item_limit <= incident_item_limit
0 < max_passes_per_incident
```

For an application budget:

```text
0 < footprint_recover <= footprint_soft < footprint_stop
0 < over_limit_for
0 < cooldown
```

The fast sampling interval must fit the maximum qualification gap and decision freshness limit. Ordinary graceful termination requires a positive grace period. Immediate force is a distinct authorized disposable-workload strategy, not an accidental consequence of `grace_period = "0s"`.

For the project rules:

```text
1h <= quiet_period <= 90d
```

`plan_ttl` bounds a plan that the agent prepares automatically. It must allow the intended grace interval; it does not guarantee that later escalation will still be valid. `manual_plan_ttl` bounds a plan that a user prepares and reviews before approval, and it must be long enough for that review. Both values are finite and positive. Expiry, permission loss, or a cleared trigger can stop a later step, and an expired plan of either type requires a new plan.

### Cleanup rule settings

The `[cleanup.projects]` table holds the settings of the project activity of [CLEANUP_RULES.md](CLEANUP_RULES.md) section 6 ("Project activity"):

| Key | Type | Template value | Meaning |
| --- | --- | --- | --- |
| `quiet_period` | Duration, 1 hour to 90 days | `"24h"` | The time with no project activity after which a project is `quiet` |
| `paseo_agents` | Boolean | `false` | `true` turns on the Paseo source. A project is then `busy` while Paseo lists a running or starting agent in it, and each project is `busy` when the listing fails |
| `search_roots` | List of strings, at most 16 | `[]` | The search roots of `project.dependency-directory` and of `git.linked-worktree` ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 4), for example `["Developer", "GitHub"]`. Each one is a plain path relative to the home directory, with at most 16 components and no empty, `.`, `..`, or `~` component; a path that starts with `/` is refused. Two paths that differ in the case of ASCII letters only are the same path (`duplicate_identifier`). A command adds the roots of `--root` and of mise to these roots |
| `layouts` | Array of tables, at most 16 | None | The user-configured layouts of `project.dependency-directory` ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 12, "User-configured layouts") |

A setting of this table gives no authority. A shorter quiet period can only make more projects `quiet`; it does not make a unit a candidate without the other predicates. `paseo_agents = true` can only make more projects `busy`. A search root only names a place to look; each check of the rule applies to each unit below it. `config show` gives the table as `cleanup.projects`, with the quiet period in nanoseconds, `search_roots` as a list of strings, and each layout in the list `cleanup.projects.layouts`, with its quiet period in nanoseconds or `null`.

Each `[[cleanup.projects.layouts]]` table (owner decision of 2026-11-22) is a parameter of the reviewed rule, not a rule. It has these keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `directory` | String, required | The generated directory, relative to the project directory: one, two, or three names with `/` between them. The first name can be a pattern with `*` and `?`, for example `cmake-build-*` |
| `markers` | Array of 1 to 8 strings, required | The project markers. One of them must be in the directory that holds the first name of `directory`: a regular file, or a directory when the marker ends with `/` (for example `.storybook/`). A marker of one name can be a pattern with `*` and `?`. A marker can be a path of at most four names with no pattern, for example `ProjectSettings/ProjectVersion.txt`; each directory on its way must be a directory, not a symbolic link |
| `inner_marker` | String | A regular file that the unit must have |
| `protected` | Array of at most 8 strings | Paths relative to the unit, of at most 4 components, each a name or a pattern with `*` and `?`. A unit with an entry at one of them is refused |
| `quiet_period` | Duration, 1 hour to 90 days | The quiet period of the projects of this layout, in place of `quiet_period` of the table |

The validation refuses each of these before activation, with the finding code in parentheses:

- A `directory` that is absolute, that starts with `~`, that has more than three names, an empty, `.`, or `..` component, a pattern in a name other than the first, `\`, `[`, `]`, or a control character, or a component longer than 255 bytes (`invalid_path`).
- A pattern first name with no literal part of two or more characters that is not only `.` (for example `*`, `*.*`, `?`, or `a*`), or that can match a name of the skip list, a name that [CLEANUP_RULES.md](CLEANUP_RULES.md) section 12 keeps out, or a protected name of the next item, with the case of ASCII letters ignored (for example `.c*`, `de*`, `*mp`, or `Doc*`) (`invalid_path`).
- A `directory` with a component of the skip list of the walk (`.git`, `.hg`, `.jj`, `.svn`, and `.cache`), or with the name of a protected location of the home directory: a personal folder of the default `[protections]` list (section 12), `Library`, or `Applications` (`invalid_path`). The comparisons ignore the case of ASCII letters.
- A `directory` whose first name is a name that [CLEANUP_RULES.md](CLEANUP_RULES.md) section 12 keeps out: `zig-out`, `deps`, `vendor`, `tmp`, and `_build` (`invalid_path`). A first name of another built-in layout, for example `build` or `target`, is accepted (owner decision of 2026-11-23): the built-in layouts come first, a built-in layout whose marker is present gives the unit, and a unit in or around a built-in unit is refused with `overlaps_unit`.
- A second table with the same `directory`, with the case of ASCII letters ignored (`duplicate_identifier`).
- An absent `directory` or `markers` (`missing_key`), an empty `markers` list, a marker that starts with `/`, has more than four names, an empty component, or a pattern in a path of more than one name, a pattern marker with no literal part of two or more characters that is not only `.` (for example `*`, `*.*`, `a*`, `.*`, or `*e`; `*.csproj` is accepted), and a marker with a name of the skip list (`invalid_path`).
- An `inner_marker` with `/` or a pattern, and a protected path that is absolute or has an empty, `.`, or `..` component (`invalid_path`).
- More than 16 tables or more than 8 entries in a list (`too_many_entries`), a `quiet_period` outside the range (`out_of_range`), and an unknown key (`unknown_key`).

A user-configured layout has the layout name `user-configured`. It is never used by an automatic operation, in each lifecycle state, and each check of the rule applies to it unchanged. For example:

```toml
[[cleanup.projects.layouts]]
directory = "builddir"
markers = ["meson.build"]
protected = ["meson-private/install.dat"]
quiet_period = "3d"
```

## 4. Illustrative complete policy values

The following expands the README example with proposed explicit bounds and timing fields. Numbers demonstrate relationships, not suitable settings for every Mac. Application identity, rule readiness, grants, and actual release defaults still need implementation and validation.

```toml
schema_version = 1

[agent]
profile = "balanced"
sample_interval = "60s"
pressure_sample_interval = "5s"
decision_sample_max_age = "10s"
max_qualifying_sample_gap = "10s"
plan_ttl = "30s"
manual_plan_ttl = "10m"

[protections]
excluded_paths = ["~/Desktop", "~/Documents", "~/Downloads", "~/Movies", "~/Music", "~/Pictures", "~/Public", "~/Library/Mobile Documents", "~/Library/CloudStorage"]
protected_bundle_ids = []
protected_executable_paths = []

[disk_guard]
enabled = true
volumes = ["startup-data"]
warn_below = "20GiB"
reclaim_below = "10GiB"
emergency_below = "2GiB"
recover_above = "25GiB"
sustain_for = "30s"
emergency_sustain_for = "5s"
recovery_stable_for = "60s"
batch_limit = "1GiB"
pass_limit = "8GiB"
incident_limit = "16GiB"
batch_item_limit = 256
pass_item_limit = 2048
incident_item_limit = 4096
pass_time_limit = "30s"
max_passes_per_incident = 2
pass_cooldown = "5m"
observe_after_action = "5s"
no_effect_backoff = "15m"
automatic_mode = "permanent"
approved_rules = ["svalnir.expired-temporary", "xcode.inactive-derived-data"]

[disk_guard.exclusions]
paths = ["~/Documents", "~/Downloads", "~/Pictures", "~/Movies"]
protect_archives = true
protect_backups = true
protect_databases = true
protect_model_weights = true

[memory_guard]
enabled = true
global_trigger = "critical"
sustain_for = "15s"
grace_period = "10s"
observe_after_action = "15s"
recovery_stable_for = "60s"
max_applications_per_incident = 3
protect_foreground = true
allow_force_quit = true
allow_volatile_journal_on_critical = false
eligible_groups = ["background-user-applications", "managed-jobs"]
protected_bundle_ids = []
protected_executable_paths = []

[[memory_guard.app_budgets]]
id = "example-build-worker"
bundle_id = "com.example.BuildWorker"
footprint_soft = "4GiB"
footprint_stop = "6GiB"
footprint_recover = "3GiB"
over_limit_for = "30s"
cooldown = "10m"
restart = "never"

[cleanup.projects]
quiet_period = "24h"
paseo_agents = false

[history]
retention = "30d"
max_database_size = "256MiB"
redact_exported_paths = true

[privacy]
telemetry = false
include_command_arguments = false
```

Byte limits charge `work_bytes` as defined in section 11, not promised reclaimed capacity. Catalog retention is subordinate to hard storage bounds. This example does not configure every adapter-specific limit; those must resolve to finite reviewed values in the effective policy.

The example is not permission to execute either listed rule. The registry, grant versions, target conditions, and release validation must all admit the rule.

## 5. Activation, amendment, and revocation

A supported apply operation supplies the expected current revision. The agent parses and validates the proposed configuration, resolves supported selectors and templates, computes the effective differences, and checks the grants needed for any expansion.

Activation atomically records the effective user revision and associated user-side authorization state before acknowledging durable success. Concurrent edits use revision comparison; the CLI and GUI must not silently overwrite one another. A file watcher may detect a changed proposal but cannot convert arbitrary bytes into acknowledged root authority.

An invalid or unpersistable expansion leaves the previous effective revision active and reports the failure. A requested restriction, pause, or revoke that cannot be persisted still inhibits affected current-instance dispatch, but returns a non-durable/degraded acknowledgement. It may be lost on restart. Do not describe it as durably applied.

The helper independently authorizes and persists its grants. User and helper storage do not form one transaction. Missing, stale, or pending helper approval blocks the privileged subset and is visible in effective status; it must not be reported as a completed privilege expansion.

Any relevant revision change invalidates unconsumed plans. A replacement plan requires fresh evaluation and keeps the same incident usage. Increasing a ceiling requires appropriate authorization; decreasing it immediately reduces remaining admission capacity. Changes never undo a submitted effect.

Rule updates that broaden roots, eligible versions, deletion method, or data classes require renewed applicable scope approval. Selecting the same rule ID does not automatically approve every future implementation.

## 6. Observation quality and qualification windows

Each input carries source, scope, units, sample time, quality, and boot/session context. Required fields must be supported, sufficiently fresh, and attributable to the intended target. A failed query is not zero, a counter reset is not negative activity, and an unknown foreground identity is not evidence that an application is background.

Qualification is a sampled-evidence contract:

1. Start a window at the first qualifying observation.
2. Accept successive compatible observations only while the predicate remains true and the gap stays within `max_qualifying_sample_gap`.
3. Require at least two distinct observation instants spanning the configured duration.
4. Reset qualification on a contradicting value, stale or missing required evidence, identity/membership discontinuity, or an excessive gap.
5. Require fresh evidence again immediately before dispatch.

Repeatedly reading one cached sample does not advance the window. Native events may trigger faster sampling; they must not be relabeled as repeated independent measurements. Sampling establishes the stated evidence window, not proof that an unobserved resource state was mathematically continuous.

Switch the relevant bounded collectors to `pressure_sample_interval` when any guard begins qualifying or has an active incident, including an application-budget violation while global pressure is normal. Keep that cadence through outcome observation and recovery qualification. The ordinary interval resumes after those windows finish. Thus the example's 60-second idle cadence does not prevent a 10-second maximum qualification gap; detection may still wait for the next ordinary sample when no event arrives.

Sleep, wake, collector restart, and relevant clock/counter discontinuities invalidate qualification and recovery windows. They do not clear incident usage or protected identities. Across restart, a wall-clock timestamp alone cannot prove that a cooldown elapsed or recovery was sustained.

The collector must document how native pressure state and corroborating measurements are maintained. Dispatch memory-pressure events are a platform input, not a replacement for the policy's freshness contract. See [Apple's pressure API][pressure].

## 7. Decisions and explanation

A decision identifies its policy revision, principal, incident and budget generation, trigger/evidence window, candidate identities, applicable grants, required capabilities, proposed bounds, expiry, and reasons for skipped targets.

The decision families are `Observe`, `Prepare`, `ProposeAction`, `Blocked`, and `Recovering`. These are semantic categories, not a finalized wire encoding.

Evaluate hard protections, current authority, enabled/profile/pause state, user exclusions, target eligibility, observation quality, trigger qualification, cooldowns, leases, budgets, and journal capability. Return all relevant reasons with a stable primary reason; do not let ordering hide a denied grant behind a generic failure.

Representative reasons include:

| Reason | Meaning |
| --- | --- |
| `ACTION_NOT_GRANTED` | Required class, scope, or escalation is outside current authorization |
| `HARD_PROTECTED` / `USER_EXCLUDED` | Target violates a product protection or current user exclusion |
| `METRIC_UNAVAILABLE` / `METRIC_STALE` | Required evidence cannot support a decision |
| `TRIGGER_NOT_SUSTAINED` / `TRIGGER_CLEARED` | Admission or continuation predicate is not satisfied |
| `RULE_NOT_READY` / `RULE_VERSION_UNAPPROVED` | Rule cannot perform the requested automatic action |
| `COOLDOWN_ACTIVE` / `BUDGET_EXHAUSTED` | Further work is temporarily or incident-wide inhibited |
| `UNKNOWN_PRIOR_OUTCOME` | Conflicting work requires reconciliation |
| `JOURNAL_UNAVAILABLE` | Required durable admission cannot be established |

These decision reasons are distinct from executor errors and observed effects. A decision to attempt recovery does not promise successful recovery.

## 8. Incident identity and lifecycle

A `DiskIncident` belongs to a capacity domain. A `MemoryIncident` belongs to one principal and spans overlapping global-critical and application-budget episodes. The latter share `max_applications_per_incident`: changing trigger, PID, policy revision, or client cannot create a fresh allowance.

Incident state includes identity, budget generation, latched trigger episodes, consumed/reserved budgets, outstanding operations, recovery evidence, and backoff reasons.

| State or flag | Meaning |
| --- | --- |
| Qualifying | Evidence is accumulating; no new action is authorized yet |
| Ready | An actionable trigger and all admission conditions are present |
| Acting / observing outcome | One bounded intervention is underway or its effect is being measured |
| Recovering | The incident remains open while recovery stability is evaluated |
| Cooldown | A target, rule, pass, or incident is temporarily inhibited |
| Exhausted | The relevant ceiling admits no further automatic work |
| Paused / degraded | Orthogonal conditions that inhibit affected work without resetting the incident |

Incident latching and action eligibility are separate. A warning memory-pressure state can keep a critical incident open while permitting no new termination.

The controller summary in the README (normal, warning, acting, recovering, degraded) is a presentation grouping of these states. It does not define additional policy states.

An incident closes only after its latched episodes meet their recovery conditions and no conflicting outstanding effect remains unresolved. Explicit rearm creates a separately authorized, recorded budget generation; it is not a profile toggle, policy reload, or automatic response to exhaustion. Rearm cannot recall a syscall, erase usage history, or expand helper limits.

A rearm is refused while the guard has no standing: the guard is disabled, its grant is revoked or absent, or the guard has a different reason of no standing, for example an expired grant. A rearm is also refused while a pause of automation is in effect, and a retained pause of an earlier boot (section 14) is such a pause. Each refusal has its own stable code. The decision uses the authority record that is durable when the rearm request is decided, so a disable or a pause that is recorded before that time applies to it. A generation that a rearm recorded in these conditions would become usable at the next enable or resume with no new decision of the user.

The budget generation is state of the controller of the agent, so only that controller records a rearm. When no agent runs, a rearm is refused: a client does not change the stored controller record, because a record of an earlier lifetime is not evidence that the incident is still open, and the agent applies its own restart rules to that record.

## 9. Disk guard

### Entry and continuation

Use the configured available-capacity measurement for the selected volume. The first baseline uses native user-available capacity; Foundation important/opportunistic estimates may be displayed but must not silently replace the triggering metric. [Apple's statistics][statfs] and [capacity guidance][capacity] describe distinct inputs.

Entry requires capacity `< reclaim_below` for `sustain_for`, or capacity `< emergency_below` for the positive `emergency_sustain_for`. Warning begins at `< warn_below` and can prepare candidates or notify without deleting.

Once a disk incident is admitted, its continuation predicate is fresh capacity `< recover_above`, within the same authorized scope and remaining budgets. This permits bounded work toward the recovery target even after capacity rises above the entry threshold.

At capacity `>= recover_above`, stop new dispatch and start the stable-recovery window. A drop before stability does not create a new incident or reset limits. Requalify the continuation predicate for `sustain_for` before resuming; the shorter `emergency_sustain_for` applies only while capacity is below `emergency_below`. A gap/wake similarly requires requalification, using retained incident identity and usage; without a trustworthy prior incident, apply the initial entry test.

### Scope and APFS

Keep per-volume trigger evidence while coordinating actions and ceilings across the shared capacity domain. Do not sum available capacity reported for volumes sharing an APFS container. [Apple documents APFS space sharing][apfs].

Quota or reserve constraints can make another volume's deletion irrelevant. Bind candidates to the affected volume unless the adapter can establish that shared-domain reclamation addresses the constraining measurement. Shared free space does not authorize another user's files.

### Passes and selection

A pass contains bounded batches. It stops at byte, item, time, rule, or incident limits; recovery; cancellation; capability failure; or lack of eligible candidates. Starting another pass requires the configured cooldown and remaining pass/incident allowance.

Rank only eligible candidates, preferring configured rule priority, lower rebuild cost, and known inactivity before deterministic identity tie-breaking. A large estimate cannot override an exclusion or unknown activity. Revalidate before each batch and remeasure afterward.

No-effect or immediate-regrowth results activate backoff; they do not justify broader roots or more personal-data access. Full rescans, duplicate hashing, and maintenance compaction stay outside emergency handling.

### Candidate preparation

The candidates of the disk guard come from the discovery of each rule that `approved_rules` names and that the registry permits for automatic eviction ([CLEANUP_RULES.md](CLEANUP_RULES.md) sections 4 and 6). A rule in a different lifecycle state is not examined. The exclusions of the discovery are the paths of `[protections].excluded_paths` and of `[disk_guard.exclusions].paths`.

| Capacity of a selected volume | Preparation |
| --- | --- |
| In the warning band (`< warn_below`, not `< reclaim_below`), with no open disk incident | One bounded discovery when the agent has no candidate set or its set is older than 15 minutes. The discovery lists the approved roots and measures each unit. It is optional work: it does not start with memory pressure, in a pause, in the restart backoff, or when the agent is over its own budget, and it stops at its next name when one of these conditions starts |
| Below `reclaim_below`, or in an open disk incident | The known candidates only: the agent examines the identity, the records, and the activity of each candidate of its latest discovery again. It lists no directory and measures no tree |

A discovery runs on a worker thread of the agent, so the evaluation of the memory guard does not wait for it. A plan is made only from a set that an examination of the known candidates made not more than `decision_sample_max_age` before the decision.

The agent does not keep the candidates across a restart. Thus an agent that starts while a volume is below `reclaim_below`, and an agent whose volume goes from above `warn_below` to below `reclaim_below` between two samples, has no known candidate: the disk guard reports that it has no eligible target, and it evicts nothing until a sample is in the warning band with no open disk incident. Whether the guard starts one bounded discovery in that state is not decided.

The approved roots of an automatic operation are the roots of the same rules, as the agent resolves them from the rule declarations immediately before it applies a plan ([ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) section 4).

## 10. Memory guard

### Global pressure

The first release's automatic global trigger is sustained native `critical` pressure, with fresh corroborating system and target observations. `normal`, `warning`, and `unknown` do not independently admit global-pressure termination. Only host memory observations corroborate the pressure state: the VM page and paging metrics, the compressor metrics, and the swap metrics. A metric of another resource, such as CPU or disk, does not. When the application list of the collector can be stale, no application candidate is admissible and the absence of a budgeted application is not proven; the decision detail is `application_list_stale`. A process with an unrecognized association also prevents the conclusion that a budgeted application is absent.

Before a graceful request and again before force escalation, the critical predicate must remain currently qualified. If it clears or required evidence becomes stale, stop subsequent termination steps while retaining the incident and observing any submitted request. Later critical pressure requires qualification again.

Global recovery requires `normal` pressure through `recovery_stable_for`. Warning inhibits new critical-trigger steps but does not satisfy recovery. Nonzero swap, high utilization, and growth trends remain explanatory signals.

### Application budgets

A soft threshold is advisory. Stop eligibility requires the configured attributed physical-footprint measure `>= footprint_stop` through `over_limit_for`. This path remains independent of global pressure.

The budget binds to a verified application/job instance and a documented member-attribution method. Do not substitute RSS for unavailable footprint or count arbitrary shared services as exclusive application memory. A sum of attributed process footprints is labeled as such, not exact system allocation or predicted reclamation. Apple discusses footprint as a distinct accounting concept in its [memory guidance][footprint].

Missing required members or ambiguous attribution blocks budget-based action. A membership or generation change resets qualification; it does not erase the incident or silently expand a prepared target set.

Falling below `footprint_stop` inhibits subsequent budget-trigger termination, even if the episode remains latched. Recovery requires footprint `<= footprint_recover` through the stable window, or verified original-instance exit followed by reliable absence of an associated relaunch through the longer of recovery stability and application cooldown. Unknown metrics or uncertain liveness cannot clear the episode.

### Shared incident and ranking

All overlapping memory trigger episodes share the principal's incident ceiling. An application selected under both triggers consumes one intervention slot, and the plan records its admission trigger. A budget-trigger operation cannot silently change to global-critical authority during escalation. To change admission authority, settle the old operation and admit a fresh plan under the same memory incident, preserving its consumed charge; a newly dispatched intervention consumes another slot and must satisfy the remaining budget and cooldowns.

Prefer configured disposable workloads and explicitly configured applications before broadly eligible background applications, then use declared termination priority, verified budget violation, footprint, and deterministic identity tie-breaking. A managed job ranks before a broadly eligible application. The configuration has no declared termination priority field yet, so the evaluation does not use one. Unknown optional growth does not become a fabricated zero; unknown required attribution blocks selection.

Foreground protection is checked before each step. Hard-protected OS/session identities and Svalnir's control plane remain ineligible in every profile. Ordinary first-release control targets the requesting user's applications/jobs; ambiguous or cross-user ownership is rejected.

Force escalation requires current authorization and the same admitted target. A separately scoped disposable-workload strategy may authorize immediate force. Otherwise request graceful exit, wait asynchronously, recheck, and verify actual exit as specified in ACTION_CONTRACTS.

### Relaunch and restart

A replacement process is a new instance, not completion of an old request. Cooldown keys include stable application/job identity so relaunch cannot evade them. A new intervention consumes another incident slot.

`restart = "never"` is the baseline. Restart after recovery/cooldown requires a supported managed-job adapter, explicit restart authorization, and finite attempts; unsupported strategies fail activation. A generic app controller must not rewrite launchd jobs or relaunch arbitrary executables to implement a restart preference.

## 11. Budget accounting and coordination

Budgets are admission ceilings, not predictions of benefit.

For filesystem work, `work_bytes` is the rule's conservative charge for the fixed bounded target set. Supported ordinary-file rules can use the larger of logical and allocated bytes with checked aggregation; every rule states its exact basis. It is distinct from actual I/O and reclaimable bytes. Unknown or unbounded charge blocks automatic dispatch. Entry-count and time bounds still apply to tiny-file workloads.

Reserve all applicable limits before dispatch. A file candidate must fit the remaining batch, pass, rule, and incident bounds; an indivisible candidate is skipped if it does not fit. The caller supplies the remaining allowance of each rule. A first batch that has a target whose rule has no supplied allowance is not admissible, and its report states that the rule ceiling was not evaluated. A candidate with no items is not eligible, and a repeated target on one volume is an input error. Splitting is permitted only where the rule defines independently safe units. Dynamic enumeration cannot add unreserved entries behind a plan.

For memory, reserve one application slot before starting an intervention. Charge the slot together with the dispatch consumption of the first termination step, before the external call, as [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) specifies. Graceful and force steps of that intervention share the slot. A submitted failed or uncertain request remains charged. Release a reservation or charge only when the executor proves that no external call was issued. Exit or pressure improvement does not refund consumed usage.

For every ceiling:

```text
remaining = max(0, effective_ceiling - consumed - reserved)
```

Rule limits, grant limits, and helper limits are intersected with policy limits. Changing a revision recomputes remaining capacity without resetting the counters.

One coordinator serializes conflicting interventions while observation and control remain responsive. The host lease broker is required for concurrent Svalnir cleanup of shared resources across users, as specified in the architecture. Lease expiry is not evidence that an old executor stopped.

An admission deadline stops future steps; it cannot make an already-issued native call cancellable or guarantee its wall-clock completion. Each adapter must disclose its cancellation and partial-effect boundaries.

## 12. Manual actions and exclusions

Manual actions have explicit, finite, immutable plan limits and one-shot authorization for the selected mode. They do not consume, reset, or refund automatic incident counters. Their observed effects can contribute to incident recovery.

`MoveToTrash` is the normal manual removal mode. `DeleteSelectedFiles` is a separately authorized manual permanent-removal class. `EvictRegenerableData` is rule-based and can be admitted automatically. `RunOwnerOperation` runs the fixed cleanup command of a producer for a rule; it is manual, and only a bounded `prune` operation can be admitted automatically ([CLEANUP_RULES.md](CLEANUP_RULES.md) section 9). A failed Trash operation never silently becomes permanent deletion.

Distinguish:

- **Hard protections:** OS-managed storage, swap, essential process identities, and Svalnir control-plane state; ordinary cleanup/termination plans cannot override them.
- **Automatic-data exclusions:** personal documents, Downloads, media, backups, archives/dSYMs, databases, model weights, and entire application containers; generic automatic eviction cannot include them.
- **User exclusions:** additional paths/applications protected in their declared scope; changing a protection is a separate explicit policy operation.

Scope is explicit. `[protections]` applies to both manual and automatic actions. `[disk_guard.exclusions]` applies to automatic disk-guard work. The eligibility, foreground, protected-application lists, and `allow_force_quit` settings under `memory_guard` govern automatic memory intervention. A reviewed cleanup rule's own mandatory exclusions apply whenever that rule executes, including a manual rule action.

The default of `[protections].excluded_paths`, when the document does not give the key, is the list of the personal folders of the home directory: `~/Desktop`, `~/Documents`, `~/Downloads`, `~/Movies`, `~/Music`, `~/Pictures`, `~/Public`, `~/Library/Mobile Documents` (iCloud Drive), and `~/Library/CloudStorage` (the folders of file-provider services). Each path protects the folder, each entry below it, and each directory that contains it, for manual and automatic actions. These are defaults of the configuration, not hard protections: a document that gives `excluded_paths` replaces the list. Validation then reports a warning for each personal folder of the default list that no path of the document protects (no path is the folder or a directory that contains it), so that the replacement is never silent. To permit a manual cleanup inside a personal folder, the user activates a configuration whose `excluded_paths` does not name that folder, for example the list without `~/Downloads`, or `excluded_paths = []`; that is a separate explicit policy operation. The hard protections stay in effect in each case.

An exact manual selection may remove appropriate user-owned personal files through its own authorization and executor contract: the user names each entry, and a selection is never the whole of a scan. A manual force-quit request needs its own explicit authorization even when automatic force is enabled; disabling automatic force does not independently prohibit that manual request. Automatic grants cannot be reused to justify a different manual action. Neither a `--force` flag nor administrator access bypasses hard protections, explicitly applicable global/manual exclusions, identity checks, or helper ceilings.

## 13. Journal failure, restart, and lost budgets

Permanent filesystem mutation requires durable intent and dispatch consumption. Process intervention also requires durability by default.

`allow_volatile_journal_on_critical` is an exception for an otherwise eligible sustained global-critical intervention when durable persistence fails. The option and applicable target/escalation grants must have been enabled and recorded before the current incident. It never applies to manual actions, ordinary application-budget enforcement, or filesystem deletion. A cleared critical predicate inhibits later escalation even if the incident remains open.

The exception records intent, consumption, and budget charges in bounded volatile state before submission. Earlier executor-epoch requests cannot be replayed. It cannot expand target scope or helper authority, and degraded auditability must be visible.

On restart, reconcile incomplete actions and restore trustworthy consumed/reserved usage before new admission. Clear qualifying/recovery windows and require fresh observations. Never manufacture recovery from elapsed downtime.

If previous volatile action or budget state may have been lost, mark the affected budget exhausted until observed sustained recovery and a new incident, or explicit authorized rearm. Restart must not replenish a budget during continuing pressure. Ordinary durable uncertainty also blocks conflicting work until its action contract permits reconciliation.

A controller record that cannot be read at a start is lost budget state for each guard. Each guard is then held: it makes no automatic intervention until the agent observes its recovery. The recovery of a held guard is a continuous time of `recovery_stable_for` in the current lifetime of the agent in which each trigger of the guard is `normal` and the guard has no open incident. An evaluation with no trigger shows nothing, and a trigger at the warning level is not a recovery. A sleep of the host starts the time again, and the time is not stored: a restart is not evidence of a recovery. The time that the agent did not run does not count.

Reservations backed by unresolved dispatch state remain charged conservatively. A journal is not an undo mechanism, and an `UnknownOutcome` is not permission to repeat the operation.

## 14. Pause, cooldown, and simultaneous pressure

Pause scope may cover all automation, one guard, a rule, or an application. Pause inhibits new dispatch and subsequent escalation/batches once observed; it does not recall a submitted OS request. Monitoring and bounded verification continue.

A timed pause needs an explicit deadline and reported remaining state. If a restart cannot establish that it expired safely, retain the pause until renewed evidence or explicit resume. The wall clock is not such evidence: a pause of an earlier boot or of a different clock domain stays in effect until an explicit resume. A resume of a durable pause records its time, with its boot and clock domain, in the durable authority record. Each process that authorizes an automatic action reads that time, so trigger evidence from before the resume supports no automatic action, also in a process that did not see the resume. The time is a floor only in its boot and clock domain. Durable and non-durable acknowledgements follow section 5.

Cooldowns are scoped to their cause: application relaunch, rule regrowth, pass pacing, or no-effect backoff. Expiry only allows reevaluation; it does not provide fresh evidence, expand grants, or reset incident usage. Rearm may replace a budget generation but cannot erase independent target cooldowns or unresolved effects.

During simultaneous disk and memory pressure, reduce optional Svalnir work first. Choose bounded work already supported by fresh evidence and prepared candidates. A critical-memory decision must not wait for a whole-disk scan. Deleting data whose immediate rebuild would amplify memory pressure requires the rule's workload constraints to permit it.

If no action remains eligible, publish the reason and continue inexpensive observation. Exhaustion does not select progressively less protected targets.

## 15. Simulation and outcome feedback

Simulation evaluates a fixed snapshot with the same predicates, ordering, and bounds used for real admission. It reports effective policy, assumed grants, evidence age, eligible/skipped identities, estimates, limits, and missing preconditions.

Simulation must not request new permissions, acquire mutation leases, reserve real budgets, consume a plan, or call a mutating owner command as a probe. A simulation that assumes hypothetical grants labels them explicitly. Its results do not authorize later execution or guarantee that the environment will remain unchanged.

After execution, feed independently reported target outcomes and resource observations back into policy. Separate submitted action, verified exit/removal, estimated benefit, observed capacity/pressure change, and incident recovery.

A disappearing file does not prove Svalnir removed it; a capacity increase can include unrelated activity. Force-call acceptance is not verified exit. [Apple's termination API][force-terminate] explicitly requires observing the resulting application state.

“No effect” concerns the measured policy objective after its observation window. A disk operation can complete without useful capacity improvement; an application can exit while global pressure remains critical. Preserve both facts, apply relevant backoff, and consider another target only within current authority and remaining budgets. A disk operation that submitted no call, for example because each of its steps was skipped at the fresh check, has no benefit, and a capacity increase in its window comes from other activity: it ends the pass with the no-effect backoff, so that the guard does not make a new plan in each observation window, and the next pass counts against the pass limit of the incident.

## 16. Acceptance scenarios

These checks use injected clocks and observations and disposable action fixtures.

| Scenario | Required decision or behavior |
| --- | --- |
| Disk below reclaim threshold for less than its sustain period | Prepare/observe; no eviction |
| Emergency capacity sustained for the shorter configured window | Admit only approved bounded eviction; no protection bypass |
| Capacity rises above reclaim but remains below recovery target | Continue the same disk incident within remaining limits |
| Capacity reaches recovery target briefly, then falls | Stop while high; requalify before resuming; retain incident usage |
| Memory becomes warning during graceful wait | Do not force under global-critical authority; keep observing |
| App remains above its stop budget with normal global pressure | Permit its authorized budget path |
| App drops below stop but remains above recovery threshold | Stop further budget-trigger steps; retain the episode |
| Both memory triggers select the same app | One intervention and one shared incident slot |
| App relaunches with a different PID | New identity, same cooldown/incident history; no automatic retarget |
| Policy lowers a limit below already consumed usage | Zero remaining allowance; no reset or rollback |
| Manual operation frees capacity | Update observations without altering automatic usage history |
| Stale sample or wake during qualification | Reset evidence window, preserve incident counters |
| Journal fails during a budget-trigger operation | Block further termination; critical-only exception cannot be borrowed |
| Volatile history is lost on restart | Exhaust affected budget until observed recovery/new incident or authorized rearm |
| Rule version or target scope changes | Old plan invalidated; no implicit scope expansion |
| User pauses while an external call is in flight | Stop later steps, report the submitted call's actual or unknown outcome |

Before release, publish concrete bounded template values, the supported metric/identity matrix, effective-policy serialization, and evidence for each enabled rule/backend. Configuration examples and successful pure evaluation alone do not validate native deletion, signaling, or privilege boundaries.

## References

- [Apple: Dispatch memory-pressure events][pressure]
- [Apple: Filesystem statistics][statfs]
- [Apple: Checking volume storage capacity][capacity]
- [Apple: APFS volume space sharing][apfs]
- [Apple: Memory footprint guidance][footprint]
- [Apple: Application force termination][force-terminate]

[pressure]: https://developer.apple.com/documentation/dispatch/dispatch_source_type_memorypressure
[statfs]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/statfs.2.html
[capacity]: https://developer.apple.com/documentation/foundation/checking-volume-storage-capacity
[apfs]: https://support.apple.com/en-ie/guide/disk-utility/dskua9e6a110/mac
[footprint]: https://developer.apple.com/videos/play/wwdc2022/10106/
[force-terminate]: https://developer.apple.com/documentation/appkit/nsrunningapplication/forceterminate()
