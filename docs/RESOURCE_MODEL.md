# Svalnir Resource Model

**Status:** Design specification; no collector, native backend, or supported macOS matrix is claimed as implemented or verified.  
**Last reviewed:** 2026-11-16

This document defines what Svalnir measures, how observations retain their meaning, and which conclusions consumers may draw. [ARCHITECTURE.md](ARCHITECTURE.md) assigns component responsibilities. [POLICY_SPEC.md](POLICY_SPEC.md) defines intervention thresholds and evidence windows; [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md) defines execution outcomes. [CLEANUP_RULES.md](CLEANUP_RULES.md), [INTERFACES.md](INTERFACES.md), and [VALIDATION.md](VALIDATION.md) specify eligibility, transport, and verification. [THREAT_MODEL.md](THREAT_MODEL.md) covers incorrect or stale measurements as threat T-07.

## 1. Accounting principles

An observation is a measurement about an identified scope, acquired by a particular worker during a bounded interval. Its value is meaningful only with its unit, source, identity, coverage, and time context.

The model must preserve these distinctions:

- Unknown, denied, unsupported, stale, and measured zero are different conditions.
- A display label, path, PID, or application name is not sufficient target identity.
- Logical file length, allocated storage, estimated reclaimability, admission charge, and observed capacity improvement are different quantities.
- RSS, physical footprint, compressed memory, and swap cannot be substituted or freely added.
- A complete measurement of one scope does not establish complete visibility of its surrounding system.
- Observing pressure or a large consumer grants no authority to modify it.
- Accepted dispatch, verified target effect, and resource recovery remain separate facts.

No collector silently changes a metric's definition to preserve a populated dashboard. Unsupported fields remain visible as unavailable; policy evaluates its declared requirements.

## 2. Identities and scopes

Domain types carry opaque IDs plus evidence available to the trusted collector. Public identifiers must not expose raw kernel handles or imply that possession authorizes an operation.

| Identity | Required interpretation |
| --- | --- |
| Host and boot | Distinguish a machine from its current boot; prevent mixing counters and process generations across boots |
| Worker and collector epoch | Identify the actual collecting process and a particular collector lifetime; restart creates a new epoch |
| Volume and mount | Bind filesystem evidence to the mounted volume and mount generation; a mount path can be reused |
| Capacity domain | Identify a verified shared-capacity relationship, such as an APFS container, for coordination and deduplication |
| File object and directory entry | Distinguish the observed object from the particular name through which an action would address it |
| Process generation | Bind PID, start evidence, owner, boot context, and verified executable/job evidence |
| Application instance | Identify a running application or managed-job instance and its documented attribution method |
| Membership snapshot | Identify the exact process-generation set attributed to an application at a particular revision |

Keep native identifiers, filesystem evidence, and confidence in the identity record. A volume UUID, device number, inode, or process start timestamp alone is not a universally durable identity. Missing evidence limits the operations that the record can support.

File identity includes the approved root, relative entry, mount/volume evidence, object type, ownership, and available file identifiers. Aliases can refer to one object; a replacement at the same path is a different target. Process identity similarly distinguishes a restarted application from its predecessor even when its PID or bundle identifier matches. Identity checks do not establish an atomic conditional unlink or signal operation; the execution contracts retain those residual races.

An observation's scope references one identity record. An application scope references a membership snapshot, so a sum cannot silently acquire new members. Shared services may have their own scope and remain unattributed. System metrics do not authorize cross-user process or file disclosure.

Paths and names are presentation data. Preserve filesystem names losslessly in the internal model and use the interface's escaped or encoded representation when they are not valid display text. Do not replace an unrepresentable name with a different actionable path.

## 3. Units and numerical representation

Use distinct internal types for bytes, page counts, entry counts, durations, counter values, and identities. All conversions use checked arithmetic and validated native lengths and signedness.

| Quantity | Canonical meaning |
| --- | --- |
| Bytes | Integer bytes; decimal `GB` and binary `GiB` are presentation choices |
| Pages | Integer count with the applicable runtime VM page size retained |
| Duration | Integer nanoseconds internally; policy syntax may use explicit larger units |
| Timestamp | Monotonic nanoseconds within a named clock domain; UTC wall time for display |
| Counter | Integer cumulative count with its reset identity and unit |
| Rate | Finite approximation with numerator unit, interval, and input observations |
| Delta | Signed difference between comparable observations; negative values are valid |
| State | Defined enumeration, such as native memory pressure |

At JSON boundaries, exact integer quantities use canonical base-10 strings: bytes, counters, nanoseconds, sequence numbers, and potentially 64-bit revisions. Unsigned values use `"0"` or digits without a leading zero; signed deltas may start with `-`, excluding negative zero. Small structural discriminators such as the outer schema version may be JSON integers as specified in [INTERFACES.md](INTERFACES.md). IDs are opaque strings.

Unsigned byte/count/time fields have the range `0..=18446744073709551615`. Differences use a checked signed representation capable of the full difference between two such values; intermediate multiplication may use a wider type but must fit the declared output. Narrower native counters retain their source width and reset semantics.

Finite approximate rates and ratios may be JSON numbers with a declared definition. JSON must never contain `NaN`, infinity, or an overflowing value coerced to the nearest representable integer. Reject malformed, out-of-range, or unit-incompatible input. Native sentinel values do not become enormous unsigned measurements. An unavailable value is `null` with a reason; zero means a successful measurement of zero.

## 4. Canonical observation envelope

`Observation<T>` has the following logical fields. The serialized example is normative for the envelope shape; registered metric definitions constrain `T`.

| Field | Contract |
| --- | --- |
| `metric_id` | Stable metric name with one documented meaning |
| `scope` | `kind` and `identity_id` identifying the measured subject |
| `value` | Typed scalar, state, or explicitly registered structure; `null` when unavailable |
| `unit` | Registered unit; consumers must understand it before arithmetic |
| `kind` | `gauge`, `counter`, `rate`, `state`, or `estimate` |
| `availability` | `available` or `unavailable` |
| `reason` | `null` when available; stable reason code otherwise |
| `coverage` | `complete`, `partial`, or `unknown`, relative to the declared scope |
| `source` | Adapter/revision, native API and field, and actual worker identity |
| `sample` | Unique acquisition identity, clock/boot/collector context, interval, and wall timestamp |

```json
{
  "metric_id": "disk.available_bytes",
  "scope": {
    "kind": "volume",
    "identity_id": "vol_example"
  },
  "value": "8589934592",
  "unit": "byte",
  "kind": "gauge",
  "availability": "available",
  "reason": null,
  "coverage": "complete",
  "source": {
    "adapter_id": "macos.statfs",
    "adapter_revision": "1",
    "native_api": "statfs",
    "native_field": "f_bavail * f_bsize",
    "worker_id": "worker_example"
  },
  "sample": {
    "sample_id": "sample_example",
    "clock_domain": "clock_example",
    "boot_id": "boot_example",
    "collector_epoch": "collector_example",
    "started_monotonic_ns": "120000000000",
    "finished_monotonic_ns": "120003000000",
    "captured_at": "2026-11-16T12:00:00.003Z"
  }
}
```

The example is illustrative. Replaying or redisplaying an observation retains `sample_id`, acquisition times, and provenance. A new transport message is not a new measurement.

Unavailable reasons include `permission_denied`, `unsupported`, `resource_gone`, `not_initialized`, `transient_failure`, `identity_changed`, `inconsistent_data`, `clock_discontinuity`, `overflow`, and `not_collected`. Keep bounded native error details separately from stable reasons; redact private paths and arguments from ordinary diagnostics.

Coverage is independent of availability. A scan can successfully report a partial sum. Its scan record must identify exclusions, visited entries, skipped/unreadable entries, cancellation, and unresolved regions. `complete` means complete for the recorded scope and collection method, not an atomic view of a changing filesystem.

A failed current query produces an unavailable observation. An older successful observation can remain in history with its original timestamp. Clients may label it “last observed,” but must not substitute it into current admission without satisfying freshness.

Unknown units, states, metric definitions, or incompatible revisions cannot be coerced to known meanings. A client that cannot interpret a new pressure state renders it as unsupported or unknown, never normal.

## 5. Time, freshness, and snapshots

The macOS clock adapter must normalize supported native timestamps to a host-wide monotonic nanosecond timeline. Agent and helper can compare times only when their `clock_domain` and `boot_id` match and the shared adapter's conversion is validated. Process-local Rust `Instant` origins are not interchangeable wire timestamps. Another clock domain needs an explicit validated conversion; otherwise cross-domain age and interval calculations are unavailable.

Acquisition start and finish bound when a reading was obtained. A consumer conservatively computes age from acquisition start and checks maximum acquisition duration and inter-metric skew. Long-running scans retain per-region acquisition bounds rather than claiming that their final publication time timestamps every entry.

Freshness is derived for the current request or policy predicate. It depends on maximum age, scope identity, collector continuity, source support, required coverage, and clock validity. Do not store an authoritative `fresh: true` flag. Human history uses RFC 3339 UTC `captured_at`; wall-clock corrections cannot advance sustain periods or cooldowns.

A published snapshot is an immutable collection with a publication revision. Its stream barrier guarantees transport ordering as defined in [INTERFACES.md](INTERFACES.md), not simultaneous kernel observation. Every constituent retains its acquisition window. Consumers reject excessive skew when combining values.

Sleep, wake, boot changes, collector restart, and relevant identity discontinuities invalidate qualification windows. Wake requires new observations even if the selected monotonic clock includes sleep. Downtime cannot establish uninterrupted pressure or recovery. These events do not reset incident budgets or grant a new intervention allowance.

History downsampling retains the method, contributing interval, gaps, and useful extrema. An average or interpolated history point cannot replace a fresh native sample for policy qualification.

## 6. Counter deltas and trends

For comparable cumulative counter readings `C0` and `C1`:

```text
delta = C1 - C0
rate_per_second = delta / (elapsed_monotonic_ns / 1_000_000_000)
```

A valid interval requires matching metric definition, unit, scope generation, reset domain, and clock domain; distinct ordered samples; a positive elapsed duration; and no disallowed gap or sleep boundary. Use checked subtraction before approximate division. Retain both sample IDs and the interval in derived provenance.

If the counter decreases, report a reset or discontinuity. Do not emit negative activity, assume wraparound, clamp to zero, or join across restart without a documented counter-specific contract. A changed VM page size or CPU-capacity convention also invalidates the corresponding rate interval.

Gauge differences, including footprint growth, are signed and have different semantics from counter activity. A growing footprint may identify a workload trend; it does not prove a leak. Missing samples create a gap, not evidence of steady growth. Forecasts carry their model and uncertainty and remain advisory under the policy specification.

## 7. Disk capacity

The baseline disk trigger uses user-available capacity for the selected volume. [Apple's `statfs` documentation][statfs] distinguishes its block counts and filesystem block size.

| Metric | Source or definition |
| --- | --- |
| `disk.total_bytes` | Valid `f_blocks * f_bsize` |
| `disk.free_bytes` | Valid `f_bfree * f_bsize` |
| `disk.available_bytes` | Valid `f_bavail * f_bsize`; baseline policy input |
| `disk.important_available_bytes` | Foundation capacity for important usage |
| `disk.opportunistic_available_bytes` | Foundation capacity for opportunistic usage |

`f_bsize` is the filesystem block unit for these calculations. `f_iosize` is not a capacity multiplier. Preserve returned types, validity, and multiplication overflow checks rather than assuming every native field is usable on every filesystem.

Foundation's usage-dependent capacity values are distinct planning inputs. They must not replace `disk.available_bytes` under an unchanged policy or be added to physically available capacity. Preserve unsupported/absent results. Query the intended volume, not whichever volume contains the executable. [Apple's capacity guidance][capacity] describes these usage categories.

APFS volumes can share container space while applying volume reserves or quotas. Retain both selected-volume capacity evidence and a verified capacity-domain relationship. Do not add the available values of sibling volumes to produce a host total. An aggregate view either shows separate scoped measurements or uses a verified domain-level source with its own definition. [Apple's APFS documentation][apfs] describes space sharing and volume limits.

A missing, unmounted, inaccessible, or read-only volume does not have zero available bytes by implication. Read-only state is an independent action constraint. Unknown capacity-domain membership blocks shared-domain automation unless the architecture's explicitly supported deployment restriction resolves coordination.

Capacity snapshots can change immediately after collection. Neither collection nor a Svalnir lease reserves space against other applications.

## 8. File inventory and cleanup accounting

[Apple's `stat` documentation][stat] distinguishes file length, allocated blocks, and preferred I/O size:

```text
logical_bytes = st_size
allocated_bytes = st_blocks * 512
```

Apply these meanings to validated supported file types and nonnegative values. `st_blksize` is an I/O hint; it is not the multiplier for `st_blocks`. VM page size and filesystem capacity block size are also unrelated to this conversion.

Directory metadata size is not its subtree total. A traversal produces an inventory and explicit aggregation convention:

- Entry totals count names within the declared root and traversal boundary.
- Object totals deduplicate confirmed hard-linked objects within a verified filesystem/mount identity.
- Sparse files can have logical length exceeding allocated storage.
- Symlinks are recorded as links under the rule's traversal policy, not silently followed into another scope.
- Mount boundaries, denied directories, changed entries, and cancellation remain visible in coverage.

File-object deduplication does not establish exclusive ownership of physical blocks. APFS clones and snapshots can retain shared storage; a surviving hard link or open reference can also prevent an entry removal from producing the expected capacity gain. Apple's APFS guidance describes shared clone blocks and sparse allocation. [Source][apfs-accounting] An ordinary metadata walk cannot prove exact exclusive extents or exact reclamation. Keep `exclusive_bytes` unavailable unless a reviewed backend establishes that quantity. Do not infer clone sharing from matching size or content alone. Apple's unlink semantics explain why removal and final storage release can differ. [Source][unlink]

A cleanup estimate references the exact candidate identities, rule revision, acquisition interval, estimation method, and coverage. Report uncertain reclaimability as an estimate with explicit limitations or as unavailable. A numerical lower or upper bound requires evidence that it actually bounds the named quantity; a convenient sum is not a bound by declaration.

`work_bytes` is a separate conservative admission charge defined by the rule and [POLICY_SPEC.md](POLICY_SPEC.md). For ordinary entries, the documented convention can use checked `max(logical_bytes, allocated_bytes)` aggregation. Hard-link and directory handling must follow the rule's explicit charge convention; optimizing display deduplication must not silently reduce an approved work bound. Unknown or unbounded charges block unattended dispatch.

Moving entries to Trash records transferred entries and the chosen byte convention. It does not report reclaimed capacity. Cloud placeholders must not be hydrated merely to measure or classify them. FSEvents invalidate affected inventory regions; lost or coalesced events require the documented reconciliation strategy, not invented complete coverage. [Source][fsevents]

## 9. Host memory accounting

Expose `memory.physical_bytes` separately from VM-state observations. The adapter obtains the applicable runtime VM page size and retains it with all page-derived measurements. Do not assume 4 KiB or 16 KiB from the machine architecture, and do not reuse filesystem block size.

Candidate native backends include typed `sysctl` queries and supported Mach host-statistics flavors. Validate returned size/count, structure flavor, field availability, and platform revision before decoding. XNU identifies `hw.memsize` as physical-memory bytes and page-size queries as separate inputs; the native sysctl API requires typed buffers and checked lengths. [Sources][sysctl-definitions] [API][sysctl]

The following mappings describe meanings to preserve, not a claim that all fields exist on every supported release. [XNU's VM statistics definitions][vm-statistics] distinguish them:

| Host-scoped metric | Interpretation |
| --- | --- |
| `memory.vm.{free,active,inactive,wired}_pages` | Native VM-state gauges, converted with the applicable page size |
| `memory.vm.speculative_pages` | A subset already included in `free_count`; do not add it again |
| `memory.vm.{internal,external}_pages` | Anonymous and file-backed gauges; not additional disjoint slices |
| `memory.compressor.physical_pages` | `compressor_page_count`: pages physically occupied by compressed data |
| `memory.compressor.uncompressed_pages` | `total_uncompressed_pages_in_compressor`: logical page content represented |
| `memory.compressor.{compressions,decompressions}_total` | Cumulative page-operation counters |
| `memory.vm.{pageins,pageouts}_total` | Native paging counters, distinct from compressor swap counters |
| `memory.swap.{swapins,swapouts}_total` | Explicit native swap counters where supported |

Braces in tables abbreviate separate registered metric names, not literal wire IDs. VM gauges use `page`; these cumulative counters use `page` with `kind: counter`. Optional derived byte metrics retain their input IDs and page-size evidence. All host measurements describe the host's recorded boot identity.

Multiplying a page count by runtime page size produces a byte representation of that particular count. “Logical uncompressed bytes represented” and “physical compressor bytes” must keep their distinct names. Their difference is not a general amount of memory Svalnir can reclaim.

Do not create a universal “RAM used” equation by summing every VM category. Categories can overlap, and readings taken through different calls can differ in time. Any derived summary must publish its exact definition, exclusions, and source compatibility. The initial policy needs trustworthy pressure and attributed footprint; it does not require a misleading pie chart that sums to physical RAM.

## 10. Native memory pressure

The host-scoped `memory.pressure` metric has `kind: state`, `unit: state`, and available values `normal`, `warning`, and `critical`. Unavailable pressure uses `value: null` and a reason. A high RAM utilization ratio, nonzero swap, or an unrecognized native flag cannot be mapped to critical pressure.

[Dispatch memory-pressure sources][pressure] provide native pressure events. Their event timestamp, subscription lifecycle, and last known state must remain distinct from a fresh synchronous measurement.

A backend exposing maintained pressure state must validate how it initializes current state, establishes continuity, handles delayed/coalesced events, and recovers after gaps or wake. Repeating an old event every collection tick does not manufacture independent measurements. Each sample records whether its provenance is a poll, event, maintained state, or derivation in the associated adapter metadata.

The policy's required distinct observations and freshness rules still apply. A maintained-state backend must establish a reviewed evidence contract that satisfies them, including fresh corroborating observations where required. Otherwise pressure-dependent admission remains unavailable. Startup, collector failure, and wake must not default to normal. This is a backend release gate; the existence of an event API alone does not satisfy the first-release monitoring requirement.

## 11. Process and application memory

Keep these quantities separate for each process generation:

| Process-scoped byte gauge | Meaning and restriction |
| --- | --- |
| `process.resident_bytes` / RSS | Resident address-space accounting; includes mappings that do not equal exclusive physical ownership |
| `process.footprint_bytes` | Native charged-footprint measure used by the configured application budget |
| `process.virtual_bytes` | Virtual address-space size; not committed RAM |
| `process.peak_footprint_bytes` | A peak over the source's stated lifetime/window; not current footprint |

Separately registered process paging counters describe source-defined activity, not exact process swap occupancy.

Apple's footprint guidance explains that clean resident pages and dirty/compressed memory have different accounting treatment. It demonstrates `proc_pid_rusage` and `ri_phys_footprint`; its self-process example does not guarantee access to arbitrary other processes. Do not substitute RSS when footprint is unavailable, or add RSS, footprint, and swapped content into a new total. [Source][footprint]

A process adapter may use supported `proc_pidinfo`/`proc_pid_rusage` flavors where available. Returned structure size, target liveness, process generation, permission failures, and native revisions must be checked. XNU's process declarations expose process start and memory fields, but declarations alone do not prove runtime visibility. [Source][proc-info]

The application-scoped `application.attributed_footprint_bytes` gauge is the checked sum of the selected native footprint measure over a verified membership snapshot. Record the member list, membership revision, per-member sample IDs, maximum skew, and attribution method. Label it “sum of attributed process footprints.” It is neither exact exclusive physical allocation nor predicted RAM recovery.

Membership requires positive application/job evidence. Parentage, display name, executable basename, or shared signing identity alone does not establish exclusive ownership. Shared services remain separately identified unless a tested adapter supplies defensible attribution.

An exited member is not simply a zero reading. Verify its exit and update the membership snapshot; an inaccessible member remains missing. Partial coverage cannot silently satisfy or clear a complete-application budget predicate. A membership change invalidates the corresponding qualifying window while preserving incident usage and cooldown history.

Foreground state, owner, protected status, and application liveness are independent evidence. Unknown foreground identity is not background. Ordinary collection avoids raw arguments, environment variables, file contents, and unnecessary cross-user inventory.

## 12. Swap and optional CPU context

Swap occupancy, allocation, and activity are different metrics. A supported typed `vm.swapusage` adapter may expose host-scoped `memory.swap.{allocated,used,available}_bytes` gauges after its SDK layout, returned size, units, and semantics are verified. This document does not prescribe an unverified structure layout or claim availability on every macOS release.

Explicit VM `swapins`/`swapouts` counters can provide page rates and page-equivalent byte rates using the matched runtime page size. They do not measure exact SSD write traffic: compression, metadata, and other I/O are outside that conversion. Ordinary page-ins/page-outs include different activity and must not be relabeled as swap traffic. [Source][vm-statistics]

Do not derive exact per-application swap occupancy by distributing host swap in proportion to RSS or footprint. Swap use may remain after an intervention; recovery is defined by the authorized pressure or application predicate, not by forcing swap to zero. Swap files remain outside cleanup.

Optional process CPU context uses `process.cpu_time_ns`, a verified cumulative counter normalized to nanoseconds, and derives `process.cpu_core_equivalent_percent` as a finite rate with unit `percent`:

```text
core_equivalent_percent = 100 * delta_process_cpu_ns / elapsed_ns
```

This measure can exceed 100% when work uses multiple cores. If a normalized fraction of host CPU capacity is also shown, document the denominator, processor availability changes, and sampling interval. A logical-core count is a utilization convention, not a claim that heterogeneous cores provide equal throughput. CPU-time unit conversion must be verified for the particular native field; a generic “time” field name is insufficient.

CPU, load average, footprint growth, and swap activity may explain contention. They do not add CPU-only termination authority to the existing policy.

## 13. Capabilities and source support

A metric support record binds its definition to adapter revision, native API/flavor, tested OS build and architecture, worker role/signing context, required permissions, known limits, and validation evidence. Candidate implementations and XNU `main` declarations are not a release support matrix.

Capability states are `available`, `denied`, `unsupported`, or `unknown`, independently of an individual observation's availability. Probe the intended operation and resource under the actual worker. Agent access cannot be inferred from Terminal, GUI, or root access, and a read probe does not authorize deletion or signaling.

Apple does not provide a supported universal Full Disk Access confirmation API. An actual-resource failure must remain actionable diagnostic information; reading TCC databases or an unrelated successful probe cannot establish universal access. [Source][fda]

Use bounded probes and invalidate results on relevant worker, permission, mount, or lifecycle changes. Capabilities can disappear after a successful probe, so executors still handle actual-operation denial. Optional metrics can degrade independently; a missing required metric blocks its predicate without disabling unrelated observation.

## 14. Action effects and measured recovery

Each intervention relates its existing `OperationId` and `StepId` to before/after observation IDs. Preserve acquisition intervals, source definitions, target identities, coverage, and any observation gap.

A comparable capacity change is:

```text
observed_available_delta_bytes = after_available_bytes - before_available_bytes
```

Report a signed value only when both measurements describe the same selected-volume metric and compatible identity. Changed mounts, missing samples, or incompatible sources make the delta unavailable. Never subtract an important-usage estimate from a statfs baseline.

The action contract independently reports dispatch, verified removal or exit, attribution, durability, and aggregate completion. Examples illustrate why those dimensions remain separate:

| Evidence | Permitted report |
| --- | --- |
| Entry removed; available capacity unchanged | Verified removal and measured zero capacity change |
| Entry removed; capacity falls | Verified removal and negative observed delta |
| Original application exits; critical pressure persists | Verified exit; global recovery not established |
| RSS falls; footprint is unchanged | RSS reduction; no attributed footprint reduction |
| Action accepted; after-sample denied | Submitted action; resource effect unavailable |

There is no universal `memory_reclaimed_bytes` formula. Disappearing process RSS, footprint differences, compressor changes, and host free-page changes answer different questions. Preserve those measurements rather than selecting whichever gives the largest benefit.

Concurrent applications and kernel activity can improve or consume capacity during observation. Report “observed change after operation” unless a separately validated experiment establishes causal attribution. An aggregate `Completed` result does not imply successful incident recovery; an unavailable after-sample is not measured no-effect.

## 15. Acceptance requirements

[VALIDATION.md](VALIDATION.md) owns executable validation plans and release evidence. The resource model requires these invariants:

- Exact integer round trips preserve values beyond JavaScript's safe-integer range; unavailable and zero remain distinguishable.
- Unit and source tests distinguish filesystem blocks, 512-byte allocation units, VM pages, bytes, and native time units.
- Hard links, clones, sparse files, snapshots, inaccessible regions, and mount changes cannot produce unsupported exclusive-reclaim claims.
- Replayed samples, counter resets, excessive skew, collector restart, and wake cannot advance qualification or manufacture recovery.
- Partial application membership, PID reuse, process relaunch, and denied footprint cannot become a complete zero-valued application observation.
- Pressure events retain acquisition and continuity semantics; missing current-state evidence cannot be labeled normal.
- Required evidence is probed under the actual worker and retained through transport without silently broadening scope.
- Completed actions with zero, negative, or unknown improvement preserve the action outcome and resource result independently.

Validate portable arithmetic and policy with injected observations and clocks. Validate native meanings, permissions, event continuity, and identities on the declared macOS matrix using disposable fixtures.

## Primary references

Archived man pages establish field semantics; implementation must use the selected SDK's actual declarations and verified runtime behavior.

- [Apple: statfs filesystem statistics][statfs]
- [Apple: stat file metadata][stat]
- [Apple: Checking volume storage capacity][capacity]
- [Apple: APFS volumes, shared space, reserves, and quotas][apfs]
- [Apple: APFS clone, shared-capacity, and sparse-file accounting][apfs-accounting]
- [Apple: unlink semantics][unlink]
- [Apple: FSEvents event handling and reconciliation][fsevents]
- [Apple/XNU: VM statistics declarations][vm-statistics]
- [Apple/XNU: process information declarations][proc-info]
- [Apple/XNU: sysctl memory and page-size declarations][sysctl-definitions]
- [Apple: sysctl API][sysctl]
- [Apple: Dispatch memory-pressure source][pressure]
- [Apple WWDC22: Profile and optimize your app's memory][footprint]
- [Apple Developer Technical Support: Full Disk Access checking][fda]

[statfs]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/statfs.2.html
[stat]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html
[capacity]: https://developer.apple.com/documentation/foundation/checking-volume-storage-capacity
[apfs]: https://support.apple.com/en-ie/guide/disk-utility/dskua9e6a110/mac
[apfs-accounting]: https://developer.apple.com/documentation/foundation/about-apple-file-system
[unlink]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/unlink.2.html
[fsevents]: https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html
[vm-statistics]: https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/vm_statistics.h
[proc-info]: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
[sysctl-definitions]: https://github.com/apple-oss-distributions/xnu/blob/main/libkern/libkern/sysctl.h
[sysctl]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html
[pressure]: https://developer.apple.com/documentation/dispatch/dispatch_source_type_memorypressure
[footprint]: https://developer.apple.com/videos/play/wwdc2022/10106/
[fda]: https://developer.apple.com/forums/thread/835851
