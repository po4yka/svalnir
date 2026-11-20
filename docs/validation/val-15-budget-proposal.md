# Draft: VAL-15 release budgets

**Status:** Draft proposal. The project owner has not approved it. **Each number below is a proposal, not an approved limit.** [VALIDATION.md](../VALIDATION.md#10-performance-evidence) section 10 requires that the owner freezes the limits before the release measurement campaign; until then, this file sets no limit, and a measurement against it is characterization, not a passed gate. No measurement of the artifacts was made for this draft.

The draft has two kinds of rows:

- **A cap of the code.** The code has a constant that bounds the quantity. The proposed limit is that a measurement never shows a value above the constant. The basis is the constant at its source path; a change of the constant changes the proposal.
- **A measured budget.** The code and the documents give no number. The row names the measure and the conditions, and the limit stays open for the owner.

Each row keeps the scope, the unit, the workload, the statistic, and the duration that section 10 requires.

## Caps of the code

| Measure | Proposed limit (not approved) | Unit and statistic | Basis |
| --- | --- | --- | --- |
| Agent log file | At most 8 MiB, in each state of the agent | Bytes, maximum over the run | `AGENT_LOG_LIMIT_BYTES`, `crates/svalnir-agent/src/runtime/log_file.rs` |
| Write-ahead log of the store after a checkpoint | At most 4 MiB after each checkpoint | Bytes, maximum after a checkpoint | `JOURNAL_SIZE_LIMIT_BYTES`, `crates/svalnir-agent/src/store/mod.rs`. The high-water mark between two checkpoints has no basis: open |
| Settled operations in the memory of the coordinator | At most 256 | Count, maximum | `MAX_RETAINED_OPERATIONS`, `crates/svalnir-agent/src/coordinator/board.rs` |
| Targets of one plan | At most 4096 | Count, maximum | `MAX_PLAN_TARGETS`, `crates/svalnir-core/src/action/plan.rs` |
| Candidates that the controller prepares | At most 1024 | Count, maximum | `MAX_PREPARED_CANDIDATES`, `crates/svalnir-agent/src/controller/model.rs` |
| Notification queue of the agent | At most 8 notices in the queue; at most 6 notices in each 10 minutes | Count, maximum | `QUEUE_CAPACITY`, `RATE_LIMIT`, `RATE_WINDOW`, `crates/svalnir-agent/src/notify.rs` |
| Examination of the known candidates in a disk incident | At most 2 s for each examination, with no directory listing | Seconds, maximum | `KNOWN_ONLY_DURATION`, `crates/svalnir-agent/src/runtime/candidates.rs`; [POLICY_SPEC.md](../POLICY_SPEC.md) section 9 |
| Stop of the agent at a safe point, with no step in progress | At most 1 s from the stop request until each thread reads it | Seconds, maximum | `STOP_CHECK`, `crates/svalnir-agent/src/runtime/service.rs`. The time to the exit after that has no basis: open |
| Restart backoff of the agent | At most 600 s between two starts | Seconds, maximum | `RESTART_BACKOFF_MAX`, `crates/svalnir-agent/src/runtime/record.rs` |
| Stored scan result | At most 16 MiB for each scan record | Bytes, maximum | `MAX_SCAN_RESULT_BYTES`, `crates/svalnir-agent/src/store/scan.rs` |
| Readings that the GPUI client keeps | At most 180 for each series | Count, maximum | `MAX_READINGS`, `crates/svalnir-gui/src/app.rs`; `HISTORY_MAX`, `crates/svalnir-gui/src/data/model.rs` |

A cap of the code is a bound on a quantity, not a budget of the cost of the work. A row of this table can pass while the cost of the work is too high; the second table covers the cost.

## Measured budgets (open)

The code and the documents give no basis for a number in these rows. The owner sets each limit, or decides that the row is characterization only.

| Measure | Scope | Workload and conditions | Statistic | Limit |
| --- | --- | --- | --- | --- |
| Idle CPU and wake activity | Agent, with both clients closed | Ordinary collection, no incident, 1 hour after a warm start | Mean and 99th percentile of CPU time for each minute; wakes for each minute | Open |
| Memory overhead | Agent; GPUI client; both | Steady state; peak during a scan of a large tree; peak during an incident | Physical footprint and RSS, separately; maximum | Open |
| Disk I/O and state growth | Agent | 24 hours of ordinary collection; 100 incidents | Bytes written for each hour; size of the store and of `operations.sqlite` | Open |
| Scan work | Agent and CLI | A representative tree of a stated entry count | Entries for each second; peak memory; cancellation latency | Open |
| Intervention latency | Agent | Fixture trigger to the verified effect, as separate intervals of section 10 | Median and maximum of each interval, with the configured delays left out | Open |
| Control responsiveness | Agent and CLI | Pause, query, and cancel during an application wait, with a full request queue, and with a storage fault | Maximum time to the recorded result | Open |
| GPUI responsiveness | GPUI client | Updates, scrolling, and a restart of the agent | Frame time; longest block of the event thread | Open. [DESIGN.md](../../DESIGN.md) gives motion durations, not a frame budget |
| Endurance | Agent | Repeated incidents, relaunches, idle periods, and history retention over a stated duration | Trend of each measure above | Open |

## Open questions for the owner

1. Approve, change, or reject each cap of the first table as a release limit.
2. Set a limit for each row of the second table, or mark it as characterization only.
3. Name the hardware and the build of the measurement campaign (section 8 of [VALIDATION.md](../VALIDATION.md#8-supported-environment-matrix)).
