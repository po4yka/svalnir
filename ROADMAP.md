# Roadmap and release criteria

This document has the milestones of Svalnir and the acceptance criteria of the first release. Each item is planned behavior, not a statement that something ships. The [README](README.md) gives the product scope, and the specifications in `docs/` own the contracts.

## Milestone 1 — Core model and observation

Establish the Rust workspace, CLI contract, macOS collectors, volume-aware scans, process identity model, local state, capability diagnostics, and deterministic policy simulation. This is an internal foundation milestone.

## Milestone 2 — Controlled intervention

Implement manual cleanup plans, the operation coordinator, reviewed cache adapters, background disk protection, application budgets, graceful termination, force escalation, cooldowns, and crash recovery. Validate resource limits. The privileged boundary moves to after the first release.

## Milestone 3 — First usable release

Package the agent, CLI, and core GPUI experience. The privileged helper has no operation in this release (owner decision of 2026-11-19); its code stays, not registered and not called. Its registration, its grant enrollment, and its validation with a signed build come after the release, in a milestone that is not decided. Complete setup, permission diagnostics, background registration, notifications (in this release, a system dialog of the agent for the three urgent kinds only, with no banner; owner decision of 2026-11-20, [INTERFACES.md](docs/INTERFACES.md) section 4), policy controls, history, upgrade behavior, and uninstall.

Owner decisions of 2026-11-20 for this milestone: the rule registry has six more package and build caches ([CLEANUP_RULES.md](docs/CLEANUP_RULES.md) section 10), each `proposed` until its promotion; the release has the FSEvents invalidation of the candidate catalog, which replaces the decision of the same day that it has none; and a Homebrew cask follows the Developer ID signature.

This release includes **automatic disk eviction and automatic application force termination under enabled policies**. An observation-only prototype does not satisfy the first-release goal.

Release acceptance requires:

- CLI and GUI agree on state, policy, targets, and history.
- Monitoring continues with both clients closed while the user agent can run.
- The disk guard reclaims only approved candidates and stops at its budgets.
- The memory guard supports both global pressure and per-application thresholds.
- Foreground preferences, protected identities, action limits, and restart controls work.
- Permanent eviction, Trash operations, estimated reclaim, and observed capacity remain distinct.
- Degraded permissions and unavailable metrics are visible.
- Crash recovery and low-space journal failure follow documented behavior.
- Validation covers the supported hardware and macOS matrix.
- Distribution includes the license and required source/notice materials.
- All nine release gates in the [validation plan](docs/VALIDATION.md) pass for the declared release scope.

## Milestone 4 — Deeper integrations

Milestone 4 starts after Milestone 3 (owner decision of 2026-11-19). Expand developer adapters, managed jobs, application storage maps, duplicate review, uninstall assistance, open-file diagnosis, APFS tooling, and optional event/network/energy modules. Each module must preserve the same identity, authorization, and outcome contracts.

The first items of this milestone have this order (owner decision of 2026-11-20):

1. The incremental catalog from FSEvents, with a full reconciliation when the event history has a gap ([ARCHITECTURE.md](docs/ARCHITECTURE.md)). This item moved to the first release.
2. Rules for project dependency and build directories ([CLEANUP_RULES.md](docs/CLEANUP_RULES.md) section 10).
3. Simulator, container build cache, and Homebrew cleanup through the owner tool, as producer-supported operations.
4. A read-only report of the capacity that the scanned categories do not explain ([RESOURCE_MODEL.md](docs/RESOURCE_MODEL.md) section 7).
5. A history of the available capacity and an estimate of the time to a threshold.
6. The listening ports and the working directory in the detail of one process ([RESOURCE_MODEL.md](docs/RESOURCE_MODEL.md) section 11).
7. Manual Git worktree cleanup that preserves uncommitted work.

State of 2026-11-20: the owner asked for items of this list before the end of Milestone 3. Items 1, 4, 5, and 6 are in code and are not validated on a host. In item 4, the entry for the local snapshots is always unavailable, because the snapshot list needs superuser rights and an entitlement. Items 2, 3, and 7 are not in code.

Considered and not on the roadmap (owner decision of 2026-11-20): rules that a user edits as data, time-based cleanup schedules, an undo of a permanent removal, an update check in the product, and automatic removal of local snapshots. A Model Context Protocol server and the attribution of processes to a coding-agent session have no milestone; the structured output of the CLI is the interface for an agent.
