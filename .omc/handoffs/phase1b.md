# Phase 1b handoff (branch phase1b-process-use, worktree .claude/worktrees/phase1b-process-use)

Done:
- d2f41b8 spec (CLEANUP_RULES s6 "Use by a running process", ACTION_CONTRACTS s7, INTERFACES codes, THREAT_MODEL).
- 0f3b7f9 platform inventory (platform/process/uses.rs, native.rs queries) + rules/in_use.rs matching, tests.
- next commit: discovery use check (rules/eviction.rs use_check), SkipReason UnitInUse/UnitUseUnknown,
  DiscoveryEnvironment::path_uses/unit_use, AuthoritySource::unit_use, dispatch refusal unit_in_use/unit_use_unknown.

Remaining:
- run cargo test -p svalnir-agent / -p svalnir-cli; fix fallout.
- tests: discovery skip with injected inventory (eviction_tests), coordinator step refusal (coordinator tests).
- project.dependency-directory inspection: add uses to ProjectUnitReport (ProcessEvidence::path_uses).
- spec: align "not_visible" (identity-denied) and unknown-process semantics in CLEANUP_RULES s6.
