# Phase 1b handoff (branch phase1b-process-use, worktree .claude/worktrees/phase1b-process-use)

Status: complete with the owner decisions of 2026-11-22 (Apple platform blind spot,
flavor 22 with fallback, exit = gone). Checks pass; rustdoc fails only on the two
pre-existing links in rules/caches/config.rs.

Host observation (2026-11-22): 8 hardened agents are platform_refused, 4 login processes
not_visible; 2 chrome-native-host helpers of /Applications/Claude.app fail proc_pidpath
and stay unknown, so a project unit is still unit_use_unknown on this host while they run.
The build-process evidence of the project rule fails on them too (executable_query_failed).
