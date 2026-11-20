# Validation records

This directory has the promotion records of [VALIDATION.md](../VALIDATION.md#13-rule-promotion-record-and-host-procedure) section 13 and their evidence files.

**Status:** No promotion record exists. [xcode.inactive-derived-data-r1.md](xcode.inactive-derived-data-r1.md) is an empty template, and each layout of each rule is `proposed`. [val-15-budget-proposal.md](val-15-budget-proposal.md) is a draft of the VAL-15 limits that the owner has not approved.

## Owner checklist: promotion run of `xcode.inactive-derived-data`

**Only the project owner runs this checklist**, on a host that the owner selects. The run removes files on that host. No contributor, automated agent, or test runner runs it, and no agent session runs a step of it for the owner.

Section 13 of [VALIDATION.md](../VALIDATION.md#13-rule-promotion-record-and-host-procedure) owns the procedure and the expected result of each step. This checklist adds the commands, the JSON fields to examine, and the file of each output. When this checklist and section 13 disagree, section 13 applies; correct this checklist.

### Where the outputs go

- Put the evidence files of the run in `docs/validation/xcode.inactive-derived-data-r1/`, beside the record. Name each file after its step: for example `step09-plan.json`.
- For each command, keep a command record as section 14 of [VALIDATION.md](../VALIDATION.md#14-host-validation-records) describes: the command, the UTC time, the standard output, the exit status, and the standard error. One way:

  ```sh
  date -u +%Y-%m-%dT%H:%M:%SZ > step09-plan.time
  svalnir clean plan --mode evict --rule xcode.inactive-derived-data --format json \
    > step09-plan.json 2> step09-plan.err
  echo $? > step09-plan.status
  ```

- Before you commit an evidence file, read it. The account of the run has no personal data, but each path names its home directory.
- Write the result of each step in `observed_results` of the record, and each file in `evidence_paths`.

### Preparation (steps 1 to 5)

| Step | Command | Output |
| --- | --- | --- |
| 1 | Make a standard user account with no personal data, and log in as that user | `limitations`: the account name, not its password |
| 2 | `sw_vers`; `xcodebuild -version`; `diskutil info /System/Volumes/Data`; `git rev-parse HEAD` | `step02-*.txt`; `host_versions`, `producer_versions`, `filesystems` |
| 3 | On a branch, set the lifecycle state of the layout in `crates/svalnir-agent/src/rules/xcode.rs` to `automatic_eviction_validated`, with the `record_id` of the record as its reference. Then `scripts/check.sh`; `cargo build --release --locked --workspace --bins`; `shasum -a 256 target/release/svalnir target/release/svalnir-agent` | `step03-check.status`, `step03-shasum.txt`; `fixture_test_revision`, `artifact_digest`, `source_revision` |
| 4 | `export SVALNIR_STATE_DIR="$HOME/svalnir-validation-state"` | Use the same value in each later command |
| 5 | Make two or more disposable Xcode projects, as section 13 step 5 describes | `fixture_manifest` |

Use the `svalnir` and `svalnir-agent` binaries of step 3 in each later step, and no other build.

### Inspection stage (steps 6 to 12)

| Step | Command | JSON fields to examine | Output |
| --- | --- | --- | --- |
| 6 | `xcodebuild -scheme SCHEME -configuration Debug build`; the same with `Release`; `xcodebuild -scheme SCHEME test`; open the project in Xcode until the indexing ends | None | `step06-*.txt` |
| 7 | `find "$HOME/Library/Developer/Xcode/DerivedData" -mindepth 2 -maxdepth 4 -print` | None. Compare with the allow-list of [CLEANUP_RULES.md](../CLEANUP_RULES.md#11-initial-automatic-targets) section 11 | `step07-find.txt`; `allow_list_observations` |
| 8 | `plutil -p PROJECT_DIRECTORY/info.plist` for each project directory | None | `step08-*.txt` |
| 9 to 11 | `svalnir clean plan --mode evict --rule xcode.inactive-derived-data --format json` | No plan: `explanation.targets` is empty. The reason of each unit is in `discovery.blocked[].reasons` or in `discovery.roots[].skipped[].reasons`: `active_producer` in steps 9 and 10, `retention_not_elapsed` in step 11 | `step09-plan.json`, `step10-plan.json`, `step11-plan.json` |
| 12 | The wait of 14 days, or the `touch` and `plutil -replace` commands of section 13 step 12 | None. Record which way you used | `limitations` |

### Manual stage (steps 13 to 19)

| Step | Command | JSON fields to examine | Output |
| --- | --- | --- | --- |
| 13 | `svalnir config validate --config ./config.toml`, then `svalnir config apply --config ./config.toml --expected-revision none` | The exit status | `step13-*.json` |
| 14 | `svalnir clean plan --mode evict --rule xcode.inactive-derived-data --format json` | `explanation.plan.plan_id`; `explanation.targets` (one for each unit); `cleanup_roots` (`~/Library/Developer/Xcode/DerivedData` only); `discovery.complete` is `true` | `step14-plan.json` |
| 15 | Add the exclusion fixtures of section 13 step 15, then the same `clean plan` command | The unit is not in `explanation.targets`, and its reasons are in `discovery` | `step15-plan.json` |
| 16 | Make a plan, replace one unit as section 13 step 16 describes, then `svalnir clean apply --plan PLAN_ID` | The question names permanent removal and each target | `step16-*.json`, `step16-find.txt` |
| 17 | Make a plan, start a build, then `svalnir clean apply --plan PLAN_ID` | Each target is skipped with `producer_active` | `step17-*.json` |
| 18 | `svalnir clean apply --plan PLAN_ID`, then `svalnir history --format json` | In the record of the operation: `effects.permanently_removed` is the count of units, `effects.moved_to_trash` is `0` | `step18-apply.json`, `step18-history.json` |
| 19 | Build and test each project again with each Xcode version | None. Record the time of the first build and of the indexing | `step19-*.txt` |

### Automatic stage (steps 20 to 23)

| Step | Command | JSON fields to examine | Output |
| --- | --- | --- | --- |
| 20 | `svalnir status --format json`; write the configuration of section 13 step 20; `svalnir config validate --config FILE`; `svalnir config apply --config FILE --expected-revision REVISION`; `svalnir policy enable disk-guard --accept-permanent-eviction` | `disk.available` of `status` | `step20-*.json` |
| 21 | In a second terminal: `svalnir-agent --foreground --state-dir "$SVALNIR_STATE_DIR"`. Do not run `agent install`. Then `svalnir agent status --format json` | `lock_holder` and `coordinator` show the agent; the `controller` value shows the state of the disk guard | `step21-agent-status.json`, the standard error of the agent |
| 22 | Apply the second configuration of section 13 step 22, enable the disk guard again, then `svalnir history --format json` after `sustain_for` | One automatic operation of the disk guard; `effects.permanently_removed`; `resource_effects` | `step22-*.json` |
| 23 | Repeat step 22 with a build in progress | Nothing removed; the reason in `svalnir agent status --format json` | `step23-*.json` |
| 24 | Stop the agent with Control-C; `svalnir agent status --format json`; then remove the account and its home directory after the record is complete | Exit status 0 of the agent; a clean stop | `step24-*.json` |

### After the run

1. Fill in each field of the record, the gate table, and the stage table. A case with no qualifying execution is `not_run`; do not write `passed` for it.
2. Set `lifecycle_target` and the last part of `record_id` as the subsection "Stages and the build of the run" of section 13 says.
3. Name the fixture tests for the cases that the procedure does not run (section 13, "Not in this procedure"), with their revision.
4. Write `owner_approval` with your name and the date. A record with no approval promotes nothing.
5. Merge the branch of step 3 together with the approved record, with the state of the record.
