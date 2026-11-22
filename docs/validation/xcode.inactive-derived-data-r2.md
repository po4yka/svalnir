# Promotion record: `xcode.inactive-derived-data` r2

**Status:** Empty template. No promotion record exists. The host procedure of [VALIDATION.md](../VALIDATION.md#13-rule-promotion-record-and-host-procedure) section 13 did not run, each field below is empty, and `owner_approval` is `null`, so this file promotes nothing. The layout `derived-data-project-v1` stays `proposed`.

Only the project owner fills in this file, after the run of the [owner checklist](README.md). Do not change the lifecycle state in `crates/svalnir-agent/src/rules/xcode.rs` on `main` before the owner approves this record.

## Record

The fields are those of [VALIDATION.md](../VALIDATION.md#12-evidence-record-and-triage) section 12 and section 13. The subsection "Stages and the build of the run" of section 13 gives the value of `lifecycle_target` and the last part of `record_id`.

```yaml
validation_id: VAL-05
case_id: promotion
status: not_run
source_revision: null
artifact_digest: null
adapter_revision: null
environment_record: null
fixture_manifest: null
effective_policy_and_grants: null
seed_or_trace: null
expected_assertions: []
observed_results: []
evidence_paths: []
limitations: []
reviewer: null
run_started_at: null
rule_id: xcode.inactive-derived-data
rule_revision: r2
layout: derived-data-project-v1
lifecycle_target: automatic_eviction_validated
record_id: VAL-05/xcode.inactive-derived-data/r2/derived-data-project-v1/automatic
producer_versions: []
host_versions: []
filesystems: []
allow_list_observations: []
gate_results: []
fixture_test_revision: null
residual_risks: []
open_points_closed: []
owner_approval: null
```

## Gate results

One row for each gate of [CLEANUP_RULES.md](../CLEANUP_RULES.md#15-verification-and-promotion) section 15. The status values are those of [VALIDATION.md](../VALIDATION.md#2-evidence-status-and-scope) section 2. A gate that the host procedure does not examine names the fixture tests and their revision, or stays `not_run`.

| Gate | Status | Steps or fixture tests | Evidence paths |
| --- | --- | --- | --- |
| Classification | `not_run` | | |
| Ownership and roots | `not_run` | | |
| Activity | `not_run` | | |
| Identity and confinement | `not_run` | | |
| Accounting | `not_run` | | |
| Bounds | `not_run` | | |
| Persistence | `not_run` | | |
| Outcomes | `not_run` | | |
| Privacy and presentation | `not_run` | | |

## Stage results

| Stage | Steps | Status |
| --- | --- | --- |
| `inspection_validated` | 6 to 12 | `not_run` |
| `manual_action_validated` | 13 to 19 | `not_run` |
| `automatic_eviction_validated` | 20 to 23 | `not_run` |
