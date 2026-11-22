//! The cleanup rules of a fixture: synthetic inspections and plans. Nothing
//! is read and nothing is recorded.
//!
//! Two rules have a fixture lifecycle state that permits a manual plan, so
//! that a screenshot shows a sealed plan; the state names no validation
//! record. Each other rule is `proposed`, as in a released build, and its
//! plan is refused with `rule_mode_not_validated`.

use super::{
    ActionState, Unavailable,
    cleanup::{
        CleanupProposal, CleanupRequest, CleanupSnapshot, CleanupTarget, OwnerFacts, PlanKind,
        RootRow, RuleFamily, RuleInspection, SizeKind, UnitRow,
    },
};
use std::time::{Duration, SystemTime};

/// The lifetime of a fixture plan.
const PLAN_LIFETIME: Duration = Duration::from_secs(300);

/// The lifecycle text of a fixture rule that permits a manual plan.
pub const FIXTURE_LIFECYCLE: &str = "manual_action_validated (fixture, no validation record)";

const MIB: u64 = 1024 * 1024;

fn unit(path: &str, size: u64, kind: SizeKind, reason: Option<&str>) -> UnitRow {
    UnitRow {
        path: path.to_owned(),
        size: Some(size),
        size_kind: kind,
        partial: false,
        reason: reason.map(str::to_owned),
    }
}

fn root(path: &str, state: &str) -> RootRow {
    RootRow {
        path: path.to_owned(),
        state: state.to_owned(),
    }
}

fn go_owner() -> OwnerFacts {
    OwnerFacts {
        kind: "clear".to_owned(),
        command: "/opt/homebrew/bin/go clean -cache".to_owned(),
        environment: vec![
            "GOCACHE=/Users/fixture/Library/Caches/go-build".to_owned(),
            "GOFLAGS=".to_owned(),
        ],
        effect: "go removes each file of its build cache.".to_owned(),
        consequence: "The next build of each Go project compiles its packages again, also of a project that you use now.".to_owned(),
        scope: "/Users/fixture/Library/Caches/go-build".to_owned(),
    }
}

/// The inspections of the fixture rules.
#[must_use]
#[expect(clippy::too_many_lines, reason = "one literal for each fixture rule")]
pub fn inspections() -> Vec<RuleInspection> {
    vec![
        RuleInspection {
            rule: "project.dependency-directory".to_owned(),
            revision: "3".to_owned(),
            family: RuleFamily::Project,
            producer: "npm, pnpm, yarn, cargo".to_owned(),
            lifecycle: FIXTURE_LIFECYCLE.to_owned(),
            plan: Some(PlanKind::Evict),
            permits_plan: true,
            needs_clear: false,
            project_options: true,
            roots: vec![root("/Users/fixture/Projects", "examined")],
            units: vec![
                unit(
                    "/Users/fixture/Projects/web-shop/node_modules",
                    1_240 * MIB,
                    SizeKind::PrivateAllocated,
                    None,
                ),
                unit(
                    "/Users/fixture/Projects/engine/target",
                    3_610 * MIB,
                    SizeKind::PrivateAllocated,
                    None,
                ),
                unit(
                    "/Users/fixture/Projects/notes-app/node_modules",
                    86 * MIB,
                    SizeKind::PrivateAllocated,
                    None,
                ),
                unit(
                    "/Users/fixture/Projects/api/node_modules",
                    640 * MIB,
                    SizeKind::PrivateAllocated,
                    Some("project_active"),
                ),
                unit(
                    "/Users/fixture/Projects/cli-tool/target",
                    410 * MIB,
                    SizeKind::AllocatedUpperBound,
                    Some("project_busy"),
                ),
            ],
            units_omitted: 0,
            owner: None,
            problem: None,
        },
        RuleInspection {
            rule: "go.build-cache".to_owned(),
            revision: "2".to_owned(),
            family: RuleFamily::Owner,
            producer: "go".to_owned(),
            lifecycle: FIXTURE_LIFECYCLE.to_owned(),
            plan: Some(PlanKind::Owner),
            permits_plan: true,
            needs_clear: true,
            project_options: false,
            roots: vec![root("/Users/fixture/Library/Caches/go-build", "examined")],
            units: vec![unit(
                "/Users/fixture/Library/Caches/go-build",
                2_300 * MIB,
                SizeKind::PrivateAllocated,
                None,
            )],
            units_omitted: 0,
            owner: Some(go_owner()),
            problem: None,
        },
        RuleInspection {
            rule: "homebrew.cleanup".to_owned(),
            revision: "2".to_owned(),
            family: RuleFamily::Owner,
            producer: "homebrew".to_owned(),
            lifecycle: "proposed".to_owned(),
            plan: Some(PlanKind::Owner),
            permits_plan: false,
            needs_clear: false,
            project_options: false,
            roots: vec![root("/Users/fixture/Library/Caches/Homebrew", "examined")],
            units: vec![unit(
                "/Users/fixture/Library/Caches/Homebrew",
                1_870 * MIB,
                SizeKind::WholeCache,
                None,
            )],
            units_omitted: 0,
            owner: Some(OwnerFacts {
                kind: "prune".to_owned(),
                command: "/opt/homebrew/bin/brew cleanup --prune=all".to_owned(),
                environment: vec!["HOMEBREW_NO_AUTO_UPDATE=1".to_owned()],
                effect: "Homebrew removes the downloads and the old versions that no installed formula uses.".to_owned(),
                consequence: "A later install downloads a removed file again.".to_owned(),
                scope: "/Users/fixture/Library/Caches/Homebrew".to_owned(),
            }),
            problem: None,
        },
        RuleInspection {
            rule: "pnpm.content-store".to_owned(),
            revision: "1".to_owned(),
            family: RuleFamily::Cache,
            producer: "pnpm".to_owned(),
            lifecycle: "proposed".to_owned(),
            plan: None,
            permits_plan: false,
            needs_clear: false,
            project_options: false,
            roots: vec![root("/Users/fixture/Library/pnpm/store", "examined")],
            units: vec![unit(
                "/Users/fixture/Library/pnpm/store/v10",
                4_020 * MIB,
                SizeKind::AllocatedNotReclaim,
                None,
            )],
            units_omitted: 0,
            owner: None,
            problem: None,
        },
        RuleInspection {
            rule: "git.linked-worktree".to_owned(),
            revision: "1".to_owned(),
            family: RuleFamily::Worktree,
            producer: "git".to_owned(),
            lifecycle: "proposed".to_owned(),
            plan: None,
            permits_plan: false,
            needs_clear: false,
            project_options: false,
            roots: vec![root("/Users/fixture/Projects", "examined")],
            units: vec![UnitRow {
                path: "/Users/fixture/Projects/engine/.worktrees/fix-cache".to_owned(),
                size: None,
                size_kind: SizeKind::AllocatedUpperBound,
                partial: false,
                reason: Some("uncommitted_changes".to_owned()),
            }],
            units_omitted: 0,
            owner: None,
            problem: None,
        },
        RuleInspection {
            rule: "xcode.inactive-derived-data".to_owned(),
            revision: "2".to_owned(),
            family: RuleFamily::Xcode,
            producer: "xcode".to_owned(),
            lifecycle: "proposed".to_owned(),
            plan: Some(PlanKind::Evict),
            permits_plan: false,
            needs_clear: false,
            project_options: false,
            roots: vec![root(
                "/Users/fixture/Library/Developer/Xcode/DerivedData",
                "not inspected",
            )],
            units: Vec::new(),
            units_omitted: 0,
            owner: None,
            problem: Some("This build has no inspection for this rule. A plan of the evict mode finds its units.".to_owned()),
        },
    ]
}

/// The snapshot of the fixture rules.
#[must_use]
pub fn snapshot() -> CleanupSnapshot {
    CleanupSnapshot {
        rules: inspections(),
        captured_at: SystemTime::now(),
    }
}

/// The plan of `request` for a fixture. `available` is false when the
/// fixture has no agent.
///
/// # Errors
///
/// Returns the refusal of the rule, or the state of an unavailable agent.
pub fn proposal(request: &CleanupRequest, available: bool) -> Result<CleanupProposal, ActionState> {
    let rules: Vec<RuleInspection> = inspections();
    let rule: &RuleInspection = rules
        .iter()
        .find(|rule| rule.rule == request.rule)
        .ok_or_else(|| ActionState::refused("unknown_rule"))?;
    // The checks have the order of the CLI: the lifecycle state, then the
    // consent, before anything is read.
    if !rule.permits_plan || rule.plan != Some(request.kind) {
        return Err(ActionState::refused("rule_mode_not_validated"));
    }
    if rule.needs_clear && !request.options.include_clear {
        return Err(ActionState::refused("clear_not_included"));
    }
    if !available {
        return Err(ActionState::Unavailable(Unavailable::NoAgent));
    }
    let mut targets: Vec<CleanupTarget> = Vec::new();
    let mut omitted: Vec<(String, String)> = Vec::new();
    for unit in &rule.units {
        let active: bool = unit.reason.as_deref() == Some("project_active");
        let below: bool = request
            .options
            .min_size
            .is_some_and(|minimum| unit.size.unwrap_or(0) < minimum);
        match &unit.reason {
            Some(reason) if !(active && request.options.include_active) => {
                omitted.push((unit.path.clone(), reason.clone()));
            }
            _ if below => omitted.push((unit.path.clone(), "below_minimum_size".to_owned())),
            _ => targets.push(CleanupTarget {
                path: unit.path.clone(),
                estimate: unit.size,
            }),
        }
    }
    let estimate: Option<u64> = targets.iter().map(|target| target.estimate).sum();
    let (consequence, warnings): (&str, Vec<String>) = match request.kind {
        PlanKind::Evict => (
            "Each entry is removed from the disk, not moved to the Trash. There is no undo. The producer makes the data again when a project needs it.",
            targets
                .iter()
                .filter(|target| target.path.ends_with("target"))
                .map(|target| {
                    format!(
                        "{} holds a Git repository (nested_repository) at vendor/engine-core. A repository can hold commits that exist nowhere else.",
                        target.path
                    )
                })
                .collect(),
        ),
        PlanKind::Owner => (
            "The producer runs its own command on the scope. There is no undo. Svalnir measures the scope again after the command.",
            Vec::new(),
        ),
    };
    let count: usize = targets.len();
    Ok(CleanupProposal {
        rule: rule.rule.clone(),
        kind: request.kind,
        plan_id: (count > 0).then(|| "plan-fixture-cleanup".to_owned()),
        target_count: count,
        estimate,
        estimate_statement: "The estimate is the private allocated size at the discovery. It is not a measured result: the agent measures the volume again after the plan.".to_owned(),
        omitted_count: omitted.len(),
        omitted,
        warnings,
        owner: rule.owner.clone(),
        consequence: consequence.to_owned(),
        permanent: true,
        expires_at: SystemTime::now() + PLAN_LIFETIME,
        plan: None,
        targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::cleanup::CleanupOptions;

    fn request(rule: &str, kind: PlanKind, options: CleanupOptions) -> CleanupRequest {
        CleanupRequest {
            rule: rule.to_owned(),
            kind,
            options,
        }
    }

    #[test]
    fn a_proposed_rule_is_refused_with_its_code() {
        let result = proposal(
            &request(
                "homebrew.cleanup",
                PlanKind::Owner,
                CleanupOptions::default(),
            ),
            true,
        );
        assert!(
            matches!(result, Err(ActionState::Refused { code, .. }) if code == "rule_mode_not_validated")
        );
    }

    #[test]
    fn a_clear_plan_needs_the_consent() {
        let without = proposal(
            &request("go.build-cache", PlanKind::Owner, CleanupOptions::default()),
            true,
        );
        assert!(
            matches!(without, Err(ActionState::Refused { code, .. }) if code == "clear_not_included")
        );
        let with = proposal(
            &request(
                "go.build-cache",
                PlanKind::Owner,
                CleanupOptions {
                    include_clear: true,
                    ..CleanupOptions::default()
                },
            ),
            true,
        )
        .expect("plan");
        assert!(with.owner.is_some());
    }

    #[test]
    fn with_no_agent_no_plan_is_made() {
        let result = proposal(
            &request(
                "project.dependency-directory",
                PlanKind::Evict,
                CleanupOptions::default(),
            ),
            false,
        );
        assert_eq!(
            result.err(),
            Some(ActionState::Unavailable(Unavailable::NoAgent))
        );
    }

    #[test]
    fn the_options_select_the_targets() {
        let default = proposal(
            &request(
                "project.dependency-directory",
                PlanKind::Evict,
                CleanupOptions::default(),
            ),
            true,
        )
        .expect("plan");
        assert_eq!(default.target_count, 3);
        let wider = proposal(
            &request(
                "project.dependency-directory",
                PlanKind::Evict,
                CleanupOptions {
                    include_active: true,
                    min_size: Some(100 * MIB),
                    include_clear: false,
                },
            ),
            true,
        )
        .expect("plan");
        // The active project comes in, the small unit goes out, and the busy
        // project stays out.
        let paths: Vec<&str> = wider.targets.iter().map(|t| t.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("/api/")));
        assert!(!paths.iter().any(|p| p.contains("notes-app")));
        assert!(!paths.iter().any(|p| p.contains("cli-tool")));
    }
}
