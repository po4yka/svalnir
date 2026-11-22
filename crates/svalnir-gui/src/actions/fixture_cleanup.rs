//! The cleanup rules of a fixture: synthetic inspections and plans. Nothing
//! is read and nothing is recorded.
//!
//! Three rules have a fixture lifecycle state that permits a manual plan, so
//! that a screenshot shows a sealed plan; the state names no validation
//! record. Each other rule is `proposed`, as in a released build, and its
//! plan is refused with `rule_mode_not_validated`. The fixture follows the
//! discovery of the agent: a unit that holds a Git repository is not a
//! candidate (`nested_repository`), so an eviction plan leaves it out.

use super::{
    ActionState, Unavailable,
    cleanup::{
        CleanupProposal, CleanupRequest, CleanupSnapshot, CleanupTarget, OwnerFacts, PlanKind,
        RootRow, RuleFamily, RuleInspection, SizeKind, UnitRow,
    },
};
use std::time::{Duration, SystemTime};
use svalnir_agent::rules::{
    XCODE_DERIVED_DATA_REVISION, clear::CLEAR_RULE_REVISION, producers::EXTENDED_RULE_REVISION,
    projects::PROJECT_RULE_REVISION, worktrees::WORKTREE_RULE_REVISION,
};

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

/// The revision of the rule `rule` in the registry of this build. The
/// producer rules that extend a cache rule or an owner tool have the
/// revision of [`EXTENDED_RULE_REVISION`].
fn revision_of(rule: &str) -> &'static str {
    match rule {
        "project.dependency-directory" => PROJECT_RULE_REVISION,
        "git.linked-worktree" => WORKTREE_RULE_REVISION,
        "cargo.registry-cache" => CLEAR_RULE_REVISION,
        "xcode.inactive-derived-data" => XCODE_DERIVED_DATA_REVISION,
        _ => EXTENDED_RULE_REVISION,
    }
}

/// A rule with no root, no unit, and one layout in its lifecycle state.
fn base(
    rule: &str,
    family: RuleFamily,
    producer: &str,
    validated: bool,
    plan: Option<PlanKind>,
) -> RuleInspection {
    let lifecycle: &str = if validated {
        FIXTURE_LIFECYCLE
    } else {
        "proposed"
    };
    RuleInspection {
        rule: rule.to_owned(),
        revision: revision_of(rule).to_owned(),
        family,
        producer: producer.to_owned(),
        lifecycle: lifecycle.to_owned(),
        layouts: Vec::new(),
        plan,
        permits_plan: validated,
        needs_clear: false,
        project_options: false,
        roots: Vec::new(),
        units: Vec::new(),
        units_omitted: 0,
        owner: None,
        notes: Vec::new(),
        problem: None,
    }
}

fn project_rule() -> RuleInspection {
    RuleInspection {
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
                Some("nested_repository"),
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
        ..base(
            "project.dependency-directory",
            RuleFamily::Project,
            "npm, pnpm, yarn, cargo",
            true,
            Some(PlanKind::Evict),
        )
    }
}

fn go_rule() -> RuleInspection {
    RuleInspection {
        needs_clear: true,
        roots: vec![root("/Users/fixture/Library/Caches/go-build", "examined")],
        units: vec![unit(
            "/Users/fixture/Library/Caches/go-build",
            2_300 * MIB,
            SizeKind::PrivateAllocated,
            None,
        )],
        owner: Some(OwnerFacts {
            kind: "clear".to_owned(),
            command: "/opt/homebrew/bin/go clean -cache".to_owned(),
            environment: vec![
                "GOCACHE=/Users/fixture/Library/Caches/go-build".to_owned(),
                "GOFLAGS=".to_owned(),
            ],
            effect: "go removes each file of its build cache.".to_owned(),
            consequence: "The next build of each Go project compiles its packages again, also of a project that you use now.".to_owned(),
            scope: "/Users/fixture/Library/Caches/go-build".to_owned(),
        }),
        ..base("go.build-cache", RuleFamily::Owner, "go", true, Some(PlanKind::Owner))
    }
}

fn homebrew_rule() -> RuleInspection {
    RuleInspection {
        roots: vec![root("/Users/fixture/Library/Caches/Homebrew", "examined")],
        units: vec![unit(
            "/Users/fixture/Library/Caches/Homebrew",
            1_870 * MIB,
            SizeKind::WholeCache,
            None,
        )],
        owner: Some(OwnerFacts {
            kind: "prune".to_owned(),
            command: "/opt/homebrew/bin/brew cleanup --prune=all".to_owned(),
            environment: vec!["HOMEBREW_NO_AUTO_UPDATE=1".to_owned()],
            effect: "Homebrew removes the downloads and the old versions that no installed formula uses.".to_owned(),
            consequence: "A later install downloads a removed file again.".to_owned(),
            scope: "/Users/fixture/Library/Caches/Homebrew".to_owned(),
        }),
        ..base(
            "homebrew.cleanup",
            RuleFamily::Owner,
            "homebrew",
            false,
            Some(PlanKind::Owner),
        )
    }
}

fn cargo_clear_rule() -> RuleInspection {
    RuleInspection {
        needs_clear: true,
        roots: vec![
            root("/Users/fixture/.cargo/registry/cache", "from default .cargo/registry/cache"),
            root("/Users/fixture/.cargo/registry/src", "from default .cargo/registry/src"),
        ],
        units: vec![
            unit(
                "/Users/fixture/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f",
                612 * MIB,
                SizeKind::AllocatedUpperBound,
                None,
            ),
            unit(
                "/Users/fixture/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f",
                2_050 * MIB,
                SizeKind::AllocatedUpperBound,
                Some("active_producer"),
            ),
        ],
        notes: vec![
            "Kept: `~/.cargo/registry/index`, `~/.cargo/git`, `~/.cargo/bin`, and the configuration and credentials of the Cargo home stay.".to_owned(),
            "After a removal: the next build downloads each removed crate archive again; `cargo build --offline` fails for a crate whose archive is gone.".to_owned(),
        ],
        ..base(
            "cargo.registry-cache",
            RuleFamily::Clear,
            "cargo",
            true,
            Some(PlanKind::Evict),
        )
    }
}

fn pnpm_rule() -> RuleInspection {
    RuleInspection {
        roots: vec![root("/Users/fixture/Library/pnpm/store", "examined")],
        units: vec![unit(
            "/Users/fixture/Library/pnpm/store/v10",
            4_020 * MIB,
            SizeKind::AllocatedNotReclaim,
            None,
        )],
        ..base("pnpm.content-store", RuleFamily::Cache, "pnpm", false, None)
    }
}

fn worktree_rule() -> RuleInspection {
    RuleInspection {
        roots: vec![root("/Users/fixture/Projects", "examined")],
        units: vec![UnitRow {
            path: "/Users/fixture/Projects/engine/.worktrees/fix-cache".to_owned(),
            size: None,
            size_kind: SizeKind::AllocatedUpperBound,
            partial: false,
            reason: Some("uncommitted_changes".to_owned()),
        }],
        ..base(
            "git.linked-worktree",
            RuleFamily::Worktree,
            "git",
            false,
            None,
        )
    }
}

fn xcode_rule() -> RuleInspection {
    RuleInspection {
        layouts: vec![
            ("derived-data-project-v1".to_owned(), "proposed".to_owned()),
            ("derived-data-orphan-v1".to_owned(), "proposed".to_owned()),
        ],
        roots: vec![root(
            "/Users/fixture/Library/Developer/Xcode/DerivedData",
            "not inspected",
        )],
        notes: vec!["The layout derived-data-orphan-v1 is the project directory whose project is gone; it is for a manual eviction only.".to_owned()],
        problem: Some(
            "This build has no inspection for this rule. A plan of the evict mode finds its units."
                .to_owned(),
        ),
        ..base(
            "xcode.inactive-derived-data",
            RuleFamily::Xcode,
            "xcode",
            false,
            Some(PlanKind::Evict),
        )
    }
}

/// The inspections of the fixture rules.
#[must_use]
pub fn inspections() -> Vec<RuleInspection> {
    vec![
        project_rule(),
        go_rule(),
        homebrew_rule(),
        cargo_clear_rule(),
        pnpm_rule(),
        worktree_rule(),
        xcode_rule(),
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
    let consequence: &str = match request.kind {
        PlanKind::Evict => {
            "Each entry is removed from the disk, not moved to the Trash. There is no undo. The producer makes the data again when a project needs it."
        }
        PlanKind::Owner => {
            "The producer runs its own command on the scope. There is no undo. Svalnir measures the scope again after the command."
        }
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
        warnings: Vec::new(),
        owner: rule.owner.clone(),
        consequence: consequence.to_owned(),
        permanent: true,
        clear: rule.needs_clear,
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
            cancel: svalnir_agent::scan::CancellationToken::new(),
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
        for (rule, kind) in [
            ("go.build-cache", PlanKind::Owner),
            ("cargo.registry-cache", PlanKind::Evict),
        ] {
            let without = proposal(&request(rule, kind, CleanupOptions::default()), true);
            assert!(
                matches!(without, Err(ActionState::Refused { code, .. }) if code == "clear_not_included"),
                "{rule}"
            );
            let with = proposal(
                &request(
                    rule,
                    kind,
                    CleanupOptions {
                        include_clear: true,
                        ..CleanupOptions::default()
                    },
                ),
                true,
            )
            .expect("plan");
            assert!(with.clear, "{rule}");
        }
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
    fn a_unit_with_a_repository_is_left_out_as_the_discovery_leaves_it_out() {
        let plan = proposal(
            &request(
                "project.dependency-directory",
                PlanKind::Evict,
                CleanupOptions::default(),
            ),
            true,
        )
        .expect("plan");
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert!(!plan.targets.iter().any(|t| t.path.contains("engine")));
        assert!(
            plan.omitted
                .iter()
                .any(|(path, reason)| path.contains("engine") && reason == "nested_repository")
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
        assert_eq!(default.target_count, 2);
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
        // project and the repository stay out.
        let paths: Vec<&str> = wider.targets.iter().map(|t| t.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("/api/")));
        assert!(!paths.iter().any(|p| p.contains("notes-app")));
        assert!(!paths.iter().any(|p| p.contains("cli-tool")));
    }

    #[test]
    fn each_fixture_rule_has_the_revision_of_the_registry() {
        use svalnir_core::rule::RuleRegistry as _;
        let registry =
            svalnir_agent::rules::ReviewedRules::new().unwrap_or_else(|error| panic!("{error}"));
        for rule in inspections() {
            let known = registry
                .rules()
                .into_iter()
                .find(|known| known.reference.id.as_str() == rule.rule)
                .unwrap_or_else(|| panic!("{} is not a rule of this build", rule.rule));
            assert_eq!(
                known.reference.revision.as_str(),
                rule.revision,
                "{}",
                rule.rule
            );
        }
    }
}
