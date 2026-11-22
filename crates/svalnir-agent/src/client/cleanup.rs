//! The manual cleanup plans and the rule inspections that the clients
//! share: `svalnir clean plan --mode evict|owner`, `svalnir clean inspect`,
//! and the Cleanup section of the GPUI client call these functions, so each
//! client selects, discovers, and binds a rule in the same way.
//!
//! The functions read the filesystem, the process table, and the output of
//! the read-only Git queries of the rules, within the bounds of the rule
//! modules. None of them records a plan, writes the journal, or removes a
//! file: a client records the sealed plan and writes its apply request to
//! the queue only after the approval of the user.
//!
//! The rule checks come first and read nothing ([`evict_rule`],
//! [`owner_rule`]): a rule whose lifecycle state does not permit the manual
//! mode is refused before a directory is read.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use svalnir_core::action::{OwnerOperationKind, Principal, WorkCharge};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{PlanId, PolicyRevisionId, RuleId, StepId, TargetId};
use svalnir_core::plan::{
    CleanupEntry, CleanupLimits, CleanupRequest, ModeSelection, OmissionReason, OwnerPlanRequest,
    PlanBuildError, PlanContext, PlanOutcome, SelectionPreset, build_cleanup_plan,
    build_owner_plan, manual_plan_lifetime,
};
use svalnir_core::policy::EvaluationClock;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{Rule, RuleMode, RuleRegistry as _};
use svalnir_core::time::WallTime;

use crate::executor::owner::ScopeLimits;
use crate::protection::ProtectedLocations;
use crate::rules::caches::InspectionHost;
use crate::rules::clear::ClearRootEntry;
use crate::rules::git::{GitTool, GitToolProblem};
use crate::rules::producers::{
    MAX_PRODUCER_EXECUTABLE_BYTES, ProducerBindRequest, ProducerBinding, ProducerRule,
};
use crate::rules::projects::{
    ClaudeTranscripts, EnvironmentEvidence, GitHeadActivity, MiseDiscovery, MiseLocations,
    PaseoAgents, ProjectHost, ProjectInspection, ProjectLimits, ProjectRequest, RecencyHost,
    RootKind, RootSource, SearchRootEntry, SearchRoots, quiet_period, tracked_projects,
};
use crate::rules::worktrees::{WorktreeHost, WorktreeInspection, WorktreeLimits};
use crate::rules::{
    DiscoveryEnvironment, DiscoveryHost, DiscoveryLimits, EvictionCandidate, EvictionDiscovery,
    EvictionRequest, ReviewedRules, SkipReason,
};
use crate::scan::CancellationToken;

/// The time that the execution of a manual cleanup plan can use.
pub const EXECUTION_DEADLINE: Nanoseconds = Nanoseconds::new(30 * 60 * 1_000_000_000);

/// The time in which the executor verifies the effect of one step.
pub const VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

/// The stable name of a reason that a unit is not a candidate now, as
/// `docs/CLEANUP_RULES.md` section 13 and the JSON output name it, for
/// example `active_producer`.
#[must_use]
pub fn skip_reason_name(reason: SkipReason) -> String {
    match serde_json::to_value(reason) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

/// The stable name of a reason that the plan builder left an entry out,
/// as the JSON output names it (its `reason` field), for example
/// `hard_protected`.
#[must_use]
pub fn omission_reason_name(reason: OmissionReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| {
            value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Why a rule cannot have the manual plan that a request names. Each value
/// has the stable code of `docs/INTERFACES.md` section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSelectionError {
    /// The registry has no rule with the identity.
    UnknownRule,
    /// The rule has no owner operation in this build.
    OwnerOperationNotAvailable,
    /// No layout of the rule is validated for the manual mode.
    ModeNotValidated,
    /// The rule removes data that a project can use now, and the request
    /// has no consent to it.
    ClearNotIncluded,
}

impl RuleSelectionError {
    /// The stable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownRule => "unknown_rule",
            Self::OwnerOperationNotAvailable => "owner_operation_not_available",
            Self::ModeNotValidated => "rule_mode_not_validated",
            Self::ClearNotIncluded => "clear_not_included",
        }
    }
}

/// Whether a layout of `rule` that an eviction removes is validated for a
/// manual eviction. The layout of the scope root of an owner operation is
/// for the `owner` mode: an eviction removes no scope root as a whole.
#[must_use]
pub fn permits_evict(registry: &ReviewedRules, rule: &Rule) -> bool {
    let owner_layout: Option<&str> = registry
        .producer(rule.reference.id.as_str())
        .map(|producer| producer.spec().layout);
    rule.layouts.iter().any(|layout| {
        Some(layout.layout.as_str()) != owner_layout && layout.permits(&RuleMode::ManualEviction)
    })
}

/// Whether the layout of the scope root of `producer` is validated for a
/// manual action.
#[must_use]
pub fn permits_owner(producer: &ProducerRule) -> bool {
    producer
        .layout()
        .is_some_and(|layout| layout.permits(&RuleMode::ManualEviction))
}

/// Whether the plan of the rule `id` needs the consent to a clear: a clear
/// rule, or a rule whose owner command has the kind `clear`.
#[must_use]
pub fn needs_clear_consent(registry: &ReviewedRules, id: &str) -> bool {
    registry.clear_rule(id).is_some()
        || registry
            .producer(id)
            .is_some_and(|producer| matches!(producer.spec().kind, OwnerOperationKind::Clear))
}

/// The rule `name` for a manual eviction: a rule with a layout that is
/// validated for it and, for a clear rule, the consent `include_clear`.
/// Reads nothing.
///
/// # Errors
///
/// Returns the reason in the order of the checks: the rule, its lifecycle
/// state, then the consent.
pub fn evict_rule<'a>(
    registry: &'a ReviewedRules,
    name: &str,
    include_clear: bool,
) -> Result<&'a Rule, RuleSelectionError> {
    let found: &Rule = registry
        .rules()
        .into_iter()
        .find(|candidate| candidate.reference.id.as_str() == name)
        .ok_or(RuleSelectionError::UnknownRule)?;
    if !permits_evict(registry, found) {
        return Err(RuleSelectionError::ModeNotValidated);
    }
    if registry.clear_rule(name).is_some() && !include_clear {
        return Err(RuleSelectionError::ClearNotIncluded);
    }
    Ok(found)
}

/// The rule `name` with an owner operation whose layout of the scope root
/// is validated for manual action, and whose kind the request permits.
/// Reads nothing.
///
/// # Errors
///
/// Returns the reason in the order of the checks.
pub fn owner_rule<'a>(
    registry: &'a ReviewedRules,
    name: &str,
    include_clear: bool,
) -> Result<&'a ProducerRule, RuleSelectionError> {
    let Some(rule) = registry.producer(name) else {
        let known: bool = registry
            .rules()
            .iter()
            .any(|rule| rule.reference.id.as_str() == name);
        return Err(if known {
            RuleSelectionError::OwnerOperationNotAvailable
        } else {
            RuleSelectionError::UnknownRule
        });
    };
    if !permits_owner(rule) {
        return Err(RuleSelectionError::ModeNotValidated);
    }
    if matches!(rule.spec().kind, OwnerOperationKind::Clear) && !include_clear {
        return Err(RuleSelectionError::ClearNotIncluded);
    }
    Ok(rule)
}

/// The roots of one request of a rule that searches projects, and the
/// result of the read of mise.
#[derive(Debug, Clone)]
pub struct ProjectRoots {
    /// The roots.
    pub roots: SearchRoots,
    /// The read of the tracked-configs directory of mise.
    pub mise: MiseDiscovery,
}

/// The read of mise of a request.
#[derive(Debug, Clone, Copy)]
pub struct MiseRequest<'a> {
    /// Whether the project roots that mise records are read.
    pub read: bool,
    /// `XDG_STATE_HOME`.
    pub state_home: Option<&'a OsStr>,
    /// `XDG_CONFIG_HOME`.
    pub config_home: Option<&'a OsStr>,
}

/// A request with more roots than a search takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManySearchRoots;

/// The roots of a request: `[cleanup.projects].search_roots`, then
/// `arguments` (roots that the client resolved below `home`), then, when
/// `mise.read` is true, the project roots that mise records.
///
/// # Errors
///
/// Returns [`TooManySearchRoots`] above the bound of [`SearchRoots`].
pub fn project_roots(
    config: &ValidatedConfig,
    home: &Path,
    arguments: Vec<SearchRootEntry>,
    mise: MiseRequest<'_>,
    principal: Uid,
) -> Result<ProjectRoots, TooManySearchRoots> {
    let mut entries: Vec<SearchRootEntry> = config
        .cleanup()
        .projects
        .search_roots
        .iter()
        .map(|relative| SearchRootEntry {
            relative: PathBuf::from(relative),
            kind: RootKind::Search,
            source: RootSource::Configuration,
        })
        .collect();
    entries.extend(arguments);
    let locations: MiseLocations = MiseLocations::resolve(home, mise.state_home, mise.config_home);
    let read: MiseDiscovery = if mise.read {
        tracked_projects(home, &locations, principal)
    } else {
        MiseDiscovery::off(&locations)
    };
    entries.extend(read.entries());
    let roots: SearchRoots = SearchRoots::with_entries(entries).map_err(|_| TooManySearchRoots)?;
    Ok(ProjectRoots { roots, mise: read })
}

/// The sources of the project activity of one request.
pub struct ProjectSources {
    git: Result<GitTool, GitToolProblem>,
    transcripts: ClaudeTranscripts,
    agents: PaseoAgents,
    quiet_period: Nanoseconds,
}

impl std::fmt::Debug for ProjectSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectSources").finish_non_exhaustive()
    }
}

impl ProjectSources {
    /// The sources of `config` for the user with `home`.
    #[must_use]
    pub fn new(config: &ValidatedConfig, home: Option<&Path>) -> Self {
        let projects = &config.cleanup().projects;
        Self {
            git: GitTool::locate(),
            transcripts: ClaudeTranscripts::for_home(home),
            agents: PaseoAgents::new(projects.paseo_agents, home),
            quiet_period: quiet_period(projects),
        }
    }

    /// The Git tool, or why there is none.
    ///
    /// # Errors
    ///
    /// Returns the problem of the tool.
    pub fn git(&self) -> Result<&GitTool, GitToolProblem> {
        self.git.as_ref().map_err(|problem| *problem)
    }

    /// The recency sources with the activity of the head of `head`.
    #[must_use]
    pub fn recency<'a>(&'a self, head: &'a GitHeadActivity<'a>) -> RecencyHost<'a> {
        RecencyHost {
            quiet_period: self.quiet_period,
            head,
            transcripts: &self.transcripts,
            agents: &self.agents,
        }
    }
}

/// The inputs of the discovery of one rule for a manual eviction.
#[derive(Debug, Clone, Copy)]
pub struct EvictDiscovery<'a> {
    /// The configuration in effect.
    pub config: &'a ValidatedConfig,
    /// The roots of `project.dependency-directory`; `None` for each other
    /// rule.
    pub roots: Option<&'a SearchRoots>,
    /// Also select the units of a project whose activity state is
    /// `active`.
    pub include_active: bool,
}

/// The discovery of `rule` for a manual eviction. `cancel` stops it; a
/// cancelled discovery has a part of the candidates, and a client makes no
/// plan from a part.
#[must_use]
pub fn discover_for_manual_eviction(
    registry: &ReviewedRules,
    rule: &Rule,
    host: &DiscoveryHost,
    environment: &dyn DiscoveryEnvironment,
    options: &EvictDiscovery<'_>,
    cancel: &CancellationToken,
) -> EvictionDiscovery {
    let sources: ProjectSources =
        ProjectSources::new(options.config, host.locations.home_directory());
    let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
    let request: Option<ProjectRequest<'_>> = options.roots.map(|roots| ProjectRequest {
        roots,
        git: sources.git(),
        recency: sources.recency(&head),
        layouts: &options.config.cleanup().projects.layouts,
        include_active: options.include_active,
        limits: ProjectLimits::default(),
    });
    let rules: [RuleId; 1] = [rule.reference.id.clone()];
    registry.discover_for_eviction(
        &EvictionRequest {
            host,
            purpose: &RuleMode::ManualEviction,
            rules: Some(&rules),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel,
            projects: request.as_ref(),
        },
        environment,
    )
}

/// The candidates of a discovery whose estimate is at least `min_size`, and
/// those that are smaller. `None` selects each candidate.
#[must_use]
pub fn split_min_size(
    candidates: &[EvictionCandidate],
    min_size: Option<Bytes>,
) -> (Vec<EvictionCandidate>, Vec<EvictionCandidate>) {
    candidates.iter().cloned().partition(|candidate| {
        min_size.is_none_or(|minimum| candidate.discovered.measurement.estimate.bytes >= minimum)
    })
}

/// Why a manual plan was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualPlanError {
    /// An identity of the plan could not be made.
    Identity,
    /// The plan builder refused the request.
    Build(PlanBuildError),
}

/// The inputs of the plan builder of a manual plan beside its targets.
#[derive(Debug, Clone, Copy)]
pub struct ManualPlanInputs<'a> {
    /// The text of the plan identity; target and step identities derive
    /// from it.
    pub plan_text: &'a str,
    /// The principal of the client.
    pub principal: &'a Principal,
    /// The revision in effect.
    pub policy_revision: &'a PolicyRevisionId,
    /// The configuration of that revision.
    pub config: &'a ValidatedConfig,
    /// The monotonic time.
    pub clock: &'a EvaluationClock,
    /// The wall-clock time.
    pub created_wall: WallTime,
    /// The home directory of the user.
    pub home_directory: Option<&'a LosslessPath>,
}

impl ManualPlanInputs<'_> {
    /// The context of the plan builder. A manual plan has no action grant:
    /// its authority is the approval that is bound to the plan.
    fn context(&self) -> Result<PlanContext<'_>, ManualPlanError> {
        let lifetime: Nanoseconds = manual_plan_lifetime(self.config)
            .ok_or(ManualPlanError::Build(PlanBuildError::Lifetime))?;
        Ok(PlanContext {
            plan_id: PlanId::new(self.plan_text.to_owned())
                .map_err(|_| ManualPlanError::Identity)?,
            principal: self.principal.clone(),
            authority: AuthorityBinding {
                policy_revision: self.policy_revision.clone(),
                action_grants: Vec::new(),
                privilege_grant: None,
            },
            clock: self.clock,
            created_wall: self.created_wall,
            lifetime,
            protections: self.config.protections(),
            home_directory: self.home_directory,
        })
    }

    fn identity(&self, kind: char, index: usize) -> String {
        format!("{}-{kind}{index:04}", self.plan_text)
    }
}

/// The entries of the plan builder for the candidates of a discovery.
///
/// # Errors
///
/// Returns [`ManualPlanError::Identity`] when an identity cannot be made.
pub fn eviction_entries(
    candidates: &[EvictionCandidate],
    inputs: &ManualPlanInputs<'_>,
) -> Result<Vec<CleanupEntry>, ManualPlanError> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            Ok(candidate.cleanup_entry(
                TargetId::new(inputs.identity('t', index))
                    .map_err(|_| ManualPlanError::Identity)?,
                StepId::new(inputs.identity('s', index)).map_err(|_| ManualPlanError::Identity)?,
            ))
        })
        .collect()
}

/// The plan of `entries` for a manual eviction under `rule`. The builder
/// charges no more than one pass of the rule, and the rule gives the
/// ceiling of one candidate.
///
/// # Errors
///
/// Returns the error of the plan builder.
pub fn build_eviction_plan(
    registry: &ReviewedRules,
    rule: &Rule,
    entries: &[CleanupEntry],
    preset: Option<&SelectionPreset>,
    inputs: &ManualPlanInputs<'_>,
) -> Result<PlanOutcome, ManualPlanError> {
    let context: PlanContext<'_> = inputs.context()?;
    let request = CleanupRequest {
        mode: ModeSelection::Evict {
            rule: registry.lookup(&rule.reference),
        },
        entries,
        preset,
        limits: CleanupLimits {
            plan: rule.budget.per_pass,
            batch: WorkCharge::new(
                rule.budget.per_pass.work_bytes.max(Bytes::new(1)),
                rule.budget.per_pass.items.max(EntryCount::new(1)),
            ),
            execution_deadline: EXECUTION_DEADLINE,
            verification_window: VERIFICATION_WINDOW,
        },
    };
    build_cleanup_plan(&context, &request).map_err(ManualPlanError::Build)
}

/// The request of the binding of an owner operation.
#[must_use]
pub fn owner_bind_request<'a>(
    principal: Uid,
    locations: &'a ProtectedLocations,
    user_exclusions: &'a [PathBuf],
    include_clear: bool,
) -> ProducerBindRequest<'a> {
    ProducerBindRequest {
        host: InspectionHost {
            principal,
            locations,
            user_exclusions,
        },
        include_clear,
        max_executable_bytes: MAX_PRODUCER_EXECUTABLE_BYTES,
        scope_limits: ScopeLimits::default(),
    }
}

/// The manual plan of the owner operation `bound`.
///
/// # Errors
///
/// Returns the error of the plan builder, or an identity error.
pub fn build_owner_operation_plan(
    registry: &ReviewedRules,
    bound: &ProducerBinding,
    locations: &ProtectedLocations,
    inputs: &ManualPlanInputs<'_>,
) -> Result<PlanOutcome, ManualPlanError> {
    let context: PlanContext<'_> = inputs.context()?;
    build_owner_plan(
        &context,
        &OwnerPlanRequest {
            target_id: TargetId::new(inputs.identity('t', 0))
                .map_err(|_| ManualPlanError::Identity)?,
            step_id: StepId::new(inputs.identity('s', 0)).map_err(|_| ManualPlanError::Identity)?,
            binding: &bound.binding,
            rule: registry.lookup(&bound.binding.rule),
            protection: locations.of_text(&bound.root.binding.path),
            verification_window: VERIFICATION_WINDOW,
        },
    )
    .map_err(ManualPlanError::Build)
}

/// The inspection of `project.dependency-directory` below `roots`.
#[must_use]
pub fn inspect_projects(
    registry: &ReviewedRules,
    host: &DiscoveryHost,
    config: &ValidatedConfig,
    roots: &SearchRoots,
    environment: &dyn DiscoveryEnvironment,
    cancel: &CancellationToken,
) -> ProjectInspection {
    let sources: ProjectSources = ProjectSources::new(config, host.locations.home_directory());
    let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
    let processes: EnvironmentEvidence<'_> = EnvironmentEvidence(environment);
    let project_host: ProjectHost<'_> = ProjectHost {
        principal: host.principal,
        locations: &host.locations,
        user_exclusions: &host.user_exclusions,
        git: sources.git(),
        processes: &processes,
        recency: sources.recency(&head),
        layouts: &config.cleanup().projects.layouts,
    };
    registry.projects().inspect(
        project_host,
        roots,
        ProjectLimits::default(),
        cancel,
        environment,
    )
}

/// The inspection of `git.linked-worktree` below `roots`.
#[must_use]
pub fn inspect_worktrees(
    registry: &ReviewedRules,
    host: &DiscoveryHost,
    roots: &SearchRoots,
    cancel: &CancellationToken,
) -> WorktreeInspection {
    let git: Result<GitTool, GitToolProblem> = GitTool::locate();
    registry.worktrees().inspect(
        WorktreeHost {
            principal: host.principal,
            locations: &host.locations,
            user_exclusions: &host.user_exclusions,
            git: git.as_ref().map_err(|problem| *problem),
        },
        roots,
        WorktreeLimits::default(),
        cancel,
    )
}

/// The inspection of the clear rule `id`: the discovery of its roots,
/// whatever its lifecycle state, with no consent and no plan. `None` when
/// `id` is not a clear rule.
#[must_use]
pub fn inspect_clear(
    registry: &ReviewedRules,
    id: &str,
    host: &DiscoveryHost,
    environment: &dyn DiscoveryEnvironment,
    cancel: &CancellationToken,
) -> Option<(EvictionDiscovery, Vec<ClearRootEntry>)> {
    let request: EvictionRequest<'_> = EvictionRequest {
        host,
        purpose: &RuleMode::Inspection,
        rules: None,
        volumes: None,
        known: None,
        limits: DiscoveryLimits::default(),
        cancel,
        projects: None,
    };
    registry.inspect_clear(id, &request, environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registries() -> (ReviewedRules, ReviewedRules) {
        let released = ReviewedRules::new().unwrap_or_else(|error| panic!("{error}"));
        let fixture = ReviewedRules::with_fixture_lifecycle(
            &crate::rules::fixture::manual_action_validated(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        (released, fixture)
    }

    #[test]
    fn a_proposed_rule_is_refused_before_the_consent() {
        let (released, _) = registries();
        for name in ["project.dependency-directory", "cargo.registry-cache"] {
            assert_eq!(
                evict_rule(&released, name, false).err(),
                Some(RuleSelectionError::ModeNotValidated),
                "{name}"
            );
        }
        assert_eq!(
            owner_rule(&released, "go.build-cache", false).err(),
            Some(RuleSelectionError::ModeNotValidated)
        );
        assert_eq!(
            evict_rule(&released, "no.such-rule", true).err(),
            Some(RuleSelectionError::UnknownRule)
        );
    }

    #[test]
    fn a_clear_needs_the_consent_in_both_modes() {
        let (_, fixture) = registries();
        assert_eq!(
            evict_rule(&fixture, "cargo.registry-cache", false).err(),
            Some(RuleSelectionError::ClearNotIncluded)
        );
        assert!(evict_rule(&fixture, "cargo.registry-cache", true).is_ok());
        assert_eq!(
            owner_rule(&fixture, "go.build-cache", false).err(),
            Some(RuleSelectionError::ClearNotIncluded)
        );
        assert!(owner_rule(&fixture, "go.build-cache", true).is_ok());
        assert!(needs_clear_consent(&fixture, "cargo.registry-cache"));
        assert!(needs_clear_consent(&fixture, "go.build-cache"));
        assert!(!needs_clear_consent(
            &fixture,
            "project.dependency-directory"
        ));
        assert_eq!(
            owner_rule(&fixture, "project.dependency-directory", true).err(),
            Some(RuleSelectionError::OwnerOperationNotAvailable)
        );
    }

    #[test]
    fn each_error_has_its_stable_code() {
        assert_eq!(RuleSelectionError::UnknownRule.code(), "unknown_rule");
        assert_eq!(
            RuleSelectionError::ModeNotValidated.code(),
            "rule_mode_not_validated"
        );
        assert_eq!(
            RuleSelectionError::ClearNotIncluded.code(),
            "clear_not_included"
        );
        assert_eq!(
            RuleSelectionError::OwnerOperationNotAvailable.code(),
            "owner_operation_not_available"
        );
    }
}
