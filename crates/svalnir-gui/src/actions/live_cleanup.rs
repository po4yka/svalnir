//! The live path of the cleanup rules: the inspection of each rule and the
//! sealed plan of one rule, from the functions of `svalnir_agent::rules`
//! and `svalnir_core::plan` that `svalnir clean inspect` and `svalnir clean
//! plan --mode evict|owner` call.
//!
//! The inspection is read-only. The plan is made in this process and is
//! not recorded: the window records it and writes its apply request to the
//! queue only after the confirmation ([`super::live::LivePort`]). The
//! lifecycle state of the rule is checked first, as the CLI checks it, so a
//! `proposed` rule is refused with `rule_mode_not_validated` before a
//! directory is read. Each read has the bounds of the agent library, and
//! the model calls these functions on a background thread only.

use super::{
    ActionState,
    cleanup::{
        CleanupProposal, CleanupRequest, CleanupSnapshot, CleanupTarget, OwnerFacts, PlanKind,
        RootRow, RuleFamily, RuleInspection, SizeKind, TARGET_LIMIT, UNIT_LIMIT, UnitRow,
        snake_name,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use svalnir_agent::{
    executor::owner::ScopeLimits,
    platform::process::DarwinProcessSource,
    protection::ProtectedLocations,
    rules::{
        DiscoveryHost, DiscoveryLimits, EvictionCandidate, EvictionDiscovery, EvictionRequest,
        ReviewedRules, RootResult, SharedEnvironment, SourceEnvironment,
        caches::{
            CacheInspection, CacheMeasurement, InspectionHost, InspectionLimits, ReclaimFigure,
            RootOutcome, UnitOutcome,
        },
        git::{GitTool, GitToolProblem},
        producers::{
            GuardOutcome, MAX_PRODUCER_EXECUTABLE_BYTES, OWNER_SCOPE_UNMARKED, OwnerInspection,
            ProducerBindError, ProducerBindRequest, ProducerBinding, ProducerRule, guard_code,
        },
        projects::{
            ClaudeTranscripts, EnvironmentEvidence, GitHeadActivity, MiseLocations,
            PROJECT_RULE_ID, PaseoAgents, ProjectHost, ProjectLimits, ProjectRequest,
            ProjectUnitOutcome, RecencyHost, RootKind, RootSource, SearchRootEntry,
            SearchRootOutcome, SearchRootReport, SearchRoots, quiet_period, tracked_projects,
        },
        worktrees::{WorktreeHost, WorktreeLimits},
    },
    scan::{CancellationToken, WallScanClock},
};
use svalnir_core::{
    action::{ClientRole, OwnerOperationKind, Plan, WorkCharge},
    authority::AuthorityBinding,
    config::ValidatedConfig,
    file::LosslessPath,
    id::{PlanId, PolicyRevisionId, StepId, TargetId},
    plan::{
        CleanupEntry, CleanupLimits, CleanupRequest as PlanRequest, ModeSelection,
        OwnerPlanRequest, PlanBuildError, PlanContext, PlanExplanation, PlanOutcome,
        TargetExplanation, build_cleanup_plan, build_owner_plan, explain, manual_plan_lifetime,
    },
    policy::EvaluationClock,
    process::Uid,
    quantity::{Bytes, EntryCount, Nanoseconds},
    rule::{LifecycleState, Rule, RuleMode, RuleRegistry as _},
    time::WallTime,
};

/// The time that the execution of a manual cleanup plan can use, as the
/// CLI gives it.
const EXECUTION_DEADLINE: Nanoseconds = Nanoseconds::new(30 * 60 * 1_000_000_000);

/// The time in which the executor verifies the effect of one step.
const VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5 * 1_000_000_000);

/// The text of the configuration template: a document with no key other
/// than the schema version, so each value comes from the template.
const TEMPLATE_DOCUMENT: &str = "schema_version = 1\n";

/// The inputs that each inspection and each plan read.
struct Host {
    config: ValidatedConfig,
    locations: ProtectedLocations,
    discovery: DiscoveryHost,
    principal: Uid,
    evidence: SharedEnvironment,
}

impl Host {
    fn new(config: ValidatedConfig, state_directory: Option<&Path>) -> Self {
        let home: Option<PathBuf> = std::env::var_os("HOME").map(PathBuf::from);
        let locations: ProtectedLocations =
            ProtectedLocations::resolve(home.as_deref(), state_directory);
        let principal: Uid = svalnir_agent::observe::current_uid();
        let discovery: DiscoveryHost = DiscoveryHost::manual(principal, locations.clone(), &config);
        Self {
            config,
            locations,
            discovery,
            principal,
            evidence: Arc::new(SourceEnvironment(DarwinProcessSource::new())),
        }
    }

    fn inspection_host(&self) -> InspectionHost<'_> {
        InspectionHost {
            principal: self.principal,
            locations: &self.locations,
            user_exclusions: &self.discovery.user_exclusions,
        }
    }
}

/// The configuration of an inspection: the revision in effect, when the
/// journal has one, else the built-in template. `None` when neither gives a
/// valid configuration.
fn inspection_config(state_directory: Option<&Path>) -> Option<ValidatedConfig> {
    let from_journal: Option<ValidatedConfig> = state_directory.and_then(|directory| {
        let path: PathBuf = svalnir_agent::runtime::journal_path(directory);
        let journal = svalnir_agent::observe::open_existing_journal_read_only(&path).ok()??;
        let stored =
            svalnir_agent::observe::read_authority(&journal, svalnir_agent::observe::current_uid())
                .ok()?;
        svalnir_agent::client::active_config(&journal, &stored.state)
            .ok()
            .map(|active| active.config)
    });
    from_journal.or_else(|| {
        svalnir_core::config::parse_and_validate(TEMPLATE_DOCUMENT)
            .result
            .ok()
    })
}

/// The lifecycle state of the layouts of `rule`, as one text: the state of
/// each layout when they differ.
fn lifecycle_text(rule: &Rule) -> String {
    let mut states: Vec<&'static str> = rule
        .layouts
        .iter()
        .map(|layout| lifecycle_name(&layout.lifecycle))
        .collect();
    states.dedup();
    if states.is_empty() {
        "proposed".to_owned()
    } else {
        states.join(", ")
    }
}

const fn lifecycle_name(state: &LifecycleState) -> &'static str {
    match state {
        LifecycleState::Proposed => "proposed",
        LifecycleState::InspectionValidated { .. } => "inspection_validated",
        LifecycleState::ManualActionValidated { .. } => "manual_action_validated",
        LifecycleState::AutomaticEvictionValidated { .. } => "automatic_eviction_validated",
        LifecycleState::Disabled { .. } => "disabled",
        LifecycleState::Retired => "retired",
        LifecycleState::Unrecognized => "unrecognized",
    }
}

/// Whether a layout of `rule` that an eviction removes is validated for a
/// manual eviction. The layout of the scope root of an owner operation is
/// for the `owner` mode: an eviction removes no scope root as a whole.
fn permits_evict(registry: &ReviewedRules, rule: &Rule) -> bool {
    let owner_layout: Option<&str> = registry
        .producer(rule.reference.id.as_str())
        .map(|producer| producer.spec().layout);
    rule.modes.contains(&RuleMode::ManualEviction)
        && rule.layouts.iter().any(|layout| {
            Some(layout.layout.as_str()) != owner_layout
                && layout.permits(&RuleMode::ManualEviction)
        })
}

/// Whether the layout of the scope root of `producer` is validated for a
/// manual action.
fn permits_owner(producer: &ProducerRule) -> bool {
    producer
        .layout()
        .is_some_and(|layout| layout.permits(&RuleMode::ManualEviction))
}

fn path_text(path: Option<&Path>) -> String {
    path.map_or_else(
        || "(not resolved)".to_owned(),
        |path| path.display().to_string(),
    )
}

fn cache_unit(path: &Path, measurement: &CacheMeasurement) -> UnitRow {
    UnitRow {
        path: path.display().to_string(),
        size: Some(measurement.allocated_bytes.get()),
        size_kind: match measurement.reclaim {
            ReclaimFigure::AllocatedUpperBound { .. } => SizeKind::AllocatedUpperBound,
            ReclaimFigure::NotKnownLinkedIntoProjects | ReclaimFigure::NotKnownClonedStorage => {
                SizeKind::AllocatedNotReclaim
            }
        },
        partial: measurement.partial,
        reason: None,
    }
}

fn root_outcome(outcome: RootOutcome) -> String {
    match outcome {
        RootOutcome::Examined => "examined".to_owned(),
        RootOutcome::Absent => "absent".to_owned(),
        RootOutcome::NoPath => "no path".to_owned(),
        RootOutcome::Refused(reason) => format!("refused: {reason}"),
    }
}

/// An inspection with no unit yet.
fn empty_inspection(
    rule: &Rule,
    family: RuleFamily,
    plan: Option<PlanKind>,
    permits_plan: bool,
) -> RuleInspection {
    RuleInspection {
        rule: rule.reference.id.as_str().to_owned(),
        revision: rule.reference.revision.as_str().to_owned(),
        family,
        producer: rule.owner.producer.clone(),
        lifecycle: lifecycle_text(rule),
        plan,
        permits_plan,
        needs_clear: false,
        project_options: false,
        roots: Vec::new(),
        units: Vec::new(),
        units_omitted: 0,
        owner: None,
        problem: None,
    }
}

fn push_unit(inspection: &mut RuleInspection, unit: UnitRow) {
    if inspection.units.len() < UNIT_LIMIT {
        inspection.units.push(unit);
    } else {
        inspection.units_omitted = inspection.units_omitted.saturating_add(1);
    }
}

fn add_cache(inspection: &mut RuleInspection, cache: &CacheInspection) {
    for root in &cache.roots {
        inspection.roots.push(RootRow {
            path: path_text(root.path.as_deref()),
            state: root_outcome(root.outcome),
        });
        for unit in &root.units {
            let row: UnitRow = match &unit.outcome {
                UnitOutcome::Measured(measurement) => cache_unit(&unit.path, measurement),
                UnitOutcome::Absent => continue,
                UnitOutcome::UnsupportedLayout => UnitRow {
                    path: unit.path.display().to_string(),
                    size: None,
                    size_kind: SizeKind::AllocatedUpperBound,
                    partial: false,
                    reason: Some("unsupported_layout".to_owned()),
                },
                UnitOutcome::Refused { reason } => UnitRow {
                    path: unit.path.display().to_string(),
                    size: None,
                    size_kind: SizeKind::AllocatedUpperBound,
                    partial: false,
                    reason: Some((*reason).to_owned()),
                },
            };
            push_unit(inspection, row);
        }
    }
}

/// The owner facts of an inspection.
fn owner_facts(owner: &OwnerInspection) -> OwnerFacts {
    let executable: String = owner.program.executable.as_ref().map_or_else(
        || {
            format!(
                "(no executable: {})",
                owner.program.problem.unwrap_or("executable_not_found")
            )
        },
        LosslessPath::display_label,
    );
    let mut command: Vec<String> = Vec::new();
    if let Some(interpreter) = &owner.program.interpreter {
        command.push(interpreter.display_label());
        command.extend(owner.program.interpreter_arguments.iter().cloned());
    }
    command.push(executable);
    command.extend(owner.arguments.iter().cloned());
    OwnerFacts {
        kind: owner.kind.as_str().to_owned(),
        command: command.join(" "),
        environment: owner
            .environment
            .iter()
            .map(|entry| format!("{}={}", entry.name, entry.value))
            .collect(),
        effect: owner.effect.to_owned(),
        consequence: owner.regeneration.to_owned(),
        scope: path_text(owner.scope.path.as_deref()),
    }
}

fn add_owner(inspection: &mut RuleInspection, owner: &OwnerInspection) {
    inspection.needs_clear = owner.needs_include_clear;
    inspection.owner = Some(owner_facts(owner));
    if inspection.roots.is_empty() {
        inspection.roots.push(RootRow {
            path: path_text(owner.scope.path.as_deref()),
            state: root_outcome(owner.scope.outcome),
        });
    }
    if let Some(measured) = &owner.measured {
        let (size, kind): (u64, SizeKind) =
            match (owner.whole_cache, measured.private_allocated_bytes) {
                (true, _) => (measured.allocated_bytes.get(), SizeKind::WholeCache),
                (false, Some(private)) => (private.get(), SizeKind::PrivateAllocated),
                (false, None) => (
                    measured.allocated_bytes.get(),
                    SizeKind::AllocatedUpperBound,
                ),
            };
        if inspection.units.is_empty() {
            push_unit(
                inspection,
                UnitRow {
                    path: path_text(owner.scope.path.as_deref()),
                    size: Some(size),
                    size_kind: kind,
                    partial: !measured.complete,
                    reason: None,
                },
            );
        }
    }
    if let GuardOutcome::Refused { reason, .. } = &owner.guard {
        inspection.problem = Some(format!(
            "The guard of the rule refuses the command now ({reason})."
        ));
    }
}

/// The search roots of a rule that searches the projects of the user:
/// `[cleanup.projects].search_roots` and, with `with_mise`, the project
/// roots that mise records.
fn search_roots(host: &Host, with_mise: bool) -> Result<SearchRoots, &'static str> {
    let home: &Path = host
        .locations
        .home_directory()
        .ok_or("home_directory_unavailable")?;
    let mut entries: Vec<SearchRootEntry> = host
        .config
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
    if with_mise {
        let state_home = std::env::var_os("XDG_STATE_HOME");
        let config_home = std::env::var_os("XDG_CONFIG_HOME");
        let mise: MiseLocations =
            MiseLocations::resolve(home, state_home.as_deref(), config_home.as_deref());
        entries.extend(tracked_projects(home, &mise, host.principal).entries());
    }
    let roots: SearchRoots =
        SearchRoots::with_entries(entries).map_err(|_| "too_many_search_roots")?;
    if roots.is_empty() {
        return Err("no_search_roots");
    }
    Ok(roots)
}

fn search_root_rows(reports: &[SearchRootReport]) -> Vec<RootRow> {
    reports
        .iter()
        .map(|report| RootRow {
            path: report.path.as_ref().map_or_else(
                || report.relative.display().to_string(),
                |path| path.display().to_string(),
            ),
            state: match &report.outcome {
                SearchRootOutcome::Examined(_) => "examined".to_owned(),
                SearchRootOutcome::Absent => "absent".to_owned(),
                SearchRootOutcome::Refused(reason) => format!("refused: {reason}"),
                SearchRootOutcome::Covered(reason) => format!("left out: {reason}"),
            },
        })
        .collect()
}

/// The sources of the project activity of one request.
struct ProjectSources {
    git: Result<GitTool, GitToolProblem>,
    transcripts: ClaudeTranscripts,
    agents: PaseoAgents,
    quiet_period: Nanoseconds,
}

impl ProjectSources {
    fn new(config: &ValidatedConfig, home: Option<&Path>) -> Self {
        let projects = &config.cleanup().projects;
        Self {
            git: GitTool::locate(),
            transcripts: ClaudeTranscripts::for_home(home),
            agents: PaseoAgents::new(projects.paseo_agents, home),
            quiet_period: quiet_period(projects),
        }
    }

    fn git(&self) -> Result<&GitTool, GitToolProblem> {
        self.git.as_ref().map_err(|problem| *problem)
    }

    fn recency<'a>(&'a self, head: &'a GitHeadActivity<'a>) -> RecencyHost<'a> {
        RecencyHost {
            quiet_period: self.quiet_period,
            head,
            transcripts: &self.transcripts,
            agents: &self.agents,
        }
    }
}

fn inspect_projects(
    host: &Host,
    registry: &ReviewedRules,
    cancel: &CancellationToken,
    inspection: &mut RuleInspection,
) {
    let roots: SearchRoots = match search_roots(host, true) {
        Ok(roots) => roots,
        Err(code) => {
            inspection.problem = Some(format!("{} ({code}).", super::reason_of(code)));
            return;
        }
    };
    let sources: ProjectSources =
        ProjectSources::new(&host.config, host.locations.home_directory());
    let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
    let processes: EnvironmentEvidence<'_> = EnvironmentEvidence(host.evidence.as_ref());
    let project_host: ProjectHost<'_> = ProjectHost {
        principal: host.principal,
        locations: &host.locations,
        user_exclusions: &host.discovery.user_exclusions,
        git: sources.git(),
        processes: &processes,
        recency: sources.recency(&head),
        layouts: &host.config.cleanup().projects.layouts,
    };
    let result = registry.projects().inspect(
        project_host,
        &roots,
        ProjectLimits::default(),
        cancel,
        host.evidence.as_ref(),
    );
    inspection.roots = search_root_rows(&result.roots);
    for unit in &result.units {
        let row: UnitRow = match &unit.outcome {
            ProjectUnitOutcome::Measured(measurement) => cache_unit(&unit.path, measurement),
            ProjectUnitOutcome::Refused { reason } => UnitRow {
                path: unit.path.display().to_string(),
                size: None,
                size_kind: SizeKind::AllocatedUpperBound,
                partial: false,
                reason: Some((*reason).to_owned()),
            },
            ProjectUnitOutcome::RepositoryRefused(refusal) => UnitRow {
                path: unit.path.display().to_string(),
                size: None,
                size_kind: SizeKind::AllocatedUpperBound,
                partial: false,
                reason: Some(refusal.reason.as_str().to_owned()),
            },
            ProjectUnitOutcome::Checked => continue,
        };
        push_unit(inspection, row);
    }
}

fn inspect_worktrees(
    host: &Host,
    registry: &ReviewedRules,
    cancel: &CancellationToken,
    inspection: &mut RuleInspection,
) {
    let roots: SearchRoots = match search_roots(host, false) {
        Ok(roots) => roots,
        Err(code) => {
            inspection.problem = Some(format!("{} ({code}).", super::reason_of(code)));
            return;
        }
    };
    let git: Result<GitTool, GitToolProblem> = GitTool::locate();
    let result = registry.worktrees().inspect(
        WorktreeHost {
            principal: host.principal,
            locations: &host.locations,
            user_exclusions: &host.discovery.user_exclusions,
            git: git.as_ref().map_err(|problem| *problem),
        },
        &roots,
        WorktreeLimits::default(),
        cancel,
    );
    inspection.roots = search_root_rows(&result.roots);
    for repository in &result.repositories {
        for worktree in &repository.worktrees {
            push_unit(
                inspection,
                UnitRow {
                    path: path_text(worktree.path.as_deref()),
                    size: None,
                    size_kind: SizeKind::AllocatedUpperBound,
                    partial: false,
                    reason: repository.refused.map(str::to_owned),
                },
            );
        }
    }
}

/// Inspects each rule of `registry`. Read-only.
pub(super) fn inspect_rules(
    registry: &ReviewedRules,
    state_directory: Option<&Path>,
) -> Result<CleanupSnapshot, String> {
    let config: ValidatedConfig = inspection_config(state_directory)
        .ok_or_else(|| "No valid configuration is available for the inspection.".to_owned())?;
    let host: Host = Host::new(config, state_directory);
    let cancel: CancellationToken = CancellationToken::new();
    let mut rules: Vec<RuleInspection> = Vec::new();
    // The rules that search the projects of the user.
    let projects: &Rule = registry.projects().rule();
    let mut project: RuleInspection = empty_inspection(
        projects,
        RuleFamily::Project,
        Some(PlanKind::Evict),
        permits_evict(registry, projects),
    );
    project.project_options = true;
    inspect_projects(&host, registry, &cancel, &mut project);
    rules.push(project);
    // The package and build caches, with the owner command of a producer.
    for cache in registry.caches() {
        let rule: &Rule = cache.rule();
        let producer: Option<&ProducerRule> = registry.producer(rule.reference.id.as_str());
        let (family, plan, permits): (RuleFamily, Option<PlanKind>, bool) = match producer {
            Some(producer) => (
                RuleFamily::Owner,
                Some(PlanKind::Owner),
                permits_owner(producer),
            ),
            None => (RuleFamily::Cache, None, false),
        };
        let mut inspection: RuleInspection = empty_inspection(rule, family, plan, permits);
        add_cache(
            &mut inspection,
            &cache.inspect(
                host.inspection_host(),
                InspectionLimits::default(),
                &cancel,
                host.evidence.as_ref(),
            ),
        );
        if let Some(producer) = producer {
            let owner: OwnerInspection = producer.inspect(
                &host.inspection_host(),
                MAX_PRODUCER_EXECUTABLE_BYTES,
                &cancel,
                host.evidence.as_ref(),
            );
            add_owner(&mut inspection, &owner);
        }
        rules.push(inspection);
    }
    // The producers with an owner command that are not a cache rule.
    for producer in registry.producers() {
        let id: &str = producer.rule().reference.id.as_str();
        if registry.cache(id).is_some() {
            continue;
        }
        let mut inspection: RuleInspection = empty_inspection(
            producer.rule(),
            RuleFamily::Owner,
            Some(PlanKind::Owner),
            permits_owner(producer),
        );
        let owner: OwnerInspection = producer.inspect(
            &host.inspection_host(),
            MAX_PRODUCER_EXECUTABLE_BYTES,
            &cancel,
            host.evidence.as_ref(),
        );
        add_owner(&mut inspection, &owner);
        rules.push(inspection);
    }
    // The linked Git worktrees.
    let worktrees: &Rule = registry.worktrees().rule();
    let mut worktree: RuleInspection =
        empty_inspection(worktrees, RuleFamily::Worktree, None, false);
    inspect_worktrees(&host, registry, &cancel, &mut worktree);
    rules.push(worktree);
    // The derived data of Xcode: this build has no inspection of it.
    let xcode: &Rule = registry.xcode_derived_data().rule();
    let mut derived: RuleInspection = empty_inspection(
        xcode,
        RuleFamily::Xcode,
        Some(PlanKind::Evict),
        permits_evict(registry, xcode),
    );
    derived.problem = Some(
        "This build has no inspection for this rule. A plan of the evict mode finds its units."
            .to_owned(),
    );
    rules.push(derived);
    Ok(CleanupSnapshot {
        rules,
        captured_at: SystemTime::now(),
    })
}

/// The checks of `request` that read nothing: the rule, its lifecycle
/// state, and the consent to a `clear` command. They have the order and
/// the codes of the CLI.
pub(super) fn check_request(
    registry: &ReviewedRules,
    request: &CleanupRequest,
) -> Result<(), ActionState> {
    let known: bool = registry
        .rules()
        .iter()
        .any(|rule| rule.reference.id.as_str() == request.rule);
    if !known {
        return Err(ActionState::refused("unknown_rule"));
    }
    match request.kind {
        PlanKind::Evict => {
            let rule: &Rule = registry
                .rules()
                .into_iter()
                .find(|rule| rule.reference.id.as_str() == request.rule)
                .ok_or_else(|| ActionState::refused("unknown_rule"))?;
            if !permits_evict(registry, rule) {
                return Err(ActionState::refused("rule_mode_not_validated"));
            }
        }
        PlanKind::Owner => {
            let producer: &ProducerRule = registry
                .producer(&request.rule)
                .ok_or_else(|| ActionState::refused("owner_operation_not_available"))?;
            if !permits_owner(producer) {
                return Err(ActionState::refused("rule_mode_not_validated"));
            }
            if matches!(producer.spec().kind, OwnerOperationKind::Clear)
                && !request.options.include_clear
            {
                return Err(ActionState::refused("clear_not_included"));
            }
        }
    }
    Ok(())
}

/// The inputs of the plan builder of one request.
pub(super) struct PlanInputs<'a> {
    pub(super) policy_revision: PolicyRevisionId,
    pub(super) config: ValidatedConfig,
    pub(super) clock: &'a EvaluationClock,
    pub(super) wall: WallTime,
    pub(super) state_directory: Option<&'a Path>,
}

fn plan_refusal(error: &PlanBuildError) -> ActionState {
    ActionState::refused(match error {
        PlanBuildError::Rule(_) => "rule_mode_not_validated",
        PlanBuildError::UnsupportedExecutor => "helper_not_available",
        PlanBuildError::Authority | PlanBuildError::Principal => "plan_authority_not_usable",
        PlanBuildError::Lifetime | PlanBuildError::Limits => "plan_limits_not_usable",
        _ => "plan_not_buildable",
    })
}

fn context<'a>(
    plan_text: &str,
    inputs: &'a PlanInputs<'a>,
    home: Option<&'a LosslessPath>,
) -> Result<PlanContext<'a>, ActionState> {
    let lifetime: Nanoseconds = manual_plan_lifetime(&inputs.config)
        .ok_or_else(|| plan_refusal(&PlanBuildError::Lifetime))?;
    Ok(PlanContext {
        plan_id: PlanId::new(plan_text.to_owned())
            .map_err(|_| ActionState::refused("identity_unavailable"))?,
        principal: svalnir_agent::client::principal(ClientRole::Gui),
        // A manual plan has no action grant: its authority is the approval
        // that is bound to the plan.
        authority: AuthorityBinding {
            policy_revision: inputs.policy_revision.clone(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: inputs.clock,
        created_wall: inputs.wall,
        lifetime,
        protections: inputs.config.protections(),
        home_directory: home,
    })
}

/// Makes the sealed plan of `request`, after [`check_request`] and the gate
/// of the agent. Nothing is recorded.
pub(super) fn build(
    registry: &ReviewedRules,
    request: &CleanupRequest,
    inputs: &PlanInputs<'_>,
) -> Result<CleanupProposal, ActionState> {
    let host: Host = Host::new(inputs.config.clone(), inputs.state_directory);
    let home: Option<LosslessPath> = host
        .locations
        .home_directory()
        .and_then(|home| LosslessPath::from_path(home).ok());
    let plan_text: String = svalnir_agent::client::new_id("plan");
    let context: PlanContext<'_> = context(&plan_text, inputs, home.as_ref())?;
    match request.kind {
        PlanKind::Evict => build_evict(registry, request, &host, &context, &plan_text, inputs),
        PlanKind::Owner => build_owner(registry, request, &host, &context, &plan_text, inputs),
    }
}

fn identity(plan_text: &str, kind: char, index: usize) -> String {
    format!("{plan_text}-{kind}{index:04}")
}

fn build_evict(
    registry: &ReviewedRules,
    request: &CleanupRequest,
    host: &Host,
    context: &PlanContext<'_>,
    plan_text: &str,
    inputs: &PlanInputs<'_>,
) -> Result<CleanupProposal, ActionState> {
    let rule: &Rule = registry
        .rules()
        .into_iter()
        .find(|rule| rule.reference.id.as_str() == request.rule)
        .ok_or_else(|| ActionState::refused("unknown_rule"))?;
    let cancel: CancellationToken = CancellationToken::new();
    let rules = [rule.reference.id.clone()];
    let sources: ProjectSources =
        ProjectSources::new(&host.config, host.locations.home_directory());
    let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
    let roots: Option<SearchRoots> = if request.rule == PROJECT_RULE_ID {
        Some(search_roots(host, true).map_err(ActionState::refused)?)
    } else {
        None
    };
    let projects: Option<ProjectRequest<'_>> = roots.as_ref().map(|roots| ProjectRequest {
        roots,
        git: sources.git(),
        recency: sources.recency(&head),
        layouts: &host.config.cleanup().projects.layouts,
        include_active: request.options.include_active,
        limits: ProjectLimits::default(),
    });
    let discovery: EvictionDiscovery = registry.discover_for_eviction(
        &EvictionRequest {
            host: &host.discovery,
            purpose: &RuleMode::ManualEviction,
            rules: Some(&rules),
            volumes: None,
            known: None,
            limits: DiscoveryLimits::default(),
            cancel: &cancel,
            projects: projects.as_ref(),
        },
        host.evidence.as_ref(),
    );
    // The minimum size only filters: a smaller candidate is not given to
    // the plan builder, and the confirmation names it.
    let (selected, below): (Vec<EvictionCandidate>, Vec<EvictionCandidate>) =
        discovery.candidates.iter().cloned().partition(|candidate| {
            request.options.min_size.is_none_or(|minimum| {
                candidate.discovered.measurement.estimate.bytes >= Bytes::new(minimum)
            })
        });
    let entries: Vec<CleanupEntry> = selected
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            Ok(candidate.cleanup_entry(
                TargetId::new(identity(plan_text, 't', index))
                    .map_err(|_| ActionState::refused("identity_unavailable"))?,
                StepId::new(identity(plan_text, 's', index))
                    .map_err(|_| ActionState::refused("identity_unavailable"))?,
            ))
        })
        .collect::<Result<Vec<CleanupEntry>, ActionState>>()?;
    let outcome: PlanOutcome = build_cleanup_plan(
        context,
        &PlanRequest {
            mode: ModeSelection::Evict {
                rule: registry.lookup(&rule.reference),
            },
            entries: &entries,
            preset: None,
            limits: CleanupLimits {
                plan: rule.budget.per_pass,
                batch: WorkCharge::new(
                    rule.budget.per_pass.work_bytes.max(Bytes::new(1)),
                    rule.budget.per_pass.items.max(EntryCount::new(1)),
                ),
                execution_deadline: EXECUTION_DEADLINE,
                verification_window: VERIFICATION_WINDOW,
            },
        },
    )
    .map_err(|error| plan_refusal(&error))?;
    let mut proposal: CleanupProposal =
        proposal_of(request, &outcome, &explain(&outcome, inputs.clock));
    add_discovery_notes(&mut proposal, &discovery, &below);
    Ok(proposal)
}

/// Adds to `proposal` the candidates that the minimum size leaves out, the
/// candidates whose eligibility the rule did not establish, and the
/// warnings of the discovery.
fn add_discovery_notes(
    proposal: &mut CleanupProposal,
    discovery: &EvictionDiscovery,
    below: &[EvictionCandidate],
) {
    for candidate in below.iter().take(TARGET_LIMIT) {
        proposal.omitted.push((
            candidate.candidate.candidate.path.display_label(),
            "below_minimum_size".to_owned(),
        ));
    }
    proposal.omitted_count = proposal.omitted_count.saturating_add(below.len());
    for candidate in discovery
        .candidates
        .iter()
        .filter(|candidate| !candidate.discovered.blockers.is_empty())
        .take(TARGET_LIMIT)
    {
        let reasons: Vec<String> = candidate
            .discovered
            .blockers
            .iter()
            .map(|reason| snake_name(&format!("{reason:?}")))
            .collect();
        proposal.omitted.push((
            candidate.candidate.candidate.path.display_label(),
            reasons.join(", "),
        ));
    }
    if !discovery.complete {
        proposal.warnings.push(
            "The discovery stopped at a bound, so the plan can have fewer entries than the rule finds. A later plan can take the others.".to_owned(),
        );
    }
    for root in &discovery.roots {
        if let RootResult::Refused(reason) = &root.result {
            proposal.warnings.push(format!(
                "The root {} was refused ({reason}).",
                path_text(root.path.as_deref())
            ));
        }
    }
}

fn owner_bind_refusal(error: &ProducerBindError) -> ActionState {
    match error {
        ProducerBindError::ClearNotIncluded => ActionState::refused("clear_not_included"),
        ProducerBindError::NoScope(report) => {
            if report.outcome == RootOutcome::Refused(OWNER_SCOPE_UNMARKED) {
                ActionState::refused(OWNER_SCOPE_UNMARKED)
            } else {
                ActionState::refused("owner_scope_unavailable")
            }
        }
        ProducerBindError::Guard(GuardOutcome::Refused { reason, .. }) => {
            ActionState::refused(guard_code(reason))
        }
        ProducerBindError::Guard(_) => ActionState::refused("owner_guard_refused"),
        ProducerBindError::Bind(error) => ActionState::refused(error.as_str()),
    }
}

fn build_owner(
    registry: &ReviewedRules,
    request: &CleanupRequest,
    host: &Host,
    context: &PlanContext<'_>,
    plan_text: &str,
    inputs: &PlanInputs<'_>,
) -> Result<CleanupProposal, ActionState> {
    let producer: &ProducerRule = registry
        .producer(&request.rule)
        .ok_or_else(|| ActionState::refused("owner_operation_not_available"))?;
    let bind_request = ProducerBindRequest {
        host: host.inspection_host(),
        include_clear: request.options.include_clear,
        max_executable_bytes: MAX_PRODUCER_EXECUTABLE_BYTES,
        scope_limits: ScopeLimits::default(),
    };
    let bound: ProducerBinding = producer
        .bind(&bind_request, &CancellationToken::new(), &WallScanClock)
        .map_err(|error| owner_bind_refusal(&error))?;
    let outcome: PlanOutcome = build_owner_plan(
        context,
        &OwnerPlanRequest {
            target_id: TargetId::new(identity(plan_text, 't', 0))
                .map_err(|_| ActionState::refused("identity_unavailable"))?,
            step_id: StepId::new(identity(plan_text, 's', 0))
                .map_err(|_| ActionState::refused("identity_unavailable"))?,
            binding: &bound.binding,
            rule: registry.lookup(&bound.binding.rule),
            protection: host.locations.of_text(&bound.root.binding.path),
            verification_window: VERIFICATION_WINDOW,
        },
    )
    .map_err(|error| plan_refusal(&error))?;
    let explanation: PlanExplanation = explain(&outcome, inputs.clock);
    let mut proposal: CleanupProposal = proposal_of(request, &outcome, &explanation);
    let binding = &bound.binding;
    let command: Option<String> = explanation.targets.iter().find_map(|target| match target {
        TargetExplanation::OwnerOperation {
            executable,
            arguments,
            ..
        } => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(interpreter) = &binding.interpreter {
                parts.push(interpreter.executable.path.display_label());
                parts.extend(interpreter.arguments.iter().cloned());
            }
            parts.push(executable.display_label());
            parts.extend(arguments.iter().cloned());
            Some(parts.join(" "))
        }
        _ => None,
    });
    proposal.owner = Some(OwnerFacts {
        kind: binding.operation.as_str().to_owned(),
        command: command.unwrap_or_default(),
        environment: binding
            .environment
            .iter()
            .map(|entry| format!("{}={}", entry.name, entry.value))
            .collect(),
        effect: producer.spec().effect.to_owned(),
        consequence: producer.spec().regeneration.to_owned(),
        scope: bound.root.binding.path.display().to_string(),
    });
    if producer.spec().whole_cache {
        proposal.warnings.push(
            "The measured size is of the whole cache; the producer removes only a part of it."
                .to_owned(),
        );
    }
    Ok(proposal)
}

/// The proposal of a plan outcome: the targets, the estimate, the entries
/// that the plan leaves out, and the consequence, from the explanation of
/// the plan builder.
fn proposal_of(
    request: &CleanupRequest,
    outcome: &PlanOutcome,
    explanation: &PlanExplanation,
) -> CleanupProposal {
    let plan: Option<Arc<Plan>> = outcome.plan.clone().map(Arc::new);
    let mut targets: Vec<CleanupTarget> = Vec::new();
    for target in &explanation.targets {
        let row: CleanupTarget = match target {
            TargetExplanation::File {
                path,
                relative_entry,
                estimate,
                ..
            } => CleanupTarget {
                path: path.as_ref().unwrap_or(relative_entry).display_label(),
                estimate: estimate.estimated_reclaimable_bytes.map(Bytes::get),
            },
            TargetExplanation::OwnerOperation {
                root_path,
                measured,
                ..
            } => CleanupTarget {
                path: root_path.display_label(),
                estimate: measured.private_allocated_bytes.map(Bytes::get),
            },
            TargetExplanation::Application { .. } | TargetExplanation::Process { .. } => continue,
        };
        if targets.len() < TARGET_LIMIT {
            targets.push(row);
        }
    }
    let omitted: Vec<(String, String)> = explanation
        .omitted
        .iter()
        .take(TARGET_LIMIT)
        .map(|omission| {
            (
                omission.path.as_ref().map_or_else(
                    || omission.target_id.to_string(),
                    LosslessPath::display_label,
                ),
                omission
                    .reasons
                    .iter()
                    .map(|reason| snake_name(&format!("{reason:?}")))
                    .collect::<Vec<String>>()
                    .join(", "),
            )
        })
        .collect();
    CleanupProposal {
        rule: request.rule.clone(),
        kind: request.kind,
        plan_id: plan.as_ref().map(|plan| plan.plan_id.to_string()),
        target_count: explanation.totals.targets,
        estimate: explanation
            .totals
            .estimated_reclaimable_bytes
            .map(Bytes::get),
        estimate_statement: explanation.estimate_statement.to_owned(),
        omitted_count: explanation.omitted.len(),
        omitted,
        warnings: Vec::new(),
        owner: None,
        consequence: explanation.consequence_statement.to_owned(),
        // An eviction and an owner command both remove data with no undo.
        permanent: true,
        expires_at: plan
            .as_deref()
            .map_or_else(SystemTime::now, super::live::expiry_wall),
        plan,
        targets,
    }
}
