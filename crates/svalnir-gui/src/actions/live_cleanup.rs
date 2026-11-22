//! The live path of the cleanup rules: the view of the inspection of each
//! rule and of the sealed plan of one rule.
//!
//! The rule checks, the discoveries, the inspections, and the plan builder
//! calls are the shared ones of `svalnir_agent::client::cleanup`, which
//! `svalnir clean inspect` and `svalnir clean plan --mode evict|owner` also
//! call; this module only turns their results into the rows of the window.
//!
//! The inspection is read-only. The plan is made in this process and is
//! not recorded: the window records it and writes its apply request to the
//! queue only after the confirmation ([`super::live::LivePort`]). The
//! model calls these functions on a background thread only.

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
    client::cleanup::{
        self, EvictDiscovery, ManualPlanError, ManualPlanInputs, MiseRequest, ProjectRoots,
        RuleSelectionError,
    },
    platform::process::DarwinProcessSource,
    protection::ProtectedLocations,
    rules::{
        DiscoveryHost, EvictionCandidate, EvictionDiscovery, ReviewedRules, RootResult,
        SharedEnvironment, SourceEnvironment, XCODE_ORPHAN_LAYOUT,
        caches::{
            CacheInspection, CacheMeasurement, InspectionLimits, ReclaimFigure, RootOutcome,
            UnitOutcome,
        },
        clear::{ClearRootEntry, ClearRule, RootSource as ClearRootSource},
        producers::{
            GuardOutcome, MAX_PRODUCER_EXECUTABLE_BYTES, OWNER_SCOPE_UNMARKED, OwnerInspection,
            ProducerBindError, ProducerBinding, ProducerRule, guard_code,
        },
        projects::{PROJECT_RULE_ID, ProjectUnitOutcome, SearchRootOutcome, SearchRootReport},
    },
    scan::{CancellationToken, WallScanClock},
};
use svalnir_core::{
    action::{ClientRole, Plan},
    config::ValidatedConfig,
    file::LosslessPath,
    id::PolicyRevisionId,
    plan::{
        CleanupEntry, PlanBuildError, PlanExplanation, PlanOutcome, TargetExplanation, explain,
    },
    policy::EvaluationClock,
    process::Uid,
    quantity::Bytes,
    rule::{LifecycleState, Rule},
    time::WallTime,
};

/// The text of the configuration template: a document with no key other
/// than the schema version, so each value comes from the template.
const TEMPLATE_DOCUMENT: &str = "schema_version = 1\n";

/// The inputs that each inspection and each plan read.
struct Host {
    config: ValidatedConfig,
    locations: ProtectedLocations,
    principal: Uid,
    evidence: SharedEnvironment,
}

impl Host {
    fn new(config: ValidatedConfig, state_directory: Option<&Path>) -> Self {
        let home: Option<PathBuf> = std::env::var_os("HOME").map(PathBuf::from);
        Self {
            config,
            locations: ProtectedLocations::resolve(home.as_deref(), state_directory),
            principal: svalnir_agent::observe::current_uid(),
            evidence: Arc::new(SourceEnvironment(DarwinProcessSource::new())),
        }
    }

    /// The host of an inspection, as `clean inspect` makes it.
    fn inspection(&self) -> DiscoveryHost {
        DiscoveryHost::automatic(self.principal, self.locations.clone(), &self.config)
    }

    /// The host of a manual plan, as `clean plan` makes it.
    fn manual(&self) -> DiscoveryHost {
        DiscoveryHost::manual(self.principal, self.locations.clone(), &self.config)
    }

    /// The roots of a rule that searches projects: the configuration and,
    /// with `with_mise`, the project roots that mise records.
    fn project_roots(&self, with_mise: bool) -> Result<ProjectRoots, &'static str> {
        let home: &Path = self
            .locations
            .home_directory()
            .ok_or("home_directory_unavailable")?;
        let state_home = std::env::var_os("XDG_STATE_HOME");
        let config_home = std::env::var_os("XDG_CONFIG_HOME");
        let roots: ProjectRoots = cleanup::project_roots(
            &self.config,
            home,
            Vec::new(),
            MiseRequest {
                read: with_mise,
                state_home: state_home.as_deref(),
                config_home: config_home.as_deref(),
            },
            self.principal,
        )
        .map_err(|_| "too_many_search_roots")?;
        if roots.roots.is_empty() {
            return Err("no_search_roots");
        }
        Ok(roots)
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

fn refused_unit(path: &Path, reason: &str) -> UnitRow {
    UnitRow {
        path: path.display().to_string(),
        size: None,
        size_kind: SizeKind::AllocatedUpperBound,
        partial: false,
        reason: Some(reason.to_owned()),
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
        layouts: rule
            .layouts
            .iter()
            .map(|layout| {
                (
                    layout.layout.clone(),
                    lifecycle_name(&layout.lifecycle).to_owned(),
                )
            })
            .collect(),
        plan,
        permits_plan,
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
                UnitOutcome::UnsupportedLayout => refused_unit(&unit.path, "unsupported_layout"),
                UnitOutcome::Refused { reason } => refused_unit(&unit.path, reason),
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
    if let Some(measured) = &owner.measured
        && inspection.units.is_empty()
    {
        let (size, kind): (u64, SizeKind) =
            match (owner.whole_cache, measured.private_allocated_bytes) {
                (true, _) => (measured.allocated_bytes.get(), SizeKind::WholeCache),
                (false, Some(private)) => (private.get(), SizeKind::PrivateAllocated),
                (false, None) => (
                    measured.allocated_bytes.get(),
                    SizeKind::AllocatedUpperBound,
                ),
            };
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
    if let GuardOutcome::Refused { reason, .. } = &owner.guard {
        inspection.problem = Some(format!(
            "The guard of the rule refuses the command now ({reason})."
        ));
    }
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

fn blocker_names(candidate: &EvictionCandidate) -> Option<String> {
    let reasons: Vec<String> = candidate
        .discovered
        .blockers
        .iter()
        .map(|reason| snake_name(&format!("{reason:?}")))
        .collect();
    (!reasons.is_empty()).then(|| reasons.join(", "))
}

fn inspect_projects(
    host: &Host,
    registry: &ReviewedRules,
    cancel: &CancellationToken,
    inspection: &mut RuleInspection,
) {
    let roots: ProjectRoots = match host.project_roots(true) {
        Ok(roots) => roots,
        Err(code) => {
            inspection.problem = Some(format!("{} ({code}).", super::reason_of(code)));
            return;
        }
    };
    let result = cleanup::inspect_projects(
        registry,
        &host.inspection(),
        &host.config,
        &roots.roots,
        host.evidence.as_ref(),
        cancel,
    );
    inspection.roots = search_root_rows(&result.roots);
    for unit in &result.units {
        let row: UnitRow = match &unit.outcome {
            ProjectUnitOutcome::Measured(measurement) => cache_unit(&unit.path, measurement),
            ProjectUnitOutcome::Refused { reason } => refused_unit(&unit.path, reason),
            ProjectUnitOutcome::RepositoryRefused(refusal) => {
                refused_unit(&unit.path, refusal.reason.as_str())
            }
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
    let roots: ProjectRoots = match host.project_roots(false) {
        Ok(roots) => roots,
        Err(code) => {
            inspection.problem = Some(format!("{} ({code}).", super::reason_of(code)));
            return;
        }
    };
    let result = cleanup::inspect_worktrees(registry, &host.inspection(), &roots.roots, cancel);
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

fn clear_root_row(root: &ClearRootEntry) -> RootRow {
    let source: String = match &root.source {
        ClearRootSource::Default { pattern } => format!("default {pattern}"),
        ClearRootSource::Configuration { file } => format!("configuration {file}"),
    };
    match (&root.path, root.problem) {
        (Some(path), _) => RootRow {
            path: path.display().to_string(),
            state: format!("from {source}"),
        },
        (None, problem) => RootRow {
            path: "(not resolved)".to_owned(),
            state: format!("from {source}: {}", problem.unwrap_or("root_not_resolved")),
        },
    }
}

fn inspect_clear(
    host: &Host,
    registry: &ReviewedRules,
    clear: &ClearRule,
    cancel: &CancellationToken,
) -> RuleInspection {
    let rule: &Rule = clear.rule();
    let mut inspection: RuleInspection = empty_inspection(
        rule,
        RuleFamily::Clear,
        Some(PlanKind::Evict),
        cleanup::permits_evict(registry, rule),
    );
    inspection.needs_clear = true;
    inspection.notes = vec![
        format!("Kept: {}", clear.spec().kept),
        format!("After a removal: {}", clear.spec().regeneration),
    ];
    let id: &str = rule.reference.id.as_str();
    let Some((discovery, roots)) = cleanup::inspect_clear(
        registry,
        id,
        &host.inspection(),
        host.evidence.as_ref(),
        cancel,
    ) else {
        inspection.problem = Some("This build has no inspection for this clear rule.".to_owned());
        return inspection;
    };
    inspection.roots = roots.iter().map(clear_root_row).collect();
    for candidate in &discovery.candidates {
        push_unit(
            &mut inspection,
            UnitRow {
                path: candidate.candidate.candidate.path.display_label(),
                size: Some(candidate.discovered.measurement.allocated_bytes.get()),
                size_kind: SizeKind::AllocatedUpperBound,
                partial: false,
                reason: blocker_names(candidate),
            },
        );
    }
    if !discovery.complete {
        inspection.problem =
            Some("The discovery stopped at a bound, so the list is not complete.".to_owned());
    }
    inspection
}

/// Inspects each rule of `registry`. Read-only.
///
/// # Errors
///
/// Returns the reason when no configuration is available.
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
        cleanup::permits_evict(registry, projects),
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
                cleanup::permits_owner(producer),
            ),
            None => (RuleFamily::Cache, None, false),
        };
        let mut inspection: RuleInspection = empty_inspection(rule, family, plan, permits);
        let inspection_host = host.inspection();
        add_cache(
            &mut inspection,
            &cache.inspect(
                svalnir_agent::rules::caches::InspectionHost {
                    principal: host.principal,
                    locations: &host.locations,
                    user_exclusions: &inspection_host.user_exclusions,
                },
                InspectionLimits::default(),
                &cancel,
                host.evidence.as_ref(),
            ),
        );
        if let Some(producer) = producer {
            add_owner(&mut inspection, &owner_inspection(&host, producer, &cancel));
        }
        rules.push(inspection);
    }
    // The producers with an owner command that are not a cache rule.
    for producer in registry.producers() {
        if registry
            .cache(producer.rule().reference.id.as_str())
            .is_some()
        {
            continue;
        }
        let mut inspection: RuleInspection = empty_inspection(
            producer.rule(),
            RuleFamily::Owner,
            Some(PlanKind::Owner),
            cleanup::permits_owner(producer),
        );
        add_owner(&mut inspection, &owner_inspection(&host, producer, &cancel));
        rules.push(inspection);
    }
    // The clear rules: manual only, and each plan needs the consent.
    for clear in registry.clear().all() {
        rules.push(inspect_clear(&host, registry, clear, &cancel));
    }
    // The linked Git worktrees.
    let worktrees: &Rule = registry.worktrees().rule();
    let mut worktree: RuleInspection =
        empty_inspection(worktrees, RuleFamily::Worktree, None, false);
    inspect_worktrees(&host, registry, &cancel, &mut worktree);
    rules.push(worktree);
    // The derived data of Xcode: this build has no inspection of it. Its
    // orphan layout is for a manual eviction only.
    let xcode: &Rule = registry.xcode_derived_data().rule();
    let mut derived: RuleInspection = empty_inspection(
        xcode,
        RuleFamily::Xcode,
        Some(PlanKind::Evict),
        cleanup::permits_evict(registry, xcode),
    );
    derived.notes = vec![format!(
        "The layout {XCODE_ORPHAN_LAYOUT} is the project directory whose project is gone; it is for a manual eviction only."
    )];
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

fn owner_inspection(
    host: &Host,
    producer: &ProducerRule,
    cancel: &CancellationToken,
) -> OwnerInspection {
    let inspection_host = host.inspection();
    producer.inspect(
        &svalnir_agent::rules::caches::InspectionHost {
            principal: host.principal,
            locations: &host.locations,
            user_exclusions: &inspection_host.user_exclusions,
        },
        MAX_PRODUCER_EXECUTABLE_BYTES,
        cancel,
        host.evidence.as_ref(),
    )
}

/// The checks of `request` that read nothing: the rule, its lifecycle
/// state, and the consent to a clear, with the shared checks and the codes
/// of the CLI.
///
/// # Errors
///
/// Returns the refusal with its code.
pub(super) fn check_request(
    registry: &ReviewedRules,
    request: &CleanupRequest,
) -> Result<(), ActionState> {
    let include_clear: bool = request.options.include_clear;
    let checked: Result<(), RuleSelectionError> = match request.kind {
        PlanKind::Evict => cleanup::evict_rule(registry, &request.rule, include_clear).map(drop),
        PlanKind::Owner => cleanup::owner_rule(registry, &request.rule, include_clear).map(drop),
    };
    checked.map_err(|error| ActionState::refused(error.code()))
}

/// The inputs of the plan builder of one request.
pub(super) struct PlanInputs<'a> {
    pub(super) policy_revision: PolicyRevisionId,
    pub(super) config: ValidatedConfig,
    pub(super) clock: &'a EvaluationClock,
    pub(super) wall: WallTime,
    pub(super) state_directory: Option<&'a Path>,
}

fn plan_refusal(error: &ManualPlanError) -> ActionState {
    ActionState::refused(match error {
        ManualPlanError::Identity => "identity_unavailable",
        ManualPlanError::Build(PlanBuildError::Rule(_)) => "rule_mode_not_validated",
        ManualPlanError::Build(PlanBuildError::UnsupportedExecutor) => "helper_not_available",
        ManualPlanError::Build(PlanBuildError::Authority | PlanBuildError::Principal) => {
            "plan_authority_not_usable"
        }
        ManualPlanError::Build(PlanBuildError::Lifetime | PlanBuildError::Limits) => {
            "plan_limits_not_usable"
        }
        ManualPlanError::Build(_) => "plan_not_buildable",
    })
}

/// Makes the sealed plan of `request`, after [`check_request`] and the gate
/// of the agent. Nothing is recorded.
///
/// # Errors
///
/// Returns the refusal with its code.
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
    let principal = svalnir_agent::client::principal(ClientRole::Gui);
    let plan_inputs = ManualPlanInputs {
        plan_text: &plan_text,
        principal: &principal,
        policy_revision: &inputs.policy_revision,
        config: &inputs.config,
        clock: inputs.clock,
        created_wall: inputs.wall,
        home_directory: home.as_ref(),
    };
    let mut proposal: CleanupProposal = match request.kind {
        PlanKind::Evict => build_evict(registry, request, &host, &plan_inputs)?,
        PlanKind::Owner => build_owner(registry, request, &host, &plan_inputs)?,
    };
    proposal.clear = cleanup::needs_clear_consent(registry, &request.rule);
    Ok(proposal)
}

fn build_evict(
    registry: &ReviewedRules,
    request: &CleanupRequest,
    host: &Host,
    inputs: &ManualPlanInputs<'_>,
) -> Result<CleanupProposal, ActionState> {
    let rule: &Rule = cleanup::evict_rule(registry, &request.rule, request.options.include_clear)
        .map_err(|error| ActionState::refused(error.code()))?;
    let roots: Option<ProjectRoots> = if request.rule == PROJECT_RULE_ID {
        Some(host.project_roots(true).map_err(ActionState::refused)?)
    } else {
        None
    };
    let discovery: EvictionDiscovery = cleanup::discover_for_manual_eviction(
        registry,
        rule,
        &host.manual(),
        host.evidence.as_ref(),
        &EvictDiscovery {
            config: &host.config,
            roots: roots.as_ref().map(|roots| &roots.roots),
            include_active: request.options.include_active,
        },
        &CancellationToken::new(),
    );
    let (selected, below): (Vec<EvictionCandidate>, Vec<EvictionCandidate>) =
        cleanup::split_min_size(
            &discovery.candidates,
            request.options.min_size.map(Bytes::new),
        );
    let entries: Vec<CleanupEntry> =
        cleanup::eviction_entries(&selected, inputs).map_err(|error| plan_refusal(&error))?;
    let outcome: PlanOutcome = cleanup::build_eviction_plan(registry, rule, &entries, None, inputs)
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
        proposal.omitted.push((
            candidate.candidate.candidate.path.display_label(),
            blocker_names(candidate).unwrap_or_default(),
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
    inputs: &ManualPlanInputs<'_>,
) -> Result<CleanupProposal, ActionState> {
    let producer: &ProducerRule =
        cleanup::owner_rule(registry, &request.rule, request.options.include_clear)
            .map_err(|error| ActionState::refused(error.code()))?;
    let manual: DiscoveryHost = host.manual();
    let bind_request = cleanup::owner_bind_request(
        host.principal,
        &host.locations,
        &manual.user_exclusions,
        request.options.include_clear,
    );
    let bound: ProducerBinding = producer
        .bind(&bind_request, &CancellationToken::new(), &WallScanClock)
        .map_err(|error| owner_bind_refusal(&error))?;
    let outcome: PlanOutcome =
        cleanup::build_owner_operation_plan(registry, &bound, &host.locations, inputs)
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
        clear: false,
        expires_at: plan
            .as_deref()
            .map_or_else(SystemTime::now, super::live::expiry_wall),
        plan,
        targets,
    }
}
