//! `clean inspect`: the inspection of one reviewed rule, and the roots of
//! the rules that search the projects of the user.
//!
//! The command is read-only. It reads the configuration proposal, the
//! directories below the roots, the tracked-configs directory of mise, the
//! process table, and the output of the read-only Git queries of the rules.
//! It writes no file, makes no plan, and removes nothing
//! (`docs/INTERFACES.md` section 4).

use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_agent::client::cleanup::{self, MiseRequest, ProjectRoots};
use svalnir_agent::protection::ProtectedLocations;
use svalnir_agent::rules::caches::{
    CacheInspection, CacheMeasurement, InspectionHost, InspectionLimits, RootOutcome, UnitOutcome,
};
use svalnir_agent::rules::clear::{ClearRootEntry, RootSource as ClearRootSource};
use svalnir_agent::rules::producers::{MAX_PRODUCER_EXECUTABLE_BYTES, OwnerInspection};
use svalnir_agent::rules::projects::{
    ArgumentRootError, MiseDiscovery, MiseState, PROJECT_RULE_ID, ProjectInspection,
    ProjectUnitOutcome, RootKind, RootSource, SearchRootEntry, SearchRootOutcome, SearchRootReport,
    argument_root,
};
use svalnir_agent::rules::worktrees::WorktreeInspection;
use svalnir_agent::rules::{
    DiscoveryHost, EvictionDiscovery, ReviewedRules, SharedEnvironment, SkipReason,
};
use svalnir_agent::scan::{CancellationToken, PrivateBytes};
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Bytes;
use svalnir_core::rule::RuleRegistry as _;

use super::config::{self, Proposal};
use super::evict::DiscoveryView;
use super::session;
use super::{CommandFailure, Invocation};
use crate::cli::{CleanInspectArgs, ProjectRootArgs, ProposalOption};
use crate::environment::Environment;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind};
use crate::text::{human_bytes, put_line};

/// The identity of the rule of the linked Git worktrees.
const WORKTREE_RULE_ID: &str = "git.linked-worktree";

/// The error of a project option with a command or a rule that does not
/// take it.
pub(crate) fn option_not_accepted() -> ErrorBody {
    ErrorBody::new(
        "option_not_accepted",
        ErrorFamily::Request,
        ErrorStage::Arguments,
        "`--root`, `--no-mise`, `--include-active`, `--allow-unmarked`, and `--min-size` are options of `--mode evict --rule project.dependency-directory`, and `clean inspect` takes `--root` and `--no-mise` for the rules that search projects and `--allow-unmarked` for `project.dependency-directory`; the command made no change",
    )
    .with_fields(&[
        "root",
        "no_mise",
        "include_active",
        "allow_unmarked",
        "min_size",
    ])
}

/// Refuses the project options of `clean plan` for a mode or a rule that
/// does not take them.
///
/// # Errors
///
/// Returns `option_not_accepted`.
pub(crate) fn check_plan_options(arguments: &crate::cli::CleanPlanArgs) -> Result<(), ErrorBody> {
    let project_rule: bool = arguments.mode == crate::cli::CleanMode::Evict
        && arguments.rule.as_deref() == Some(PROJECT_RULE_ID);
    let project_options: bool = !arguments.projects.roots.is_empty()
        || arguments.projects.no_mise
        || arguments.include_active
        || arguments.allow_unmarked
        || arguments.min_size.is_some();
    if project_options && !project_rule {
        return Err(option_not_accepted());
    }
    Ok(())
}

fn search_root_error(error: ArgumentRootError, path: &Path) -> ErrorBody {
    ErrorBody::new(
        match error {
            ArgumentRootError::NotFound => "search_root_not_found",
            _ => "invalid_search_root",
        },
        ErrorFamily::Request,
        ErrorStage::Arguments,
        format!(
            "the root `{}` is not accepted ({}): a root is an existing directory below the home directory, and not the home directory; the command made no change",
            path.display(),
            error.as_str()
        ),
    )
    .with_fields(&["root"])
}

/// The error of a request with no root for a rule that searches projects.
pub(crate) fn no_search_roots() -> ErrorBody {
    ErrorBody::new(
        "no_search_roots",
        ErrorFamily::Request,
        ErrorStage::Arguments,
        "the rule has no root: name one with `--root PATH`, set `[cleanup.projects].search_roots`, or let mise record a project; the command made no change",
    )
    .with_fields(&["root"])
}

fn home_unknown() -> ErrorBody {
    ErrorBody::new(
        "home_directory_unavailable",
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        "the home directory of the user is not known, so no root below it can be resolved; the command made no change",
    )
}

/// The roots of a request: `[cleanup.projects].search_roots`, each
/// `--root`, and, when `with_mise` is true and `--no-mise` is not given,
/// the project roots that mise records ([`cleanup::project_roots`]).
///
/// # Errors
///
/// Returns an error for a `--root` that is not an existing directory below
/// the home directory, for too many roots, and for a home directory that is
/// not known.
pub(crate) fn project_roots(
    environment: &Environment,
    config: &ValidatedConfig,
    arguments: &ProjectRootArgs,
    locations: &ProtectedLocations,
    with_mise: bool,
) -> Result<ProjectRoots, ErrorBody> {
    let home: &Path = locations.home_directory().ok_or_else(home_unknown)?;
    let mut entries: Vec<SearchRootEntry> = Vec::with_capacity(arguments.roots.len());
    for root in &arguments.roots {
        let absolute: PathBuf = environment.resolve(root, &["root"])?;
        let relative: PathBuf =
            argument_root(&absolute, home).map_err(|error| search_root_error(error, root))?;
        entries.push(SearchRootEntry {
            relative,
            kind: RootKind::Search,
            source: RootSource::Argument,
        });
    }
    cleanup::project_roots(
        config,
        home,
        entries,
        MiseRequest {
            read: with_mise && !arguments.no_mise,
            state_home: environment.xdg_state_home.as_deref(),
            config_home: environment.xdg_config_home.as_deref(),
        },
        session::current_uid(),
    )
    .map_err(|_| {
        ErrorBody::new(
            "too_many_search_roots",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the request has more than 16 search roots or more than 256 project roots; name fewer roots or give `--no-mise`; the command made no change",
        )
        .with_fields(&["root"])
    })
}

/// The result of `clean inspect`.
#[derive(Debug, Clone, Serialize)]
struct InspectView {
    /// The rule that the command inspected.
    rule: String,
    /// `project`, `cache`, `worktree`, or `owner`. A cache rule with an
    /// owner operation is `cache` and has `owner` too.
    kind: &'static str,
    /// The read of mise, for a rule that searches projects.
    mise: Option<MiseDiscovery>,
    projects: Option<ProjectInspection>,
    cache: Option<CacheInspection>,
    worktrees: Option<WorktreeInspection>,
    /// The inspection of a clear rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    clear: Option<ClearInspectView>,
    /// The owner operation of a rule that has one: the resolved
    /// executable, the scope root, the measured size, the kind, and the
    /// exact command. The inspection runs no command.
    owner: Option<OwnerInspection>,
    note: &'static str,
}

/// The largest number of units that the inspection of a clear rule lists.
const CLEAR_UNIT_LIMIT: usize = 64;

/// One unit of a clear rule that the discovery found.
#[derive(Debug, Clone, Serialize)]
struct ClearUnitView {
    path: LosslessPath,
    allocated_bytes: u64,
    /// The private allocated bytes of the unit, or the cause that they are
    /// unavailable. The reclaim estimate of the unit uses them when they
    /// are available.
    private_allocated_bytes: PrivateBytes,
    /// The shared parts of the clone families whose members are each in
    /// the unit. Not a reclaim figure.
    complete_family_shared_bytes: PrivateBytes,
    /// The reasons that the unit is not eligible now. Empty for a unit
    /// that each check accepts.
    blockers: Vec<SkipReason>,
}

/// The inspection of a clear rule (`docs/CLEANUP_RULES.md` section 12,
/// "Clear rules").
#[derive(Debug, Clone, Serialize)]
struct ClearInspectView {
    /// Each root of the rule on this host, with its source.
    resolved_roots: Vec<ClearRootEntry>,
    /// The units that the discovery found, to 64.
    units: Vec<ClearUnitView>,
    /// The number of units that are not in `units`.
    units_omitted: usize,
    /// The sum of the allocated bytes of the units with no blocker. It is
    /// not exclusive storage.
    eligible_allocated_bytes: u64,
    /// The sum of the reclaim estimates of the units with no blocker: the
    /// private allocated bytes of a unit when they are available, and
    /// otherwise its allocated bytes.
    eligible_estimated_bytes: Bytes,
    /// The discovery of the roots, as `clean plan --mode evict` reports it.
    discovery: DiscoveryView,
    /// The data that the rule keeps.
    kept: &'static str,
    /// The consequence of a removal.
    regeneration: &'static str,
}

impl ClearInspectView {
    fn new(
        rule: &svalnir_agent::rules::clear::ClearRule,
        discovery: &EvictionDiscovery,
        resolved_roots: Vec<ClearRootEntry>,
    ) -> Self {
        let units: Vec<ClearUnitView> = discovery
            .candidates
            .iter()
            .map(|candidate| ClearUnitView {
                path: candidate.candidate.candidate.path.clone(),
                allocated_bytes: candidate.discovered.measurement.allocated_bytes.get(),
                private_allocated_bytes: candidate.discovered.measurement.private_allocated_bytes,
                complete_family_shared_bytes: candidate
                    .discovered
                    .measurement
                    .complete_family_shared_bytes,
                blockers: candidate.discovered.blockers.clone(),
            })
            .collect();
        let eligible_estimated_bytes: Bytes = Bytes::new(
            discovery
                .candidates
                .iter()
                .filter(|candidate| candidate.discovered.blockers.is_empty())
                .fold(0_u64, |sum, candidate| {
                    sum.saturating_add(candidate.discovered.measurement.estimate.bytes.get())
                }),
        );
        let eligible_allocated_bytes: u64 = units
            .iter()
            .filter(|unit| unit.blockers.is_empty())
            .fold(0_u64, |sum, unit| sum.saturating_add(unit.allocated_bytes));
        let units_omitted: usize = units.len().saturating_sub(CLEAR_UNIT_LIMIT);
        Self {
            resolved_roots,
            units: units.into_iter().take(CLEAR_UNIT_LIMIT).collect(),
            units_omitted,
            eligible_allocated_bytes,
            eligible_estimated_bytes,
            discovery: DiscoveryView::new(rule.rule().reference.clone(), discovery),
            kept: rule.spec().kept,
            regeneration: rule.spec().regeneration,
        }
    }

    fn render(&self, out: &mut String) {
        for root in &self.resolved_roots {
            let source: String = match &root.source {
                ClearRootSource::Default { pattern } => format!("default {pattern}"),
                ClearRootSource::Configuration { file } => format!("configuration {file}"),
                ClearRootSource::Location => {
                    "[[cleanup.caches.locations]] of the configuration".to_owned()
                }
            };
            match (&root.path, root.problem) {
                (Some(path), _) => {
                    put_line!(out, "  Root: {}   from {source}", path.display());
                }
                (None, problem) => put_line!(
                    out,
                    "  Root: (not resolved)   from {source}: {}",
                    problem.unwrap_or("root_not_resolved")
                ),
            }
        }
        for unit in &self.units {
            if unit.blockers.is_empty() {
                put_line!(
                    out,
                    "  Unit: {}   {} allocated, {}",
                    unit.path.display_label(),
                    human_bytes(unit.allocated_bytes),
                    private_label(
                        unit.private_allocated_bytes,
                        unit.complete_family_shared_bytes
                    )
                );
            } else {
                let reasons: Vec<String> = unit
                    .blockers
                    .iter()
                    .filter_map(|reason| {
                        serde_json::to_value(reason)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                    })
                    .collect();
                put_line!(
                    out,
                    "  Unit: {}   not eligible now: {}",
                    unit.path.display_label(),
                    reasons.join(", ")
                );
            }
        }
        if self.units_omitted > 0 {
            put_line!(out, "  ... and {} more units", self.units_omitted);
        }
        put_line!(
            out,
            "  Eligible now: {} allocated (not exclusive storage), estimate {}",
            human_bytes(self.eligible_allocated_bytes),
            human_bytes(self.eligible_estimated_bytes.get())
        );
        put_line!(out, "  Kept: {}", self.kept);
        put_line!(out, "  After a removal: {}", self.regeneration);
        self.discovery.render(out);
    }
}

const NOTE: &str = "An inspection gives no candidate and removes nothing. Each layout of this build is `proposed`.";

const CLEAR_NOTE: &str = "An inspection gives no authority and removes nothing. A clear rule is manual only: `clean plan --mode evict --include-clear` plans its units when its layout is validated. Each layout of this build is `proposed`.";

fn source_label(source: &RootSource) -> String {
    match source {
        RootSource::Caller => "caller".to_owned(),
        RootSource::Configuration => "configuration".to_owned(),
        RootSource::Argument => "--root".to_owned(),
        RootSource::Mise { config } => format!("mise {}", config.display()),
    }
}

fn outcome_label(outcome: &SearchRootOutcome) -> String {
    match outcome {
        SearchRootOutcome::Examined(completion) => serde_json::to_value(completion)
            .ok()
            .and_then(|value| value.as_str().map(|text| format!("examined: {text}")))
            .unwrap_or_else(|| "examined".to_owned()),
        SearchRootOutcome::Absent => "absent".to_owned(),
        SearchRootOutcome::Refused(reason) => format!("refused: {reason}"),
        SearchRootOutcome::Covered(reason) => format!("left out: {reason}"),
    }
}

/// The text lines of the roots of a rule that searches projects.
pub(crate) fn render_roots(out: &mut String, roots: &[SearchRootReport]) {
    for root in roots {
        let path: String = root.path.as_ref().map_or_else(
            || root.relative.display().to_string(),
            |path| path.display().to_string(),
        );
        let kind: &str = match root.kind {
            RootKind::Search => "search root",
            RootKind::Project => "project root",
        };
        put_line!(
            out,
            "  Root: {path}   {kind} from {}   {}",
            source_label(&root.source),
            outcome_label(&root.outcome)
        );
    }
}

/// The text line of the read of mise.
pub(crate) fn render_mise(out: &mut String, mise: &MiseDiscovery) {
    let state: String = match mise.state {
        MiseState::Off => "off".to_owned(),
        MiseState::Read => format!(
            "{} project roots, {} links ignored{}",
            mise.roots.len(),
            mise.ignored.len(),
            if mise.truncated { ", truncated" } else { "" }
        ),
        MiseState::Absent => "no tracked-configs directory".to_owned(),
        MiseState::Refused(reason) => format!("refused: {reason}"),
    };
    put_line!(out, "  mise: {}   {state}", mise.directory.display());
}

impl InspectView {
    fn render(&self) -> String {
        let mut out: String = String::new();
        put_line!(out, "Inspection: {}", self.rule);
        if let Some(mise) = &self.mise {
            render_mise(&mut out, mise);
        }
        if let Some(inspection) = &self.projects {
            render_roots(&mut out, &inspection.roots);
            for unit in &inspection.units {
                let outcome: String = match &unit.outcome {
                    ProjectUnitOutcome::Measured(measurement) => measured_label(measurement),
                    ProjectUnitOutcome::Refused { reason } => format!("refused: {reason}"),
                    ProjectUnitOutcome::RepositoryRefused(refusal) => {
                        format!("refused: {}", refusal.reason.as_str())
                    }
                    ProjectUnitOutcome::Checked => "checked".to_owned(),
                };
                // A unit of an unmarked layout name has no project marker.
                let allowance: String = unit
                    .marker_allowance
                    .map_or_else(String::new, |allowance| format!("   {allowance}"));
                put_line!(
                    out,
                    "  Unit: {}   {}   {outcome}{allowance}",
                    unit.path.display(),
                    unit.layout
                );
            }
        }
        if let Some(inspection) = &self.cache {
            for root in &inspection.roots {
                let path: String = root.path.as_ref().map_or_else(
                    || "(not resolved)".to_owned(),
                    |path| path.display().to_string(),
                );
                let outcome: String = match root.outcome {
                    RootOutcome::Examined => "examined".to_owned(),
                    other => serde_json::to_value(other)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                };
                put_line!(out, "  Root: {path}   {outcome}");
                for unit in &root.units {
                    let outcome: String = match &unit.outcome {
                        UnitOutcome::Measured(measurement) => measured_label(measurement),
                        UnitOutcome::Absent => "absent".to_owned(),
                        UnitOutcome::UnsupportedLayout => "unsupported_layout".to_owned(),
                        UnitOutcome::Refused { reason } => format!("refused: {reason}"),
                    };
                    put_line!(out, "    Unit: {}   {outcome}", unit.path.display());
                }
            }
            put_line!(out, "  Owner workflow: {}", inspection.owner_workflow);
        }
        if let Some(inspection) = &self.clear {
            inspection.render(&mut out);
        }
        if let Some(inspection) = &self.owner {
            render_owner(&mut out, inspection);
        }
        if let Some(inspection) = &self.worktrees {
            render_roots(&mut out, &inspection.roots);
            for repository in &inspection.repositories {
                put_line!(
                    out,
                    "  Repository: {}   {} linked worktrees",
                    repository.work_tree.display(),
                    repository.worktrees.len()
                );
            }
        }
        put_line!(out, "{}", self.note);
        out
    }
}

/// The private-size text of a unit: the private allocated bytes, or the
/// cause that they are unavailable, and the shared bytes of the complete
/// clone families when there are some.
pub(crate) fn private_label(private: PrivateBytes, family_shared: PrivateBytes) -> String {
    let text: String = match private {
        PrivateBytes::Available { bytes } => {
            format!("{} private allocated", human_bytes(bytes.get()))
        }
        PrivateBytes::Unavailable { cause } => {
            format!("private size unavailable: {}", cause.as_str())
        }
    };
    match family_shared.value().filter(|shared| shared.get() > 0) {
        Some(shared) => format!(
            "{text}, {} more shared in complete clone families (not a reclaim figure)",
            human_bytes(shared.get())
        ),
        None => text,
    }
}

/// The text of a measured unit of an inspection.
fn measured_label(measurement: &CacheMeasurement) -> String {
    format!(
        "measured, {} allocated, {}{}",
        human_bytes(measurement.allocated_bytes.get()),
        private_label(
            measurement.private_allocated_bytes,
            measurement.complete_family_shared_bytes
        ),
        if measurement.partial { ", partial" } else { "" }
    )
}

/// The text lines of the owner operation of a rule.
fn render_owner(out: &mut String, inspection: &OwnerInspection) {
    put_line!(
        out,
        "  Owner operation: {} ({}), layout {} {}",
        inspection.kind.as_str(),
        label(&inspection.bound),
        inspection.layout.layout,
        label(&inspection.layout.lifecycle)
    );
    let root: String = inspection.scope.path.as_ref().map_or_else(
        || "(not resolved)".to_owned(),
        |path| path.display().to_string(),
    );
    put_line!(
        out,
        "  Scope root: {root}   {}",
        label(&inspection.scope.outcome)
    );
    match &inspection.measured {
        Some(measured) => put_line!(
            out,
            "  Measured: {} allocated, {} entries{}{}",
            human_bytes(measured.allocated_bytes.get()),
            measured.entries.get(),
            if measured.complete {
                ""
            } else {
                ", not complete"
            },
            if inspection.whole_cache {
                "; the size is of the whole cache, and the producer removes only a part of it"
            } else {
                ""
            }
        ),
        None => out.push_str("  Measured: no measurement\n"),
    }
    match (&inspection.program.executable, inspection.program.problem) {
        (Some(executable), _) => {
            put_line!(out, "  Executable: {}", executable.display_label());
            if let Some(interpreter) = &inspection.program.interpreter {
                put_line!(
                    out,
                    "  Interpreter: {} {}",
                    interpreter.display_label(),
                    inspection.program.interpreter_arguments.join(" ")
                );
            }
        }
        (None, problem) => put_line!(
            out,
            "  Executable: none ({})",
            problem.unwrap_or("executable_not_found")
        ),
    }
    put_line!(out, "  Command: {}", inspection.arguments.join(" "));
    for entry in &inspection.environment {
        put_line!(out, "  Env: {}={}", entry.name, entry.value);
    }
    put_line!(out, "  Guard: {}", label(&inspection.guard));
    put_line!(out, "  Effect: {}", inspection.effect);
    put_line!(out, "  Consequence: {}", inspection.regeneration);
    put_line!(out, "  Bound: {}", inspection.bound_reason);
    put_line!(out, "  Root lookup: {}", inspection.lookup);
    if inspection.needs_include_clear {
        out.push_str("  A plan of this rule needs `--include-clear`.\n");
    }
}

/// The short label of a serialized value: its text, or the text of its
/// `kind` field with its `reason` field.
fn label<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(serde_json::Value::Object(map)) => {
            let kind: &str = map
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match map.get("reason").and_then(serde_json::Value::as_str) {
                Some(reason) => format!("{kind}: {reason}"),
                None => kind.to_owned(),
            }
        }
        _ => String::new(),
    }
}

/// Refuses `--root`, `--no-mise`, and `--allow-unmarked` for a rule that
/// does not search projects.
fn no_project_roots(arguments: &CleanInspectArgs) -> Result<(), ErrorBody> {
    if !arguments.projects.roots.is_empty()
        || arguments.projects.no_mise
        || arguments.allow_unmarked
    {
        return Err(option_not_accepted());
    }
    Ok(())
}

impl InspectView {
    /// The view of the inspection of a clear rule.
    fn set_clear(&mut self, clear: ClearInspectView) {
        self.kind = "clear";
        self.clear = Some(clear);
        self.note = CLEAR_NOTE;
    }
}

/// The configuration of the command: the proposal of the user, or the
/// built-in template when the default file does not exist.
fn proposal_config(environment: &Environment) -> Result<ValidatedConfig, ErrorBody> {
    let proposal: Proposal = config::load(environment, &ProposalOption { config: None }, true)?;
    config::validated(&proposal)
}

/// The inputs of one inspection.
struct InspectContext<'a> {
    environment: &'a Environment,
    registry: &'a ReviewedRules,
    config: &'a ValidatedConfig,
    locations: &'a ProtectedLocations,
    host: &'a DiscoveryHost,
    evidence: &'a SharedEnvironment,
    cancel: &'a CancellationToken,
}

impl InspectContext<'_> {
    /// The inspection of `project.dependency-directory` and the read of
    /// mise.
    fn projects(
        &self,
        arguments: &ProjectRootArgs,
        allow_unmarked: bool,
    ) -> Result<(ProjectInspection, MiseDiscovery), ErrorBody> {
        let roots: ProjectRoots = project_roots(
            self.environment,
            self.config,
            arguments,
            self.locations,
            true,
        )?;
        if roots.roots.is_empty() {
            return Err(no_search_roots());
        }
        let inspection: ProjectInspection = cleanup::inspect_projects(
            self.registry,
            self.host,
            self.config,
            &roots.roots,
            allow_unmarked,
            self.evidence.as_ref(),
            self.cancel,
        );
        Ok((inspection, roots.mise))
    }

    /// The inspection of the clear rule `rule`: the discovery of its roots,
    /// whatever its lifecycle state, with no consent and no plan.
    fn clear(&self, rule: &str) -> Result<ClearInspectView, ErrorBody> {
        let found = self.registry.clear_rule(rule).zip(cleanup::inspect_clear(
            self.registry,
            rule,
            self.host,
            self.evidence.as_ref(),
            self.cancel,
        ));
        let Some((clear, (discovery, roots))) = found else {
            return Err(rule_error(
                "inspection_not_available",
                "this build has no inspection for this clear rule; the command made no change",
            ));
        };
        Ok(ClearInspectView::new(clear, &discovery, roots))
    }

    /// The inspection of `git.linked-worktree`. The rule has search roots
    /// only: a project root of mise is not walked for it, and it takes no
    /// `--allow-unmarked`.
    fn worktrees(&self, arguments: &CleanInspectArgs) -> Result<WorktreeInspection, ErrorBody> {
        if arguments.allow_unmarked {
            return Err(option_not_accepted());
        }
        let roots: ProjectRoots = project_roots(
            self.environment,
            self.config,
            &arguments.projects,
            self.locations,
            false,
        )?;
        if roots.roots.is_empty() {
            return Err(no_search_roots());
        }
        Ok(cleanup::inspect_worktrees(
            self.registry,
            self.host,
            &roots.roots,
            self.cancel,
        ))
    }
}

fn rule_error(code: &'static str, message: &'static str) -> ErrorBody {
    ErrorBody::new(code, ErrorFamily::Request, ErrorStage::Arguments, message)
        .with_fields(&["rule"])
}

pub(crate) fn inspect(
    arguments: &CleanInspectArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let environment: &Environment = invocation.environment;
    let registry: ReviewedRules = environment.seams.rule_registry().map_err(|_| {
        ErrorBody::new(
            "rule_registry_unavailable",
            ErrorFamily::Native,
            ErrorStage::Dispatch,
            "the rule registry of this build is not usable; the command made no change",
        )
    })?;
    let rule: &str = arguments.rule.as_str();
    let config: ValidatedConfig = proposal_config(environment)?;
    let locations: ProtectedLocations = ProtectedLocations::resolve(
        environment.home.as_deref(),
        environment.state_directory().ok().as_deref(),
    );
    let principal: Uid = session::current_uid();
    let host: DiscoveryHost = DiscoveryHost::automatic(principal, locations.clone(), &config);
    let cancel: CancellationToken = CancellationToken::new();
    let evidence: SharedEnvironment = environment.seams.discovery_environment();
    let context: InspectContext<'_> = InspectContext {
        environment,
        registry: &registry,
        config: &config,
        locations: &locations,
        host: &host,
        evidence: &evidence,
        cancel: &cancel,
    };
    let mut view: InspectView = InspectView {
        rule: rule.to_owned(),
        kind: "project",
        mise: None,
        projects: None,
        cache: None,
        worktrees: None,
        clear: None,
        owner: None,
        note: NOTE,
    };
    let owner_host: InspectionHost<'_> = InspectionHost {
        principal,
        locations: &locations,
        user_exclusions: &host.user_exclusions,
        cache_locations: &host.cache_locations,
    };
    let owner: Option<OwnerInspection> = registry.producer(rule).map(|producer| {
        producer.inspect(
            &owner_host,
            MAX_PRODUCER_EXECUTABLE_BYTES,
            &cancel,
            evidence.as_ref(),
        )
    });
    if rule == PROJECT_RULE_ID {
        let (inspection, mise) = context.projects(&arguments.projects, arguments.allow_unmarked)?;
        view.projects = Some(inspection);
        view.mise = Some(mise);
    } else if rule == WORKTREE_RULE_ID {
        view.kind = "worktree";
        view.worktrees = Some(context.worktrees(arguments)?);
    } else if let Some(cache) = registry.cache(rule) {
        no_project_roots(arguments)?;
        view.kind = "cache";
        view.cache = Some(cache.inspect(
            owner_host,
            InspectionLimits::default(),
            &cancel,
            evidence.as_ref(),
        ));
        view.owner = owner;
    } else if let Some(owner) = owner {
        no_project_roots(arguments)?;
        view.kind = "owner";
        view.owner = Some(owner);
    } else if registry.clear_rule(rule).is_some() {
        no_project_roots(arguments)?;
        view.set_clear(context.clear(rule)?);
    } else if registry
        .rules()
        .iter()
        .any(|known| known.reference.id.as_str() == rule)
    {
        return Err(rule_error(
            "inspection_not_available",
            "this build has no `clean inspect` for this rule: it inspects `project.dependency-directory`, `git.linked-worktree`, the six cache rules, each rule with an owner operation, and the clear rules; the command made no change",
        )
        .into());
    } else {
        return Err(rule_error(
            "unknown_rule",
            "the rule registry of this build has no rule with this ID; the command made no change",
        )
        .into());
    }
    invocation.emit(Kind::Report, &view, InspectView::render)?;
    Ok(ExitStatus::Success)
}
