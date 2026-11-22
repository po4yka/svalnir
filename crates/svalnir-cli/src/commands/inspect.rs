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
use svalnir_agent::protection::ProtectedLocations;
use svalnir_agent::rules::caches::{
    CacheInspection, InspectionHost, InspectionLimits, RootOutcome, UnitOutcome,
};
use svalnir_agent::rules::git::{GitTool, GitToolProblem};
use svalnir_agent::rules::projects::{
    ArgumentRootError, ClaudeTranscripts, EnvironmentEvidence, GitHeadActivity, MiseDiscovery,
    MiseLocations, MiseState, PROJECT_RULE_ID, PaseoAgents, ProjectHost, ProjectInspection,
    ProjectLimits, ProjectUnitOutcome, RecencyHost, RootKind, RootSource, SearchRootEntry,
    SearchRootOutcome, SearchRootReport, SearchRoots, argument_root, quiet_period,
    tracked_projects,
};
use svalnir_agent::rules::worktrees::{WorktreeHost, WorktreeInspection, WorktreeLimits};
use svalnir_agent::rules::{DiscoveryHost, ReviewedRules, SharedEnvironment};
use svalnir_agent::scan::CancellationToken;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::process::Uid;
use svalnir_core::rule::RuleRegistry as _;

use super::config::{self, Proposal};
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
        "`--root`, `--no-mise`, `--include-active`, and `--min-size` are options of `--mode evict --rule project.dependency-directory`, and `clean inspect` takes `--root` and `--no-mise` for the rules that search projects; the command made no change",
    )
    .with_fields(&["root", "no_mise", "include_active", "min_size"])
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

/// The roots of one request of a rule that searches projects, and the
/// result of the read of mise.
#[derive(Debug, Clone)]
pub(crate) struct ProjectRoots {
    pub(crate) roots: SearchRoots,
    pub(crate) mise: MiseDiscovery,
}

/// The roots of a request: `[cleanup.projects].search_roots`, each
/// `--root`, and, when `with_mise` is true and `--no-mise` is not given,
/// the project roots that mise records.
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
    let mise_locations: MiseLocations = MiseLocations::resolve(
        home,
        environment.xdg_state_home.as_deref(),
        environment.xdg_config_home.as_deref(),
    );
    let mise: MiseDiscovery = if with_mise && !arguments.no_mise {
        tracked_projects(home, &mise_locations, session::current_uid())
    } else {
        MiseDiscovery::off(&mise_locations)
    };
    entries.extend(mise.entries());
    let roots: SearchRoots = SearchRoots::with_entries(entries).map_err(|_| {
        ErrorBody::new(
            "too_many_search_roots",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the request has more than 16 search roots or more than 256 project roots; name fewer roots or give `--no-mise`; the command made no change",
        )
        .with_fields(&["root"])
    })?;
    Ok(ProjectRoots { roots, mise })
}

/// The sources of the project activity of one command.
pub(crate) struct ProjectSources {
    pub(crate) git: Result<GitTool, GitToolProblem>,
    transcripts: ClaudeTranscripts,
    agents: PaseoAgents,
    quiet_period: svalnir_core::quantity::Nanoseconds,
}

impl ProjectSources {
    pub(crate) fn new(config: &ValidatedConfig, home: Option<&Path>) -> Self {
        let projects = &config.cleanup().projects;
        Self {
            git: GitTool::locate(),
            transcripts: ClaudeTranscripts::for_home(home),
            agents: PaseoAgents::new(projects.paseo_agents, home),
            quiet_period: quiet_period(projects),
        }
    }

    pub(crate) fn git(&self) -> Result<&GitTool, GitToolProblem> {
        self.git.as_ref().map_err(|problem| *problem)
    }

    pub(crate) fn recency<'a>(&'a self, head: &'a GitHeadActivity<'a>) -> RecencyHost<'a> {
        RecencyHost {
            quiet_period: self.quiet_period,
            head,
            transcripts: &self.transcripts,
            agents: &self.agents,
        }
    }
}

/// The result of `clean inspect`.
#[derive(Debug, Clone, Serialize)]
struct InspectView {
    /// The rule that the command inspected.
    rule: String,
    /// `project`, `cache`, or `worktree`.
    kind: &'static str,
    /// The read of mise, for a rule that searches projects.
    mise: Option<MiseDiscovery>,
    projects: Option<ProjectInspection>,
    cache: Option<CacheInspection>,
    worktrees: Option<WorktreeInspection>,
    note: &'static str,
}

const NOTE: &str = "An inspection gives no candidate and removes nothing. Each layout of this build is `proposed`.";

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
                    ProjectUnitOutcome::Measured(measurement) => {
                        format!(
                            "measured, {} allocated",
                            human_bytes(measurement.allocated_bytes.get())
                        )
                    }
                    ProjectUnitOutcome::Refused { reason } => format!("refused: {reason}"),
                    ProjectUnitOutcome::RepositoryRefused(refusal) => {
                        format!("refused: {}", refusal.reason.as_str())
                    }
                    ProjectUnitOutcome::Checked => "checked".to_owned(),
                };
                put_line!(
                    out,
                    "  Unit: {}   {}   {outcome}",
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
                        UnitOutcome::Measured(measurement) => format!(
                            "measured, {} allocated",
                            human_bytes(measurement.allocated_bytes.get())
                        ),
                        UnitOutcome::Absent => "absent".to_owned(),
                        UnitOutcome::UnsupportedLayout => "unsupported_layout".to_owned(),
                        UnitOutcome::Refused { reason } => format!("refused: {reason}"),
                    };
                    put_line!(out, "    Unit: {}   {outcome}", unit.path.display());
                }
            }
            put_line!(out, "  Owner workflow: {}", inspection.owner_workflow);
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
        let sources: ProjectSources =
            ProjectSources::new(self.config, self.locations.home_directory());
        let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
        let processes: EnvironmentEvidence<'_> = EnvironmentEvidence(self.evidence.as_ref());
        let host: ProjectHost<'_> = ProjectHost {
            principal: self.host.principal,
            locations: self.locations,
            user_exclusions: &self.host.user_exclusions,
            git: sources.git(),
            processes: &processes,
            recency: sources.recency(&head),
            layouts: &self.config.cleanup().projects.layouts,
        };
        let inspection: ProjectInspection = self.registry.projects().inspect(
            host,
            &roots.roots,
            ProjectLimits::default(),
            self.cancel,
            self.evidence.as_ref(),
        );
        Ok((inspection, roots.mise))
    }

    /// The inspection of `git.linked-worktree`. The rule has search roots
    /// only: a project root of mise is not walked for it.
    fn worktrees(&self, arguments: &ProjectRootArgs) -> Result<WorktreeInspection, ErrorBody> {
        let roots: ProjectRoots = project_roots(
            self.environment,
            self.config,
            arguments,
            self.locations,
            false,
        )?;
        if roots.roots.is_empty() {
            return Err(no_search_roots());
        }
        let git: Result<GitTool, GitToolProblem> = GitTool::locate();
        Ok(self.registry.worktrees().inspect(
            WorktreeHost {
                principal: self.host.principal,
                locations: self.locations,
                user_exclusions: &self.host.user_exclusions,
                git: git.as_ref().map_err(|problem| *problem),
            },
            &roots.roots,
            WorktreeLimits::default(),
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
        note: NOTE,
    };
    if rule == PROJECT_RULE_ID {
        let (inspection, mise) = context.projects(&arguments.projects)?;
        view.projects = Some(inspection);
        view.mise = Some(mise);
    } else if rule == WORKTREE_RULE_ID {
        view.kind = "worktree";
        view.worktrees = Some(context.worktrees(&arguments.projects)?);
    } else if let Some(cache) = registry.cache(rule) {
        if !arguments.projects.roots.is_empty() || arguments.projects.no_mise {
            return Err(option_not_accepted().into());
        }
        view.kind = "cache";
        view.cache = Some(cache.inspect(
            InspectionHost {
                principal,
                locations: &locations,
                user_exclusions: &host.user_exclusions,
            },
            InspectionLimits::default(),
            &cancel,
            evidence.as_ref(),
        ));
    } else if registry
        .rules()
        .iter()
        .any(|known| known.reference.id.as_str() == rule)
    {
        return Err(rule_error(
            "inspection_not_available",
            "this build has no `clean inspect` for this rule: it inspects `project.dependency-directory`, `git.linked-worktree`, and the six cache rules; the command made no change",
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
