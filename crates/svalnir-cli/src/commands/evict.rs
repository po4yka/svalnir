//! `clean plan --mode evict`: the plan of a manual eviction of the
//! candidates of one reviewed rule.
//!
//! The candidates come from the discovery of the rule
//! ([`svalnir_agent::rules::ReviewedRules::discover_for_eviction`]) and
//! not from a scan. The command reads the filesystem and the process
//! table, and it writes only the sealed plan and the plan document of
//! this client. It removes nothing: `clean apply` hands the plan to the
//! coordinator, which examines each target again.
//!
//! A rule permits this mode only for a layout whose lifecycle state is
//! validated for manual action (`docs/CLEANUP_RULES.md` section 2). Each
//! reviewed rule of this build is `proposed`, so the command refuses each
//! rule with `rule_mode_not_validated` before it reads a directory.

use serde::Serialize;
use svalnir_agent::journal::OperationJournal;
use svalnir_agent::protection::ProtectedLocations;
use svalnir_agent::rules::projects::{
    GitHeadActivity, MiseDiscovery, PROJECT_RULE_ID, ProjectLimits, ProjectRequest,
    SearchRootReport,
};
use svalnir_agent::rules::{
    DiscoveryCompletion, DiscoveryHost, DiscoveryLimits, EvictionCandidate, EvictionDiscovery,
    EvictionRequest, ReviewedRules, RootResult, SkipReason,
};
use svalnir_agent::scan::CancellationToken;
use svalnir_core::action::WorkCharge;
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{PlanId, RuleId, StepId, TargetId};
use svalnir_core::plan::{
    CleanupEntry, CleanupLimits, CleanupRequest, ModeSelection, PlanBuildError, PlanContext,
    PlanOutcome, SelectionPreset, build_cleanup_plan, explain, manual_plan_lifetime,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{Rule, RuleMode, RuleRef, RuleRefusal, RuleRegistry as _};

use super::clean::{self, PlanView};
use super::inspect::{self, ProjectRoots, ProjectSources};
use super::plan_store::RootRecord;
use super::session::{self, ActiveConfig, Now};
use super::{CommandFailure, Invocation};
use crate::cli::CleanPlanArgs;
use crate::environment::Environment;
use crate::host::Host;
use crate::interrupt::Interrupt;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind};
use crate::text::put_line;

/// The name of the selection preset of this build.
pub(crate) const DEVELOPER_PRESET: &str = "developer";

/// The rules of the `developer` preset: the rules whose producer is a
/// developer tool.
const DEVELOPER_RULES: [&str; 1] = [svalnir_agent::rules::XCODE_DERIVED_DATA_RULE_ID];

/// The largest number of skipped units that the result shows for one
/// root.
const SKIPPED_LIMIT: usize = 64;

const INTERRUPTED_NOTE: &str =
    "The rule discovery was interrupted, so no plan was made. This command changed no file.";

/// The time between two checks of the interrupt flag during a discovery.
const INTERRUPT_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// The selection preset `name`.
///
/// A preset only filters candidates: it includes the candidates that one
/// of its rules found. It cannot add an entry, enable a rule, remove a
/// protection, or grant authority.
///
/// # Errors
///
/// Returns `unknown_profile` when this build has no preset with the name.
pub(crate) fn preset(name: &str) -> Result<SelectionPreset, ErrorBody> {
    if name != DEVELOPER_PRESET {
        return Err(ErrorBody::new(
            "unknown_profile",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "this build has no selection preset with this name; the selection preset of this build is `developer`; the command made no change",
        )
        .with_fields(&["profile"]));
    }
    Ok(SelectionPreset {
        name: DEVELOPER_PRESET.to_owned(),
        rules: Some(
            DEVELOPER_RULES
                .iter()
                .filter_map(|rule| RuleId::new(*rule).ok())
                .collect(),
        ),
        roots: None,
    })
}

/// One unit that the discovery of a rule did not accept.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SkippedView {
    /// The unit, below the root.
    pub(crate) relative_entry: LosslessPath,
    /// The reasons, as the stable names of `docs/CLEANUP_RULES.md`
    /// section 13.
    pub(crate) reasons: Vec<SkipReason>,
}

/// What the discovery found at one approved root of the rule.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RootView {
    /// The path of the root. `None` when the home directory or the state
    /// directory of the user is not known.
    pub(crate) path: Option<LosslessPath>,
    /// `examined`, `not_bound`, or `refused`.
    pub(crate) result: &'static str,
    /// The reason of a root that was not bound or that the discovery
    /// refused.
    pub(crate) reason: Option<&'static str>,
    /// How the discovery of the root ended.
    pub(crate) completion: Option<DiscoveryCompletion>,
    /// The units that are not candidates, to a bound.
    pub(crate) skipped: Vec<SkippedView>,
    /// The number of skipped units that are not in `skipped`.
    pub(crate) skipped_omitted: u64,
}

/// The discovery behind an eviction plan.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoveryView {
    /// The exact rule revision.
    pub(crate) rule: RuleRef,
    /// False when a discovery stopped at a bound, was interrupted, or
    /// could not resolve its overlaps: the list of candidates is then not
    /// complete.
    pub(crate) complete: bool,
    /// The number of candidates that the rule found. The plan has those
    /// that each check accepts; the explanation has the reason of each
    /// other one.
    pub(crate) candidates: usize,
    /// The number of overlap conflicts between rules.
    pub(crate) conflicts: usize,
    /// The candidates whose age or inactivity the rule did not establish,
    /// with the reasons of the rule, to a bound. The plan leaves each of
    /// them out.
    pub(crate) blocked: Vec<SkippedView>,
    /// The number of blocked candidates that are not in `blocked`.
    pub(crate) blocked_omitted: usize,
    pub(crate) roots: Vec<RootView>,
    /// For `project.dependency-directory`: each root of the request, with
    /// its kind (`search` or `project`) and its source (`configuration`,
    /// `argument`, or `mise` with the configuration file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_roots: Option<Vec<SearchRootReport>>,
    /// For `project.dependency-directory`: the read of the tracked-configs
    /// directory of mise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mise: Option<MiseDiscovery>,
    /// The candidates that `--min-size` leaves out, to a bound.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) below_minimum_size: Vec<LosslessPath>,
}

impl DiscoveryView {
    fn new(rule: RuleRef, discovery: &EvictionDiscovery) -> Self {
        let lossless = |path: &std::path::PathBuf| LosslessPath::from_path(path).ok();
        let blocked = || {
            discovery
                .candidates
                .iter()
                .filter(|candidate| !candidate.discovered.blockers.is_empty())
        };
        Self {
            rule,
            complete: discovery.complete,
            candidates: discovery.candidates.len(),
            conflicts: discovery.conflicts.len(),
            blocked: blocked()
                .take(SKIPPED_LIMIT)
                .map(|candidate| SkippedView {
                    relative_entry: candidate.discovered.evidence.relative_entry.clone(),
                    reasons: candidate.discovered.blockers.clone(),
                })
                .collect(),
            blocked_omitted: blocked().count().saturating_sub(SKIPPED_LIMIT),
            roots: discovery
                .roots
                .iter()
                .map(|report| {
                    let path: Option<LosslessPath> = report.path.as_ref().and_then(lossless);
                    match &report.result {
                        RootResult::Examined {
                            completion,
                            skipped,
                            skipped_omitted,
                        } => RootView {
                            path,
                            result: "examined",
                            reason: None,
                            completion: Some(*completion),
                            skipped: skipped
                                .iter()
                                .take(SKIPPED_LIMIT)
                                .map(|unit| SkippedView {
                                    relative_entry: unit.relative_entry.clone(),
                                    reasons: unit.reasons.clone(),
                                })
                                .collect(),
                            skipped_omitted: skipped_omitted.saturating_add(
                                u64::try_from(skipped.len().saturating_sub(SKIPPED_LIMIT))
                                    .unwrap_or(u64::MAX),
                            ),
                        },
                        other => RootView {
                            path,
                            result: match other {
                                RootResult::Refused(_) => "refused",
                                _ => "not_bound",
                            },
                            reason: match other {
                                RootResult::NotBound(problem) => Some(problem.as_str()),
                                RootResult::Refused(reason) => Some(reason),
                                RootResult::OtherVolume => Some("other_volume"),
                                RootResult::NothingKnown => Some("nothing_known"),
                                RootResult::Examined { .. } => None,
                            },
                            completion: None,
                            skipped: Vec::new(),
                            skipped_omitted: 0,
                        },
                    }
                })
                .collect(),
            project_roots: None,
            mise: None,
            below_minimum_size: Vec::new(),
        }
    }

    /// The view with the roots of `project.dependency-directory`, the read
    /// of mise, and the candidates that `--min-size` leaves out.
    fn with_projects(
        mut self,
        discovery: &EvictionDiscovery,
        mise: Option<MiseDiscovery>,
        below: &[EvictionCandidate],
    ) -> Self {
        if let Some(mise) = mise {
            self.mise = Some(mise);
            self.project_roots = Some(discovery.project_roots.clone());
        }
        self.below_minimum_size = below
            .iter()
            .take(SKIPPED_LIMIT)
            .map(|candidate| candidate.candidate.candidate.path.clone())
            .collect();
        self
    }

    pub(crate) fn render(&self, out: &mut String) {
        put_line!(
            out,
            "\nRule discovery: {} revision {}",
            self.rule.id,
            self.rule.revision
        );
        put_line!(
            out,
            "  Candidates found: {}{}",
            self.candidates,
            if self.complete {
                ""
            } else {
                "   (the discovery is not complete)"
            }
        );
        let names = |reasons: &[SkipReason]| -> String {
            reasons
                .iter()
                .map(|reason| {
                    serde_json::to_value(reason)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_default()
                })
                .collect::<Vec<String>>()
                .join(", ")
        };
        for unit in &self.blocked {
            put_line!(
                out,
                "  Not eligible now: {}   {}",
                unit.relative_entry.display_label(),
                names(&unit.reasons)
            );
        }
        if self.blocked_omitted > 0 {
            put_line!(out, "  ... and {} more", self.blocked_omitted);
        }
        for root in &self.roots {
            let path: String = root
                .path
                .as_ref()
                .map_or_else(|| "(not resolved)".to_owned(), LosslessPath::display_label);
            if let Some(reason) = root.reason {
                put_line!(out, "  Root: {path}   {}: {reason}", root.result);
            } else {
                put_line!(out, "  Root: {path}   {}", root.result);
            }
            for unit in &root.skipped {
                put_line!(
                    out,
                    "    Not a candidate: {}   {}",
                    unit.relative_entry.display_label(),
                    names(&unit.reasons)
                );
            }
            if root.skipped_omitted > 0 {
                put_line!(out, "    ... and {} more", root.skipped_omitted);
            }
        }
    }
}

fn registry_unavailable() -> ErrorBody {
    ErrorBody::new(
        "rule_registry_unavailable",
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        "the rule registry of this build is not usable; the command made no change",
    )
}

/// The rule revision `name` of the registry, when one of its layouts is
/// validated for manual eviction.
fn selected_rule<'a>(registry: &'a ReviewedRules, name: &str) -> Result<&'a Rule, ErrorBody> {
    let Some(found) = registry
        .rules()
        .into_iter()
        .find(|candidate| candidate.reference.id.as_str() == name)
    else {
        return Err(ErrorBody::new(
            "unknown_rule",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the rule registry of this build has no rule with this ID; the command made no change",
        )
        .with_fields(&["rule"]));
    };
    // The layout of the scope root of an owner operation is for the
    // `owner` mode: an eviction removes no scope root as a whole.
    let owner_layout: Option<&str> = registry
        .producer(name)
        .map(|producer| producer.spec().layout);
    let validated: bool = found.layouts.iter().any(|layout| {
        Some(layout.layout.as_str()) != owner_layout && layout.permits(&RuleMode::ManualEviction)
    });
    if !validated {
        return Err(ErrorBody::new(
            "rule_mode_not_validated",
            ErrorFamily::Eligibility,
            ErrorStage::Admission,
            "the rule has no recorded validation for manual eviction, so the `evict` mode is not permitted for it; the command made no change",
        )
        .with_fields(&["rule", "mode"]));
    }
    Ok(found)
}

/// Sets `finished` when it is dropped, so that the interrupt thread ends
/// also when the discovery panics.
struct Finish<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Runs the discovery of `rule` and stops it when the user interrupts.
fn discover(
    registry: &ReviewedRules,
    rule: &Rule,
    host: &DiscoveryHost,
    environment: &Environment,
    projects: Option<&ProjectRequest<'_>>,
) -> EvictionDiscovery {
    use std::sync::atomic::{AtomicBool, Ordering};

    let interrupt: &Interrupt = &environment.interrupt;
    interrupt.arm();
    let cancel = CancellationToken::new();
    let finished = AtomicBool::new(false);
    let evidence = environment.seams.discovery_environment();
    let rules: [RuleId; 1] = [rule.reference.id.clone()];
    std::thread::scope(|scope| {
        // With no thread for the interrupt, the discovery still runs to
        // its bounds; it then does not stop at an interrupt.
        drop(
            std::thread::Builder::new()
                .name("svalnir-interrupt".to_owned())
                .spawn_scoped(scope, || {
                    while !finished.load(Ordering::SeqCst) {
                        if interrupt.is_requested() {
                            cancel.cancel();
                            return;
                        }
                        std::thread::sleep(INTERRUPT_POLL);
                    }
                }),
        );
        let _finish = Finish(&finished);
        registry.discover_for_eviction(
            &EvictionRequest {
                host,
                purpose: &RuleMode::ManualEviction,
                rules: Some(&rules),
                volumes: None,
                known: None,
                limits: DiscoveryLimits::default(),
                cancel: &cancel,
                projects,
            },
            evidence.as_ref(),
        )
    })
}

/// The roots of the request of `project.dependency-directory`: the
/// configuration, `--root`, and mise. `None` for each other rule.
///
/// # Errors
///
/// Returns the error of [`inspect::project_roots`], or `no_search_roots`
/// when the request has no root.
fn request_roots(
    arguments: &CleanPlanArgs,
    environment: &Environment,
    rule: &Rule,
    config: &ValidatedConfig,
    locations: &ProtectedLocations,
) -> Result<Option<ProjectRoots>, ErrorBody> {
    if rule.reference.id.as_str() != PROJECT_RULE_ID {
        return Ok(None);
    }
    let roots: ProjectRoots =
        inspect::project_roots(environment, config, &arguments.projects, locations, true)?;
    if roots.roots.is_empty() {
        return Err(inspect::no_search_roots());
    }
    Ok(Some(roots))
}

/// The inputs of the discovery of `project.dependency-directory`.
struct DiscoveryOptions<'a> {
    config: &'a ValidatedConfig,
    roots: Option<&'a ProjectRoots>,
    include_active: bool,
}

/// [`discover`] with the request of `project.dependency-directory` when
/// `options` has its roots.
fn discover_with_roots(
    registry: &ReviewedRules,
    rule: &Rule,
    host: &DiscoveryHost,
    environment: &Environment,
    options: &DiscoveryOptions<'_>,
) -> EvictionDiscovery {
    let sources: ProjectSources =
        ProjectSources::new(options.config, host.locations.home_directory());
    let head: GitHeadActivity<'_> = GitHeadActivity::new(sources.git());
    let request: Option<ProjectRequest<'_>> = options.roots.map(|roots| ProjectRequest {
        roots: &roots.roots,
        git: sources.git(),
        recency: sources.recency(&head),
        layouts: &options.config.cleanup().projects.layouts,
        include_active: options.include_active,
        limits: ProjectLimits::default(),
    });
    discover(registry, rule, host, environment, request.as_ref())
}

/// The inputs of the plan builder beside the entries.
struct PlanInputs<'a> {
    plan_id: PlanId,
    policy_revision: svalnir_core::id::PolicyRevisionId,
    config: &'a ValidatedConfig,
    now: &'a Now,
    locations: &'a ProtectedLocations,
}

/// The plan of `entries` for a manual eviction under `rule`.
///
/// # Errors
///
/// Returns the error of the plan builder.
fn build_outcome(
    registry: &ReviewedRules,
    rule: &Rule,
    entries: &[CleanupEntry],
    preset: Option<&SelectionPreset>,
    inputs: &PlanInputs<'_>,
) -> Result<PlanOutcome, ErrorBody> {
    let home: Option<LosslessPath> = inputs
        .locations
        .home_directory()
        .and_then(|home| LosslessPath::from_path(home).ok());
    let lifetime: Nanoseconds = manual_plan_lifetime(inputs.config)
        .ok_or_else(|| clean::plan_error(&PlanBuildError::Lifetime))?;
    let context = PlanContext {
        plan_id: inputs.plan_id.clone(),
        principal: session::principal(),
        // A manual plan has no action grant: its authority is the approval
        // that is bound to the plan.
        authority: AuthorityBinding {
            policy_revision: inputs.policy_revision.clone(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        clock: &inputs.now.clock,
        created_wall: inputs.now.wall,
        lifetime,
        protections: inputs.config.protections(),
        home_directory: home.as_ref(),
    };
    let selected: Result<&Rule, RuleRefusal> = registry.lookup(&rule.reference);
    let request = CleanupRequest {
        mode: ModeSelection::Evict { rule: selected },
        entries,
        preset,
        // The builder charges no more than one pass of the rule, and the
        // rule gives the ceiling of one candidate.
        limits: CleanupLimits {
            plan: rule.budget.per_pass,
            batch: WorkCharge::new(
                rule.budget.per_pass.work_bytes.max(Bytes::new(1)),
                rule.budget.per_pass.items.max(EntryCount::new(1)),
            ),
            execution_deadline: clean::EXECUTION_DEADLINE,
            verification_window: clean::VERIFICATION_WINDOW,
        },
    };
    build_cleanup_plan(&context, &request).map_err(|error| clean::plan_error(&error))
}

/// The entries of the plan builder for the candidates of a discovery.
fn entries(
    candidates: &[EvictionCandidate],
    plan_text: &str,
) -> Result<Vec<CleanupEntry>, ErrorBody> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let identity = |kind: char| format!("{plan_text}-{kind}{index:04}");
            Ok(candidate.cleanup_entry(
                TargetId::new(identity('t')).map_err(|_| session::identity_error())?,
                StepId::new(identity('s')).map_err(|_| session::identity_error())?,
            ))
        })
        .collect()
}

/// The cleanup roots of the plan document: the binding of each root that
/// a target of the plan binds.
fn root_records(discovery: &EvictionDiscovery, outcome: &PlanOutcome) -> Vec<RootRecord> {
    let bound: std::collections::BTreeSet<&svalnir_core::id::RootId> = outcome
        .plan
        .iter()
        .flat_map(|plan| &plan.targets)
        .filter_map(|target| match &target.binding {
            svalnir_core::action::TargetBinding::File(file) => Some(&file.root_id),
            _ => None,
        })
        .collect();
    discovery
        .bound_roots
        .iter()
        .filter(|root| bound.contains(&root.binding.root_id))
        .filter_map(|root| {
            Some(RootRecord {
                root_id: root.binding.root_id.clone(),
                path: LosslessPath::from_path(&root.binding.path).ok()?,
                object: root.object,
                volume: root.volume.clone(),
            })
        })
        .collect()
}

pub(crate) fn plan(
    arguments: &CleanPlanArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let environment: &Environment = invocation.environment;
    let registry: ReviewedRules = environment
        .seams
        .rule_registry()
        .map_err(|_| registry_unavailable())?;
    let rule: &Rule = selected_rule(&registry, arguments.rule.as_deref().unwrap_or_default())?;
    let preset: Option<SelectionPreset> = arguments.profile.as_deref().map(preset).transpose()?;

    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = session::open_journal(environment)?;
    let authority = session::read_authority(&journal)?;
    let ActiveConfig { active, config } = session::active_config(&journal, &authority.state)?;

    let locations: ProtectedLocations = ProtectedLocations::resolve(
        environment.home.as_deref(),
        environment.state_directory().ok().as_deref(),
    );
    let discovery_host: DiscoveryHost =
        DiscoveryHost::manual(session::current_uid(), locations.clone(), &config);
    let project_roots: Option<ProjectRoots> =
        request_roots(arguments, environment, rule, &config, &locations)?;
    let discovery: EvictionDiscovery = discover_with_roots(
        &registry,
        rule,
        &discovery_host,
        environment,
        &DiscoveryOptions {
            config: &config,
            roots: project_roots.as_ref(),
            include_active: arguments.include_active,
        },
    );
    // An interrupted discovery has a part of the candidates. No plan is
    // made from a part: the result has the discovery and no target.
    let interrupted: bool = environment.interrupt.is_requested();

    // `--min-size` only filters: a candidate whose estimate is smaller is
    // not given to the plan builder, and the result names it.
    let (selected, below_minimum): (Vec<EvictionCandidate>, Vec<EvictionCandidate>) =
        discovery.candidates.iter().cloned().partition(|candidate| {
            arguments
                .min_size
                .is_none_or(|minimum| candidate.discovered.measurement.estimate.bytes >= minimum)
        });
    let plan_text: String = session::new_id("plan");
    let plan_id: PlanId = PlanId::new(plan_text.clone()).map_err(|_| session::identity_error())?;
    let entries: Vec<CleanupEntry> = if interrupted {
        Vec::new()
    } else {
        entries(&selected, &plan_text)?
    };
    let outcome: PlanOutcome = build_outcome(
        &registry,
        rule,
        &entries,
        preset.as_ref(),
        &PlanInputs {
            plan_id: plan_id.clone(),
            policy_revision: active.revision.revision_id.clone(),
            config: &config,
            now: &now,
            locations: &locations,
        },
    )?;
    let roots: Vec<RootRecord> = root_records(&discovery, &outcome);
    let has_plan: bool = outcome.plan.is_some();
    clean::store_plan(&mut journal, environment, &outcome, roots.clone())?;
    let view = PlanView {
        scan_id: None,
        explanation: explain(&outcome, &now.clock),
        stale_entries: Vec::new(),
        operation_id: None,
        cleanup_roots: roots.into_iter().map(|root| root.path).collect(),
        has_plan_document: has_plan,
        plan_document: if has_plan { "used" } else { "absent" },
        discovery: Some(
            DiscoveryView::new(rule.reference.clone(), &discovery).with_projects(
                &discovery,
                project_roots.map(|roots| roots.mise),
                &below_minimum,
            ),
        ),
        owner: None,
        repository_warnings: Vec::new(),
        note: if interrupted {
            INTERRUPTED_NOTE
        } else if has_plan {
            clean::PLAN_NOTE
        } else {
            clean::EMPTY_PLAN_NOTE
        },
    };
    invocation.emit(Kind::Report, &view, PlanView::render)?;
    Ok(if interrupted {
        ExitStatus::Interrupted
    } else {
        ExitStatus::Success
    })
}
