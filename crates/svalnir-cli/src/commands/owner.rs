//! `clean plan --mode owner`: the plan of the owner operation of one
//! reviewed rule: the fixed command of its producer on its measured scope
//! root (`docs/CLEANUP_RULES.md` section 9, `docs/INTERFACES.md` section
//! 4).
//!
//! The command reads the configuration files of the producer, the scope
//! root, and the declared executable files, and it writes only the sealed
//! plan and the plan document of this client. It runs no command of the
//! producer: `clean apply` hands the plan to the coordinator, which makes
//! the command again from the declaration of the rule and examines the
//! executable and the scope again.
//!
//! The layout of the scope root must be validated for manual action. Each
//! layout of this build is `proposed`, so the command refuses each rule
//! with `rule_mode_not_validated` before it reads a file.

use serde::Serialize;
use svalnir_agent::executor::owner::ScopeLimits;
use svalnir_agent::journal::OperationJournal;
use svalnir_agent::protection::ProtectedLocations;
use svalnir_agent::rules::caches::{InspectionHost, RootOutcome};
use svalnir_agent::rules::producers::{
    GuardOutcome, MAX_PRODUCER_EXECUTABLE_BYTES, ProducerBindError, ProducerBindRequest,
    ProducerBinding, ProducerRule,
};
use svalnir_agent::rules::{DiscoveryHost, ReviewedRules};
use svalnir_agent::scan::{CancellationToken, WallScanClock};
use svalnir_core::action::{EnvironmentEntry, OwnerOperationKind};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::PolicyRevisionId;
use svalnir_core::id::{PlanId, StepId, TargetId};
use svalnir_core::plan::{
    OwnerPlanRequest, PlanBuildError, PlanContext, PlanMode, PlanOutcome, PlanPreview,
    build_owner_plan, explain, manual_plan_lifetime,
};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{RuleMode, RuleRegistry as _};

use super::clean::{self, PlanView};
use super::plan_store::RootRecord;
use super::session::{self, ActiveConfig, Now};
use super::{CommandFailure, Invocation};
use crate::cli::CleanPlanArgs;
use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind};
use crate::text::put_line;

/// The time between two checks of the interrupt flag during the
/// measurement of the scope.
const INTERRUPT_POLL: std::time::Duration = std::time::Duration::from_millis(50);

const INTERRUPTED_NOTE: &str = "The measurement of the scope was interrupted, so no plan was made. This command changed no file.";

/// The owner-operation facts of a plan that this invocation made.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnerView {
    /// The kind of the command.
    pub(crate) kind: OwnerOperationKind,
    /// The interpreter of a script executable.
    pub(crate) interpreter: Option<LosslessPath>,
    /// The interpreter argument of the `#!` line.
    pub(crate) interpreter_arguments: Vec<String>,
    /// The only entries of the environment of the command.
    pub(crate) environment: Vec<EnvironmentEntry>,
    /// The deadline of the command.
    pub(crate) deadline: Nanoseconds,
    /// Whether the measurement is of the whole cache while the producer
    /// removes only a part of it.
    pub(crate) whole_cache: bool,
    /// The result of the guard of the rule.
    pub(crate) guard: GuardOutcome,
    /// The consequence of the command.
    pub(crate) regeneration: &'static str,
    /// Why the review gave the bound of the command.
    pub(crate) bound_reason: &'static str,
}

impl OwnerView {
    fn new(rule: &ProducerRule, bound: &ProducerBinding) -> Self {
        let binding = &bound.binding;
        Self {
            kind: binding.operation,
            interpreter: binding
                .interpreter
                .as_ref()
                .map(|interpreter| interpreter.executable.path.clone()),
            interpreter_arguments: binding
                .interpreter
                .as_ref()
                .map_or_else(Vec::new, |interpreter| interpreter.arguments.clone()),
            environment: binding.environment.clone(),
            deadline: binding.command_deadline,
            whole_cache: rule.spec().whole_cache,
            guard: bound.guard.clone(),
            regeneration: rule.spec().regeneration,
            bound_reason: rule.spec().bound_reason,
        }
    }

    pub(crate) fn render(&self, out: &mut String) {
        put_line!(out, "\nOwner command ({}):", self.kind.as_str());
        if let Some(interpreter) = &self.interpreter {
            let arguments: String = self.interpreter_arguments.join(" ");
            put_line!(
                out,
                "  interpreter: {} {arguments}",
                interpreter.display_label()
            );
        }
        for entry in &self.environment {
            put_line!(out, "  env: {}={}", entry.name, entry.value);
        }
        put_line!(out, "  deadline: {} s", self.deadline.get() / 1_000_000_000);
        if self.whole_cache {
            out.push_str("  The measured size is of the whole cache; the producer removes only a part of it.\n");
        }
        if let GuardOutcome::Passed { files } = &self.guard {
            put_line!(out, "  guard: passed ({files} tracked files)");
        }
        put_line!(out, "  bound: {}", self.bound_reason);
        put_line!(out, "  consequence: {}", self.regeneration);
    }
}

fn rule_error(code: &'static str, message: &'static str) -> ErrorBody {
    ErrorBody::new(code, ErrorFamily::Request, ErrorStage::Arguments, message)
        .with_fields(&["rule"])
}

/// The rule `name` of the registry with an owner operation whose layout of
/// the scope root is validated for manual action, and whose kind the
/// request permits.
fn selected_rule<'a>(
    registry: &'a ReviewedRules,
    name: &str,
    include_clear: bool,
) -> Result<&'a ProducerRule, ErrorBody> {
    let Some(rule) = registry.producer(name) else {
        let known: bool = registry
            .rules()
            .iter()
            .any(|rule| rule.reference.id.as_str() == name);
        return Err(if known {
            rule_error(
                "owner_operation_not_available",
                "the rule has no owner operation in this build; the command made no change",
            )
        } else {
            rule_error(
                "unknown_rule",
                "the rule registry of this build has no rule with this ID; the command made no change",
            )
        });
    };
    let validated: bool = rule
        .layout()
        .is_some_and(|layout| layout.permits(&RuleMode::ManualEviction));
    if !validated {
        return Err(ErrorBody::new(
            "rule_mode_not_validated",
            ErrorFamily::Eligibility,
            ErrorStage::Admission,
            "the rule has no recorded validation for its owner operation, so the `owner` mode is not permitted for it; the command made no change",
        )
        .with_fields(&["rule", "mode"]));
    }
    if matches!(rule.spec().kind, OwnerOperationKind::Clear) && !include_clear {
        return Err(ErrorBody::new(
            "clear_not_included",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the owner command of this rule has the kind `clear`: the producer removes its cache, also data that a project uses now; add `--include-clear` to plan it; the command made no change",
        )
        .with_fields(&["rule", "include_clear"]));
    }
    Ok(rule)
}

/// The error of a rule that gives no binding.
fn bind_error(error: &ProducerBindError) -> ErrorBody {
    match error {
        ProducerBindError::ClearNotIncluded => ErrorBody::new(
            "clear_not_included",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the owner command of this rule has the kind `clear`; add `--include-clear` to plan it; the command made no change",
        )
        .with_fields(&["include_clear"]),
        ProducerBindError::NoScope(report) => {
            let reason: &str = match report.outcome {
                RootOutcome::Absent => "the scope root does not exist",
                RootOutcome::NoPath => "the configuration of the producer gives no scope root",
                RootOutcome::Refused(reason) => reason,
                RootOutcome::Examined => "the scope root is not known",
            };
            ErrorBody::new(
                "owner_scope_unavailable",
                ErrorFamily::Eligibility,
                ErrorStage::Admission,
                format!(
                    "the rule has no scope root that a plan can bind ({reason}); run `svalnir clean inspect --rule RULE_ID` for the details; the command made no change"
                ),
            )
            .with_fields(&["rule"])
        }
        ProducerBindError::Guard(outcome) => {
            let reason: &str = match outcome {
                GuardOutcome::Refused { reason, .. } => reason,
                GuardOutcome::None | GuardOutcome::Passed { .. } => "the guard refused",
            };
            ErrorBody::new(
                "owner_guard_refused",
                ErrorFamily::Eligibility,
                ErrorStage::Admission,
                format!(
                    "the guard of the rule refused the owner operation ({reason}); run `svalnir clean inspect --rule RULE_ID` for the details; the command made no change"
                ),
            )
            .with_fields(&["rule"])
        }
        ProducerBindError::Bind(error) => ErrorBody::new(
            error.as_str(),
            ErrorFamily::Evidence,
            ErrorStage::Admission,
            format!(
                "the owner operation has no binding: {error}; run `svalnir clean inspect --rule RULE_ID` for the details; the command made no change"
            ),
        )
        .with_fields(&["rule"]),
    }
}

/// Sets `finished` when it is dropped, so that the interrupt thread ends
/// also when the binding panics.
struct Finish<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Binds the rule and stops the measurement when the user interrupts.
fn bind(
    rule: &ProducerRule,
    request: &ProducerBindRequest<'_>,
    environment: &Environment,
) -> Result<ProducerBinding, ProducerBindError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let interrupt = &environment.interrupt;
    interrupt.arm();
    let cancel = CancellationToken::new();
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        // With no thread for the interrupt, the measurement still runs to
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
        rule.bind(request, &cancel, &WallScanClock)
    })
}

/// The root record of the plan document for the scope root.
fn root_record(bound: &ProducerBinding) -> Result<RootRecord, ErrorBody> {
    Ok(RootRecord {
        root_id: bound.root.binding.root_id.clone(),
        path: LosslessPath::from_path(&bound.root.binding.path)
            .map_err(|_| bind_error(&ProducerBindError::NoScope(Box::new(bound.scope.clone()))))?,
        object: bound.root.object,
        volume: bound.root.volume.clone(),
    })
}

/// The result of a measurement that the user interrupted: no plan.
fn interrupted_view(kind: OwnerOperationKind, now: &Now) -> PlanView {
    PlanView {
        scan_id: None,
        explanation: explain(
            &PlanOutcome {
                mode: PlanMode::Owner(kind),
                plan: None,
                preview: PlanPreview {
                    targets: Vec::new(),
                    batches: Vec::new(),
                    omitted: Vec::new(),
                    preset: None,
                },
            },
            &now.clock,
        ),
        stale_entries: Vec::new(),
        operation_id: None,
        cleanup_roots: Vec::new(),
        has_plan_document: false,
        plan_document: "absent",
        discovery: None,
        owner: None,
        repository_warnings: Vec::new(),
        note: INTERRUPTED_NOTE,
    }
}

/// The inputs of the plan builder beside the binding.
struct PlanInputs<'a> {
    plan_text: &'a str,
    plan_id: &'a PlanId,
    policy_revision: &'a PolicyRevisionId,
    config: &'a ValidatedConfig,
    now: &'a Now,
    locations: &'a ProtectedLocations,
}

/// The manual plan of the binding `bound`.
///
/// # Errors
///
/// Returns the error of the plan builder, or an identity error.
fn build_outcome(
    registry: &ReviewedRules,
    bound: &ProducerBinding,
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
    let plan_text: &str = inputs.plan_text;
    build_owner_plan(
        &context,
        &OwnerPlanRequest {
            target_id: TargetId::new(format!("{plan_text}-t0000"))
                .map_err(|_| session::identity_error())?,
            step_id: StepId::new(format!("{plan_text}-s0000"))
                .map_err(|_| session::identity_error())?,
            binding: &bound.binding,
            rule: registry.lookup(&bound.binding.rule),
            protection: inputs.locations.of_text(&bound.root.binding.path),
            verification_window: clean::VERIFICATION_WINDOW,
        },
    )
    .map_err(|error| clean::plan_error(&error))
}

pub(crate) fn plan(
    arguments: &CleanPlanArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    if !arguments.entries.is_empty() || arguments.scan.is_some() || arguments.profile.is_some() {
        return Err(ErrorBody::new(
            "option_not_accepted",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the `owner` mode takes `--rule` and `--include-clear` only: its scope comes from the rule; the command made no change",
        )
        .with_fields(&["entry", "scan", "profile"])
        .into());
    }
    let environment: &Environment = invocation.environment;
    let registry: ReviewedRules = environment.seams.rule_registry().map_err(|_| {
        ErrorBody::new(
            "rule_registry_unavailable",
            ErrorFamily::Native,
            ErrorStage::Dispatch,
            "the rule registry of this build is not usable; the command made no change",
        )
    })?;
    let rule: &ProducerRule = selected_rule(
        &registry,
        arguments.rule.as_deref().unwrap_or_default(),
        arguments.include_clear,
    )?;

    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = session::open_journal(environment)?;
    let authority = session::read_authority(&journal)?;
    let ActiveConfig { active, config } = session::active_config(&journal, &authority.state)?;
    let locations: ProtectedLocations = ProtectedLocations::resolve(
        environment.home.as_deref(),
        environment.state_directory().ok().as_deref(),
    );
    let principal = session::current_uid();
    let discovery_host: DiscoveryHost =
        DiscoveryHost::manual(principal, locations.clone(), &config);
    let request = ProducerBindRequest {
        host: InspectionHost {
            principal,
            locations: &locations,
            user_exclusions: &discovery_host.user_exclusions,
        },
        include_clear: arguments.include_clear,
        max_executable_bytes: MAX_PRODUCER_EXECUTABLE_BYTES,
        scope_limits: ScopeLimits::default(),
    };
    let result: Result<ProducerBinding, ProducerBindError> = bind(rule, &request, environment);
    if environment.interrupt.is_requested() {
        let view: PlanView = interrupted_view(rule.spec().kind, &now);
        invocation.emit(Kind::Report, &view, PlanView::render)?;
        return Ok(ExitStatus::Interrupted);
    }
    let bound: ProducerBinding = result.map_err(|error| bind_error(&error))?;
    let plan_text: String = session::new_id("plan");
    let plan_id: PlanId = PlanId::new(plan_text.clone()).map_err(|_| session::identity_error())?;
    let outcome: PlanOutcome = build_outcome(
        &registry,
        &bound,
        &PlanInputs {
            plan_text: &plan_text,
            plan_id: &plan_id,
            policy_revision: &active.revision.revision_id,
            config: &config,
            now: &now,
            locations: &locations,
        },
    )?;
    let root: RootRecord = root_record(&bound)?;
    let has_plan: bool = outcome.plan.is_some();
    clean::store_plan(&mut journal, environment, &outcome, vec![root.clone()])?;
    let view = PlanView {
        scan_id: None,
        explanation: explain(&outcome, &now.clock),
        stale_entries: Vec::new(),
        operation_id: None,
        cleanup_roots: if has_plan {
            vec![root.path]
        } else {
            Vec::new()
        },
        has_plan_document: has_plan,
        plan_document: if has_plan { "used" } else { "absent" },
        discovery: None,
        owner: Some(OwnerView::new(rule, &bound)),
        repository_warnings: Vec::new(),
        note: if has_plan {
            clean::PLAN_NOTE
        } else {
            clean::EMPTY_PLAN_NOTE
        },
    };
    invocation.emit(Kind::Report, &view, PlanView::render)?;
    Ok(ExitStatus::Success)
}
