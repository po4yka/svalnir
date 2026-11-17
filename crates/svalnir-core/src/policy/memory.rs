//! The memory guard.
//!
//! `docs/POLICY_SPEC.md` section 10 owns the contract. The guard has two
//! independent triggers:
//!
//! - Global pressure: the native pressure state is `critical` for
//!   `sustain_for`, with fresh corroborating system observations.
//! - Application budget: the attributed footprint of one verified
//!   application instance is at or above `footprint_stop` for
//!   `over_limit_for`, also when the global pressure is normal.
//!
//! `footprint_soft` gives an advisory state only. A large footprint, swap
//! use, or CPU use is not a trigger: this module reads none of them as one.
//!
//! [`evaluate_memory_guard`] evaluates the triggers. [`plan_intervention`]
//! decides the eligibility of the candidate applications, ranks them, and
//! names the first intervention.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use super::control::{
    CandidateDecision, Cooldown, EvaluationContext, MAX_APPLICATION_CANDIDATES,
    MAX_CANDIDATE_PROCESSES, MAX_COOLDOWNS, MAX_CORROBORATING, PathSet, PolicyInputError,
    ProtectionFact, TriggerState, check_count, decision_of, is_canonical,
};
use super::disk::state_reason;
use super::evidence::{
    CorroboratingEvidence, EvidenceProblem, EvidenceReport, ScopeCheck, Usable, assess, binding,
    nanoseconds, report as evidence_report, sample_age,
};
use super::reason::{DecisionReason, Explanation, ReasonDetail, push_reason};
use super::window::{
    QualificationWindow, QualifyingSample, WindowEvidence, WindowReport, WindowStep, advance,
};
use crate::config::{AppBudget, EligibleGroup, GlobalTrigger, MemoryGuard};
use crate::id::{ApplicationInstanceId, MembershipSnapshotId};
use crate::observation::{Coverage, MetricId, Observation, Sample, Scope, ScopeKind, metric};
use crate::process::{ProcessAssociation, ProcessIdentity, VerifiedMembership};
use crate::quantity::{Bytes, Nanoseconds};
use crate::state::PressureState;

/// Whether an application is the frontmost application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForegroundStatus {
    /// The application is the active application.
    Foreground,
    /// The application is not the active application.
    Background,
    /// No foreground evidence. This status is not `Background`.
    Unknown,
}

/// One candidate application or managed job: the processes of one
/// membership snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCandidate {
    /// Each process of the membership snapshot, with its identity and its
    /// association.
    pub processes: Vec<ProcessIdentity>,
    /// The membership snapshot that the footprint is a sum over.
    pub membership_snapshot: MembershipSnapshotId,
    /// The foreground status of the application.
    pub foreground: ForegroundStatus,
    /// The `application.attributed_footprint_bytes` observation of the
    /// membership snapshot.
    pub footprint: Observation<Bytes>,
    /// The product protection of the application.
    pub hard_protection: ProtectionFact,
}

/// The evidence that the process inventory is complete. An application
/// that the inventory does not have is known to be absent only with this
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEvidence {
    /// How much of the processes of the user the inventory covers.
    pub coverage: Coverage,
    /// The acquisition of the inventory.
    pub sample: Sample,
}

/// The inputs of a memory-guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemorySnapshot {
    /// The `memory.pressure` observation of the host.
    pub pressure: Option<Observation<PressureState>>,
    /// Other system memory observations of the host.
    pub corroborating: Vec<CorroboratingEvidence>,
    /// The candidate applications and managed jobs. The list must have each
    /// application and job of the inventory: an application that the list
    /// does not have is absent for its budget when `inventory` is complete.
    pub applications: Vec<ApplicationCandidate>,
    /// The evidence of the process inventory.
    pub inventory: Option<InventoryEvidence>,
}

impl MemorySnapshot {
    /// Checks the lengths of the lists.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyInputError`] when a list is longer than its limit.
    pub fn check(&self) -> Result<(), PolicyInputError> {
        check_count(
            "corroborating observations",
            self.corroborating.len(),
            MAX_CORROBORATING,
        )?;
        check_count(
            "application candidates",
            self.applications.len(),
            MAX_APPLICATION_CANDIDATES,
        )?;
        for candidate in &self.applications {
            check_count(
                "processes of one application candidate",
                candidate.processes.len(),
                MAX_CANDIDATE_PROCESSES,
            )?;
        }
        Ok(())
    }
}

/// The window state of one application budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BudgetState {
    /// The identifier of the budget in the configuration.
    pub budget_id: String,
    /// The window of `footprint_stop`.
    pub stop_window: QualificationWindow,
    /// The window of recovery.
    pub recovery_window: QualificationWindow,
    /// True when the budget has a trigger episode that did not recover.
    pub latched: bool,
}

/// The memory incident of one principal. The global trigger and each budget
/// trigger share it and its application slots. The evaluation opens and
/// closes it. The caller owns the slots and the outstanding-operation flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct MemoryIncident {
    /// The application slots that the incident consumed.
    pub consumed_slots: u32,
    /// The application slots that the incident reserved.
    pub reserved_slots: u32,
    /// True when an operation of the incident is not settled.
    pub outstanding_operation: bool,
}

impl MemoryIncident {
    /// `max(0, ceiling - consumed - reserved)`.
    fn slots_left(&self, ceiling: u32) -> u32 {
        ceiling
            .saturating_sub(self.consumed_slots)
            .saturating_sub(self.reserved_slots)
    }
}

/// The cooldown of one application. The key is the stable application or
/// job identity, so a relaunch with a new process does not evade it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApplicationCooldown {
    /// The bundle identifier of the application or the label of the job.
    pub application: String,
    /// The cooldown.
    pub cooldown: Cooldown,
}

/// The state of the memory guard that the caller keeps between evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct MemoryGuardState {
    /// The window of the global trigger.
    pub critical_window: QualificationWindow,
    /// The window of global recovery.
    pub recovery_window: QualificationWindow,
    /// True when the global trigger has an episode that did not recover.
    pub global_latched: bool,
    /// One entry for each application budget.
    pub budgets: Vec<BudgetState>,
    /// The open incident.
    pub incident: Option<MemoryIncident>,
    /// The application cooldowns that the caller recorded.
    pub cooldowns: Vec<ApplicationCooldown>,
}

/// The evaluation of the global-pressure trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GlobalPressureTrigger {
    /// The incident state of the trigger.
    pub state: TriggerState,
    /// The pressure state, when the observation is usable.
    pub pressure: Option<PressureState>,
    /// The pressure state that the trigger needs.
    pub required_pressure: PressureState,
    /// The evidence that the evaluation used.
    pub evidence: EvidenceReport,
    /// The metrics of the fresh corroborating observations.
    pub corroborating_metrics: Vec<MetricId>,
    /// The window of the trigger.
    pub critical_window: WindowReport,
    /// The window of recovery.
    pub recovery_window: WindowReport,
    /// True when the trigger has an episode that did not recover.
    pub latched: bool,
    /// The reasons that no action is admissible for this trigger now.
    pub reasons: Vec<Explanation>,
}

/// The attributed footprint against the thresholds of a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintLevel {
    /// Below `footprint_soft`.
    BelowSoft,
    /// At or above `footprint_soft` and below `footprint_stop`: advisory.
    Soft,
    /// At or above `footprint_stop`.
    Stop,
    /// The application is known to be absent.
    NotRunning,
    /// No usable footprint. This level is not a safe level.
    Unknown,
}

/// The evaluation of one application-budget trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetTrigger {
    /// The identifier of the budget.
    pub budget_id: String,
    /// The bundle identifier of the budget.
    pub bundle_id: String,
    /// The incident state of the trigger.
    pub state: TriggerState,
    /// The footprint against the thresholds.
    pub level: FootprintLevel,
    /// True when the footprint is at or above `footprint_soft`. An advisory
    /// signal authorizes no action.
    pub advisory: bool,
    /// The attributed footprint, when the observation is usable.
    pub footprint: Option<Bytes>,
    /// The application instance that the budget is bound to.
    pub instance_id: Option<ApplicationInstanceId>,
    /// The evidence that the evaluation used.
    pub evidence: EvidenceReport,
    /// The window of `footprint_stop`.
    pub stop_window: WindowReport,
    /// The window of recovery.
    pub recovery_window: WindowReport,
    /// True when the budget has an episode that did not recover.
    pub latched: bool,
    /// The reasons that no action is admissible for this trigger now.
    pub reasons: Vec<Explanation>,
}

/// The result of [`evaluate_memory_guard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEvaluation {
    /// The global-pressure trigger.
    pub global: GlobalPressureTrigger,
    /// One trigger for each application budget, in the sequence of the
    /// configuration.
    pub budgets: Vec<BudgetTrigger>,
    /// The application slots that the incident can still charge.
    pub slots_remaining: u32,
    /// The state that the caller keeps for the next evaluation.
    pub next_state: MemoryGuardState,
}

/// The kind of a verified candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
    /// A running application.
    Application,
    /// A managed job.
    ManagedJob,
}

/// The verified identity of a candidate.
#[derive(Debug, Clone, Copy)]
struct Identity<'a> {
    kind: ApplicationKind,
    instance_id: &'a ApplicationInstanceId,
    /// The bundle identifier of an application or the label of a job.
    name: &'a str,
}

/// The identity of a candidate, when each process has a verified membership
/// of the same application or job instance.
fn verified_identity(candidate: &ApplicationCandidate) -> Result<Identity<'_>, ReasonDetail> {
    let mut identity: Option<Identity<'_>> = None;
    for process in &candidate.processes {
        let one: Identity<'_> = match process.association.verified_membership() {
            Some(VerifiedMembership::Application {
                instance_id,
                bundle_identifier,
            }) => Identity {
                kind: ApplicationKind::Application,
                instance_id,
                name: bundle_identifier,
            },
            Some(VerifiedMembership::ManagedJob { instance_id, label }) => Identity {
                kind: ApplicationKind::ManagedJob,
                instance_id,
                name: label,
            },
            None => return Err(ReasonDetail::MembershipUnverified),
        };
        match identity {
            None => identity = Some(one),
            Some(first)
                if first.kind == one.kind
                    && first.instance_id == one.instance_id
                    && first.name == one.name => {}
            Some(_) => return Err(ReasonDetail::MembersInconsistent),
        }
    }
    identity.ok_or(ReasonDetail::MembershipUnverified)
}

/// The bundle identifiers that the processes of a candidate claim, verified
/// or not. A protection applies to a claimed identifier.
fn claimed_bundle_ids(candidate: &ApplicationCandidate) -> impl Iterator<Item = &str> {
    candidate
        .processes
        .iter()
        .filter_map(|process| match &process.association {
            ProcessAssociation::Application {
                bundle_identifier, ..
            } => Some(bundle_identifier.as_str()),
            _ => None,
        })
}

/// The window subject of a candidate: the instance, the membership
/// snapshot, and each process generation.
fn subject_of(
    prefix: &str,
    identity: &Identity<'_>,
    candidate: &ApplicationCandidate,
) -> Vec<String> {
    let mut generations: Vec<String> = candidate
        .processes
        .iter()
        .map(|process| process.generation_id.as_str().to_owned())
        .collect();
    generations.sort_unstable();
    let mut subject: Vec<String> = vec![
        prefix.to_owned(),
        identity.instance_id.as_str().to_owned(),
        candidate.membership_snapshot.as_str().to_owned(),
    ];
    subject.extend(generations);
    subject
}

/// The durations of the configuration that the evaluation uses.
struct Timing {
    max_age: Nanoseconds,
    max_gap: Nanoseconds,
    recovery_stable: Nanoseconds,
}

/// Evaluates the memory guard for one snapshot.
///
/// The function evaluates the global-pressure trigger and each application
/// budget, and advances the qualification windows of `state`. It opens the
/// incident when a trigger qualifies and closes it when each latched episode
/// has a stable recovery and no operation is outstanding. It does not change
/// the slots of the incident.
///
/// The function is pure: equal arguments give an equal result.
///
/// # Errors
///
/// Returns a [`PolicyInputError`] when a list of the snapshot or of the
/// state is longer than its limit.
pub fn evaluate_memory_guard(
    context: &EvaluationContext<'_>,
    state: &MemoryGuardState,
    snapshot: &MemorySnapshot,
) -> Result<MemoryEvaluation, PolicyInputError> {
    snapshot.check()?;
    check_count(
        "application cooldowns",
        state.cooldowns.len(),
        MAX_COOLDOWNS,
    )?;
    let guard: &MemoryGuard = context.config.memory_guard();
    let agent = context.config.agent();
    let timing: Timing = Timing {
        max_age: nanoseconds(agent.decision_sample_max_age),
        max_gap: nanoseconds(agent.max_qualifying_sample_gap),
        recovery_stable: nanoseconds(guard.recovery_stable_for),
    };

    let (mut global, critical_window, recovery_window) =
        evaluate_global(context, guard, &timing, state, snapshot);
    let mut budgets: Vec<BudgetTrigger> = Vec::with_capacity(guard.app_budgets.len());
    let mut next_budgets: Vec<BudgetState> = Vec::with_capacity(guard.app_budgets.len());
    for budget in &guard.app_budgets {
        let prior: BudgetState = state
            .budgets
            .iter()
            .find(|entry| entry.budget_id == budget.id.as_str())
            .cloned()
            .unwrap_or_else(|| BudgetState {
                budget_id: budget.id.as_str().to_owned(),
                stop_window: QualificationWindow::Idle,
                recovery_window: QualificationWindow::Idle,
                latched: false,
            });
        let (trigger, next) = evaluate_budget(context, &timing, budget, &prior, snapshot);
        budgets.push(trigger);
        next_budgets.push(next);
    }

    // The incident is open while an episode is latched or an operation is
    // outstanding.
    let latched: bool = global.latched || next_budgets.iter().any(|budget| budget.latched);
    let incident: Option<MemoryIncident> = match state.incident {
        Some(incident) if latched || incident.outstanding_operation => Some(incident),
        Some(_) => None,
        None => latched.then(MemoryIncident::default),
    };
    let ceiling: u32 = guard.max_applications_per_incident.get();
    let slots_remaining: u32 = incident.map_or(ceiling, |incident| incident.slots_left(ceiling));
    apply_incident(
        &mut global.state,
        &mut global.reasons,
        incident,
        slots_remaining,
    );
    for budget in &mut budgets {
        apply_incident(
            &mut budget.state,
            &mut budget.reasons,
            incident,
            slots_remaining,
        );
    }

    Ok(MemoryEvaluation {
        next_state: MemoryGuardState {
            critical_window,
            recovery_window,
            global_latched: global.latched,
            budgets: next_budgets,
            incident,
            cooldowns: state.cooldowns.clone(),
        },
        global,
        budgets,
        slots_remaining,
    })
}

/// Applies the incident conditions to a qualified trigger and sets its
/// reasons.
fn apply_incident(
    state: &mut TriggerState,
    reasons: &mut Vec<Explanation>,
    incident: Option<MemoryIncident>,
    slots_remaining: u32,
) {
    if *state == TriggerState::Ready {
        if incident.is_some_and(|incident| incident.outstanding_operation) {
            *state = TriggerState::Acting;
        } else if slots_remaining == 0 {
            *state = TriggerState::Exhausted;
            push_reason(
                reasons,
                Explanation::new(
                    DecisionReason::BudgetExhausted,
                    ReasonDetail::ApplicationSlotsExhausted,
                ),
            );
        }
    }
    if let Some(reason) = state_reason(*state) {
        push_reason(reasons, reason);
    }
}

/// The usable pressure observation, with its corroboration.
fn assess_pressure<'a>(
    context: &EvaluationContext<'_>,
    timing: &Timing,
    snapshot: &'a MemorySnapshot,
) -> Result<Usable<'a, PressureState>, EvidenceProblem> {
    let Some(observation) = &snapshot.pressure else {
        return Err(EvidenceProblem::Missing);
    };
    let usable: Usable<'a, PressureState> = assess(
        observation,
        &metric::MEMORY_PRESSURE,
        ScopeCheck::Kind(&ScopeKind::Host),
        context.clock,
        timing.max_age,
    )?;
    // A state that this build does not recognize is not normal and not
    // critical.
    if !usable.value.is_recognized() {
        return Err(EvidenceProblem::Unrecognized);
    }
    let corroborated: bool = snapshot
        .corroborating
        .iter()
        .any(|evidence| evidence.corroborates(context.clock, timing.max_age));
    if !corroborated {
        return Err(EvidenceProblem::CorroborationMissing);
    }
    Ok(usable)
}

fn evaluate_global(
    context: &EvaluationContext<'_>,
    guard: &MemoryGuard,
    timing: &Timing,
    state: &MemoryGuardState,
    snapshot: &MemorySnapshot,
) -> (
    GlobalPressureTrigger,
    QualificationWindow,
    QualificationWindow,
) {
    let sustain: Nanoseconds = nanoseconds(guard.sustain_for);
    let required_pressure: PressureState = match guard.global_trigger {
        GlobalTrigger::Critical => PressureState::Critical,
    };
    let corroborating_metrics: Vec<MetricId> = snapshot
        .corroborating
        .iter()
        .filter(|evidence| evidence.corroborates(context.clock, timing.max_age))
        .map(|evidence| evidence.metric_id.clone())
        .collect();
    let assessed = assess_pressure(context, timing, snapshot);
    let evidence: EvidenceReport = match &snapshot.pressure {
        Some(observation) => {
            evidence_report(observation, context.clock, assessed.as_ref().err().cloned())
        }
        None => EvidenceReport::missing(metric::MEMORY_PRESSURE, EvidenceProblem::Missing),
    };

    let usable: Usable<'_, PressureState> = match assessed {
        Ok(usable) => usable,
        Err(problem) => {
            let unusable = || WindowEvidence::Unusable(problem.clone());
            let critical: WindowStep =
                advance(&state.critical_window, unusable(), sustain, timing.max_gap);
            let recovery: WindowStep = advance(
                &state.recovery_window,
                unusable(),
                timing.recovery_stable,
                timing.max_gap,
            );
            let trigger: GlobalPressureTrigger = GlobalPressureTrigger {
                state: TriggerState::Blocked,
                pressure: None,
                required_pressure,
                evidence,
                corroborating_metrics,
                critical_window: critical.report,
                recovery_window: recovery.report,
                latched: state.global_latched,
                reasons: vec![problem.explanation()],
            };
            return (trigger, critical.window, recovery.window);
        }
    };
    let pressure: &PressureState = usable.value;
    let holds = |predicate: bool| {
        if predicate {
            WindowEvidence::Holds(usable.qualifying(context.clock, vec!["host".to_owned()]))
        } else {
            WindowEvidence::Contradicts
        }
    };
    let critical: WindowStep = advance(
        &state.critical_window,
        holds(*pressure == required_pressure),
        sustain,
        timing.max_gap,
    );
    let mut latched: bool = state.global_latched || critical.report.qualified;
    // Recovery needs `normal`. A warning state does not satisfy it.
    let recovery: WindowStep = advance(
        &state.recovery_window,
        holds(latched && *pressure == PressureState::Normal),
        timing.recovery_stable,
        timing.max_gap,
    );
    if recovery.report.qualified {
        latched = false;
    }
    let trigger_state: TriggerState = if critical.report.qualified {
        TriggerState::Ready
    } else if *pressure == required_pressure {
        TriggerState::Qualifying
    } else if *pressure == PressureState::Normal {
        if latched {
            TriggerState::Recovering
        } else {
            TriggerState::Normal
        }
    } else if latched {
        TriggerState::Held
    } else {
        TriggerState::Advisory
    };
    let trigger: GlobalPressureTrigger = GlobalPressureTrigger {
        state: trigger_state,
        pressure: Some(pressure.clone()),
        required_pressure,
        evidence,
        corroborating_metrics,
        critical_window: critical.report,
        recovery_window: recovery.report,
        latched,
        reasons: Vec::new(),
    };
    (trigger, critical.window, recovery.window)
}

/// What the snapshot says about the application of a budget.
enum BudgetSubject<'a> {
    /// One verified running instance.
    Running(&'a ApplicationCandidate, Identity<'a>),
    /// The application is known to be absent at this inventory sample.
    Absent(&'a Sample),
    /// The evidence cannot support a decision.
    Unusable(EvidenceProblem),
}

fn budget_subject<'a>(
    context: &EvaluationContext<'_>,
    timing: &Timing,
    budget: &AppBudget,
    snapshot: &'a MemorySnapshot,
) -> BudgetSubject<'a> {
    let bundle_id: &str = budget.bundle_id.as_str();
    let mut running: Vec<(&ApplicationCandidate, Identity<'_>)> = Vec::new();
    for candidate in &snapshot.applications {
        match verified_identity(candidate) {
            Ok(identity) => {
                if identity.kind == ApplicationKind::Application
                    && identity.name.eq_ignore_ascii_case(bundle_id)
                {
                    running.push((candidate, identity));
                }
            }
            // An unverified process that claims the bundle identifier makes
            // the attribution ambiguous.
            Err(_) => {
                if claimed_bundle_ids(candidate)
                    .any(|claimed| claimed.eq_ignore_ascii_case(bundle_id))
                {
                    return BudgetSubject::Unusable(EvidenceProblem::MembershipUnverified);
                }
            }
        }
    }
    match running.as_slice() {
        [(candidate, identity)] => BudgetSubject::Running(candidate, *identity),
        [] => {
            let Some(inventory) = &snapshot.inventory else {
                return BudgetSubject::Unusable(EvidenceProblem::Missing);
            };
            if inventory.coverage != Coverage::Complete {
                return BudgetSubject::Unusable(EvidenceProblem::InventoryIncomplete);
            }
            match sample_age(&inventory.sample, context.clock, timing.max_age) {
                Ok(_) => BudgetSubject::Absent(&inventory.sample),
                Err(problem) => BudgetSubject::Unusable(problem),
            }
        }
        _ => BudgetSubject::Unusable(EvidenceProblem::AmbiguousInstances),
    }
}

/// The measured facts of a budget, before the windows.
struct BudgetFacts {
    level: FootprintLevel,
    footprint: Option<Bytes>,
    instance_id: Option<ApplicationInstanceId>,
    evidence: EvidenceReport,
    /// The sample that can qualify the stop window.
    stop: WindowEvidence,
    /// The sample that can qualify the recovery window, and its duration.
    recovery: WindowEvidence,
    recovery_required: Nanoseconds,
    problem: Option<EvidenceProblem>,
}

fn budget_facts(
    context: &EvaluationContext<'_>,
    timing: &Timing,
    budget: &AppBudget,
    snapshot: &MemorySnapshot,
) -> BudgetFacts {
    let metric_id: MetricId = metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES;
    let unusable = |problem: EvidenceProblem, evidence: EvidenceReport, instance_id| BudgetFacts {
        level: FootprintLevel::Unknown,
        footprint: None,
        instance_id,
        evidence,
        stop: WindowEvidence::Unusable(problem.clone()),
        recovery: WindowEvidence::Unusable(problem.clone()),
        recovery_required: timing.recovery_stable,
        problem: Some(problem),
    };
    match budget_subject(context, timing, budget, snapshot) {
        BudgetSubject::Unusable(problem) => {
            let evidence: EvidenceReport = EvidenceReport::missing(metric_id, problem.clone());
            unusable(problem, evidence, None)
        }
        BudgetSubject::Absent(sample) => {
            // Recovery by exit needs the longer of the recovery stability
            // and the application cooldown.
            let subject: Vec<String> = vec![budget.id.as_str().to_owned(), "absent".to_owned()];
            let mut evidence: EvidenceReport =
                EvidenceReport::missing(metric_id, EvidenceProblem::Missing);
            evidence.problem = None;
            evidence.usable = true;
            evidence.sample_id = Some(sample.sample_id.clone());
            evidence.captured_at = Some(sample.captured_at);
            evidence.sampled_at = Some(sample.started_monotonic_ns);
            evidence.age = context
                .clock
                .now
                .checked_duration_since(sample.started_monotonic_ns);
            BudgetFacts {
                level: FootprintLevel::NotRunning,
                footprint: None,
                instance_id: None,
                evidence,
                stop: WindowEvidence::Contradicts,
                recovery: WindowEvidence::Holds(QualifyingSample {
                    binding: binding(sample, context.clock, subject),
                    at: sample.started_monotonic_ns,
                    sample_id: sample.sample_id.clone(),
                }),
                recovery_required: timing.recovery_stable.max(nanoseconds(budget.cooldown)),
                problem: None,
            }
        }
        BudgetSubject::Running(candidate, identity) => {
            let instance_id: Option<ApplicationInstanceId> = Some(identity.instance_id.clone());
            let scope: Scope = Scope::application(candidate.membership_snapshot.clone());
            let usable = match assess(
                &candidate.footprint,
                &metric_id,
                ScopeCheck::Exact(&scope),
                context.clock,
                timing.max_age,
            ) {
                Ok(usable) => usable,
                Err(problem) => {
                    let evidence: EvidenceReport =
                        evidence_report(&candidate.footprint, context.clock, Some(problem.clone()));
                    return unusable(problem, evidence, instance_id);
                }
            };
            let footprint: Bytes = *usable.value;
            let holds = |predicate: bool| {
                if predicate {
                    let subject: Vec<String> = subject_of(budget.id.as_str(), &identity, candidate);
                    WindowEvidence::Holds(usable.qualifying(context.clock, subject))
                } else {
                    WindowEvidence::Contradicts
                }
            };
            let level: FootprintLevel = if footprint >= budget.footprint_stop {
                FootprintLevel::Stop
            } else if footprint >= budget.footprint_soft {
                FootprintLevel::Soft
            } else {
                FootprintLevel::BelowSoft
            };
            BudgetFacts {
                level,
                footprint: Some(footprint),
                instance_id,
                evidence: evidence_report(&candidate.footprint, context.clock, None),
                stop: holds(footprint >= budget.footprint_stop),
                recovery: holds(footprint <= budget.footprint_recover),
                recovery_required: timing.recovery_stable,
                problem: None,
            }
        }
    }
}

fn evaluate_budget(
    context: &EvaluationContext<'_>,
    timing: &Timing,
    budget: &AppBudget,
    prior: &BudgetState,
    snapshot: &MemorySnapshot,
) -> (BudgetTrigger, BudgetState) {
    let facts: BudgetFacts = budget_facts(context, timing, budget, snapshot);
    let stop: WindowStep = advance(
        &prior.stop_window,
        facts.stop,
        nanoseconds(budget.over_limit_for),
        timing.max_gap,
    );
    let mut latched: bool = prior.latched || stop.report.qualified;
    // The recovery window runs only while an episode is latched.
    let recovery_evidence: WindowEvidence = match facts.recovery {
        WindowEvidence::Holds(_) if !latched => WindowEvidence::Contradicts,
        other => other,
    };
    let recovering: bool = matches!(recovery_evidence, WindowEvidence::Holds(_));
    let recovery: WindowStep = advance(
        &prior.recovery_window,
        recovery_evidence,
        facts.recovery_required,
        timing.max_gap,
    );
    if recovery.report.qualified {
        latched = false;
    }

    let mut reasons: Vec<Explanation> = Vec::new();
    let state: TriggerState = if let Some(problem) = &facts.problem {
        reasons.push(problem.explanation());
        TriggerState::Blocked
    } else if stop.report.qualified {
        TriggerState::Ready
    } else if facts.level == FootprintLevel::Stop {
        TriggerState::Qualifying
    } else if latched && recovering {
        TriggerState::Recovering
    } else if latched {
        TriggerState::Held
    } else if facts.level == FootprintLevel::Soft {
        TriggerState::Advisory
    } else {
        TriggerState::Normal
    };
    let trigger: BudgetTrigger = BudgetTrigger {
        budget_id: budget.id.as_str().to_owned(),
        bundle_id: budget.bundle_id.as_str().to_owned(),
        state,
        level: facts.level,
        advisory: matches!(facts.level, FootprintLevel::Soft | FootprintLevel::Stop),
        footprint: facts.footprint,
        instance_id: facts.instance_id,
        evidence: facts.evidence,
        stop_window: stop.report,
        recovery_window: recovery.report,
        latched,
        reasons,
    };
    let next: BudgetState = BudgetState {
        budget_id: prior.budget_id.clone(),
        stop_window: stop.window,
        recovery_window: recovery.window,
        latched,
    };
    (trigger, next)
}

/// The trigger that admits an intervention.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "trigger", rename_all = "snake_case")]
pub enum AdmissionTrigger {
    /// The global-pressure trigger.
    GlobalPressure,
    /// The budget of the application.
    ApplicationBudget {
        /// The identifier of the budget.
        budget_id: String,
    },
}

/// The decision for one candidate application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationDecision {
    /// The membership snapshot of the candidate.
    pub membership_snapshot: MembershipSnapshotId,
    /// The verified application or job instance.
    pub instance_id: Option<ApplicationInstanceId>,
    /// The verified kind.
    pub kind: Option<ApplicationKind>,
    /// The verified bundle identifier or job label.
    pub name: Option<String>,
    /// The number of processes of the candidate.
    pub process_count: usize,
    /// The foreground status.
    pub foreground: ForegroundStatus,
    /// The identifier of the budget of the application.
    pub budget_id: Option<String>,
    /// The attributed footprint, when the observation is usable.
    pub footprint: Option<Bytes>,
    /// The footprint evidence that the evaluation used.
    pub evidence: EvidenceReport,
    /// The decision.
    pub decision: CandidateDecision,
    /// Each reason, with the primary reason first. Empty for an eligible
    /// candidate.
    pub reasons: Vec<Explanation>,
    /// The position among the eligible candidates, from 1.
    pub rank: Option<u32>,
    /// The qualified triggers that admit an intervention on the candidate
    /// at this snapshot.
    pub admission: Vec<AdmissionTrigger>,
    /// True when the first intervention has the candidate as its target.
    pub first_intervention: bool,
}

/// Whether the intervention can escalate to force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForceEscalation {
    /// The configuration and the assumed grant permit force after the grace
    /// period, for the same target, while the trigger stays qualified.
    Permitted,
    /// `allow_force_quit` is off.
    NotAllowedByPolicy,
    /// The evaluation assumes no `ForceApplicationExit` grant.
    NotGranted,
}

/// The first intervention that an incident would start: one application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstIntervention {
    /// True when no reason inhibits the intervention at this snapshot.
    pub admissible_now: bool,
    /// The reasons that inhibit the intervention at this snapshot.
    pub blocked_by: Vec<Explanation>,
    /// The membership snapshot of the target.
    pub target: Option<MembershipSnapshotId>,
    /// The verified instance of the target.
    pub instance_id: Option<ApplicationInstanceId>,
    /// The trigger that the plan would record as its admission trigger.
    /// `None` when no qualified trigger admits the target now.
    pub admission_trigger: Option<AdmissionTrigger>,
    /// The first step: a graceful exit request.
    pub first_step: &'static str,
    /// The wait before a force step.
    pub grace_period: Nanoseconds,
    /// Whether a force step can follow.
    pub force_escalation: ForceEscalation,
    /// The wait before the measurement after the action.
    pub observe_after_action: Nanoseconds,
    /// The application slots that the incident can still charge.
    pub slots_remaining: u32,
    /// The application ceiling of one incident.
    pub slots_limit: u32,
}

/// The result of [`plan_intervention`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterventionPlan {
    /// The decision for each candidate: the eligible ones in rank sequence,
    /// then the others by membership snapshot.
    pub decisions: Vec<ApplicationDecision>,
    /// The first intervention.
    pub first: FirstIntervention,
}

/// The lists and the settings that the candidate checks use.
struct ApplicationChecks<'a> {
    context: &'a EvaluationContext<'a>,
    guard: &'a MemoryGuard,
    evaluation: &'a MemoryEvaluation,
    protected_paths: PathSet,
    has_protected_paths: bool,
    max_age: Nanoseconds,
}

/// A candidate after the checks.
struct Checked<'a> {
    decision: ApplicationDecision,
    identity: Option<Identity<'a>>,
    group_eligible: bool,
    budget: Option<&'a BudgetTrigger>,
}

impl<'a> ApplicationChecks<'a> {
    fn bundle_protected(&self, candidate: &ApplicationCandidate) -> bool {
        let protections = self.context.config.protections();
        claimed_bundle_ids(candidate).any(|claimed| {
            protections
                .protected_bundle_ids
                .iter()
                .chain(&self.guard.protected_bundle_ids)
                .any(|protected| protected.as_str().eq_ignore_ascii_case(claimed))
        })
    }

    fn group_eligible(&self, kind: ApplicationKind) -> bool {
        let group: EligibleGroup = match kind {
            ApplicationKind::Application => EligibleGroup::BackgroundUserApplications,
            ApplicationKind::ManagedJob => EligibleGroup::ManagedJobs,
        };
        self.guard.eligible_groups.contains(&group)
    }

    /// The reasons that the protections, the eligible scope, and the
    /// identity evidence of a candidate give. `in_scope` is true when the
    /// candidate is in an eligible group or has a budget.
    fn target_reasons(
        &self,
        candidate: &ApplicationCandidate,
        unverified: Option<ReasonDetail>,
        in_scope: bool,
    ) -> Vec<Explanation> {
        use DecisionReason as Reason;
        use ReasonDetail as Detail;
        let mut reasons: Vec<Explanation> = Vec::new();
        let mut add = |reason: Reason, detail: Detail| {
            push_reason(&mut reasons, Explanation::new(reason, detail));
        };
        let executables_known: bool = candidate
            .processes
            .iter()
            .all(|process| process.executable.is_some());

        if candidate.hard_protection == ProtectionFact::Protected {
            add(Reason::HardProtected, Detail::ProductProtection);
        }
        if self.bundle_protected(candidate) {
            add(Reason::UserExcluded, Detail::ProtectedBundleId);
        }
        let path_protected: bool = candidate
            .processes
            .iter()
            .filter_map(|process| process.executable.as_ref())
            .any(|executable| self.protected_paths.covers(&executable.path));
        if path_protected {
            add(Reason::UserExcluded, Detail::ProtectedExecutablePath);
        }
        if self.guard.protect_foreground && candidate.foreground == ForegroundStatus::Foreground {
            add(Reason::UserExcluded, Detail::ForegroundProtected);
        }
        if candidate
            .processes
            .iter()
            .any(|process| process.uid != self.context.principal)
        {
            add(Reason::TargetNotEligible, Detail::OtherUser);
        }
        if unverified.is_none() && !in_scope {
            add(Reason::TargetNotEligible, Detail::GroupNotEligible);
        }
        if candidate.hard_protection == ProtectionFact::Unknown {
            add(Reason::MetricUnavailable, Detail::ProtectionUnknown);
        }
        if self.protected_paths.unresolved {
            add(Reason::MetricUnavailable, Detail::HomeDirectoryUnknown);
        }
        let paths_canonical: bool = candidate
            .processes
            .iter()
            .filter_map(|process| process.executable.as_ref())
            .all(|executable| is_canonical(&executable.path));
        if !paths_canonical {
            add(Reason::MetricUnavailable, Detail::PathNotCanonical);
        }
        if self.has_protected_paths && !executables_known {
            add(Reason::MetricUnavailable, Detail::ExecutableUnknown);
        }
        // An unknown foreground status is not evidence of the background.
        if self.guard.protect_foreground && candidate.foreground == ForegroundStatus::Unknown {
            add(Reason::MetricUnavailable, Detail::ForegroundUnknown);
        }
        if let Some(detail) = unverified {
            add(Reason::MetricUnavailable, detail);
        }
        reasons
    }

    /// Checks one candidate. The reasons are in the sequence of
    /// `docs/POLICY_SPEC.md` section 7: hard protections, user exclusions,
    /// target eligibility, observation quality, and cooldowns.
    fn check(&self, candidate: &'a ApplicationCandidate) -> Checked<'a> {
        let verified: Result<Identity<'a>, ReasonDetail> = verified_identity(candidate);
        let identity: Option<Identity<'a>> = verified.as_ref().ok().copied();
        let budget: Option<&'a BudgetTrigger> = identity.and_then(|identity| {
            self.evaluation.budgets.iter().find(|budget| {
                identity.kind == ApplicationKind::Application
                    && budget.bundle_id.eq_ignore_ascii_case(identity.name)
            })
        });
        let group_eligible: bool =
            identity.is_some_and(|identity| self.group_eligible(identity.kind));
        let mut reasons: Vec<Explanation> = self.target_reasons(
            candidate,
            verified.err(),
            group_eligible || budget.is_some(),
        );
        let mut add = |explanation: Explanation| push_reason(&mut reasons, explanation);

        let scope: Scope = Scope::application(candidate.membership_snapshot.clone());
        let assessed = assess(
            &candidate.footprint,
            &metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES,
            ScopeCheck::Exact(&scope),
            self.context.clock,
            self.max_age,
        );
        let footprint: Option<Bytes> = assessed.as_ref().ok().map(|usable| *usable.value);
        let problem: Option<EvidenceProblem> = assessed.err();
        if let Some(problem) = &problem {
            add(problem.explanation());
        }
        if let Some(identity) = identity {
            let cooldown: Option<Explanation> = self
                .evaluation
                .next_state
                .cooldowns
                .iter()
                .filter(|entry| entry.application.eq_ignore_ascii_case(identity.name))
                .find_map(|entry| entry.cooldown.reason(self.context.clock));
            if let Some(explanation) = cooldown {
                add(explanation);
            }
        }

        let decision: ApplicationDecision = ApplicationDecision {
            membership_snapshot: candidate.membership_snapshot.clone(),
            instance_id: identity.map(|identity| identity.instance_id.clone()),
            kind: identity.map(|identity| identity.kind),
            name: identity.map(|identity| identity.name.to_owned()),
            process_count: candidate.processes.len(),
            foreground: candidate.foreground,
            budget_id: budget.map(|budget| budget.budget_id.clone()),
            footprint,
            evidence: evidence_report(&candidate.footprint, self.context.clock, problem),
            decision: decision_of(&reasons),
            reasons,
            rank: None,
            admission: Vec::new(),
            first_intervention: false,
        };
        Checked {
            decision,
            identity,
            group_eligible,
            budget,
        }
    }

    /// The qualified triggers that admit an intervention on the candidate.
    fn admission(&self, checked: &Checked<'_>) -> Vec<AdmissionTrigger> {
        let mut admission: Vec<AdmissionTrigger> = Vec::new();
        if let (Some(budget), Some(identity)) = (checked.budget, checked.identity)
            && budget.state == TriggerState::Ready
            && budget.instance_id.as_ref() == Some(identity.instance_id)
        {
            admission.push(AdmissionTrigger::ApplicationBudget {
                budget_id: budget.budget_id.clone(),
            });
        }
        if checked.group_eligible && self.evaluation.global.state == TriggerState::Ready {
            admission.push(AdmissionTrigger::GlobalPressure);
        }
        admission
    }
}

/// True when the stop window of the budget is qualified for this instance.
fn budget_violation(checked: &Checked<'_>) -> bool {
    match (checked.budget, checked.identity) {
        (Some(budget), Some(identity)) => {
            budget.stop_window.qualified
                && budget.instance_id.as_ref() == Some(identity.instance_id)
        }
        _ => false,
    }
}

/// The rank key of an eligible candidate: an explicitly configured
/// application first, then a verified budget violation, the larger
/// footprint, and the instance identity.
fn rank_key<'a>(checked: &'a Checked<'_>) -> (bool, bool, Reverse<Bytes>, &'a str) {
    (
        checked.budget.is_none(),
        !budget_violation(checked),
        Reverse(checked.decision.footprint.unwrap_or(Bytes::ZERO)),
        checked
            .identity
            .map_or("", |identity| identity.instance_id.as_str()),
    )
}

/// Decides the eligibility of each candidate application, ranks the
/// eligible ones, and names the first intervention.
///
/// A candidate is eligible when it has no product protection, no protected
/// bundle identifier or executable path, is not a protected foreground
/// application, belongs to the requesting user, has a verified membership
/// for each process, is in an eligible group or has a budget, has a usable
/// footprint, and has no active cooldown.
///
/// The first intervention is what an incident would start first: one
/// application. `blocked_by` tells why it is not admissible at this
/// snapshot. The function reserves no slot.
pub fn plan_intervention(
    context: &EvaluationContext<'_>,
    evaluation: &MemoryEvaluation,
    snapshot: &MemorySnapshot,
) -> InterventionPlan {
    let guard: &MemoryGuard = context.config.memory_guard();
    let protections = context.config.protections();
    let has_protected_paths: bool = !protections.protected_executable_paths.is_empty()
        || !guard.protected_executable_paths.is_empty();
    let checks: ApplicationChecks<'_> = ApplicationChecks {
        context,
        guard,
        evaluation,
        protected_paths: PathSet::resolve(
            protections
                .protected_executable_paths
                .iter()
                .chain(&guard.protected_executable_paths),
            context.home_directory,
        ),
        has_protected_paths,
        max_age: nanoseconds(context.config.agent().decision_sample_max_age),
    };

    let mut checked: Vec<Checked<'_>> = snapshot
        .applications
        .iter()
        .map(|candidate| checks.check(candidate))
        .collect();
    for entry in &mut checked {
        if entry.decision.decision == CandidateDecision::Eligible {
            entry.decision.admission = checks.admission(entry);
        }
    }
    checked.sort_by(|left, right| {
        let excluded = |entry: &Checked<'_>| entry.decision.decision != CandidateDecision::Eligible;
        excluded(left)
            .cmp(&excluded(right))
            .then_with(|| {
                if excluded(left) {
                    std::cmp::Ordering::Equal
                } else {
                    rank_key(left).cmp(&rank_key(right))
                }
            })
            .then_with(|| {
                left.decision
                    .membership_snapshot
                    .cmp(&right.decision.membership_snapshot)
            })
    });
    let mut rank: u32 = 0;
    for entry in &mut checked {
        if entry.decision.decision == CandidateDecision::Eligible {
            rank = rank.saturating_add(1);
            entry.decision.rank = Some(rank);
        }
    }

    let first: FirstIntervention = first_intervention(context, guard, evaluation, &mut checked);
    InterventionPlan {
        decisions: checked.into_iter().map(|entry| entry.decision).collect(),
        first,
    }
}

fn first_intervention(
    context: &EvaluationContext<'_>,
    guard: &MemoryGuard,
    evaluation: &MemoryEvaluation,
    checked: &mut [Checked<'_>],
) -> FirstIntervention {
    let eligible = |entry: &Checked<'_>| entry.decision.decision == CandidateDecision::Eligible;
    // The first eligible candidate that a qualified trigger admits. With no
    // such candidate, the first eligible candidate shows what an incident
    // would start with.
    let target: Option<usize> = checked
        .iter()
        .position(|entry| eligible(entry) && !entry.decision.admission.is_empty())
        .or_else(|| checked.iter().position(eligible));

    let mut blocked_by: Vec<Explanation> =
        context.authority_reasons(guard.enabled, context.grants.request_application_exit);
    let mut admission_trigger: Option<AdmissionTrigger> = None;
    if let Some(entry) = target.and_then(|index| checked.get_mut(index)) {
        entry.decision.first_intervention = true;
        // A budget trigger is independent of the pressure state, so the
        // plan records it when the two triggers admit the application.
        admission_trigger = entry.decision.admission.first().cloned();
        if admission_trigger.is_none() {
            // No qualified trigger admits the target. The reason below
            // makes sure of a blocker also when the evaluation and the
            // snapshot do not agree and no trigger gives a reason.
            let before: usize = blocked_by.len();
            if let Some(budget) = entry.budget {
                for reason in &budget.reasons {
                    push_reason(&mut blocked_by, *reason);
                }
            }
            if entry.group_eligible {
                for reason in &evaluation.global.reasons {
                    push_reason(&mut blocked_by, *reason);
                }
            }
            if blocked_by.len() == before {
                blocked_by.push(Explanation::new(
                    DecisionReason::TriggerNotSustained,
                    ReasonDetail::PredicateNotTrue,
                ));
            }
        }
    } else {
        for reason in &evaluation.global.reasons {
            push_reason(&mut blocked_by, *reason);
        }
        push_reason(
            &mut blocked_by,
            Explanation::new(
                DecisionReason::TargetNotEligible,
                ReasonDetail::NoEligibleCandidate,
            ),
        );
    }
    if evaluation.slots_remaining == 0 {
        push_reason(
            &mut blocked_by,
            Explanation::new(
                DecisionReason::BudgetExhausted,
                ReasonDetail::ApplicationSlotsExhausted,
            ),
        );
    }
    let entry: Option<&Checked<'_>> = target.and_then(|index| checked.get(index));
    FirstIntervention {
        admissible_now: blocked_by.is_empty(),
        blocked_by,
        target: entry.map(|entry| entry.decision.membership_snapshot.clone()),
        instance_id: entry.and_then(|entry| entry.decision.instance_id.clone()),
        admission_trigger,
        first_step: "request_application_exit",
        grace_period: nanoseconds(guard.grace_period),
        force_escalation: if !guard.allow_force_quit {
            ForceEscalation::NotAllowedByPolicy
        } else if context.grants.force_application_exit {
            ForceEscalation::Permitted
        } else {
            ForceEscalation::NotGranted
        },
        observe_after_action: nanoseconds(guard.observe_after_action),
        slots_remaining: evaluation.slots_remaining,
        slots_limit: guard.max_applications_per_incident.get(),
    }
}
