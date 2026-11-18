//! The step function of the controller.
//!
//! [`step`] is pure: it reads no clock, no file, and no process. The
//! runtime gives the time and the observations and carries out the
//! intents.

use std::time::Duration;

use serde::Serialize;
use svalnir_core::action::{
    ActionClass, BudgetScope, ClientRole, Plan, PlanContent, Principal, ScopedAllowance,
    SlotAllowance, Trigger, WorkAllowance, WorkBudget, WorkCharge,
};
use svalnir_core::authority::{ActionGrant, AuthorityBinding};
use svalnir_core::grant::{
    AuthorityState, ControlClock, GuardStanding, IncidentBudget, PauseStatus, guard_standing,
    pause_status,
};
use svalnir_core::id::{DecisionId, IncidentId, PlanId, RuleId, StepId, TargetId, VolumeId};
use svalnir_core::plan::{
    CleanupEntry, CleanupLimits, CleanupRequest, ModeSelection, PlanBuildError, PlanContext,
    PlanOutcome, RuleEvidence, StopLimits, StopRequest, StopStepIds, StopStrategy,
    build_cleanup_plan, build_stop_plan,
};
use svalnir_core::policy::{
    AdmissionTrigger, ApplicationCandidate, ApplicationCooldown, AssumedGrants, CapacityDomainKey,
    CleanupCandidate, Cooldown, CooldownCause, CooldownStatus, DecisionReason, DiskEvaluation,
    DiskIncident, DiskSnapshot, EvaluationContext, Explanation, ForceEscalation, GrantBasis,
    MemoryEvaluation, PolicyId, ProtectionContext, ReasonDetail, RuleAllowance, RuleReadiness,
    TriggerState, VolumeTrigger, WorkUsage, evaluate_disk_guard, evaluate_memory_guard,
    plan_cleanup, plan_intervention,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{Rule, RuleMode, RuleRef, RuleRefusal};
use svalnir_core::time::MonotonicNanos;

use super::model::{
    ApplyReport, AutomaticApply, BlockedReason, CONTROLLER_STATUS_VERSION, CandidateSet,
    ControllerState, ControllerStatus, DiskIncidentRecord, Guard, GuardPhase, GuardStatus,
    IncidentStatus, Intent, MAX_APPLICATION_COOLDOWNS, MAX_PREPARED_CANDIDATES, MAX_REPORTS,
    MAX_STATUS_REASONS, MemoryIncidentRecord, MonotonicMark, Notification, OperationResult,
    Outstanding, PreparationMode, PreparedCandidate, QuietMark, ReduceReason, ReportedCondition,
    RuleUsage, StepInput, StepOutput, Summary, TriggerKey, TriggerRecord, stamp,
};
use crate::coordinator::{IncidentAllowance, Pacing, TriggerStanding};

/// The time in which an executor observes the result of one call.
const VERIFICATION_WINDOW: Nanoseconds = Nanoseconds::new(5_000_000_000);

/// The margin of the execution deadline of an application plan above its
/// grace period and its two verification windows.
const DEADLINE_MARGIN: Nanoseconds = Nanoseconds::new(5_000_000_000);

/// The age above which a candidate set is prepared again as optional
/// work.
const CANDIDATE_REFRESH_AGE: Nanoseconds = Nanoseconds::new(900_000_000_000);

/// The largest multiple of the base cooldown that the backoff of an
/// incident reaches.
const MAX_BACKOFF_FACTOR: u64 = 8;

/// The value of a duration of the configuration. A duration that does not
/// fit is the largest value, which is the safe direction for a wait.
fn nanoseconds(duration: Duration) -> Nanoseconds {
    Nanoseconds::try_from(duration).unwrap_or(Nanoseconds::new(u64::MAX))
}

/// The JSON spelling of a value that serializes as one string.
fn wire<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

fn reason_text(explanation: Explanation) -> String {
    format!(
        "{}:{}",
        explanation.reason.as_str(),
        wire(&explanation.detail)
    )
}

/// A time after `now`. A sum that does not fit is the largest time.
fn after(now: MonotonicNanos, wait: Nanoseconds) -> MonotonicNanos {
    now.checked_add(wait)
        .unwrap_or(MonotonicNanos::new(u64::MAX))
}

/// Whether a cooldown inhibits work now. A cooldown of a different boot
/// or clock domain is not comparable and still inhibits: a restart does
/// not shorten a cooldown.
fn inhibits(cooldown: Option<&Cooldown>, input: &StepInput<'_>) -> bool {
    cooldown.is_some_and(|cooldown| {
        !matches!(cooldown.status(&input.time.clock), CooldownStatus::Elapsed)
    })
}

fn cooldown(cause: CooldownCause, until: MonotonicNanos, input: &StepInput<'_>) -> Cooldown {
    Cooldown {
        cause,
        until,
        clock_domain: input.time.clock.clock_domain.clone(),
        boot_id: input.time.clock.boot_id.clone(),
    }
}

/// The evaluation of the disk guard with the snapshot that it read.
struct DiskView {
    evaluation: DiskEvaluation,
    snapshot: DiskSnapshot,
}

/// The working values of one step.
struct Run<'a> {
    input: &'a StepInput<'a>,
    state: ControllerState,
    intents: Vec<Intent>,
    blocked: Vec<(Guard, BlockedReason)>,
    degraded: Vec<String>,
    triggers: Vec<TriggerRecord>,
    paused_until: Option<svalnir_core::time::WallTime>,
    /// True when this step made an apply intent.
    applied: bool,
}

impl<'a> Run<'a> {
    fn now(&self) -> MonotonicNanos {
        self.input.time.clock.now
    }

    fn block(&mut self, guard: Guard, reason: BlockedReason) {
        if !self
            .blocked
            .iter()
            .any(|(known, text)| *known == guard && *text == reason)
        {
            self.blocked.push((guard, reason));
        }
    }

    fn next_sequence(&mut self) -> u64 {
        self.state.sequence = self.state.sequence.saturating_add(1);
        self.state.sequence
    }

    fn standing(&self, guard: Guard) -> Option<GuardStanding> {
        self.input.authority.map(|authority| {
            guard_standing(
                authority,
                self.input.inhibition,
                guard.policy(),
                self.input.time.wall,
            )
        })
    }

    fn grant(&self, guard: Guard) -> Option<&'a ActionGrant> {
        if self.standing(guard) != Some(GuardStanding::Active) {
            return None;
        }
        self.input
            .authority
            .and_then(|authority| authority.guard(guard.policy()))
            .and_then(|guard| guard.grant.as_ref())
    }

    fn covers(&self, guard: Guard, class: &ActionClass) -> bool {
        self.grant(guard)
            .is_some_and(|grant| grant.covers_class(class, self.input.time.wall))
    }

    fn context(&self) -> EvaluationContext<'a> {
        EvaluationContext {
            config: self.input.config,
            clock: &self.input.time.clock,
            grants: AssumedGrants {
                basis: GrantBasis::Recorded,
                evict_regenerable_data: self
                    .covers(Guard::Disk, &ActionClass::EvictRegenerableData),
                request_application_exit: self
                    .covers(Guard::Memory, &ActionClass::RequestApplicationExit),
                force_application_exit: self
                    .covers(Guard::Memory, &ActionClass::ForceApplicationExit),
            },
            principal: self.input.principal,
            home_directory: self.input.home_directory,
        }
    }

    /// Reads the pause and records its end.
    fn pause(&mut self) {
        let control: ControlClock<'_> = ControlClock {
            clock: &self.input.time.clock,
            wall: self.input.time.wall,
        };
        let pauses = [
            self.input
                .authority
                .and_then(|authority| authority.pause.as_ref()),
            self.input.inhibition.pause.as_ref(),
        ];
        // The end that the status shows is the latest end. With a pause
        // that has no end, the status shows none.
        let mut in_effect: bool = false;
        let mut no_end: bool = false;
        // The expiry of a pause that ended between two steps. No step saw
        // that pause in effect, so the change of `paused` does not show it.
        let mut expiry: Option<MonotonicNanos> = None;
        for pause in pauses {
            match pause_status(pause, &control) {
                PauseStatus::Paused { until, .. } => {
                    in_effect = true;
                    no_end |= until.is_none();
                    self.paused_until = self.paused_until.max(until);
                }
                PauseStatus::Expired { floor, .. } => expiry = expiry.max(floor),
                PauseStatus::NotPaused => {}
            }
        }
        if no_end {
            self.paused_until = None;
        }
        if let Some(expiry) = expiry {
            // Expiry only allows reevaluation: evidence from before it
            // supports no automatic action.
            let known: Option<MonotonicNanos> = self
                .state
                .measurement_floor
                .as_ref()
                .filter(|mark| {
                    mark.clock_domain == self.input.time.clock.clock_domain
                        && mark.boot_id == self.input.time.clock.boot_id
                })
                .map(|mark| mark.at);
            if known.is_none_or(|known| known < expiry) {
                self.state.measurement_floor = Some(MonotonicMark {
                    at: expiry,
                    clock_domain: self.input.time.clock.clock_domain.clone(),
                    boot_id: self.input.time.clock.boot_id.clone(),
                });
            }
        }
        if self.state.paused && !in_effect {
            // A resume takes a fresh measurement first: evidence from
            // before this time supports no automatic action.
            self.state.measurement_floor = Some(MonotonicMark {
                at: self.now(),
                clock_domain: self.input.time.clock.clock_domain.clone(),
                boot_id: self.input.time.clock.boot_id.clone(),
            });
        }
        self.state.paused = in_effect;
    }

    /// The end of the latest pause, when it is a time of this boot.
    fn floor(&self) -> Option<MonotonicNanos> {
        let own: Option<MonotonicNanos> = self
            .state
            .measurement_floor
            .as_ref()
            .filter(|mark| {
                mark.clock_domain == self.input.time.clock.clock_domain
                    && mark.boot_id == self.input.time.clock.boot_id
            })
            .map(|mark| mark.at);
        let instance: Option<MonotonicNanos> = self
            .input
            .inhibition
            .measurement_floor
            .as_ref()
            .map(|floor| floor.at);
        own.max(instance)
    }

    /// True when a measurement at `sampled_at` is newer than the end of
    /// the latest pause. A measurement with no time is not.
    fn is_fresh(&self, sampled_at: Option<MonotonicNanos>) -> bool {
        match (self.floor(), sampled_at) {
            (None, Some(_)) => true,
            (Some(floor), Some(sampled_at)) => sampled_at >= floor,
            (_, None) => false,
        }
    }

    // The reports of the plans of earlier steps.

    fn reports(&mut self) {
        let reports: &[ApplyReport] = self.input.reports;
        if reports.len() > MAX_REPORTS {
            // A report that is not read is not a normal state: its plan
            // stays in progress.
            self.degraded.push("reports_dropped".to_owned());
        }
        for report in reports.iter().take(MAX_REPORTS) {
            let plan_id: &PlanId = match report {
                ApplyReport::Admitted { plan_id, .. }
                | ApplyReport::Refused { plan_id, .. }
                | ApplyReport::Finished { plan_id, .. } => plan_id,
            };
            let Some(outstanding) = self
                .state
                .outstanding
                .clone()
                .filter(|outstanding| &outstanding.plan_id == plan_id)
            else {
                continue;
            };
            match report {
                ApplyReport::Admitted { operation_id, .. } => {
                    if let Some(known) = &mut self.state.outstanding {
                        known.operation_id = Some(operation_id.clone());
                    }
                    self.set_refusal(&outstanding, None);
                }
                ApplyReport::Refused { code, .. } => {
                    self.settle(&outstanding, false);
                    let refusals: u32 = self.set_refusal(&outstanding, Some(code.clone()));
                    // The next plan waits for one observation window, so
                    // that a refusal does not make a loop of plans. The
                    // wait doubles with each refusal in sequence, to a
                    // maximum: an action that is not permitted is not
                    // tried again at a constant rate.
                    let doublings: u32 = refusals.saturating_sub(1).min(16);
                    let factor: u64 = 1_u64
                        .checked_shl(doublings)
                        .unwrap_or(MAX_BACKOFF_FACTOR)
                        .min(MAX_BACKOFF_FACTOR);
                    self.observe(&outstanding, factor);
                }
                ApplyReport::Finished { result, .. } => self.finished(&outstanding, result),
            }
        }
    }

    /// Records the refusal code of the latest plan of an incident, or
    /// removes it after an admission. Returns the number of refusals in
    /// sequence.
    fn set_refusal(&mut self, outstanding: &Outstanding, code: Option<String>) -> u32 {
        let count = |refusals: u32| {
            if code.is_some() {
                refusals.saturating_add(1)
            } else {
                0
            }
        };
        match outstanding.guard {
            Guard::Disk => {
                if let Some(record) = self
                    .state
                    .disk_incidents
                    .iter_mut()
                    .find(|record| record.incident_id == outstanding.incident_id)
                {
                    record.refusals = count(record.refusals);
                    record.last_refusal = code;
                    return record.refusals;
                }
            }
            Guard::Memory => {
                if let Some(record) = &mut self.state.memory_incident {
                    record.refusals = count(record.refusals);
                    record.last_refusal = code;
                    return record.refusals;
                }
            }
        }
        0
    }

    /// Starts the observation window after an action of the incident of
    /// `outstanding`. The window is `factor` times the configured time.
    fn observe(&mut self, outstanding: &Outstanding, factor: u64) {
        let guard_wait: Duration = match outstanding.guard {
            Guard::Disk => self.input.config.disk_guard().observe_after_action,
            Guard::Memory => self.input.config.memory_guard().observe_after_action,
        };
        let wait: Nanoseconds =
            Nanoseconds::new(nanoseconds(guard_wait).get().saturating_mul(factor));
        let until: Cooldown = cooldown(
            CooldownCause::PassPacing,
            after(self.now(), wait),
            self.input,
        );
        match outstanding.guard {
            Guard::Disk => {
                if let Some(record) = self
                    .state
                    .disk_incidents
                    .iter_mut()
                    .find(|record| record.incident_id == outstanding.incident_id)
                {
                    record.observe_until = Some(until);
                }
            }
            Guard::Memory => {
                if let Some(record) = &mut self.state.memory_incident {
                    record.observe_until = Some(until);
                }
            }
        }
    }

    /// Ends the reservation of a plan: the charge is consumed when a call
    /// was possibly submitted, and is released in each other case.
    fn settle(&mut self, outstanding: &Outstanding, charged: bool) {
        self.state.outstanding = None;
        match outstanding.guard {
            Guard::Disk => {
                let Some(record) = self
                    .state
                    .disk_incidents
                    .iter_mut()
                    .find(|record| record.incident_id == outstanding.incident_id)
                else {
                    return;
                };
                let domain: CapacityDomainKey = record.domain.clone();
                if !charged {
                    for used in &outstanding.rules {
                        if let Some(entry) = record
                            .rule_usage
                            .iter_mut()
                            .find(|entry| entry.rule_id == used.rule_id)
                        {
                            entry.charge = entry
                                .charge
                                .checked_sub(used.charge)
                                .unwrap_or(WorkCharge::ZERO);
                        }
                    }
                }
                let total: WorkCharge = outstanding
                    .rules
                    .iter()
                    .fold(WorkCharge::ZERO, |sum, used| {
                        sum.checked_add(used.charge).unwrap_or(sum)
                    });
                let Some(incident) = self
                    .state
                    .policy
                    .disk
                    .incidents
                    .iter_mut()
                    .find(|incident| incident.domain == domain)
                else {
                    return;
                };
                incident.outstanding_operation = false;
                unreserve(&mut incident.usage, total, charged);
                if let Some(pass) = &mut incident.current_pass {
                    unreserve(pass, total, charged);
                }
            }
            Guard::Memory => {
                if let Some(incident) = &mut self.state.policy.memory.incident {
                    incident.outstanding_operation = false;
                    incident.reserved_slots = incident.reserved_slots.saturating_sub(1);
                    if charged {
                        incident.consumed_slots = incident.consumed_slots.saturating_add(1);
                    }
                }
            }
        }
    }

    /// Records the result of an eviction plan. Returns whether its
    /// benefit was low.
    fn finished_disk(&mut self, outstanding: &Outstanding, result: &OperationResult) -> bool {
        let now: MonotonicNanos = self.now();
        // An unavailable measurement is not a benefit.
        let gained: bool = result.capacity_gain.is_some_and(|gain| gain.get() > 0);
        let low: bool = result.possibly_submitted && !gained;
        let guard = self.input.config.disk_guard();
        let record: Option<&mut DiskIncidentRecord> = self
            .state
            .disk_incidents
            .iter_mut()
            .find(|record| record.incident_id == outstanding.incident_id);
        let Some(record) = record else {
            return false;
        };
        record.unknown_outcome |= result.unknown_outcome;
        let domain: CapacityDomainKey = record.domain.clone();
        let incident: Option<&mut DiskIncident> = self
            .state
            .policy
            .disk
            .incidents
            .iter_mut()
            .find(|incident| incident.domain == domain);
        let pass_full: bool = incident
            .as_ref()
            .and_then(|incident| incident.current_pass.as_ref())
            .is_some_and(|pass| {
                let used: WorkCharge = charged(pass);
                used.work_bytes >= guard.pass_limit || used.items >= guard.pass_item_limit
            });
        // The pass ends with a low benefit, with a cooldown of the
        // coordinator, and when it used its ceiling. The next
        // pass starts after its cooldown, with the candidates
        // that are authorized then; nothing gets wider.
        let ending: Option<Cooldown> = if low || result.cooldown_until.is_some() {
            let own: MonotonicNanos = after(now, nanoseconds(guard.no_effect_backoff));
            let until: MonotonicNanos = result
                .cooldown_until
                .map_or(own, |given| if low { given.max(own) } else { given });
            Some(cooldown(CooldownCause::NoEffectBackoff, until, self.input))
        } else if pass_full {
            Some(cooldown(
                CooldownCause::PassPacing,
                after(now, nanoseconds(guard.pass_cooldown)),
                self.input,
            ))
        } else {
            None
        };
        if let (Some(ending), Some(incident)) = (ending, incident) {
            incident.current_pass = None;
            incident.cooldown = Some(ending);
            if let Some(record) = self
                .state
                .disk_incidents
                .iter_mut()
                .find(|record| record.incident_id == outstanding.incident_id)
            {
                record.rule_usage.clear();
            }
        }
        low
    }

    /// Records the result of an application stop. Returns whether its
    /// benefit was low.
    fn finished_memory(&mut self, outstanding: &Outstanding, result: &OperationResult) -> bool {
        let now: MonotonicNanos = self.now();
        let improved: bool = result.pressure_after.as_ref().is_some_and(|pressure| {
            !matches!(pressure, svalnir_core::state::PressureState::Critical)
                && pressure.is_recognized()
        });
        let low: bool = result.possibly_submitted && (!improved || !result.completed);
        let guard = self.input.config.memory_guard();
        if result.possibly_submitted
            && let Some(application) = &outstanding.application
        {
            // The relaunch cooldown has the stable identity of the
            // application, so a new process does not evade it.
            let wait: Duration = match &outstanding.trigger {
                TriggerKey::Budget { budget_id } => guard
                    .app_budgets
                    .iter()
                    .find(|budget| budget.id.as_str() == budget_id)
                    .map_or(guard.recovery_stable_for, |budget| budget.cooldown),
                _ => guard.recovery_stable_for,
            };
            let cooldowns = &mut self.state.policy.memory.cooldowns;
            cooldowns.retain(|entry| !entry.application.eq_ignore_ascii_case(application));
            if cooldowns.len() >= MAX_APPLICATION_COOLDOWNS {
                // Each kept cooldown is in effect. The one that ends first
                // is removed, so that no later cooldown outlives a longer
                // one that was removed.
                let first_to_end: Option<usize> = cooldowns
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.cooldown.until)
                    .map(|(index, _)| index);
                if let Some(index) = first_to_end {
                    cooldowns.remove(index);
                }
            }
            cooldowns.push(ApplicationCooldown {
                application: application.clone(),
                cooldown: cooldown(
                    CooldownCause::ApplicationRelaunch,
                    after(now, nanoseconds(wait)),
                    self.input,
                ),
            });
        }
        let backoff: Option<Cooldown> = if low || result.cooldown_until.is_some() {
            let own: MonotonicNanos = after(now, nanoseconds(guard.observe_after_action));
            Some(cooldown(
                CooldownCause::NoEffectBackoff,
                result.cooldown_until.map_or(own, |given| given.max(own)),
                self.input,
            ))
        } else {
            None
        };
        if let Some(record) = &mut self.state.memory_incident {
            record.unknown_outcome |= result.unknown_outcome;
            record.backoff = backoff;
        }
        low
    }

    fn finished(&mut self, outstanding: &Outstanding, result: &OperationResult) {
        self.settle(outstanding, result.possibly_submitted);
        self.observe(outstanding, 1);
        let low_benefit: bool = match outstanding.guard {
            Guard::Disk => self.finished_disk(outstanding, result),
            Guard::Memory => self.finished_memory(outstanding, result),
        };
        self.intents.push(Intent::Notify(Notification::Finished {
            guard: outstanding.guard,
            plan_id: outstanding.plan_id.clone(),
            state: result.state.clone(),
            low_benefit,
        }));
    }

    // The evaluation.

    /// The usable candidate set: complete, not older than the decision
    /// age, and not older than the end of the latest pause.
    fn usable_candidates(&self) -> Option<&'a CandidateSet> {
        let set: &CandidateSet = self.input.observations.candidates.as_ref()?;
        let max_age: Nanoseconds = nanoseconds(self.input.config.agent().decision_sample_max_age);
        let age: Nanoseconds = self.now().checked_duration_since(set.prepared_at)?;
        let usable: bool = set.complete
            && set.candidates.len() <= MAX_PREPARED_CANDIDATES
            && age <= max_age
            && self.is_fresh(Some(set.prepared_at));
        usable.then_some(set)
    }

    /// The candidate of the policy evaluation for a prepared candidate.
    /// The readiness of the rule is never better than the registry says
    /// for automatic eviction.
    fn policy_candidate(&self, prepared: &PreparedCandidate) -> CleanupCandidate {
        let mut candidate: CleanupCandidate = prepared.candidate.candidate.clone();
        match self.input.registry.resolve(
            &prepared.candidate.rule,
            &prepared.candidate.layout,
            &RuleMode::AutomaticEviction,
        ) {
            Ok(_) => {}
            Err(RuleRefusal::ModeNotValidated | RuleRefusal::UnknownLayout) => {
                candidate.facts.rule_readiness = RuleReadiness::NotReady;
            }
            Err(RuleRefusal::UnknownRule | RuleRefusal::UnknownRevision) => {
                candidate.facts.rule_readiness = RuleReadiness::VersionUnapproved;
            }
        }
        candidate
    }

    /// What remains of the pass ceiling of each rule of the candidates.
    fn rule_allowances(&self, set: &CandidateSet) -> Vec<RuleAllowance> {
        let mut allowances: Vec<RuleAllowance> = Vec::new();
        for prepared in &set.candidates {
            let reference: &RuleRef = &prepared.candidate.rule;
            if allowances
                .iter()
                .any(|allowance| allowance.rule_id == reference.id)
            {
                continue;
            }
            let Some(rule) = self.input.registry.rule(reference) else {
                continue;
            };
            // The largest usage of the rule in an open incident.
            let used: WorkCharge = self
                .state
                .disk_incidents
                .iter()
                .flat_map(|record| &record.rule_usage)
                .filter(|usage| usage.rule_id == reference.id)
                .fold(WorkCharge::ZERO, |largest, usage| WorkCharge {
                    work_bytes: largest.work_bytes.max(usage.charge.work_bytes),
                    items: largest.items.max(usage.charge.items),
                });
            let left: WorkCharge = rule
                .budget
                .per_pass
                .checked_sub(used)
                .unwrap_or(WorkCharge::ZERO);
            allowances.push(RuleAllowance {
                rule_id: reference.id.clone(),
                remaining_bytes: left.work_bytes,
                remaining_items: left.items,
            });
        }
        allowances
    }

    fn evaluate_disk(&mut self) -> Option<DiskView> {
        let set: Option<&CandidateSet> = self.usable_candidates();
        let snapshot: DiskSnapshot = DiskSnapshot {
            volumes: self.input.observations.volumes.clone(),
            candidates: set.map_or_else(Vec::new, |set| {
                set.candidates
                    .iter()
                    .map(|prepared| self.policy_candidate(prepared))
                    .collect()
            }),
            rule_allowances: set.map_or_else(Vec::new, |set| self.rule_allowances(set)),
        };
        let evaluation: DiskEvaluation =
            match evaluate_disk_guard(&self.context(), &self.state.policy.disk, &snapshot) {
                Ok(evaluation) => evaluation,
                Err(error) => {
                    self.degraded.push(format!("disk_guard_input: {error}"));
                    return None;
                }
            };
        self.state.policy.disk = evaluation.next_state.clone();
        self.sync_disk_incidents();
        for trigger in &evaluation.volumes {
            let Some(volume_id) = &trigger.volume_id else {
                continue;
            };
            let qualified: bool =
                trigger.entry_window.qualified || trigger.emergency_window.qualified;
            let standing: TriggerStanding = match (qualified, trigger.evidence.sampled_at) {
                (true, Some(sampled_at)) => {
                    TriggerStanding::Holds(stamp(self.input.time, sampled_at))
                }
                (true, None) => TriggerStanding::Unknown,
                (false, _) if trigger.state == TriggerState::Blocked => TriggerStanding::Unknown,
                (false, _) => TriggerStanding::Cleared,
            };
            self.triggers.push(TriggerRecord {
                key: TriggerKey::Disk {
                    volume_id: volume_id.clone(),
                },
                standing,
            });
        }
        Some(DiskView {
            evaluation,
            snapshot,
        })
    }

    fn open_budget(&self, incident_id: &IncidentId, policy: PolicyId) -> IncidentBudget {
        let empty: AuthorityState = AuthorityState::new(self.input.principal);
        IncidentBudget::open(
            incident_id.clone(),
            policy,
            self.input.authority.unwrap_or(&empty),
            self.input.inhibition,
            self.input.time.wall,
        )
    }

    fn incident_id(&mut self, guard: Guard) -> Option<IncidentId> {
        let sequence: u64 = self.next_sequence();
        IncidentId::new(format!(
            "incident-{}-{}-{sequence}",
            guard.tag(),
            self.input.epoch
        ))
        .ok()
    }

    /// Makes a record for each incident that the evaluation opened, and
    /// removes the record of each incident that it closed.
    fn sync_disk_incidents(&mut self) {
        let domains: Vec<CapacityDomainKey> = self
            .state
            .policy
            .disk
            .incidents
            .iter()
            .map(|incident| incident.domain.clone())
            .collect();
        self.state
            .disk_incidents
            .retain(|record| domains.contains(&record.domain));
        for domain in domains {
            if self.state.disk_incident(&domain).is_some() {
                continue;
            }
            let Some(incident_id) = self.incident_id(Guard::Disk) else {
                self.degraded.push("incident_identity".to_owned());
                continue;
            };
            let budget: IncidentBudget = self.open_budget(&incident_id, PolicyId::DiskGuard);
            self.state.disk_incidents.push(DiskIncidentRecord {
                incident_id,
                domain,
                budget,
                opened_in: self.input.epoch.clone(),
                established: true,
                unknown_outcome: false,
                rule_usage: Vec::new(),
                observe_until: None,
                last_refusal: None,
                refusals: 0,
            });
        }
    }

    fn evaluate_memory(&mut self) -> Option<MemoryEvaluation> {
        // An elapsed cooldown has no further use.
        let clock = &self.input.time.clock;
        self.state
            .policy
            .memory
            .cooldowns
            .retain(|entry| !matches!(entry.cooldown.status(clock), CooldownStatus::Elapsed));
        let evaluation: MemoryEvaluation = match evaluate_memory_guard(
            &self.context(),
            &self.state.policy.memory,
            &self.input.observations.memory,
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                self.degraded.push(format!("memory_guard_input: {error}"));
                return None;
            }
        };
        self.state.policy.memory = evaluation.next_state.clone();
        match (
            self.state.policy.memory.incident.is_some(),
            self.state.memory_incident.is_some(),
        ) {
            (true, false) => match self.incident_id(Guard::Memory) {
                Some(incident_id) => {
                    let budget: IncidentBudget =
                        self.open_budget(&incident_id, PolicyId::MemoryGuard);
                    self.state.memory_incident = Some(MemoryIncidentRecord {
                        incident_id,
                        budget,
                        opened_in: self.input.epoch.clone(),
                        established: true,
                        unknown_outcome: false,
                        observe_until: None,
                        backoff: None,
                        last_refusal: None,
                        refusals: 0,
                    });
                }
                None => self.degraded.push("incident_identity".to_owned()),
            },
            (false, true) => self.state.memory_incident = None,
            _ => {}
        }
        let record =
            |qualified: bool, state: TriggerState, sampled_at: Option<MonotonicNanos>| match (
                qualified, sampled_at,
            ) {
                (true, Some(sampled_at)) => {
                    TriggerStanding::Holds(stamp(self.input.time, sampled_at))
                }
                (true, None) => TriggerStanding::Unknown,
                (false, _) if state == TriggerState::Blocked => TriggerStanding::Unknown,
                (false, _) => TriggerStanding::Cleared,
            };
        let global = &evaluation.global;
        let mut triggers: Vec<TriggerRecord> = vec![TriggerRecord {
            key: TriggerKey::GlobalMemory,
            standing: record(
                global.critical_window.qualified,
                global.state,
                global.evidence.sampled_at,
            ),
        }];
        for budget in &evaluation.budgets {
            triggers.push(TriggerRecord {
                key: TriggerKey::Budget {
                    budget_id: budget.budget_id.clone(),
                },
                standing: record(
                    budget.stop_window.qualified,
                    budget.state,
                    budget.evidence.sampled_at,
                ),
            });
        }
        self.triggers.extend(triggers);
        Some(evaluation)
    }

    // The decisions.

    /// The conditions that inhibit each automatic action of a guard, in
    /// the sequence of their precedence. `None` permits the next check.
    fn gate(&self, guard: Guard) -> Option<BlockedReason> {
        if self.input.health.stopping {
            return Some(BlockedReason::AgentStopping);
        }
        if self.input.authority.is_none() {
            return Some(BlockedReason::ObservationOnly);
        }
        if self.input.health.restart_backoff {
            return Some(BlockedReason::RestartBackoff);
        }
        if self.state.paused {
            return Some(BlockedReason::Paused);
        }
        if self.state.held_until_recovery.contains(&guard) {
            return Some(BlockedReason::HeldUntilRecovery);
        }
        match self.standing(guard) {
            Some(GuardStanding::Active) => {}
            Some(standing) => {
                return Some(BlockedReason::GuardNotActive {
                    standing: wire(&standing),
                });
            }
            None => return Some(BlockedReason::ObservationOnly),
        }
        match &self.state.outstanding {
            Some(outstanding) if outstanding.guard != guard => {
                return Some(BlockedReason::OtherGuardActing);
            }
            None if self.applied => return Some(BlockedReason::OtherGuardActing),
            _ => {}
        }
        None
    }

    fn plan_context(&self, plan_id: PlanId, authority: &AuthorityState) -> Option<PlanContext<'a>> {
        let active = authority.active.as_ref()?;
        Some(PlanContext {
            plan_id,
            principal: Principal {
                uid: self.input.principal,
                session: None,
                role: ClientRole::Agent,
            },
            // The builder makes a plan with no grant. The grant of the
            // guard is added with the automatic trigger.
            authority: AuthorityBinding {
                policy_revision: active.revision.revision_id.clone(),
                action_grants: Vec::new(),
                privilege_grant: None,
            },
            clock: &self.input.time.clock,
            created_wall: self.input.time.wall,
            lifetime: nanoseconds(self.input.config.agent().plan_ttl),
            protections: self.input.config.protections(),
            home_directory: self.input.home_directory,
        })
    }

    /// Makes the automatic plan from the plan of a builder: the same
    /// targets, steps, limits, and validity, with the trigger of the
    /// incident and the current grant of the guard.
    fn automatic_plan(
        &mut self,
        guard: Guard,
        built: &Plan,
        trigger: &TriggerKey,
        incident_id: &IncidentId,
    ) -> Result<Plan, String> {
        let grant: &ActionGrant = self
            .grant(guard)
            .ok_or("the guard has no grant in effect")?;
        let sequence: u64 = self.next_sequence();
        let decision_id: DecisionId =
            DecisionId::new(format!("decision-{}-{sequence}", self.input.epoch))
                .map_err(|error| error.to_string())?;
        let mut content: PlanContent = PlanContent::clone(built);
        content.trigger = Trigger {
            class: trigger.class(),
            incident_id: Some(incident_id.clone()),
            decision_id: Some(decision_id),
        };
        content.authority.action_grants = vec![grant.reference()];
        Plan::seal(content).map_err(|error| error.to_string())
    }

    fn plan_ids(&mut self, guard: Guard) -> Result<(PlanId, String), String> {
        let sequence: u64 = self.next_sequence();
        let text: String = format!("auto-{}-{}-{sequence}", guard.tag(), self.input.epoch);
        PlanId::new(text.clone())
            .map(|plan_id| (plan_id, text))
            .map_err(|error| error.to_string())
    }

    /// The condition of an incident record that inhibits its next action.
    fn record_block(
        &self,
        established: bool,
        unknown_outcome: bool,
        observe_until: Option<&Cooldown>,
        last_refusal: Option<&String>,
    ) -> Option<BlockedReason> {
        if !established {
            return Some(BlockedReason::IncidentStateNotEstablished);
        }
        if unknown_outcome {
            return Some(BlockedReason::UnknownPriorOutcome);
        }
        if inhibits(observe_until, self.input) {
            return Some(
                last_refusal.map_or(BlockedReason::ObservingOutcome, |code| {
                    BlockedReason::Refused { code: code.clone() }
                }),
            );
        }
        None
    }

    fn decide_memory(&mut self, evaluation: &MemoryEvaluation) {
        let guard: Guard = Guard::Memory;
        let ready: bool = evaluation.global.state == TriggerState::Ready
            || evaluation
                .budgets
                .iter()
                .any(|budget| budget.state == TriggerState::Ready);
        if !ready {
            return;
        }
        if let Some(reason) = self.gate(guard) {
            self.block(guard, reason);
            return;
        }
        if self.state.outstanding.is_some() {
            return;
        }
        let Some(record) = self.state.memory_incident.clone() else {
            self.block(guard, no_record());
            return;
        };
        let waiting: Option<BlockedReason> = self
            .record_block(
                record.established,
                record.unknown_outcome,
                record.observe_until.as_ref(),
                record.last_refusal.as_ref(),
            )
            .or_else(|| {
                inhibits(record.backoff.as_ref(), self.input).then_some(BlockedReason::Cooldown)
            });
        if let Some(reason) = waiting {
            self.block(guard, reason);
            return;
        }
        let selection: Selection<'a> = match self.select_application(evaluation, &record) {
            Ok(selection) => selection,
            Err(reason) => {
                self.block(guard, reason);
                return;
            }
        };
        let plan: Result<Plan, String> = self.build_stop(&selection).and_then(|built| {
            self.automatic_plan(guard, &built, &selection.trigger, &record.incident_id)
        });
        match plan {
            Ok(plan) => self.commit_memory(plan, selection, record),
            Err(detail) => self.block(guard, BlockedReason::PlanNotBuilt { detail }),
        }
    }

    /// Selects the application of the next intervention: the first
    /// intervention of the policy evaluation, when a qualified trigger
    /// admits it now.
    fn select_application(
        &self,
        evaluation: &MemoryEvaluation,
        record: &MemoryIncidentRecord,
    ) -> Result<Selection<'a>, BlockedReason> {
        let snapshot = &self.input.observations.memory;
        let plan = plan_intervention(&self.context(), evaluation, snapshot);
        let first = &plan.first;
        if !first.admissible_now {
            return Err(policy_reason(&first.blocked_by));
        }
        let (Some(target), Some(admission)) = (&first.target, &first.admission_trigger) else {
            return Err(BlockedReason::NoEligibleTarget);
        };
        let (trigger, sampled_at): (TriggerKey, Option<MonotonicNanos>) = match admission {
            AdmissionTrigger::GlobalPressure => (
                TriggerKey::GlobalMemory,
                evaluation.global.evidence.sampled_at,
            ),
            AdmissionTrigger::ApplicationBudget { budget_id } => (
                TriggerKey::Budget {
                    budget_id: budget_id.clone(),
                },
                evaluation
                    .budgets
                    .iter()
                    .find(|budget| &budget.budget_id == budget_id)
                    .and_then(|budget| budget.evidence.sampled_at),
            ),
        };
        if !self.is_fresh(sampled_at) {
            return Err(BlockedReason::AwaitingFreshMeasurement);
        }
        // The critical-memory exception is the only action with no
        // durable record, and only the global trigger has it.
        if self.input.health.journal_unavailable
            && !(matches!(trigger, TriggerKey::GlobalMemory)
                && record.budget.volatile_exception_at_open)
        {
            return Err(BlockedReason::JournalUnavailable);
        }
        let candidate: &'a ApplicationCandidate = snapshot
            .applications
            .iter()
            .find(|candidate| &candidate.membership_snapshot == target)
            .ok_or(BlockedReason::NoEligibleTarget)?;
        Ok(Selection {
            candidate,
            trigger,
            application: plan
                .decisions
                .iter()
                .find(|decision| decision.first_intervention)
                .and_then(|decision| decision.name.clone()),
            strategy: match first.force_escalation {
                ForceEscalation::Permitted => StopStrategy::ForceAfterGrace {
                    grace: first.grace_period,
                },
                ForceEscalation::NotAllowedByPolicy | ForceEscalation::NotGranted => {
                    StopStrategy::Graceful
                }
            },
        })
    }

    /// Builds the stop plan of a selection with the plan builder.
    fn build_stop(&mut self, selection: &Selection<'_>) -> Result<Plan, String> {
        let grace: Nanoseconds = selection.strategy.grace().unwrap_or(Nanoseconds::ZERO);
        let deadline: Nanoseconds = Nanoseconds::new(
            grace
                .get()
                .saturating_add(VERIFICATION_WINDOW.get().saturating_mul(2))
                .saturating_add(DEADLINE_MARGIN.get()),
        );
        let authority: &AuthorityState = self.input.authority.ok_or("no authority record")?;
        let (plan_id, text) = self.plan_ids(Guard::Memory)?;
        let context: PlanContext<'_> = self
            .plan_context(plan_id, authority)
            .ok_or("no policy revision is in effect")?;
        let id = |suffix: &str| format!("{text}-{suffix}");
        let request: StopRequest<'_> = StopRequest {
            target_id: TargetId::new(id("app")).map_err(|error| error.to_string())?,
            candidate: selection.candidate,
            protection: &ProtectionContext {
                principal: self.input.principal,
                control_plane: self.input.control_plane,
            },
            strategy: selection.strategy,
            steps: StopStepIds {
                graceful: StepId::new(id("graceful")).map_err(|error| error.to_string())?,
                force: StepId::new(id("force")).map_err(|error| error.to_string())?,
            },
            limits: StopLimits {
                execution_deadline: deadline,
                verification_window: VERIFICATION_WINDOW,
                max_grace: grace.max(Nanoseconds::new(1)),
                max_verification_window: VERIFICATION_WINDOW,
                max_execution_deadline: deadline,
            },
        };
        let outcome: PlanOutcome =
            build_stop_plan(&context, &request).map_err(|error| error.to_string())?;
        built_plan(outcome)
    }

    /// Reserves one slot of the incident for `plan` and makes the apply
    /// intent.
    fn commit_memory(
        &mut self,
        plan: Plan,
        selection: Selection<'_>,
        record: MemoryIncidentRecord,
    ) {
        let guard: Guard = Guard::Memory;
        let memory_guard = self.input.config.memory_guard();
        let ceiling: u32 = memory_guard.max_applications_per_incident.get();
        let Some(incident) = &mut self.state.policy.memory.incident else {
            return;
        };
        let Ok(slots) = SlotAllowance::with_usage(ceiling, incident.consumed_slots.min(ceiling), 0)
        else {
            self.block(guard, BlockedReason::Exhausted);
            return;
        };
        incident.reserved_slots = incident.reserved_slots.saturating_add(1);
        incident.outstanding_operation = true;
        let base: Nanoseconds = nanoseconds(memory_guard.observe_after_action);
        let allowance: IncidentAllowance = IncidentAllowance {
            incident_id: record.incident_id.clone(),
            generation: record.budget.generation,
            opened_in: record.opened_in.clone(),
            slots: Some(slots),
            work: None,
            pacing: pacing(base),
        };
        self.state.outstanding = Some(Outstanding {
            guard,
            incident_id: record.incident_id.clone(),
            plan_id: plan.plan_id.clone(),
            operation_id: None,
            trigger: selection.trigger.clone(),
            rules: Vec::new(),
            application: selection.application,
        });
        self.applied = true;
        self.intents.push(Intent::Apply(Box::new(AutomaticApply {
            guard,
            plan,
            allowance,
            budget: record.budget,
            trigger: selection.trigger,
        })));
    }

    /// Checks each approved rule of the disk guard against the registry
    /// and records a reason for each rule that does not permit automatic
    /// eviction. Returns `true` when one or more rules permit it.
    fn any_approved_rule_is_validated(&mut self) -> bool {
        let reasons: Vec<BlockedReason> = self.approved_rule_reasons();
        let validated: bool = reasons.is_empty();
        for reason in reasons {
            self.block(Guard::Disk, reason);
        }
        validated
    }

    /// The reasons that no approved rule of the disk guard permits
    /// automatic eviction. Empty when one or more rules permit it.
    fn approved_rule_reasons(&self) -> Vec<BlockedReason> {
        let approved: &[RuleId] = &self.input.config.disk_guard().approved_rules;
        let mut reasons: Vec<BlockedReason> = Vec::new();
        for rule_id in approved {
            let revisions: Vec<&Rule> = self
                .input
                .registry
                .rules()
                .into_iter()
                .filter(|rule| &rule.reference.id == rule_id)
                .collect();
            let permits: bool = revisions.iter().any(|rule| {
                rule.layouts
                    .iter()
                    .any(|layout| layout.lifecycle.permits(&RuleMode::AutomaticEviction))
            });
            if permits {
                return Vec::new();
            }
            let rule: String = rule_id.as_str().to_owned();
            reasons.push(if revisions.is_empty() {
                BlockedReason::RuleNotRegistered { rule }
            } else {
                BlockedReason::RuleNotValidated { rule }
            });
        }
        if reasons.is_empty() {
            reasons.push(BlockedReason::NoEligibleTarget);
        }
        reasons
    }

    /// Asks the runtime for a candidate set when the disk guard can use
    /// one. With pressure, only the known candidates are examined.
    fn prepare(&mut self, volumes: Vec<VolumeId>, mode: PreparationMode) {
        if !volumes.is_empty() {
            self.intents
                .push(Intent::PrepareCandidates { volumes, mode });
        }
    }

    /// A warning can prepare candidates. This is optional work: it does
    /// not run with memory pressure, with a pause, or when the agent is
    /// over its own budget. A volume below the reclaim threshold is not a
    /// warning: its window qualifies, and a discovery does not start then.
    fn prepare_for_warning(&mut self, view: &DiskView, memory_quiet: bool) {
        let warned: Vec<VolumeId> = view
            .evaluation
            .volumes
            .iter()
            .filter(|trigger| trigger.state == TriggerState::Advisory)
            .filter_map(|trigger| trigger.volume_id.clone())
            .collect();
        let old: bool = self
            .input
            .observations
            .candidates
            .as_ref()
            .is_none_or(|set| {
                self.now()
                    .checked_duration_since(set.prepared_at)
                    .is_none_or(|age| age > CANDIDATE_REFRESH_AGE)
            });
        // A discovery does not start in an incident, or while a volume
        // has a trigger that is more than a warning.
        let disk_quiet: bool = self.state.disk_incidents.is_empty()
            && view.evaluation.volumes.iter().all(|trigger| {
                matches!(trigger.state, TriggerState::Normal | TriggerState::Advisory)
            });
        let permitted: bool = memory_quiet
            && disk_quiet
            && !self.input.health.stopping
            && !self.input.health.restart_backoff
            && !self.state.held_until_recovery.contains(&Guard::Disk)
            && self.approved_rule_reasons().is_empty()
            && !self.state.paused
            && !self.input.health.self_over_budget
            && self.standing(Guard::Disk) == Some(GuardStanding::Active)
            && self.state.outstanding.is_none();
        if old && permitted {
            self.prepare(warned, PreparationMode::Refresh);
        }
    }

    fn decide_disk(&mut self, view: &DiskView, memory_quiet: bool) {
        let guard: Guard = Guard::Disk;
        let ready: Option<&VolumeTrigger> = view
            .evaluation
            .volumes
            .iter()
            .find(|trigger| trigger.state == TriggerState::Ready && trigger.domain_verified);
        let Some(trigger) = ready else {
            self.prepare_for_warning(view, memory_quiet);
            return;
        };
        if let Some(reason) = self.gate(guard) {
            self.block(guard, reason);
            return;
        }
        if self.state.outstanding.is_some() {
            return;
        }
        // A filesystem action always needs a durable record.
        if self.input.health.journal_unavailable {
            self.block(guard, BlockedReason::JournalUnavailable);
            return;
        }
        // The approved rules of the policy against the registry. With no
        // rule that permits automatic eviction, the guard has nothing to
        // select, and no candidate is prepared. The reason names each
        // rule, so that a status shows that its lifecycle state inhibits
        // the guard.
        if !self.any_approved_rule_is_validated() {
            return;
        }
        if !self.is_fresh(trigger.evidence.sampled_at) {
            self.block(guard, BlockedReason::AwaitingFreshMeasurement);
            return;
        }
        let (Some(volume_id), Some(domain)) = (&trigger.volume_id, &trigger.domain) else {
            return;
        };
        let Some(record) = self.state.disk_incident(domain).cloned() else {
            self.block(guard, no_record());
            return;
        };
        if let Some(reason) = self.record_block(
            record.established,
            record.unknown_outcome,
            record.observe_until.as_ref(),
            record.last_refusal.as_ref(),
        ) {
            self.block(guard, reason);
            return;
        }
        let Some(set) = self.usable_candidates() else {
            // A resource emergency starts no scan: the runtime examines
            // the candidates that it knows.
            self.block(guard, BlockedReason::CandidatesNotPrepared);
            self.prepare(vec![volume_id.clone()], PreparationMode::KnownOnly);
            return;
        };
        let batch: Batch<'a> = match self.select_batch(view, trigger, volume_id, set) {
            Ok(batch) => batch,
            Err(reasons) => {
                for reason in reasons {
                    self.block(guard, reason);
                }
                return;
            }
        };
        let key: TriggerKey = TriggerKey::Disk {
            volume_id: volume_id.clone(),
        };
        let plan: Result<Plan, String> = self
            .build_eviction(&batch)
            .and_then(|built| self.automatic_plan(guard, &built, &key, &record.incident_id));
        match plan {
            Ok(plan) => self.commit_disk(plan, &batch, record, key),
            Err(detail) => self.block(guard, BlockedReason::PlanNotBuilt { detail }),
        }
    }

    /// Selects the targets of the next plan: the targets of the first
    /// batch of the policy evaluation that have the rule of its first
    /// target. One plan has the targets of one rule.
    fn select_batch(
        &self,
        view: &DiskView,
        trigger: &VolumeTrigger,
        volume_id: &VolumeId,
        set: &'a CandidateSet,
    ) -> Result<Batch<'a>, Vec<BlockedReason>> {
        let on_volume: Vec<&'a PreparedCandidate> = set
            .candidates
            .iter()
            .filter(|prepared| &prepared.candidate.candidate.volume_id == volume_id)
            .collect();
        // The lifecycle state of the rule of each candidate, as a
        // specific reason.
        let mut reasons: Vec<BlockedReason> = Vec::new();
        let mut validated: usize = 0;
        for prepared in &on_volume {
            let reference: &RuleRef = &prepared.candidate.rule;
            let rule: String = reference.id.as_str().to_owned();
            let reason: BlockedReason = match self.input.registry.resolve(
                reference,
                &prepared.candidate.layout,
                &RuleMode::AutomaticEviction,
            ) {
                Ok(_) => {
                    validated = validated.saturating_add(1);
                    continue;
                }
                Err(RuleRefusal::ModeNotValidated | RuleRefusal::UnknownLayout) => {
                    BlockedReason::RuleNotValidated { rule }
                }
                Err(RuleRefusal::UnknownRule | RuleRefusal::UnknownRevision) => {
                    BlockedReason::RuleNotRegistered { rule }
                }
            };
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        if validated == 0 {
            if reasons.is_empty() {
                reasons.push(BlockedReason::NoEligibleTarget);
            }
            return Err(reasons);
        }
        let cleanup = plan_cleanup(&self.context(), &view.evaluation, &view.snapshot);
        let first_batch = cleanup
            .first_batches
            .iter()
            .find(|batch| batch.selector == trigger.selector)
            .ok_or_else(|| vec![BlockedReason::NoEligibleTarget])?;
        if !first_batch.admissible_now {
            return Err(vec![policy_reason(&first_batch.blocked_by)]);
        }
        let in_batch: Vec<&'a PreparedCandidate> = first_batch
            .targets
            .iter()
            .filter_map(|target_id| {
                on_volume
                    .iter()
                    .find(|prepared| &prepared.candidate.candidate.target_id == target_id)
                    .copied()
            })
            .collect();
        let first: &PreparedCandidate = in_batch
            .first()
            .copied()
            .ok_or_else(|| vec![BlockedReason::NoEligibleTarget])?;
        let reference: RuleRef = first.candidate.rule.clone();
        Ok(Batch {
            layout: first.candidate.layout.clone(),
            targets: in_batch
                .iter()
                .filter(|prepared| prepared.candidate.rule == reference)
                .copied()
                .collect(),
            reference,
            work: WorkCharge::new(first_batch.work_bytes, first_batch.item_count),
            limit: WorkCharge::new(
                first_batch.allowance.batch_limit,
                first_batch.allowance.batch_item_limit,
            ),
            time_limit: first_batch.allowance.pass_time_limit,
        })
    }

    /// Builds the eviction plan of a batch with the plan builder.
    fn build_eviction(&mut self, batch: &Batch<'_>) -> Result<Plan, String> {
        let authority: &AuthorityState = self.input.authority.ok_or("no authority record")?;
        let (plan_id, text) = self.plan_ids(Guard::Disk)?;
        let context: PlanContext<'_> = self
            .plan_context(plan_id, authority)
            .ok_or("no policy revision is in effect")?;
        let mut entries: Vec<CleanupEntry> = Vec::with_capacity(batch.targets.len());
        for (index, prepared) in batch.targets.iter().enumerate() {
            let candidate: &CleanupCandidate = &prepared.candidate.candidate;
            entries.push(CleanupEntry {
                target_id: candidate.target_id.clone(),
                step_id: StepId::new(format!("{text}-s{index}"))
                    .map_err(|error| error.to_string())?,
                path: candidate.path.clone(),
                root_id: prepared.root_id.clone(),
                root_path: prepared.root_path.clone(),
                root_object: prepared.root_object,
                relative_entry: prepared.relative_entry.clone(),
                volume_id: candidate.volume_id.clone(),
                mount_id: prepared.mount_id.clone(),
                object_type: prepared.object_type.clone(),
                owner: prepared.owner,
                object: prepared.object,
                charge: prepared.charge,
                estimate: prepared.estimate,
                hard_protection: candidate.facts.hard_protection,
                rule: Some(RuleEvidence::of(&prepared.candidate)),
            });
        }
        let rule: Result<&Rule, RuleRefusal> = self.input.registry.resolve(
            &batch.reference,
            &batch.layout,
            &RuleMode::AutomaticEviction,
        );
        let request: CleanupRequest<'_> = CleanupRequest {
            mode: ModeSelection::Evict { rule },
            entries: &entries,
            preset: None,
            limits: CleanupLimits {
                plan: batch.work,
                batch: batch.limit,
                execution_deadline: batch.time_limit,
                verification_window: VERIFICATION_WINDOW,
            },
        };
        let outcome: PlanOutcome = build_cleanup_plan(&context, &request)
            .map_err(|error: PlanBuildError| error.to_string())?;
        built_plan(outcome)
    }

    /// The work ceilings of a disk incident with the usage before a new
    /// plan. The coordinator reserves the charge of the plan in each
    /// scope.
    fn disk_budget(
        &self,
        record: &DiskIncidentRecord,
        reference: &RuleRef,
        incident: &DiskIncident,
    ) -> Option<WorkBudget> {
        let disk_guard = self.input.config.disk_guard();
        let allowance_of = |scope: BudgetScope, ceiling: WorkCharge, used: WorkCharge| {
            WorkAllowance::with_usage(ceiling, used.min(ceiling), WorkCharge::ZERO)
                .map(|allowance| ScopedAllowance { scope, allowance })
        };
        let mut scopes: Vec<Result<ScopedAllowance, _>> = vec![
            allowance_of(
                BudgetScope::Incident(record.incident_id.clone()),
                WorkCharge::new(disk_guard.incident_limit, disk_guard.incident_item_limit),
                charged(&incident.usage),
            ),
            allowance_of(
                BudgetScope::Pass,
                WorkCharge::new(disk_guard.pass_limit, disk_guard.pass_item_limit),
                incident
                    .current_pass
                    .as_ref()
                    .map_or(WorkCharge::ZERO, charged),
            ),
            allowance_of(
                BudgetScope::Batch,
                WorkCharge::new(disk_guard.batch_limit, disk_guard.batch_item_limit),
                WorkCharge::ZERO,
            ),
        ];
        if let Some(rule) = self.input.registry.rule(reference) {
            let used: WorkCharge = record
                .rule_usage
                .iter()
                .find(|usage| usage.rule_id == reference.id)
                .map_or(WorkCharge::ZERO, |usage| usage.charge);
            scopes.push(allowance_of(
                BudgetScope::Rule(reference.id.clone()),
                rule.budget.per_pass,
                used,
            ));
        }
        scopes
            .into_iter()
            .collect::<Result<Vec<ScopedAllowance>, _>>()
            .ok()
            .and_then(|allowances| WorkBudget::new(allowances).ok())
    }

    /// Reserves the charge of `plan` in its incident and in the pass, and
    /// makes the apply intent.
    fn commit_disk(
        &mut self,
        plan: Plan,
        batch: &Batch<'_>,
        record: DiskIncidentRecord,
        key: TriggerKey,
    ) {
        let guard: Guard = Guard::Disk;
        let Some(charge) = plan.limits.work else {
            self.block(
                guard,
                BlockedReason::PlanNotBuilt {
                    detail: "the plan has no work limit".to_owned(),
                },
            );
            return;
        };
        let budget: Option<WorkBudget> = self
            .state
            .policy
            .disk
            .incidents
            .iter()
            .find(|incident| incident.domain == record.domain)
            .and_then(|incident| self.disk_budget(&record, &batch.reference, incident));
        let Some(budget) = budget else {
            self.block(guard, BlockedReason::Exhausted);
            return;
        };
        let Some(incident) = self
            .state
            .policy
            .disk
            .incidents
            .iter_mut()
            .find(|incident| incident.domain == record.domain)
        else {
            return;
        };
        // The reservation of the plan in the incident and in its pass.
        if incident.current_pass.is_none() {
            incident.current_pass = Some(WorkUsage::default());
            incident.passes_started = incident.passes_started.saturating_add(1);
        }
        reserve(&mut incident.usage, charge);
        if let Some(pass) = &mut incident.current_pass {
            reserve(pass, charge);
        }
        incident.outstanding_operation = true;
        if let Some(known) = self
            .state
            .disk_incidents
            .iter_mut()
            .find(|known| known.incident_id == record.incident_id)
        {
            add_rule_usage(&mut known.rule_usage, &batch.reference.id, charge);
        }
        let base: Nanoseconds = nanoseconds(self.input.config.disk_guard().no_effect_backoff);
        let allowance: IncidentAllowance = IncidentAllowance {
            incident_id: record.incident_id.clone(),
            generation: record.budget.generation,
            opened_in: record.opened_in.clone(),
            slots: None,
            work: Some(budget),
            pacing: pacing(base),
        };
        self.state.outstanding = Some(Outstanding {
            guard,
            incident_id: record.incident_id.clone(),
            plan_id: plan.plan_id.clone(),
            operation_id: None,
            trigger: key.clone(),
            rules: vec![RuleUsage {
                rule_id: batch.reference.id.clone(),
                charge,
            }],
            application: None,
        });
        self.applied = true;
        self.intents.push(Intent::Apply(Box::new(AutomaticApply {
            guard,
            plan,
            allowance,
            budget: record.budget,
            trigger: key,
        })));
    }

    // The status.

    fn phase(&self, guard: Guard, states: Option<&[TriggerState]>) -> GuardPhase {
        let Some(states) = states else {
            return GuardPhase::Degraded;
        };
        let acting: bool = self
            .state
            .outstanding
            .as_ref()
            .is_some_and(|outstanding| outstanding.guard == guard);
        let first_block: Option<&BlockedReason> = self
            .blocked
            .iter()
            .find(|(known, _)| *known == guard)
            .map(|(_, reason)| reason);
        let mut phase: GuardPhase = if acting {
            GuardPhase::Acting
        } else {
            GuardPhase::Normal
        };
        for state in states {
            let one: GuardPhase = phase_of(*state, first_block);
            if phase_rank(one) > phase_rank(phase) {
                phase = one;
            }
        }
        phase
    }

    fn incident_statuses(&self, guard: Guard, slots_remaining: Option<u32>) -> Vec<IncidentStatus> {
        match guard {
            Guard::Disk => self
                .state
                .disk_incidents
                .iter()
                .map(|record| {
                    let incident = self
                        .state
                        .policy
                        .disk
                        .incidents
                        .iter()
                        .find(|incident| incident.domain == record.domain);
                    IncidentStatus {
                        incident_id: record.incident_id.clone(),
                        generation: record.budget.generation.get(),
                        established: record.established,
                        work_bytes: incident
                            .map(|incident| charged(&incident.usage).work_bytes.get()),
                        passes_started: incident.map(|incident| incident.passes_started),
                        slots_used: None,
                        slots_remaining: None,
                    }
                })
                .collect(),
            Guard::Memory => self
                .state
                .memory_incident
                .iter()
                .map(|record| IncidentStatus {
                    incident_id: record.incident_id.clone(),
                    generation: record.budget.generation.get(),
                    established: record.established,
                    work_bytes: None,
                    passes_started: None,
                    slots_used: self.state.policy.memory.incident.map(|incident| {
                        incident
                            .consumed_slots
                            .saturating_add(incident.reserved_slots)
                    }),
                    slots_remaining,
                })
                .collect(),
        }
    }

    fn guard_status(
        &self,
        guard: Guard,
        phase: GuardPhase,
        triggers: Vec<String>,
        slots_remaining: Option<u32>,
    ) -> GuardStatus {
        GuardStatus {
            guard,
            standing: self
                .standing(guard)
                .map_or_else(|| "observation_only".to_owned(), |standing| wire(&standing)),
            phase,
            triggers,
            blocked: self
                .blocked
                .iter()
                .filter(|(known, _)| *known == guard)
                .map(|(_, reason)| reason.clone())
                .take(MAX_STATUS_REASONS)
                .collect(),
            incidents: self.incident_statuses(guard, slots_remaining),
        }
    }

    /// The status of the two guards, the memory guard first.
    fn guard_statuses(
        &mut self,
        disk: Option<&DiskView>,
        memory: Option<&MemoryEvaluation>,
    ) -> Vec<GuardStatus> {
        let disk_states: Option<Vec<TriggerState>> = disk.map(|view| {
            view.evaluation
                .volumes
                .iter()
                .map(|trigger| trigger.state)
                .collect()
        });
        let memory_states: Option<Vec<TriggerState>> = memory.map(|evaluation| {
            std::iter::once(evaluation.global.state)
                .chain(evaluation.budgets.iter().map(|budget| budget.state))
                .collect()
        });
        // A guard that waited for recovery is free after a sustained
        // recovery that this lifetime observed: each evaluation shows
        // each trigger normal for the recovery time of the guard, and no
        // incident is open at its end. A warning state does not satisfy
        // recovery, and a restart must not replenish a budget during
        // continuing pressure.
        let disk_quiet: bool = is_quiet(disk_states.as_deref());
        let memory_quiet: bool = is_quiet(memory_states.as_deref());
        let disk_open: bool = !self.state.disk_incidents.is_empty();
        let memory_open: bool = self.state.memory_incident.is_some();
        let clock = &self.input.time.clock;
        let now: MonotonicNanos = clock.now;
        let mut marks: Vec<QuietMark> = Vec::new();
        let mut released: Vec<Guard> = Vec::new();
        for guard in &self.state.held_until_recovery {
            let (quiet, open, stable_for): (bool, bool, Duration) = match guard {
                Guard::Disk => (
                    disk_quiet,
                    disk_open,
                    self.input.config.disk_guard().recovery_stable_for,
                ),
                Guard::Memory => (
                    memory_quiet,
                    memory_open,
                    self.input.config.memory_guard().recovery_stable_for,
                ),
            };
            if !quiet {
                continue;
            }
            // A mark of a different boot, clock domain, or continuity
            // generation is not comparable: the sequence starts again.
            let mark: QuietMark = self
                .state
                .quiet_since
                .iter()
                .find(|mark| {
                    mark.guard == *guard
                        && mark.continuity == clock.continuity
                        && mark.since.clock_domain == clock.clock_domain
                        && mark.since.boot_id == clock.boot_id
                })
                .cloned()
                .unwrap_or_else(|| QuietMark {
                    guard: *guard,
                    since: MonotonicMark {
                        at: now,
                        clock_domain: clock.clock_domain.clone(),
                        boot_id: clock.boot_id.clone(),
                    },
                    continuity: clock.continuity,
                });
            let stable: bool = now
                .checked_duration_since(mark.since.at)
                .is_some_and(|quiet_for| quiet_for >= nanoseconds(stable_for));
            if stable && !open {
                released.push(*guard);
            } else {
                marks.push(mark);
            }
        }
        self.state.quiet_since = marks;
        self.state
            .held_until_recovery
            .retain(|guard| !released.contains(guard));
        let disk_triggers: Vec<String> = disk.map_or_else(Vec::new, |view| {
            view.evaluation
                .volumes
                .iter()
                .map(|trigger| format!("{}:{}", trigger.selector, wire(&trigger.state)))
                .collect()
        });
        let memory_triggers: Vec<String> =
            memory.map_or_else(Vec::new, |evaluation| {
                std::iter::once(format!("global:{}", wire(&evaluation.global.state)))
                    .chain(evaluation.budgets.iter().map(|budget| {
                        format!("budget.{}:{}", budget.budget_id, wire(&budget.state))
                    }))
                    .collect()
            });
        vec![
            self.guard_status(
                Guard::Memory,
                self.phase(Guard::Memory, memory_states.as_deref()),
                memory_triggers,
                memory.map(|evaluation| evaluation.slots_remaining),
            ),
            self.guard_status(
                Guard::Disk,
                self.phase(Guard::Disk, disk_states.as_deref()),
                disk_triggers,
                None,
            ),
        ]
    }

    /// Makes a notification for each change of a guard condition.
    fn notify_changes(&mut self, guards: &[GuardStatus]) {
        let mut reported: Vec<ReportedCondition> = Vec::with_capacity(guards.len());
        for status in guards {
            let condition: ReportedCondition = ReportedCondition {
                guard: status.guard,
                phase: status.phase,
                blocked: status.blocked.first().cloned(),
            };
            let earlier: Option<&ReportedCondition> = self
                .state
                .reported
                .iter()
                .find(|known| known.guard == status.guard);
            let earlier_phase: GuardPhase = earlier.map_or(GuardPhase::Normal, |known| known.phase);
            if earlier_phase != condition.phase {
                self.intents.push(Intent::Notify(Notification::Phase {
                    guard: status.guard,
                    phase: condition.phase,
                }));
            }
            if let Some(reason) = &condition.blocked
                && earlier.and_then(|known| known.blocked.as_ref()) != Some(reason)
            {
                self.intents.push(Intent::Notify(Notification::Blocked {
                    guard: status.guard,
                    reason: reason.clone(),
                }));
            }
            reported.push(condition);
        }
        self.state.reported = reported;
    }

    fn finish(mut self, disk: Option<&DiskView>, memory: Option<&MemoryEvaluation>) -> StepOutput {
        let guards: Vec<GuardStatus> = self.guard_statuses(disk, memory);
        let phase_of_guard = |guard: Guard| {
            guards
                .iter()
                .find(|status| status.guard == guard)
                .map_or(GuardPhase::Degraded, |status| status.phase)
        };
        let disk_phase: GuardPhase = phase_of_guard(Guard::Disk);
        let memory_phase: GuardPhase = phase_of_guard(Guard::Memory);

        // The optional work of the agent.
        let reduce: Option<ReduceReason> = if self.input.health.self_over_budget {
            Some(ReduceReason::SelfBudget)
        } else if has_pressure(disk_phase) && has_pressure(memory_phase) {
            Some(ReduceReason::SimultaneousPressure)
        } else if !self.state.disk_incidents.is_empty() || self.state.memory_incident.is_some() {
            Some(ReduceReason::IncidentOpen)
        } else {
            None
        };
        if let Some(reason) = reduce {
            self.intents.insert(0, Intent::ReduceOptionalWork(reason));
        }
        self.notify_changes(&guards);

        if self.input.health.journal_unavailable {
            self.degraded.push("journal_unavailable".to_owned());
        }
        let summary: Summary = if self.degraded.is_empty() {
            summary_of(disk_phase).max(summary_of(memory_phase))
        } else {
            Summary::Degraded
        };
        let outstanding: Option<&Outstanding> = self.state.outstanding.as_ref();
        let status: ControllerStatus = ControllerStatus {
            schema_version: CONTROLLER_STATUS_VERSION,
            evaluated_at: self.input.time.wall,
            summary,
            paused: self.state.paused,
            paused_until: self.paused_until,
            observation_only: self.input.authority.is_none(),
            guards,
            outstanding_plan: outstanding.map(|outstanding| outstanding.plan_id.clone()),
            outstanding_operation: outstanding
                .and_then(|outstanding| outstanding.operation_id.clone()),
            degraded: self.degraded.clone(),
            optional_work_reduced: reduce.is_some(),
        };
        if self.intents.is_empty() {
            self.intents.push(Intent::Idle);
        }
        let incidents: Vec<IncidentBudget> = self
            .state
            .disk_incidents
            .iter()
            .map(|record| record.budget.clone())
            .chain(
                self.state
                    .memory_incident
                    .iter()
                    .map(|record| record.budget.clone()),
            )
            .collect();
        StepOutput {
            state: self.state,
            intents: self.intents,
            status,
            triggers: self.triggers,
            incidents,
        }
    }
}

/// The application that the memory guard selected, with the trigger and
/// the strategy of its plan.
struct Selection<'s> {
    candidate: &'s ApplicationCandidate,
    trigger: TriggerKey,
    /// The cooldown key of the application.
    application: Option<String>,
    strategy: StopStrategy,
}

/// The targets of one eviction plan: the targets of the first batch that
/// have one rule.
struct Batch<'s> {
    reference: RuleRef,
    layout: String,
    targets: Vec<&'s PreparedCandidate>,
    /// The charge of the first batch: the ceiling of the plan.
    work: WorkCharge,
    /// The ceiling of one batch.
    limit: WorkCharge,
    /// The time limit of the pass: the execution deadline of the plan.
    time_limit: Nanoseconds,
}

fn no_record() -> BlockedReason {
    BlockedReason::PlanNotBuilt {
        detail: "the incident has no record".to_owned(),
    }
}

/// The plan of a builder, or the reasons that it left each target out.
fn built_plan(outcome: PlanOutcome) -> Result<Plan, String> {
    outcome.plan.ok_or_else(|| {
        let reasons: Vec<String> = outcome
            .preview
            .omitted
            .iter()
            .flat_map(|omission| &omission.reasons)
            .map(wire)
            .collect();
        format!("each target was left out: {}", reasons.join(", "))
    })
}

/// The specific reason of the reasons of the policy evaluation.
fn policy_reason(reasons: &[Explanation]) -> BlockedReason {
    let has = |reason: DecisionReason, detail: Option<ReasonDetail>| {
        reasons.iter().any(|explanation| {
            explanation.reason == reason && detail.is_none_or(|detail| explanation.detail == detail)
        })
    };
    if has(DecisionReason::BudgetExhausted, None) {
        BlockedReason::Exhausted
    } else if has(DecisionReason::CooldownActive, None) {
        BlockedReason::Cooldown
    } else if has(
        DecisionReason::TargetNotEligible,
        Some(ReasonDetail::NoEligibleCandidate),
    ) {
        BlockedReason::NoEligibleTarget
    } else {
        BlockedReason::Policy {
            reasons: reasons
                .iter()
                .take(MAX_STATUS_REASONS)
                .map(|explanation| reason_text(*explanation))
                .collect(),
        }
    }
}

/// The pacing of an incident: the base cooldown, and its largest
/// multiple.
fn pacing(base: Nanoseconds) -> Pacing {
    Pacing {
        cooldown: base,
        max_cooldown: Nanoseconds::new(base.get().saturating_mul(MAX_BACKOFF_FACTOR)),
        min_capacity_gain: Bytes::new(1),
    }
}

/// The consumed and the reserved charge of a usage.
fn charged(usage: &WorkUsage) -> WorkCharge {
    WorkCharge::new(
        Bytes::new(
            usage
                .consumed_bytes
                .get()
                .saturating_add(usage.reserved_bytes.get()),
        ),
        EntryCount::new(
            usage
                .consumed_items
                .get()
                .saturating_add(usage.reserved_items.get()),
        ),
    )
}

/// Adds a charge to the reservation of a usage.
fn reserve(usage: &mut WorkUsage, charge: WorkCharge) {
    usage.reserved_bytes = Bytes::new(
        usage
            .reserved_bytes
            .get()
            .saturating_add(charge.work_bytes.get()),
    );
    usage.reserved_items = EntryCount::new(
        usage
            .reserved_items
            .get()
            .saturating_add(charge.items.get()),
    );
}

/// Ends a reservation of a usage: the charge is consumed, or released.
fn unreserve(usage: &mut WorkUsage, charge: WorkCharge, consumed: bool) {
    let bytes: u64 = charge.work_bytes.get();
    let items: u64 = charge.items.get();
    usage.reserved_bytes = Bytes::new(usage.reserved_bytes.get().saturating_sub(bytes));
    usage.reserved_items = EntryCount::new(usage.reserved_items.get().saturating_sub(items));
    if consumed {
        usage.consumed_bytes = Bytes::new(usage.consumed_bytes.get().saturating_add(bytes));
        usage.consumed_items = EntryCount::new(usage.consumed_items.get().saturating_add(items));
    }
}

/// True when an evaluation has one trigger or more and each one is
/// normal. An advisory state is not a recovery, and an evaluation with no
/// trigger shows nothing.
fn is_quiet(states: Option<&[TriggerState]>) -> bool {
    states.is_some_and(|states| {
        !states.is_empty()
            && states
                .iter()
                .all(|state| matches!(state, TriggerState::Normal))
    })
}

/// True when a guard has a qualifying or a qualified trigger, or an
/// incident.
const fn has_pressure(phase: GuardPhase) -> bool {
    !matches!(
        phase,
        GuardPhase::Normal | GuardPhase::Warning | GuardPhase::Degraded
    )
}

/// The phase of one trigger state, with the first reason that inhibits
/// the guard.
fn phase_of(state: TriggerState, first_block: Option<&BlockedReason>) -> GuardPhase {
    match state {
        TriggerState::Acting => GuardPhase::Acting,
        TriggerState::Ready => match first_block {
            None => GuardPhase::Ready,
            Some(BlockedReason::ObservingOutcome) => GuardPhase::Acting,
            Some(BlockedReason::Cooldown) => GuardPhase::Cooldown,
            // A budget that a restart did not establish is exhausted
            // until the incident closes or a person rearms it.
            Some(
                BlockedReason::Exhausted
                | BlockedReason::IncidentStateNotEstablished
                | BlockedReason::UnknownPriorOutcome
                | BlockedReason::HeldUntilRecovery,
            ) => GuardPhase::Exhausted,
            Some(_) => GuardPhase::Blocked,
        },
        TriggerState::Exhausted => GuardPhase::Exhausted,
        TriggerState::Cooldown => GuardPhase::Cooldown,
        TriggerState::Recovering => GuardPhase::Recovering,
        TriggerState::Qualifying | TriggerState::Held => GuardPhase::Qualifying,
        TriggerState::Advisory => GuardPhase::Warning,
        TriggerState::Normal => GuardPhase::Normal,
        // Evidence that is not usable, and a state that this build does
        // not know, are not normal.
        _ => GuardPhase::Degraded,
    }
}

/// The precedence of the phases of the triggers of one guard.
const fn phase_rank(phase: GuardPhase) -> u8 {
    match phase {
        GuardPhase::Normal => 0,
        GuardPhase::Warning => 1,
        GuardPhase::Qualifying => 2,
        GuardPhase::Recovering => 3,
        GuardPhase::Cooldown => 4,
        GuardPhase::Exhausted => 5,
        GuardPhase::Ready => 6,
        GuardPhase::Blocked => 7,
        GuardPhase::Acting => 8,
        GuardPhase::Degraded => 9,
    }
}

/// The summary of the phase of one guard.
const fn summary_of(phase: GuardPhase) -> Summary {
    match phase {
        GuardPhase::Normal => Summary::Normal,
        GuardPhase::Warning
        | GuardPhase::Qualifying
        | GuardPhase::Blocked
        | GuardPhase::Exhausted => Summary::Warning,
        GuardPhase::Recovering => Summary::Recovering,
        GuardPhase::Ready | GuardPhase::Acting | GuardPhase::Cooldown => Summary::Acting,
        GuardPhase::Degraded => Summary::Degraded,
    }
}

fn add_rule_usage(usage: &mut Vec<RuleUsage>, rule_id: &RuleId, charge: WorkCharge) {
    if let Some(entry) = usage.iter_mut().find(|entry| &entry.rule_id == rule_id) {
        entry.charge = entry.charge.checked_add(charge).unwrap_or(entry.charge);
    } else {
        usage.push(RuleUsage {
            rule_id: rule_id.clone(),
            charge,
        });
    }
}

/// Does one step of the controller.
///
/// The function reads the reports of the plans of earlier steps, gives the
/// observations to the evaluation of the two guards, keeps the windows and
/// the incident state, and decides at most one automatic plan. The memory
/// guard decides first, so its decision never waits for the disk guard.
/// The function is deterministic: the same state and the same input give
/// the same result.
#[must_use]
pub fn step(prior: &ControllerState, input: &StepInput<'_>) -> StepOutput {
    let mut run: Run<'_> = Run {
        input,
        state: prior.clone(),
        intents: Vec::new(),
        blocked: Vec::new(),
        degraded: Vec::new(),
        triggers: Vec::new(),
        paused_until: None,
        applied: false,
    };
    run.state.clean_stop = false;
    run.pause();
    run.reports();
    let disk: Option<DiskView> = run.evaluate_disk();
    let memory: Option<MemoryEvaluation> = run.evaluate_memory();
    if let Some(evaluation) = &memory {
        run.decide_memory(evaluation);
    }
    // Optional preparation does not run while the memory guard has
    // pressure.
    let memory_quiet: bool = memory.as_ref().is_some_and(|evaluation| {
        evaluation.global.state == TriggerState::Normal && run.state.memory_incident.is_none()
    });
    if let Some(view) = &disk {
        run.decide_disk(view, memory_quiet);
    }
    run.finish(disk.as_ref(), memory.as_ref())
}
