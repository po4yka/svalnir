//! Tests of the controller step with injected observations. No test
//! reads a clock, a file, or a process, and no test changes the host.

pub(crate) mod support;

use svalnir_core::action::{ActionClass, Escalation, Plan, TargetBinding, TriggerClass};
use svalnir_core::config::ValidatedConfig;
use svalnir_core::grant::{AuthorityState, InstanceInhibition};
use svalnir_core::id::{ExecutorEpochId, OperationId, PlanId};
use svalnir_core::policy::ApplicationCandidate;
use svalnir_core::quantity::ByteDelta;
use svalnir_core::state::PressureState;

use self::support::{
    CandidateSpec, GIBIBYTE, RULE, Registry, SECOND, candidate_set, config, config_text, enabled,
    epoch, job, memory, memory_grant_revoked, observations, paused, proposed_registry, resumed,
    rule, time, user, validated_registry,
};
use super::{
    ApplyReport, AutomaticApply, BlockedReason, ControllerState, Guard, GuardPhase, GuardStatus,
    Health, Intent, Notification, Observations, OperationResult, PreparationMode, PriorState,
    ReduceReason, StepInput, StepOutput, Summary, TriggerKey, step,
};
use crate::coordinator::TriggerStanding;

/// The time of the first step of a test.
const START: u64 = 1_000 * SECOND;
/// The time between two samples of a test.
const SAMPLE: u64 = 5 * SECOND;

struct Bench {
    config: ValidatedConfig,
    authority: Option<AuthorityState>,
    registry: Registry,
    state: ControllerState,
    epoch: ExecutorEpochId,
    now: u64,
    health: Health,
}

impl Bench {
    /// The two guards active, with the test-only registry whose rule
    /// permits automatic eviction.
    fn new() -> Self {
        Self::with(validated_registry(), &[])
    }

    fn with(registry: Registry, changes: &[(&str, &str)]) -> Self {
        Self {
            config: config(changes),
            authority: Some(enabled(&config_text(changes), &registry)),
            registry,
            state: ControllerState::default(),
            epoch: epoch("epoch_1"),
            now: START,
            health: Health::default(),
        }
    }

    fn advance(&mut self, nanoseconds: u64) {
        self.now += nanoseconds;
    }

    /// Does one step at the time of the bench, with no change of the
    /// stored state.
    fn peek(&self, observations: &Observations, reports: &[ApplyReport]) -> StepOutput {
        let reading = time(self.now);
        let input = StepInput {
            time: &reading,
            epoch: &self.epoch,
            principal: user(),
            home_directory: None,
            config: &self.config,
            authority: self.authority.as_ref(),
            inhibition: &InstanceInhibition::default(),
            registry: &self.registry,
            observations,
            reports,
            health: self.health,
            control_plane: Some(&[]),
        };
        step(&self.state, &input)
    }

    fn step(&mut self, observations: &Observations, reports: &[ApplyReport]) -> StepOutput {
        let output: StepOutput = self.peek(observations, reports);
        self.state = output.state.clone();
        output
    }

    /// Gives one sample each five seconds for `duration` and returns the
    /// result of the last step. `make` makes the observations of a time.
    fn run(&mut self, duration: u64, make: impl Fn(u64) -> Observations) -> StepOutput {
        let mut output: StepOutput = self.step(&make(self.now), &[]);
        let end: u64 = self.now + duration;
        while self.now < end {
            self.advance(SAMPLE);
            output = self.step(&make(self.now), &[]);
        }
        output
    }
}

fn applies(output: &StepOutput) -> Vec<&AutomaticApply> {
    output
        .intents
        .iter()
        .filter_map(|intent| match intent {
            Intent::Apply(apply) => Some(apply.as_ref()),
            _ => None,
        })
        .collect()
}

fn the_apply(output: &StepOutput) -> &AutomaticApply {
    match applies(output).as_slice() {
        [one] => one,
        other => panic!(
            "expected one apply intent, found {}: {:?}",
            other.len(),
            output.status
        ),
    }
}

fn preparations(output: &StepOutput) -> Vec<PreparationMode> {
    output
        .intents
        .iter()
        .filter_map(|intent| match intent {
            Intent::PrepareCandidates { mode, .. } => Some(*mode),
            _ => None,
        })
        .collect()
}

fn guard(output: &StepOutput, guard: Guard) -> &GuardStatus {
    output
        .status
        .guards
        .iter()
        .find(|status| status.guard == guard)
        .unwrap()
}

fn finished(plan: &Plan, gain: Option<i128>, pressure: Option<PressureState>) -> ApplyReport {
    ApplyReport::Finished {
        plan_id: plan.plan_id.clone(),
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: gain.map(|gain| ByteDelta::new(gain).unwrap()),
            pressure_after: pressure,
            cooldown_until: None,
        },
    }
}

fn admitted(plan: &Plan, operation: &str) -> ApplyReport {
    ApplyReport::Admitted {
        plan_id: plan.plan_id.clone(),
        operation_id: OperationId::new(operation).unwrap(),
    }
}

/// The observations of a disk with `available` bytes and normal memory,
/// with the candidates `specs` prepared at the same time.
fn disk(available: u64, specs: &[CandidateSpec]) -> impl Fn(u64) -> Observations + '_ {
    move |at| {
        let mut made: Observations = observations(Some(available), Some(PressureState::Normal), at);
        if !specs.is_empty() {
            made.candidates = Some(candidate_set(&rule(support::automatic()), specs, at));
        }
        made
    }
}

/// The observations of critical memory pressure with `applications` and a
/// disk with enough capacity.
fn critical(
    applications: impl Fn(u64) -> Vec<ApplicationCandidate>,
) -> impl Fn(u64) -> Observations {
    move |at| {
        let mut made: Observations =
            observations(Some(100 * GIBIBYTE), Some(PressureState::Critical), at);
        made.memory = memory(Some(PressureState::Critical), at, applications(at));
        made
    }
}

fn two_jobs(at: u64) -> Vec<ApplicationCandidate> {
    vec![
        job("alpha", 4_001, 3 * GIBIBYTE, at),
        job("beta", 4_002, 2 * GIBIBYTE, at),
    ]
}

fn specs() -> Vec<CandidateSpec> {
    vec![
        CandidateSpec::synthetic("first", 11, 1_000),
        CandidateSpec::synthetic("second", 12, 2_000),
    ]
}

#[test]
fn a_warning_prepares_candidates_and_makes_no_plan() {
    let mut bench = Bench::new();
    let output = bench.run(60 * SECOND, disk(15 * GIBIBYTE, &[]));
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Warning);
    assert_eq!(output.status.summary, Summary::Warning);
    assert_eq!(applies(&output).len(), 0);
    // A warning can prepare candidates with a bounded discovery.
    assert_eq!(preparations(&output), vec![PreparationMode::Refresh]);
    assert_eq!(bench.state.disk_incidents.len(), 0);
}

#[test]
fn a_disk_incident_goes_from_ready_to_acting_to_recovery_and_closes() {
    let mut bench = Bench::new();
    let all = specs();
    // The entry predicate holds; the window is not qualified yet.
    let output = bench.run(20 * SECOND, disk(5 * GIBIBYTE, &[]));
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Qualifying);
    assert_eq!(applies(&output).len(), 0);

    // The trigger is ready and the runtime has no candidate set: the
    // controller asks for the known candidates only.
    let output = bench.run(10 * SECOND, disk(5 * GIBIBYTE, &[]));
    assert_eq!(preparations(&output), vec![PreparationMode::KnownOnly]);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::CandidatesNotPrepared]
    );
    assert_eq!(bench.state.disk_incidents.len(), 1);

    // With a prepared set the controller makes one plan of the first
    // batch.
    bench.advance(SAMPLE);
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[]);
    let apply = the_apply(&output).clone();
    assert_eq!(apply.guard, Guard::Disk);
    assert_eq!(apply.plan.trigger.class, TriggerClass::DiskPressure);
    assert_eq!(
        apply.plan.trigger.incident_id.as_ref(),
        Some(&bench.state.disk_incidents[0].incident_id)
    );
    assert_eq!(apply.plan.authority.action_grants.len(), 1);
    assert_eq!(apply.plan.targets.len(), 2);
    assert!(
        apply
            .plan
            .steps
            .iter()
            .all(|step| { step.action_class == ActionClass::EvictRegenerableData })
    );
    for target in &apply.plan.targets {
        let TargetBinding::File(file) = &target.binding else {
            panic!("a file target");
        };
        assert_eq!(file.rule.as_ref().unwrap().id.as_str(), RULE);
    }
    assert!(apply.allowance.work.is_some());
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Acting);
    assert_eq!(output.status.summary, Summary::Acting);
    assert_eq!(
        output.status.outstanding_plan,
        Some(apply.plan.plan_id.clone())
    );
    // The trigger of the plan holds, with its newest measurement.
    assert!(output.triggers.iter().any(|record| {
        record.key == apply.trigger && matches!(record.standing, TriggerStanding::Holds(_))
    }));

    // While the plan is in progress, no second plan is made.
    bench.advance(SAMPLE);
    let report = admitted(&apply.plan, "operation_1");
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        output.status.outstanding_operation,
        Some(OperationId::new("operation_1").unwrap())
    );

    // The result with a capacity gain: the charge is consumed, and the
    // incident observes the outcome before the next batch.
    bench.advance(SAMPLE);
    let report = finished(&apply.plan, Some(3_000), None);
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::ObservingOutcome]
    );
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Acting);
    assert!(output.intents.iter().any(|intent| matches!(
        intent,
        Intent::Notify(Notification::Finished {
            low_benefit: false,
            ..
        })
    )));
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.usage.consumed_bytes.get(), 3_000);
    assert_eq!(incident.usage.reserved_bytes.get(), 0);
    assert_eq!(incident.passes_started, 1);

    // After the observation window the same pass takes the next batch.
    let third = [CandidateSpec::synthetic("third", 13, 4_000)];
    bench.advance(10 * SECOND);
    let output = bench.step(&disk(5 * GIBIBYTE, &third)(bench.now), &[]);
    let second = the_apply(&output).clone();
    assert_ne!(second.plan.plan_id, apply.plan.plan_id);
    assert_eq!(bench.state.policy.disk.incidents[0].passes_started, 1);
    bench.advance(SAMPLE);
    let report = finished(&second.plan, Some(4_000), None);
    bench.step(&disk(5 * GIBIBYTE, &[])(bench.now), &[report]);

    // The capacity is at the recovery target: the incident stays open
    // while the recovery is not stable.
    let output = bench.run(30 * SECOND, disk(30 * GIBIBYTE, &[]));
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Recovering);
    assert_eq!(output.status.summary, Summary::Recovering);
    assert_eq!(bench.state.disk_incidents.len(), 1);
    let output = bench.run(40 * SECOND, disk(30 * GIBIBYTE, &[]));
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Normal);
    assert_eq!(output.status.summary, Summary::Normal);
    assert_eq!(bench.state.disk_incidents.len(), 0);
    assert_eq!(output.incidents.len(), 0);
}

#[test]
fn a_low_benefit_ends_the_pass_and_starts_a_backoff() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    // The first ready step with a candidate set made a plan in the run.
    let first: PlanId = bench.state.outstanding.as_ref().unwrap().plan_id.clone();
    let plan_report = ApplyReport::Finished {
        plan_id: first,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            // The removal completed, and the capacity did not increase.
            capacity_gain: Some(ByteDelta::new(0).unwrap()),
            pressure_after: None,
            cooldown_until: None,
        },
    };
    bench.advance(SAMPLE);
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[plan_report]);
    assert!(output.intents.iter().any(|intent| matches!(
        intent,
        Intent::Notify(Notification::Finished {
            low_benefit: true,
            ..
        })
    )));
    let incident = &bench.state.policy.disk.incidents[0];
    assert!(incident.current_pass.is_none());
    assert!(incident.cooldown.is_some());

    // The backoff of 15 minutes inhibits each further plan. Nothing gets
    // wider: the same rule and the same ceilings apply after it.
    let output = bench.run(600 * SECOND, disk(5 * GIBIBYTE, &all));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Cooldown);
    assert_eq!(applies(&output).len(), 0);

    bench.run(320 * SECOND, disk(5 * GIBIBYTE, &all));
    let incident = &bench.state.policy.disk.incidents[0];
    assert!(bench.state.outstanding.is_some());
    assert_eq!(incident.passes_started, 2);
}

#[test]
fn a_memory_incident_stops_one_application_at_a_time_to_its_ceiling() {
    let mut bench = Bench::new();
    let output = bench.run(10 * SECOND, critical(two_jobs));
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Qualifying);
    assert_eq!(applies(&output).len(), 0);

    let output = bench.run(10 * SECOND, critical(two_jobs));
    // The run made the plan at the first ready step.
    let outstanding = bench.state.outstanding.clone().unwrap();
    assert_eq!(outstanding.guard, Guard::Memory);
    assert_eq!(outstanding.trigger, TriggerKey::GlobalMemory);
    assert_eq!(
        outstanding.application.as_deref(),
        Some("com.example.alpha")
    );
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Acting);
    let incident = bench.state.policy.memory.incident.unwrap();
    assert_eq!((incident.consumed_slots, incident.reserved_slots), (0, 1));

    // The application exited, and the pressure is still critical. The
    // slot stays charged, and the incident backs off.
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id.clone(),
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Critical),
            cooldown_until: None,
        },
    };
    let output = bench.step(&critical(two_jobs)(bench.now), &[report]);
    assert_eq!(applies(&output).len(), 0);
    assert!(output.intents.iter().any(|intent| matches!(
        intent,
        Intent::Notify(Notification::Finished {
            low_benefit: true,
            ..
        })
    )));
    let incident = bench.state.policy.memory.incident.unwrap();
    assert_eq!((incident.consumed_slots, incident.reserved_slots), (1, 0));

    // In the observation window nothing is selected.
    bench.advance(SAMPLE);
    let output = bench.step(&critical(two_jobs)(bench.now), &[]);
    assert_eq!(applies(&output).len(), 0);

    // After it, the next eligible application is selected. The first one
    // has a relaunch cooldown under its stable identity, so the same
    // label with a new process is not selected again.
    let relaunched = |at: u64| {
        vec![
            job("alpha", 5_001, 3 * GIBIBYTE, at),
            job("beta", 4_002, 2 * GIBIBYTE, at),
            job("gamma", 4_003, GIBIBYTE, at),
        ]
    };
    let output = bench.run(20 * SECOND, critical(relaunched));
    let second = bench.state.outstanding.clone().unwrap();
    assert_eq!(second.application.as_deref(), Some("com.example.beta"));
    assert_ne!(second.plan_id, outstanding.plan_id);
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Acting);

    // The second result uses the last slot: the incident is exhausted,
    // and no third application is selected.
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: second.plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Critical),
            cooldown_until: None,
        },
    };
    bench.step(&critical(relaunched)(bench.now), &[report]);
    let output = bench.run(120 * SECOND, critical(relaunched));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Exhausted);
    assert_eq!(output.status.summary, Summary::Warning);
    let status = guard(&output, Guard::Memory);
    assert_eq!(status.incidents[0].slots_remaining, Some(0));
    assert_eq!(status.incidents[0].slots_used, Some(2));
}

#[test]
fn the_plan_of_a_memory_incident_has_the_configured_strategy_and_grace_period() {
    let mut bench = Bench::new();
    let mut plan: Option<Plan> = None;
    for _ in 0..6 {
        let output = bench.step(&critical(two_jobs)(bench.now), &[]);
        if let Some(apply) = applies(&output).first() {
            plan = Some(apply.plan.clone());
            assert_eq!(apply.allowance.slots.unwrap().ceiling(), 2);
            assert_eq!(apply.allowance.slots.unwrap().consumed(), 0);
            assert_eq!(apply.budget.incident_id, apply.allowance.incident_id);
        }
        bench.advance(SAMPLE);
    }
    let plan = plan.unwrap();
    assert_eq!(plan.trigger.class, TriggerClass::GlobalCriticalMemory);
    assert_eq!(plan.limits.escalation, Escalation::ForceAfterGrace);
    assert_eq!(plan.limits.grace.unwrap().get(), 10 * SECOND);
    let classes: Vec<&ActionClass> = plan.steps.iter().map(|step| &step.action_class).collect();
    assert_eq!(
        classes,
        vec![
            &ActionClass::RequestApplicationExit,
            &ActionClass::ForceApplicationExit
        ]
    );

    // With force quit not permitted, the plan is a graceful request only.
    let changes = [("allow_force_quit = true", "allow_force_quit = false")];
    let registry = validated_registry();
    let mut graceful = Bench {
        config: config(&changes),
        // This policy does not request force quit, so the acceptance of
        // the guard is the graceful exit.
        authority: Some(support::enabled_with_application_exit(
            &config_text(&changes),
            &registry,
        )),
        registry,
        state: ControllerState::default(),
        epoch: epoch("epoch_1"),
        now: START,
        health: Health::default(),
    };
    let mut plan: Option<Plan> = None;
    for _ in 0..6 {
        let output = graceful.step(&critical(two_jobs)(graceful.now), &[]);
        if let Some(apply) = applies(&output).first() {
            plan = Some(apply.plan.clone());
        }
        graceful.advance(SAMPLE);
    }
    let plan = plan.unwrap();
    assert_eq!(plan.limits.escalation, Escalation::None);
    assert_eq!(plan.limits.grace, None);
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(
        plan.steps[0].action_class,
        ActionClass::RequestApplicationExit
    );
}

#[test]
fn missing_evidence_is_degraded_and_never_normal() {
    let mut bench = Bench::new();
    // The pressure measurement is not available.
    let output = bench.run(30 * SECOND, |at| {
        observations(Some(100 * GIBIBYTE), None, at)
    });
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Degraded);
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Normal);
    assert_eq!(output.status.summary, Summary::Degraded);
    assert_eq!(applies(&output).len(), 0);

    // No volume was resolved, and the capacity is not available.
    let output = bench.run(30 * SECOND, |at| Observations {
        volumes: Vec::new(),
        memory: memory(Some(PressureState::Normal), at, Vec::new()),
        candidates: None,
    });
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Degraded);
    let output = bench.run(30 * SECOND, |at| {
        observations(None, Some(PressureState::Normal), at)
    });
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Degraded);
    assert_eq!(output.status.summary, Summary::Degraded);

    // A sample that is older than the decision age is not usable.
    let old = observations(Some(5 * GIBIBYTE), Some(PressureState::Critical), bench.now);
    bench.advance(60 * SECOND);
    let output = bench.step(&old, &[]);
    assert_eq!(output.status.summary, Summary::Degraded);
    assert_eq!(applies(&output).len(), 0);
}

#[test]
fn a_restart_in_the_middle_of_an_incident_does_not_replenish_the_budget() {
    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_some());
    let incident_id = bench
        .state
        .memory_incident
        .as_ref()
        .unwrap()
        .incident_id
        .clone();

    // The agent stops with the plan in progress. The record is the
    // durable view, as the journal has it.
    let stored: String = serde_json::to_string(&bench.state.durable_view()).unwrap();
    let recorded: ControllerState = serde_json::from_str(&stored).unwrap();
    bench.state = ControllerState::restore(PriorState::Recorded(Box::new(recorded)));
    bench.epoch = epoch("epoch_2");
    assert!(bench.state.outstanding.is_none());
    let record = bench.state.memory_incident.clone().unwrap();
    assert_eq!(record.incident_id, incident_id);
    assert!(!record.established);
    assert!(record.unknown_outcome);
    // The reserved slot of the interrupted plan stays charged.
    let incident = bench.state.policy.memory.incident.unwrap();
    assert_eq!((incident.consumed_slots, incident.reserved_slots), (1, 0));

    // The pressure continues. The windows start again, and the incident
    // permits no automatic work: it is exhausted for this lifetime.
    bench.advance(30 * SECOND);
    let output = bench.run(40 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::IncidentStateNotEstablished]
    );
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Exhausted);
    assert!(!guard(&output, Guard::Memory).incidents[0].established);

    // Fresh observations show a stable recovery: the incident closes. A
    // new incident has a new identity and a new budget.
    let normal = |at: u64| observations(Some(100 * GIBIBYTE), Some(PressureState::Normal), at);
    bench.run(90 * SECOND, normal);
    assert!(bench.state.memory_incident.is_none());
    bench.run(20 * SECOND, critical(two_jobs));
    let reopened = bench.state.memory_incident.clone().unwrap();
    assert_ne!(reopened.incident_id, incident_id);
    assert!(reopened.established);
    assert!(bench.state.outstanding.is_some());
}

#[test]
fn a_clean_restart_keeps_the_usage_and_the_cooldowns_of_an_open_incident() {
    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    let outstanding = bench.state.outstanding.clone().unwrap();
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Critical),
            cooldown_until: None,
        },
    };
    bench.step(&critical(two_jobs)(bench.now), &[report]);

    let mut view: ControllerState = bench.state.durable_view();
    view.clean_stop = true;
    let stored: String = serde_json::to_string(&view).unwrap();
    bench.state = ControllerState::restore(PriorState::Recorded(Box::new(
        serde_json::from_str(&stored).unwrap(),
    )));
    bench.epoch = epoch("epoch_2");
    let record = bench.state.memory_incident.clone().unwrap();
    assert!(record.established);
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        1
    );
    assert_eq!(bench.state.policy.memory.cooldowns.len(), 1);

    // The next plan of the incident has the usage of before the restart,
    // and the application of the first plan keeps its cooldown.
    bench.advance(SAMPLE);
    let mut second: Option<AutomaticApply> = None;
    for _ in 0..12 {
        let output = bench.step(&critical(two_jobs)(bench.now), &[]);
        if let Some(apply) = applies(&output).first() {
            second = Some((*apply).clone());
        }
        bench.advance(SAMPLE);
    }
    let second = second.unwrap();
    assert_eq!(second.allowance.slots.unwrap().consumed(), 1);
    assert_eq!(second.allowance.opened_in, epoch("epoch_1"));
    assert_eq!(
        bench.state.outstanding.unwrap().application.as_deref(),
        Some("com.example.beta")
    );
}

#[test]
fn a_record_that_is_not_readable_holds_each_guard_until_recovery() {
    let mut bench = Bench::new();
    bench.state = ControllerState::restore(PriorState::Unreadable);
    let output = bench.run(40 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::HeldUntilRecovery]
    );
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Exhausted);
    // The disk guard had no pressure, so its hold ended at once.
    assert_eq!(bench.state.held_until_recovery, vec![Guard::Memory]);

    let normal = |at: u64| observations(Some(100 * GIBIBYTE), Some(PressureState::Normal), at);
    bench.run(90 * SECOND, normal);
    assert_eq!(bench.state.held_until_recovery.len(), 0);
    bench.run(20 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_some());
}

#[test]
fn a_pause_inhibits_each_plan_and_a_resume_needs_a_fresh_measurement() {
    let mut bench = Bench::new();
    let active: AuthorityState = bench.authority.clone().unwrap();
    bench.authority = Some(paused(&active, bench.now));
    let output = bench.run(30 * SECOND, critical(two_jobs));
    assert!(output.status.paused);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::Paused]
    );
    // The pause does not reset the incident.
    assert!(bench.state.memory_incident.is_some());

    // The resume. The sample is from before it, so it supports no action.
    let before = critical(two_jobs)(bench.now);
    bench.advance(SECOND);
    bench.authority = Some(resumed(&bench.authority.clone().unwrap(), bench.now));
    let output = bench.step(&before, &[]);
    assert!(!output.status.paused);
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    assert!(bench.state.measurement_floor.is_some());

    // A measurement after the resume supports the plan.
    bench.advance(SAMPLE - SECOND);
    let output = bench.step(&critical(two_jobs)(bench.now), &[]);
    assert_eq!(the_apply(&output).guard, Guard::Memory);
}

#[test]
fn a_revoked_grant_stops_the_incident_with_a_specific_reason() {
    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    let outstanding = bench.state.outstanding.clone().unwrap();
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Critical),
            cooldown_until: None,
        },
    };
    bench.step(&critical(two_jobs)(bench.now), &[report]);

    // The user revokes the grant during the incident.
    bench.authority = Some(memory_grant_revoked(&bench.authority.clone().unwrap()));
    let output = bench.run(120 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    let blocked = &guard(&output, Guard::Memory).blocked;
    assert!(
        matches!(
            blocked.as_slice(),
            [BlockedReason::GuardNotActive { standing }] if standing.contains("revoked")
        ),
        "{blocked:?}"
    );
    assert_eq!(guard(&output, Guard::Memory).phase, GuardPhase::Blocked);
    // The incident and its usage stay.
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        1
    );
}

#[test]
fn with_both_guards_critical_the_memory_guard_acts_and_no_scan_starts() {
    let mut bench = Bench::new();
    let all = specs();
    // The disk predicate holds from the start, and the pressure is
    // critical from 15 seconds after it, so the two triggers qualify in
    // the same step.
    let both = |at: u64| {
        let pressure: PressureState = if at >= START + 15 * SECOND {
            PressureState::Critical
        } else {
            PressureState::Normal
        };
        let mut made: Observations = observations(Some(5 * GIBIBYTE), Some(pressure.clone()), at);
        made.memory = memory(Some(pressure), at, two_jobs(at));
        made.candidates = Some(candidate_set(&rule(support::automatic()), &all, at));
        made
    };
    let mut plans: Vec<Guard> = Vec::new();
    let mut modes: Vec<PreparationMode> = Vec::new();
    let mut last: Option<StepOutput> = None;
    for _ in 0..10 {
        let output = bench.step(&both(bench.now), &[]);
        plans.extend(applies(&output).iter().map(|apply| apply.guard));
        modes.extend(preparations(&output));
        last = Some(output);
        bench.advance(SAMPLE);
    }
    // One plan, and it is the application stop: the disk guard waits.
    assert_eq!(plans, vec![Guard::Memory]);
    // No discovery starts in the emergency.
    assert!(!modes.contains(&PreparationMode::Refresh));
    let output = last.unwrap();
    assert_eq!(
        output.intents.first(),
        Some(&Intent::ReduceOptionalWork(
            ReduceReason::SimultaneousPressure
        ))
    );
    assert!(output.status.optional_work_reduced);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::OtherGuardActing]
    );

    // After the application stop, the disk guard uses the candidates
    // that are already known.
    let memory_plan = bench.state.outstanding.clone().unwrap().plan_id;
    let report = ApplyReport::Finished {
        plan_id: memory_plan,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: None,
            pressure_after: Some(PressureState::Warning),
            cooldown_until: None,
        },
    };
    let output = bench.step(&both(bench.now), &[report]);
    assert_eq!(the_apply(&output).guard, Guard::Disk);
}

#[test]
fn a_rule_in_the_proposed_state_is_a_specific_refusal_and_not_a_plan() {
    let mut bench = Bench::with(proposed_registry(), &[]);
    let all = specs();
    let proposed = rule(svalnir_core::rule::LifecycleState::Proposed);
    let low = |at: u64| {
        let mut made: Observations =
            observations(Some(5 * GIBIBYTE), Some(PressureState::Normal), at);
        made.candidates = Some(candidate_set(&proposed, &all, at));
        made
    };
    let output = bench.run(60 * SECOND, low);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    // The controller does not prepare candidates for a rule that cannot
    // act, and it does not make a plan of another kind.
    assert_eq!(preparations(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::RuleNotValidated {
            rule: RULE.to_owned()
        }]
    );
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Blocked);
    assert_eq!(output.status.summary, Summary::Warning);
    assert!(
        output.intents.iter().any(|intent| matches!(
            intent,
            Intent::Notify(Notification::Blocked {
                guard: Guard::Disk,
                reason: BlockedReason::RuleNotValidated { .. }
            })
        )) || output
            .intents
            .contains(&Intent::ReduceOptionalWork(ReduceReason::IncidentOpen))
    );
    // The incident is open, and its budget has no charge.
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.usage.consumed_bytes.get(), 0);
    assert_eq!(incident.usage.reserved_bytes.get(), 0);
}

#[test]
fn a_refused_plan_releases_its_reservation_and_is_reported() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let outstanding = bench.state.outstanding.clone().unwrap();
    assert_ne!(
        bench.state.policy.disk.incidents[0]
            .usage
            .reserved_bytes
            .get(),
        0
    );
    bench.advance(SECOND);
    let report = ApplyReport::Refused {
        plan_id: outstanding.plan_id,
        code: "rule_mode_not_validated".to_owned(),
    };
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(applies(&output).len(), 0);
    assert!(bench.state.outstanding.is_none());
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.usage.reserved_bytes.get(), 0);
    assert_eq!(incident.usage.consumed_bytes.get(), 0);
    assert!(!incident.outstanding_operation);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::Refused {
            code: "rule_mode_not_validated".to_owned()
        }]
    );
}

#[test]
fn with_no_authority_record_the_controller_only_observes() {
    let mut bench = Bench::new();
    bench.authority = None;
    let output = bench.run(40 * SECOND, critical(two_jobs));
    assert!(output.status.observation_only);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::ObservationOnly]
    );
    assert_eq!(guard(&output, Guard::Memory).standing, "observation_only");
    // A qualified trigger with no permitted action is a warning.
    assert_eq!(output.status.summary, Summary::Warning);
}

#[test]
fn a_stopping_agent_and_a_restart_backoff_make_no_plan() {
    let mut stopping = Bench::new();
    stopping.health.stopping = true;
    let output = stopping.run(40 * SECOND, critical(two_jobs));
    assert!(stopping.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::AgentStopping]
    );

    let mut backoff = Bench::new();
    backoff.health.restart_backoff = true;
    let output = backoff.run(40 * SECOND, critical(two_jobs));
    assert!(backoff.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::RestartBackoff]
    );
    // The backoff ends: the same incident continues.
    backoff.health.restart_backoff = false;
    backoff.advance(SAMPLE);
    let output = backoff.step(&critical(two_jobs)(backoff.now), &[]);
    assert_eq!(the_apply(&output).guard, Guard::Memory);
}

#[test]
fn the_step_is_deterministic() {
    let run = || {
        let mut bench = Bench::new();
        let all = specs();
        let mut outputs: Vec<StepOutput> = Vec::new();
        for index in 0..12_u64 {
            let mut made: Observations =
                observations(Some(5 * GIBIBYTE), Some(PressureState::Critical), bench.now);
            made.memory = memory(
                Some(PressureState::Critical),
                bench.now,
                two_jobs(bench.now),
            );
            if index > 6 {
                made.candidates = Some(candidate_set(&rule(support::automatic()), &all, bench.now));
            }
            outputs.push(bench.step(&made, &[]));
            bench.advance(SAMPLE);
        }
        outputs
    };
    let first: Vec<StepOutput> = run();
    let second: Vec<StepOutput> = run();
    assert_eq!(first, second);
    assert!(first.iter().any(|output| !applies(output).is_empty()));

    // The same state and the same input give the same result, and the
    // step does not change its input state.
    let bench = Bench::new();
    let made = critical(two_jobs)(bench.now);
    let before: ControllerState = bench.state.clone();
    assert_eq!(bench.peek(&made, &[]), bench.peek(&made, &[]));
    assert_eq!(bench.state, before);
}

#[test]
fn a_full_pass_ends_with_a_pass_cooldown_and_a_restart_keeps_an_open_pass() {
    let changes = [
        ("batch_item_limit = 256", "batch_item_limit = 2"),
        ("pass_item_limit = 2048", "pass_item_limit = 2"),
    ];
    let mut bench = Bench::with(validated_registry(), &changes);
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let outstanding = bench.state.outstanding.clone().unwrap();

    // A restart in the pass does not end the pass: a new lifetime gets no
    // new pass allowance.
    let mut view: ControllerState = bench.state.durable_view();
    view.outstanding = None;
    view.clean_stop = true;
    let restored = ControllerState::restore(PriorState::Recorded(Box::new(view)));
    let incident = &restored.policy.disk.incidents[0];
    assert_eq!(incident.passes_started, 1);
    assert_eq!(incident.current_pass.unwrap().consumed_items.get(), 2);

    // The plan used the item ceiling of the pass. With a capacity gain,
    // the pass ends with the pass cooldown, and no plan follows at once.
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: Some(ByteDelta::new(3_000).unwrap()),
            pressure_after: None,
            cooldown_until: None,
        },
    };
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.current_pass, None);
    assert_eq!(
        incident.cooldown.as_ref().unwrap().cause,
        svalnir_core::policy::CooldownCause::PassPacing
    );
    let third = [CandidateSpec::synthetic("third", 13, 4_000)];
    let output = bench.run(60 * SECOND, disk(5 * GIBIBYTE, &third));
    assert_eq!(bench.state.outstanding, None);
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Cooldown);
    // After the pass cooldown of 5 minutes, the second pass starts.
    bench.run(260 * SECOND, disk(5 * GIBIBYTE, &third));
    assert_eq!(bench.state.policy.disk.incidents[0].passes_started, 2);
}

#[test]
fn no_discovery_starts_while_an_incident_is_open() {
    let mut bench = Bench::new();
    // The incident opens, and the candidates of the fixture are used.
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &specs()));
    let outstanding = bench.state.outstanding.clone().unwrap();
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: Some(ByteDelta::new(3_000).unwrap()),
            pressure_after: None,
            cooldown_until: None,
        },
    };
    bench.step(&disk(5 * GIBIBYTE, &[])(bench.now), &[report]);
    // The capacity is in the warning range, and the incident is open.
    // The candidate set is old. No discovery starts.
    bench.advance(1_000 * SECOND);
    let mut modes: Vec<PreparationMode> = Vec::new();
    for _ in 0..6 {
        let output = bench.step(&disk(15 * GIBIBYTE, &[])(bench.now), &[]);
        modes.extend(preparations(&output));
        bench.advance(SAMPLE);
    }
    assert_eq!(bench.state.disk_incidents.len(), 1);
    assert!(!modes.contains(&PreparationMode::Refresh), "{modes:?}");
}
