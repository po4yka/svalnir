//! Tests of the controller step with injected observations. No test
//! reads a clock, a file, or a process, and no test changes the host.

mod rearm;
pub(crate) mod support;

use svalnir_core::action::{ActionClass, Escalation, Plan, TargetBinding, TriggerClass};
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::grant::{AuthorityState, InstanceInhibition};
use svalnir_core::id::{ExecutorEpochId, IncidentId, OperationId, PlanId};
use svalnir_core::policy::{ApplicationCandidate, ForegroundStatus};
use svalnir_core::quantity::ByteDelta;
use svalnir_core::state::PressureState;

use self::support::{
    CandidateSpec, GIBIBYTE, RULE, Registry, SECOND, candidate_set, config, config_text,
    disk_grant_revoked, enabled, epoch, job, memory, memory_grant_revoked, observations, paused,
    paused_for, proposed_registry, resumed, rule, time, user, validated_registry,
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
    /// The inhibition of the agent instance.
    inhibition: InstanceInhibition,
    /// The home directory of the agent. The default `[protections]` table
    /// has paths below it, and no candidate of the bench is there.
    home: LosslessPath,
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
            inhibition: InstanceInhibition::default(),
            home: LosslessPath::from_bytes("/Users/test").unwrap(),
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
            home_directory: Some(&self.home),
            config: &self.config,
            authority: self.authority.as_ref(),
            inhibition: &self.inhibition,
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

/// `disk` with a candidate set that an `FSEvents` invalidation marked.
fn invalidated_disk(available: u64, specs: &[CandidateSpec]) -> impl Fn(u64) -> Observations + '_ {
    move |at| {
        let mut made: Observations = disk(available, specs)(at);
        if let Some(set) = &mut made.candidates {
            set.invalidated = true;
        }
        made
    }
}

#[test]
fn an_invalidated_set_asks_for_a_discovery_in_a_warning() {
    let mut bench = Bench::new();
    let all = specs();
    // A fresh set asks for no discovery.
    let output = bench.run(60 * SECOND, disk(15 * GIBIBYTE, &all));
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Warning);
    assert_eq!(preparations(&output), Vec::<PreparationMode>::new());
    // The same set, invalidated: a bounded discovery, as for an old set.
    let output = bench.run(0, invalidated_disk(15 * GIBIBYTE, &all));
    assert_eq!(preparations(&output), vec![PreparationMode::Refresh]);
    assert_eq!(applies(&output).len(), 0);
}

#[test]
fn an_invalidated_set_starts_no_discovery_in_an_incident() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(20 * SECOND, disk(5 * GIBIBYTE, &[]));
    bench.run(10 * SECOND, disk(5 * GIBIBYTE, &[]));
    assert_eq!(bench.state.disk_incidents.len(), 1);
    // In an incident the invalidation adds no work: no discovery, and the
    // set supports a plan whose targets the coordinator checks again.
    bench.advance(SAMPLE);
    let output = bench.step(&invalidated_disk(5 * GIBIBYTE, &all)(bench.now), &[]);
    assert!(!preparations(&output).contains(&PreparationMode::Refresh));
    assert_eq!(the_apply(&output).plan.targets.len(), 2);
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
fn an_eviction_that_submitted_no_call_ends_the_pass_and_starts_a_backoff() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let first: PlanId = bench.state.outstanding.as_ref().unwrap().plan_id.clone();
    let plan_report = ApplyReport::Finished {
        plan_id: first,
        result: OperationResult {
            state: "Skipped".to_owned(),
            completed: false,
            // Each target was skipped at its step: no call was submitted.
            possibly_submitted: false,
            unknown_outcome: false,
            // Other activity freed space in the window of the operation.
            capacity_gain: Some(ByteDelta::new(4_096).unwrap()),
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

    // The guard does not make a new plan in each observation window.
    let output = bench.run(600 * SECOND, disk(5 * GIBIBYTE, &all));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Cooldown);
    assert_eq!(applies(&output).len(), 0);
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
        inhibition: InstanceInhibition::default(),
        home: LosslessPath::from_bytes("/Users/test").unwrap(),
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
}

#[test]
fn a_sample_that_is_older_than_the_decision_age_supports_no_plan() {
    let mut bench = Bench::new();
    // The critical window runs until a fresh sample supports a plan. The
    // state of the bench stays one step before that plan.
    let limit: u64 = bench.now + 120 * SECOND;
    while applies(&bench.peek(&critical(two_jobs)(bench.now), &[])).is_empty() {
        assert!(bench.now < limit, "no plan in the time of the test");
        bench.step(&critical(two_jobs)(bench.now), &[]);
        bench.advance(SAMPLE);
    }
    // At this time a fresh sample supports the plan, so the age of the
    // sample is the only cause of the result below.
    let fresh = bench.peek(&critical(two_jobs)(bench.now), &[]);
    assert_eq!(the_apply(&fresh).guard, Guard::Memory);
    let old = critical(two_jobs)(bench.now - 60 * SECOND);
    let output = bench.step(&old, &[]);
    assert_eq!(output.status.summary, Summary::Degraded);
    assert_eq!(applies(&output).len(), 0);
    assert!(bench.state.outstanding.is_none());
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
    // The disk guard had no pressure for 40 seconds. Its hold ends after
    // the recovery time of 60 seconds, not at the first quiet sample.
    assert_eq!(
        bench.state.held_until_recovery,
        vec![Guard::Memory, Guard::Disk]
    );

    let normal = |at: u64| observations(Some(100 * GIBIBYTE), Some(PressureState::Normal), at);
    // The incident closes after its recovery time, and the hold ends
    // after one more recovery time with each trigger normal.
    bench.run(90 * SECOND, normal);
    assert_eq!(bench.state.held_until_recovery, vec![Guard::Memory]);
    bench.run(60 * SECOND, normal);
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
fn a_timed_pause_of_an_earlier_boot_inhibits_each_plan_until_a_resume() {
    let mut bench = Bench::new();
    let active: AuthorityState = bench.authority.clone().unwrap();
    // A pause of 6 seconds that started in an earlier boot. The wall clock
    // of this boot is far after its recorded expiry, and that is not
    // evidence that the pause ended.
    let mut earlier = paused_for(&active, bench.now, 6 * SECOND);
    if let Some(deadline) = earlier
        .pause
        .as_mut()
        .and_then(|pause| pause.deadline.as_mut())
    {
        deadline.boot_id = svalnir_core::id::BootId::new("boot_0").unwrap();
    }
    bench.authority = Some(earlier);
    let output = bench.run(30 * SECOND, critical(two_jobs));
    assert!(output.status.paused);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::Paused]
    );

    // An explicit resume ends the pause; a measurement after it supports
    // the plan.
    bench.advance(SECOND);
    bench.authority = Some(resumed(&bench.authority.clone().unwrap(), bench.now));
    bench.advance(SAMPLE);
    let output = bench.step(&critical(two_jobs)(bench.now), &[]);
    assert!(!output.status.paused);
    assert_eq!(the_apply(&output).guard, Guard::Memory);
}

#[test]
fn the_resume_floor_of_the_instance_is_a_floor_only_in_its_boot_and_clock_domain() {
    use svalnir_core::grant::MeasurementFloor;
    use svalnir_core::id::{BootId, ClockDomainId};
    use svalnir_core::time::MonotonicNanos;
    let floor = |boot: &str, domain: &str| MeasurementFloor {
        // Later than each sample of the test.
        at: MonotonicNanos::new(START + 3_600 * SECOND),
        clock_domain: ClockDomainId::new(domain).unwrap(),
        boot_id: BootId::new(boot).unwrap(),
    };
    // A floor of a different boot or of a different clock domain is not a
    // time of this timeline: each measurement of the current boot is
    // newer, as the rule of the authorization says.
    for (boot, domain) in [("boot_0", "clock_main"), ("boot_1", "clock_other")] {
        let mut bench = Bench::new();
        bench.inhibition.measurement_floor = Some(floor(boot, domain));
        bench.run(30 * SECOND, critical(two_jobs));
        // A step of the run made the plan of the memory guard.
        assert!(bench.state.outstanding.is_some(), "{boot} {domain}");
        assert!(bench.state.measurement_floor.is_none());
    }
    // The floor of this boot and this clock domain: no sample is newer,
    // so no plan is made.
    let mut bench = Bench::new();
    bench.inhibition.measurement_floor = Some(floor("boot_1", "clock_main"));
    let output = bench.run(30 * SECOND, critical(two_jobs));
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    assert!(bench.state.outstanding.is_none());
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
    // Each step of the run, with its intents: a notification is an intent
    // of the step in which the reason changed.
    let mut intents: Vec<Intent> = Vec::new();
    let mut output: StepOutput = bench.step(&low(bench.now), &[]);
    intents.extend(output.intents.iter().cloned());
    for _ in 0..12 {
        bench.advance(SAMPLE);
        output = bench.step(&low(bench.now), &[]);
        intents.extend(output.intents.iter().cloned());
    }
    assert!(bench.state.outstanding.is_none());
    assert!(
        !intents
            .iter()
            .any(|intent| matches!(intent, Intent::Apply(_)))
    );
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
    // One notification for the reason, and not one for each step.
    let blocked: usize = intents
        .iter()
        .filter(|intent| {
            matches!(
                intent,
                Intent::Notify(Notification::Blocked {
                    guard: Guard::Disk,
                    reason: BlockedReason::RuleNotValidated { .. }
                })
            )
        })
        .count();
    assert_eq!(blocked, 1);
    assert!(intents.contains(&Intent::ReduceOptionalWork(ReduceReason::IncidentOpen)));
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

#[test]
fn a_hold_after_an_unreadable_record_needs_a_sustained_recovery_and_not_a_warning() {
    let mut bench = Bench::new();
    bench.state = ControllerState::restore(PriorState::Unreadable);
    // The pressure is at the warning level, as in an incident that was
    // open before the restart. A warning does not satisfy recovery.
    let warning = |at: u64| observations(Some(100 * GIBIBYTE), Some(PressureState::Warning), at);
    bench.run(120 * SECOND, warning);
    assert!(bench.state.held_until_recovery.contains(&Guard::Memory));
    // The disk had no pressure for the recovery time: its hold ended.
    assert!(!bench.state.held_until_recovery.contains(&Guard::Disk));

    // A normal state that is shorter than the recovery time does not end
    // the hold, and a pressure state starts the time again.
    let normal = |at: u64| observations(Some(100 * GIBIBYTE), Some(PressureState::Normal), at);
    bench.run(30 * SECOND, normal);
    assert!(bench.state.held_until_recovery.contains(&Guard::Memory));
    bench.advance(SAMPLE);
    bench.run(10 * SECOND, warning);
    bench.advance(SAMPLE);
    bench.run(40 * SECOND, normal);
    assert!(bench.state.held_until_recovery.contains(&Guard::Memory));

    // The pressure is critical again: the budget that the restart lost
    // does not come back.
    bench.advance(SAMPLE);
    let output = bench.run(40 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::HeldUntilRecovery]
    );
    // The time with no pressure is not a part of the stored record.
    assert_eq!(bench.state.durable_view().quiet_since.len(), 0);
}

#[test]
fn a_pause_that_expired_between_two_steps_needs_a_measurement_after_its_expiry() {
    let mut bench = Bench::new();
    let active: AuthorityState = bench.authority.clone().unwrap();
    // The critical window starts and is not qualified at 10 seconds.
    let output = bench.run(10 * SECOND, critical(two_jobs));
    assert_eq!(applies(&output).len(), 0);
    // A pause from 11 seconds to 17 seconds. No step runs in it. The
    // sample of 16 seconds is from the pause.
    let during = critical(two_jobs)(START + 16 * SECOND);
    bench.authority = Some(paused_for(&active, START + 11 * SECOND, 6 * SECOND));
    bench.advance(8 * SECOND);
    let output = bench.step(&during, &[]);
    assert!(!output.status.paused);
    assert_eq!(applies(&output).len(), 0, "{:?}", output.status);
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    assert!(bench.state.outstanding.is_none());

    // A measurement after the expiry supports the plan.
    bench.advance(2 * SECOND);
    let output = bench.step(&critical(two_jobs)(bench.now), &[]);
    assert_eq!(the_apply(&output).guard, Guard::Memory);
}

#[test]
fn the_wait_after_a_refusal_doubles_to_a_maximum_and_an_admission_resets_it() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let mut waits: Vec<u64> = Vec::new();
    for _ in 0..5 {
        let outstanding = bench.state.outstanding.clone().unwrap();
        let refused_at: u64 = bench.now;
        let report = ApplyReport::Refused {
            plan_id: outstanding.plan_id,
            code: "lease_conflict".to_owned(),
        };
        bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
        assert!(bench.state.outstanding.is_none());
        while bench.state.outstanding.is_none() {
            assert!(bench.now - refused_at < 100 * SECOND, "{waits:?}");
            bench.advance(SECOND);
            bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[]);
        }
        waits.push((bench.now - refused_at) / SECOND);
    }
    // The observation window of the disk guard is 5 seconds.
    assert!(waits[0] <= 6, "{waits:?}");
    assert!(waits[1] >= 10, "{waits:?}");
    assert!(waits[2] >= 20, "{waits:?}");
    assert!(waits[3] >= 40, "{waits:?}");
    assert!(waits[4] <= 41, "{waits:?}");
    assert_eq!(bench.state.disk_incidents[0].refusals, 5);

    let plan = bench.state.outstanding.clone().unwrap().plan_id;
    let report = ApplyReport::Admitted {
        plan_id: plan,
        operation_id: OperationId::new("operation-1").unwrap(),
    };
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(bench.state.disk_incidents[0].refusals, 0);
    assert_eq!(bench.state.disk_incidents[0].last_refusal, None);
}

#[test]
fn an_admission_that_the_journal_did_not_record_is_planned_again_at_the_next_evaluation() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    for _ in 0..3 {
        let outstanding = bench.state.outstanding.clone().unwrap();
        // The journal was locked by a different process.
        let report = ApplyReport::Refused {
            plan_id: outstanding.plan_id.clone(),
            code: "admission_not_recorded".to_owned(),
        };
        bench.advance(SECOND);
        let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
        // The refusal released the plan, and no observation window
        // follows it: the evaluation of the same step plans again.
        assert_eq!(applies(&output).len(), 1);
        assert_ne!(
            bench.state.outstanding.as_ref().unwrap().plan_id,
            outstanding.plan_id
        );
    }
    assert_eq!(
        bench.state.disk_incidents[0].last_refusal.as_deref(),
        Some("admission_not_recorded")
    );
    // The refusals that recorded nothing are not in the sequence: the
    // first real refusal after them waits one window, with no doubling.
    assert_eq!(bench.state.disk_incidents[0].refusals, 0);
    let outstanding = bench.state.outstanding.clone().unwrap();
    let refused_at: u64 = bench.now;
    let report = ApplyReport::Refused {
        plan_id: outstanding.plan_id,
        code: "lease_conflict".to_owned(),
    };
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(bench.state.disk_incidents[0].refusals, 1);
    while bench.state.outstanding.is_none() {
        assert!(bench.now - refused_at < 100 * SECOND);
        bench.advance(SECOND);
        bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[]);
    }
    // The observation window of the disk guard is 5 seconds.
    assert!((bench.now - refused_at) / SECOND <= 6);
}

#[test]
fn a_rearm_does_not_release_a_plan_in_progress_and_is_not_applied_two_times() {
    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    let outstanding = bench.state.outstanding.clone().unwrap();
    let recorded = bench.state.memory_incident.clone().unwrap().budget;
    let mut newer = recorded.clone();
    newer.generation = recorded.generation.next().unwrap();
    // A plan of the incident is in progress: its reservation stays.
    assert!(!bench.state.apply_rearm(newer.clone(), &epoch("epoch_1")));
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().reserved_slots,
        1
    );

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
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        1
    );
    // The recorded generation gives no new budget.
    assert!(!bench.state.apply_rearm(recorded, &epoch("epoch_1")));
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        1
    );
    // A newer generation does, one time.
    assert!(bench.state.apply_rearm(newer.clone(), &epoch("epoch_1")));
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        0
    );
    bench
        .state
        .policy
        .memory
        .incident
        .as_mut()
        .unwrap()
        .consumed_slots = 1;
    assert!(!bench.state.apply_rearm(newer, &epoch("epoch_1")));
    assert_eq!(
        bench.state.policy.memory.incident.unwrap().consumed_slots,
        1
    );
}

#[test]
fn a_full_cooldown_list_drops_the_cooldown_that_ends_first() {
    use svalnir_core::policy::{ApplicationCooldown, Cooldown, CooldownCause};

    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    let outstanding = bench.state.outstanding.clone().unwrap();
    // The list is full of cooldowns in effect. The first entry is the
    // longest one.
    let reading = time(bench.now);
    for index in 0..super::MAX_APPLICATION_COOLDOWNS {
        let seconds: u64 = if index == 0 {
            9_000
        } else {
            600 + index as u64
        };
        bench
            .state
            .policy
            .memory
            .cooldowns
            .push(ApplicationCooldown {
                application: format!("com.example.filler-{index}"),
                cooldown: Cooldown {
                    cause: CooldownCause::ApplicationRelaunch,
                    until: svalnir_core::time::MonotonicNanos::new(bench.now + seconds * SECOND),
                    clock_domain: reading.clock.clock_domain.clone(),
                    boot_id: reading.clock.boot_id.clone(),
                },
            });
    }
    bench.advance(SAMPLE);
    let report = ApplyReport::Finished {
        plan_id: outstanding.plan_id,
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
    bench.step(&critical(two_jobs)(bench.now), &[report]);
    let cooldowns = &bench.state.policy.memory.cooldowns;
    assert_eq!(cooldowns.len(), super::MAX_APPLICATION_COOLDOWNS);
    let has = |name: &str| cooldowns.iter().any(|entry| entry.application == name);
    assert!(has("com.example.filler-0"));
    assert!(!has("com.example.filler-1"));
    assert!(has("com.example.alpha"));
}

#[test]
fn reports_above_the_bound_are_a_degraded_state() {
    let mut bench = Bench::new();
    let reports: Vec<ApplyReport> = (0..=super::MAX_REPORTS)
        .map(|index| ApplyReport::Refused {
            plan_id: PlanId::new(format!("plan-{index}")).unwrap(),
            code: "none".to_owned(),
        })
        .collect();
    let normal = observations(Some(100 * GIBIBYTE), Some(PressureState::Normal), bench.now);
    let output = bench.step(&normal, &reports);
    assert!(
        output
            .status
            .degraded
            .contains(&"reports_dropped".to_owned())
    );
    assert_eq!(output.status.summary, Summary::Degraded);
}

#[test]
fn with_both_guards_critical_and_no_candidate_set_no_discovery_starts() {
    let mut bench = Bench::new();
    // The runtime has no candidate set, so the disk guard must ask for
    // one. In the emergency it asks only for the known candidates.
    let both = |at: u64| {
        let mut made: Observations =
            observations(Some(5 * GIBIBYTE), Some(PressureState::Critical), at);
        made.memory = memory(Some(PressureState::Critical), at, two_jobs(at));
        made
    };
    let mut modes: Vec<PreparationMode> = Vec::new();
    for _ in 0..12 {
        let output = bench.step(&both(bench.now), &[]);
        modes.extend(preparations(&output));
        bench.advance(SAMPLE);
    }
    assert!(!modes.contains(&PreparationMode::Refresh), "{modes:?}");
}

/// The report of a plan that completed with the capacity gain `gain`.
fn completed_with_gain(plan_id: PlanId, gain: i128) -> ApplyReport {
    ApplyReport::Finished {
        plan_id,
        result: OperationResult {
            state: "Completed".to_owned(),
            completed: true,
            possibly_submitted: true,
            unknown_outcome: false,
            capacity_gain: Some(ByteDelta::new(gain).unwrap()),
            pressure_after: None,
            cooldown_until: None,
        },
    }
}

/// One background job whose foreground status is `status`.
fn one_job(status: ForegroundStatus) -> impl Fn(u64) -> Vec<ApplicationCandidate> {
    move |at| {
        vec![support::with_foreground(
            job("alpha", 4_001, 3 * GIBIBYTE, at),
            status,
        )]
    }
}

#[test]
fn a_pause_and_a_resume_on_the_disk_path_inhibit_the_plan_and_need_a_fresh_measurement() {
    let mut bench = Bench::new();
    let all = specs();
    let active: AuthorityState = bench.authority.clone().unwrap();
    // The incident is open before the pause, and its first plan is complete.
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let plan_id: PlanId = bench.state.outstanding.clone().unwrap().plan_id;
    bench.advance(SAMPLE);
    let report = completed_with_gain(plan_id, 3_000);
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(bench.state.disk_incidents.len(), 1);
    assert!(bench.state.outstanding.is_none());
    let incident_id: IncidentId = bench.state.disk_incidents[0].incident_id.clone();
    bench.authority = Some(paused(&active, bench.now));
    let output = bench.run(40 * SECOND, disk(5 * GIBIBYTE, &all));
    assert!(output.status.paused);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::Paused]
    );
    // The pause does not reset the incident.
    assert_eq!(bench.state.disk_incidents.len(), 1);
    assert_eq!(bench.state.disk_incidents[0].incident_id, incident_id);

    // The resume. The sample is from before it, so it supports no action.
    let before = disk(5 * GIBIBYTE, &all)(bench.now);
    bench.advance(SECOND);
    bench.authority = Some(resumed(&bench.authority.clone().unwrap(), bench.now));
    let output = bench.step(&before, &[]);
    assert!(!output.status.paused);
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    assert!(bench.state.measurement_floor.is_some());

    // A measurement after the resume supports the plan.
    bench.advance(SAMPLE - SECOND);
    let output = bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[]);
    assert_eq!(the_apply(&output).guard, Guard::Disk);
}

#[test]
fn a_revoked_disk_grant_stops_the_incident_with_a_specific_reason() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let plan_id: PlanId = bench.state.outstanding.clone().unwrap().plan_id;
    bench.advance(SAMPLE);
    let report = completed_with_gain(plan_id, 3_000);
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    assert_eq!(
        bench.state.policy.disk.incidents[0]
            .usage
            .consumed_bytes
            .get(),
        3_000
    );

    // The user revokes the grant during the incident. The candidate set
    // has a candidate that is eligible, so only the grant is the cause.
    bench.authority = Some(disk_grant_revoked(&bench.authority.clone().unwrap()));
    let third = [CandidateSpec::synthetic("third", 13, 4_000)];
    let output = bench.run(120 * SECOND, disk(5 * GIBIBYTE, &third));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    let blocked = &guard(&output, Guard::Disk).blocked;
    assert!(
        matches!(
            blocked.as_slice(),
            [BlockedReason::GuardNotActive { standing }] if standing.contains("revoked")
        ),
        "{blocked:?}"
    );
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Blocked);
    // The incident and its usage stay.
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.usage.consumed_bytes.get(), 3_000);
    assert_eq!(incident.usage.reserved_bytes.get(), 0);
}

#[test]
fn a_clean_restart_keeps_the_cooldown_of_an_open_disk_incident() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let plan_id: PlanId = bench.state.outstanding.clone().unwrap().plan_id;
    bench.advance(SAMPLE);
    let reported_at: u64 = bench.now;
    // The removal completed and the capacity did not increase: a backoff.
    let report = completed_with_gain(plan_id, 0);
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    let stored_cooldown = bench.state.policy.disk.incidents[0].cooldown.clone();
    let incident_id: IncidentId = bench.state.disk_incidents[0].incident_id.clone();
    assert_eq!(
        stored_cooldown.as_ref().unwrap().until.get(),
        reported_at + 900 * SECOND
    );

    let mut view: ControllerState = bench.state.durable_view();
    view.clean_stop = true;
    let stored: String = serde_json::to_string(&view).unwrap();
    bench.state = ControllerState::restore(PriorState::Recorded(Box::new(
        serde_json::from_str(&stored).unwrap(),
    )));
    bench.epoch = epoch("epoch_2");
    assert!(bench.state.disk_incidents[0].established);
    assert_eq!(bench.state.disk_incidents[0].incident_id, incident_id);
    let incident = &bench.state.policy.disk.incidents[0];
    assert_eq!(incident.cooldown, stored_cooldown);

    // Before the end of the stored cooldown, no plan is made, although the
    // candidates are eligible.
    let output = bench.run(600 * SECOND, disk(5 * GIBIBYTE, &all));
    assert_eq!(applies(&output).len(), 0);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Cooldown);
    // After it, the same incident makes its next plan.
    bench.run(320 * SECOND, disk(5 * GIBIBYTE, &all));
    let outstanding = bench.state.outstanding.clone().unwrap();
    assert_eq!(outstanding.incident_id, incident_id);
}

#[test]
fn an_interrupted_disk_plan_after_an_unclean_restart_keeps_its_charge_and_blocks_the_incident() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let outstanding = bench.state.outstanding.clone().unwrap();
    let before = &bench.state.policy.disk.incidents[0].usage;
    assert_eq!(before.reserved_bytes.get(), 3_000);
    assert_eq!(before.consumed_bytes.get(), 0);

    // The agent stops with the plan in progress, with no clean stop.
    let stored: String = serde_json::to_string(&bench.state.durable_view()).unwrap();
    let recorded: ControllerState = serde_json::from_str(&stored).unwrap();
    bench.state = ControllerState::restore(PriorState::Recorded(Box::new(recorded)));
    bench.epoch = epoch("epoch_2");
    assert!(bench.state.outstanding.is_none());
    let record = bench.state.disk_incidents[0].clone();
    assert_eq!(record.incident_id, outstanding.incident_id);
    assert!(!record.established);
    assert!(record.unknown_outcome);
    // The reservation of the interrupted plan is a charge now.
    let usage = &bench.state.policy.disk.incidents[0].usage;
    assert_eq!(usage.reserved_bytes.get(), 0);
    assert_eq!(usage.consumed_bytes.get(), 3_000);

    // The pressure continues with eligible candidates, and the incident
    // permits no automatic work.
    bench.advance(30 * SECOND);
    let third = [CandidateSpec::synthetic("third", 13, 4_000)];
    let output = bench.run(40 * SECOND, disk(5 * GIBIBYTE, &third));
    assert!(bench.state.outstanding.is_none());
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::IncidentStateNotEstablished]
    );
    assert_eq!(guard(&output, Guard::Disk).phase, GuardPhase::Exhausted);
}

#[test]
fn a_foreground_application_and_an_unknown_foreground_state_are_not_stopped() {
    // Control: the same state with a background application gives a plan.
    let mut control = Bench::new();
    let limit: u64 = control.now + 120 * SECOND;
    let background = critical(one_job(ForegroundStatus::Background));
    while applies(&control.peek(&background(control.now), &[])).is_empty() {
        assert!(control.now < limit, "no plan in the time of the test");
        control.step(&background(control.now), &[]);
        control.advance(SAMPLE);
    }
    assert_eq!(
        the_apply(&control.peek(&background(control.now), &[])).guard,
        Guard::Memory
    );

    // The same state and time, with the application in the foreground, and
    // then with no foreground evidence: no plan, and the guard says why.
    for status in [ForegroundStatus::Foreground, ForegroundStatus::Unknown] {
        let mut bench = Bench::new();
        bench.state = control.state.clone();
        bench.now = control.now;
        let output = bench.run(40 * SECOND, critical(one_job(status)));
        assert_eq!(applies(&output).len(), 0, "{status:?}");
        assert!(bench.state.outstanding.is_none(), "{status:?}");
        assert_eq!(
            guard(&output, Guard::Memory).blocked,
            vec![BlockedReason::NoEligibleTarget],
            "{status:?}"
        );
    }
}

#[test]
fn the_next_batch_waits_for_the_end_of_the_observation_window_and_starts_at_its_end() {
    let mut bench = Bench::new();
    let all = specs();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &all));
    let plan_id: PlanId = bench.state.outstanding.clone().unwrap().plan_id;
    bench.advance(SAMPLE);
    let report = completed_with_gain(plan_id, 3_000);
    bench.step(&disk(5 * GIBIBYTE, &all)(bench.now), &[report]);
    let until: u64 = bench.state.disk_incidents[0]
        .observe_until
        .clone()
        .unwrap()
        .until
        .get();
    assert!(until > bench.now);

    // The incident has a slot left and a new candidate is eligible.
    let third = [CandidateSpec::synthetic("third", 13, 4_000)];
    let at_end = |now: u64| disk(5 * GIBIBYTE, &third)(now);
    bench.now = until - 1;
    let output = bench.peek(&at_end(bench.now), &[]);
    assert_eq!(applies(&output).len(), 0);
    assert_eq!(
        guard(&output, Guard::Disk).blocked,
        vec![BlockedReason::ObservingOutcome]
    );
    bench.now = until;
    let output = bench.step(&at_end(bench.now), &[]);
    assert_eq!(the_apply(&output).guard, Guard::Disk);
}

#[test]
fn the_durable_resume_floor_applies_to_a_controller_that_did_not_see_the_pause() {
    let mut bench = Bench::new();
    let active: AuthorityState = bench.authority.clone().unwrap();
    // A client paused and resumed while this controller did not run. The
    // instance of the controller has no floor of its own.
    bench.authority = Some(resumed(
        &paused(&active, bench.now),
        bench.now + 40 * SECOND,
    ));
    // Each sample of the run is from before the resume.
    let output = bench.run(30 * SECOND, critical(two_jobs));
    assert_eq!(applies(&output).len(), 0);
    assert!(bench.state.outstanding.is_none());
    assert_eq!(
        guard(&output, Guard::Memory).blocked,
        vec![BlockedReason::AwaitingFreshMeasurement]
    );
    // A sample after the resume supports the plan.
    bench.run(30 * SECOND, critical(two_jobs));
    assert!(bench.state.outstanding.is_some());
}

#[test]
fn a_stored_incident_record_with_no_refusal_count_is_not_read() {
    // No compatibility default: a record of a different form is not read.
    let mut bench = Bench::new();
    bench.run(35 * SECOND, disk(5 * GIBIBYTE, &specs()));
    let mut disk_value = serde_json::to_value(&bench.state.disk_incidents[0]).unwrap();
    assert!(serde_json::from_value::<super::DiskIncidentRecord>(disk_value.clone()).is_ok());
    disk_value.as_object_mut().unwrap().remove("refusals");
    assert!(serde_json::from_value::<super::DiskIncidentRecord>(disk_value).is_err());

    let mut bench = Bench::new();
    bench.run(20 * SECOND, critical(two_jobs));
    let record = bench.state.memory_incident.clone().unwrap();
    let mut memory_value = serde_json::to_value(&record).unwrap();
    assert!(serde_json::from_value::<super::MemoryIncidentRecord>(memory_value.clone()).is_ok());
    memory_value.as_object_mut().unwrap().remove("refusals");
    assert!(serde_json::from_value::<super::MemoryIncidentRecord>(memory_value).is_err());
}
