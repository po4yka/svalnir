//! Tests of the policy evaluation, with injected time and observations.
//!
//! This file has the fixtures. A time in a fixture is in whole seconds on
//! one monotonic timeline.

mod disk;
mod memory;
mod simulate;
mod window;

use super::{
    ApplicationCandidate, AssumedGrants, ContinuityGeneration, CorroboratingEvidence,
    DiskEvaluation, DiskGuardState, DiskSnapshot, EvaluationClock, EvaluationContext,
    ForegroundStatus, InventoryEvidence, MemoryEvaluation, MemoryGuardState, MemorySnapshot,
    ProtectionFact, VolumeEvidence, VolumeTrigger, evaluate_disk_guard, evaluate_memory_guard,
};
use crate::config::{ValidatedConfig, VolumeSelector, parse_and_validate};
use crate::file::{DeviceNumber, LosslessPath};
use crate::id::{
    AdapterId, ApplicationInstanceId, BootId, CapacityDomainId, ClockDomainId, CollectorEpochId,
    IdentityId, MembershipSnapshotId, MountId, ProcessGenerationId, SampleId, VolumeId, WorkerId,
};
use crate::observation::{
    Coverage, MetricId, MetricKind, Observation, Reading, Sample, Scope, ScopeKind, Source, Unit,
    metric,
};
use crate::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use crate::quantity::Bytes;
use crate::state::PressureState;
use crate::time::{MonotonicNanos, WallTime};
use crate::volume::{CapacityDomainKind, CapacityDomainMembership, VolumeIdentity};

const SECOND: u64 = 1_000_000_000;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The user of each evaluation.
const USER: Uid = Uid::new(501);

/// The configuration of the tests: the example of `docs/POLICY_SPEC.md`
/// section 4, with protected identities and an excluded path.
const BASE_CONFIG: &str = r#"
schema_version = 1

[agent]
profile = "balanced"
sample_interval = "60s"
pressure_sample_interval = "5s"
decision_sample_max_age = "10s"
max_qualifying_sample_gap = "10s"
plan_ttl = "30s"

[disk_guard]
enabled = true
volumes = ["startup-data"]
warn_below = "20GiB"
reclaim_below = "10GiB"
emergency_below = "2GiB"
recover_above = "25GiB"
sustain_for = "30s"
emergency_sustain_for = "5s"
recovery_stable_for = "60s"
batch_limit = "1GiB"
pass_limit = "8GiB"
incident_limit = "16GiB"
batch_item_limit = 256
pass_item_limit = 2048
incident_item_limit = 4096
max_passes_per_incident = 2
approved_rules = ["svalnir.expired-temporary", "xcode.inactive-derived-data"]

[disk_guard.exclusions]
paths = ["~/Documents"]

[memory_guard]
enabled = true
global_trigger = "critical"
sustain_for = "15s"
grace_period = "10s"
recovery_stable_for = "60s"
max_applications_per_incident = 3
protect_foreground = true
allow_force_quit = true
eligible_groups = ["background-user-applications", "managed-jobs"]
protected_bundle_ids = ["com.example.Protected"]
protected_executable_paths = ["/Applications/Keep.app"]

[[memory_guard.app_budgets]]
id = "build-worker"
bundle_id = "com.example.BuildWorker"
footprint_soft = "4GiB"
footprint_stop = "6GiB"
footprint_recover = "3GiB"
over_limit_for = "30s"
cooldown = "10m"
restart = "never"
"#;

fn config_from(text: &str) -> ValidatedConfig {
    let validation = parse_and_validate(text);
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

fn base_config() -> ValidatedConfig {
    config_from(BASE_CONFIG)
}

fn monotonic(seconds: u64) -> MonotonicNanos {
    MonotonicNanos::new(seconds * SECOND)
}

fn clock_at(seconds: u64, continuity: u64) -> EvaluationClock {
    EvaluationClock {
        now: monotonic(seconds),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        continuity: ContinuityGeneration::new(continuity),
        last_discontinuity: None,
    }
}

fn sample_at(id: &str, seconds: u64) -> Sample {
    Sample {
        sample_id: SampleId::new(id).unwrap(),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        collector_epoch: CollectorEpochId::new("epoch_1").unwrap(),
        started_monotonic_ns: monotonic(seconds),
        finished_monotonic_ns: monotonic(seconds),
        captured_at: WallTime::from_unix(1_800_000_000 + i64::try_from(seconds).unwrap(), 0)
            .unwrap(),
    }
}

fn observation<T>(
    metric_id: MetricId,
    scope: Scope,
    reading: Reading<T>,
    unit: Unit,
    kind: MetricKind,
    seconds: u64,
) -> Observation<T> {
    let sample_id: String = format!("s_{}_{seconds}", metric_id.as_str().replace('.', "_"));
    Observation {
        metric_id,
        scope,
        reading,
        unit,
        kind,
        coverage: Coverage::Complete,
        source: Source {
            adapter_id: AdapterId::new("adapter_test").unwrap(),
            adapter_revision: "1".to_owned(),
            native_api: "test".to_owned(),
            native_field: "test".to_owned(),
            worker_id: WorkerId::new("worker_test").unwrap(),
        },
        sample: sample_at(&sample_id, seconds),
    }
}

fn shared(domain: &str) -> CapacityDomainMembership {
    CapacityDomainMembership::Shared {
        domain_id: CapacityDomainId::new(domain).unwrap(),
        domain_kind: CapacityDomainKind::ApfsContainer,
    }
}

fn volume(name: &str, membership: CapacityDomainMembership) -> VolumeIdentity {
    VolumeIdentity {
        volume_id: VolumeId::new(format!("vol_{name}")).unwrap(),
        mount_id: MountId::new(format!("mount_{name}")).unwrap(),
        mount_point: LosslessPath::from_bytes(format!("/Volumes/{name}")).unwrap(),
        device: DeviceNumber::new(16_777_234),
        filesystem_type: "apfs".to_owned(),
        volume_uuid: None,
        capacity_domain: membership,
    }
}

fn capacity_reading(
    identity: &VolumeIdentity,
    reading: Reading<Bytes>,
    seconds: u64,
) -> Observation<Bytes> {
    observation(
        metric::DISK_AVAILABLE_BYTES,
        Scope::volume(identity.volume_id.clone()),
        reading,
        Unit::Byte,
        MetricKind::Gauge,
        seconds,
    )
}

fn volume_evidence(
    selector: &str,
    identity: VolumeIdentity,
    bytes: u64,
    seconds: u64,
) -> VolumeEvidence {
    VolumeEvidence {
        selector: VolumeSelector::new(selector).unwrap(),
        available: capacity_reading(&identity, Reading::Available(Bytes::new(bytes)), seconds),
        identity,
    }
}

/// A snapshot with the startup data volume at `bytes` of available
/// capacity, sampled at `seconds`.
fn disk_snapshot(bytes: u64, seconds: u64) -> DiskSnapshot {
    DiskSnapshot {
        rule_allowances: Vec::new(),
        volumes: vec![volume_evidence(
            "startup-data",
            volume("data", shared("domain_disk3")),
            bytes,
            seconds,
        )],
        candidates: Vec::new(),
    }
}

fn host_scope() -> Scope {
    Scope {
        kind: ScopeKind::Host,
        identity_id: IdentityId::new("host_1").unwrap(),
    }
}

fn pressure_observation(state: PressureState, seconds: u64) -> Observation<PressureState> {
    observation(
        metric::MEMORY_PRESSURE,
        host_scope(),
        Reading::Available(state),
        Unit::State,
        MetricKind::State,
        seconds,
    )
}

fn corroboration(seconds: u64) -> CorroboratingEvidence {
    CorroboratingEvidence::from_observation(&observation(
        metric::MEMORY_SWAP_USED_BYTES,
        host_scope(),
        Reading::Available(Bytes::new(3 * GIB)),
        Unit::Byte,
        MetricKind::Gauge,
        seconds,
    ))
}

/// A snapshot with the pressure state, one corroborating observation, a
/// complete inventory, and the applications, all sampled at `seconds`.
fn memory_snapshot(
    state: PressureState,
    seconds: u64,
    applications: Vec<ApplicationCandidate>,
) -> MemorySnapshot {
    MemorySnapshot {
        pressure: Some(pressure_observation(state, seconds)),
        corroborating: vec![corroboration(seconds)],
        applications,
        inventory: Some(InventoryEvidence {
            coverage: Coverage::Complete,
            sample: sample_at(&format!("s_inventory_{seconds}"), seconds),
        }),
    }
}

fn footprint_reading(
    snapshot: &MembershipSnapshotId,
    reading: Reading<Bytes>,
    seconds: u64,
) -> Observation<Bytes> {
    observation(
        metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES,
        Scope::application(snapshot.clone()),
        reading,
        Unit::Byte,
        MetricKind::Gauge,
        seconds,
    )
}

fn process(name: &str, generation: &str, association: ProcessAssociation) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(generation).unwrap(),
        pid: Pid::new(4242).unwrap(),
        start_time: ProcessStartTime::new(1_794_830_400_000_000),
        uid: USER,
        boot_id: BootId::new("boot_1").unwrap(),
        executable: Some(ExecutableIdentity {
            path: LosslessPath::from_bytes(format!(
                "/Applications/{name}.app/Contents/MacOS/{name}"
            ))
            .unwrap(),
            file: None,
            code_signature: None,
        }),
        association,
    }
}

fn application_association(name: &str) -> ProcessAssociation {
    ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new(format!("app_{name}")).unwrap(),
        bundle_identifier: format!("com.example.{name}"),
        attribution: AttributionMethod::LaunchServices,
    }
}

/// A background application `com.example.NAME` of the user, with one
/// process of generation `generation` in membership snapshot `snapshot`.
fn app_with(
    name: &str,
    generation: &str,
    snapshot: &str,
    footprint: u64,
    seconds: u64,
) -> ApplicationCandidate {
    let membership_snapshot: MembershipSnapshotId = MembershipSnapshotId::new(snapshot).unwrap();
    ApplicationCandidate {
        processes: vec![process(name, generation, application_association(name))],
        footprint: footprint_reading(
            &membership_snapshot,
            Reading::Available(Bytes::new(footprint)),
            seconds,
        ),
        membership_snapshot,
        foreground: ForegroundStatus::Background,
        hard_protection: ProtectionFact::NotProtected,
    }
}

fn app(name: &str, footprint: u64, seconds: u64) -> ApplicationCandidate {
    app_with(
        name,
        &format!("gen_{name}"),
        &format!("members_{name}"),
        footprint,
        seconds,
    )
}

/// The state of the two guards and the inputs that stay the same between
/// the evaluations of one scenario.
struct Harness {
    config: ValidatedConfig,
    disk: DiskGuardState,
    memory: MemoryGuardState,
    continuity: u64,
    /// The time of the latest clock discontinuity, in seconds.
    last_discontinuity: Option<u64>,
    grants: AssumedGrants,
    home: Option<LosslessPath>,
}

impl Harness {
    fn new() -> Self {
        Self::with_config(BASE_CONFIG)
    }

    fn with_config(text: &str) -> Self {
        Self {
            config: config_from(text),
            disk: DiskGuardState::default(),
            memory: MemoryGuardState::default(),
            continuity: 0,
            last_discontinuity: None,
            grants: AssumedGrants::hypothetical_all(),
            home: Some(LosslessPath::from_bytes("/Users/tester").unwrap()),
        }
    }

    fn clock(&self, seconds: u64) -> EvaluationClock {
        EvaluationClock {
            last_discontinuity: self.last_discontinuity.map(monotonic),
            ..clock_at(seconds, self.continuity)
        }
    }

    fn context<'a>(&'a self, clock: &'a EvaluationClock) -> EvaluationContext<'a> {
        EvaluationContext {
            config: &self.config,
            clock,
            grants: self.grants,
            principal: USER,
            home_directory: self.home.as_ref(),
        }
    }

    /// Evaluates the disk guard at `seconds` and keeps the next state.
    fn disk(&mut self, seconds: u64, snapshot: &DiskSnapshot) -> DiskEvaluation {
        let clock: EvaluationClock = self.clock(seconds);
        let evaluation: DiskEvaluation =
            evaluate_disk_guard(&self.context(&clock), &self.disk, snapshot).unwrap();
        self.disk = evaluation.next_state.clone();
        evaluation
    }

    /// Evaluates the disk guard with a fresh capacity sample at `seconds`.
    fn disk_at(&mut self, seconds: u64, bytes: u64) -> VolumeTrigger {
        self.disk(seconds, &disk_snapshot(bytes, seconds))
            .volumes
            .remove(0)
    }

    /// Gives the same capacity every five seconds, from `from` to `to`.
    fn disk_hold(&mut self, from: u64, to: u64, bytes: u64) -> VolumeTrigger {
        let mut last: Option<VolumeTrigger> = None;
        for seconds in (from..=to).step_by(5) {
            last = Some(self.disk_at(seconds, bytes));
        }
        last.unwrap()
    }

    /// Evaluates the memory guard at `seconds` and keeps the next state.
    fn memory(&mut self, seconds: u64, snapshot: &MemorySnapshot) -> MemoryEvaluation {
        let clock: EvaluationClock = self.clock(seconds);
        let evaluation: MemoryEvaluation =
            evaluate_memory_guard(&self.context(&clock), &self.memory, snapshot).unwrap();
        self.memory = evaluation.next_state.clone();
        evaluation
    }

    /// Evaluates the memory guard with a fresh pressure sample at
    /// `seconds` and no application.
    fn pressure_at(&mut self, seconds: u64, state: PressureState) -> MemoryEvaluation {
        self.memory(seconds, &memory_snapshot(state, seconds, Vec::new()))
    }

    /// Evaluates the memory guard with normal pressure and the build
    /// worker at `footprint`, sampled at `seconds`.
    fn worker_at(&mut self, seconds: u64, footprint: u64) -> MemoryEvaluation {
        let worker: ApplicationCandidate = app("BuildWorker", footprint, seconds);
        self.memory(
            seconds,
            &memory_snapshot(PressureState::Normal, seconds, vec![worker]),
        )
    }

    /// Gives the same footprint every five seconds, from `from` to `to`.
    fn worker_hold(&mut self, from: u64, to: u64, footprint: u64) -> MemoryEvaluation {
        let mut last: Option<MemoryEvaluation> = None;
        for seconds in (from..=to).step_by(5) {
            last = Some(self.worker_at(seconds, footprint));
        }
        last.unwrap()
    }
}

/// An allowance with no practical bound for each rule of the candidates.
pub(super) fn ample_allowances(
    candidates: &[crate::policy::CleanupCandidate],
) -> Vec<crate::policy::RuleAllowance> {
    let mut allowances: Vec<crate::policy::RuleAllowance> = Vec::new();
    for candidate in candidates {
        if allowances
            .iter()
            .all(|rule| rule.rule_id != candidate.rule_id)
        {
            allowances.push(crate::policy::RuleAllowance {
                rule_id: candidate.rule_id.clone(),
                remaining_bytes: Bytes::new(u64::MAX),
                remaining_items: crate::quantity::EntryCount::new(u64::MAX),
            });
        }
    }
    allowances
}
