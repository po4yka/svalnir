//! The fixtures of the controller tests and of the runtime tests.
//!
//! Each value is synthetic: a configuration text, authority records that
//! the grant module made, a registry with one test rule, and observations
//! with a time that the test gives. No fixture reads the host, except
//! [`user`], which reads the effective user of the test process.

use svalnir_core::action::Checked;
use svalnir_core::action::{FileObjectType, WorkCharge};
use svalnir_core::config::{ValidatedConfig, VolumeSelector, parse_and_validate};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};
use svalnir_core::grant::{
    Acceptance, ActivationRequest, AuthorityState, ControlClock, EnableRequest, InstanceInhibition,
    PauseRequest, Persistence, ResumeRequest, RevokeRequest, activate, enable, pause, resume,
    revoke,
};
use svalnir_core::id::{
    ActionGrantId, AdapterId, ApplicationInstanceId, BootId, ClockDomainId, CollectorEpochId,
    ExecutorEpochId, IdentityId, MembershipSnapshotId, MountId, PolicyRevisionId,
    ProcessGenerationId, RootId, RuleId, RuleRevisionId, SampleId, TargetId, VolumeId, WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricId, MetricKind, Observation, Reading, Sample, Scope, ScopeKind, Source, Unit,
    metric,
};
use svalnir_core::plan::SizeEstimate;
use svalnir_core::policy::{
    ActivityFact, ApplicationCandidate, CleanupCandidate, CleanupFacts, ContinuityGeneration,
    CorroboratingEvidence, EvaluationClock, ForegroundStatus, InventoryEvidence, MemorySnapshot,
    OwnerFact, PolicyId, ProtectionFact, RebuildCost, RuleReadiness, VolumeEvidence,
};
use svalnir_core::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, CandidateEligibility, DeletionMethod,
    Fact, LayoutSupport, LifecycleState, OwnerAttribution, PromotionEvidence, Retention, RootBase,
    Rule, RuleBudget, RuleCandidate, RuleCandidateRecord, RuleDeclaration, RuleExclusions,
    RuleMode, RuleOwner, RuleRef, RuleRegistry,
};
use svalnir_core::state::PressureState;
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::{CapacityDomainMembership, VolumeIdentity};

use crate::controller::{CandidateSet, Observations, PreparedCandidate};
use crate::coordinator::TimeReading;

pub(crate) const SECOND: u64 = 1_000_000_000;
pub(crate) const GIBIBYTE: u64 = 1024 * 1024 * 1024;
pub(crate) const VOLUME: &str = "volume_1";
pub(crate) const MOUNT: &str = "mount_1";
pub(crate) const ROOT_ID: &str = "root_1";
pub(crate) const RULE: &str = "test.cache";
pub(crate) const LAYOUT: &str = "layout-v1";

/// The configuration of the tests: the two guards are requested, and force
/// quit is permitted.
pub(crate) const CONFIG: &str = r#"
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
approved_rules = ["test.cache"]

[memory_guard]
enabled = true
global_trigger = "critical"
sustain_for = "15s"
grace_period = "10s"
recovery_stable_for = "60s"
max_applications_per_incident = 2
protect_foreground = true
allow_force_quit = true
allow_volatile_journal_on_critical = false
eligible_groups = ["background-user-applications", "managed-jobs"]
"#;

/// The effective user of the test process. The executors act only for
/// this user.
pub(crate) fn user() -> Uid {
    // SAFETY: `geteuid` has no argument, changes nothing, and does not
    // fail.
    Uid::new(unsafe { libc::geteuid() })
}

/// The test configuration with each `(from, to)` text replacement.
pub(crate) fn config_text(changes: &[(&str, &str)]) -> String {
    let mut text: String = CONFIG.to_owned();
    for (from, to) in changes {
        assert!(text.contains(from), "the configuration has no {from:?}");
        text = text.replace(from, to);
    }
    text
}

pub(crate) fn config(changes: &[(&str, &str)]) -> ValidatedConfig {
    let validation = parse_and_validate(&config_text(changes));
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

/// A registry with a fixed list of rules.
#[derive(Debug, Clone)]
pub(crate) struct Registry(pub(crate) Vec<Rule>);

impl RuleRegistry for Registry {
    fn rules(&self) -> Vec<&Rule> {
        self.0.iter().collect()
    }
}

pub(crate) fn rule_ref() -> RuleRef {
    RuleRef {
        id: RuleId::new(RULE).unwrap(),
        revision: RuleRevisionId::new("r1").unwrap(),
    }
}

/// The lifecycle state that permits automatic eviction. Only a test has a
/// rule in this state: each reviewed rule of the agent is `proposed`.
pub(crate) fn automatic() -> LifecycleState {
    LifecycleState::AutomaticEvictionValidated {
        evidence: PromotionEvidence {
            record: "test-only/no-recorded-evidence".to_owned(),
        },
    }
}

/// The test rule with `lifecycle` for its one layout.
pub(crate) fn rule(lifecycle: LifecycleState) -> Rule {
    Checked::new(RuleDeclaration {
        reference: rule_ref(),
        owner: RuleOwner {
            producer: "test".to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts: vec![LayoutSupport {
            layout: LAYOUT.to_owned(),
            lifecycle,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::UserHome,
            relative: LosslessPath::from_bytes("Library/Caches/test.cache").unwrap(),
        }],
        retention: Retention {
            age_basis: AgeBasis::FilesystemMetadata,
            minimum_age: Nanoseconds::new(3_600 * SECOND),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::SealedLifecycleRecord],
            quiescence: Nanoseconds::new(60 * SECOND),
            evidence_expiry: Nanoseconds::new(5 * SECOND),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::RegularFile, FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: RuleMode::ALL.to_vec(),
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: svalnir_core::action::ExecutorRole::User,
        rebuild_cost: RebuildCost::Low,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(1_000_000), EntryCount::new(100)),
            per_pass: WorkCharge::new(Bytes::new(10_000_000), EntryCount::new(1_000)),
        },
    })
    .unwrap()
}

/// The test-only registry: its rule permits automatic eviction.
pub(crate) fn validated_registry() -> Registry {
    Registry(vec![rule(automatic())])
}

/// The registry with the test rule in the `proposed` lifecycle state.
pub(crate) fn proposed_registry() -> Registry {
    Registry(vec![rule(LifecycleState::Proposed)])
}

pub(crate) fn wall(nanoseconds: u64) -> WallTime {
    WallTime::from_unix(
        1_800_000_000 + i64::try_from(nanoseconds / SECOND).unwrap(),
        0,
    )
    .unwrap()
}

pub(crate) fn clock_domain() -> ClockDomainId {
    ClockDomainId::new("clock_main").unwrap()
}

pub(crate) fn boot() -> BootId {
    BootId::new("boot_1").unwrap()
}

/// The time `now`, in nanoseconds, in the clock of the tests.
pub(crate) fn time(now: u64) -> TimeReading {
    TimeReading {
        clock: EvaluationClock {
            now: MonotonicNanos::new(now),
            clock_domain: clock_domain(),
            boot_id: boot(),
            continuity: ContinuityGeneration::new(0),
            last_discontinuity: None,
        },
        wall: wall(now),
    }
}

pub(crate) fn epoch(text: &str) -> ExecutorEpochId {
    ExecutorEpochId::new(text).unwrap()
}

/// The digest of a configuration text, as an activation records it.
pub(crate) fn content_digest(text: &str) -> ContentDigest {
    ContentDigest::of_bytes(text.as_bytes())
}

/// The authority record with the configuration `text` in effect as
/// `policy_1` and no grant.
pub(crate) fn activated(text: &str, registry: &dyn RuleRegistry) -> AuthorityState {
    let validation = parse_and_validate(text);
    let config: &ValidatedConfig = validation.config().unwrap();
    let request = ActivationRequest {
        principal: user(),
        config,
        content: content_digest(text),
        expected_revision: None,
        revision_id: PolicyRevisionId::new("policy_1").unwrap(),
        now: wall(0),
    };
    activate(&AuthorityState::new(user()), &request, registry)
        .unwrap()
        .acknowledge(&InstanceInhibition::default(), Persistence::Durable)
        .state
}

fn with_guard(state: &AuthorityState, policy: PolicyId) -> AuthorityState {
    let acceptance: Acceptance = match policy {
        PolicyId::DiskGuard => Acceptance::PermanentEviction,
        _ => Acceptance::ForceQuit,
    };
    with_acceptance(state, policy, acceptance)
}

fn with_acceptance(
    state: &AuthorityState,
    policy: PolicyId,
    acceptance: Acceptance,
) -> AuthorityState {
    let grant: &str = match policy {
        PolicyId::DiskGuard => "grant_disk",
        _ => "grant_memory",
    };
    let request = EnableRequest {
        principal: user(),
        policy,
        accepted: Acceptance::classes_of(&[acceptance]),
        reviewed_revision: Some(PolicyRevisionId::new("policy_1").unwrap()),
        interactive: false,
        grant_id: ActionGrantId::new(grant).unwrap(),
        now: wall(0),
    };
    let none = InstanceInhibition::default();
    enable(state, &none, &request)
        .unwrap()
        .acknowledge(&none, Persistence::Durable)
        .state
}

/// The authority record with the configuration `text` in effect and the
/// two guards enabled.
pub(crate) fn enabled(text: &str, registry: &dyn RuleRegistry) -> AuthorityState {
    let state: AuthorityState = activated(text, registry);
    let state: AuthorityState = with_guard(&state, PolicyId::DiskGuard);
    with_guard(&state, PolicyId::MemoryGuard)
}

/// The authority record of a configuration that does not permit force
/// quit: the memory guard has the acceptance of a graceful exit only.
pub(crate) fn enabled_with_application_exit(
    text: &str,
    registry: &dyn RuleRegistry,
) -> AuthorityState {
    let state: AuthorityState = activated(text, registry);
    let state: AuthorityState = with_guard(&state, PolicyId::DiskGuard);
    with_acceptance(&state, PolicyId::MemoryGuard, Acceptance::ApplicationExit)
}

/// `state` with a durable pause of all automation that has no end.
pub(crate) fn paused(state: &AuthorityState, now: u64) -> AuthorityState {
    let reading: TimeReading = time(now);
    let control = ControlClock {
        clock: &reading.clock,
        wall: reading.wall,
    };
    let request = PauseRequest {
        principal: user(),
        duration: None,
    };
    pause(state, &request, &control)
        .unwrap()
        .acknowledge(&InstanceInhibition::default(), Persistence::Durable)
        .state
}

/// `state` after a durable resume.
pub(crate) fn resumed(state: &AuthorityState, now: u64) -> AuthorityState {
    let reading: TimeReading = time(now);
    let control = ControlClock {
        clock: &reading.clock,
        wall: reading.wall,
    };
    let none = InstanceInhibition::default();
    resume(state, &none, &ResumeRequest { principal: user() }, &control)
        .unwrap()
        .acknowledge(&none, Persistence::Durable)
        .state
}

/// `state` with the grant of the memory guard revoked.
pub(crate) fn memory_grant_revoked(state: &AuthorityState) -> AuthorityState {
    let request = RevokeRequest {
        principal: user(),
        grant_id: ActionGrantId::new("grant_memory").unwrap(),
    };
    revoke(state, &request)
        .unwrap()
        .acknowledge(&InstanceInhibition::default(), Persistence::Durable)
        .state
}

// Observations.

/// The sample of a measurement that started at `at`.
pub(crate) fn sample(at: u64) -> Sample {
    Sample {
        sample_id: SampleId::new(format!("sample-{at}")).unwrap(),
        clock_domain: clock_domain(),
        boot_id: boot(),
        collector_epoch: CollectorEpochId::new("collector_1").unwrap(),
        started_monotonic_ns: MonotonicNanos::new(at),
        finished_monotonic_ns: MonotonicNanos::new(at),
        captured_at: wall(at),
    }
}

fn source() -> Source {
    Source {
        adapter_id: AdapterId::new("test.measurement").unwrap(),
        adapter_revision: "1".to_owned(),
        native_api: "test".to_owned(),
        native_field: "test".to_owned(),
        worker_id: WorkerId::new("worker_1").unwrap(),
    }
}

fn observation<T>(
    metric_id: MetricId,
    scope: Scope,
    value: Option<T>,
    unit: Unit,
    kind: MetricKind,
    at: u64,
) -> Observation<T> {
    Observation {
        metric_id,
        scope,
        reading: value.map_or(
            Reading::Unavailable(svalnir_core::observation::UnavailableReason::PermissionDenied),
            Reading::Available,
        ),
        unit,
        kind,
        coverage: Coverage::Complete,
        source: source(),
        sample: sample(at),
    }
}

fn host_scope() -> Scope {
    Scope {
        kind: ScopeKind::Host,
        identity_id: IdentityId::new("host_1").unwrap(),
    }
}

pub(crate) fn volume_id() -> VolumeId {
    VolumeId::new(VOLUME).unwrap()
}

/// The available capacity of the test volume, measured at `at`. `None`
/// is a measurement that is not available.
pub(crate) fn capacity(bytes: Option<u64>, at: u64) -> Observation<Bytes> {
    observation(
        metric::DISK_AVAILABLE_BYTES,
        Scope::volume(volume_id()),
        bytes.map(Bytes::new),
        Unit::Byte,
        MetricKind::Gauge,
        at,
    )
}

pub(crate) fn volume(bytes: Option<u64>, at: u64) -> VolumeEvidence {
    VolumeEvidence {
        selector: VolumeSelector::new("startup-data").unwrap(),
        identity: VolumeIdentity {
            volume_id: volume_id(),
            mount_id: MountId::new(MOUNT).unwrap(),
            mount_point: LosslessPath::from_bytes("/").unwrap(),
            device: DeviceNumber::new(1),
            filesystem_type: "apfs".to_owned(),
            volume_uuid: None,
            capacity_domain: CapacityDomainMembership::Exclusive,
        },
        available: capacity(bytes, at),
    }
}

pub(crate) fn pressure(state: Option<PressureState>, at: u64) -> Observation<PressureState> {
    observation(
        metric::MEMORY_PRESSURE,
        host_scope(),
        state,
        Unit::State,
        MetricKind::State,
        at,
    )
}

/// A memory snapshot at `at` with the pressure `state`, one corroborating
/// observation, a complete inventory, and `applications`.
pub(crate) fn memory(
    state: Option<PressureState>,
    at: u64,
    applications: Vec<ApplicationCandidate>,
) -> MemorySnapshot {
    MemorySnapshot {
        pressure: Some(pressure(state, at)),
        corroborating: vec![CorroboratingEvidence {
            metric_id: metric::MEMORY_VM_FREE_PAGES,
            scope: host_scope(),
            available: true,
            coverage: Coverage::Complete,
            sample: sample(at),
        }],
        applications,
        inventory: Some(InventoryEvidence {
            coverage: Coverage::Complete,
            sample: sample(at),
        }),
        application_list_may_be_stale: false,
    }
}

/// The identity of a synthetic job process.
pub(crate) fn job_member(process: i32, instance: &str, label: &str) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(format!("pg-{process}")).unwrap(),
        pid: Pid::new(process).unwrap(),
        start_time: ProcessStartTime::from_timeval(1_000, 0).unwrap(),
        uid: user(),
        boot_id: boot(),
        executable: Some(ExecutableIdentity {
            path: LosslessPath::from_bytes(format!("/opt/example/bin/job{process}")).unwrap(),
            file: Some(FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: u64::try_from(process).unwrap().into(),
            }),
            code_signature: None,
        }),
        association: ProcessAssociation::ManagedJob {
            instance_id: ApplicationInstanceId::new(instance).unwrap(),
            label: label.to_owned(),
            attribution: AttributionMethod::LaunchdJob,
        },
    }
}

/// A background job instance with the processes `members` and the
/// footprint `footprint`, measured at `at`.
pub(crate) fn application(
    membership: &str,
    members: Vec<ProcessIdentity>,
    footprint: u64,
    at: u64,
) -> ApplicationCandidate {
    let membership_snapshot = MembershipSnapshotId::new(membership).unwrap();
    ApplicationCandidate {
        processes: members,
        membership_snapshot: membership_snapshot.clone(),
        foreground: ForegroundStatus::Background,
        footprint: observation(
            metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES,
            Scope::application(membership_snapshot),
            Some(Bytes::new(footprint)),
            Unit::Byte,
            MetricKind::Gauge,
            at,
        ),
        hard_protection: ProtectionFact::NotProtected,
    }
}

/// A synthetic job instance `name` with one process.
pub(crate) fn job(name: &str, process: i32, footprint: u64, at: u64) -> ApplicationCandidate {
    application(
        &format!("members-{name}"),
        vec![job_member(
            process,
            &format!("instance-{name}"),
            &format!("com.example.{name}"),
        )],
        footprint,
        at,
    )
}

fn satisfied() -> CandidateEligibility {
    CandidateEligibility {
        rule_supports_layout: Fact::Satisfied,
        identity_matches: Fact::Satisfied,
        within_authorized_scope: Fact::Satisfied,
        regenerable: Fact::Satisfied,
        age_and_inactivity: Fact::Satisfied,
        protocols_valid: Fact::Satisfied,
        no_exclusion_overlap: Fact::Satisfied,
        unit_and_charge_known: Fact::Satisfied,
        resources_available: Fact::Satisfied,
        fresh_check: Fact::Satisfied,
    }
}

/// The description of one prepared candidate of the test rule.
#[derive(Debug, Clone)]
pub(crate) struct CandidateSpec {
    pub(crate) name: String,
    pub(crate) root_path: LosslessPath,
    pub(crate) object: FileObjectEvidence,
    pub(crate) object_type: FileObjectType,
    pub(crate) work_bytes: u64,
}

impl CandidateSpec {
    /// A synthetic candidate `name` below `/cache/root`.
    pub(crate) fn synthetic(name: &str, inode: u64, work_bytes: u64) -> Self {
        Self {
            name: name.to_owned(),
            root_path: LosslessPath::from_bytes("/cache/root").unwrap(),
            object: FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: inode.into(),
            },
            object_type: FileObjectType::RegularFile,
            work_bytes,
        }
    }

    pub(crate) fn target_id(&self) -> TargetId {
        TargetId::new(format!(
            "file:{}:{}",
            self.object.device.get(),
            self.object.inode.get()
        ))
        .unwrap()
    }
}

/// A prepared candidate of `rule` with each eligibility fact satisfied.
pub(crate) fn prepared(rule: &Rule, spec: &CandidateSpec) -> PreparedCandidate {
    let mut path: Vec<u8> = spec.root_path.as_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(spec.name.as_bytes());
    let charge = WorkCharge::new(Bytes::new(spec.work_bytes), EntryCount::new(1));
    let record = RuleCandidateRecord {
        candidate: CleanupCandidate {
            target_id: spec.target_id(),
            rule_id: rule.reference.id.clone(),
            volume_id: volume_id(),
            path: LosslessPath::from_bytes(path).unwrap(),
            work_bytes: Some(charge.work_bytes),
            item_count: Some(charge.items),
            estimated_reclaimable_bytes: Some(charge.work_bytes),
            facts: CleanupFacts {
                // A rule that does not permit automatic eviction has no
                // candidate that is ready.
                rule_readiness: if rule.permits(LAYOUT, &RuleMode::AutomaticEviction).is_ok() {
                    RuleReadiness::Ready
                } else {
                    RuleReadiness::NotReady
                },
                hard_protection: ProtectionFact::NotProtected,
                protected_classes: Vec::new(),
                owner: OwnerFact::RequestingUser,
                activity: ActivityFact::Inactive {
                    inactive_for: Nanoseconds::new(30 * 24 * 3_600 * SECOND),
                },
                rebuild_cost: RebuildCost::Low,
            },
        },
        rule: rule.reference.clone(),
        layout: LAYOUT.to_owned(),
        eligibility: satisfied(),
    };
    PreparedCandidate {
        candidate: RuleCandidate::new(rule, record).unwrap(),
        root_id: RootId::new(ROOT_ID).unwrap(),
        root_path: spec.root_path.clone(),
        relative_entry: LosslessPath::from_bytes(spec.name.as_bytes()).unwrap(),
        mount_id: MountId::new(MOUNT).unwrap(),
        object_type: spec.object_type.clone(),
        owner: Some(user()),
        object: Some(spec.object),
        charge: Some(charge),
        estimate: SizeEstimate::default(),
    }
}

/// A complete candidate set that was prepared at `at`.
pub(crate) fn candidate_set(rule: &Rule, specs: &[CandidateSpec], at: u64) -> CandidateSet {
    CandidateSet {
        prepared_at: MonotonicNanos::new(at),
        complete: true,
        candidates: specs.iter().map(|spec| prepared(rule, spec)).collect(),
    }
}

/// The observations of one step: the available capacity and the memory
/// pressure at `at`, with no application and no candidate set.
pub(crate) fn observations(
    available: Option<u64>,
    state: Option<PressureState>,
    at: u64,
) -> Observations {
    Observations {
        volumes: vec![volume(available, at)],
        memory: memory(state, at, Vec::new()),
        candidates: None,
    }
}
