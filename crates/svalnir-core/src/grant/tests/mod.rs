//! Tests of the activation and grant logic.
//!
//! This file has the fixtures. A time in a fixture is in whole seconds on
//! one monotonic timeline, and the wall clock is at the same second.

mod authorize;
mod control;
mod pause;
mod rearm;
mod scope;

use super::{
    Acceptance, Acknowledged, ActivationReport, ActivationRequest, AuthorityState, Change,
    ControlClock, EnableRefusal, EnableReport, EnableRequest, InstanceInhibition, Persistence,
    activate,
};
use crate::action::{
    ActionClass, ApplicationBinding, Checked, ClientRole, Escalation, ExecutorRole, FileBinding,
    FileObjectType, PLAN_SCHEMA_VERSION, Plan, PlanContent, PlanLimits, PlanTarget, PlannedStep,
    Principal, TargetBinding, Trigger, TriggerClass, Validity, WorkCharge,
};
use crate::authority::{ActionGrant, ActionGrantRef, AuthorityBinding};
use crate::config::{ValidatedConfig, parse_and_validate};
use crate::digest::ContentDigest;
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use crate::id::{
    ActionGrantId, ApplicationInstanceId, BootId, ClockDomainId, DecisionId, IncidentId,
    MembershipSnapshotId, MountId, PlanId, PolicyRevisionId, ProcessGenerationId, RootId, RuleId,
    RuleRevisionId, StepId, TargetId, VolumeId,
};
use crate::policy::{ContinuityGeneration, EvaluationClock, PolicyId, RebuildCost};
use crate::process::{
    AttributionMethod, Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid,
};
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, LayoutSupport,
    LifecycleState, OwnerAttribution, PromotionEvidence, Retention, RootBase, Rule, RuleBudget,
    RuleDeclaration, RuleExclusions, RuleMode, RuleOwner, RuleRef, RuleRegistry,
};
use crate::time::{MonotonicNanos, WallTime};

const SECOND: u64 = 1_000_000_000;

/// The user of each record.
const USER: Uid = Uid::new(501);

/// The layout of each rule of the test registry.
const LAYOUT: &str = "layout-v1";

/// The configuration of the tests: the two guards are requested, force
/// quit is permitted, and the critical-memory exception is not.
const BASE_CONFIG: &str = r#"
schema_version = 1

[agent]
profile = "balanced"
sample_interval = "60s"
pressure_sample_interval = "5s"
decision_sample_max_age = "10s"
max_qualifying_sample_gap = "10s"
plan_ttl = "30s"

[protections]
excluded_paths = ["~/Keep"]

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
allow_volatile_journal_on_critical = false
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

/// The base configuration with each `(from, to)` text replacement.
fn config(changes: &[(&str, &str)]) -> ValidatedConfig {
    let mut text: String = BASE_CONFIG.to_owned();
    for (from, to) in changes {
        assert!(
            text.contains(from),
            "the base configuration has no {from:?}"
        );
        text = text.replace(from, to);
    }
    let validation = parse_and_validate(&text);
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

fn base_config() -> ValidatedConfig {
    config(&[])
}

/// A registry with a fixed list of rules.
struct Registry(Vec<Rule>);

impl RuleRegistry for Registry {
    fn rules(&self) -> Vec<&Rule> {
        self.0.iter().collect()
    }
}

fn rule_ref(id: &str, revision: &str) -> RuleRef {
    RuleRef {
        id: RuleId::new(id).unwrap(),
        revision: RuleRevisionId::new(revision).unwrap(),
    }
}

fn evidence() -> PromotionEvidence {
    PromotionEvidence {
        record: "VAL-07/2026-11-17/example".to_owned(),
    }
}

fn automatic() -> LifecycleState {
    LifecycleState::AutomaticEvictionValidated {
        evidence: evidence(),
    }
}

fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
}

fn declaration(id: &str, revision: &str, lifecycle: LifecycleState) -> RuleDeclaration {
    RuleDeclaration {
        reference: rule_ref(id, revision),
        owner: RuleOwner {
            producer: "example".to_owned(),
            attribution: OwnerAttribution::ProducerLayout,
        },
        layouts: vec![LayoutSupport {
            layout: LAYOUT.to_owned(),
            lifecycle,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::UserHome,
            relative: LosslessPath::from_bytes(format!("Library/Caches/{id}")).unwrap(),
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
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::Low,
        budget: RuleBudget {
            per_candidate: charge(1_000_000, 100),
            per_pass: charge(10_000_000, 1_000),
            measurement_expiry: Nanoseconds::new(600 * SECOND),
        },
    }
}

fn rule(id: &str, revision: &str, lifecycle: LifecycleState) -> Rule {
    Checked::new(declaration(id, revision, lifecycle)).unwrap()
}

const TEMPORARY: &str = "svalnir.expired-temporary";
const DERIVED_DATA: &str = "xcode.inactive-derived-data";

/// The two rules of the base configuration, revision `r1`, each with the
/// lifecycle state `lifecycle` for the layout of the tests.
fn registry_with(lifecycle: &LifecycleState) -> Registry {
    Registry(vec![
        rule(TEMPORARY, "r1", lifecycle.clone()),
        rule(DERIVED_DATA, "r1", lifecycle.clone()),
    ])
}

/// The two rules, validated for automatic eviction.
fn registry() -> Registry {
    registry_with(&automatic())
}

fn monotonic(seconds: u64) -> MonotonicNanos {
    MonotonicNanos::new(seconds * SECOND)
}

fn wall(seconds: u64) -> WallTime {
    WallTime::from_unix(1_800_000_000 + i64::try_from(seconds).unwrap(), 0).unwrap()
}

fn clock_in(boot: &str, seconds: u64) -> EvaluationClock {
    EvaluationClock {
        now: monotonic(seconds),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new(boot).unwrap(),
        continuity: ContinuityGeneration::new(0),
        last_discontinuity: None,
    }
}

fn clock(seconds: u64) -> EvaluationClock {
    clock_in("boot_1", seconds)
}

/// The control clock of `clock`, with the wall clock at `wall_seconds`.
fn control(clock: &EvaluationClock, wall_seconds: u64) -> ControlClock<'_> {
    ControlClock {
        clock,
        wall: wall(wall_seconds),
    }
}

fn revision_id(text: &str) -> PolicyRevisionId {
    PolicyRevisionId::new(text).unwrap()
}

fn grant_id(text: &str) -> ActionGrantId {
    ActionGrantId::new(text).unwrap()
}

/// The digest of a configuration. Two different configurations have
/// different digests.
fn digest(config: &ValidatedConfig) -> ContentDigest {
    ContentDigest::of_bytes(format!("{config:?}").as_bytes())
}

/// A request to activate `config` as `revision`, which expects the
/// revision in effect of `state`.
fn activation<'a>(
    state: &AuthorityState,
    config: &'a ValidatedConfig,
    revision: &str,
) -> ActivationRequest<'a> {
    ActivationRequest {
        principal: USER,
        config,
        content: digest(config),
        expected_revision: state
            .active
            .as_ref()
            .map(|active| active.revision.revision_id.clone()),
        revision_id: revision_id(revision),
        now: wall(10),
    }
}

/// Completes a change with a durable write and no volatile state.
fn durable<R>(change: Change<R>) -> Acknowledged<R> {
    change.acknowledge(&InstanceInhibition::default(), Persistence::Durable)
}

/// Activates `config` durably.
fn activated(
    state: &AuthorityState,
    config: &ValidatedConfig,
    revision: &str,
) -> (AuthorityState, ActivationReport) {
    let change = activate(state, &activation(state, config, revision), &registry()).unwrap();
    let acknowledged = durable(change);
    (acknowledged.state, acknowledged.report)
}

/// A noninteractive request to enable `policy` with `acceptances`, which
/// names the revision in effect of `state`.
fn enable_request(
    state: &AuthorityState,
    policy: PolicyId,
    acceptances: &[Acceptance],
) -> EnableRequest {
    EnableRequest {
        principal: USER,
        policy,
        accepted: Acceptance::classes_of(acceptances),
        reviewed_revision: state
            .active
            .as_ref()
            .map(|active| active.revision.revision_id.clone()),
        grant_id: grant_id(match policy {
            PolicyId::DiskGuard => "grant_disk",
            PolicyId::MemoryGuard => "grant_memory",
        }),
        now: wall(20),
    }
}

/// An enable request in an instance with no inhibition.
fn enable(
    state: &AuthorityState,
    request: &EnableRequest,
) -> Result<Change<EnableReport>, EnableRefusal> {
    super::enable(state, &InstanceInhibition::default(), request)
}

/// Enables `policy` durably.
fn enabled(state: &AuthorityState, policy: PolicyId, acceptances: &[Acceptance]) -> AuthorityState {
    let change = enable(state, &enable_request(state, policy, acceptances)).unwrap();
    durable(change).state
}

/// A record with `config` in effect as `policy_1` and no grant.
fn active_state(config: &ValidatedConfig) -> AuthorityState {
    activated(&AuthorityState::new(USER), config, "policy_1").0
}

/// A record with the base configuration in effect and the two guards
/// enabled.
fn enabled_state() -> AuthorityState {
    let state = active_state(&base_config());
    let state = enabled(
        &state,
        PolicyId::DiskGuard,
        &[Acceptance::PermanentEviction],
    );
    enabled(&state, PolicyId::MemoryGuard, &[Acceptance::ForceQuit])
}

fn grant(state: &AuthorityState, policy: PolicyId) -> &ActionGrant {
    state.guard(policy).unwrap().grant.as_ref().unwrap()
}

fn grant_ref(state: &AuthorityState, policy: PolicyId) -> ActionGrantRef {
    grant(state, policy).reference()
}

// Plans.

fn target_id(text: &str) -> TargetId {
    TargetId::new(text).unwrap()
}

fn step(id: &str, class: ActionClass, target: &str) -> PlannedStep {
    PlannedStep {
        step_id: StepId::new(id).unwrap(),
        action_class: class,
        target_id: target_id(target),
    }
}

fn incident_id() -> IncidentId {
    IncidentId::new("incident_1").unwrap()
}

fn automatic_trigger(class: TriggerClass) -> Trigger {
    Trigger {
        class,
        incident_id: Some(incident_id()),
        decision_id: Some(DecisionId::new("decision_1").unwrap()),
        budget_generation: Some(crate::authority::Generation::new(1)),
    }
}

fn file_binding(rule: Option<RuleRef>) -> FileBinding {
    FileBinding {
        root_id: RootId::new("root_1").unwrap(),
        root_path: LosslessPath::from_bytes("/Users/a/Library/Caches").unwrap(),
        root_object: FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(2),
        },
        // A target of a rule has the layout that the rule found.
        layout: rule.as_ref().map(|_| LAYOUT.to_owned()),
        relative_entry: LosslessPath::from_bytes("entry").unwrap(),
        volume_id: VolumeId::new("volume_1").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        object_type: FileObjectType::RegularFile,
        owner: USER,
        object: None,
        rule,
        charge: charge(60, 1),
        repositories: Vec::new(),
    }
}

fn member(generation: &str, pid: i32) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(generation).unwrap(),
        pid: Pid::new(pid).unwrap(),
        start_time: ProcessStartTime::from_timeval(1_794_830_400, 0).unwrap(),
        uid: USER,
        boot_id: BootId::new("boot_1").unwrap(),
        executable: None,
        association: ProcessAssociation::Application {
            instance_id: ApplicationInstanceId::new("app_1").unwrap(),
            bundle_identifier: "com.example.Example".to_owned(),
            attribution: AttributionMethod::LaunchServices,
        },
    }
}

/// The policy revision in effect of `state`, or `policy_0` when there is
/// none.
fn bound_revision(state: &AuthorityState) -> PolicyRevisionId {
    state.active.as_ref().map_or_else(
        || revision_id("policy_0"),
        |active| active.revision.revision_id.clone(),
    )
}

/// A manual plan of one file step `s1` of `class`, valid from second 100
/// to second 1000, bound to the revision in effect of `state`.
fn file_content(state: &AuthorityState, class: &ActionClass, rule: Option<RuleRef>) -> PlanContent {
    PlanContent {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: PlanId::new("plan_1").unwrap(),
        principal: Principal {
            uid: USER,
            session: None,
            role: ClientRole::Cli,
        },
        trigger: Trigger::manual(),
        authority: AuthorityBinding {
            policy_revision: bound_revision(state),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        executor: ExecutorRole::User,
        targets: vec![PlanTarget {
            target_id: target_id("a"),
            binding: TargetBinding::File(file_binding(rule)),
        }],
        steps: vec![step("s1", class.clone(), "a")],
        limits: PlanLimits {
            work: Some(charge(100, 2)),
            execution_deadline: Nanoseconds::new(30 * SECOND),
            grace: None,
            verification_window: Nanoseconds::new(5 * SECOND),
            escalation: Escalation::None,
        },
        validity: Validity {
            clock_domain: ClockDomainId::new("clock_main").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            created_at: monotonic(100),
            expires_at: monotonic(1_000),
            created_wall: wall(100),
        },
    }
}

/// A manual application plan with the force strategy `escalation`: the
/// steps `graceful` and `force`, as the strategy has them.
fn application_content(state: &AuthorityState, escalation: Escalation) -> PlanContent {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let steps = match escalation {
        Escalation::ForceAfterGrace => vec![
            step("graceful", RequestApplicationExit, "app"),
            step("force", ForceApplicationExit, "app"),
        ],
        Escalation::ImmediateForce => vec![step("force", ForceApplicationExit, "app")],
        _ => vec![step("graceful", RequestApplicationExit, "app")],
    };
    let grace =
        matches!(escalation, Escalation::ForceAfterGrace).then_some(Nanoseconds::new(10 * SECOND));
    let base = file_content(state, &ActionClass::MoveToTrash, None);
    PlanContent {
        targets: vec![PlanTarget {
            target_id: target_id("app"),
            binding: TargetBinding::Application(ApplicationBinding {
                instance_id: ApplicationInstanceId::new("app_1").unwrap(),
                membership: MembershipSnapshotId::new("members_1").unwrap(),
                members: vec![member("proc_1", 4242)],
            }),
        }],
        steps,
        limits: PlanLimits {
            work: None,
            grace,
            escalation,
            ..base.limits.clone()
        },
        ..base
    }
}

/// Makes `content` the plan of an automatic trigger of `policy`, bound to
/// the current grant of the guard.
fn as_automatic(
    state: &AuthorityState,
    mut content: PlanContent,
    class: TriggerClass,
    policy: PolicyId,
) -> PlanContent {
    content.trigger = automatic_trigger(class);
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![grant_ref(state, policy)];
    content
}

/// The automatic eviction plan of the disk guard, with a target of the
/// rule `svalnir.expired-temporary` revision `r1`.
fn eviction_plan(state: &AuthorityState) -> Plan {
    eviction_plan_of_layout(state, LAYOUT)
}

/// The automatic eviction plan of the disk guard, with a target that the
/// rule found in `layout`.
fn eviction_plan_of_layout(state: &AuthorityState, layout: &str) -> Plan {
    let mut content = file_content(
        state,
        &ActionClass::EvictRegenerableData,
        Some(rule_ref(TEMPORARY, "r1")),
    );
    if let TargetBinding::File(file) = &mut content.targets[0].binding {
        file.layout = Some(layout.to_owned());
    }
    seal(as_automatic(
        state,
        content,
        TriggerClass::DiskPressure,
        PolicyId::DiskGuard,
    ))
}

/// The automatic intervention plan of the memory guard.
fn intervention_plan(state: &AuthorityState, class: TriggerClass, escalation: Escalation) -> Plan {
    seal(as_automatic(
        state,
        application_content(state, escalation),
        class,
        PolicyId::MemoryGuard,
    ))
}

fn seal(content: PlanContent) -> Plan {
    Plan::seal(content).unwrap()
}
