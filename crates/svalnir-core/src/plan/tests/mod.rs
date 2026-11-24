//! Tests of the manual plan builder. Each test uses synthetic inputs: no
//! file, process, or clock of the host is read.

mod apply;
mod cleanup;
mod explain;
mod owner;
mod paths;
mod review;
mod stop;

use super::{
    CleanupEntry, CleanupLimits, CleanupRequest, ModeSelection, PlanContext, PlanOutcome,
    RuleEvidence, SizeEstimate, build_cleanup_plan,
};
use crate::action::{Checked, ClientRole, ExecutorRole, FileObjectType, Principal, WorkCharge};
use crate::authority::AuthorityBinding;
use crate::config::{ValidatedConfig, parse_and_validate};
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use crate::id::{
    BootId, ClockDomainId, MountId, PlanId, PolicyRevisionId, RootId, RuleId, RuleRevisionId,
    StepId, TargetId, VolumeId,
};
use crate::policy::{ContinuityGeneration, EvaluationClock, ProtectionFact, RebuildCost};
use crate::process::Uid;
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, CandidateEligibility, DeletionMethod,
    Fact, LayoutSupport, LifecycleState, OwnerAttribution, PromotionEvidence, Retention, RootBase,
    Rule, RuleBudget, RuleDeclaration, RuleExclusions, RuleMode, RuleOwner, RuleRef,
};
use crate::time::{MonotonicNanos, WallTime};

const SECOND: u64 = 1_000_000_000;

/// The user of each plan.
const USER: Uid = Uid::new(501);

/// The time at which each plan is built, in seconds.
const BUILT_AT: u64 = 1_000;

/// The lifetime of each plan: ten minutes.
const LIFETIME: Nanoseconds = Nanoseconds::new(600 * SECOND);

/// The layout of the rule of the tests.
const LAYOUT: &str = "temporary-v1";

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

fn config_with(protections: &str) -> ValidatedConfig {
    let text: String = format!("schema_version = 1\n\n[protections]\n{protections}\n");
    let validation = parse_and_validate(&text);
    assert!(
        validation.findings().is_empty(),
        "the test configuration has findings: {:?}",
        validation.findings()
    );
    validation.config().unwrap().clone()
}

fn clock_at(seconds: u64) -> EvaluationClock {
    EvaluationClock {
        now: MonotonicNanos::new(seconds * SECOND),
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        continuity: ContinuityGeneration::new(0),
        last_discontinuity: None,
    }
}

fn principal() -> Principal {
    Principal {
        uid: USER,
        session: None,
        role: ClientRole::Cli,
    }
}

fn authority() -> AuthorityBinding {
    AuthorityBinding {
        policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
        action_grants: Vec::new(),
        privilege_grant: None,
    }
}

/// The inputs that stay the same in one test.
struct Fixture {
    config: ValidatedConfig,
    clock: EvaluationClock,
    home: Option<LosslessPath>,
}

impl Fixture {
    /// A fixture whose `[protections]` table has the lines of `text`.
    fn with_protections(text: &str) -> Self {
        Self {
            config: config_with(text),
            clock: clock_at(BUILT_AT),
            home: Some(path("/Users/a")),
        }
    }

    /// A fixture with no user protection.
    fn new() -> Self {
        Self::with_protections("")
    }

    fn context(&self) -> PlanContext<'_> {
        PlanContext {
            plan_id: PlanId::new("plan_1").unwrap(),
            principal: principal(),
            authority: authority(),
            clock: &self.clock,
            created_wall: WallTime::from_unix(1_800_000_000, 0).unwrap(),
            lifetime: LIFETIME,
            protections: self.config.protections(),
            home_directory: self.home.as_ref(),
        }
    }
}

fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
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

fn rule_reference(revision: &str) -> RuleRef {
    RuleRef {
        id: RuleId::new("svalnir.expired-temporary").unwrap(),
        revision: RuleRevisionId::new(revision).unwrap(),
    }
}

fn manual_validated() -> LifecycleState {
    LifecycleState::ManualActionValidated {
        evidence: PromotionEvidence {
            record: "VAL-07/2026-11-17/expired-temporary".to_owned(),
        },
    }
}

fn declaration(lifecycle: LifecycleState) -> RuleDeclaration {
    RuleDeclaration {
        reference: rule_reference("r1"),
        owner: RuleOwner {
            producer: "svalnir".to_owned(),
            attribution: OwnerAttribution::SvalnirLifecycleRecord,
        },
        layouts: vec![LayoutSupport {
            layout: LAYOUT.to_owned(),
            lifecycle,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::SvalnirState,
            relative: path("temporary"),
        }],
        retention: Retention {
            age_basis: AgeBasis::SvalnirLifecycleRecord,
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

fn rule_with(lifecycle: LifecycleState) -> Rule {
    Checked::new(declaration(lifecycle)).unwrap()
}

/// The rule of the tests, validated for manual eviction.
fn rule() -> Rule {
    rule_with(manual_validated())
}

/// A file serial number for the entry `name`: each name has its own
/// number, so two entries of the tests are two objects.
fn inode_of(name: &str) -> u64 {
    name.bytes()
        .fold(14_695_981_039_346_656_037_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
        })
}

/// One selected directory `/Users/a/Library/Caches/NAME` of the user, with
/// a charge of `bytes` and ten items, no protection, and satisfied evidence
/// of the rule of the tests.
fn entry(name: &str, bytes: u64) -> CleanupEntry {
    CleanupEntry {
        target_id: TargetId::new(format!("target_{name}")).unwrap(),
        step_id: StepId::new(format!("step_{name}")).unwrap(),
        path: path(&format!("/Users/a/Library/Caches/{name}")),
        root_id: RootId::new("root_caches").unwrap(),
        root_path: path("/Users/a/Library/Caches"),
        root_object: FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(2),
        },
        relative_entry: path(name),
        volume_id: VolumeId::new("volume_data").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        object_type: FileObjectType::Directory,
        owner: Some(USER),
        object: Some(FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(inode_of(name)),
        }),
        link_count: Some(EntryCount::new(1)),
        charge: Some(charge(bytes, 10)),
        estimate: SizeEstimate {
            logical_bytes: Some(Bytes::new(bytes)),
            allocated_bytes: Some(Bytes::new(bytes)),
            estimated_reclaimable_bytes: Some(Bytes::new(bytes / 2)),
        },
        hard_protection: ProtectionFact::NotProtected,
        resolved_paths: Vec::new(),
        rule: Some(RuleEvidence {
            rule: rule_reference("r1"),
            layout: LAYOUT.to_owned(),
            eligibility: satisfied(),
        }),
        repositories: Vec::new(),
    }
}

/// Limits that leave no entry of the tests out.
fn limits() -> CleanupLimits {
    CleanupLimits {
        plan: charge(1_000_000_000, 10_000),
        batch: charge(1_000_000_000, 10_000),
        execution_deadline: Nanoseconds::new(300 * SECOND),
        verification_window: Nanoseconds::new(5 * SECOND),
    }
}

fn request<'a>(mode: ModeSelection<'a>, entries: &'a [CleanupEntry]) -> CleanupRequest<'a> {
    CleanupRequest {
        mode,
        entries,
        preset: None,
        limits: limits(),
    }
}

/// Each mode, with the rule of the `evict` mode.
fn modes(rule: &Rule) -> [ModeSelection<'_>; 3] {
    [
        ModeSelection::Trash,
        ModeSelection::Permanent,
        ModeSelection::Evict { rule: Ok(rule) },
    ]
}

/// Builds a `trash` plan of the entries with no user protection.
fn trash(entries: &[CleanupEntry]) -> PlanOutcome {
    let fixture: Fixture = Fixture::new();
    build_cleanup_plan(&fixture.context(), &request(ModeSelection::Trash, entries)).unwrap()
}

/// The target identities of the plan of an outcome, in the sequence of the
/// plan.
fn planned(outcome: &PlanOutcome) -> Vec<&str> {
    outcome.plan.as_ref().map_or_else(Vec::new, |plan| {
        plan.targets
            .iter()
            .map(|target| target.target_id.as_str())
            .collect()
    })
}
