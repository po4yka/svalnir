//! The manual plan of one owner operation ([`super::super::build_owner_plan`]).

use super::{
    Fixture, LAYOUT, LIFETIME, SECOND, USER, charge, path, rule, rule_reference, rule_with,
};
use crate::action::{
    ActionClass, ExecutableBinding, FileTimestamp, OwnerOperationBinding, OwnerOperationBound,
    OwnerOperationKind, ScopeMeasurement, TargetBinding,
};
use crate::digest::ContentDigest;
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber};
use crate::id::{MountId, RootId, RuleId, RuleRevisionId, StepId, TargetId, VolumeId};
use crate::plan::{
    OmissionReason, OwnerPlanRequest, PlanBuildError, PlanMode, build_owner_plan, mode_of,
};
use crate::policy::ProtectionFact;
use crate::process::Uid;
use crate::quantity::{Bytes, EntryCount, Nanoseconds};
use crate::rule::{LifecycleState, RuleRef, RuleRefusal};

fn binding(kind: OwnerOperationKind) -> OwnerOperationBinding {
    let measured = ScopeMeasurement {
        allocated_bytes: Bytes::new(8192),
        private_allocated_bytes: Some(Bytes::new(8192)),
        entries: EntryCount::new(3),
        complete: true,
        measured_at: None,
    };
    OwnerOperationBinding {
        root_id: RootId::new("root_tool").unwrap(),
        root_path: path("/Users/a/Library/Caches/tool"),
        root_object: FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(9),
        },
        volume_id: VolumeId::new("volume_data").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        owner: USER,
        rule: rule_reference("r1"),
        layout: LAYOUT.to_owned(),
        operation: kind,
        clear_opt_in: matches!(kind, OwnerOperationKind::Clear),
        bound: OwnerOperationBound::Unbounded,
        executable: ExecutableBinding {
            path: path("/opt/homebrew/bin/tool"),
            object: FileObjectEvidence {
                device: DeviceNumber::new(1),
                inode: InodeNumber::new(10),
            },
            owner: USER,
            mode: 0o755,
            size: Bytes::new(64),
            changed_at: FileTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
            modified_at: FileTimestamp {
                seconds: 1,
                nanoseconds: 0,
            },
            digest: ContentDigest::of_bytes(b"tool"),
            signature: None,
        },
        interpreter: None,
        arguments: vec!["cache".to_owned(), "prune".to_owned()],
        environment: Vec::new(),
        working_directory: path("/Users/a"),
        command_deadline: Nanoseconds::new(120 * SECOND),
        charge: measured.charge().unwrap(),
        measured,
        expected_effect: "The tool removes its unused entries.".to_owned(),
    }
}

fn request(binding: &OwnerOperationBinding) -> OwnerPlanRequest<'_> {
    OwnerPlanRequest {
        target_id: TargetId::new("target_owner").unwrap(),
        step_id: StepId::new("step_owner").unwrap(),
        binding,
        rule: Err(RuleRefusal::UnknownRule),
        protection: ProtectionFact::NotProtected,
        verification_window: Nanoseconds::new(5 * SECOND),
    }
}

#[test]
fn an_owner_plan_has_one_step_and_the_limits_of_its_command() {
    let fixture = Fixture::new();
    let rule = rule();
    for kind in [OwnerOperationKind::Prune, OwnerOperationKind::Clear] {
        let binding = binding(kind);
        let outcome = build_owner_plan(
            &fixture.context(),
            &OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&binding)
            },
        )
        .unwrap();
        assert_eq!(outcome.mode, PlanMode::Owner(kind));
        let plan = outcome.plan.unwrap();
        assert_eq!(mode_of(&plan), Some(PlanMode::Owner(kind)));
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].action_class, ActionClass::RunOwnerOperation);
        assert!(matches!(
            &plan.targets[0].binding,
            TargetBinding::OwnerOperation(bound) if **bound == binding
        ));
        assert_eq!(plan.limits.work, Some(binding.charge));
        assert_eq!(
            plan.limits.execution_deadline,
            Nanoseconds::new(125 * SECOND)
        );
        // The preview has the scope root and no estimate of reclaimed
        // bytes: the producer selects its own data.
        let preview = &outcome.preview.targets[0];
        assert_eq!(preview.path.as_ref(), Some(&binding.root_path));
        assert_eq!(preview.estimate.estimated_reclaimable_bytes, None);
        assert_eq!(preview.estimate.allocated_bytes, Some(Bytes::new(8192)));
        assert_eq!(outcome.preview.batches.len(), 1);
    }
}

#[test]
fn a_protected_excluded_or_proposed_scope_is_left_out() {
    let binding = binding(OwnerOperationKind::Prune);
    let rule = rule();
    let reasons = |fixture: &Fixture, request: OwnerPlanRequest<'_>| {
        let outcome = build_owner_plan(&fixture.context(), &request).unwrap();
        assert!(outcome.plan.is_none());
        outcome.preview.omitted[0].reasons.clone()
    };
    let fixture = Fixture::new();
    assert_eq!(
        reasons(
            &fixture,
            OwnerPlanRequest {
                rule: Ok(&rule),
                protection: ProtectionFact::Protected,
                ..request(&binding)
            }
        ),
        [OmissionReason::HardProtected]
    );
    // An exclusion inside the root leaves the whole root out: the command
    // acts on the whole scope.
    let excluded = Fixture::with_protections("excluded_paths = [\"~/Library/Caches/tool/keep\"]");
    assert_eq!(
        reasons(
            &excluded,
            OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&binding)
            }
        ),
        [OmissionReason::ExcludedPath]
    );
    let proposed = rule_with(LifecycleState::Proposed);
    assert_eq!(
        reasons(
            &fixture,
            OwnerPlanRequest {
                rule: Ok(&proposed),
                ..request(&binding)
            }
        ),
        [OmissionReason::ModeNotValidated]
    );
    let mut other = binding.clone();
    other.owner = Uid::new(502);
    other.layout = "other-layout".to_owned();
    assert_eq!(
        reasons(
            &fixture,
            OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&other)
            }
        ),
        [
            OmissionReason::OtherUser,
            OmissionReason::LayoutNotSupported
        ]
    );
    let mut large = binding.clone();
    large.charge = charge(1 << 40, 4);
    assert_eq!(
        reasons(
            &fixture,
            OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&large)
            }
        ),
        [OmissionReason::ExceedsPlanLimit]
    );
}

#[test]
fn an_owner_plan_needs_the_exact_revision_and_a_deadline_inside_the_lifetime() {
    let fixture = Fixture::new();
    let binding = binding(OwnerOperationKind::Prune);
    assert_eq!(
        build_owner_plan(&fixture.context(), &request(&binding)),
        Err(PlanBuildError::Rule(RuleRefusal::UnknownRule))
    );
    let rule = rule();
    let mut other = binding.clone();
    other.rule = RuleRef {
        id: RuleId::new("svalnir.expired-temporary").unwrap(),
        revision: RuleRevisionId::new("r2").unwrap(),
    };
    assert_eq!(
        build_owner_plan(
            &fixture.context(),
            &OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&other)
            }
        ),
        Err(PlanBuildError::Rule(RuleRefusal::UnknownRevision))
    );
    let mut long = binding.clone();
    long.command_deadline = LIFETIME;
    assert_eq!(
        build_owner_plan(
            &fixture.context(),
            &OwnerPlanRequest {
                rule: Ok(&rule),
                ..request(&long)
            }
        ),
        Err(PlanBuildError::Limits)
    );
    assert_eq!(
        build_owner_plan(
            &fixture.context(),
            &OwnerPlanRequest {
                rule: Ok(&rule),
                verification_window: Nanoseconds::ZERO,
                ..request(&binding)
            }
        ),
        Err(PlanBuildError::Limits)
    );
}
