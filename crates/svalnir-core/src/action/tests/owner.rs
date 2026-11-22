//! Tests of the owner-operation binding, its plan, its envelope, and its
//! results (`docs/ACTION_CONTRACTS.md` sections 3, 7, and 9).

use serde_json::json;

use super::super::{
    EnvironmentEntry, ExecutableBinding, OwnerOperationBinding, OwnerOperationBound,
    OwnerOperationKind, ScopeAllocationEffect, ScopeMeasurement,
};
use super::{
    ActionClass, Attribution, Check, Checked, ClientRole, DispatchState, EffectEvidence,
    EnvelopeContent, EnvelopeError, ExecutorRole, LeaseResource, NativeResult, PlanContent,
    PlanError, PlanTarget, Reservation, StopReason, TargetBinding, TargetEffect,
    TargetResultRecord, TriggerClass, automatic, charge, file_content, file_envelope, file_target,
    grant_ref, privilege_ref, record, rule, seal, step, target_id,
};
use crate::digest::ContentDigest;
use crate::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use crate::id::{MountId, RootId, VolumeId};
use crate::plan::{PlanMode, mode_of};
use crate::process::Uid;
use crate::quantity::{ByteDelta, Bytes, EntryCount, Nanoseconds};

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

fn measurement(allocated: u64, private: Option<u64>, complete: bool) -> ScopeMeasurement {
    ScopeMeasurement {
        allocated_bytes: Bytes::new(allocated),
        private_allocated_bytes: private.map(Bytes::new),
        entries: EntryCount::new(3),
        complete,
        measured_at: None,
    }
}

fn owner_binding(kind: OwnerOperationKind) -> OwnerOperationBinding {
    OwnerOperationBinding {
        root_id: RootId::new("root_owner").unwrap(),
        root_path: path("/Users/a/Library/Caches/tool"),
        root_object: FileObjectEvidence {
            device: DeviceNumber::new(16_777_234),
            inode: InodeNumber::new(77),
        },
        volume_id: VolumeId::new("volume_1").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        owner: Uid::new(501),
        rule: rule(),
        layout: "layout-v1".to_owned(),
        operation: kind,
        clear_opt_in: matches!(kind, OwnerOperationKind::Clear),
        bound: OwnerOperationBound::WithinScope,
        executable: ExecutableBinding {
            path: path("/Users/a/.local/bin/tool"),
            object: FileObjectEvidence {
                device: DeviceNumber::new(16_777_234),
                inode: InodeNumber::new(88),
            },
            owner: Uid::new(501),
            mode: 0o755,
            size: Bytes::new(120),
            digest: ContentDigest::of_bytes(b"#!/bin/sh\nexit 0\n"),
            signature: None,
        },
        arguments: vec!["cache".to_owned(), "prune".to_owned()],
        environment: vec![EnvironmentEntry {
            name: "HOME".to_owned(),
            value: "/Users/a".to_owned(),
        }],
        working_directory: path("/Users/a"),
        command_deadline: Nanoseconds::new(10_000_000_000),
        measured: measurement(4096, Some(4096), true),
        charge: charge(4096, 4),
        expected_effect: "The tool removes the entries that no project uses.".to_owned(),
    }
}

fn owner_target(kind: OwnerOperationKind) -> PlanTarget {
    PlanTarget {
        target_id: target_id("owner"),
        binding: TargetBinding::OwnerOperation(owner_binding(kind)),
    }
}

/// A manual plan with one owner operation of `kind`.
fn owner_content(kind: OwnerOperationKind) -> PlanContent {
    let mut content: PlanContent = file_content(&ActionClass::RunOwnerOperation);
    content.targets = vec![owner_target(kind)];
    content.steps = vec![step("s1", ActionClass::RunOwnerOperation, "owner")];
    content.limits.work = Some(charge(4096, 4));
    content
}

fn owner_of(content: &mut PlanContent) -> &mut OwnerOperationBinding {
    let TargetBinding::OwnerOperation(owner) = &mut content.targets[0].binding else {
        panic!("the first target is not an owner operation");
    };
    owner
}

fn automatic_owner_content(kind: OwnerOperationKind) -> PlanContent {
    let mut content: PlanContent = owner_content(kind);
    content.trigger = automatic(TriggerClass::DiskPressure);
    content.principal.role = ClientRole::Agent;
    content.authority.action_grants = vec![grant_ref()];
    content
}

#[test]
fn a_manual_owner_operation_plan_seals_and_has_the_mode_of_its_kind() {
    for kind in [OwnerOperationKind::Prune, OwnerOperationKind::Clear] {
        let plan = seal(owner_content(kind));
        assert_eq!(mode_of(&plan), Some(PlanMode::Owner(kind)));
        let text = serde_json::to_string(&plan).unwrap();
        assert_eq!(
            serde_json::from_str::<super::super::Plan>(&text).unwrap(),
            plan
        );
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(
            value["content"]["targets"][0]["binding"]["kind"],
            json!("owner_operation")
        );
        assert_eq!(
            value["content"]["targets"][0]["binding"]["kind"],
            json!("owner_operation")
        );
    }
}

#[test]
fn the_digest_covers_the_executable_and_the_arguments() {
    let first = seal(owner_content(OwnerOperationKind::Prune));
    let mut changed = owner_content(OwnerOperationKind::Prune);
    owner_of(&mut changed).executable.digest = ContentDigest::of_bytes(b"other");
    assert_ne!(seal(changed).digest(), first.digest());
    let mut changed = owner_content(OwnerOperationKind::Prune);
    owner_of(&mut changed).arguments.push("--all".to_owned());
    assert_ne!(seal(changed).digest(), first.digest());
}

#[test]
fn a_bounded_prune_is_the_only_automatic_owner_operation() {
    let plan = seal(automatic_owner_content(OwnerOperationKind::Prune));
    assert!(plan.trigger.class.is_automatic());
    // A `clear` is manual only, and an unbounded command too.
    assert_eq!(
        super::super::Plan::seal(automatic_owner_content(OwnerOperationKind::Clear)),
        Err(PlanError::Trigger)
    );
    let mut unbounded = automatic_owner_content(OwnerOperationKind::Prune);
    owner_of(&mut unbounded).bound = OwnerOperationBound::Unbounded;
    assert_eq!(super::super::Plan::seal(unbounded), Err(PlanError::Trigger));
    // A manual unbounded command seals.
    let mut manual = owner_content(OwnerOperationKind::Prune);
    owner_of(&mut manual).bound = OwnerOperationBound::Unbounded;
    assert!(super::super::Plan::seal(manual).is_ok());
}

#[test]
#[expect(clippy::too_many_lines, reason = "the test is one table of cases")]
fn an_owner_operation_plan_that_does_not_agree_with_itself_is_rejected() {
    type Change = Box<dyn Fn(&mut PlanContent)>;
    let cases: Vec<(&str, Change, PlanError)> = vec![
        (
            "clear with no opt-in",
            Box::new(|c| owner_of(c).clear_opt_in = false),
            PlanError::Binding,
        ),
        (
            "opt-in for a prune",
            Box::new(|c| owner_of(c).clear_opt_in = true),
            PlanError::Binding,
        ),
        (
            "helper executor",
            Box::new(|c| {
                c.executor = ExecutorRole::Helper;
                c.authority.privilege_grant = Some(privilege_ref());
            }),
            PlanError::Binding,
        ),
        (
            "scope of another user",
            Box::new(|c| owner_of(c).owner = Uid::new(502)),
            PlanError::Binding,
        ),
        (
            "relative executable",
            Box::new(|c| owner_of(c).executable.path = path("bin/tool")),
            PlanError::Binding,
        ),
        (
            "executable with a dot component",
            Box::new(|c| owner_of(c).executable.path = path("/Users/a/../tool")),
            PlanError::Binding,
        ),
        (
            "relative working directory",
            Box::new(|c| owner_of(c).working_directory = path("a")),
            PlanError::Binding,
        ),
        (
            "too many arguments",
            Box::new(|c| owner_of(c).arguments = vec!["x".to_owned(); 33]),
            PlanError::Binding,
        ),
        (
            "argument with a NUL byte",
            Box::new(|c| owner_of(c).arguments = vec!["a\0b".to_owned()]),
            PlanError::Binding,
        ),
        (
            "lower-case environment name",
            Box::new(|c| owner_of(c).environment[0].name = "home".to_owned()),
            PlanError::Binding,
        ),
        (
            "environment name two times",
            Box::new(|c| {
                let again = owner_of(c).environment[0].clone();
                owner_of(c).environment.push(again);
            }),
            PlanError::Binding,
        ),
        (
            "zero deadline",
            Box::new(|c| owner_of(c).command_deadline = Nanoseconds::ZERO),
            PlanError::Binding,
        ),
        (
            "deadline after the execution deadline",
            Box::new(|c| owner_of(c).command_deadline = Nanoseconds::new(31_000_000_000)),
            PlanError::Binding,
        ),
        (
            "charge smaller than the measurement",
            Box::new(|c| {
                owner_of(c).charge = charge(100, 3);
                c.limits.work = Some(charge(100, 3));
            }),
            PlanError::Binding,
        ),
        (
            "executable that the group can change",
            Box::new(|c| owner_of(c).executable.mode = 0o775),
            PlanError::Binding,
        ),
        (
            "executable of another user",
            Box::new(|c| owner_of(c).executable.owner = Uid::new(502)),
            PlanError::Binding,
        ),
        (
            "empty layout",
            Box::new(|c| owner_of(c).layout.clear()),
            PlanError::Binding,
        ),
        (
            "empty effect statement",
            Box::new(|c| owner_of(c).expected_effect.clear()),
            PlanError::Binding,
        ),
        (
            "eviction class on an owner target",
            Box::new(|c| c.steps[0].action_class = ActionClass::EvictRegenerableData),
            PlanError::Binding,
        ),
        (
            "limit smaller than the charge",
            Box::new(|c| c.limits.work = Some(charge(10, 1))),
            PlanError::Limits,
        ),
        (
            "two operations on one root",
            Box::new(|c| {
                let mut second = owner_target(OwnerOperationKind::Prune);
                second.target_id = target_id("owner_2");
                c.targets.push(second);
                c.steps
                    .push(step("s2", ActionClass::RunOwnerOperation, "owner_2"));
                c.limits.work = Some(charge(8192, 8));
            }),
            PlanError::Duplicate,
        ),
    ];
    for (name, change, expected) in cases {
        let mut content = owner_content(if name == "clear with no opt-in" {
            OwnerOperationKind::Clear
        } else {
            OwnerOperationKind::Prune
        });
        change(&mut content);
        assert_eq!(
            super::super::Plan::seal(content),
            Err(expected),
            "the case `{name}`"
        );
    }
    // A file target is not the scope of a command.
    let mut content = file_content(&ActionClass::RunOwnerOperation);
    content.targets.truncate(1);
    content.steps.truncate(1);
    content.limits.work = Some(charge(60, 1));
    assert_eq!(super::super::Plan::seal(content), Err(PlanError::Binding));
    // Owner operations of two kinds have no one consequence.
    let mut mixed = owner_content(OwnerOperationKind::Prune);
    let mut second = owner_target(OwnerOperationKind::Clear);
    second.target_id = target_id("owner_2");
    if let TargetBinding::OwnerOperation(owner) = &mut second.binding {
        owner.root_id = RootId::new("root_other").unwrap();
        owner.root_object.inode = InodeNumber::new(78);
    }
    mixed.targets.push(second);
    mixed
        .steps
        .push(step("s2", ActionClass::RunOwnerOperation, "owner_2"));
    mixed.limits.work = Some(charge(8192, 8));
    assert_eq!(super::super::Plan::seal(mixed), Err(PlanError::Steps));
    // An owner operation and an eviction are two classes.
    let mut classes = owner_content(OwnerOperationKind::Prune);
    classes.targets.push(file_target("a", 60));
    classes
        .steps
        .push(step("s2", ActionClass::EvictRegenerableData, "a"));
    classes.limits.work = Some(charge(8192, 8));
    assert_eq!(super::super::Plan::seal(classes), Err(PlanError::Steps));
}

#[test]
fn an_owner_envelope_repeats_the_checks_of_the_plan() {
    let plan = seal(owner_content(OwnerOperationKind::Prune));
    let base: EnvelopeContent = EnvelopeContent {
        action_class: ActionClass::RunOwnerOperation,
        correlation: super::Correlation {
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.digest().clone(),
            ..file_envelope().correlation
        },
        target: plan.targets[0].clone(),
        limits: super::StepLimits {
            reservation: Reservation::Work {
                charge: charge(4096, 4),
            },
            ..file_envelope().limits
        },
        leases: vec![super::lease(LeaseResource::CleanupRoot(
            RootId::new("root_owner").unwrap(),
        ))],
        ..file_envelope()
    };
    assert_eq!(base.check(), Ok(()));
    let mut other_charge = base.clone();
    other_charge.limits.reservation = Reservation::Work {
        charge: charge(1, 1),
    };
    assert_eq!(other_charge.check(), Err(EnvelopeError::Target));
    let mut other_class = base.clone();
    other_class.action_class = ActionClass::EvictRegenerableData;
    assert_eq!(other_class.check(), Err(EnvelopeError::Target));
    let mut other_lease = base.clone();
    other_lease.leases = vec![super::lease(LeaseResource::CleanupRoot(
        RootId::new("root_1").unwrap(),
    ))];
    assert_eq!(other_lease.check(), Err(EnvelopeError::Lease));
    let mut clear = base;
    if let TargetBinding::OwnerOperation(owner) = &mut clear.target.binding {
        owner.operation = OwnerOperationKind::Clear;
    }
    assert_eq!(clear.check(), Err(EnvelopeError::Target));
}

#[test]
fn a_completed_owner_operation_has_the_exit_status_zero_of_its_command() {
    let completed = record("owner", TargetEffect::OperationCompleted);
    assert!(Checked::new(completed.clone()).is_ok());
    for native in [
        NativeResult::ExitStatus { status: 1 },
        NativeResult::Succeeded,
    ] {
        let changed = TargetResultRecord {
            evidence: EffectEvidence {
                native,
                ..completed.evidence.clone()
            },
            ..completed.clone()
        };
        assert!(Checked::new(changed).is_err());
    }
    let established = TargetResultRecord {
        attribution: Attribution::Established,
        ..completed.clone()
    };
    assert!(Checked::new(established).is_err());
    let uncertain = TargetResultRecord {
        dispatch: DispatchState::SubmissionUncertain,
        ..completed.clone()
    };
    assert!(Checked::new(uncertain).is_err());
    let failed = TargetResultRecord {
        stop_reason: StopReason::Failed,
        ..completed
    };
    assert!(Checked::new(failed).is_err());
    let value = serde_json::to_value(NativeResult::ExitStatus { status: 3 }).unwrap();
    assert_eq!(value, json!({ "kind": "exit_status", "status": 3 }));
}

#[test]
fn the_scope_change_needs_two_complete_measurements_with_private_bytes() {
    let effect = ScopeAllocationEffect::new(
        target_id("owner"),
        measurement(4096, Some(4000), true),
        Some(measurement(1024, Some(1000), true)),
    );
    assert_eq!(effect.delta(), Some(ByteDelta::new(-3000).unwrap()));
    let partial = ScopeAllocationEffect::new(
        target_id("owner"),
        measurement(4096, Some(4000), true),
        Some(measurement(1024, Some(1000), false)),
    );
    assert_eq!(partial.delta(), None);
    let no_private = ScopeAllocationEffect::new(
        target_id("owner"),
        measurement(4096, None, true),
        Some(measurement(1024, Some(1000), true)),
    );
    assert_eq!(no_private.delta(), None);
    let no_after =
        ScopeAllocationEffect::new(target_id("owner"), measurement(4096, Some(1), true), None);
    assert_eq!(no_after.delta(), None);
    let mut value = serde_json::to_value(super::ResourceEffect::ScopeAllocation(effect)).unwrap();
    assert_eq!(value["resource"], json!("scope_allocation"));
    assert!(serde_json::from_value::<super::ResourceEffect>(value.clone()).is_ok());
    value["delta"] = json!(5);
    assert!(serde_json::from_value::<super::ResourceEffect>(value).is_err());
}
