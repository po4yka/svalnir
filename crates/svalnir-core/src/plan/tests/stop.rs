//! Tests of the application stop plan builder: strategies, protections,
//! durations, and the digest.

use std::collections::BTreeSet;

use super::{Fixture, LIFETIME, SECOND, USER, path};
use crate::action::{
    ActionClass, ErrorFamily, Escalation, ExecutorRole, PlanError, TargetBinding, TriggerClass,
};
use crate::digest::ContentDigest;
use crate::file::LosslessPath;
use crate::id::{
    AdapterId, ApplicationInstanceId, BootId, ClockDomainId, CollectorEpochId,
    MembershipSnapshotId, ProcessGenerationId, SampleId, StepId, TargetId, WorkerId,
};
use crate::observation::{
    Coverage, MetricKind, Observation, Reading, Sample, Scope, Source, Unit, metric,
};
use crate::plan::{
    OmissionReason, PlanBuildError, PlanContext, PlanMode, PlanOutcome, StopKind, StopLimits,
    StopRequest, StopStepIds, StopStrategy, build_stop_plan, mode_of, split_batches,
};
use crate::policy::{
    ApplicationCandidate, ControlPlaneProcess, ForegroundStatus, ProtectionContext, ProtectionFact,
};
use crate::process::{
    AttributionMethod, ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity,
    ProcessStartTime, Uid,
};
use crate::quantity::{Bytes, Nanoseconds};
use crate::time::{MonotonicNanos, WallTime};

/// The evaluating process of the tests: a process that is not a member of
/// a candidate.
const CONTROL_PLANE: [ControlPlaneProcess; 1] = [ControlPlaneProcess {
    pid: match Pid::new(900) {
        Ok(pid) => pid,
        Err(_) => panic!("900 is a process ID"),
    },
    start_time: ProcessStartTime::new(1),
}];

const PROTECTION: ProtectionContext<'static> = ProtectionContext {
    principal: USER,
    control_plane: Some(&CONTROL_PLANE),
};

fn association(name: &str) -> ProcessAssociation {
    ProcessAssociation::Application {
        instance_id: ApplicationInstanceId::new(format!("app_{name}")).unwrap(),
        bundle_identifier: format!("com.example.{name}"),
        attribution: AttributionMethod::LaunchServices,
    }
}

/// One process of the application `name` of the user.
fn process(name: &str, generation: &str, pid: i32) -> ProcessIdentity {
    ProcessIdentity {
        generation_id: ProcessGenerationId::new(generation).unwrap(),
        pid: Pid::new(pid).unwrap(),
        start_time: ProcessStartTime::new(1_794_830_400_000_000),
        uid: USER,
        boot_id: BootId::new("boot_1").unwrap(),
        executable: Some(ExecutableIdentity {
            path: path(&format!("/Applications/{name}.app/Contents/MacOS/{name}")),
            file: None,
            code_signature: None,
        }),
        association: association(name),
    }
}

fn footprint(snapshot: &MembershipSnapshotId) -> Observation<Bytes> {
    Observation {
        metric_id: metric::APPLICATION_ATTRIBUTED_FOOTPRINT_BYTES,
        scope: Scope::application(snapshot.clone()),
        reading: Reading::Available(Bytes::new(1_000_000)),
        unit: Unit::Byte,
        kind: MetricKind::Gauge,
        coverage: Coverage::Complete,
        source: Source {
            adapter_id: AdapterId::new("adapter_test").unwrap(),
            adapter_revision: "1".to_owned(),
            native_api: "test".to_owned(),
            native_field: "test".to_owned(),
            worker_id: WorkerId::new("worker_test").unwrap(),
        },
        sample: Sample {
            sample_id: SampleId::new("sample_1").unwrap(),
            clock_domain: ClockDomainId::new("clock_main").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            collector_epoch: CollectorEpochId::new("epoch_1").unwrap(),
            started_monotonic_ns: MonotonicNanos::new(999 * SECOND),
            finished_monotonic_ns: MonotonicNanos::new(999 * SECOND),
            captured_at: WallTime::from_unix(1_800_000_000, 0).unwrap(),
        },
    }
}

/// The application `Editor` with a main process and one helper process.
fn candidate() -> ApplicationCandidate {
    let membership_snapshot: MembershipSnapshotId = MembershipSnapshotId::new("members_1").unwrap();
    ApplicationCandidate {
        processes: vec![
            process("Editor", "gen_main", 4242),
            process("Editor", "gen_helper", 4243),
        ],
        footprint: footprint(&membership_snapshot),
        membership_snapshot,
        foreground: ForegroundStatus::Foreground,
        hard_protection: ProtectionFact::NotProtected,
    }
}

fn stop_limits() -> StopLimits {
    StopLimits {
        execution_deadline: Nanoseconds::new(60 * SECOND),
        verification_window: Nanoseconds::new(5 * SECOND),
        max_grace: Nanoseconds::new(30 * SECOND),
        max_verification_window: Nanoseconds::new(10 * SECOND),
        max_execution_deadline: Nanoseconds::new(120 * SECOND),
    }
}

const GRACE: Nanoseconds = Nanoseconds::new(10 * SECOND);

fn strategies() -> [StopStrategy; 3] {
    [
        StopStrategy::Graceful,
        StopStrategy::ForceAfterGrace { grace: GRACE },
        StopStrategy::ImmediateForce,
    ]
}

fn stop_request(candidate: &ApplicationCandidate, strategy: StopStrategy) -> StopRequest<'_> {
    StopRequest {
        target_id: TargetId::new("target_editor").unwrap(),
        candidate,
        protection: &PROTECTION,
        strategy,
        steps: StopStepIds {
            graceful: StepId::new("step_graceful").unwrap(),
            force: StepId::new("step_force").unwrap(),
        },
        limits: stop_limits(),
    }
}

fn digest_of(outcome: &PlanOutcome) -> ContentDigest {
    outcome.plan.as_ref().unwrap().digest().clone()
}

/// The reasons of the only target, when it was left out.
fn reasons(outcome: &PlanOutcome) -> Vec<OmissionReason> {
    assert!(outcome.preview.omitted.len() <= 1);
    outcome
        .preview
        .omitted
        .first()
        .map_or_default(|omission| omission.reasons.clone())
}

/// The kind, the force strategy, the steps, and the grace period that a
/// strategy gives.
type ExpectedPlan = (
    StopKind,
    Escalation,
    Vec<(&'static str, ActionClass)>,
    Option<Nanoseconds>,
);

#[test]
fn each_strategy_gives_its_steps_and_its_force_strategy() {
    use ActionClass::{ForceApplicationExit, RequestApplicationExit};
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let expected: [ExpectedPlan; 3] = [
        (
            StopKind::Graceful,
            Escalation::None,
            vec![("step_graceful", RequestApplicationExit)],
            None,
        ),
        (
            StopKind::ForceAfterGrace,
            Escalation::ForceAfterGrace,
            vec![
                ("step_graceful", RequestApplicationExit),
                ("step_force", ForceApplicationExit),
            ],
            Some(GRACE),
        ),
        (
            StopKind::ImmediateForce,
            Escalation::ImmediateForce,
            vec![("step_force", ForceApplicationExit)],
            None,
        ),
    ];
    for (strategy, (kind, escalation, steps, grace)) in strategies().into_iter().zip(expected) {
        let outcome: PlanOutcome =
            build_stop_plan(&fixture.context(), &stop_request(&candidate, strategy)).unwrap();
        let plan = outcome.plan.as_ref().unwrap();
        assert_eq!(strategy.kind(), kind);
        assert_eq!(outcome.mode, PlanMode::Stop(kind));
        assert_eq!(mode_of(plan), Some(PlanMode::Stop(kind)));
        assert_eq!(outcome.preview.omitted, []);
        let actual: Vec<(&str, ActionClass)> = plan
            .steps
            .iter()
            .map(|step| (step.step_id.as_str(), step.action_class.clone()))
            .collect();
        assert_eq!(actual, steps);
        assert!(
            plan.steps
                .iter()
                .all(|step| step.target_id.as_str() == "target_editor")
        );
        assert_eq!(plan.limits.escalation, escalation);
        assert_eq!(plan.limits.grace, grace);
        assert_eq!(plan.limits.work, None);
        assert_eq!(plan.trigger.class, TriggerClass::Manual);
        assert_eq!(plan.executor, ExecutorRole::User);
        assert_eq!(
            plan.validity.expires_at,
            fixture.clock.now.checked_add(LIFETIME).unwrap()
        );
        // An application plan has no batches.
        assert_eq!(split_batches(plan, &super::charge(1, 1)).unwrap(), []);

        // One target: the membership snapshot of the candidate, with its
        // members in the sequence of their generation identities.
        let [target] = plan.targets.as_slice() else {
            panic!("a stop plan has one target");
        };
        let TargetBinding::Application(binding) = &target.binding else {
            panic!("a stop plan has an application target");
        };
        assert_eq!(binding.instance_id.as_str(), "app_Editor");
        assert_eq!(binding.membership, candidate.membership_snapshot);
        let members: Vec<&str> = binding
            .members
            .iter()
            .map(|member| member.generation_id.as_str())
            .collect();
        assert_eq!(members, ["gen_helper", "gen_main"]);
    }
}

/// One change of the candidate, the `[protections]` lines, the home
/// directory, and the reasons that the change gives.
struct ProtectionCase {
    name: &'static str,
    protections: &'static str,
    home: Option<&'static str>,
    change: fn(&mut ApplicationCandidate),
    control_plane_known: bool,
    expected: Vec<OmissionReason>,
}

impl ProtectionCase {
    fn of(
        name: &'static str,
        change: fn(&mut ApplicationCandidate),
        expected: Vec<OmissionReason>,
    ) -> Self {
        Self {
            name,
            protections: "",
            home: Some("/Users/a"),
            change,
            control_plane_known: true,
            expected,
        }
    }

    fn with_protections(mut self, protections: &'static str) -> Self {
        self.protections = protections;
        self
    }
}

fn protection_cases() -> Vec<ProtectionCase> {
    let mut cases: Vec<ProtectionCase> = hard_protection_cases();
    cases.extend(user_protection_cases());
    cases
}

/// The cases of the hard protections and of the membership evidence.
fn hard_protection_cases() -> Vec<ProtectionCase> {
    use OmissionReason as Reason;
    vec![
        ProtectionCase::of(
            "recorded protection",
            |candidate| candidate.hard_protection = ProtectionFact::Protected,
            vec![Reason::HardProtected],
        ),
        ProtectionCase::of(
            "recorded unknown protection",
            |candidate| candidate.hard_protection = ProtectionFact::Unknown,
            vec![Reason::ProtectionUnknown],
        ),
        // The caller recorded no protection, and the catalog finds one.
        ProtectionCase::of(
            "system executable",
            |candidate| {
                candidate.processes[1].executable.as_mut().unwrap().path = path("/usr/libexec/x");
            },
            vec![Reason::HardProtected],
        ),
        ProtectionCase::of(
            "session application",
            |candidate| {
                for process in &mut candidate.processes {
                    process.association = ProcessAssociation::Application {
                        instance_id: ApplicationInstanceId::new("app_Editor").unwrap(),
                        bundle_identifier: "com.apple.Finder".to_owned(),
                        attribution: AttributionMethod::LaunchServices,
                    };
                }
            },
            vec![Reason::HardProtected],
        ),
        ProtectionCase::of(
            "control plane member",
            |candidate| {
                candidate.processes[0].pid = CONTROL_PLANE[0].pid;
                candidate.processes[0].start_time = CONTROL_PLANE[0].start_time;
            },
            vec![Reason::HardProtected],
        ),
        ProtectionCase::of(
            "process of another user",
            |candidate| candidate.processes[1].uid = Uid::new(502),
            vec![Reason::HardProtected, Reason::OtherUser],
        ),
        ProtectionCase::of(
            "no executable evidence",
            |candidate| candidate.processes[1].executable = None,
            vec![Reason::ProtectionUnknown],
        ),
        ProtectionCase::of(
            "executable path that is not canonical",
            |candidate| {
                candidate.processes[1].executable.as_mut().unwrap().path =
                    path("/Applications/../Applications/Editor.app/Contents/MacOS/Editor");
            },
            vec![Reason::PathNotCanonical, Reason::ProtectionUnknown],
        ),
        ProtectionCase::of(
            "no member",
            |candidate| candidate.processes.clear(),
            vec![Reason::MembershipNotVerified, Reason::ProtectionUnknown],
        ),
        ProtectionCase::of(
            "member with no application evidence",
            |candidate| candidate.processes[1].association = ProcessAssociation::Unattributed,
            vec![Reason::MembershipNotVerified],
        ),
        // The binding for one process exists, and this builder makes no
        // plan with it: this build has no executor step for it.
        ProtectionCase::of(
            "one process with no membership",
            |candidate| {
                candidate.processes.truncate(1);
                candidate.processes[0].association = ProcessAssociation::Unattributed;
            },
            vec![Reason::MembershipNotVerified],
        ),
        ProtectionCase::of(
            "attribution method that this build does not recognize",
            |candidate| {
                candidate.processes[1].association = ProcessAssociation::Application {
                    instance_id: ApplicationInstanceId::new("app_Editor").unwrap(),
                    bundle_identifier: "com.example.Editor".to_owned(),
                    attribution: AttributionMethod::from_wire("parent_process"),
                };
            },
            vec![Reason::MembershipNotVerified],
        ),
        ProtectionCase::of(
            "members of two instances",
            |candidate| candidate.processes[1].association = association("Other"),
            vec![Reason::MembershipNotVerified],
        ),
    ]
}

/// The cases of the user protections of the `[protections]` table and of
/// the control plane.
fn user_protection_cases() -> Vec<ProtectionCase> {
    use OmissionReason as Reason;
    fn keep(_: &mut ApplicationCandidate) {}
    let mut cases: Vec<ProtectionCase> = vec![
        ProtectionCase::of(
            "protected bundle identifier",
            keep,
            vec![Reason::ProtectedBundleId],
        )
        .with_protections("protected_bundle_ids = [\"COM.example.editor\"]"),
        // A protection applies to a claimed identifier, verified or not.
        ProtectionCase::of(
            "claimed bundle identifier",
            |candidate| {
                candidate.processes[1].association = ProcessAssociation::Application {
                    instance_id: ApplicationInstanceId::new("app_Editor").unwrap(),
                    bundle_identifier: "com.example.Vault".to_owned(),
                    attribution: AttributionMethod::from_wire("parent_process"),
                };
            },
            vec![Reason::ProtectedBundleId, Reason::MembershipNotVerified],
        )
        .with_protections("protected_bundle_ids = [\"com.example.Vault\"]"),
        ProtectionCase::of(
            "protected executable path",
            keep,
            vec![Reason::ProtectedExecutablePath],
        )
        .with_protections("protected_executable_paths = [\"/applications/editor.APP\"]"),
        ProtectionCase::of("protected path from the home directory", keep, vec![])
            .with_protections("protected_executable_paths = [\"~/Applications\"]"),
        // The home directory resolves the `~/` path of the list.
        ProtectionCase::of(
            "executable below a protected path of the home directory",
            |candidate| {
                if let Some(executable) = candidate.processes[1].executable.as_mut() {
                    executable.path =
                        path("/Users/a/Applications/Editor.app/Contents/MacOS/Editor");
                }
            },
            vec![Reason::ProtectedExecutablePath],
        )
        .with_protections("protected_executable_paths = [\"~/Applications\"]"),
        // An identity of a different boot is not evidence of a process of
        // the boot of the plan.
        ProtectionCase::of(
            "member with an identity of a different boot",
            |candidate| candidate.processes[1].boot_id = BootId::new("boot_2").unwrap(),
            vec![Reason::MembershipNotVerified],
        ),
        ProtectionCase::of(
            "protected paths and no executable evidence",
            |candidate| candidate.processes[1].executable = None,
            vec![Reason::ProtectionUnknown, Reason::ExecutableUnknown],
        )
        .with_protections("protected_executable_paths = [\"/Applications/Keep.app\"]"),
    ];
    let mut no_home: ProtectionCase = ProtectionCase::of(
        "protected path with no usable home directory",
        keep,
        vec![Reason::HomeDirectoryUnknown],
    )
    .with_protections("protected_executable_paths = [\"~/Applications\"]");
    no_home.home = None;
    cases.push(no_home);
    let mut no_control_plane: ProtectionCase = ProtectionCase::of(
        "control plane that is not known",
        keep,
        vec![Reason::ProtectionUnknown],
    );
    no_control_plane.control_plane_known = false;
    cases.push(no_control_plane);
    cases
}

#[test]
fn no_strategy_includes_a_target_with_a_protection_or_an_unknown_fact() {
    for case in protection_cases() {
        let mut fixture: Fixture = Fixture::with_protections(case.protections);
        fixture.home = case.home.map(path);
        let mut changed: ApplicationCandidate = candidate();
        (case.change)(&mut changed);
        let protection: ProtectionContext<'_> = ProtectionContext {
            principal: USER,
            control_plane: case.control_plane_known.then_some(&CONTROL_PLANE),
        };
        // `--force` selects a strategy. It removes no protection.
        for strategy in strategies() {
            let mut request: StopRequest<'_> = stop_request(&changed, strategy);
            request.protection = &protection;
            let outcome: PlanOutcome = build_stop_plan(&fixture.context(), &request).unwrap();
            assert_eq!(reasons(&outcome), case.expected, "{}", case.name);
            assert_eq!(
                outcome.plan.is_some(),
                case.expected.is_empty(),
                "{}",
                case.name
            );
            if let Some(omission) = outcome.preview.omitted.first() {
                assert_eq!(omission.target_id.as_str(), "target_editor");
                assert_eq!(omission.path, None);
                assert_eq!(outcome.preview.targets, []);
            }
        }
    }
}

#[test]
fn the_automatic_settings_of_the_memory_guard_do_not_apply() {
    // The candidate of the tests is the foreground application, and the
    // automatic guard protects the foreground and has no force consent. A
    // manual request has its own authorization.
    let text: &str = "\n[memory_guard]\nprotect_foreground = true\nallow_force_quit = false\n\
                      protected_bundle_ids = [\"com.example.Editor\"]\n\
                      protected_executable_paths = [\"/Applications/Editor.app\"]\n";
    let fixture: Fixture = Fixture::with_protections(text);
    let candidate: ApplicationCandidate = candidate();
    assert_eq!(candidate.foreground, ForegroundStatus::Foreground);
    for strategy in strategies() {
        let outcome: PlanOutcome =
            build_stop_plan(&fixture.context(), &stop_request(&candidate, strategy)).unwrap();
        assert!(outcome.plan.is_some());
    }
}

#[test]
fn each_duration_is_positive_and_fits_its_bound() {
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let build = |strategy: StopStrategy, change: fn(&mut StopLimits)| {
        let mut request: StopRequest<'_> = stop_request(&candidate, strategy);
        change(&mut request.limits);
        build_stop_plan(&fixture.context(), &request).map(|outcome| outcome.plan.is_some())
    };
    let force_after = |seconds: u64| StopStrategy::ForceAfterGrace {
        grace: Nanoseconds::new(seconds * SECOND),
    };
    let refused: Result<bool, PlanBuildError> = Err(PlanBuildError::Limits);
    assert_eq!(PlanBuildError::Limits.family(), ErrorFamily::Limits);

    for strategy in strategies() {
        // The bounds themselves are permitted.
        assert_eq!(
            build(strategy, |limits| {
                limits.verification_window = limits.max_verification_window;
                limits.execution_deadline = limits.max_execution_deadline;
            }),
            Ok(true)
        );
        for change in [
            (|limits| limits.verification_window = Nanoseconds::ZERO) as fn(&mut StopLimits),
            |limits| limits.execution_deadline = Nanoseconds::ZERO,
            |limits| limits.verification_window = Nanoseconds::new(10 * SECOND + 1),
            |limits| limits.execution_deadline = Nanoseconds::new(120 * SECOND + 1),
        ] {
            assert_eq!(build(strategy, change), refused);
        }
    }

    // The grace period: positive, not larger than its bound.
    assert_eq!(build(force_after(30), |_| {}), Ok(true));
    assert_eq!(build(force_after(0), |_| {}), refused);
    assert_eq!(
        build(
            StopStrategy::ForceAfterGrace {
                grace: Nanoseconds::new(30 * SECOND + 1)
            },
            |_| {}
        ),
        refused
    );

    // The steps fit in the execution deadline: one window for one step,
    // and the grace period and two windows for two steps.
    for single in [StopStrategy::Graceful, StopStrategy::ImmediateForce] {
        assert_eq!(
            build(single, |limits| limits.execution_deadline =
                Nanoseconds::new(5 * SECOND)),
            Ok(true)
        );
        assert_eq!(
            build(single, |limits| limits.execution_deadline =
                Nanoseconds::new(5 * SECOND - 1)),
            refused
        );
    }
    assert_eq!(
        build(force_after(10), |limits| limits.execution_deadline =
            Nanoseconds::new(20 * SECOND)),
        Ok(true)
    );
    assert_eq!(
        build(force_after(10), |limits| limits.execution_deadline =
            Nanoseconds::new(20 * SECOND - 1)),
        refused
    );
    // A sum that overflows does not fit. The grace period is in its bound
    // and is shorter than the lifetime, so only the sum of the grace period
    // and the two windows refuses the request.
    assert_eq!(
        build(force_after(10), |limits| {
            limits.verification_window = Nanoseconds::new(u64::MAX / 2 + 1);
            limits.max_verification_window = Nanoseconds::MAX;
            limits.max_execution_deadline = Nanoseconds::MAX;
            limits.execution_deadline = Nanoseconds::MAX;
        }),
        refused
    );
}

#[test]
fn the_grace_period_ends_before_the_plan_expires() {
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let build = |lifetime: Nanoseconds| {
        let mut context: PlanContext<'_> = fixture.context();
        context.lifetime = lifetime;
        let request: StopRequest<'_> =
            stop_request(&candidate, StopStrategy::ForceAfterGrace { grace: GRACE });
        build_stop_plan(&context, &request).map(|outcome| outcome.plan.is_some())
    };
    assert_eq!(build(Nanoseconds::new(GRACE.get() + 1)), Ok(true));
    assert_eq!(build(GRACE), Err(PlanBuildError::Limits));
    assert_eq!(
        build(Nanoseconds::new(GRACE.get() - 1)),
        Err(PlanBuildError::Limits)
    );
}

#[test]
fn a_stop_request_that_a_plan_cannot_express_is_an_error() {
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let base = || stop_request(&candidate, StopStrategy::Graceful);

    let mut same_steps: StopRequest<'_> = base();
    same_steps.steps.force = same_steps.steps.graceful.clone();
    assert_eq!(
        build_stop_plan(&fixture.context(), &same_steps),
        Err(PlanBuildError::DuplicateIdentity)
    );

    // The catalog must evaluate the owner rule for the principal of the
    // plan.
    let other_principal: ProtectionContext<'_> = ProtectionContext {
        principal: Uid::new(502),
        control_plane: Some(&CONTROL_PLANE),
    };
    let mut wrong_context: StopRequest<'_> = base();
    wrong_context.protection = &other_principal;
    let error: PlanBuildError = build_stop_plan(&fixture.context(), &wrong_context).unwrap_err();
    assert_eq!(error, PlanBuildError::Principal);
    assert_eq!(error.family(), ErrorFamily::Authority);

    let mut no_lifetime: PlanContext<'_> = fixture.context();
    no_lifetime.lifetime = Nanoseconds::ZERO;
    assert_eq!(
        build_stop_plan(&no_lifetime, &base()),
        Err(PlanBuildError::Lifetime)
    );

    // The check of the foundation applies: two members with one
    // generation identity are rejected.
    let mut repeated: ApplicationCandidate = candidate.clone();
    repeated.processes[1].generation_id = repeated.processes[0].generation_id.clone();
    assert_eq!(
        build_stop_plan(
            &fixture.context(),
            &stop_request(&repeated, StopStrategy::Graceful)
        ),
        Err(PlanBuildError::Plan(PlanError::Duplicate))
    );
}

#[test]
fn the_digest_does_not_depend_on_the_sequence_of_the_members() {
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let mut reversed: ApplicationCandidate = candidate.clone();
    reversed.processes.reverse();
    for strategy in strategies() {
        let first: PlanOutcome =
            build_stop_plan(&fixture.context(), &stop_request(&candidate, strategy)).unwrap();
        let second: PlanOutcome =
            build_stop_plan(&fixture.context(), &stop_request(&reversed, strategy)).unwrap();
        assert_eq!(second, first);
        assert_eq!(digest_of(&second), digest_of(&first));
        assert_eq!(
            build_stop_plan(&fixture.context(), &stop_request(&candidate, strategy)).unwrap(),
            first
        );
    }
}

/// A named change of a candidate.
type CandidateChange = (&'static str, fn(&mut ApplicationCandidate));

#[test]
fn a_change_of_each_covered_field_of_a_stop_plan_changes_the_digest() {
    let fixture: Fixture = Fixture::new();
    let base_candidate: ApplicationCandidate = candidate();
    let digest = |candidate: &ApplicationCandidate,
                  strategy: StopStrategy,
                  change: &dyn Fn(&mut StopRequest<'_>)| {
        let mut request: StopRequest<'_> = stop_request(candidate, strategy);
        change(&mut request);
        digest_of(&build_stop_plan(&fixture.context(), &request).unwrap())
    };
    let force_after: StopStrategy = StopStrategy::ForceAfterGrace { grace: GRACE };
    let base: ContentDigest = digest(&base_candidate, force_after, &|_| {});
    let mut digests: Vec<(&str, ContentDigest)> = vec![
        (
            "graceful strategy",
            digest(&base_candidate, StopStrategy::Graceful, &|_| {}),
        ),
        (
            "immediate force strategy",
            digest(&base_candidate, StopStrategy::ImmediateForce, &|_| {}),
        ),
        (
            "grace period",
            digest(
                &base_candidate,
                StopStrategy::ForceAfterGrace {
                    grace: Nanoseconds::new(GRACE.get() + 1),
                },
                &|_| {},
            ),
        ),
        (
            "verification window",
            digest(&base_candidate, force_after, &|request| {
                request.limits.verification_window = Nanoseconds::new(6 * SECOND);
            }),
        ),
        (
            "execution deadline",
            digest(&base_candidate, force_after, &|request| {
                request.limits.execution_deadline = Nanoseconds::new(61 * SECOND);
            }),
        ),
        (
            "target identity",
            digest(&base_candidate, force_after, &|request| {
                request.target_id = TargetId::new("target_other").unwrap();
            }),
        ),
        (
            "step identity",
            digest(&base_candidate, force_after, &|request| {
                request.steps.force = StepId::new("step_force_2").unwrap();
            }),
        ),
    ];
    let candidate_changes: Vec<CandidateChange> = vec![
        ("membership snapshot", |candidate| {
            candidate.membership_snapshot = MembershipSnapshotId::new("members_2").unwrap();
        }),
        ("member set", |candidate| {
            candidate.processes.pop();
        }),
        ("process ID", |candidate| {
            candidate.processes[0].pid = Pid::new(5000).unwrap();
        }),
        ("start time", |candidate| {
            candidate.processes[0].start_time = ProcessStartTime::new(2);
        }),
        ("generation", |candidate| {
            candidate.processes[0].generation_id = ProcessGenerationId::new("gen_new").unwrap();
        }),
        ("executable", |candidate| {
            candidate.processes[0].executable.as_mut().unwrap().path =
                LosslessPath::from_bytes("/Applications/Editor.app/Contents/MacOS/Editor2")
                    .unwrap();
        }),
        ("instance", |candidate| {
            for process in &mut candidate.processes {
                process.association = association("Editor2");
            }
        }),
    ];
    for (name, change) in candidate_changes {
        let mut changed: ApplicationCandidate = base_candidate.clone();
        change(&mut changed);
        digests.push((name, digest(&changed, force_after, &|_| {})));
    }
    let distinct: BTreeSet<&ContentDigest> = digests.iter().map(|(_, digest)| digest).collect();
    for (name, changed) in &digests {
        assert_ne!(changed, &base, "{name} is not in the digest");
    }
    assert_eq!(distinct.len(), digests.len(), "two changes give one digest");

    // The foreground status and the footprint are not in the plan.
    let mut background: ApplicationCandidate = base_candidate.clone();
    background.foreground = ForegroundStatus::Background;
    assert_eq!(digest(&background, force_after, &|_| {}), base);
}

#[test]
fn the_explanation_of_a_stop_plan_shows_the_members_and_the_strategy() {
    use crate::plan::{Consequence, PlanExplanation, TargetExplanation, explain};
    let fixture: Fixture = Fixture::new();
    let candidate: ApplicationCandidate = candidate();
    let request: StopRequest<'_> =
        stop_request(&candidate, StopStrategy::ForceAfterGrace { grace: GRACE });
    let outcome: PlanOutcome = build_stop_plan(&fixture.context(), &request).unwrap();
    let explanation: PlanExplanation = explain(&outcome, &fixture.clock);

    assert_eq!(explanation.consequence, Consequence::ForceAfterGrace);
    assert!(explanation.consequence_statement.contains("forced to exit"));
    // A stop is not reclaimed capacity, and it has no size.
    assert!(!explanation.counts_as_reclaimed_capacity);
    assert_eq!(explanation.totals.admission_charge, None);
    assert_eq!(explanation.totals.estimated_logical_bytes, None);
    assert_eq!(explanation.totals.estimated_reclaimable_bytes, None);
    assert_eq!(explanation.batches, []);
    let summary = explanation.plan.as_ref().unwrap();
    assert_eq!(summary.grace, Some(GRACE));
    assert_eq!(
        summary.action_classes,
        [
            ActionClass::RequestApplicationExit,
            ActionClass::ForceApplicationExit
        ]
    );
    assert_eq!(summary.revisions.rules, []);
    let [
        TargetExplanation::Application {
            target_id,
            instance_id,
            membership,
            members,
        },
    ] = explanation.targets.as_slice()
    else {
        panic!("a stop plan has one application target");
    };
    assert_eq!(target_id.as_str(), "target_editor");
    assert_eq!(instance_id.as_str(), "app_Editor");
    assert_eq!(membership.as_str(), "members_1");
    let pids: Vec<i32> = members.iter().map(|member| member.pid.get()).collect();
    assert_eq!(pids, [4243, 4242]);
    assert!(members.iter().all(|member| member.executable.is_some()));

    // A target that a protection leaves out has an explanation and no
    // plan to approve.
    let mut protected: ApplicationCandidate = candidate.clone();
    protected.hard_protection = ProtectionFact::Protected;
    let request: StopRequest<'_> = stop_request(&protected, StopStrategy::ImmediateForce);
    let outcome: PlanOutcome = build_stop_plan(&fixture.context(), &request).unwrap();
    let explanation: PlanExplanation = explain(&outcome, &fixture.clock);
    assert_eq!(explanation.plan, None);
    assert_eq!(explanation.targets, []);
    assert_eq!(explanation.consequence, Consequence::ImmediateForce);
    assert_eq!(
        explanation.omitted[0].reasons,
        [OmissionReason::HardProtected]
    );
    assert_eq!(
        OmissionReason::HardProtected.family(),
        ErrorFamily::Eligibility
    );
}
