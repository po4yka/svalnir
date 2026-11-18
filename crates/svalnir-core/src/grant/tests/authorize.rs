//! Tests of the authorization question.

use std::collections::BTreeSet;

use super::super::{
    Acceptance, ActionRequest, AuthorityState, Authorization, AuthorizationBasis,
    AuthorizationContext, DisableRequest, EvidenceStamp, IncidentBudget, InstanceInhibition,
    PauseRequest, Persistence, Refusal, RefusalReason, ResumeRequest, RevokeRequest, authorize,
    disable, pause, resume, revoke,
};
use super::{
    DERIVED_DATA, Registry, TEMPORARY, USER, activated, active_state, application_content,
    as_automatic, automatic, base_config, clock, clock_in, config, control, declaration, durable,
    enabled, enabled_state, eviction_plan, eviction_plan_of_layout, file_content, grant_id,
    grant_ref, incident_id, intervention_plan, monotonic, registry, registry_with, rule, rule_ref,
    seal, wall,
};
use crate::action::{
    ActionClass, ActionStage, Checked, DispatchState, ErrorFamily, Escalation, PermittedNextStep,
    Plan, PlanApproval, PlanError, RecordingMode, TriggerClass,
};
use crate::authority::{ActionGrantRef, Generation};
use crate::digest::ContentDigest;
use crate::id::{IncidentId, StepId};
use crate::policy::{EvaluationClock, PolicyId};
use crate::process::Uid;
use crate::quantity::Nanoseconds;
use crate::rule::{LayoutSupport, LifecycleState};

const DISK: PolicyId = PolicyId::DiskGuard;
const MEMORY: PolicyId = PolicyId::MemoryGuard;

/// One question, with the values of a permitted automatic step at second
/// 200. A test changes one value.
struct Ask {
    state: AuthorityState,
    inhibition: InstanceInhibition,
    registry: Registry,
    clock: EvaluationClock,
    principal: Uid,
    plan: Plan,
    step: &'static str,
    approval: Option<PlanApproval>,
    recording: RecordingMode,
    incident: Option<IncidentBudget>,
    evidence: Option<EvidenceStamp>,
}

fn evidence_at(seconds: u64) -> EvidenceStamp {
    let at = clock(seconds);
    EvidenceStamp {
        acquired_at: at.now,
        clock_domain: at.clock_domain,
        boot_id: at.boot_id,
    }
}

impl Ask {
    fn new(state: AuthorityState, plan: Plan, step: &'static str) -> Self {
        // An automatic plan has the budget record of its incident.
        let guard = match plan.trigger.class {
            TriggerClass::DiskPressure => Some(DISK),
            TriggerClass::GlobalCriticalMemory | TriggerClass::ApplicationBudget => Some(MEMORY),
            _ => None,
        };
        let incident = guard.map(|policy| {
            IncidentBudget::open(
                incident_id(),
                policy,
                &state,
                &InstanceInhibition::default(),
                wall(150),
            )
        });
        Self {
            state,
            inhibition: InstanceInhibition::default(),
            registry: registry(),
            clock: clock(200),
            principal: USER,
            plan,
            step,
            approval: None,
            recording: RecordingMode::Durable,
            incident,
            evidence: Some(evidence_at(199)),
        }
    }

    /// The automatic eviction step of the disk guard.
    fn eviction(state: AuthorityState) -> Self {
        let plan = eviction_plan(&state);
        Self::new(state, plan, "s1")
    }

    /// A step of the automatic intervention of the memory guard, with
    /// force after grace.
    fn intervention(state: AuthorityState, class: TriggerClass, step: &'static str) -> Self {
        let plan = intervention_plan(&state, class, Escalation::ForceAfterGrace);
        Self::new(state, plan, step)
    }

    /// The manual step of `class`, with the approval of its plan.
    fn manual(state: AuthorityState, class: &ActionClass) -> Self {
        let plan = seal(file_content(&state, class, None));
        let approval = approval_of(&plan);
        Self {
            approval: Some(approval),
            evidence: None,
            ..Self::new(state, plan, "s1")
        }
    }

    fn answer(&self) -> Result<Authorization, Refusal> {
        let step_id = StepId::new(self.step).unwrap();
        let wall_seconds = self.clock.now.get() / super::SECOND;
        let context = AuthorizationContext {
            state: &self.state,
            inhibition: &self.inhibition,
            registry: &self.registry,
            clock: control(&self.clock, wall_seconds),
        };
        let request = ActionRequest {
            principal: self.principal,
            plan: &self.plan,
            step_id: &step_id,
            stage: ActionStage::Admission,
            approval: self.approval.as_ref(),
            recording: &self.recording,
            incident: self.incident.as_ref(),
            evidence: self.evidence.as_ref(),
        };
        let first = authorize(&context, &request);
        // The answer is a function of its inputs.
        assert_eq!(first, authorize(&context, &request));
        first
    }

    fn reason(&self) -> RefusalReason {
        self.answer().unwrap_err().reason
    }
}

fn approval_of(plan: &Plan) -> PlanApproval {
    PlanApproval {
        plan_id: plan.plan_id.clone(),
        digest: plan.digest().clone(),
    }
}

/// A record with the critical-memory exception configured and granted.
fn volatile_state() -> AuthorityState {
    let state = active_state(&config(&[(
        "allow_volatile_journal_on_critical = false",
        "allow_volatile_journal_on_critical = true",
    )]));
    let state = enabled(&state, DISK, &[Acceptance::PermanentEviction]);
    enabled(&state, MEMORY, &[Acceptance::ForceQuit])
}

/// The critical-memory step with volatile recording and the budget record
/// of its incident.
fn volatile_ask(state: AuthorityState) -> Ask {
    let incident = IncidentBudget::open(
        incident_id(),
        MEMORY,
        &state,
        &InstanceInhibition::default(),
        wall(150),
    );
    Ask {
        recording: RecordingMode::VolatileCriticalException,
        incident: Some(incident),
        ..Ask::intervention(state, TriggerClass::GlobalCriticalMemory, "graceful")
    }
}

// Permitted steps.

#[test]
fn an_automatic_eviction_of_an_active_guard_is_permitted() {
    let ask = Ask::eviction(enabled_state());
    let authorization = ask.answer().unwrap();
    assert_eq!(
        authorization.basis,
        AuthorizationBasis::StandingGrant {
            policy: DISK,
            grant: grant_ref(&ask.state, DISK),
        }
    );
    assert_eq!(
        authorization.policy_revision,
        ask.state.active.as_ref().unwrap().revision.revision_id
    );
    assert_eq!(
        authorization.action_class,
        ActionClass::EvictRegenerableData
    );
    assert_eq!(authorization.recording, RecordingMode::Durable);
}

#[test]
fn each_step_of_an_automatic_intervention_is_permitted_for_each_memory_trigger() {
    for class in [
        TriggerClass::GlobalCriticalMemory,
        TriggerClass::ApplicationBudget,
    ] {
        for step in ["graceful", "force"] {
            let ask = Ask::intervention(enabled_state(), class.clone(), step);
            let authorization = ask.answer().unwrap();
            assert_eq!(
                authorization.basis,
                AuthorizationBasis::StandingGrant {
                    policy: MEMORY,
                    grant: grant_ref(&ask.state, MEMORY),
                }
            );
        }
    }
    // A graceful request alone.
    let state = enabled_state();
    let plan = intervention_plan(&state, TriggerClass::ApplicationBudget, Escalation::None);
    Ask::new(state, plan, "graceful").answer().unwrap();
}

#[test]
fn a_manual_step_with_the_approval_of_its_plan_is_permitted() {
    for class in [ActionClass::MoveToTrash, ActionClass::DeleteSelectedFiles] {
        // No guard is enabled: a manual step needs no standing grant.
        let ask = Ask::manual(active_state(&base_config()), &class);
        let authorization = ask.answer().unwrap();
        assert_eq!(
            authorization.basis,
            AuthorizationBasis::PlanApproval {
                plan_id: ask.plan.plan_id.clone(),
                digest: ask.plan.digest().clone(),
            }
        );
        assert_eq!(authorization.action_class, class);
    }
    // A manual application plan with a force step. The automatic force
    // setting of the memory guard has no effect on it.
    let state = active_state(&config(&[(
        "allow_force_quit = true",
        "allow_force_quit = false",
    )]));
    let plan = seal(application_content(&state, Escalation::ForceAfterGrace));
    let ask = Ask {
        approval: Some(approval_of(&plan)),
        evidence: None,
        ..Ask::new(state, plan, "force")
    };
    ask.answer().unwrap();
}

#[test]
fn a_pause_and_a_guard_condition_do_not_refuse_a_manual_step() {
    // Paused, with the two guards disabled, and with the `observe`
    // profile.
    let observing = config(&[(r#"profile = "balanced""#, r#"profile = "observe""#)]);
    let (state, _) = activated(&enabled_state(), &observing, "policy_2");
    let at = clock(150);
    let state = durable(
        pause(
            &state,
            &PauseRequest {
                principal: USER,
                duration: None,
            },
            &control(&at, 150),
        )
        .unwrap(),
    )
    .state;
    let disable_disk = DisableRequest {
        principal: USER,
        policy: DISK,
    };
    let state = durable(disable(&state, &disable_disk).unwrap()).state;
    Ask::manual(state, &ActionClass::MoveToTrash)
        .answer()
        .unwrap();
}

#[test]
fn a_manual_rule_action_needs_a_rule_that_is_validated_for_manual_use() {
    let manual = LifecycleState::ManualActionValidated {
        evidence: super::evidence(),
    };
    let ask = |lifecycle: &LifecycleState, class: &ActionClass| {
        let state = active_state(&base_config());
        let plan = seal(file_content(&state, class, Some(rule_ref(TEMPORARY, "r1"))));
        Ask {
            approval: Some(approval_of(&plan)),
            evidence: None,
            registry: registry_with(lifecycle),
            ..Ask::new(state, plan, "s1")
        }
    };
    for class in [ActionClass::EvictRegenerableData, ActionClass::MoveToTrash] {
        ask(&manual, &class).answer().unwrap();
        ask(&automatic(), &class).answer().unwrap();
        assert_eq!(
            ask(&LifecycleState::Proposed, &class).reason(),
            RefusalReason::RuleModeNotValidated
        );
    }
    // A selected-file deletion is not a rule action: its plan binds no
    // rule revision, in each lifecycle state of the rule.
    for lifecycle in [LifecycleState::Proposed, manual.clone(), automatic()] {
        assert_eq!(
            ask(&lifecycle, &ActionClass::DeleteSelectedFiles).reason(),
            RefusalReason::RuleNotGranted
        );
    }
}

// Refusals.

/// Each refusal, with the reason that the test expects.
fn refusals() -> Vec<(RefusalReason, Ask)> {
    use RefusalReason as R;
    let mut cases: Vec<(RefusalReason, Ask)> = Vec::new();
    let mut case = |reason: RefusalReason, ask: Ask| cases.push((reason, ask));

    // The request.
    case(
        R::StepNotInPlan,
        Ask {
            step: "s9",
            ..Ask::eviction(enabled_state())
        },
    );
    case(
        R::UnsupportedValue,
        Ask {
            recording: RecordingMode::from_wire("best_effort"),
            ..Ask::eviction(enabled_state())
        },
    );
    let other_incident = IncidentBudget::open(
        IncidentId::new("incident_2").unwrap(),
        DISK,
        &enabled_state(),
        &InstanceInhibition::default(),
        wall(150),
    );
    case(
        R::IncidentMismatch,
        Ask {
            incident: Some(other_incident),
            ..Ask::eviction(enabled_state())
        },
    );
    // The record of the same incident identity for the other guard.
    let other_guard = IncidentBudget::open(
        incident_id(),
        MEMORY,
        &enabled_state(),
        &InstanceInhibition::default(),
        wall(150),
    );
    case(
        R::IncidentMismatch,
        Ask {
            incident: Some(other_guard),
            ..Ask::eviction(enabled_state())
        },
    );
    case(
        R::IncidentRecordMissing,
        Ask {
            incident: None,
            ..Ask::eviction(enabled_state())
        },
    );

    // The principal and the revision.
    case(
        R::WrongPrincipal,
        Ask {
            principal: Uid::new(502),
            ..Ask::eviction(enabled_state())
        },
    );
    case(
        R::NoActivePolicyRevision,
        Ask::manual(AuthorityState::new(USER), &ActionClass::MoveToTrash),
    );
    let (later, _) = activated(
        &enabled_state(),
        &config(&[("allow_force_quit = true", "allow_force_quit = false")]),
        "policy_2",
    );
    case(
        R::PolicyRevisionMismatch,
        Ask {
            state: later,
            ..Ask::eviction(enabled_state())
        },
    );
    case(
        R::PlanExpired,
        Ask {
            clock: clock(1_000),
            evidence: Some(evidence_at(999)),
            ..Ask::eviction(enabled_state())
        },
    );

    cases.extend(manual_refusals());
    cases.extend(guard_refusals());
    cases.extend(scope_refusals());
    cases.extend(volatile_refusals());
    cases
}

/// The refusals of a manual step.
fn manual_refusals() -> Vec<(RefusalReason, Ask)> {
    use RefusalReason as R;
    let mut cases: Vec<(RefusalReason, Ask)> = Vec::new();
    let mut case = |reason: RefusalReason, ask: Ask| cases.push((reason, ask));

    // A manual step.
    case(
        R::ManualApprovalMissing,
        Ask {
            approval: None,
            ..Ask::manual(enabled_state(), &ActionClass::DeleteSelectedFiles)
        },
    );
    let manual = Ask::manual(enabled_state(), &ActionClass::DeleteSelectedFiles);
    let other_digest = PlanApproval {
        plan_id: manual.plan.plan_id.clone(),
        digest: ContentDigest::of_bytes(b"another plan"),
    };
    case(
        R::ManualApprovalMismatch,
        Ask {
            approval: Some(other_digest),
            ..manual
        },
    );
    // A manual deletion that names the standing grant of the disk guard.
    let state = enabled_state();
    let mut content = file_content(&state, &ActionClass::DeleteSelectedFiles, None);
    content.authority.action_grants = vec![grant_ref(&state, DISK)];
    let plan = seal(content);
    case(
        R::GuardGrantInManualPlan,
        Ask {
            approval: Some(approval_of(&plan)),
            evidence: None,
            ..Ask::new(state, plan, "s1")
        },
    );
    cases
}

/// The refusals of the pause and of the standing of the guard.
fn guard_refusals() -> Vec<(RefusalReason, Ask)> {
    use RefusalReason as R;
    let mut cases: Vec<(RefusalReason, Ask)> = Vec::new();
    let mut case = |reason: RefusalReason, ask: Ask| cases.push((reason, ask));

    let at = clock(150);
    let hour = PauseRequest {
        principal: USER,
        duration: Some(Nanoseconds::new(3_600 * super::SECOND)),
    };
    let paused = durable(pause(&enabled_state(), &hour, &control(&at, 150)).unwrap()).state;
    case(R::AutomationPaused, Ask::eviction(paused));

    let state = enabled_state();
    let disable_disk = DisableRequest {
        principal: USER,
        policy: DISK,
    };
    let failed = disable(&state, &disable_disk)
        .unwrap()
        .acknowledge(&InstanceInhibition::default(), Persistence::Failed);
    case(
        R::GuardInhibited,
        Ask {
            inhibition: failed.inhibition,
            ..Ask::eviction(failed.state)
        },
    );

    // The plan is bound to the revision in effect and to the current
    // generation of the grant, so only the standing refuses.
    let off = config(&[(
        "[disk_guard]\nenabled = true",
        "[disk_guard]\nenabled = false",
    )]);
    let (state, _) = activated(&enabled_state(), &off, "policy_2");
    case(R::GuardNotRequested, Ask::eviction(state));
    let observing = config(&[(r#"profile = "balanced""#, r#"profile = "observe""#)]);
    let (state, _) = activated(&enabled_state(), &observing, "policy_2");
    case(R::ObserveProfile, Ask::eviction(state));
    let state = durable(disable(&enabled_state(), &disable_disk).unwrap()).state;
    case(R::GuardDisabled, Ask::eviction(state));

    let state = enabled_state();
    let plan = eviction_plan(&state);
    let mut no_grant = state;
    no_grant.guards[0].grant = None;
    case(R::ActionGrantMissing, Ask::new(no_grant, plan, "s1"));

    let revoke_disk = RevokeRequest {
        principal: USER,
        grant_id: grant_id("grant_disk"),
    };
    let state = durable(revoke(&enabled_state(), &revoke_disk).unwrap()).state;
    case(R::ActionGrantRevoked, Ask::eviction(state));

    let mut state = enabled_state();
    state.guards[0].grant.as_mut().unwrap().expires_at = Some(wall(200));
    case(R::ActionGrantExpired, Ask::eviction(state));

    let wider = config(&[(r#"paths = ["~/Documents"]"#, "paths = []")]);
    let (state, _) = activated(&enabled_state(), &wider, "policy_2");
    case(R::AcceptanceRequired, Ask::eviction(state));

    // The plan names an earlier generation of the grant.
    let state = enabled_state();
    let mut content = file_content(
        &state,
        &ActionClass::EvictRegenerableData,
        Some(rule_ref(TEMPORARY, "r1")),
    );
    content = as_automatic(&state, content, TriggerClass::DiskPressure, DISK);
    content.authority.action_grants = vec![ActionGrantRef {
        generation: Generation::new(9),
        ..grant_ref(&state, DISK)
    }];
    case(R::ActionGrantMismatch, Ask::new(state, seal(content), "s1"));
    cases
}

/// The refusals of the scope of the grant, of the rule, and of the
/// evidence.
fn scope_refusals() -> Vec<(RefusalReason, Ask)> {
    use RefusalReason as R;
    let mut cases: Vec<(RefusalReason, Ask)> = Vec::new();
    let mut case = |reason: RefusalReason, ask: Ask| cases.push((reason, ask));

    // The memory guard has no force quit, and the plan has a force step.
    let graceful_only = || {
        let state = active_state(&config(&[(
            "allow_force_quit = true",
            "allow_force_quit = false",
        )]));
        enabled(&state, MEMORY, &[Acceptance::ApplicationExit])
    };
    case(
        R::ActionClassNotGranted,
        Ask::intervention(graceful_only(), TriggerClass::GlobalCriticalMemory, "force"),
    );
    case(
        R::EscalationNotGranted,
        Ask::intervention(graceful_only(), TriggerClass::ApplicationBudget, "graceful"),
    );
    // An immediate force is not a strategy of the configuration.
    let state = enabled_state();
    let plan = intervention_plan(
        &state,
        TriggerClass::GlobalCriticalMemory,
        Escalation::ImmediateForce,
    );
    case(R::EscalationNotGranted, Ask::new(state, plan, "force"));

    // A revision of the rule that the grant does not have.
    let state = enabled_state();
    let content = file_content(
        &state,
        &ActionClass::EvictRegenerableData,
        Some(rule_ref(TEMPORARY, "r2")),
    );
    let plan = seal(as_automatic(
        &state,
        content,
        TriggerClass::DiskPressure,
        DISK,
    ));
    case(R::RuleNotGranted, Ask::new(state, plan, "s1"));

    case(
        R::RuleNotRegistered,
        Ask {
            registry: Registry(Vec::new()),
            ..Ask::eviction(enabled_state())
        },
    );
    // The layout is the one that the sealed plan binds for the target.
    let state = enabled_state();
    let plan = eviction_plan_of_layout(&state, "layout-v9");
    case(R::LayoutNotSupported, Ask::new(state, plan, "s1"));
    // A rule that is only proposed cannot act automatically.
    case(
        R::RuleModeNotValidated,
        Ask {
            registry: registry_with(&LifecycleState::Proposed),
            ..Ask::eviction(enabled_state())
        },
    );

    case(
        R::TriggerEvidenceMissing,
        Ask {
            evidence: None,
            ..Ask::eviction(enabled_state())
        },
    );
    let earlier_boot = clock_in("boot_0", 199);
    case(
        R::TriggerEvidenceStale,
        Ask {
            evidence: Some(EvidenceStamp {
                acquired_at: earlier_boot.now,
                clock_domain: earlier_boot.clock_domain,
                boot_id: earlier_boot.boot_id,
            }),
            ..Ask::eviction(enabled_state())
        },
    );
    // The measurement is older than the resume at second 190.
    let at = clock(190);
    let resumed = resume(
        &enabled_state(),
        &InstanceInhibition::default(),
        &ResumeRequest { principal: USER },
        &control(&at, 190),
    )
    .unwrap()
    .acknowledge(&InstanceInhibition::default(), Persistence::Durable);
    case(
        R::MeasurementBeforeResume,
        Ask {
            inhibition: resumed.inhibition,
            evidence: Some(evidence_at(189)),
            ..Ask::eviction(resumed.state)
        },
    );
    cases
}

/// The refusals of the critical-memory exception of the journal.
fn volatile_refusals() -> Vec<(RefusalReason, Ask)> {
    use RefusalReason as R;
    let volatile = RecordingMode::VolatileCriticalException;
    let mut cases: Vec<(RefusalReason, Ask)> = Vec::new();
    let mut case = |reason: RefusalReason, ask: Ask| cases.push((reason, ask));

    // Outside its scope: a filesystem action, an application-budget
    // trigger, and manual process control.
    case(
        R::VolatileExceptionNotApplicable,
        Ask {
            recording: volatile.clone(),
            ..Ask::eviction(volatile_state())
        },
    );
    case(
        R::VolatileExceptionNotApplicable,
        Ask {
            recording: volatile.clone(),
            ..Ask::intervention(
                volatile_state(),
                TriggerClass::ApplicationBudget,
                "graceful",
            )
        },
    );
    let state = volatile_state();
    let plan = seal(application_content(&state, Escalation::None));
    case(
        R::VolatileExceptionNotApplicable,
        Ask {
            recording: volatile.clone(),
            approval: Some(approval_of(&plan)),
            evidence: None,
            ..Ask::new(state, plan, "graceful")
        },
    );

    // The configuration in effect does not have the option.
    case(
        R::VolatileExceptionNotConfigured,
        volatile_ask(enabled_state()),
    );

    // The option is configured, and the grant does not have it.
    let mut not_granted = volatile_ask(volatile_state());
    not_granted.state.guards[1]
        .grant
        .as_mut()
        .unwrap()
        .allow_volatile_journal_on_critical = false;
    case(R::VolatileExceptionNotGranted, not_granted);

    // The request has no budget record of the incident.
    case(
        R::IncidentRecordMissing,
        Ask {
            incident: None,
            ..volatile_ask(volatile_state())
        },
    );
    // The incident opened before the option was configured and granted.
    let before = IncidentBudget::open(
        incident_id(),
        MEMORY,
        &enabled_state(),
        &InstanceInhibition::default(),
        wall(150),
    );
    case(
        R::VolatileExceptionNotRecorded,
        Ask {
            incident: Some(before),
            ..volatile_ask(volatile_state())
        },
    );
    cases
}

#[test]
fn each_refusal_has_its_reason_and_its_error_family() {
    let cases = refusals();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for (expected, ask) in &cases {
        let refusal = ask.answer().unwrap_err();
        assert_eq!(refusal.reason, *expected, "{}", expected.code());
        assert_eq!(refusal.stage, ActionStage::Admission);
        assert_eq!(refusal.plan_id, ask.plan.plan_id);
        assert_eq!(refusal.step_id.as_str(), ask.step);
        let error = refusal.action_error().unwrap();
        assert_eq!(error.code.as_str(), expected.code());
        assert_eq!(error.family, expected.family());
        assert_eq!(error.family, refusal.family());
        assert_eq!(error.dispatch, DispatchState::NotSubmitted);
        assert_eq!(error.plan_id.as_ref(), Some(&ask.plan.plan_id));
        assert_eq!(error.operation_id, None);
        // No call was submitted, so the next step is the step of the
        // family.
        assert_eq!(
            error.permitted_next_step(),
            expected.family().permitted_next_step()
        );
        seen.insert(expected.code());
    }
    // A sealed plan binds the layout of each rule target (`Plan::seal`
    // refuses a rule target with none), so no sealed plan gives this
    // reason. It stays for a binding that a later change makes possible.
    seen.insert(RefusalReason::LayoutMissing.code());
    // The table has each reason of the module.
    let all: BTreeSet<&'static str> = RefusalReason::ALL.iter().map(|one| one.code()).collect();
    assert_eq!(all.len(), RefusalReason::ALL.len());
    assert_eq!(seen, all);
}

#[test]
fn each_reason_has_the_family_of_its_contract_boundary() {
    use RefusalReason as R;
    let family = |reason: RefusalReason| reason.family();
    assert_eq!(family(R::StepNotInPlan), ErrorFamily::Request);
    assert_eq!(family(R::AutomationPaused), ErrorFamily::Authority);
    assert_eq!(family(R::GuardGrantInManualPlan), ErrorFamily::Authority);
    assert_eq!(family(R::MeasurementBeforeResume), ErrorFamily::Evidence);
    assert_eq!(family(R::RuleModeNotValidated), ErrorFamily::Eligibility);
    assert_eq!(family(R::PlanExpired), ErrorFamily::Limits);
    assert_eq!(
        family(R::VolatileExceptionNotApplicable),
        ErrorFamily::Recording
    );
    assert_eq!(
        R::AutomationPaused.family().permitted_next_step(),
        PermittedNextStep::ResolveAuthority
    );
    for reason in RefusalReason::ALL {
        assert!(reason.family().is_recognized());
        assert_eq!(reason.to_string(), reason.code());
    }
}

#[test]
fn the_critical_memory_exception_is_permitted_only_in_its_exact_scope() {
    // The option was configured and granted before the incident opened,
    // and the step is an automatic global-pressure termination.
    for step in ["graceful", "force"] {
        let ask = Ask {
            step,
            ..volatile_ask(volatile_state())
        };
        let authorization = ask.answer().unwrap();
        assert_eq!(
            authorization.recording,
            RecordingMode::VolatileCriticalException
        );
    }
    // With durable recording, the same step needs no exception.
    let ask = Ask {
        recording: RecordingMode::Durable,
        ..volatile_ask(enabled_state())
    };
    ask.answer().unwrap();
}

#[test]
fn a_paused_agent_refuses_each_automatic_step_and_resumes_with_a_new_measurement() {
    let at = clock(150);
    let hour = PauseRequest {
        principal: USER,
        duration: Some(Nanoseconds::new(40 * super::SECOND)),
    };
    let none = InstanceInhibition::default();
    let paused = durable(pause(&enabled_state(), &hour, &control(&at, 150)).unwrap()).state;
    // The plans are of the record before the pause: a pause changes no
    // revision and no grant.
    let ask = |clock_seconds: u64, evidence_seconds: u64| Ask {
        clock: clock(clock_seconds),
        evidence: Some(evidence_at(evidence_seconds)),
        ..Ask::eviction(paused.clone())
    };
    // One second before the expiry.
    assert_eq!(ask(189, 188).reason(), RefusalReason::AutomationPaused);
    assert_eq!(
        Ask {
            clock: clock(189),
            ..Ask::intervention(paused.clone(), TriggerClass::GlobalCriticalMemory, "force")
        }
        .reason(),
        RefusalReason::AutomationPaused
    );
    // At the expiry the pause inhibits nothing, and a measurement from the
    // time of the pause is not sufficient.
    assert_eq!(
        ask(190, 189).reason(),
        RefusalReason::MeasurementBeforeResume
    );
    ask(190, 190).answer().unwrap();
    ask(200, 195).answer().unwrap();

    // A pause that only the instance has refuses also.
    let failed = pause(&enabled_state(), &hour, &control(&at, 150))
        .unwrap()
        .acknowledge(&none, Persistence::Failed);
    let volatile = Ask {
        clock: clock(160),
        evidence: Some(evidence_at(159)),
        inhibition: failed.inhibition.clone(),
        ..Ask::eviction(failed.state.clone())
    };
    assert_eq!(volatile.reason(), RefusalReason::AutomationPaused);

    // After a resume at second 170, only a measurement that is not older
    // is accepted.
    let later = clock(170);
    let resumed = resume(
        &paused,
        &none,
        &ResumeRequest { principal: USER },
        &control(&later, 170),
    )
    .unwrap()
    .acknowledge(&none, Persistence::Durable);
    let after = |evidence_seconds: u64| Ask {
        clock: clock(175),
        evidence: Some(evidence_at(evidence_seconds)),
        inhibition: resumed.inhibition.clone(),
        ..Ask::eviction(resumed.state.clone())
    };
    assert_eq!(after(169).reason(), RefusalReason::MeasurementBeforeResume);
    after(170).answer().unwrap();
    // A measurement that is later than the check is not usable.
    assert_eq!(after(176).reason(), RefusalReason::TriggerEvidenceStale);
    // In the next boot, each measurement of that boot is newer than the
    // resume.
    let rebooted = Ask {
        clock: clock_in("boot_2", 5),
        evidence: Some(EvidenceStamp {
            acquired_at: monotonic(4),
            ..evidence_for(&clock_in("boot_2", 4))
        }),
        inhibition: resumed.inhibition.clone(),
        ..Ask::eviction(resumed.state.clone())
    };
    // The plan is of the earlier boot, so it is expired; the evidence
    // check is not the reason.
    assert_eq!(rebooted.reason(), RefusalReason::PlanExpired);
}

fn evidence_for(clock: &EvaluationClock) -> EvidenceStamp {
    EvidenceStamp {
        acquired_at: clock.now,
        clock_domain: clock.clock_domain.clone(),
        boot_id: clock.boot_id.clone(),
    }
}

#[test]
fn a_disabled_or_revoked_guard_refuses_the_next_step_of_a_plan_in_progress() {
    // The plan was admitted with the first generation of the grant. The
    // force step is checked again at its dispatch boundary.
    let state = enabled_state();
    let admitted = Ask::intervention(state.clone(), TriggerClass::GlobalCriticalMemory, "force");
    admitted.answer().unwrap();

    let disable_memory = DisableRequest {
        principal: USER,
        policy: MEMORY,
    };
    let disabled = durable(disable(&state, &disable_memory).unwrap()).state;
    let at_dispatch = Ask {
        state: disabled.clone(),
        ..Ask::intervention(state.clone(), TriggerClass::GlobalCriticalMemory, "force")
    };
    assert_eq!(at_dispatch.reason(), RefusalReason::GuardDisabled);

    // The guard is enabled again: the plan of the first generation stays
    // invalid.
    let again = enabled(&disabled, MEMORY, &[Acceptance::ForceQuit]);
    let old_plan = Ask {
        state: again,
        ..Ask::intervention(state.clone(), TriggerClass::GlobalCriticalMemory, "force")
    };
    assert_eq!(old_plan.reason(), RefusalReason::ActionGrantMismatch);

    let revoke_memory = RevokeRequest {
        principal: USER,
        grant_id: grant_id("grant_memory"),
    };
    let revoked = durable(revoke(&state, &revoke_memory).unwrap()).state;
    let after_revoke = Ask {
        state: revoked,
        ..Ask::intervention(state, TriggerClass::GlobalCriticalMemory, "force")
    };
    assert_eq!(after_revoke.reason(), RefusalReason::ActionGrantRevoked);
}

#[test]
fn the_grant_of_one_guard_does_not_authorize_the_other_guard() {
    // Only the disk guard is enabled.
    let state = enabled(
        &active_state(&base_config()),
        DISK,
        &[Acceptance::PermanentEviction],
    );
    // An intervention plan that names the disk grant.
    let mut content = application_content(&state, Escalation::None);
    content = as_automatic(&state, content, TriggerClass::GlobalCriticalMemory, DISK);
    let ask = Ask::new(state, seal(content), "graceful");
    assert_eq!(ask.reason(), RefusalReason::GuardDisabled);

    // The two guards are enabled, and the plan of the memory guard names
    // the disk grant.
    let state = enabled_state();
    let mut content = application_content(&state, Escalation::None);
    content = as_automatic(&state, content, TriggerClass::ApplicationBudget, DISK);
    let ask = Ask::new(state, seal(content), "graceful");
    assert_eq!(ask.reason(), RefusalReason::ActionGrantMismatch);

    // The plan names the grant of its guard and the grant of the other
    // guard: each named grant must be the grant of the guard.
    let state = enabled_state();
    let mut content = application_content(&state, Escalation::None);
    content = as_automatic(&state, content, TriggerClass::ApplicationBudget, MEMORY);
    content
        .authority
        .action_grants
        .push(grant_ref(&state, DISK));
    let ask = Ask::new(state, seal(content), "graceful");
    assert_eq!(ask.reason(), RefusalReason::ActionGrantMismatch);
}

#[test]
fn a_timed_pause_of_an_earlier_boot_refuses_each_automatic_step_after_its_wall_clock_expiry() {
    // A pause of 40 seconds from second 150 of the first boot.
    let at = clock(150);
    let request = PauseRequest {
        principal: USER,
        duration: Some(Nanoseconds::new(40 * super::SECOND)),
    };
    let paused = durable(pause(&enabled_state(), &request, &control(&at, 150)).unwrap()).state;
    // The second boot starts while the pause applies. At its second 100
    // the wall clock is 20 seconds after the recorded expiry. The wall
    // clock is not evidence that the pause ended, so the pause is
    // retained.
    let boot = "boot_2";
    let ask = |evidence_seconds: u64| {
        let mut content = file_content(
            &paused,
            &ActionClass::EvictRegenerableData,
            Some(rule_ref(TEMPORARY, "r1")),
        );
        content = as_automatic(&paused, content, TriggerClass::DiskPressure, DISK);
        content.validity.boot_id = clock_in(boot, 0).boot_id;
        content.validity.created_at = monotonic(90);
        Ask {
            clock: clock_in(boot, 100),
            evidence: Some(evidence_for(&clock_in(boot, evidence_seconds))),
            ..Ask::new(paused.clone(), seal(content), "s1")
        }
    };
    let answer = |evidence_seconds: u64| {
        let ask = ask(evidence_seconds);
        let step_id = StepId::new(ask.step).unwrap();
        let context = AuthorizationContext {
            state: &ask.state,
            inhibition: &ask.inhibition,
            registry: &ask.registry,
            // The wall clock is at second 210: 20 seconds after the expiry.
            clock: control(&ask.clock, 210),
        };
        let request = ActionRequest {
            principal: ask.principal,
            plan: &ask.plan,
            step_id: &step_id,
            stage: ActionStage::Dispatch,
            approval: None,
            recording: &ask.recording,
            incident: ask.incident.as_ref(),
            evidence: ask.evidence.as_ref(),
        };
        authorize(&context, &request)
    };
    for evidence_seconds in [79, 80, 95] {
        let refusal = answer(evidence_seconds).unwrap_err();
        assert_eq!(refusal.reason, RefusalReason::AutomationPaused);
        assert_eq!(refusal.stage, ActionStage::Dispatch);
    }
}

#[test]
fn a_manual_step_of_a_class_with_no_rule_mode_cannot_bind_a_rule() {
    let state = enabled_state();
    // A permanent deletion of selected files that names a rule revision.
    // The rule has no mode for the class, so no lifecycle state permits
    // it. The registry has the rule as validated for automatic eviction.
    let plan = seal(file_content(
        &state,
        &ActionClass::DeleteSelectedFiles,
        Some(rule_ref(TEMPORARY, "r1")),
    ));
    let ask = Ask {
        approval: Some(approval_of(&plan)),
        evidence: None,
        ..Ask::new(state.clone(), plan, "s1")
    };
    assert_eq!(ask.reason(), RefusalReason::RuleNotGranted);
    // With no rule, the approval is the authority.
    Ask::manual(state, &ActionClass::DeleteSelectedFiles)
        .answer()
        .unwrap();
}

#[test]
fn the_plan_contract_refuses_a_force_step_with_no_force_strategy() {
    let state = enabled_state();
    let mut content = as_automatic(
        &state,
        application_content(&state, Escalation::ImmediateForce),
        TriggerClass::GlobalCriticalMemory,
        MEMORY,
    );
    // The plan has a force step and names no force strategy.
    content.limits.escalation = Escalation::None;
    // The plan contract refuses the plan, so the authorization never sees
    // a force step with no force strategy.
    assert!(matches!(Plan::seal(content), Err(PlanError::Steps)));
}

#[test]
fn a_layout_that_is_only_proposed_is_not_evicted_under_a_validated_layout_of_its_rule() {
    // One rule revision with a validated layout and a proposed layout.
    let mut declaration = declaration(TEMPORARY, "r1", automatic());
    declaration.layouts.push(LayoutSupport {
        layout: "layout-v2".to_owned(),
        lifecycle: LifecycleState::Proposed,
    });
    let two_layouts = || {
        Registry(vec![
            Checked::new(declaration.clone()).unwrap(),
            rule(DERIVED_DATA, "r1", automatic()),
        ])
    };
    let ask = |layout: &str| {
        let state = enabled_state();
        let plan = eviction_plan_of_layout(&state, layout);
        Ask {
            registry: two_layouts(),
            ..Ask::new(state, plan, "s1")
        }
    };
    // The target of the validated layout is permitted.
    ask("layout-v1").answer().unwrap();
    // The target of the proposed layout is refused. The request has no
    // field with which a caller can name the validated layout.
    assert_eq!(
        ask("layout-v2").reason(),
        RefusalReason::RuleModeNotValidated
    );
}
