//! The authorization question of admission.
//!
//! [`authorize`] answers whether the authority records permit one step of
//! a sealed plan, at admission and again at each dispatch boundary
//! (`docs/ACTION_CONTRACTS.md` sections 4 and 11). The answer is a
//! permission with its basis, or a [`Refusal`] with one specific reason
//! and the error family of `docs/ACTION_CONTRACTS.md` section 10.
//!
//! The function checks authority only. Hard protections, target identity,
//! budgets, leases, the trigger predicate, and the helper grant are checks
//! of other modules.

use std::fmt;

use serde::Serialize;
use thiserror::Error;

use super::guard::{GuardStanding, guard_standing};
use super::pause::{ControlClock, measurement_floor, pause_status};
use super::rearm::IncidentBudget;
use super::state::{ActiveRevision, AuthorityState, InstanceInhibition, policy_id};
use crate::action::{
    ActionClass, ActionError, ActionStage, DispatchState, ErrorCode, ErrorCodeError, ErrorFamily,
    Escalation, FileBinding, OwnerOperationBound, OwnerOperationKind, Plan, PlanApproval,
    PlannedStep, RecordingMode, TargetBinding, TriggerClass, critical_exception_applies,
};
use crate::authority::{ActionGrant, ActionGrantRef};
use crate::digest::ContentDigest;
use crate::id::{BootId, ClockDomainId, PlanId, PolicyRevisionId, StepId};
use crate::policy::PolicyId;
use crate::process::Uid;
use crate::rule::{DeletionMethod, Rule, RuleMode, RuleRef, RuleRefusal, RuleRegistry};
use crate::time::MonotonicNanos;

/// The records that the authorization reads.
#[derive(Clone, Copy)]
pub struct AuthorizationContext<'a> {
    /// The durable authority record.
    pub state: &'a AuthorityState,
    /// The volatile state of the running instance.
    pub inhibition: &'a InstanceInhibition,
    /// The rule registry, for the lifecycle state of a rule revision.
    pub registry: &'a dyn RuleRegistry,
    /// The time of the check.
    pub clock: ControlClock<'a>,
}

impl fmt::Debug for AuthorizationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationContext")
            .field("state", self.state)
            .field("inhibition", self.inhibition)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

/// The acquisition time of the newest measurement that supports the
/// trigger of an automatic action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceStamp {
    /// The monotonic time at which the measurement was acquired.
    pub acquired_at: MonotonicNanos,
    /// The clock domain of `acquired_at`.
    pub clock_domain: ClockDomainId,
    /// The boot of `acquired_at`.
    pub boot_id: BootId,
}

/// One step of a plan that admission or dispatch asks about.
///
/// The action class, the target, the layout of a rule target, the trigger,
/// the force strategy, and the bound revisions come from the sealed plan,
/// so the caller cannot state them differently.
#[derive(Debug, Clone)]
pub struct ActionRequest<'a> {
    /// The authenticated user of the request. The transport gives it.
    pub principal: Uid,
    /// The sealed plan.
    pub plan: &'a Plan,
    /// The step.
    pub step_id: &'a StepId,
    /// The stage of the check, for the error record.
    pub stage: ActionStage,
    /// The approval of a manual plan: the plan identity and the digest
    /// that the client reviewed.
    pub approval: Option<&'a PlanApproval>,
    /// The recording that the step will have.
    pub recording: &'a RecordingMode,
    /// The budget record of the incident of an automatic plan.
    pub incident: Option<&'a IncidentBudget>,
    /// The newest measurement that supports the trigger of an automatic
    /// plan.
    pub evidence: Option<&'a EvidenceStamp>,
}

/// The specific reason of a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// The plan has no step with the identity.
    StepNotInPlan,
    /// A value of the plan or of the request is one that this build does
    /// not recognize, or the plan does not agree with itself. A sealed plan
    /// has neither condition; only the recording of the request can.
    UnsupportedValue,
    /// The plan does not bind the layout of a target that a rule
    /// selected. A sealed plan binds it; the reason stays for a binding
    /// that does not.
    LayoutMissing,
    /// The budget record is of a different incident or guard than the plan.
    IncidentMismatch,
    /// An automatic plan has no budget record of its incident.
    IncidentRecordMissing,
    /// The user of the request, of the plan, and of the record are not the
    /// same user.
    WrongPrincipal,
    /// No policy revision is in effect.
    NoActivePolicyRevision,
    /// The plan is bound to a different policy revision than the revision
    /// in effect.
    PolicyRevisionMismatch,
    /// A manual plan has no approval.
    ManualApprovalMissing,
    /// The approval is not bound to the plan: the identity or the digest
    /// is different.
    ManualApprovalMismatch,
    /// A manual plan names an action grant. The standing authority of a
    /// guard is for its automatic incidents only.
    GuardGrantInManualPlan,
    /// Automatic intervention is paused.
    AutomationPaused,
    /// The running instance inhibits the guard.
    GuardInhibited,
    /// The configuration in effect does not request the guard.
    GuardNotRequested,
    /// The profile in effect permits no automatic intervention.
    ObserveProfile,
    /// The guard is not enabled.
    GuardDisabled,
    /// The guard has no action grant.
    ActionGrantMissing,
    /// The action grant was revoked.
    ActionGrantRevoked,
    /// The action grant is at its expiry or after it.
    ActionGrantExpired,
    /// The action grant does not cover the scope of the revision in
    /// effect. A new acceptance is necessary.
    AcceptanceRequired,
    /// The plan does not name the current generation of the action grant
    /// of the guard.
    ActionGrantMismatch,
    /// The action grant does not cover the action class.
    ActionClassNotGranted,
    /// The action grant or the revision in effect does not cover the rule
    /// revision, or the target of a rule action has no rule revision.
    RuleNotGranted,
    /// The action grant does not permit the force strategy of the plan.
    EscalationNotGranted,
    /// An automatic plan has no trigger evidence.
    TriggerEvidenceMissing,
    /// The trigger evidence is of a different boot or clock domain, or is
    /// later than the time of the check.
    TriggerEvidenceStale,
    /// The trigger evidence is older than the latest resume or pause
    /// expiry. A new measurement is necessary.
    MeasurementBeforeResume,
    /// The rule revision is not in the registry.
    RuleNotRegistered,
    /// The rule revision does not support the layout.
    LayoutNotSupported,
    /// The lifecycle state of the rule revision does not permit the mode
    /// for the layout. A rule that is only proposed is in this condition.
    RuleModeNotValidated,
    /// The plan is expired.
    PlanExpired,
    /// The critical-memory exception of the journal does not apply to the
    /// step: it applies only to an automatic application intervention with
    /// the global critical-memory trigger.
    VolatileExceptionNotApplicable,
    /// The configuration in effect does not permit the exception.
    VolatileExceptionNotConfigured,
    /// The action grant does not permit the exception.
    VolatileExceptionNotGranted,
    /// The exception was not configured and granted when the incident
    /// opened.
    VolatileExceptionNotRecorded,
}

impl RefusalReason {
    /// Each reason.
    pub const ALL: [Self; 35] = [
        Self::StepNotInPlan,
        Self::UnsupportedValue,
        Self::LayoutMissing,
        Self::IncidentMismatch,
        Self::IncidentRecordMissing,
        Self::WrongPrincipal,
        Self::NoActivePolicyRevision,
        Self::PolicyRevisionMismatch,
        Self::ManualApprovalMissing,
        Self::ManualApprovalMismatch,
        Self::GuardGrantInManualPlan,
        Self::AutomationPaused,
        Self::GuardInhibited,
        Self::GuardNotRequested,
        Self::ObserveProfile,
        Self::GuardDisabled,
        Self::ActionGrantMissing,
        Self::ActionGrantRevoked,
        Self::ActionGrantExpired,
        Self::AcceptanceRequired,
        Self::ActionGrantMismatch,
        Self::ActionClassNotGranted,
        Self::RuleNotGranted,
        Self::EscalationNotGranted,
        Self::TriggerEvidenceMissing,
        Self::TriggerEvidenceStale,
        Self::MeasurementBeforeResume,
        Self::RuleNotRegistered,
        Self::LayoutNotSupported,
        Self::RuleModeNotValidated,
        Self::PlanExpired,
        Self::VolatileExceptionNotApplicable,
        Self::VolatileExceptionNotConfigured,
        Self::VolatileExceptionNotGranted,
        Self::VolatileExceptionNotRecorded,
    ];

    /// The stable error code of the reason.
    pub const fn code(self) -> &'static str {
        match self {
            Self::StepNotInPlan => "step_not_in_plan",
            Self::UnsupportedValue => "unsupported_value",
            Self::LayoutMissing => "layout_missing",
            Self::IncidentMismatch => "incident_mismatch",
            Self::IncidentRecordMissing => "incident_record_missing",
            Self::WrongPrincipal => "wrong_principal",
            Self::NoActivePolicyRevision => "no_active_policy_revision",
            Self::PolicyRevisionMismatch => "policy_revision_mismatch",
            Self::ManualApprovalMissing => "manual_approval_missing",
            Self::ManualApprovalMismatch => "manual_approval_mismatch",
            Self::GuardGrantInManualPlan => "guard_grant_in_manual_plan",
            Self::AutomationPaused => "automation_paused",
            Self::GuardInhibited => "guard_inhibited",
            Self::GuardNotRequested => "guard_not_requested",
            Self::ObserveProfile => "observe_profile",
            Self::GuardDisabled => "guard_disabled",
            Self::ActionGrantMissing => "action_grant_missing",
            Self::ActionGrantRevoked => "action_grant_revoked",
            Self::ActionGrantExpired => "action_grant_expired",
            Self::AcceptanceRequired => "acceptance_required",
            Self::ActionGrantMismatch => "action_grant_mismatch",
            Self::ActionClassNotGranted => "action_class_not_granted",
            Self::RuleNotGranted => "rule_not_granted",
            Self::EscalationNotGranted => "escalation_not_granted",
            Self::TriggerEvidenceMissing => "trigger_evidence_missing",
            Self::TriggerEvidenceStale => "trigger_evidence_stale",
            Self::MeasurementBeforeResume => "measurement_before_resume",
            Self::RuleNotRegistered => "rule_not_registered",
            Self::LayoutNotSupported => "layout_not_supported",
            Self::RuleModeNotValidated => "rule_mode_not_validated",
            Self::PlanExpired => "plan_expired",
            Self::VolatileExceptionNotApplicable => "volatile_exception_not_applicable",
            Self::VolatileExceptionNotConfigured => "volatile_exception_not_configured",
            Self::VolatileExceptionNotGranted => "volatile_exception_not_granted",
            Self::VolatileExceptionNotRecorded => "volatile_exception_not_recorded",
        }
    }

    /// The error family of the reason (`docs/ACTION_CONTRACTS.md` section
    /// 10).
    pub const fn family(self) -> ErrorFamily {
        match self {
            Self::StepNotInPlan
            | Self::UnsupportedValue
            | Self::LayoutMissing
            | Self::IncidentMismatch
            | Self::IncidentRecordMissing => ErrorFamily::Request,
            Self::WrongPrincipal
            | Self::NoActivePolicyRevision
            | Self::PolicyRevisionMismatch
            | Self::ManualApprovalMissing
            | Self::ManualApprovalMismatch
            | Self::GuardGrantInManualPlan
            | Self::AutomationPaused
            | Self::GuardInhibited
            | Self::GuardNotRequested
            | Self::ObserveProfile
            | Self::GuardDisabled
            | Self::ActionGrantMissing
            | Self::ActionGrantRevoked
            | Self::ActionGrantExpired
            | Self::AcceptanceRequired
            | Self::ActionGrantMismatch
            | Self::ActionClassNotGranted
            | Self::RuleNotGranted
            | Self::EscalationNotGranted => ErrorFamily::Authority,
            Self::TriggerEvidenceMissing
            | Self::TriggerEvidenceStale
            | Self::MeasurementBeforeResume => ErrorFamily::Evidence,
            Self::RuleNotRegistered | Self::LayoutNotSupported | Self::RuleModeNotValidated => {
                ErrorFamily::Eligibility
            }
            Self::PlanExpired => ErrorFamily::Limits,
            Self::VolatileExceptionNotApplicable
            | Self::VolatileExceptionNotConfigured
            | Self::VolatileExceptionNotGranted
            | Self::VolatileExceptionNotRecorded => ErrorFamily::Recording,
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// A refused authorization. No external call was submitted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the step is not authorized: {reason}")]
pub struct Refusal {
    /// The specific reason.
    pub reason: RefusalReason,
    /// The stage of the check.
    pub stage: ActionStage,
    /// The plan.
    pub plan_id: PlanId,
    /// The step.
    pub step_id: StepId,
}

impl Refusal {
    /// The error family of the refusal.
    pub const fn family(&self) -> ErrorFamily {
        self.reason.family()
    }

    /// The error record of the action contract, with the dispatch state
    /// `not_submitted`.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorCodeError`] when the code of the reason is not an
    /// accepted error code. Each code of this module is accepted.
    pub fn action_error(&self) -> Result<ActionError, ErrorCodeError> {
        Ok(ActionError {
            code: ErrorCode::new(self.reason.code())?,
            family: self.reason.family(),
            stage: self.stage.clone(),
            dispatch: DispatchState::NotSubmitted,
            plan_id: Some(self.plan_id.clone()),
            operation_id: None,
            step_id: Some(self.step_id.clone()),
        })
    }
}

/// The authority that permits a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum AuthorizationBasis {
    /// The approval that is bound to the manual plan.
    PlanApproval {
        /// The plan.
        plan_id: PlanId,
        /// The digest that the client reviewed.
        digest: ContentDigest,
    },
    /// The standing action grant of a guard.
    StandingGrant {
        /// The guard.
        #[serde(serialize_with = "policy_id::serialize")]
        policy: PolicyId,
        /// The grant and its generation.
        grant: ActionGrantRef,
    },
}

/// A permitted step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Authorization {
    /// The authority that permits the step.
    pub basis: AuthorizationBasis,
    /// The policy revision in effect, which the plan is bound to.
    pub policy_revision: PolicyRevisionId,
    /// The action class of the step.
    pub action_class: ActionClass,
    /// The recording that the authorization covers.
    pub recording: RecordingMode,
}

/// The facts of one request that each check uses.
struct StepCheck<'a> {
    context: &'a AuthorizationContext<'a>,
    request: &'a ActionRequest<'a>,
    step: &'a PlannedStep,
    binding: &'a TargetBinding,
    active: &'a ActiveRevision,
}

/// The refusal reason of a guard that has no automatic authority. `None`
/// for [`GuardStanding::Active`]. The authorization and the rearm use this
/// one mapping.
pub(super) const fn standing_refusal(standing: GuardStanding) -> Option<RefusalReason> {
    match standing {
        GuardStanding::Active => None,
        GuardStanding::NoActiveRevision => Some(RefusalReason::NoActivePolicyRevision),
        GuardStanding::Inhibited => Some(RefusalReason::GuardInhibited),
        GuardStanding::NotRequested => Some(RefusalReason::GuardNotRequested),
        GuardStanding::ObserveProfile => Some(RefusalReason::ObserveProfile),
        GuardStanding::Disabled => Some(RefusalReason::GuardDisabled),
        GuardStanding::NoGrant => Some(RefusalReason::ActionGrantMissing),
        GuardStanding::GrantRevoked => Some(RefusalReason::ActionGrantRevoked),
        GuardStanding::GrantExpired => Some(RefusalReason::ActionGrantExpired),
        GuardStanding::AcceptanceRequired => Some(RefusalReason::AcceptanceRequired),
    }
}

fn rule_refusal(refusal: RuleRefusal) -> RefusalReason {
    match refusal {
        RuleRefusal::UnknownRule | RuleRefusal::UnknownRevision => RefusalReason::RuleNotRegistered,
        RuleRefusal::UnknownLayout => RefusalReason::LayoutNotSupported,
        RuleRefusal::ModeNotValidated => RefusalReason::RuleModeNotValidated,
    }
}

impl StepCheck<'_> {
    /// Checks that the lifecycle state of `rule` permits `mode` for the
    /// layout that the sealed plan binds for the target.
    ///
    /// An owner operation is the removal method of a rule whose deletion
    /// method is `producer_operation`; a rule with a different method has
    /// no owner operation, so no lifecycle state permits one.
    fn check_rule_mode(&self, rule: &RuleRef, mode: &RuleMode) -> Result<(), RefusalReason> {
        let (layout, is_owner): (&str, bool) = match self.binding {
            TargetBinding::File(FileBinding {
                layout: Some(layout),
                ..
            }) => (layout.as_str(), false),
            TargetBinding::OwnerOperation(owner) => (owner.layout.as_str(), true),
            _ => return Err(RefusalReason::LayoutMissing),
        };
        let resolved: &Rule = self
            .context
            .registry
            .resolve(rule, layout, mode)
            .map_err(rule_refusal)?;
        if is_owner && resolved.deletion_method != DeletionMethod::ProducerOperation {
            return Err(RefusalReason::RuleModeNotValidated);
        }
        Ok(())
    }

    /// A manual step: the approval that is bound to the plan is the
    /// authority. A guard grant, a guard flag, and a pause have no effect.
    fn manual(&self) -> Result<AuthorizationBasis, RefusalReason> {
        let plan: &Plan = self.request.plan;
        if !plan.authority.action_grants.is_empty() {
            return Err(RefusalReason::GuardGrantInManualPlan);
        }
        let approval: &PlanApproval = self
            .request
            .approval
            .ok_or(RefusalReason::ManualApprovalMissing)?;
        if !plan.is_bound_by(approval) {
            return Err(RefusalReason::ManualApprovalMismatch);
        }
        // The lifecycle state of a rule applies whenever the rule
        // executes, also for a manual plan.
        if let TargetBinding::File(FileBinding { rule, .. }) = self.binding {
            let mode: Option<RuleMode> = match self.step.action_class {
                ActionClass::EvictRegenerableData => Some(RuleMode::ManualEviction),
                ActionClass::MoveToTrash => Some(RuleMode::ManualTrash),
                _ => None,
            };
            match (rule, mode) {
                (Some(rule), Some(mode)) => self.check_rule_mode(rule, &mode)?,
                // A sealed eviction plan has a rule revision for each
                // target. A plan with none is refused here also.
                (None, Some(RuleMode::ManualEviction)) => {
                    return Err(RefusalReason::RuleNotGranted);
                }
                // A rule has no mode for another action class, so there
                // is no lifecycle state that permits it. A sealed plan of
                // the plan builder binds a rule only for an eviction.
                (Some(_), None) => return Err(RefusalReason::RuleNotGranted),
                (None, _) => {}
            }
        }
        // An owner operation uses the manual eviction mode of its rule,
        // for the layout that the sealed plan binds.
        if let TargetBinding::OwnerOperation(owner) = self.binding {
            if self.step.action_class != ActionClass::RunOwnerOperation {
                return Err(RefusalReason::RuleNotGranted);
            }
            self.check_rule_mode(&owner.rule, &RuleMode::ManualEviction)?;
        }
        Ok(AuthorizationBasis::PlanApproval {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest().clone(),
        })
    }

    /// The grant of `policy`, when the guard is active and the plan names
    /// the current generation of the grant.
    fn standing_grant(&self, policy: PolicyId) -> Result<&ActionGrant, RefusalReason> {
        let state: &AuthorityState = self.context.state;
        let standing: GuardStanding = guard_standing(
            state,
            self.context.inhibition,
            policy,
            self.context.clock.wall,
        );
        if let Some(reason) = standing_refusal(standing) {
            return Err(reason);
        }
        let grant: &ActionGrant = state
            .guard(policy)
            .and_then(|guard| guard.grant.as_ref())
            .ok_or(RefusalReason::ActionGrantMissing)?;
        let named = &self.request.plan.authority.action_grants;
        if named.is_empty() || !named.iter().all(|reference| grant.matches(reference)) {
            return Err(RefusalReason::ActionGrantMismatch);
        }
        Ok(grant)
    }

    /// Checks that the grant covers the action class and the scope of the
    /// step.
    fn check_scope(&self, grant: &ActionGrant) -> Result<(), RefusalReason> {
        let now = self.context.clock.wall;
        if !grant.covers_class(&self.step.action_class, now) {
            return Err(RefusalReason::ActionClassNotGranted);
        }
        match self.binding {
            TargetBinding::File(file) => {
                let rule: &RuleRef = file.rule.as_ref().ok_or(RefusalReason::RuleNotGranted)?;
                let approved: bool = self.active.scope.rules(PolicyId::DiskGuard).contains(rule);
                if !approved || !grant.covers_rule(&self.step.action_class, rule, now) {
                    return Err(RefusalReason::RuleNotGranted);
                }
                self.check_rule_mode(rule, &RuleMode::AutomaticEviction)
            }
            // An automatic owner operation is a bounded `prune`; the seal
            // of the plan refuses each other one, and this check fails
            // closed for it again.
            TargetBinding::OwnerOperation(owner) => {
                let rule: &RuleRef = &owner.rule;
                let approved: bool = self.active.scope.rules(PolicyId::DiskGuard).contains(rule);
                if !approved || !grant.covers_rule(&self.step.action_class, rule, now) {
                    return Err(RefusalReason::RuleNotGranted);
                }
                let bounded: bool = matches!(owner.operation, OwnerOperationKind::Prune)
                    && matches!(owner.bound, OwnerOperationBound::WithinScope)
                    && !owner.clear_opt_in;
                if !bounded {
                    return Err(RefusalReason::UnsupportedValue);
                }
                self.check_rule_mode(rule, &RuleMode::AutomaticEviction)
            }
            // A guard selects an application or a job instance and never
            // one process. A sealed plan with a process target is manual,
            // so no sealed plan reaches this arm.
            TargetBinding::Process(_) => Err(RefusalReason::UnsupportedValue),
            TargetBinding::Application(_) => {
                let escalation: &Escalation = &self.request.plan.limits.escalation;
                // A force step belongs to a force strategy. A plan with
                // no force strategy cannot use the force class of the
                // grant for one of its steps. This is a second check:
                // `Plan::seal` refuses such a plan, so no sealed plan
                // reaches this branch. The branch stays, and it fails
                // closed.
                let force_without_strategy: bool = self.step.action_class
                    == ActionClass::ForceApplicationExit
                    && matches!(escalation, Escalation::None);
                if !force_without_strategy && grant.permits_escalation(escalation, now) {
                    Ok(())
                } else {
                    Err(RefusalReason::EscalationNotGranted)
                }
            }
        }
    }

    /// Checks that the trigger evidence is of the current timeline and is
    /// not older than the latest resume or pause expiry.
    fn check_evidence(&self) -> Result<(), RefusalReason> {
        let clock = self.context.clock.clock;
        let evidence: &EvidenceStamp = self
            .request
            .evidence
            .ok_or(RefusalReason::TriggerEvidenceMissing)?;
        if evidence.clock_domain != clock.clock_domain
            || evidence.boot_id != clock.boot_id
            || evidence.acquired_at > clock.now
        {
            return Err(RefusalReason::TriggerEvidenceStale);
        }
        let floor: Option<MonotonicNanos> = measurement_floor(
            self.context.state,
            self.context.inhibition,
            &self.context.clock,
        );
        if floor.is_some_and(|floor| evidence.acquired_at < floor) {
            return Err(RefusalReason::MeasurementBeforeResume);
        }
        Ok(())
    }

    /// Checks the critical-memory exception of the journal: the
    /// configuration, the grant, and the record of the incident.
    fn check_volatile(&self, grant: &ActionGrant) -> Result<(), RefusalReason> {
        if !self.active.scope.memory.allow_volatile_journal_on_critical {
            return Err(RefusalReason::VolatileExceptionNotConfigured);
        }
        if !grant.allow_volatile_journal_on_critical {
            return Err(RefusalReason::VolatileExceptionNotGranted);
        }
        let recorded: bool = self
            .request
            .incident
            .is_some_and(|incident| incident.volatile_exception_at_open);
        if recorded {
            Ok(())
        } else {
            Err(RefusalReason::VolatileExceptionNotRecorded)
        }
    }

    /// An automatic step: the standing grant of the guard of the trigger
    /// is the authority.
    fn automatic(&self, policy: PolicyId) -> Result<AuthorizationBasis, RefusalReason> {
        let context: &AuthorizationContext<'_> = self.context;
        let trigger = &self.request.plan.trigger;
        // An automatic step belongs to one incident, and the incident has
        // a budget record.
        let incident: &IncidentBudget = self
            .request
            .incident
            .ok_or(RefusalReason::IncidentRecordMissing)?;
        // The plan uses the current budget generation of the incident: a
        // plan of an earlier generation is not charged to a generation
        // that a rearm authorized after it.
        if incident.policy != policy
            || Some(&incident.incident_id) != trigger.incident_id.as_ref()
            || Some(incident.generation) != trigger.budget_generation
        {
            return Err(RefusalReason::IncidentMismatch);
        }
        let paused: bool = [
            context.state.pause.as_ref(),
            context.inhibition.pause.as_ref(),
        ]
        .into_iter()
        .any(|pause| pause_status(pause, &context.clock).is_paused());
        if paused {
            return Err(RefusalReason::AutomationPaused);
        }
        let grant: &ActionGrant = self.standing_grant(policy)?;
        self.check_scope(grant)?;
        // The trigger evidence is a condition of the start of a step and not
        // of a command that runs (the stage `execution`).
        if !matches!(self.request.stage, ActionStage::Execution) {
            self.check_evidence()?;
        }
        if matches!(
            self.request.recording,
            RecordingMode::VolatileCriticalException
        ) {
            self.check_volatile(grant)?;
        }
        Ok(AuthorizationBasis::StandingGrant {
            policy,
            grant: grant.reference(),
        })
    }
}

fn decide(
    context: &AuthorizationContext<'_>,
    request: &ActionRequest<'_>,
) -> Result<Authorization, RefusalReason> {
    let plan: &Plan = request.plan;
    let step: &PlannedStep = plan
        .steps
        .iter()
        .find(|step| &step.step_id == request.step_id)
        .ok_or(RefusalReason::StepNotInPlan)?;
    let binding: &TargetBinding = plan
        .targets
        .iter()
        .find(|target| target.target_id == step.target_id)
        .map(|target| &target.binding)
        .ok_or(RefusalReason::StepNotInPlan)?;
    let class: &ActionClass = &step.action_class;
    let trigger: &TriggerClass = &plan.trigger.class;
    let recognized: bool = class.is_recognized()
        && trigger.is_recognized()
        && request.recording.is_recognized()
        && plan.limits.escalation.is_recognized();
    if !recognized {
        return Err(RefusalReason::UnsupportedValue);
    }
    if request.principal != context.state.principal || plan.principal.uid != request.principal {
        return Err(RefusalReason::WrongPrincipal);
    }
    let active: &ActiveRevision = context
        .state
        .active
        .as_ref()
        .ok_or(RefusalReason::NoActivePolicyRevision)?;
    if plan.authority.policy_revision != active.revision.revision_id {
        return Err(RefusalReason::PolicyRevisionMismatch);
    }
    // The stage `execution` is the check while a command of an owner
    // operation runs: the expiry of the plan does not stop a call that was
    // issued (`docs/ACTION_CONTRACTS.md` section 7).
    let running: bool = matches!(request.stage, ActionStage::Execution);
    if !running && plan.is_expired(context.clock.clock) {
        return Err(RefusalReason::PlanExpired);
    }
    if !class.accepts_trigger(trigger) {
        return Err(RefusalReason::UnsupportedValue);
    }
    if matches!(request.recording, RecordingMode::VolatileCriticalException)
        && !critical_exception_applies(class, trigger)
    {
        return Err(RefusalReason::VolatileExceptionNotApplicable);
    }
    let checked: StepCheck<'_> = StepCheck {
        context,
        request,
        step,
        binding,
        active,
    };
    let basis: AuthorizationBasis = match trigger {
        TriggerClass::Manual => checked.manual()?,
        TriggerClass::DiskPressure => checked.automatic(PolicyId::DiskGuard)?,
        TriggerClass::GlobalCriticalMemory | TriggerClass::ApplicationBudget => {
            checked.automatic(PolicyId::MemoryGuard)?
        }
        TriggerClass::Unrecognized(_) => return Err(RefusalReason::UnsupportedValue),
    };
    Ok(Authorization {
        basis,
        policy_revision: active.revision.revision_id.clone(),
        action_class: class.clone(),
        recording: request.recording.clone(),
    })
}

/// Answers whether the authority records permit one step of a plan.
///
/// Conditions of each step:
///
/// - The user of the request, of the plan, and of the record is the same.
/// - The plan is bound to the policy revision in effect and is not
///   expired.
/// - The critical-memory exception of the journal is requested only for an
///   application intervention with the global critical-memory trigger.
///
/// A manual step needs the approval that is bound to the plan: the plan
/// identity and the digest. Its plan names no action grant, so it cannot
/// borrow the automatic authority of a guard, and the grant of a guard
/// cannot authorize a manual deletion. A pause, a disabled guard, and the
/// `observe` profile do not refuse a manual step.
///
/// An automatic step needs each of these:
///
/// - The request has the budget record of the incident of the plan.
/// - No pause is in effect.
/// - The guard of the trigger has the standing
///   [`GuardStanding::Active`].
/// - The plan names the current generation of the grant of the guard.
/// - The grant covers the action class, and the rule revision or the force
///   strategy of the step.
/// - For a rule, the registry has the exact revision, and the lifecycle
///   state of the layout permits automatic eviction. A rule that is only
///   proposed is refused.
/// - The trigger evidence is of the current boot and clock domain and is
///   not older than the latest resume or pause expiry.
/// - For the critical-memory exception, the configuration in effect and
///   the grant permit it, and the budget record of the incident shows that
///   they did when the incident opened.
///
/// # Errors
///
/// Returns a [`Refusal`] with the first condition that is not true. No
/// external call was submitted.
pub fn authorize(
    context: &AuthorizationContext<'_>,
    request: &ActionRequest<'_>,
) -> Result<Authorization, Refusal> {
    decide(context, request).map_err(|reason| Refusal {
        reason,
        stage: request.stage.clone(),
        plan_id: request.plan.plan_id.clone(),
        step_id: request.step_id.clone(),
    })
}
