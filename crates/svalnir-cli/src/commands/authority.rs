//! `config apply`, `policy enable`, `policy disable`, `policy rearm`,
//! `agent pause`, and `agent resume`: the changes of the standing authority.
//!
//! Each command reads the authority record of the journal, computes the
//! change with the pure functions of `svalnir_core::grant`, and writes the
//! new record with a compare-and-set on the record revision. The result
//! states the acknowledgement of `docs/INTERFACES.md` section 13. A change
//! that is not written is an error: this client has no running instance
//! that it can inhibit.

use std::time::Duration;

use serde::Serialize;
use svalnir_agent::journal::{AgentRecord, OperationJournal, OperationJournalError};
use svalnir_core::action::ActionClass;
use svalnir_core::authority::ActionGrantRef;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::digest::ContentDigest;
use svalnir_core::grant::{
    Acceptance, Acknowledged, AcknowledgementLevel, ActivationRefusal, ActivationReport,
    ActivationRequest, AuthorityState, Change, ControlRefusal, DisableRequest, EnableRefusal,
    EnableReport, EnableRequest, GuardStanding, InstanceInhibition, PauseReport, PauseRequest,
    PauseStatus, Persistence, RestrictionReport, ResumeReport, ResumeRequest, activate, disable,
    enable, guard_standing, pause, pause_status, resume,
};
use svalnir_core::id::{ActionGrantId, IncidentId, PolicyRevisionId};
use svalnir_core::policy::PolicyId;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::WallTime;

use super::config::{self as config_command, Proposal};
use super::session::{
    self, CoordinatorPresence, Now, StoredAuthority, coordinator_presence, journal_error,
    open_journal, read_authority,
};
use super::{CommandFailure, Invocation};
use crate::cli::{
    AgentPauseArgs, ConfigApplyArgs, PolicyEnableArgs, PolicyName, PolicyRearmArgs, PolicyRef,
    ProposalOption,
};
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::seams::Confirmation;
use crate::text::{escape, json_tree, put_line};

/// The `--expected-revision` value for "no revision is in effect".
pub(crate) const NO_REVISION: &str = "none";

/// The statement of each control result about a running agent.
const AGENT_PICKUP_NOTE: &str = "The record is in the operation journal. An agent that runs reads it at its next tick; no restart is necessary. This command started no agent and enabled no guard other than the one it names.";

pub(crate) const fn policy_id(name: PolicyName) -> PolicyId {
    match name {
        PolicyName::DiskGuard => PolicyId::DiskGuard,
        PolicyName::MemoryGuard => PolicyId::MemoryGuard,
    }
}

fn level_text(level: AcknowledgementLevel) -> &'static str {
    match level {
        AcknowledgementLevel::DurablyApplied => "durably_applied",
        AcknowledgementLevel::CurrentInstanceInhibition => "current_instance_inhibition",
        AcknowledgementLevel::NotApplied => "not_applied",
    }
}

/// The result of a control command.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ControlView<R: Serialize> {
    /// The command, for example `policy enable`.
    command: &'static str,
    /// The acknowledgement of `docs/INTERFACES.md` section 13:
    /// `durably_applied` for each result of this build.
    acknowledgement: &'static str,
    /// True when the journal has the new record, or when the request
    /// needed no change of the record.
    durable: bool,
    /// False when the record already had the requested state.
    record_changed: bool,
    /// Whether a coordinator process holds the coordinator lock.
    coordinator: CoordinatorPresence,
    /// The report of the change.
    report: R,
    note: &'static str,
}

impl<R: Serialize> ControlView<R> {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        put_line!(out, "svalnir {}: {}", self.command, self.acknowledgement);
        put_line!(
            out,
            "Record: {}",
            if self.record_changed {
                "written to the operation journal (durable)"
            } else {
                "not changed; it already had the requested state"
            }
        );
        put_line!(
            out,
            "Coordinator process: {}",
            match self.coordinator {
                CoordinatorPresence::Running => "holds the coordinator lock",
                CoordinatorPresence::NotRunning => "none holds the coordinator lock",
                CoordinatorPresence::Unknown => "not known",
            }
        );
        out.push('\n');
        match serde_json::to_value(&self.report) {
            Ok(value) => out.push_str(&json_tree(&value)),
            Err(_) => out.push_str("The report cannot be shown as text; use `--format json`.\n"),
        }
        put_line!(out, "\n{}", escape(self.note));
        out
    }
}

/// The error for a change that the journal did not take.
fn not_persisted(error: &OperationJournalError, restriction: bool) -> ErrorBody {
    if matches!(error, OperationJournalError::Conflict) {
        return ErrorBody::new(
            "authority_record_changed",
            ErrorFamily::Evidence,
            ErrorStage::Storage,
            "a different process changed the authority record at the same time; this command did not change the authority record; read the state again and decide again",
        )
        .with_next_action(NextAction::RefreshObservation);
    }
    let mut body: ErrorBody = journal_error(error);
    let effect: &str = if restriction {
        "the change was not written, so it is NOT in effect: this client has no running instance that it can inhibit, and an agent continues with the earlier record"
    } else {
        "the change was not written, so it is not in effect"
    };
    body.message = format!("{}; {effect}", body.message);
    body.stage = ErrorStage::Storage;
    body
}

/// Writes the new authority record and gives the acknowledgement.
fn persist<R>(
    journal: &mut OperationJournal,
    stored: &StoredAuthority,
    change: Change<R>,
    now: WallTime,
) -> Result<(Acknowledged<R>, bool), ErrorBody> {
    let inhibition = InstanceInhibition::default();
    if !change.needs_persistence() {
        return Ok((change.acknowledge(&inhibition, Persistence::Durable), false));
    }
    let restriction: bool = change.is_restriction();
    journal
        .put_agent_record(
            AgentRecord::Authority,
            &change.next,
            Some(stored.revision),
            now,
        )
        .map_err(|error| not_persisted(&error, restriction))?;
    Ok((change.acknowledge(&inhibition, Persistence::Durable), true))
}

fn emit_control<R: Serialize>(
    command: &'static str,
    acknowledged: Acknowledged<R>,
    record_changed: bool,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let coordinator: CoordinatorPresence = invocation
        .environment
        .journal_path()
        .map_or(CoordinatorPresence::Unknown, |path| {
            coordinator_presence(&path)
        });
    let view = ControlView {
        command,
        acknowledgement: level_text(acknowledged.level),
        durable: acknowledged.level == AcknowledgementLevel::DurablyApplied,
        record_changed,
        coordinator,
        report: acknowledged.report,
        note: AGENT_PICKUP_NOTE,
    };
    invocation.emit(Kind::Report, &view, ControlView::render)?;
    Ok(ExitStatus::Success)
}

fn wrong_principal() -> ErrorBody {
    ErrorBody::new(
        "wrong_principal",
        ErrorFamily::Authority,
        ErrorStage::Admission,
        "the authority record is of a different user; the command made no change",
    )
}

fn revision_text(revision: Option<&PolicyRevisionId>) -> String {
    revision.map_or_else(|| NO_REVISION.to_owned(), ToString::to_string)
}

fn revision_conflict(
    expected: Option<&PolicyRevisionId>,
    active: Option<&PolicyRevisionId>,
    detail: &str,
) -> ErrorBody {
    ErrorBody::new(
        "revision_conflict",
        ErrorFamily::Evidence,
        ErrorStage::Admission,
        format!(
            "the expected revision is `{}`, and the revision in effect is `{}`{detail}; evaluate the proposal against the revision in effect and send the request again; the command made no change",
            revision_text(expected),
            revision_text(active),
        ),
    )
    .with_fields(&["expected_revision"])
    .with_next_action(NextAction::RefreshObservation)
}

/// Parses `--expected-revision`. The text `none` expects no revision.
fn expected_revision(text: &str) -> Result<Option<PolicyRevisionId>, ErrorBody> {
    if text == NO_REVISION {
        return Ok(None);
    }
    PolicyRevisionId::new(text).map(Some).map_err(|_| {
        session::invalid_identifier(
            "invalid_revision",
            "policy revision",
            &["expected_revision"],
        )
    })
}

#[cfg(unix)]
fn registry() -> Result<svalnir_agent::rules::ReviewedRules, ErrorBody> {
    svalnir_agent::rules::ReviewedRules::new().map_err(|_| {
        ErrorBody::new(
            "rule_registry_unavailable",
            ErrorFamily::Native,
            ErrorStage::Dispatch,
            "the rule registry of this build is not usable; the command made no change",
        )
    })
}

/// The report of `config apply`.
#[derive(Debug, Clone, Serialize)]
struct ActivationView {
    source: config_command::SourceView,
    #[serde(flatten)]
    report: ActivationReport,
    /// The standing of each guard after the activation. An activation
    /// makes no grant.
    activation_makes_no_grant: bool,
}

#[cfg(unix)]
pub(crate) fn config_apply(
    arguments: &ConfigApplyArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let expected: Option<PolicyRevisionId> = expected_revision(&arguments.expected_revision)?;
    let proposal: Proposal = config_command::load(
        invocation.environment,
        &ProposalOption {
            config: Some(arguments.config.clone()),
        },
        false,
    )?;
    let config: ValidatedConfig = config_command::validated(&proposal)?;
    let registry = registry()?;
    let revision_id: PolicyRevisionId =
        PolicyRevisionId::new(session::new_id("rev")).map_err(|_| session::identity_error())?;
    let now: WallTime = session::record_time()?;

    let mut journal: OperationJournal = open_journal(invocation.environment)?;
    let stored: StoredAuthority = read_authority(&journal)?;
    let request = ActivationRequest {
        principal: session::current_uid(),
        config: &config,
        content: ContentDigest::of_bytes(proposal.text.as_bytes()),
        expected_revision: expected,
        revision_id,
        now,
    };
    let change: Change<ActivationReport> =
        activate(&stored.state, &request, &registry).map_err(|refusal| match refusal {
            ActivationRefusal::WrongPrincipal => wrong_principal(),
            ActivationRefusal::RevisionConflict {
                expected,
                active,
                content_is_active,
            } => revision_conflict(
                expected.as_ref(),
                active.as_ref(),
                if content_is_active {
                    " (the revision in effect has the same content as the proposal, so an earlier request possibly succeeded)"
                } else {
                    ""
                },
            ),
            ActivationRefusal::RevisionIdInUse => session::identity_error(),
            ActivationRefusal::Scope(error) => ErrorBody::new(
                "invalid_configuration",
                ErrorFamily::Request,
                ErrorStage::Input,
                format!(
                    "the configuration has no scope that can be activated: {}; the command made no change",
                    escape(&error.to_string())
                ),
            )
            .with_fields(&["config"]),
        })?;
    // The text of the revision is recorded before the authority record
    // names it, so an agent never reads a revision with no text.
    if change.needs_persistence() && !change.report.unchanged {
        journal
            .record_policy_revision(&change.report.revision, Some(&proposal.text))
            .map_err(|error| not_persisted(&error, false))?;
    }
    let (acknowledged, record_changed) = persist(&mut journal, &stored, change, now)?;
    let acknowledged = Acknowledged {
        level: acknowledged.level,
        state: acknowledged.state,
        inhibition: acknowledged.inhibition,
        report: ActivationView {
            source: proposal.source,
            report: acknowledged.report,
            activation_makes_no_grant: true,
        },
    };
    emit_control("config apply", acknowledged, record_changed, invocation)
}

#[cfg(not(unix))]
pub(crate) fn config_apply(
    _arguments: &ConfigApplyArgs,
    _invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    Err(crate::host::unsupported_platform("config apply").into())
}

fn class_names(classes: &[ActionClass]) -> String {
    if classes.is_empty() {
        return "none".to_owned();
    }
    classes
        .iter()
        .map(ActionClass::as_str)
        .collect::<Vec<&str>>()
        .join(", ")
}

/// The action classes that the flags of `policy enable` accept. Enabling
/// the memory guard accepts the request for an application exit; a force
/// quit needs its own flag.
fn accepted_classes(arguments: &PolicyEnableArgs) -> Vec<ActionClass> {
    let mut acceptances: Vec<Acceptance> = Vec::new();
    if arguments.accept_permanent_eviction {
        acceptances.push(Acceptance::PermanentEviction);
    }
    if arguments.accept_force_quit {
        acceptances.push(Acceptance::ForceQuit);
    } else if arguments.policy.policy == PolicyName::MemoryGuard {
        acceptances.push(Acceptance::ApplicationExit);
    }
    Acceptance::classes_of(&acceptances)
}

fn enable_refusal(refusal: EnableRefusal) -> ErrorBody {
    let authority = |code: &'static str, message: String| {
        ErrorBody::new(code, ErrorFamily::Authority, ErrorStage::Admission, message)
    };
    match refusal {
        EnableRefusal::WrongPrincipal => wrong_principal(),
        EnableRefusal::NoActiveRevision => session::no_active_revision(),
        EnableRefusal::ReviewedRevisionRequired => authority(
            "reviewed_revision_required",
            "a request with no terminal must name the revision that was reviewed: give `--expected-revision POLICY_REVISION`; the command made no change".to_owned(),
        )
        .with_fields(&["expected_revision"]),
        EnableRefusal::RevisionConflict { reviewed, active } => {
            revision_conflict(Some(&reviewed), Some(&active), "")
        }
        EnableRefusal::ObserveProfile => authority(
            "observe_profile",
            "the profile of the revision in effect is `observe`, which permits no intervention; activate a configuration with a different profile; the command made no change".to_owned(),
        ),
        EnableRefusal::GuardNotRequested => authority(
            "guard_not_requested",
            "the revision in effect does not request this guard (`enabled = false` in its table); activate a configuration that requests it; the command made no change".to_owned(),
        ),
        EnableRefusal::AcceptanceMismatch { missing, excess } => authority(
            "acceptance_mismatch",
            format!(
                "the accepted action classes do not agree with the revision in effect: not accepted: {}; accepted but not in the policy: {}; `--accept-permanent-eviction` accepts EvictRegenerableData, and `--accept-force-quit` accepts ForceApplicationExit; the command made no change",
                class_names(&missing),
                class_names(&excess)
            ),
        )
        .with_fields(&["accept_permanent_eviction", "accept_force_quit"]),
        EnableRefusal::GrantIdInUse => session::identity_error(),
    }
}

/// The report of `policy enable`.
#[derive(Debug, Clone, Serialize)]
struct EnableView {
    #[serde(flatten)]
    report: EnableReport,
    standing: GuardStanding,
}

pub(crate) fn policy_enable(
    arguments: &PolicyEnableArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let policy: PolicyId = policy_id(arguments.policy.policy);
    let reviewed: Option<PolicyRevisionId> = match &arguments.expected_revision {
        Some(text) => expected_revision(text)?,
        None => None,
    };
    let accepted: Vec<ActionClass> = accepted_classes(arguments);
    let now: WallTime = session::record_time()?;
    // A guard is enabled only for a revision in effect, which a journal
    // records. With no journal, the command makes none.
    let mut journal: OperationJournal = session::open_existing_journal(invocation.environment)?
        .ok_or_else(session::no_active_revision)?;
    let stored: StoredAuthority = read_authority(&journal)?;
    let active: PolicyRevisionId = stored
        .state
        .active
        .as_ref()
        .map(|active| active.revision.revision_id.clone())
        .ok_or_else(session::no_active_revision)?;

    // `--expected-revision none` expects no revision in effect, and a
    // guard is enabled only for a revision in effect.
    if reviewed.is_none() && arguments.expected_revision.is_some() {
        return Err(revision_conflict(None, Some(&active), "").into());
    }
    // With no named revision, an interactive user reviews the revision in
    // effect and the action classes here. The request then binds the
    // revision that the question showed. `persist` writes the record only
    // when it is still the record that was read before the question, so a
    // revision that became active in the meantime is not bound. With no
    // terminal, the request names no revision, and the grant logic refuses
    // it.
    let reviewed: Option<PolicyRevisionId> = if arguments.expected_revision.is_some() {
        reviewed
    } else {
        let question: String = format!(
            "Enable {} for revision {} with the standing action classes: {}?\nEligible incidents then proceed with no further question.",
            policy.as_str(),
            active,
            class_names(&accepted)
        );
        match invocation
            .environment
            .seams
            .confirm(invocation.stderr, &question)
        {
            Confirmation::Approved => Some(active.clone()),
            Confirmation::Declined => {
                return Err(ErrorBody::new(
                    "approval_declined",
                    ErrorFamily::Authority,
                    ErrorStage::Admission,
                    "the request was not approved; the command made no change",
                )
                .with_next_action(NextAction::None)
                .into());
            }
            Confirmation::NotInteractive => None,
        }
    };
    let request = EnableRequest {
        principal: session::current_uid(),
        policy,
        accepted,
        reviewed_revision: reviewed,
        grant_id: ActionGrantId::new(session::new_id("grant"))
            .map_err(|_| session::identity_error())?,
        now,
    };
    let change: Change<EnableReport> =
        enable(&stored.state, &InstanceInhibition::default(), &request).map_err(enable_refusal)?;
    let (acknowledged, record_changed) = persist(&mut journal, &stored, change, now)?;
    // The grant generation is also in the revision store, for history.
    if record_changed
        && let Some(grant) = acknowledged
            .state
            .guard(policy)
            .and_then(|guard| guard.grant.as_ref())
        && journal.record_action_grant(grant).is_err()
    {
        invocation.warnings.push(crate::output::Warning {
            code: "grant_history_not_recorded".into(),
            message: "the grant is in effect, but its history record was not written".to_owned(),
        });
    }
    let standing: GuardStanding = guard_standing(
        &acknowledged.state,
        &InstanceInhibition::default(),
        policy,
        now,
    );
    let acknowledged = Acknowledged {
        level: acknowledged.level,
        state: acknowledged.state,
        inhibition: acknowledged.inhibition,
        report: EnableView {
            report: acknowledged.report,
            standing,
        },
    };
    emit_control("policy enable", acknowledged, record_changed, invocation)
}

pub(crate) fn policy_disable(
    arguments: &PolicyRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let now: WallTime = session::record_time()?;
    let mut journal: OperationJournal = open_journal(invocation.environment)?;
    let stored: StoredAuthority = read_authority(&journal)?;
    let change: Change<RestrictionReport> = disable(
        &stored.state,
        &DisableRequest {
            principal: session::current_uid(),
            policy: policy_id(arguments.policy),
        },
    )
    .map_err(|refusal| match refusal {
        ControlRefusal::WrongPrincipal => wrong_principal(),
        ControlRefusal::UnknownGrant { .. } => ErrorBody::new(
            "disable_refused",
            ErrorFamily::Authority,
            ErrorStage::Admission,
            "the request was refused; the command made no change",
        ),
    })?;
    let (acknowledged, record_changed) = persist(&mut journal, &stored, change, now)?;
    emit_control("policy disable", acknowledged, record_changed, invocation)
}

/// `policy rearm`: this build has no channel that gives a new budget
/// generation to the controller of the agent, so the command validates its
/// arguments and reports the missing capability.
pub(crate) fn policy_rearm(
    arguments: &PolicyRearmArgs,
    _invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    IncidentId::new(arguments.incident.as_str()).map_err(|_| {
        session::invalid_identifier("invalid_incident", "incident ID", &["incident"])
    })?;
    arguments.generation.parse::<u64>().map_err(|_| {
        ErrorBody::new(
            "invalid_generation",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the generation is not a decimal number; use the generation that `svalnir agent status` shows for the incident",
        )
        .with_fields(&["generation"])
    })?;
    Err(ErrorBody::new(
        "rearm_not_available",
        ErrorFamily::Native,
        ErrorStage::Dispatch,
        format!(
            "`svalnir policy rearm {}` is not available in this build: the incident budgets are in the controller record of the agent, and this build has no request that gives the agent a new budget generation; the command made no change",
            policy_id(arguments.policy.policy).as_str()
        ),
    )
    .with_next_action(NextAction::None)
    .into())
}

/// The report of `agent pause`.
#[derive(Debug, Clone, Serialize)]
struct PauseView {
    #[serde(flatten)]
    report: PauseReport,
    status: PauseStatus,
    /// What a pause does and does not do.
    effect: &'static str,
}

const PAUSE_EFFECT: &str = "A pause stops new automatic interventions. It does not stop an admitted operation, recall an issued call, or stop observation; a manual plan is not affected.";

fn nanoseconds(duration: Duration) -> Result<Nanoseconds, ErrorBody> {
    Nanoseconds::try_from(duration).map_err(|_| {
        ErrorBody::new(
            "invalid_duration",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the duration is too long",
        )
        .with_fields(&["for"])
    })
}

pub(crate) fn agent_pause(
    arguments: &AgentPauseArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let duration: Option<Nanoseconds> = arguments.duration.map(nanoseconds).transpose()?;
    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = open_journal(invocation.environment)?;
    let stored: StoredAuthority = read_authority(&journal)?;
    let change: Change<PauseReport> = pause(
        &stored.state,
        &PauseRequest {
            principal: session::current_uid(),
            duration,
        },
        &now.control(),
    )
    .map_err(|refusal| match refusal {
        svalnir_core::grant::PauseRefusal::WrongPrincipal => wrong_principal(),
        _ => ErrorBody::new(
            "invalid_duration",
            ErrorFamily::Request,
            ErrorStage::Arguments,
            "the pause duration is zero or its end is out of range; the command made no change",
        )
        .with_fields(&["for"]),
    })?;
    let (acknowledged, record_changed) = persist(&mut journal, &stored, change, now.wall)?;
    let status: PauseStatus = pause_status(acknowledged.state.pause.as_ref(), &now.control());
    let acknowledged = Acknowledged {
        level: acknowledged.level,
        state: acknowledged.state,
        inhibition: acknowledged.inhibition,
        report: PauseView {
            report: acknowledged.report,
            status,
            effect: PAUSE_EFFECT,
        },
    };
    emit_control("agent pause", acknowledged, record_changed, invocation)
}

/// The report of `agent resume`.
#[derive(Debug, Clone, Serialize)]
struct ResumeView {
    #[serde(flatten)]
    report: ResumeReport,
    status: PauseStatus,
    effect: &'static str,
}

const RESUME_EFFECT: &str = "A resume ends the pause. The agent makes new measurements before an automatic intervention; a measurement of before the resume supports none.";

pub(crate) fn agent_resume(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let host: Host = Host::open()?;
    let now: Now = Now::read(&host)?;
    let mut journal: OperationJournal = open_journal(invocation.environment)?;
    let stored: StoredAuthority = read_authority(&journal)?;
    let change: Change<ResumeReport> = resume(
        &stored.state,
        &InstanceInhibition::default(),
        &ResumeRequest {
            principal: session::current_uid(),
        },
        &now.control(),
    )
    .map_err(|_| wrong_principal())?;
    let (acknowledged, record_changed) = persist(&mut journal, &stored, change, now.wall)?;
    let status: PauseStatus = pause_status(acknowledged.state.pause.as_ref(), &now.control());
    let acknowledged = Acknowledged {
        level: acknowledged.level,
        state: acknowledged.state,
        inhibition: acknowledged.inhibition,
        report: ResumeView {
            report: acknowledged.report,
            status,
            effect: RESUME_EFFECT,
        },
    };
    emit_control("agent resume", acknowledged, record_changed, invocation)
}

/// The standing of one guard, for a status view.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct GuardView {
    pub(crate) policy: &'static str,
    pub(crate) standing: GuardStanding,
    pub(crate) grant: Option<ActionGrantRef>,
}

/// The authority record as a status view.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuthorityView {
    /// The revision in effect.
    pub(crate) active_revision: Option<PolicyRevisionId>,
    pub(crate) activated_at: Option<WallTime>,
    pub(crate) guards: Vec<GuardView>,
    /// The pause, when the clocks of this host gave a value.
    pub(crate) pause: Option<PauseStatus>,
}

impl AuthorityView {
    pub(crate) fn new(state: &AuthorityState, now: Option<&Now>) -> Self {
        let wall: WallTime = now.map_or_else(session::wall_now, |now| now.wall);
        Self {
            active_revision: state
                .active
                .as_ref()
                .map(|active| active.revision.revision_id.clone()),
            activated_at: state
                .active
                .as_ref()
                .map(|active| active.revision.activated_at),
            guards: PolicyId::ALL
                .iter()
                .map(|policy| GuardView {
                    policy: policy.as_str(),
                    standing: guard_standing(state, &InstanceInhibition::default(), *policy, wall),
                    grant: state
                        .guard(*policy)
                        .and_then(|guard| guard.grant.as_ref())
                        .map(svalnir_core::authority::ActionGrant::reference),
                })
                .collect(),
            pause: now.map(|now| pause_status(state.pause.as_ref(), &now.control())),
        }
    }

    /// Whether a guard can act now.
    pub(crate) fn any_guard_active(&self) -> bool {
        self.guards
            .iter()
            .any(|guard| guard.standing == GuardStanding::Active)
    }

    pub(crate) fn render(&self, out: &mut String) {
        put_line!(
            out,
            "  Revision in effect: {}",
            self.active_revision
                .as_ref()
                .map_or_else(|| "none".to_owned(), ToString::to_string)
        );
        for guard in &self.guards {
            let standing: String = serde_json::to_value(guard.standing)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned());
            put_line!(out, "  {}: {standing}", guard.policy);
        }
        let pause: String = match &self.pause {
            None => "not known (no clock value)".to_owned(),
            Some(PauseStatus::NotPaused) => "not paused".to_owned(),
            Some(PauseStatus::Paused { until, .. }) => until.map_or_else(
                || "paused until `svalnir agent resume`".to_owned(),
                |until| format!("paused until {until}"),
            ),
            Some(PauseStatus::Expired { .. }) => "pause expired".to_owned(),
        };
        put_line!(out, "  Automatic interventions: {pause}");
    }
}

#[cfg(test)]
mod tests {
    use super::{NO_REVISION, expected_revision};

    #[test]
    fn the_text_none_expects_no_revision() {
        assert_eq!(expected_revision(NO_REVISION).unwrap(), None);
        assert_eq!(
            expected_revision("rev_1").unwrap().unwrap().as_str(),
            "rev_1"
        );
        let error = expected_revision("not valid").unwrap_err();
        assert_eq!(&*error.code, "invalid_revision");
        assert_eq!(error.exit_status().code(), 2);
    }
}
