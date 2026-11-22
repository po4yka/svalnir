//! The live path of an action: the operation journal of the state
//! directory, through `svalnir_agent::client`.
//!
//! Each action first checks that `HOME` is the home directory of the
//! account record. A request of the queue also needs the agent that holds
//! the coordinator lock; a change of the authority record is written with
//! no agent too, as the CLI does. A request of the queue opens the existing
//! journal for writes and never makes the state directory or the journal.
//! A pause, a resume, and a disable make them when they do not exist,
//! through `client::create_state_directory`, as the CLI does. No action
//! takes the coordinator lock.

use super::{
    ADMISSION_GRACE, Action, ActionPort, ActionState, AuthorityPath, StopProposal, StopTarget,
    UNEXPECTED_COMPLETION, Unavailable,
    cleanup::{CleanupProposal, CleanupRequest, CleanupSnapshot},
    live_cleanup,
};
use crate::data::{live_records::collect_processes, model::OperationPhase};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use svalnir_agent::{
    client::{
        self, ActiveConfig, ActiveConfigError, AgentPresence, ManualStopError, ManualStopPlan,
        StateDirectoryError, StopMode, WaitError,
    },
    journal::{
        JournalOptions, OperationJournal, OperationJournalError, QueuedRequest, RequestBody,
        RequestCompletion, RequestStatus,
    },
    observe::{self, AuthorityReadError, Host, StoredAuthority},
    platform::{
        account::verify_process_home,
        process::{ProcessRecord, ProcessSnapshot, control_plane_of_this_process},
    },
    rules::ReviewedRules,
    runtime::journal_path,
};
use svalnir_core::{
    action::{ClientRole, Plan, PlanApproval},
    authority::Generation,
    file::LosslessPath,
    grant::{
        Acknowledged, Change, ControlClock, ControlRefusal, DisableRequest, EnableRefusal,
        EnableRequest, InstanceInhibition, PauseRefusal, PauseRequest, ResumeRequest, disable,
        enable, pause, resume,
    },
    id::{
        ActionGrantId, ApplicationInstanceId, IncidentId, OperationId, PolicyRevisionId, RequestId,
    },
    plan::check_expiry,
    policy::{ApplicationCandidate, EvaluationClock, PolicyId, ProtectionContext, ProtectionFact},
    process::ProcessIdentity,
    quantity::Nanoseconds,
    time::WallTime,
};

/// The longest wait for the agent to decide a queued request.
const DECISION_WAIT: Duration = Duration::from_secs(30);

/// The wait for the agent to admit a stop plan before the window follows
/// the request at each poll.
const ADMISSION_WAIT: Duration = Duration::from_secs(10);

/// The journal of the state directory.
#[derive(Debug)]
pub struct LivePort {
    state_directory: Option<PathBuf>,
    /// The home directory and the process evidence of the cleanup rules.
    environment: live_cleanup::LiveEnvironment,
    admission_wait: Duration,
    /// The rule registry of a test. `None`: the registry of this build, in
    /// which each layout has the lifecycle state of its declaration.
    registry: Option<ReviewedRules>,
}

impl LivePort {
    /// Creates the port for the journal of `state_directory`.
    #[must_use]
    pub fn new(state_directory: Option<PathBuf>) -> Self {
        Self {
            state_directory,
            environment: live_cleanup::LiveEnvironment::host(),
            admission_wait: ADMISSION_WAIT,
            registry: None,
        }
    }

    /// The port with the rule registry `registry`, for a test that gives a
    /// rule a fixture lifecycle state.
    #[cfg(test)]
    fn with_registry(mut self, registry: ReviewedRules) -> Self {
        self.registry = Some(registry);
        self
    }

    /// The rule registry: the registry of the test, else the registry of
    /// this build.
    fn registry(&self) -> Result<ReviewedRules, ActionState> {
        match &self.registry {
            Some(registry) => Ok(registry.clone()),
            None => {
                ReviewedRules::new().map_err(|_| ActionState::refused("rule_registry_unavailable"))
            }
        }
    }

    /// Records the confirmed cleanup plan and sends it to the agent, as a
    /// stop is sent.
    fn clean(&self, proposal: &CleanupProposal) -> Result<ActionState, ActionState> {
        let plan: &Plan = proposal
            .plan
            .as_deref()
            .ok_or_else(|| ActionState::refused("plan_not_buildable"))?;
        let path: PathBuf = self.gate()?;
        let (clock, _) = clocks()?;
        if check_expiry(plan, &clock).is_err() {
            return Err(ActionState::refused("plan_expired"));
        }
        let remaining: Duration = Duration::from_nanos(
            plan.validity
                .expires_at
                .get()
                .saturating_sub(clock.now.get()),
        );
        let mut journal: OperationJournal = open_for_writes(&path)?;
        journal
            .try_record_plan(plan)
            .map_err(|error| journal_refusal(&error))?;
        let approval = PlanApproval {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest().clone(),
        };
        let request_id: RequestId = enqueue(&mut journal, RequestBody::Apply { approval })?;
        let since: Instant = Instant::now();
        match client::wait_for_completion(&journal, &path, &request_id, self.admission_wait) {
            Ok(completion) => Ok(match admission_of(completion, Instant::now()) {
                ActionState::WaitingForExit { operation, since } => {
                    ActionState::Running { operation, since }
                }
                other => other,
            }),
            Err(WaitError::Pending | WaitError::CoordinatorStopped | WaitError::Journal(_)) => {
                Ok(ActionState::AwaitingAdmission {
                    request: request_id.to_string(),
                    since,
                    until: since
                        .checked_add(remaining.saturating_add(ADMISSION_GRACE))
                        .unwrap_or(since),
                })
            }
        }
    }

    /// The port with a different wait for the admission of a stop, for the
    /// tests.
    #[cfg(test)]
    const fn with_admission_wait(mut self, wait: Duration) -> Self {
        self.admission_wait = wait;
        self
    }

    /// The journal path, when the agent holds the lock of its journal and
    /// `HOME` is the home directory of the account record.
    fn gate(&self) -> Result<PathBuf, ActionState> {
        let directory: &Path = self
            .state_directory
            .as_deref()
            .ok_or(ActionState::Unavailable(Unavailable::NoStateDirectory))?;
        let path: PathBuf = journal_path(directory);
        gate_presence(client::agent_presence(&path))?;
        verify_process_home().map_err(|error| {
            ActionState::Unavailable(Unavailable::Home(capitalized(&error.to_string())))
        })?;
        Ok(path)
    }

    /// The journal path and the path of an authority change, when `HOME` is
    /// the home directory of the account record. The CLI writes the
    /// authority record with no agent too, so the presence of the agent
    /// does not gate the write; it only names the path.
    fn authority_gate(&self) -> Result<(PathBuf, AuthorityPath), ActionState> {
        let directory: &Path = self
            .state_directory
            .as_deref()
            .ok_or(ActionState::Unavailable(Unavailable::NoStateDirectory))?;
        let path: PathBuf = journal_path(directory);
        verify_process_home().map_err(|error| {
            ActionState::Unavailable(Unavailable::Home(capitalized(&error.to_string())))
        })?;
        let route: AuthorityPath = match client::agent_presence(&path) {
            AgentPresence::Agent => AuthorityPath::Agent,
            AgentPresence::Absent => AuthorityPath::NoAgent,
            AgentPresence::OtherCoordinator => AuthorityPath::OtherCoordinator,
            AgentPresence::Unknown => AuthorityPath::Unknown,
        };
        Ok((path, route))
    }

    /// Writes a pause, a resume, or an enable or disable of a guard to the
    /// authority record, as `svalnir agent pause`, `agent resume`,
    /// `policy enable`, and `policy disable` do: the change of the pure
    /// grant logic, then the compare-and-set write of
    /// `client::write_authority`. Neither client takes a lock for it; the
    /// compare-and-set refuses a record that a different process changed
    /// after the read.
    ///
    /// As the CLI does, a pause, a resume, and a disable make the state
    /// directory (`client::create_state_directory`) and the journal when
    /// they do not exist. An enable needs a revision in effect, which only a
    /// journal records, so with no journal it is refused and makes nothing.
    fn authority_action(path: &Path, action: &Action) -> Result<(ActionState, bool), ActionState> {
        let mut journal: OperationJournal = open_for_authority(path, action)?;
        let stored: StoredAuthority = read_authority(&journal)?;
        let (clock, wall) = clocks()?;
        let control = ControlClock {
            clock: &clock,
            wall,
        };
        let principal = observe::current_uid();
        match action {
            Action::Pause { duration } => {
                let duration: Option<Nanoseconds> = duration
                    .map(Nanoseconds::try_from)
                    .transpose()
                    .map_err(|_| ActionState::refused("invalid_duration"))?;
                let change = pause(
                    &stored.state,
                    &PauseRequest {
                        principal,
                        duration,
                    },
                    &control,
                )
                .map_err(|refusal| match refusal {
                    PauseRefusal::WrongPrincipal => ActionState::refused("wrong_principal"),
                    _ => ActionState::refused("invalid_duration"),
                })?;
                let detail: String = pause_detail(duration.is_some());
                write(&mut journal, &stored, change, wall)
                    .map(|(_, written)| (accepted(detail), written))
            }
            Action::Resume => {
                let change = resume(
                    &stored.state,
                    &InstanceInhibition::default(),
                    &ResumeRequest { principal },
                    &control,
                )
                .map_err(|_| ActionState::refused("wrong_principal"))?;
                write(&mut journal, &stored, change, wall).map(|(_, written)| {
                    (accepted("The pause ended. The agent makes new measurements before an automatic intervention.".to_owned()), written)
                })
            }
            Action::Enable {
                policy,
                revision,
                classes,
            } => {
                let revision: PolicyRevisionId = PolicyRevisionId::new(revision.as_str())
                    .map_err(|_| ActionState::refused("revision_conflict"))?;
                let request = EnableRequest {
                    principal,
                    policy: *policy,
                    accepted: classes.clone(),
                    reviewed_revision: Some(revision),
                    grant_id: ActionGrantId::new(client::new_id("grant"))
                        .map_err(|_| ActionState::refused("identity_unavailable"))?,
                    now: wall,
                };
                let change = enable(&stored.state, &InstanceInhibition::default(), &request)
                    .map_err(|refusal| ActionState::refused(enable_code(&refusal)))?;
                let (acknowledged, written) = write(&mut journal, &stored, change, wall)?;
                let mut detail: String = format!(
                    "The {} is enabled for its revision. An eligible incident then proceeds with no further question.",
                    policy_label(*policy)
                );
                // The grant generation is also in the revision store, for
                // history.
                if written
                    && let Some(grant) = acknowledged
                        .state
                        .guard(*policy)
                        .and_then(|guard| guard.grant.as_ref())
                    && journal.record_action_grant(grant).is_err()
                {
                    detail.push_str(" The history record of the grant was not written.");
                }
                Ok((accepted(detail), written))
            }
            Action::Disable { policy } => {
                let change = disable(
                    &stored.state,
                    &DisableRequest {
                        principal,
                        policy: *policy,
                    },
                )
                .map_err(|refusal| match refusal {
                    ControlRefusal::WrongPrincipal => ActionState::refused("wrong_principal"),
                    ControlRefusal::UnknownGrant { .. } => ActionState::refused("disable_refused"),
                })?;
                write(&mut journal, &stored, change, wall).map(|(_, written)| {
                    (
                        accepted(format!(
                            "The {} is disabled. It starts no new automatic intervention.",
                            policy_label(*policy)
                        )),
                        written,
                    )
                })
            }
            _ => Err(ActionState::refused(UNEXPECTED_COMPLETION)),
        }
    }

    fn queued_action(&self, action: &Action) -> Result<ActionState, ActionState> {
        match action {
            Action::Rearm {
                policy,
                incident,
                generation,
            } => {
                let incident_id: IncidentId = IncidentId::new(incident.as_str())
                    .map_err(|_| ActionState::refused("operation_not_found"))?;
                let body = RequestBody::Rearm {
                    policy: *policy,
                    incident_id,
                    generation: Generation::new(*generation),
                };
                let completion: RequestCompletion = self.send(body, DECISION_WAIT)?;
                Ok(match completion {
                    RequestCompletion::Rearmed { new_generation, .. } => accepted(format!(
                        "The agent recorded budget generation {new_generation} for incident {incident}. The usage of the earlier generation stays in the history."
                    )),
                    _ => ActionState::refused(UNEXPECTED_COMPLETION),
                })
            }
            Action::Cancel { operation } => {
                let body = RequestBody::Cancel {
                    operation_id: operation_id(operation)?,
                };
                let completion: RequestCompletion = self.send(body, DECISION_WAIT)?;
                Ok(match completion {
                    RequestCompletion::Stopped { .. } => {
                        accepted(super::CANCEL_ACCEPTED.to_owned())
                    }
                    _ => ActionState::refused(UNEXPECTED_COMPLETION),
                })
            }
            Action::Acknowledge { operation } => {
                let body = RequestBody::Acknowledge {
                    operation_id: operation_id(operation)?,
                };
                let completion: RequestCompletion = self.send(body, DECISION_WAIT)?;
                Ok(match completion {
                    RequestCompletion::Acknowledged { repeated, .. } => accepted(if repeated {
                        "The acknowledgment was recorded before. This request changed nothing."
                            .to_owned()
                    } else {
                        "The acknowledgment is recorded, and the leases of the operation are released. The outcome stays unknown."
                            .to_owned()
                    }),
                    _ => ActionState::refused(UNEXPECTED_COMPLETION),
                })
            }
            Action::Stop { proposal, force } => self.stop(proposal, *force),
            Action::Clean { proposal } => self.clean(proposal),
            _ => Err(ActionState::refused(UNEXPECTED_COMPLETION)),
        }
    }

    /// Records the confirmed plan and sends it to the agent.
    fn stop(&self, proposal: &StopProposal, force: bool) -> Result<ActionState, ActionState> {
        let plan: &Plan = if force {
            proposal.force.as_deref()
        } else {
            proposal.quit.as_deref()
        }
        .ok_or_else(|| ActionState::refused("plan_not_buildable"))?;
        let path: PathBuf = self.gate()?;
        // A plan that expired while the confirmation was open is not sent.
        let (clock, _) = clocks()?;
        if check_expiry(plan, &clock).is_err() {
            return Err(ActionState::refused("plan_expired"));
        }
        // The rest of the plan lifetime on the clock of the plan, read now,
        // so that the bound of the wait does not depend on the wall clock.
        let remaining: Duration = Duration::from_nanos(
            plan.validity
                .expires_at
                .get()
                .saturating_sub(clock.now.get()),
        );
        let mut journal: OperationJournal = open_for_writes(&path)?;
        journal
            .try_record_plan(plan)
            .map_err(|error| journal_refusal(&error))?;
        let approval = PlanApproval {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest().clone(),
        };
        let request_id: RequestId = enqueue(&mut journal, RequestBody::Apply { approval })?;
        let since: Instant = Instant::now();
        match client::wait_for_completion(&journal, &path, &request_id, self.admission_wait) {
            Ok(completion) => Ok(admission_of(completion, Instant::now())),
            // The agent can admit the plan later, until it expires, so the
            // window follows the request at each poll until then.
            // A read of the queue that failed after the write does not show
            // that nothing changed: the request is in the queue.
            Err(WaitError::Pending | WaitError::CoordinatorStopped | WaitError::Journal(_)) => {
                Ok(ActionState::AwaitingAdmission {
                    request: request_id.to_string(),
                    since,
                    until: since
                        .checked_add(remaining.saturating_add(ADMISSION_GRACE))
                        .unwrap_or(since),
                })
            }
        }
    }

    /// Writes `body` to the queue and waits for its completion.
    fn send(&self, body: RequestBody, wait: Duration) -> Result<RequestCompletion, ActionState> {
        let path: PathBuf = self.gate()?;
        let mut journal: OperationJournal = open_for_writes(&path)?;
        send_on(&mut journal, &path, body, wait)
    }
}

impl ActionPort for LivePort {
    fn submit(&self, action: &Action) -> ActionState {
        let result = match action {
            Action::Pause { .. }
            | Action::Resume
            | Action::Enable { .. }
            | Action::Disable { .. } => self.authority_gate().and_then(|(path, route)| {
                Self::authority_action(&path, action)
                    .map(|(state, written)| route.annotate(state, written))
            }),
            _ => self.queued_action(action),
        };
        result.unwrap_or_else(|state| state)
    }

    fn prepare_stop(&self, instance: &str, name: &str) -> Result<StopProposal, ActionState> {
        let path: PathBuf = self.gate()?;
        let journal: OperationJournal = match observe::open_existing_journal_read_only(&path) {
            Ok(Some(journal)) => journal,
            Ok(None) => return Err(ActionState::Unavailable(Unavailable::NoJournal)),
            Err(_) => return Err(ActionState::refused("journal_unavailable")),
        };
        let stored: StoredAuthority = read_authority(&journal)?;
        let ActiveConfig { active, config } = client::active_config(&journal, &stored.state)
            .map_err(|error| match error {
                ActiveConfigError::NoActiveRevision => {
                    ActionState::refused("no_active_policy_revision")
                }
                ActiveConfigError::Journal(error) => journal_refusal(&error),
                ActiveConfigError::SourceNotUsable => {
                    ActionState::refused("policy_revision_source_not_usable")
                }
            })?;
        drop(journal);
        let host: Host = Host::open().map_err(|_| ActionState::Unavailable(Unavailable::Clock))?;
        let (clock, wall) = clocks_of(&host)?;
        let snapshot: ProcessSnapshot = collect_processes(&host)
            .map_err(|_| ActionState::refused("process_reading_unavailable"))?;
        let control_plane = control_plane_of_this_process(&snapshot);
        let protection = ProtectionContext {
            principal: observe::current_uid(),
            control_plane: control_plane.as_deref(),
        };
        // The candidate and the plan come from the functions that the CLI
        // uses, so both clients bind the same processes in the same way.
        let instance_id: ApplicationInstanceId = ApplicationInstanceId::new(instance)
            .map_err(|_| ActionState::refused("group_not_found"))?;
        let candidate: ApplicationCandidate =
            client::group_candidate(&snapshot, &protection, &instance_id)
                .ok_or_else(|| ActionState::refused("group_not_found"))?;
        match candidate.hard_protection {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => return Err(ActionState::refused("target_protected")),
            ProtectionFact::Unknown => {
                return Err(ActionState::refused("target_protection_unknown"));
            }
        }
        let home = std::env::var_os("HOME")
            .and_then(|home| std::fs::canonicalize(home).ok())
            .and_then(|home| LosslessPath::from_path(&home).ok());
        let principal = client::principal(ClientRole::Gui);
        let grace: Nanoseconds = Nanoseconds::try_from(client::DEFAULT_STOP_GRACE)
            .map_err(|_| ActionState::refused("plan_not_buildable"))?;
        let build = |mode: StopMode| -> Result<Arc<Plan>, ActionState> {
            let plan_text: String = client::new_id("plan");
            let (strategy, limits) = client::manual_stop(mode, grace);
            client::build_manual_stop(&ManualStopPlan {
                plan_id: &plan_text,
                principal: &principal,
                active: &active,
                config: &config,
                clock: &clock,
                created_wall: wall,
                home_directory: home.as_ref(),
                candidate: &candidate,
                protection: &protection,
                strategy,
                limits,
            })
            .map_err(|error| match error {
                ManualStopError::Identity => ActionState::refused("identity_unavailable"),
                ManualStopError::Build(_) => ActionState::refused("plan_not_buildable"),
            })?
            .plan
            .map(Arc::new)
            .ok_or_else(|| ActionState::refused("target_not_eligible"))
        };
        let quit: Arc<Plan> = build(StopMode::Graceful)?;
        let force: Arc<Plan> = build(StopMode::ImmediateForce)?;
        // The dialog lists exactly the processes that the sealed plans
        // bind. The two plans come from one reading, so they bind the same
        // processes; plans that do not are not offered.
        let targets: Vec<StopTarget> = plan_targets(&quit, &snapshot);
        if targets.is_empty() || targets != plan_targets(&force, &snapshot) {
            return Err(ActionState::refused("plan_not_buildable"));
        }
        Ok(StopProposal {
            instance: instance.to_owned(),
            name: name.to_owned(),
            targets,
            expires_at: expiry_wall(&quit),
            quit: Some(quit),
            force: Some(force),
        })
    }

    fn admission_state(&self, request: &str) -> Option<ActionState> {
        let directory: &Path = self.state_directory.as_deref()?;
        let journal = observe::open_existing_journal_read_only(&journal_path(directory)).ok()??;
        match journal
            .request_status(&RequestId::new(request).ok()?)
            .ok()??
        {
            RequestStatus::Completed { completion } => {
                Some(admission_of(completion, Instant::now()))
            }
            _ => None,
        }
    }

    fn operation_state(&self, operation: &str) -> Option<(OperationPhase, String)> {
        let directory: &Path = self.state_directory.as_deref()?;
        let journal = observe::open_existing_journal_read_only(&journal_path(directory)).ok()??;
        let operation = journal
            .try_operation(&OperationId::new(operation).ok()?)
            .ok()??;
        Some(OperationPhase::of(operation.state()))
    }

    fn inspect_rules(&self) -> Result<CleanupSnapshot, String> {
        let registry: ReviewedRules = self
            .registry()
            .map_err(|_| "The rule registry of this build is not usable.".to_owned())?;
        live_cleanup::inspect_rules(
            &registry,
            self.state_directory.as_deref(),
            &self.environment,
        )
    }

    fn prepare_cleanup(&self, request: &CleanupRequest) -> Result<CleanupProposal, ActionState> {
        // The checks that read nothing come first, as in the CLI: a
        // `proposed` rule is refused before a directory is read.
        let registry: ReviewedRules = self.registry()?;
        live_cleanup::check_request(&registry, request)?;
        let path: PathBuf = self.gate()?;
        let journal: OperationJournal = match observe::open_existing_journal_read_only(&path) {
            Ok(Some(journal)) => journal,
            Ok(None) => return Err(ActionState::Unavailable(Unavailable::NoJournal)),
            Err(_) => return Err(ActionState::refused("journal_unavailable")),
        };
        let stored: StoredAuthority = read_authority(&journal)?;
        let ActiveConfig { active, config } = client::active_config(&journal, &stored.state)
            .map_err(|error| match error {
                ActiveConfigError::NoActiveRevision => {
                    ActionState::refused("no_active_policy_revision")
                }
                ActiveConfigError::Journal(error) => journal_refusal(&error),
                ActiveConfigError::SourceNotUsable => {
                    ActionState::refused("policy_revision_source_not_usable")
                }
            })?;
        drop(journal);
        let (clock, wall) = clocks()?;
        live_cleanup::build(
            &registry,
            request,
            &live_cleanup::PlanInputs {
                policy_revision: active.revision.revision_id.clone(),
                config,
                clock: &clock,
                wall,
                state_directory: self.state_directory.as_deref(),
                environment: &self.environment,
                cancel: &request.cancel,
            },
        )
    }
}

/// The refusal for an agent that does not hold the lock.
fn gate_presence(presence: AgentPresence) -> Result<(), ActionState> {
    match presence {
        AgentPresence::Agent => Ok(()),
        AgentPresence::Absent => Err(ActionState::Unavailable(Unavailable::NoAgent)),
        AgentPresence::OtherCoordinator => {
            Err(ActionState::Unavailable(Unavailable::OtherCoordinator))
        }
        AgentPresence::Unknown => Err(ActionState::Unavailable(Unavailable::AgentUnknown)),
    }
}

/// The state line of a pause that the authority record has.
fn pause_detail(timed: bool) -> String {
    if timed {
        "The pause is in the authority record. The agent starts no new automatic intervention until the pause ends.".to_owned()
    } else {
        "The pause is in the authority record. The agent starts no new automatic intervention until a resume.".to_owned()
    }
}

fn capitalized(text: &str) -> String {
    let mut characters = text.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(characters).collect()
    })
}

fn accepted(detail: String) -> ActionState {
    ActionState::Accepted { detail }
}

fn open_for_writes(path: &Path) -> Result<OperationJournal, ActionState> {
    match observe::open_existing_journal(path, &JournalOptions::default()) {
        Ok(Some(journal)) => Ok(journal),
        Ok(None) => Err(ActionState::Unavailable(Unavailable::NoJournal)),
        Err(observe::ExistingJournalError::Open(error)) => Err(journal_refusal(&error)),
        Err(_) => Err(ActionState::refused("journal_unavailable")),
    }
}

/// Opens the journal at `path` for the authority change `action`. An enable
/// with no journal is refused as `no_active_policy_revision`, as the CLI
/// refuses it; a different change makes the journal ([`open_or_create`]).
fn open_for_authority(path: &Path, action: &Action) -> Result<OperationJournal, ActionState> {
    if matches!(action, Action::Enable { .. }) {
        match open_for_writes(path) {
            Err(ActionState::Unavailable(Unavailable::NoJournal)) => {
                Err(ActionState::refused("no_active_policy_revision"))
            }
            other => other,
        }
    } else {
        open_or_create(path)
    }
}

/// Opens the journal at `path` for a write of the authority record. Makes
/// the state directory, the parent of `path`, and the journal when they do
/// not exist, through the function that the CLI also calls.
fn open_or_create(path: &Path) -> Result<OperationJournal, ActionState> {
    let directory: &Path = path
        .parent()
        .ok_or(ActionState::Unavailable(Unavailable::NoStateDirectory))?;
    client::create_state_directory(directory).map_err(|error| match error {
        StateDirectoryError::NotWritable(_) => ActionState::refused("state_directory_not_writable"),
        StateDirectoryError::NotPrivate => ActionState::refused("state_directory_not_private"),
    })?;
    OperationJournal::open(path, &JournalOptions::default())
        .map_err(|error| journal_refusal(&error))
}

fn read_authority(journal: &OperationJournal) -> Result<StoredAuthority, ActionState> {
    observe::read_authority(journal, observe::current_uid()).map_err(|error| match error {
        AuthorityReadError::DifferentUser => ActionState::refused("wrong_principal"),
        AuthorityReadError::Journal(OperationJournalError::Decode { .. }) => {
            ActionState::refused("authority_record_not_readable")
        }
        AuthorityReadError::Journal(error) => journal_refusal(&error),
    })
}

fn clocks() -> Result<(EvaluationClock, WallTime), ActionState> {
    let host: Host = Host::open().map_err(|_| ActionState::Unavailable(Unavailable::Clock))?;
    clocks_of(&host)
}

fn clocks_of(host: &Host) -> Result<(EvaluationClock, WallTime), ActionState> {
    client::control_time(host.context()).map_err(|_| ActionState::Unavailable(Unavailable::Clock))
}

fn write<R>(
    journal: &mut OperationJournal,
    stored: &StoredAuthority,
    change: Change<R>,
    wall: WallTime,
) -> Result<(Acknowledged<R>, bool), ActionState> {
    client::write_authority(journal, stored, change, wall).map_err(|error| match error {
        OperationJournalError::Conflict => ActionState::refused("authority_record_changed"),
        other => journal_refusal(&other),
    })
}

/// Writes `body` to the queue of `journal` and gives the identity of the
/// request.
fn enqueue(journal: &mut OperationJournal, body: RequestBody) -> Result<RequestId, ActionState> {
    let request = QueuedRequest {
        request_id: RequestId::new(client::new_id("gui-request"))
            .map_err(|_| ActionState::refused("identity_unavailable"))?,
        principal: client::principal(ClientRole::Gui),
        body,
        enqueued_at: WallTime::try_from(SystemTime::now())
            .map_err(|_| ActionState::Unavailable(Unavailable::Clock))?,
    };
    journal
        .enqueue_request(&request)
        .map_err(|error| journal_refusal(&error))?;
    Ok(request.request_id)
}

/// Writes `body` to the queue of `journal` and waits for its completion.
/// A rejection is a refusal with the code of the coordinator. After the
/// write, a wait with no answer is [`ActionState::Queued`] and never a
/// refusal: the request is in the queue, and the agent can still decide it.
fn send_on(
    journal: &mut OperationJournal,
    path: &Path,
    body: RequestBody,
    wait: Duration,
) -> Result<RequestCompletion, ActionState> {
    let request_id: RequestId = enqueue(journal, body)?;
    answer_of(client::wait_for_completion(
        journal,
        path,
        &request_id,
        wait,
    ))
}

/// The answer to a request that is in the queue: a rejection is a refusal,
/// and a wait that read no completion is [`ActionState::Queued`].
fn answer_of(wait: Result<RequestCompletion, WaitError>) -> Result<RequestCompletion, ActionState> {
    match wait {
        Ok(RequestCompletion::Rejected { error }) => Err(ActionState::refused(error.code.as_str())),
        Ok(completion) => Ok(completion),
        Err(WaitError::Pending | WaitError::CoordinatorStopped | WaitError::Journal(_)) => {
            Err(ActionState::Queued)
        }
    }
}

/// The state of a stop after the completion of its apply request at `now`.
fn admission_of(completion: RequestCompletion, now: Instant) -> ActionState {
    match completion {
        RequestCompletion::Operation { operation_id } => ActionState::WaitingForExit {
            operation: operation_id.to_string(),
            since: now,
        },
        RequestCompletion::Rejected { error } => ActionState::refused(error.code.as_str()),
        _ => ActionState::refused(UNEXPECTED_COMPLETION),
    }
}

/// The refusal of a journal failure.
fn journal_refusal(error: &OperationJournalError) -> ActionState {
    ActionState::refused(match error {
        OperationJournalError::Busy(_) => "journal_busy",
        OperationJournalError::QueueFull { .. } => "queue_full",
        OperationJournalError::AdmissionStopped(_) | OperationJournalError::Full(_) => {
            "journal_full"
        }
        OperationJournalError::Conflict => "journal_conflict",
        OperationJournalError::NotFound => "operation_not_found",
        _ => "journal_unavailable",
    })
}

const fn enable_code(refusal: &EnableRefusal) -> &'static str {
    match refusal {
        EnableRefusal::WrongPrincipal => "wrong_principal",
        EnableRefusal::NoActiveRevision => "no_active_policy_revision",
        EnableRefusal::ReviewedRevisionRequired => "reviewed_revision_required",
        EnableRefusal::RevisionConflict { .. } => "revision_conflict",
        EnableRefusal::ObserveProfile => "observe_profile",
        EnableRefusal::GuardNotRequested => "guard_not_requested",
        EnableRefusal::AcceptanceMismatch { .. } => "acceptance_mismatch",
        EnableRefusal::GrantIdInUse => "identity_unavailable",
    }
}

/// The name of a guard in a sentence.
#[must_use]
pub fn policy_label(policy: PolicyId) -> String {
    policy.as_str().replace('_', " ")
}

fn operation_id(text: &str) -> Result<OperationId, ActionState> {
    OperationId::new(text).map_err(|_| ActionState::refused("operation_not_found"))
}

/// The processes that `plan` binds, with the identity evidence of the plan
/// and the names of the snapshot.
fn plan_targets(plan: &Plan, snapshot: &ProcessSnapshot) -> Vec<StopTarget> {
    plan.targets
        .iter()
        .filter_map(|target| target.binding.processes())
        .flatten()
        .map(|process| stop_target(process, snapshot))
        .collect()
}

/// One bound process as the dialog shows it.
fn stop_target(process: &ProcessIdentity, snapshot: &ProcessSnapshot) -> StopTarget {
    let executable = process.executable.as_ref();
    StopTarget {
        pid: process.pid.get(),
        name: snapshot
            .find_pid(process.pid)
            .and_then(ProcessRecord::display_label)
            .unwrap_or_else(|| format!("PID {}", process.pid.get())),
        start_time: process.start_time.get(),
        uid: process.uid.get(),
        executable: executable.map(|executable| executable.path.display_label()),
        file: executable
            .and_then(|executable| executable.file.as_ref())
            .map(|file| format!("device {}, inode {}", file.device.get(), file.inode.get())),
        signature: executable
            .and_then(|executable| executable.code_signature.as_ref())
            .map(|signature| match &signature.team_identifier {
                Some(team) => format!("{} ({team})", signature.signing_identifier),
                None => signature.signing_identifier.clone(),
            }),
    }
}

/// The wall-clock time at which `plan` expires: its creation time plus its
/// monotonic lifetime.
pub(super) fn expiry_wall(plan: &Plan) -> SystemTime {
    let validity = &plan.validity;
    let lifetime: u64 = validity
        .expires_at
        .get()
        .saturating_sub(validity.created_at.get());
    let created: SystemTime = crate::data::live_records::system_time(validity.created_wall);
    // A lifetime out of range shows the plans as expired; the expiry check
    // before the record of the plan decides.
    created
        .checked_add(Duration::from_nanos(lifetime))
        .unwrap_or(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{Child, stop_plan};
    use svalnir_agent::journal::{CoordinatorLock, CoordinatorRole};
    use svalnir_core::{
        action::{ActionError, ActionStage, DispatchState, ErrorCode, ErrorFamily},
        id::{ExecutorEpochId, OperationId},
    };

    /// A request that is in the queue is never reported as refused when
    /// the wait reads no answer: the agent can still decide it.
    #[test]
    fn a_queued_request_with_no_answer_is_not_a_refusal() {
        for wait in [
            WaitError::Pending,
            WaitError::CoordinatorStopped,
            WaitError::Journal(OperationJournalError::Conflict),
        ] {
            let answer = answer_of(Err(wait));
            assert!(matches!(answer, Err(ActionState::Queued)), "{answer:?}");
        }
        let queued: String = ActionState::Queued.sentence(Instant::now());
        assert!(!queued.contains("Nothing changed"), "{queued}");
    }
    /// A temporary directory that is private, as a state directory must be.
    /// The `tempfile` crate makes it with the mode of the umask.
    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("{error}"));
        }
        directory
    }

    /// A temporary state directory with a journal.
    fn state_directory() -> (tempfile::TempDir, PathBuf) {
        let directory = private_tempdir();
        let path: PathBuf = journal_path(directory.path());
        OperationJournal::open(&path, &JournalOptions::default())
            .unwrap_or_else(|error| panic!("journal: {error}"));
        (directory, path)
    }

    /// The authority record of the journal at `path`.
    fn stored_authority(path: &Path) -> StoredAuthority {
        let journal = observe::open_existing_journal_read_only(path)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("no journal"));
        observe::read_authority(&journal, observe::current_uid())
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn accepted_detail(state: &ActionState) -> &str {
        match state {
            ActionState::Accepted { detail } => detail,
            other => panic!("not accepted: {other:?}"),
        }
    }

    #[test]
    fn no_agent_refuses_a_queued_request_and_writes_nothing() {
        let (directory, path) = state_directory();
        let port = LivePort::new(Some(directory.path().to_owned()));
        let before = std::fs::metadata(&path).map(|metadata| metadata.len()).ok();
        let cancel = port.submit(&Action::Cancel {
            operation: "op-1".to_owned(),
        });
        assert_eq!(cancel, ActionState::Unavailable(Unavailable::NoAgent));
        let rearm = port.submit(&Action::Rearm {
            policy: PolicyId::MemoryGuard,
            incident: "incident-1".to_owned(),
            generation: 1,
        });
        assert_eq!(rearm, ActionState::Unavailable(Unavailable::NoAgent));
        assert_eq!(stored_authority(&path).revision, 0, "no record was written");
        assert_eq!(
            std::fs::metadata(&path).map(|metadata| metadata.len()).ok(),
            before
        );
    }

    #[test]
    fn no_agent_writes_the_pause_and_the_resume_directly_as_the_cli_does() {
        let (directory, path) = state_directory();
        let port = LivePort::new(Some(directory.path().to_owned()));
        let paused = port.submit(&Action::Pause {
            duration: Some(Duration::from_secs(3600)),
        });
        assert!(
            accepted_detail(&paused).ends_with(AuthorityPath::NoAgent.sentence()),
            "{paused:?}"
        );
        let stored = stored_authority(&path);
        assert!(stored.state.pause.is_some());
        assert_eq!(stored.revision, 1);
        let resumed = port.submit(&Action::Resume);
        assert!(
            accepted_detail(&resumed).ends_with(AuthorityPath::NoAgent.sentence()),
            "{resumed:?}"
        );
        assert!(stored_authority(&path).state.pause.is_none());
        // A second resume needs no change and writes nothing.
        let again = port.submit(&Action::Resume);
        assert!(
            accepted_detail(&again).ends_with(super::super::NOTHING_WRITTEN),
            "{again:?}"
        );
        assert_eq!(stored_authority(&path).revision, 2);
    }

    #[test]
    fn no_agent_refuses_an_enable_with_no_revision_and_writes_nothing() {
        let (directory, path) = state_directory();
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Enable {
            policy: PolicyId::DiskGuard,
            revision: "rev-1".to_owned(),
            classes: Vec::new(),
        });
        assert_eq!(state, ActionState::refused("no_active_policy_revision"));
        let disabled = port.submit(&Action::Disable {
            policy: PolicyId::DiskGuard,
        });
        assert!(
            accepted_detail(&disabled).ends_with(super::super::NOTHING_WRITTEN),
            "{disabled:?}"
        );
        assert_eq!(stored_authority(&path).revision, 0, "no record was written");
    }

    #[test]
    fn a_changed_record_is_refused_and_not_replaced() {
        let (directory, path) = state_directory();
        let port = LivePort::new(Some(directory.path().to_owned()));
        let mut journal = OperationJournal::open(&path, &JournalOptions::default())
            .unwrap_or_else(|error| panic!("{error}"));
        let stored = observe::read_authority(&journal, observe::current_uid())
            .unwrap_or_else(|error| panic!("{error}"));
        let (clock, wall) = clocks().unwrap_or_else(|state| panic!("{state:?}"));
        let change = pause(
            &stored.state,
            &PauseRequest {
                principal: observe::current_uid(),
                duration: None,
            },
            &ControlClock {
                clock: &clock,
                wall,
            },
        )
        .unwrap_or_else(|refusal| panic!("{refusal:?}"));
        // A different process writes a record after the read of `stored`.
        drop(port.submit(&Action::Pause { duration: None }));
        let state = write(&mut journal, &stored, change, wall).map(|_| ());
        assert_eq!(state, Err(ActionState::refused("authority_record_changed")));
        assert_eq!(stored_authority(&path).revision, 1);
    }

    #[test]
    fn a_client_coordinator_is_not_the_agent() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Client)
            .unwrap_or_else(|error| panic!("{error}"));
        let port = LivePort::new(Some(directory.path().to_owned()));
        assert_eq!(
            port.submit(&Action::Cancel {
                operation: "op-1".to_owned()
            }),
            ActionState::Unavailable(Unavailable::OtherCoordinator)
        );
        let paused = port.submit(&Action::Pause { duration: None });
        assert!(
            accepted_detail(&paused).ends_with(AuthorityPath::OtherCoordinator.sentence()),
            "{paused:?}"
        );
    }

    #[test]
    fn no_state_directory_is_unavailable() {
        let port = LivePort::new(None);
        assert_eq!(
            port.submit(&Action::Resume),
            ActionState::Unavailable(Unavailable::NoStateDirectory)
        );
        assert!(port.operation_state("op-1").is_none());
    }

    #[test]
    fn a_pause_with_no_state_directory_makes_it_and_the_journal_as_the_cli_does() {
        let parent = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        // The state directory of `SVALNIR_STATE_DIR` and its parent do not
        // exist yet.
        let directory: PathBuf = parent.path().join("missing").join("state");
        let path: PathBuf = journal_path(&directory);
        let port = LivePort::new(Some(directory.clone()));
        let paused = port.submit(&Action::Pause { duration: None });
        assert!(
            accepted_detail(&paused).ends_with(AuthorityPath::NoAgent.sentence()),
            "{paused:?}"
        );
        assert!(client::is_private_directory(&directory));
        let stored = stored_authority(&path);
        assert!(stored.state.pause.is_some(), "the pause reads back");
        assert_eq!(stored.revision, 1);
        // The window took no coordinator lock.
        assert_eq!(client::agent_presence(&path), AgentPresence::Absent);
    }

    #[test]
    fn a_resume_and_a_disable_with_no_journal_make_it_and_write_nothing_else() {
        let directory = private_tempdir();
        let path: PathBuf = journal_path(directory.path());
        let port = LivePort::new(Some(directory.path().to_owned()));
        let resumed = port.submit(&Action::Resume);
        assert!(
            accepted_detail(&resumed).ends_with(super::super::NOTHING_WRITTEN),
            "{resumed:?}"
        );
        assert!(path.exists());
        let disabled = port.submit(&Action::Disable {
            policy: PolicyId::DiskGuard,
        });
        assert!(
            accepted_detail(&disabled).ends_with(super::super::NOTHING_WRITTEN),
            "{disabled:?}"
        );
        assert_eq!(stored_authority(&path).revision, 0, "no record was written");
    }

    #[test]
    fn no_journal_still_refuses_an_enable_and_each_queued_request_and_makes_nothing() {
        let parent = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let directory: PathBuf = parent.path().join("state");
        let port = LivePort::new(Some(directory.clone()));
        assert_eq!(
            port.submit(&Action::Enable {
                policy: PolicyId::DiskGuard,
                revision: "rev-1".to_owned(),
                classes: Vec::new(),
            }),
            ActionState::refused("no_active_policy_revision")
        );
        assert_eq!(
            port.submit(&Action::Cancel {
                operation: "op-1".to_owned(),
            }),
            ActionState::Unavailable(Unavailable::NoAgent)
        );
        assert_eq!(
            port.submit(&Action::Acknowledge {
                operation: "op-1".to_owned(),
            }),
            ActionState::Unavailable(Unavailable::NoAgent)
        );
        assert_eq!(
            port.submit(&Action::Rearm {
                policy: PolicyId::MemoryGuard,
                incident: "incident-1".to_owned(),
                generation: 1,
            }),
            ActionState::Unavailable(Unavailable::NoAgent)
        );
        assert!(!directory.exists(), "no state directory was made");
    }

    #[cfg(unix)]
    #[test]
    fn a_state_directory_that_is_not_private_is_refused_and_no_journal_is_made() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("{error}"));
        let port = LivePort::new(Some(directory.path().to_owned()));
        assert_eq!(
            port.submit(&Action::Pause { duration: None }),
            ActionState::refused("state_directory_not_private")
        );
        assert!(!journal_path(directory.path()).exists());
    }

    #[test]
    fn a_pause_with_the_agent_is_in_the_authority_record() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Pause {
            duration: Some(Duration::from_secs(3600)),
        });
        assert!(
            accepted_detail(&state).ends_with(AuthorityPath::Agent.sentence()),
            "{state:?}"
        );
        let journal = observe::open_existing_journal_read_only(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("no journal"));
        let stored = observe::read_authority(&journal, observe::current_uid())
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(stored.state.pause.is_some());
        drop(journal);
        let resumed = port.submit(&Action::Resume);
        assert!(
            matches!(resumed, ActionState::Accepted { .. }),
            "{resumed:?}"
        );
    }

    #[test]
    fn an_enable_with_no_revision_is_refused_with_its_code() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Enable {
            policy: PolicyId::DiskGuard,
            revision: "rev-1".to_owned(),
            classes: Vec::new(),
        });
        assert_eq!(state, ActionState::refused("no_active_policy_revision"));
        let prepared = port.prepare_stop("app-1", "Editor");
        assert!(
            matches!(&prepared, Err(ActionState::Refused { code, .. }) if code == "no_active_policy_revision"),
            "{prepared:?}"
        );
    }

    /// Plays the agent on the journal at `path`: it claims the next request
    /// and completes it with `completion`.
    fn serve_one(path: &Path, completion: RequestCompletion) -> std::thread::JoinHandle<()> {
        let path: PathBuf = path.to_owned();
        std::thread::spawn(move || {
            let mut journal = OperationJournal::open(&path, &JournalOptions::default())
                .unwrap_or_else(|error| panic!("{error}"));
            let lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
                .unwrap_or_else(|error| panic!("{error}"));
            let epoch =
                ExecutorEpochId::new("agent-test").unwrap_or_else(|error| panic!("{error}"));
            journal
                .begin_coordination(&lock, &epoch, WallTime::UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("{error}"));
            for _ in 0..200 {
                if let Some(claimed) = journal
                    .claim_next_request(&epoch)
                    .unwrap_or_else(|error| panic!("{error}"))
                {
                    journal
                        .complete_request(&claimed.request.request_id, &epoch, &completion)
                        .unwrap_or_else(|error| panic!("{error}"));
                    // The lock stays held while the client reads.
                    std::thread::sleep(Duration::from_millis(300));
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("no request came");
        })
    }

    fn rejection(code: &str) -> RequestCompletion {
        RequestCompletion::Rejected {
            error: ActionError {
                code: ErrorCode::new(code).unwrap_or_else(|error| panic!("{error}")),
                family: ErrorFamily::Request,
                stage: ActionStage::Admission,
                dispatch: DispatchState::NotSubmitted,
                plan_id: None,
                operation_id: None,
                step_id: None,
            },
        }
    }

    /// Waits until the test agent holds the lock.
    fn wait_for_agent(path: &Path) {
        for _ in 0..200 {
            if client::agent_presence(path) == AgentPresence::Agent {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the test agent did not take the lock");
    }

    #[test]
    fn a_rejected_request_is_refused_with_the_code_of_the_coordinator() {
        let (directory, path) = state_directory();
        let agent = serve_one(&path, rejection("operation_not_found"));
        wait_for_agent(&path);
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Acknowledge {
            operation: "op-1".to_owned(),
        });
        assert_eq!(state, ActionState::refused("operation_not_found"));
        agent
            .join()
            .unwrap_or_else(|_| panic!("the test agent failed"));
    }

    #[test]
    fn a_served_cancel_is_accepted() {
        let (directory, path) = state_directory();
        let agent = serve_one(
            &path,
            RequestCompletion::Stopped {
                fence: svalnir_core::action::StopFence::Durable,
            },
        );
        wait_for_agent(&path);
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Cancel {
            operation: "op-1".to_owned(),
        });
        assert!(matches!(state, ActionState::Accepted { .. }), "{state:?}");
        agent
            .join()
            .unwrap_or_else(|_| panic!("the test agent failed"));
    }

    #[test]
    fn a_proposal_with_no_plan_is_refused() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let port = LivePort::new(Some(directory.path().to_owned()));
        // A proposal with no plan cannot be sent.
        let proposal = Arc::new(StopProposal {
            instance: "app-1".to_owned(),
            name: "Editor".to_owned(),
            targets: Vec::new(),
            expires_at: SystemTime::UNIX_EPOCH,
            quit: None,
            force: None,
        });
        let state = port.submit(&Action::Stop {
            proposal,
            force: false,
        });
        assert_eq!(state, ActionState::refused("plan_not_buildable"));
    }

    #[test]
    fn the_listed_targets_are_exactly_the_members_of_the_sealed_plan() {
        let mut child = Child::start();
        let plan = stop_plan(&mut child, "plan-test-targets", Duration::from_secs(0));
        let members: Vec<(i32, u64, u32)> = plan
            .targets
            .iter()
            .filter_map(|target| target.binding.processes())
            .flatten()
            .map(|process| {
                (
                    process.pid.get(),
                    process.start_time.get(),
                    process.uid.get(),
                )
            })
            .collect();
        let host: Host = Host::open().unwrap_or_else(|error| panic!("{error}"));
        let snapshot = collect_processes(&host).unwrap_or_else(|error| panic!("{error}"));
        let listed: Vec<StopTarget> = plan_targets(&plan, &snapshot);
        assert_eq!(
            listed
                .iter()
                .map(|target| (target.pid, target.start_time, target.uid))
                .collect::<Vec<_>>(),
            members
        );
        let pid: i32 = i32::try_from(child.0.id()).unwrap_or_else(|error| panic!("{error}"));
        let target = listed
            .iter()
            .find(|target| target.pid == pid)
            .unwrap_or_else(|| panic!("the child is not listed: {listed:?}"));
        // The child is this test binary, started again.
        let program = std::env::current_exe().unwrap_or_else(|error| panic!("{error}"));
        let name: &str = program
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_else(|| panic!("the test binary has no name"));
        let name: String = format!("/{name}");
        assert!(
            target
                .executable
                .as_deref()
                .is_some_and(|path| path.ends_with(&name)),
            "{target:?}"
        );
        assert!(target.evidence().contains("user "), "{}", target.evidence());
    }

    #[test]
    fn a_stale_plan_is_refused_and_nothing_is_recorded() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut child = Child::start();
        let plan = stop_plan(&mut child, "plan-test-stale", Duration::from_secs(600));
        let plan_id = plan.plan_id.clone();
        let proposal = Arc::new(StopProposal {
            instance: "test".to_owned(),
            name: "sleep".to_owned(),
            targets: Vec::new(),
            expires_at: expiry_wall(&plan),
            quit: Some(Arc::new(plan)),
            force: None,
        });
        assert!(proposal.expired(SystemTime::now()));
        let port = LivePort::new(Some(directory.path().to_owned()));
        let state = port.submit(&Action::Stop {
            proposal,
            force: false,
        });
        assert_eq!(state, ActionState::refused("plan_expired"));
        let journal = observe::open_existing_journal_read_only(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("no journal"));
        assert!(
            journal
                .operation_of_plan(&plan_id)
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        drop(child);
    }

    #[test]
    fn a_stop_that_is_not_admitted_in_the_wait_is_followed_until_its_admission() {
        let (directory, path) = state_directory();
        let mut child = Child::start();
        let plan = stop_plan(&mut child, "plan-test-late", Duration::from_secs(1));
        let (admit, admitted) = std::sync::mpsc::channel::<()>();
        // The test agent claims the request only after the wait of the
        // client ended, and admits it as `op-late`.
        let agent_path: PathBuf = path.clone();
        let agent = std::thread::spawn(move || {
            let mut journal = OperationJournal::open(&agent_path, &JournalOptions::default())
                .unwrap_or_else(|error| panic!("{error}"));
            let lock = CoordinatorLock::try_acquire(&agent_path, CoordinatorRole::Agent)
                .unwrap_or_else(|error| panic!("{error}"));
            let epoch =
                ExecutorEpochId::new("agent-test").unwrap_or_else(|error| panic!("{error}"));
            journal
                .begin_coordination(&lock, &epoch, WallTime::UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("{error}"));
            admitted
                .recv_timeout(Duration::from_secs(20))
                .unwrap_or_else(|error| panic!("{error}"));
            let claimed = journal
                .claim_next_request(&epoch)
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("no request is in the queue"));
            journal
                .complete_request(
                    &claimed.request.request_id,
                    &epoch,
                    &RequestCompletion::Operation {
                        operation_id: OperationId::new("op-late")
                            .unwrap_or_else(|error| panic!("{error}")),
                    },
                )
                .unwrap_or_else(|error| panic!("{error}"));
            // The lock stays held while the client reads.
            std::thread::sleep(Duration::from_millis(300));
        });
        wait_for_agent(&path);
        let port = LivePort::new(Some(directory.path().to_owned()))
            .with_admission_wait(Duration::from_millis(200));
        let lifetime: Duration = Duration::from_nanos(
            plan.validity
                .expires_at
                .get()
                .saturating_sub(plan.validity.created_at.get()),
        );
        let proposal = Arc::new(StopProposal {
            instance: "test".to_owned(),
            name: "sleep".to_owned(),
            targets: Vec::new(),
            expires_at: expiry_wall(&plan),
            quit: Some(Arc::new(plan)),
            force: None,
        });
        let state = port.submit(&Action::Stop {
            proposal: Arc::clone(&proposal),
            force: false,
        });
        let ActionState::AwaitingAdmission { request, until, .. } = state else {
            panic!("the stop is not followed: {state:?}");
        };
        // The window follows the request until a short time after the plan
        // expires, on the monotonic clock: the rest of the plan lifetime
        // plus the grace. The plan did not expire before the submission.
        let now: Instant = Instant::now();
        assert!(
            until <= now + ADMISSION_GRACE + lifetime,
            "{until:?} {now:?} {lifetime:?}"
        );
        assert!(
            until + Duration::from_secs(1) >= now + ADMISSION_GRACE,
            "{until:?} {now:?}"
        );
        assert_eq!(port.admission_state(&request), None);
        admit.send(()).unwrap_or_else(|error| panic!("{error}"));
        let answer: Option<ActionState> = (0..100).find_map(|_| {
            let answer = port.admission_state(&request);
            if answer.is_none() {
                std::thread::sleep(Duration::from_millis(20));
            }
            answer
        });
        assert!(
            matches!(&answer, Some(ActionState::WaitingForExit { operation, .. }) if operation == "op-late"),
            "{answer:?}"
        );
        agent
            .join()
            .unwrap_or_else(|_| panic!("the test agent failed"));
        drop(child);
    }

    #[test]
    fn the_presence_maps_to_the_cause() {
        assert!(gate_presence(AgentPresence::Agent).is_ok());
        assert_eq!(
            gate_presence(AgentPresence::Unknown),
            Err(ActionState::Unavailable(Unavailable::AgentUnknown))
        );
        assert_eq!(capitalized("`HOME` is not set"), "`HOME` is not set");
        assert_eq!(capitalized("home"), "Home");
    }

    use crate::actions::cleanup::{CleanupOptions, PlanKind};

    fn cleanup_request(rule: &str, kind: PlanKind, include_clear: bool) -> CleanupRequest {
        CleanupRequest {
            rule: rule.to_owned(),
            kind,
            cancel: svalnir_agent::scan::CancellationToken::new(),
            options: CleanupOptions {
                include_clear,
                ..CleanupOptions::default()
            },
        }
    }

    fn fixture_registry() -> ReviewedRules {
        ReviewedRules::with_fixture_lifecycle(
            &svalnir_agent::rules::fixture::manual_action_validated(),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn a_proposed_rule_is_refused_before_anything_is_read_or_written() {
        // No state directory exists: the lifecycle check comes first, so the
        // refusal does not depend on the agent or the journal.
        let directory = private_tempdir();
        let state: PathBuf = directory.path().join("state");
        let port = LivePort::new(Some(state.clone()));
        for (rule, kind) in [
            ("project.dependency-directory", PlanKind::Evict),
            ("xcode.inactive-derived-data", PlanKind::Evict),
            ("go.build-cache", PlanKind::Owner),
            ("homebrew.cleanup", PlanKind::Owner),
        ] {
            let result = port.prepare_cleanup(&cleanup_request(rule, kind, true));
            assert!(
                matches!(&result, Err(ActionState::Refused { code, .. }) if code == "rule_mode_not_validated"),
                "{rule}: {result:?}"
            );
        }
        assert!(!state.exists(), "nothing was made");
    }

    #[test]
    fn a_clear_command_needs_the_consent_before_anything_is_read() {
        let directory = private_tempdir();
        let state: PathBuf = directory.path().join("state");
        let port = LivePort::new(Some(state.clone())).with_registry(fixture_registry());
        // A clear rule of the `evict` mode needs the same consent.
        let evict = port.prepare_cleanup(&cleanup_request(
            "cargo.registry-cache",
            PlanKind::Evict,
            false,
        ));
        assert!(
            matches!(&evict, Err(ActionState::Refused { code, .. }) if code == "clear_not_included"),
            "{evict:?}"
        );
        let result =
            port.prepare_cleanup(&cleanup_request("go.build-cache", PlanKind::Owner, false));
        assert!(
            matches!(&result, Err(ActionState::Refused { code, .. }) if code == "clear_not_included"),
            "{result:?}"
        );
        assert!(!state.exists(), "nothing was made");
    }

    #[test]
    fn with_no_agent_a_validated_rule_makes_no_plan_and_writes_nothing() {
        let (directory, path) = state_directory();
        let port =
            LivePort::new(Some(directory.path().to_owned())).with_registry(fixture_registry());
        let before = std::fs::metadata(&path).map(|metadata| metadata.len()).ok();
        let evict = port.prepare_cleanup(&cleanup_request(
            "project.dependency-directory",
            PlanKind::Evict,
            false,
        ));
        assert_eq!(
            evict.err(),
            Some(ActionState::Unavailable(Unavailable::NoAgent))
        );
        let owner = port.prepare_cleanup(&cleanup_request("go.build-cache", PlanKind::Owner, true));
        assert_eq!(
            owner.err(),
            Some(ActionState::Unavailable(Unavailable::NoAgent))
        );
        assert_eq!(
            std::fs::metadata(&path).map(|metadata| metadata.len()).ok(),
            before
        );
    }

    #[test]
    fn an_owner_plan_of_a_rule_with_no_owner_command_is_refused() {
        let port = LivePort::new(None).with_registry(fixture_registry());
        let result = port.prepare_cleanup(&cleanup_request(
            "project.dependency-directory",
            PlanKind::Owner,
            false,
        ));
        assert!(
            matches!(&result, Err(ActionState::Refused { code, .. }) if code == "owner_operation_not_available"),
            "{result:?}"
        );
        let unknown =
            port.prepare_cleanup(&cleanup_request("no.such-rule", PlanKind::Evict, false));
        assert!(
            matches!(&unknown, Err(ActionState::Refused { code, .. }) if code == "unknown_rule"),
            "{unknown:?}"
        );
    }

    #[test]
    fn a_clean_with_no_sealed_plan_sends_nothing() {
        let (directory, path) = state_directory();
        let port = LivePort::new(Some(directory.path().to_owned()));
        let before = std::fs::metadata(&path).map(|metadata| metadata.len()).ok();
        let proposal = crate::actions::fixture_cleanup::proposal(
            &cleanup_request("project.dependency-directory", PlanKind::Evict, false),
            true,
        )
        .unwrap_or_else(|state| panic!("{state:?}"));
        let state = port.submit(&Action::Clean {
            proposal: Arc::new(proposal),
        });
        assert_eq!(state, ActionState::refused("plan_not_buildable"));
        assert_eq!(
            std::fs::metadata(&path).map(|metadata| metadata.len()).ok(),
            before
        );
    }

    #[test]
    fn with_the_agent_a_plan_reads_the_revision_in_effect_and_records_nothing() {
        let (directory, path) = state_directory();
        let _lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let port =
            LivePort::new(Some(directory.path().to_owned())).with_registry(fixture_registry());
        let before = std::fs::metadata(&path).map(|metadata| metadata.len()).ok();
        // The agent holds the lock, so the gate passes; the journal has no
        // revision in effect, so no plan is made.
        let result = port.prepare_cleanup(&cleanup_request(
            "cargo.registry-cache",
            PlanKind::Evict,
            true,
        ));
        assert!(
            matches!(&result, Err(ActionState::Refused { code, .. }) if code == "no_active_policy_revision"),
            "{result:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).map(|metadata| metadata.len()).ok(),
            before
        );
    }
}
