//! The state-changing actions of the client.
//!
//! The client is not a coordinator. An action reaches the agent through
//! the operation journal, on the path that the CLI uses when the agent
//! holds the coordinator lock (`svalnir_agent::client`):
//!
//! - The pause, the resume, and the enable and disable of a guard write a
//!   new authority record with a compare-and-set on its revision. The agent
//!   reads the record at its next tick.
//! - The rearm of an incident, the cancel and the acknowledgment of an
//!   operation, and the stop of an application group write a request to the
//!   queue of the journal. The coordinator of the agent decides it, and the
//!   client reads the completion.
//!
//! With no agent that holds the lock, each action is refused with the
//! cause, and nothing is written. The client never takes the coordinator
//! lock.

pub mod fixture;
pub mod live;

use crate::data::model::OperationPhase;
use crate::ui::pill::Tone;
use gpui_kit::component::IconName;
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::Arc,
    time::{Duration, SystemTime},
};
use svalnir_core::{action::ActionClass, action::Plan, policy::PolicyId};

/// The control that an action belongs to. A control shows the state of
/// its last action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Slot {
    /// The pause control of the Automation screen and of the menu bar.
    Pause,
    /// The enable and disable control of one guard.
    Guard(PolicyId),
    /// The rearm control of one incident.
    Incident(String),
    /// The cancel and acknowledge controls of one operation.
    Operation(String),
    /// The stop control of one application or job instance.
    Stop(String),
}

/// What the user asks for. Each value has the identities that the user
/// saw, so that the request binds what the confirmation showed.
#[derive(Debug, Clone)]
pub enum Action {
    /// Pause automatic interventions. `None`: until a resume.
    Pause {
        /// The length of the pause.
        duration: Option<Duration>,
    },
    /// End the pause.
    Resume,
    /// Enable a guard for the reviewed revision with the action classes of
    /// its scope.
    Enable {
        /// The guard.
        policy: PolicyId,
        /// The revision that the confirmation showed.
        revision: String,
        /// The action classes that the confirmation showed.
        classes: Vec<ActionClass>,
    },
    /// Disable a guard.
    Disable {
        /// The guard.
        policy: PolicyId,
    },
    /// Rearm an incident of a guard: a new budget generation.
    Rearm {
        /// The guard.
        policy: PolicyId,
        /// The incident.
        incident: String,
        /// The budget generation that the confirmation showed.
        generation: u64,
    },
    /// Stop the dispatch of the further steps of an operation.
    Cancel {
        /// The operation.
        operation: String,
    },
    /// Acknowledge an `UnknownOutcome` operation and release its leases.
    Acknowledge {
        /// The operation.
        operation: String,
    },
    /// Stop an application group with the plan that the confirmation
    /// showed.
    Stop {
        /// The reviewed plans and their targets.
        proposal: Arc<StopProposal>,
        /// `true`: the force-quit plan; `false`: the quit plan.
        force: bool,
    },
}

impl Action {
    /// The control of the action.
    #[must_use]
    pub fn slot(&self) -> Slot {
        match self {
            Self::Pause { .. } | Self::Resume => Slot::Pause,
            Self::Enable { policy, .. } | Self::Disable { policy } => Slot::Guard(*policy),
            Self::Rearm { incident, .. } => Slot::Incident(incident.clone()),
            Self::Cancel { operation } | Self::Acknowledge { operation } => {
                Slot::Operation(operation.clone())
            }
            Self::Stop { proposal, .. } => Slot::Stop(proposal.instance.clone()),
        }
    }

    /// The name of the action for a state line, for example "Pause".
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Pause { .. } => "Pause",
            Self::Resume => "Resume",
            Self::Enable { .. } => "Enable",
            Self::Disable { .. } => "Disable",
            Self::Rearm { .. } => "Rearm",
            Self::Cancel { .. } => "Cancel",
            Self::Acknowledge { .. } => "Acknowledge",
            Self::Stop { force: false, .. } => "Quit",
            Self::Stop { force: true, .. } => "Force quit",
        }
    }
}

/// One process that a stop plan binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopTarget {
    /// The process ID.
    pub pid: i32,
    /// The name of the process.
    pub name: String,
}

/// The two stop plans of one application group, made from one process
/// reading, and the processes that they bind. Nothing is recorded until
/// the user confirms one plan.
#[derive(Debug, Clone)]
pub struct StopProposal {
    /// The instance identity of the group.
    pub instance: String,
    /// The name of the group.
    pub name: String,
    /// The processes of the plans.
    pub targets: Vec<StopTarget>,
    /// The wall-clock time at which the plans expire.
    pub expires_at: SystemTime,
    /// The quit plan: a request to exit. `None` for a fixture.
    pub quit: Option<Arc<Plan>>,
    /// The force-quit plan. `None` for a fixture.
    pub force: Option<Arc<Plan>>,
}

impl StopProposal {
    /// Whether the plans expired at `now`.
    #[must_use]
    pub fn expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }
}

/// The stop plans of the dialog that is open.
#[derive(Debug, Clone)]
pub enum Proposal {
    /// The client reads the processes and makes the plans.
    Preparing,
    /// The plans are ready for the confirmation.
    Ready(Arc<StopProposal>),
    /// No plan was made.
    Failed(ActionState),
}

/// Why an action cannot reach the agent. Nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// No process holds the coordinator lock.
    NoAgent,
    /// A client process holds the lock as a transient coordinator, not the
    /// agent.
    OtherCoordinator,
    /// The lock file cannot be read.
    AgentUnknown,
    /// The state directory has no journal.
    NoJournal,
    /// The state directory is not known.
    NoStateDirectory,
    /// `HOME` is not the home directory of the account record.
    Home(String),
    /// A clock of the host gave no value.
    Clock,
}

impl Unavailable {
    /// One sentence that names the cause and what the user can do.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::NoAgent => "No agent holds the coordinator lock, so no process can decide the request. This window does not act in place of the agent. Start the agent with `svalnir agent install`.".to_owned(),
            Self::OtherCoordinator => "A command-line client holds the coordinator lock, not the agent. Wait for the command to end, then try again.".to_owned(),
            Self::AgentUnknown => "The coordinator lock cannot be read, so it is not known whether the agent runs.".to_owned(),
            Self::NoJournal => "The state directory has no operation journal, so no agent runs on it.".to_owned(),
            Self::NoStateDirectory => "The state directory is not known.".to_owned(),
            Self::Home(reason) => format!("{reason}. The window changes nothing in this state."),
            Self::Clock => "A clock of this host gave no value.".to_owned(),
        }
    }
}

/// The state of a control after an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionState {
    /// The request was sent, and no answer came yet.
    Pending,
    /// The journal has the change, or the agent accepted the request.
    Accepted {
        /// What is now true.
        detail: String,
    },
    /// The plan of a stop is recorded and its request is in the queue, and
    /// the agent did not admit it yet. The window reads the request again
    /// at each poll until it has a result or `until` passes.
    AwaitingAdmission {
        /// The identity of the queued request.
        request: String,
        /// When the request was sent.
        since: SystemTime,
        /// When the window stops to follow the request: a short time after
        /// the plan expires, when the agent can only refuse it.
        until: SystemTime,
    },
    /// The agent admitted the stop. The exit is not confirmed.
    WaitingForExit {
        /// The operation of the stop.
        operation: String,
        /// When the agent admitted it.
        since: SystemTime,
    },
    /// The stop operation has its final record.
    Settled {
        /// The operation of the stop.
        operation: String,
        /// The phase of its final record.
        phase: OperationPhase,
    },
    /// The window did not read the final record of the stop operation in
    /// time. The operation can still end; History shows it.
    ExitNotConfirmed {
        /// The operation of the stop.
        operation: String,
    },
    /// The wait ended with no answer. The request stays in the queue, and
    /// the agent can decide it later.
    Queued,
    /// The request was refused. Nothing changed.
    Refused {
        /// The error code.
        code: String,
        /// One sentence.
        reason: String,
    },
    /// The request did not reach the agent. Nothing was written.
    Unavailable(Unavailable),
}

impl ActionState {
    /// A refusal with the sentence of its code.
    #[must_use]
    pub fn refused(code: &str) -> Self {
        Self::Refused {
            code: code.to_owned(),
            reason: reason_of(code).to_owned(),
        }
    }

    /// Whether an answer is not there yet, so the control takes no second
    /// request.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::AwaitingAdmission { .. } | Self::WaitingForExit { .. }
        )
    }

    /// The text, tone, and icon of the state pill. A state has two
    /// signals: the tone and the text.
    #[must_use]
    pub fn pill(&self) -> (&'static str, Tone, IconName) {
        match self {
            Self::Pending => ("Sent", Tone::Brand, IconName::Loader),
            Self::Accepted { .. } => ("Accepted", Tone::Positive, IconName::CircleCheck),
            Self::AwaitingAdmission { .. } => {
                ("Waiting for admission", Tone::Brand, IconName::Loader)
            }
            Self::WaitingForExit { .. } => ("Waiting for exit", Tone::Brand, IconName::Loader),
            Self::Settled { phase, .. } => match phase {
                OperationPhase::Completed => ("Exited", Tone::Positive, IconName::CircleCheck),
                OperationPhase::Partial => ("Partial", Tone::Warning, IconName::TriangleAlert),
                OperationPhase::NoAction => ("No action", Tone::Neutral, IconName::Minus),
                OperationPhase::Failed => ("Failed", Tone::Negative, IconName::CircleX),
                _ => ("Unknown outcome", Tone::Warning, IconName::Info),
            },
            Self::ExitNotConfirmed { .. } => ("Exit not confirmed", Tone::Warning, IconName::Info),
            Self::Queued => ("Not answered", Tone::Warning, IconName::Info),
            Self::Refused { .. } => ("Refused", Tone::Negative, IconName::CircleX),
            Self::Unavailable(_) => ("Unavailable", Tone::Neutral, IconName::Info),
        }
    }

    /// One sentence for the state line at `now`.
    #[must_use]
    pub fn sentence(&self, now: SystemTime) -> String {
        match self {
            Self::Pending => "The request is sent. The agent did not answer yet.".to_owned(),
            Self::Accepted { detail } => detail.clone(),
            Self::AwaitingAdmission { since, .. } => {
                let seconds: u64 = now.duration_since(*since).map_or(0, |age| age.as_secs());
                format!(
                    "The plan is recorded and the request is in the queue. The agent did not admit it yet: {seconds} s. The window follows the request until the plan expires."
                )
            }
            Self::WaitingForExit { operation, since } => {
                let seconds: u64 = now.duration_since(*since).map_or(0, |age| age.as_secs());
                format!("The agent admitted operation {operation}. Waiting for exit: {seconds} s.")
            }
            Self::Settled { operation, phase } => match phase {
                OperationPhase::Completed => {
                    format!("Operation {operation} completed: the agent confirmed the exit.")
                }
                _ => format!(
                    "Operation {operation} ended in the state {}. See History.",
                    phase_name(*phase)
                ),
            },
            Self::ExitNotConfirmed { operation } => format!("The window did not read the final record of operation {operation} in 5 min. The operation can still end; History shows its state."),
            Self::Queued => "The agent did not answer before the end of the wait. The request stays in the queue, and the agent can decide it later. See History.".to_owned(),
            Self::Refused { code, reason } if code == UNEXPECTED_COMPLETION => {
                format!("{reason} ({code}).")
            }
            Self::Refused { code, reason } => format!("{reason} ({code}). Nothing changed."),
            Self::Unavailable(cause) => cause.sentence(),
        }
    }
}

const fn phase_name(phase: OperationPhase) -> &'static str {
    match phase {
        OperationPhase::Pending => "Pending",
        OperationPhase::Running => "Running",
        OperationPhase::Completed => "Completed",
        OperationPhase::Partial => "Partial",
        OperationPhase::NoAction => "NoAction",
        OperationPhase::Failed => "Failed",
        OperationPhase::Unknown => "UnknownOutcome",
    }
}

/// The code of a completion of a different kind than the request. The
/// request reached the agent, so this refusal does not say that nothing
/// changed.
pub const UNEXPECTED_COMPLETION: &str = "unexpected_completion";

/// The sentence of an error code of the coordinator, of the authority
/// logic, or of this client.
#[must_use]
pub fn reason_of(code: &str) -> &'static str {
    match code {
        "plan_expired" => "The plan expired before the agent admitted it. Prepare a new plan",
        "plan_not_found" => "The journal has no plan with this identity",
        "approval_mismatch" | "manual_approval_mismatch" => {
            "The approval does not agree with the stored plan"
        }
        "policy_revision_changed" | "policy_revision_mismatch" => {
            "The configuration revision changed after the plan was made. Prepare a new plan"
        }
        "no_active_policy_revision" => "No configuration revision is in effect",
        "policy_revision_source_not_usable" => {
            "The journal has no usable configuration text for the revision in effect"
        }
        "target_protected" => "A hard protection applies to a process of the group",
        "target_protection_unknown" => "The protection of a process of the group is not known",
        "target_not_eligible" => "The group is not a permitted target",
        "group_not_found" => "The group has no verified member now. Read the processes again",
        "lease_unavailable" => "A different operation uses the same process or root. Wait for it",
        "queue_full" => "The request queue of the journal is full",
        "reconciliation_pending" => "An earlier operation has an unknown effect",
        "wrong_principal" | "principal_mismatch" => "The record is of a different user",
        "operation_not_found" => "The journal has no operation with this identity",
        "operation_not_unknown_outcome" => "The operation is not in the state UnknownOutcome",
        "authority_record_changed" => {
            "A different process changed the authority record at the same time. Read the state again"
        }
        "revision_conflict" => "The revision in effect is not the revision that was shown",
        "reviewed_revision_required" => "The request does not name the reviewed revision",
        "observe_profile" => "The profile of the revision in effect permits no intervention",
        "guard_not_requested" => "The revision in effect does not request this guard",
        "acceptance_mismatch" => {
            "The action classes do not agree with the revision in effect. Read the state again"
        }
        "disable_refused" | "rearm_refused" => "The request was refused",
        "invalid_duration" => "The pause duration is not usable",
        "coordinator_stopped" => {
            "The agent stopped before it decided the request. The request stays in the queue"
        }
        "journal_busy" => "A different process holds the journal. Try again",
        "journal_full" => "The operation journal has no space for new work",
        "journal_conflict" => "The journal has a different request with this identity",
        "identity_unavailable" => "An identity of the request cannot be made",
        "plan_not_buildable" => "The stop plan cannot be made",
        "process_reading_unavailable" => "The processes of this user cannot be read",
        UNEXPECTED_COMPLETION => {
            "The agent answered with a result of a different kind, so its effect is not known here. See History"
        }
        "authority_record_not_readable" => "The authority record cannot be read",
        _ => "The agent refused the request",
    }
}

/// The path from the client to the agent. Each method can block; the
/// model calls them only from a background thread.
pub trait ActionPort: Send + Sync + Debug {
    /// Sends `action` and waits for the answer.
    fn submit(&self, action: &Action) -> ActionState;

    /// Reads the processes of the instance `instance` and makes its quit
    /// and force-quit plans. Nothing is recorded.
    ///
    /// # Errors
    ///
    /// Returns the state of a refusal or of an unavailable agent.
    fn prepare_stop(&self, instance: &str, name: &str) -> Result<StopProposal, ActionState>;

    /// The phase of the operation `operation`, when the journal has it.
    fn operation_phase(&self, operation: &str) -> Option<OperationPhase>;

    /// The state of a stop whose request `request` waits for admission:
    /// `WaitingForExit` when the agent admitted the plan, or the refusal.
    /// `None` while the request has no completion or cannot be read now.
    fn admission_state(&self, request: &str) -> Option<ActionState>;
}

/// The states of the controls, and the stop plans of the open dialog.
#[derive(Debug, Default)]
pub struct ActionBook {
    states: HashMap<Slot, ActionState>,
    /// The stop dialog: the instance and its plans.
    pub stop: Option<(String, Proposal)>,
    /// The number of the latest preparation of stop plans. A result of an
    /// earlier preparation is not kept.
    stop_request: u64,
}

impl ActionBook {
    /// The state of the last action of `slot`.
    #[must_use]
    pub fn state(&self, slot: &Slot) -> Option<&ActionState> {
        self.states.get(slot)
    }

    /// Records the state of `slot`.
    pub fn set(&mut self, slot: Slot, state: ActionState) {
        self.states.insert(slot, state);
    }

    /// Opens the stop dialog of `instance` with plans that are being made,
    /// and gives the number of this preparation.
    pub fn open_stop(&mut self, instance: &str) -> u64 {
        self.stop_request = self.stop_request.wrapping_add(1);
        self.stop = Some((instance.to_owned(), Proposal::Preparing));
        self.stop_request
    }

    /// Records the plans of the preparation `request`. Returns `false` and
    /// keeps nothing when the dialog closed or a later preparation started.
    pub fn finish_stop(&mut self, request: u64, proposal: Proposal) -> bool {
        if request != self.stop_request {
            return false;
        }
        match &mut self.stop {
            Some((_, open)) => {
                *open = proposal;
                true
            }
            None => false,
        }
    }

    /// Closes the stop dialog. A preparation that runs keeps no result.
    pub fn close_stop(&mut self) {
        self.stop_request = self.stop_request.wrapping_add(1);
        self.stop = None;
    }

    /// Ends each wait for an exit that started more than `limit` before
    /// `now` as [`ActionState::ExitNotConfirmed`], and each wait for an
    /// admission after its `until` as [`ActionState::Queued`]. Returns
    /// `true` when a state changed.
    pub fn end_long_waits(&mut self, now: SystemTime, limit: Duration) -> bool {
        let mut changed: bool = false;
        for state in self.states.values_mut() {
            match state {
                ActionState::WaitingForExit { operation, since }
                    if now.duration_since(*since).is_ok_and(|age| age > limit) =>
                {
                    *state = ActionState::ExitNotConfirmed {
                        operation: operation.clone(),
                    };
                    changed = true;
                }
                ActionState::AwaitingAdmission { until, .. } if now > *until => {
                    *state = ActionState::Queued;
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    /// The stops that wait for admission: the slot and the request.
    #[must_use]
    pub fn admissions(&self) -> Vec<(Slot, String)> {
        self.states
            .iter()
            .filter_map(|(slot, state)| match state {
                ActionState::AwaitingAdmission { request, .. } => {
                    Some((slot.clone(), request.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Records the answer to the request `request` of a stop that waits for
    /// admission. A slot that no longer waits for this request keeps its
    /// state, and a state that is still a wait for admission changes
    /// nothing.
    pub fn admit(&mut self, slot: &Slot, request: &str, state: ActionState) {
        if matches!(state, ActionState::AwaitingAdmission { .. }) {
            return;
        }
        if let Some(current) = self.states.get_mut(slot)
            && matches!(current, ActionState::AwaitingAdmission { request: waiting, .. } if waiting == request)
        {
            *current = state;
        }
    }

    /// Each control with the state of its last action.
    pub fn entries(&self) -> impl Iterator<Item = (&Slot, &ActionState)> {
        self.states.iter()
    }

    /// Whether `slot` waits for an answer.
    #[must_use]
    pub fn is_busy(&self, slot: &Slot) -> bool {
        self.states.get(slot).is_some_and(ActionState::is_busy)
    }

    /// The stops that wait for the exit: the slot and the operation.
    #[must_use]
    pub fn waiting(&self) -> Vec<(Slot, String)> {
        self.states
            .iter()
            .filter_map(|(slot, state)| match state {
                ActionState::WaitingForExit { operation, .. } => {
                    Some((slot.clone(), operation.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Records the phase of a stop operation that waits for the exit. A
    /// phase that is not final changes nothing.
    pub fn settle(&mut self, slot: &Slot, operation: &str, phase: OperationPhase) {
        if matches!(phase, OperationPhase::Pending | OperationPhase::Running) {
            return;
        }
        if let Some(state) = self.states.get_mut(slot)
            && matches!(state, ActionState::WaitingForExit { operation: waiting, .. } if waiting == operation)
        {
            *state = ActionState::Settled {
                operation: operation.to_owned(),
                phase,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(expires_at: SystemTime) -> Arc<StopProposal> {
        Arc::new(StopProposal {
            instance: "app-1".to_owned(),
            name: "Editor".to_owned(),
            targets: vec![StopTarget {
                pid: 10,
                name: "Editor".to_owned(),
            }],
            expires_at,
            quit: None,
            force: None,
        })
    }

    #[test]
    fn each_action_has_its_control() {
        assert_eq!(Action::Resume.slot(), Slot::Pause);
        assert_eq!(Action::Pause { duration: None }.slot(), Slot::Pause);
        assert_eq!(
            Action::Disable {
                policy: PolicyId::DiskGuard
            }
            .slot(),
            Slot::Guard(PolicyId::DiskGuard)
        );
        assert_eq!(
            Action::Acknowledge {
                operation: "op".to_owned()
            }
            .slot(),
            Slot::Operation("op".to_owned())
        );
        let stop = Action::Stop {
            proposal: proposal(SystemTime::UNIX_EPOCH),
            force: true,
        };
        assert_eq!(stop.slot(), Slot::Stop("app-1".to_owned()));
        assert_eq!(stop.verb(), "Force quit");
    }

    #[test]
    fn a_refusal_names_its_code_and_says_that_nothing_changed() {
        let state = ActionState::refused("plan_expired");
        let (text, tone, _) = state.pill();
        assert_eq!((text, tone), ("Refused", Tone::Negative));
        let sentence = state.sentence(SystemTime::UNIX_EPOCH);
        assert!(sentence.contains("(plan_expired)"), "{sentence}");
        assert!(sentence.ends_with("Nothing changed."), "{sentence}");
        assert_eq!(
            reason_of("an_unknown_code"),
            "The agent refused the request"
        );
    }

    #[test]
    fn no_agent_names_the_cause_and_is_not_a_refusal() {
        let state = ActionState::Unavailable(Unavailable::NoAgent);
        assert_eq!(state.pill().0, "Unavailable");
        assert!(
            state
                .sentence(SystemTime::UNIX_EPOCH)
                .contains("No agent holds the coordinator lock")
        );
        assert!(!state.is_busy());
    }

    #[test]
    fn a_stop_is_done_only_after_the_exit() {
        let since = SystemTime::UNIX_EPOCH;
        let mut book = ActionBook::default();
        let slot = Slot::Stop("app-1".to_owned());
        book.set(
            slot.clone(),
            ActionState::WaitingForExit {
                operation: "op-1".to_owned(),
                since,
            },
        );
        assert!(book.is_busy(&slot));
        let text = book
            .state(&slot)
            .map(|state| state.sentence(since + Duration::from_secs(4)));
        assert_eq!(
            text.as_deref(),
            Some("The agent admitted operation op-1. Waiting for exit: 4 s.")
        );
        assert_eq!(book.waiting(), vec![(slot.clone(), "op-1".to_owned())]);
        // A phase that is not final changes nothing.
        book.settle(&slot, "op-1", OperationPhase::Running);
        assert!(book.is_busy(&slot));
        // A different operation changes nothing.
        book.settle(&slot, "op-2", OperationPhase::Completed);
        assert!(book.is_busy(&slot));
        book.settle(&slot, "op-1", OperationPhase::Completed);
        assert_eq!(
            book.state(&slot).map(|state| state.pill().0),
            Some("Exited")
        );
        assert_eq!(book.waiting(), Vec::new());
    }

    #[test]
    fn only_the_latest_preparation_of_an_open_dialog_is_kept() {
        let mut book = ActionBook::default();
        let first = book.open_stop("app-1");
        // The user asks for new plans while the first preparation runs.
        let second = book.open_stop("app-1");
        let late = Proposal::Ready(proposal(SystemTime::UNIX_EPOCH));
        assert!(!book.finish_stop(first, late));
        assert!(matches!(book.stop, Some((_, Proposal::Preparing))));
        assert!(book.finish_stop(
            second,
            Proposal::Failed(ActionState::refused("group_not_found"))
        ));
        // A dialog that closed and opened again keeps no earlier result.
        let third = book.open_stop("app-1");
        book.close_stop();
        let fourth = book.open_stop("app-1");
        assert!(!book.finish_stop(third, Proposal::Preparing));
        assert!(book.finish_stop(fourth, Proposal::Preparing));
        book.close_stop();
        assert!(!book.finish_stop(fourth, Proposal::Preparing));
        assert!(book.stop.is_none());
    }

    #[test]
    fn a_long_wait_for_the_exit_ends_and_frees_the_control() {
        let since = SystemTime::UNIX_EPOCH;
        let mut book = ActionBook::default();
        let slot = Slot::Stop("app-1".to_owned());
        book.set(
            slot.clone(),
            ActionState::WaitingForExit {
                operation: "op-1".to_owned(),
                since,
            },
        );
        let limit = Duration::from_secs(300);
        assert!(!book.end_long_waits(since + limit, limit));
        assert!(book.is_busy(&slot));
        assert!(book.end_long_waits(since + limit + Duration::from_secs(1), limit));
        assert!(!book.is_busy(&slot));
        let state = book.state(&slot).cloned();
        assert_eq!(
            state.as_ref().map(|state| state.pill().0),
            Some("Exit not confirmed")
        );
        assert_eq!(book.waiting(), Vec::new());
    }

    #[test]
    fn a_stop_that_waits_for_admission_is_followed_until_its_bound() {
        let since: SystemTime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let until: SystemTime = since + Duration::from_secs(330);
        let slot = Slot::Stop("app-1".to_owned());
        let mut book = ActionBook::default();
        let waiting = ActionState::AwaitingAdmission {
            request: "req-1".to_owned(),
            since,
            until,
        };
        book.set(slot.clone(), waiting.clone());
        assert!(book.is_busy(&slot));
        assert_eq!(waiting.pill().0, "Waiting for admission");
        assert_eq!(book.admissions(), vec![(slot.clone(), "req-1".to_owned())]);
        // An answer to a different request changes nothing.
        book.admit(&slot, "req-0", ActionState::refused("plan_expired"));
        assert_eq!(book.state(&slot), Some(&waiting));
        // The bound has not passed: the wait goes on.
        assert!(!book.end_long_waits(until, Duration::from_secs(300)));
        // The admission gives the wait for the exit.
        book.admit(
            &slot,
            "req-1",
            ActionState::WaitingForExit {
                operation: "op-1".to_owned(),
                since: until,
            },
        );
        assert_eq!(book.admissions(), Vec::new());
        assert_eq!(book.waiting(), vec![(slot.clone(), "op-1".to_owned())]);
        // With no answer, the wait ends after the bound as "not answered",
        // and the control takes a new request.
        book.set(slot.clone(), waiting);
        assert!(book.end_long_waits(until + Duration::from_secs(1), Duration::from_secs(300)));
        assert_eq!(book.state(&slot), Some(&ActionState::Queued));
        assert!(!book.is_busy(&slot));
    }

    #[test]
    fn an_unexpected_completion_does_not_say_that_nothing_changed() {
        let sentence = ActionState::refused(UNEXPECTED_COMPLETION).sentence(SystemTime::UNIX_EPOCH);
        assert!(!sentence.contains("Nothing changed"), "{sentence}");
        assert!(sentence.ends_with("(unexpected_completion)."), "{sentence}");
    }

    #[test]
    fn an_unknown_outcome_is_not_a_failure() {
        let unknown = ActionState::Settled {
            operation: "op".to_owned(),
            phase: OperationPhase::Unknown,
        };
        let failed = ActionState::Settled {
            operation: "op".to_owned(),
            phase: OperationPhase::Failed,
        };
        assert_ne!(unknown.pill().1, failed.pill().1);
        assert!(
            unknown
                .sentence(SystemTime::UNIX_EPOCH)
                .contains("UnknownOutcome")
        );
    }

    #[test]
    fn a_plan_expires_at_its_time() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let plans = proposal(at);
        assert!(!plans.expired(at - Duration::from_secs(1)));
        assert!(plans.expired(at));
    }
}
