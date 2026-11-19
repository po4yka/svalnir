//! The system notifications of the client (`README.md`, "GPUI desktop
//! experience"; `DESIGN.md` §9).
//!
//! A notification explains a meaningful change of state, one time: the
//! rules here post a note only at a transition into a condition, never
//! again while the condition stays, and never for the first value that the
//! window reads. Each condition has a fixed tag, so the notification center
//! replaces an earlier note of the same condition. A post is one call with
//! no retry: when delivery fails or is off, nothing is posted again.
//!
//! The client posts notifications only while it runs. The agent posts none
//! in this build.

use crate::{
    actions::{ActionBook, ActionState, Slot},
    data::{
        model::{AgentState, Loadable, Measured, PressureLevel},
        store::AppModel,
    },
};
use gpui_kit::{App, Entity, Global, SystemNotification};
use std::collections::HashSet;

/// One notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The tag of the condition. A note with the same tag replaces the
    /// earlier one.
    pub tag: String,
    /// The headline.
    pub title: String,
    /// One or two sentences.
    pub body: String,
}

/// The tag of the memory pressure note.
pub const PRESSURE_TAG: &str = "svalnir-memory-pressure";
/// The tag of the agent note.
pub const AGENT_TAG: &str = "svalnir-agent";

/// What the rules saw at the last observation.
#[derive(Debug, Default)]
pub struct Notifier {
    /// The last pressure that was read, when one was.
    pressure: Option<PressureLevel>,
    /// Whether the agent was reporting at the last reading, when one was.
    reporting: Option<bool>,
    /// The stop operations whose final record had a note.
    settled: HashSet<String>,
    /// The controls whose request was not answered and had a note.
    unanswered: HashSet<Slot>,
}

impl Notifier {
    /// The notes of the change from the last observation to this one.
    /// `None` is a value that was not read; it changes nothing.
    pub fn observe(
        &mut self,
        pressure: Option<PressureLevel>,
        agent: Option<&AgentState>,
        actions: &ActionBook,
    ) -> Vec<Note> {
        let mut notes: Vec<Note> = Vec::new();
        if let Some(level) = pressure {
            let before: Option<PressureLevel> = self.pressure.replace(level);
            if level == PressureLevel::Critical
                && before.is_some_and(|before| before != PressureLevel::Critical)
            {
                notes.push(Note {
                    tag: PRESSURE_TAG.to_owned(),
                    title: "Memory pressure is critical".to_owned(),
                    body: "The system memory pressure state changed to critical. See Memory for the footprint of each application.".to_owned(),
                });
            }
        }
        // A status that cannot be read is not a value.
        let reporting: Option<bool> = agent.and_then(|state| match state {
            AgentState::Reporting { .. } => Some(true),
            AgentState::Silent { .. } | AgentState::NoJournal | AgentState::NoRecord => Some(false),
            AgentState::Unknown(_) => None,
        });
        if let Some(reporting) = reporting {
            let before: Option<bool> = self.reporting.replace(reporting);
            if before == Some(true) && !reporting {
                notes.push(Note {
                    tag: AGENT_TAG.to_owned(),
                    title: "The agent stopped reporting".to_owned(),
                    body: "The agent wrote no status record in the last 90 s. With no agent, no guard acts and the window can change nothing. See Diagnostics.".to_owned(),
                });
            }
        }
        // Only the operations that a control still shows stay in the set,
        // so the set is bounded by the controls.
        self.settled.retain(|operation| {
            actions.entries().any(|(_, state)| {
                matches!(state, ActionState::Settled { operation: shown, .. } if shown == operation)
            })
        });
        for (slot, state) in actions.entries() {
            match state {
                ActionState::Settled { operation, .. } => {
                    if self.settled.insert(operation.clone()) {
                        let (pill, _, _) = state.pill();
                        notes.push(Note {
                            tag: format!("svalnir-stop-{operation}"),
                            title: format!("Stop: {pill}"),
                            body: state.sentence(std::time::SystemTime::now()),
                        });
                    }
                }
                ActionState::Queued | ActionState::NotAdmitted => {
                    if self.unanswered.insert(slot.clone()) {
                        notes.push(Note {
                            tag: format!("svalnir-request-{}", slot_key(slot)),
                            title: "The agent did not answer".to_owned(),
                            body: state.sentence(std::time::SystemTime::now()),
                        });
                    }
                }
                _ => {
                    // A new answer ends the condition: a later wait that
                    // ends with no answer has its own note.
                    self.unanswered.remove(slot);
                }
            }
        }
        notes
    }
}

/// The global that turns the notifications off (`--no-notifications`).
#[derive(Debug, Clone, Copy)]
pub struct NotificationsOff;

impl Global for NotificationsOff {}

/// The pressure of the latest host reading. A stale or failed reading is
/// not a value.
fn pressure_of(model: &AppModel) -> Option<PressureLevel> {
    match &model.host {
        Loadable::Ready(host) => match &host.pressure {
            Measured::Value(level) => Some(*level),
            Measured::Unavailable(_) => None,
        },
        _ => None,
    }
}

fn agent_of(model: &AppModel) -> Option<&AgentState> {
    match &model.agent {
        Loadable::Ready(agent) => Some(&agent.state),
        _ => None,
    }
}

/// Observes `model` and posts the notes of each change as system
/// notifications. A post is one call: GPUI does nothing outside an
/// application bundle or when the user denied the notifications, and the
/// client does not post the note again.
pub fn watch(model: &Entity<AppModel>, cx: &mut App) {
    let mut notifier = Notifier::default();
    cx.observe(model, move |model, cx| {
        let notes: Vec<Note> = {
            let model: &AppModel = model.read(cx);
            notifier.observe(pressure_of(model), agent_of(model), &model.actions)
        };
        if cx.has_global::<NotificationsOff>() {
            return;
        }
        for note in notes {
            cx.show_system_notification(SystemNotification {
                tag: note.tag.into(),
                title: note.title.into(),
                body: note.body.into(),
                actions: Vec::new(),
            });
        }
    })
    .detach();
}

/// A short key of a control for a tag.
fn slot_key(slot: &Slot) -> String {
    match slot {
        Slot::Pause => "pause".to_owned(),
        Slot::Guard(policy) => policy.as_str().to_owned(),
        Slot::Incident(id) => format!("incident-{id}"),
        Slot::Operation(id) => format!("operation-{id}"),
        Slot::Stop(instance) => format!("stop-{instance}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::model::OperationPhase;
    use std::time::SystemTime;

    fn reporting() -> AgentState {
        AgentState::Reporting {
            since: SystemTime::UNIX_EPOCH,
        }
    }

    fn silent() -> AgentState {
        AgentState::Silent {
            last: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn the_first_value_has_no_note() {
        let mut notifier = Notifier::default();
        let book = ActionBook::default();
        let notes = notifier.observe(Some(PressureLevel::Critical), Some(&silent()), &book);
        assert_eq!(notes, Vec::new());
    }

    #[test]
    fn a_sustained_condition_has_one_note() {
        let mut notifier = Notifier::default();
        let book = ActionBook::default();
        assert_eq!(
            notifier.observe(Some(PressureLevel::Warning), Some(&reporting()), &book),
            Vec::new()
        );
        let notes = notifier.observe(Some(PressureLevel::Critical), Some(&reporting()), &book);
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes.first().map(|note| note.tag.as_str()),
            Some(PRESSURE_TAG)
        );
        // The condition stays: no second note.
        assert_eq!(
            notifier.observe(Some(PressureLevel::Critical), Some(&reporting()), &book),
            Vec::new()
        );
        // A reading that failed changes nothing.
        assert_eq!(notifier.observe(None, None, &book), Vec::new());
        assert_eq!(
            notifier.observe(Some(PressureLevel::Critical), None, &book),
            Vec::new()
        );
        // The condition ends and comes again: a new note.
        assert_eq!(
            notifier.observe(Some(PressureLevel::Normal), None, &book),
            Vec::new()
        );
        assert_eq!(
            notifier
                .observe(Some(PressureLevel::Critical), None, &book)
                .len(),
            1
        );
    }

    #[test]
    fn the_agent_note_comes_when_the_agent_stops_reporting() {
        let mut notifier = Notifier::default();
        let book = ActionBook::default();
        assert_eq!(
            notifier.observe(None, Some(&reporting()), &book),
            Vec::new()
        );
        let notes = notifier.observe(None, Some(&silent()), &book);
        assert_eq!(notes.first().map(|note| note.tag.as_str()), Some(AGENT_TAG));
        assert_eq!(notifier.observe(None, Some(&silent()), &book), Vec::new());
    }

    #[test]
    fn a_status_that_cannot_be_read_is_not_a_stop_of_the_agent() {
        let mut notifier = Notifier::default();
        let book = ActionBook::default();
        assert_eq!(
            notifier.observe(None, Some(&reporting()), &book),
            Vec::new()
        );
        let unknown = AgentState::Unknown("the journal cannot be read".to_owned());
        assert_eq!(notifier.observe(None, Some(&unknown), &book), Vec::new());
        // The last value stays reporting, so a later silence is a transition.
        assert_eq!(notifier.observe(None, Some(&silent()), &book).len(), 1);
    }

    #[test]
    fn the_notified_operations_are_bounded_by_the_controls() {
        let mut notifier = Notifier::default();
        let mut book = ActionBook::default();
        let slot = Slot::Stop("app-1".to_owned());
        for operation in ["op-1", "op-2"] {
            book.set(
                slot.clone(),
                ActionState::Settled {
                    operation: operation.to_owned(),
                    phase: OperationPhase::Completed,
                },
            );
            assert_eq!(notifier.observe(None, None, &book).len(), 1);
        }
        assert_eq!(notifier.settled.len(), 1);
    }

    #[test]
    fn a_settled_stop_has_one_note() {
        let mut notifier = Notifier::default();
        let mut book = ActionBook::default();
        let slot = Slot::Stop("app-1".to_owned());
        book.set(
            slot.clone(),
            ActionState::WaitingForExit {
                operation: "op-1".to_owned(),
                since: SystemTime::UNIX_EPOCH,
            },
        );
        assert_eq!(notifier.observe(None, None, &book), Vec::new());
        book.settle(&slot, "op-1", OperationPhase::Completed);
        let notes = notifier.observe(None, None, &book);
        assert_eq!(
            notes,
            vec![Note {
                tag: "svalnir-stop-op-1".to_owned(),
                title: "Stop: Exited".to_owned(),
                body: "Operation op-1 completed: the agent confirmed the exit.".to_owned(),
            }]
        );
        assert_eq!(notifier.observe(None, None, &book), Vec::new());
    }

    #[test]
    fn an_unanswered_request_has_a_note_until_a_new_answer() {
        let mut notifier = Notifier::default();
        let mut book = ActionBook::default();
        book.set(Slot::Pause, ActionState::Queued);
        assert_eq!(notifier.observe(None, None, &book).len(), 1);
        assert_eq!(notifier.observe(None, None, &book), Vec::new());
        book.set(Slot::Pause, ActionState::Pending);
        assert_eq!(notifier.observe(None, None, &book), Vec::new());
        book.set(Slot::Pause, ActionState::Queued);
        assert_eq!(notifier.observe(None, None, &book).len(), 1);
    }
}
