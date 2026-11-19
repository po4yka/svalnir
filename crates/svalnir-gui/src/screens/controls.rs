//! The controls that change state, and their confirmations (`DESIGN.md`
//! §4 and §7).
//!
//! A confirmation names the object and the consequence, and binds what it
//! shows: the enable binds the revision and the action classes that the
//! dialog shows, the rearm binds the generation, and the stop binds the
//! plan whose processes the dialog lists. The cancel button is the first
//! focus stop, so the `danger` button is never the default. Escape cancels;
//! a click on the backdrop does not.

use crate::{
    actions::{Action, ActionState, Proposal, Slot, StopProposal, live::policy_label},
    data::store::AppModel,
    screens::common::{body_line, caption, until},
    theme::tokens::{self, Tokens},
    ui::{
        action_button::{ActionButton, ButtonVariant},
        action_status::action_status,
        pill::MonoTag,
    },
};
use gpui_kit::{
    AnyElement, App, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, Window,
    component::{ActiveTheme as _, WindowExt as _, dialog::Dialog, h_flex, v_flex},
};
use std::{sync::Arc, time::SystemTime};
use svalnir_core::{action::ActionClass, policy::PolicyId};

/// The most processes that a stop confirmation lists by name.
pub const LISTED_TARGETS_MAX: usize = 12;

/// The state line of `slot`, when it has a state.
pub fn slot_status(
    id: impl Into<SharedString>,
    model: &AppModel,
    slot: &Slot,
    now: SystemTime,
    tokens: &Tokens,
) -> Option<AnyElement> {
    model
        .actions
        .state(slot)
        .map(|state| action_status(id, state, now, tokens))
}

/// A button that sends `action` through the model.
pub fn action_button(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    variant: ButtonVariant,
    model: &Entity<AppModel>,
    action: Action,
    busy: bool,
) -> ActionButton {
    let model: Entity<AppModel> = model.clone();
    ActionButton::new(id, label)
        .variant(variant)
        .loading(busy)
        .on_click(move |_, _, cx| {
            let action: Action = action.clone();
            model.update(cx, |model, cx| model.run_action(action, cx));
        })
}

/// What an action class lets an automatic intervention do, as a phrase.
#[must_use]
pub const fn class_phrase(class: &ActionClass) -> &'static str {
    match class {
        ActionClass::EvictRegenerableData => "remove approved regenerable data",
        ActionClass::RequestApplicationExit => "ask an application to quit",
        ActionClass::ForceApplicationExit => "force an application to quit",
        ActionClass::MoveToTrash => "move files to the Trash",
        ActionClass::DeleteSelectedFiles => "delete files permanently",
        ActionClass::Unrecognized(_) => "act with a different action class",
    }
}

/// The consequence sentence of an enable with `classes`.
#[must_use]
pub fn enable_consequence(classes: &[ActionClass]) -> String {
    if classes.is_empty() {
        return "An eligible incident then proceeds with no further question.".to_owned();
    }
    let phrases: Vec<&str> = classes.iter().map(class_phrase).collect();
    format!(
        "An eligible incident then proceeds with no further question. The guard can {}.",
        phrases.join(", and ")
    )
}

fn footer(children: Vec<AnyElement>) -> AnyElement {
    h_flex()
        .w_full()
        .justify_end()
        .gap(tokens::SPACE_2)
        .children(children)
        .into_any_element()
}

fn cancel_button(model: Option<Entity<AppModel>>) -> AnyElement {
    ActionButton::new("confirm-cancel", "Cancel")
        .variant(ButtonVariant::Secondary)
        .on_click(move |_, window, cx| {
            if let Some(model) = &model {
                model.update(cx, AppModel::close_stop);
            }
            window.close_dialog(cx);
        })
        .into_any_element()
}

fn confirm_button(
    id: &'static str,
    label: String,
    variant: ButtonVariant,
    model: Entity<AppModel>,
    action: Action,
) -> AnyElement {
    ActionButton::new(id, label)
        .variant(variant)
        .on_click(move |_, window, cx| {
            let action: Action = action.clone();
            model.update(cx, |model, cx| model.run_action(action, cx));
            window.close_dialog(cx);
        })
        .into_any_element()
}

/// Opens the confirmation of the enable of `policy` for `revision` with
/// `classes`.
pub fn open_enable(
    model: &Entity<AppModel>,
    policy: PolicyId,
    revision: String,
    classes: Vec<ActionClass>,
    window: &mut Window,
    cx: &mut App,
) {
    let model: Entity<AppModel> = model.clone();
    window.open_dialog(cx, move |dialog: Dialog, _window, cx| {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let name: String = policy_label(policy);
        let mut tags = h_flex().flex_wrap().gap(tokens::SPACE_1);
        for class in &classes {
            tags = tags.child(MonoTag::new(
                SharedString::from(format!("confirm-class-{}", class.as_str())),
                class.as_str().to_owned(),
            ));
        }
        let action = Action::Enable {
            policy,
            revision: revision.clone(),
            classes: classes.clone(),
        };
        dialog
            .title(format!("Enable the {name}"))
            .overlay_closable(false)
            .close_button(false)
            .child(
                v_flex()
                    .gap(tokens::SPACE_2)
                    .child(body_line(
                        "confirm-object",
                        format!("Revision {revision} is in effect. The grant covers these action classes:"),
                        false,
                        tokens,
                    ))
                    .child(tags)
                    .child(body_line(
                        "confirm-consequence",
                        enable_consequence(&classes),
                        false,
                        tokens,
                    )),
            )
            .footer(footer(vec![
                cancel_button(None),
                confirm_button(
                    "confirm-ok",
                    format!("Enable the {name}"),
                    ButtonVariant::Primary,
                    model.clone(),
                    action,
                ),
            ]))
    });
}

/// Opens the confirmation of the rearm of `incident`.
pub fn open_rearm(
    model: &Entity<AppModel>,
    policy: PolicyId,
    incident: String,
    generation: u64,
    window: &mut Window,
    cx: &mut App,
) {
    let model: Entity<AppModel> = model.clone();
    window.open_dialog(cx, move |dialog: Dialog, _window, cx| {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let action = Action::Rearm {
            policy,
            incident: incident.clone(),
            generation,
        };
        dialog
            .title(format!("Rearm incident {incident}"))
            .overlay_closable(false)
            .close_button(false)
            .child(
                v_flex()
                    .gap(tokens::SPACE_2)
                    .child(body_line(
                        "confirm-object",
                        format!(
                            "Incident {incident} of the {}: budget generation {generation} ends, and a new generation starts with no usage.",
                            policy_label(policy)
                        ),
                        false,
                        tokens,
                    ))
                    .child(body_line(
                        "confirm-consequence",
                        "The guard can then act again for this incident. The usage of the earlier generation stays in the history. A rearm does not end a cooldown.",
                        false,
                        tokens,
                    )),
            )
            .footer(footer(vec![
                cancel_button(None),
                confirm_button(
                    "confirm-ok",
                    "Rearm".to_owned(),
                    ButtonVariant::Secondary,
                    model.clone(),
                    action,
                ),
            ]))
    });
}

/// The body of a stop confirmation with ready plans.
fn stop_body(proposal: &StopProposal, now: SystemTime, tokens: &Tokens) -> AnyElement {
    let mut list = v_flex().gap(tokens::SPACE_1);
    for target in proposal.targets.iter().take(LISTED_TARGETS_MAX) {
        list = list.child(MonoTag::new(
            SharedString::from(format!("confirm-target-{}", target.pid)),
            format!("PID {}  {}", target.pid, target.name),
        ));
    }
    let more: usize = proposal.targets.len().saturating_sub(LISTED_TARGETS_MAX);
    if more > 0 {
        list = list.child(caption(
            "confirm-more",
            format!("and {more} more processes of the same group"),
            tokens,
        ));
    }
    let count: usize = proposal.targets.len();
    let processes: &str = if count == 1 { "process" } else { "processes" };
    v_flex()
        .gap(tokens::SPACE_2)
        .child(body_line(
            "confirm-object",
            format!(
                "The plans bind {count} {processes} of {}. A process that starts later is not in the plans.",
                proposal.name
            ),
            false,
            tokens,
        ))
        .child(list)
        .child(body_line(
            "confirm-consequence",
            "Quit asks each process to exit. Force quit ends each process at once. Unsaved data of the processes can be lost. A stop has no undo.",
            false,
            tokens,
        ))
        .child(caption(
            "confirm-expiry",
            until(proposal.expires_at, now).map_or_else(
                || "The plans expire now.".to_owned(),
                |left| format!("The plans expire in {left}."),
            ),
            tokens,
        ))
        .into_any_element()
}

/// Opens the stop confirmation of the group `instance`, and makes its
/// plans in the background. The dialog shows the processes that the plans
/// bind; it removes the stop buttons when the plans expire.
pub fn open_stop(
    model: &Entity<AppModel>,
    instance: &str,
    name: &str,
    window: &mut Window,
    cx: &mut App,
) {
    let (instance, name): (String, String) = (instance.to_owned(), name.to_owned());
    model.update(cx, |model, cx| model.prepare_stop(&instance, &name, cx));
    let model: Entity<AppModel> = model.clone();
    window.open_dialog(cx, move |dialog: Dialog, _window, cx| {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let now: SystemTime = SystemTime::now();
        let close_model: Entity<AppModel> = model.clone();
        let dialog = dialog
            .title(format!("Stop {name}"))
            .overlay_closable(false)
            .close_button(false)
            .on_close(move |_, _, cx| {
                close_model.update(cx, AppModel::close_stop);
            });
        let proposal: Option<Proposal> = model
            .read(cx)
            .actions
            .stop
            .as_ref()
            .filter(|(open, _)| *open == instance)
            .map(|(_, proposal)| proposal.clone());
        match proposal {
            None | Some(Proposal::Preparing) => dialog
                .child(body_line(
                    "confirm-preparing",
                    "Reading the processes and making the plans. Nothing is recorded yet.",
                    true,
                    tokens,
                ))
                .footer(footer(vec![cancel_button(Some(model.clone()))])),
            Some(Proposal::Failed(state)) => dialog
                .child(action_status("confirm-failed", &state, now, tokens))
                .footer(footer(vec![cancel_button(Some(model.clone()))])),
            Some(Proposal::Ready(proposal)) if proposal.expired(now) => {
                let again: Entity<AppModel> = model.clone();
                let (instance, name) = (instance.clone(), name.clone());
                dialog
                    .child(body_line(
                        "confirm-expired",
                        "The plans expired, so they cannot be sent. Make new plans from a new reading of the processes.",
                        false,
                        tokens,
                    ))
                    .footer(footer(vec![
                        cancel_button(Some(model.clone())),
                        ActionButton::new("confirm-again", "Make new plans")
                            .variant(ButtonVariant::Secondary)
                            .on_click(move |_, _, cx| {
                                again.update(cx, |model, cx| model.prepare_stop(&instance, &name, cx));
                            })
                            .into_any_element(),
                    ]))
            }
            Some(Proposal::Ready(proposal)) => {
                let quit = Action::Stop {
                    proposal: Arc::clone(&proposal),
                    force: false,
                };
                let force = Action::Stop {
                    proposal: Arc::clone(&proposal),
                    force: true,
                };
                dialog
                    .child(stop_body(&proposal, now, tokens))
                    .footer(footer(vec![
                        cancel_button(Some(model.clone())),
                        confirm_button(
                            "confirm-ok",
                            format!("Quit {name}"),
                            ButtonVariant::Secondary,
                            model.clone(),
                            quit,
                        ),
                        confirm_button(
                            "confirm-force",
                            format!("Force quit {name}"),
                            ButtonVariant::Danger,
                            model.clone(),
                            force,
                        ),
                    ]))
            }
        }
    });
}

/// Whether a state is a refusal or an unavailable agent: the control shows
/// it and takes a new request.
#[must_use]
pub const fn is_final_refusal(state: &ActionState) -> bool {
    matches!(
        state,
        ActionState::Refused { .. } | ActionState::Unavailable(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enable_consequence_names_each_class() {
        let text = enable_consequence(&[
            ActionClass::RequestApplicationExit,
            ActionClass::ForceApplicationExit,
        ]);
        assert_eq!(
            text,
            "An eligible incident then proceeds with no further question. The guard can ask an application to quit, and force an application to quit."
        );
    }

    #[test]
    fn a_refusal_takes_a_new_request() {
        assert!(is_final_refusal(&ActionState::refused("plan_expired")));
        assert!(!is_final_refusal(&ActionState::Pending));
    }
}
