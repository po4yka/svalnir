//! The Automation screen: the revision in effect, the recorded pause, and
//! each guard with its standing, its grant, and its thresholds. The pause
//! control, the enable and disable of a guard, and the rearm of an open
//! incident send their change to the agent (`crate::actions`).

use super::common::{
    CardWidth, Shown, ago, body_line, caption, card, fact, failed_body, inset, problem_lines,
    screen, shown, skeleton_rows, stale_line, until,
};
use super::controls::{action_button, open_enable, open_rearm, slot_status};
use crate::{
    actions::{Action, Slot},
    data::{
        model::GuardState,
        records::{AutomationSnapshot, GrantRow, GuardDetail, IncidentRow, PauseRow, RevisionRow},
        store::AppModel,
    },
    theme::tokens::{self, Tokens},
    ui::{
        action_button::{ActionButton, ButtonVariant},
        pill::{MonoTag, StatusPill, Tone},
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window,
    component::{ActiveTheme as _, IconName, h_flex, v_flex},
};
use std::time::SystemTime;

/// The pill text, the tone, and the sentence of the recorded pause at `now`.
/// `None` means that the authority record was not read: the state is not
/// known, which is not "not paused".
#[must_use]
pub fn pause_summary(pause: Option<&PauseRow>, now: SystemTime) -> (&'static str, Tone, String) {
    match pause {
        None => (
            "Unknown",
            Tone::Neutral,
            "The pause state was not read.".to_owned(),
        ),
        Some(PauseRow::NotPaused) => (
            "Not paused",
            Tone::Neutral,
            "No pause is recorded.".to_owned(),
        ),
        Some(PauseRow::Paused { since, until: None }) => (
            "Paused",
            Tone::Warning,
            format!(
                "Automation was paused {}. The pause has no end time.",
                ago(*since, now)
            ),
        ),
        Some(PauseRow::Paused {
            since,
            until: Some(deadline),
        }) => {
            let started: String = ago(*since, now);
            match until(*deadline, now) {
                Some(remaining) => (
                    "Paused",
                    Tone::Warning,
                    format!("Automation was paused {started}. The pause ends {remaining}."),
                ),
                // The agent ends a pause on its monotonic clock, so the
                // record can stay after the wall-clock deadline.
                None => (
                    "Pause ended",
                    Tone::Neutral,
                    format!(
                        "A pause from {started} is recorded and its end time has passed. The agent removes the record."
                    ),
                ),
            }
        }
    }
}

/// `value` with a space between each group of three digits.
#[must_use]
pub fn grouped(value: u64) -> String {
    let digits: String = value.to_string();
    let mut text: String = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push('\u{2009}');
        }
        text.push(digit);
    }
    text
}

/// The pill text and tone of a grant.
#[must_use]
pub const fn grant_pill(grant: &GrantRow) -> (&'static str, Tone) {
    if grant.revoked {
        ("Revoked", Tone::Negative)
    } else if grant.in_effect {
        ("In effect", Tone::Positive)
    } else {
        ("Not in effect", Tone::Warning)
    }
}

/// The text of the expiry of a grant at `now`.
#[must_use]
pub fn expiry_text(grant: &GrantRow, now: SystemTime) -> String {
    match grant.expires_at {
        None => "No expiry".to_owned(),
        Some(time) => until(time, now).unwrap_or_else(|| format!("Expired {}", ago(time, now))),
    }
}

/// "Yes", "No", or an em dash for a value that is not known.
const fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "\u{2014}",
    }
}

/// The Automation screen entity.
#[derive(Debug)]
pub struct AutomationScreen {
    model: Entity<AppModel>,
    activation: u64,
}

impl AutomationScreen {
    /// Creates the screen and observes the model.
    pub fn new(model: Entity<AppModel>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            activation: 1,
        }
    }

    /// Marks a new activation of the screen: the cards enter again.
    pub fn activate(&mut self, cx: &mut Context<Self>) {
        self.activation += 1;
        cx.notify();
    }
}

/// The pause control: a resume while a pause is recorded, else a timed and
/// an open pause. With no authority record read, the control is absent.
fn pause_controls(
    pause: Option<&PauseRow>,
    entity: &Entity<AppModel>,
    model: &AppModel,
) -> Option<AnyElement> {
    let busy: bool = model.actions.is_busy(&Slot::Pause);
    let row = h_flex().gap(tokens::SPACE_2);
    match pause? {
        PauseRow::Paused { .. } => Some(
            row.child(action_button(
                "automation-resume",
                "Resume automation",
                ButtonVariant::Secondary,
                entity,
                Action::Resume,
                busy,
            ))
            .into_any_element(),
        ),
        PauseRow::NotPaused => Some(
            row.child(action_button(
                "automation-pause-hour",
                "Pause automation for 1 hour",
                ButtonVariant::Secondary,
                entity,
                Action::Pause {
                    duration: Some(PAUSE_HOUR),
                },
                busy,
            ))
            .child(action_button(
                "automation-pause-open",
                "Pause until resumed",
                ButtonVariant::Quiet,
                entity,
                Action::Pause { duration: None },
                busy,
            ))
            .into_any_element(),
        ),
    }
}

/// The length of the timed pause.
const PAUSE_HOUR: std::time::Duration = std::time::Duration::from_secs(3600);

fn state_card(
    automation: &Shown<AutomationSnapshot>,
    entity: &Entity<AppModel>,
    model: &AppModel,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::Settings2, "Automation")
        .subtitle("Authority record of the journal");
    let body: AnyElement = match automation {
        Shown::Loading => skeleton_rows(4),
        Shown::Failed(reason) => failed_body("automation-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let stale: bool = stale_age.is_some();
            let (text, tone, sentence) = pause_summary(value.pause.as_ref(), now);
            header = header.aside(StatusPill::new(text, tone).id("automation-pause-pill"));
            let mut body = v_flex().gap(tokens::SPACE_2);
            body = body.child(body_line("automation-pause", sentence, stale, tokens));
            body = body
                .children(pause_controls(value.pause.as_ref(), entity, model))
                .children(slot_status(
                    "automation-pause-state",
                    model,
                    &Slot::Pause,
                    now,
                    tokens,
                ));
            if let Some(revision) = &value.revision {
                body = body
                    .child(fact(
                        "automation-revision",
                        "Revision in effect",
                        revision.id.clone(),
                        mono,
                        stale,
                        tokens,
                    ))
                    .child(fact(
                        "automation-profile",
                        "Profile",
                        revision.profile.clone(),
                        mono,
                        stale,
                        tokens,
                    ))
                    .child(fact(
                        "automation-activated",
                        "Activated",
                        ago(revision.activated_at, now),
                        mono,
                        stale,
                        tokens,
                    ));
            } else {
                let text: &str = if value.pause.is_none() {
                    // The authority record was not read: the revision is not known.
                    "The revision in effect was not read."
                } else if value.journal_present {
                    "No policy revision is in effect. No guard can act."
                } else {
                    "No journal exists in the state directory, so no policy revision is in effect. No guard can act."
                };
                body = body.child(body_line("automation-no-revision", text, true, tokens));
            }
            body = body.children(problem_lines("automation", &value.problems, tokens));
            if let Some(age) = stale_age {
                body = body.child(stale_line("automation-stale", age, tokens));
            }
            body = body.child(caption(
                "automation-control-note",
                "A change goes to the agent through the operation journal. With no agent, the window refuses the change and writes nothing. A pause stops new automatic interventions; it does not stop an admitted operation.",
                tokens,
            ));
            body.into_any_element()
        }
    };
    card(header, body)
}

fn grant_block(
    guard: &GuardDetail,
    grant: &GrantRow,
    now: SystemTime,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let name: &str = guard.name;
    let (text, tone) = grant_pill(grant);
    let mut classes = h_flex().flex_wrap().gap(tokens::SPACE_1);
    for class in &grant.action_classes {
        classes = classes.child(MonoTag::new(
            SharedString::from(format!("automation-class-{name}-{class}")),
            class.clone(),
        ));
    }
    let mut block = v_flex()
        .gap(tokens::SPACE_2)
        .child(
            h_flex()
                .gap(tokens::SPACE_2)
                .items_center()
                .justify_between()
                .child(caption(
                    SharedString::from(format!("automation-grant-title-{name}")),
                    "Action grant: the authorized action classes",
                    tokens,
                ))
                .child(
                    StatusPill::new(text, tone)
                        .id(SharedString::from(format!("automation-grant-{name}"))),
                ),
        )
        .child(classes);
    if grant.action_classes.is_empty() {
        block = block.child(caption(
            SharedString::from(format!("automation-no-class-{name}")),
            "The grant authorizes no action class.",
            tokens,
        ));
    }
    block = block
        .child(fact(
            SharedString::from(format!("automation-grant-id-{name}")),
            "Grant",
            grant.id.clone(),
            mono,
            stale,
            tokens,
        ))
        .child(fact(
            SharedString::from(format!("automation-grant-expiry-{name}")),
            "Expiry",
            expiry_text(grant, now),
            mono,
            stale,
            tokens,
        ));
    if !grant.rules.is_empty() {
        block = block.child(fact(
            SharedString::from(format!("automation-grant-rules-{name}")),
            "Rules",
            grant.rules.join(", "),
            mono,
            stale,
            tokens,
        ));
    }
    inset(block, tokens)
}

/// The enable or disable control of a guard. An enable needs a revision in
/// effect that gives the guard action classes.
fn guard_controls(
    guard: &GuardDetail,
    revision: Option<&RevisionRow>,
    entity: &Entity<AppModel>,
    model: &AppModel,
    tokens: &Tokens,
) -> AnyElement {
    let name: &str = guard.name;
    let policy = guard.policy;
    let busy: bool = model.actions.is_busy(&Slot::Guard(policy));
    let mut column = v_flex().gap(tokens::SPACE_2);
    if guard.enabled {
        column = column.child(h_flex().child(action_button(
            SharedString::from(format!("automation-disable-{name}")),
            "Disable",
            ButtonVariant::Secondary,
            entity,
            Action::Disable { policy },
            busy,
        )));
    } else if let Some(revision) = revision.filter(|_| !guard.scope_classes.is_empty()) {
        let entity: Entity<AppModel> = entity.clone();
        let revision: String = revision.id.clone();
        let classes = guard.scope_classes.clone();
        column = column.child(
            h_flex().child(
                ActionButton::new(
                    SharedString::from(format!("automation-enable-{name}")),
                    "Enable…",
                )
                .variant(ButtonVariant::Secondary)
                .loading(busy)
                .on_click(move |_, window, cx| {
                    open_enable(
                        &entity,
                        policy,
                        revision.clone(),
                        classes.clone(),
                        window,
                        cx,
                    );
                }),
            ),
        );
    } else {
        column = column.child(caption(
            SharedString::from(format!("automation-enable-note-{name}")),
            "The revision in effect gives this guard no action class, so it cannot be enabled. Activate a configuration that requests it.",
            tokens,
        ));
    }
    column
        .children(slot_status(
            SharedString::from(format!("automation-guard-state-{name}")),
            model,
            &Slot::Guard(policy),
            SystemTime::now(),
            tokens,
        ))
        .into_any_element()
}

/// One open incident with its rearm control.
fn incident_row(
    guard: &GuardDetail,
    incident: &IncidentRow,
    entity: &Entity<AppModel>,
    model: &AppModel,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let slot = Slot::Incident(incident.id.clone());
    let busy: bool = model.actions.is_busy(&slot);
    let (policy, id, generation) = (guard.policy, incident.id.clone(), incident.generation);
    let opener: Entity<AppModel> = entity.clone();
    let rearm = ActionButton::new(
        SharedString::from(format!("automation-rearm-{id}")),
        "Rearm…",
    )
    .variant(ButtonVariant::Quiet)
    .loading(busy)
    .on_click(move |_, window, cx| {
        open_rearm(&opener, policy, id.clone(), generation, window, cx);
    });
    let block = v_flex()
        .gap(tokens::SPACE_1)
        .child(fact(
            SharedString::from(format!("automation-incident-{}", incident.id)),
            "Open incident",
            format!("{} · generation {}", incident.id, incident.generation),
            mono,
            false,
            tokens,
        ))
        .child(h_flex().child(rearm))
        .children(slot_status(
            SharedString::from(format!("automation-incident-state-{}", incident.id)),
            model,
            &slot,
            SystemTime::now(),
            tokens,
        ));
    inset(block, tokens)
}

#[expect(
    clippy::too_many_arguments,
    reason = "a card builder takes the guard, its context, and the theme values"
)]
fn guard_card(
    guard: &GuardDetail,
    revision: Option<&RevisionRow>,
    entity: &Entity<AppModel>,
    model: &AppModel,
    now: SystemTime,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let name: &str = guard.name;
    let (text, tone) = match guard.standing {
        GuardState::Active => ("Active", Tone::Positive),
        GuardState::Inactive => ("Inactive", Tone::Neutral),
    };
    let header: ShellHeader = ShellHeader::new(IconName::Settings, name)
        .subtitle(guard.detail)
        .aside(
            StatusPill::new(text, tone).id(SharedString::from(format!("automation-guard-{name}"))),
        );
    let mut body = v_flex()
        .gap(tokens::SPACE_2)
        .child(fact(
            SharedString::from(format!("automation-enabled-{name}")),
            "Enabled by the user",
            yes_no(Some(guard.enabled)),
            mono,
            stale,
            tokens,
        ))
        .child(fact(
            SharedString::from(format!("automation-requested-{name}")),
            "Requested by the revision",
            yes_no(guard.requested),
            mono,
            stale,
            tokens,
        ))
        .child(guard_controls(guard, revision, entity, model, tokens));
    for incident in &guard.incidents {
        body = body.child(incident_row(guard, incident, entity, model, mono, tokens));
    }
    body = match &guard.grant {
        Some(grant) => body.child(grant_block(guard, grant, now, stale, mono, tokens)),
        None => body.child(caption(
            SharedString::from(format!("automation-no-grant-{name}")),
            "The guard has no action grant, so it has no authorized action class.",
            tokens,
        )),
    };
    if !guard.thresholds.is_empty() {
        let mut list = v_flex().gap(tokens::SPACE_1).child(caption(
            SharedString::from(format!("automation-thresholds-title-{name}")),
            "Thresholds of the revision. A size is in bytes, a time is in nanoseconds, and a count is a number.",
            tokens,
        ));
        for (key, value) in &guard.thresholds {
            list = list.child(fact(
                SharedString::from(format!("automation-threshold-{name}-{key}")),
                key,
                grouped(*value),
                mono,
                stale,
                tokens,
            ));
        }
        body = body.child(inset(list, tokens));
    }
    card(header, body)
}

impl Render for AutomationScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let entity: Entity<AppModel> = self.model.clone();
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let automation = shown(&model.automation, now, |automation| automation.captured_at);
        let mut cards: Vec<(CardWidth, AnyElement)> = vec![(
            CardWidth::Full,
            state_card(&automation, &entity, model, now, &mono, tokens),
        )];
        if let Shown::Data { value, stale_age } = &automation {
            for guard in &value.guards {
                cards.push((
                    CardWidth::Share,
                    guard_card(
                        guard,
                        value.revision.as_ref(),
                        &entity,
                        model,
                        now,
                        stale_age.is_some(),
                        &mono,
                        tokens,
                    ),
                ));
            }
        }
        screen("Automation", cards, self.activation, cx.reduce_motion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn grant(revoked: bool, in_effect: bool, expires_at: Option<SystemTime>) -> GrantRow {
        GrantRow {
            id: "g".to_owned(),
            action_classes: Vec::new(),
            rules: Vec::new(),
            granted_at: SystemTime::UNIX_EPOCH,
            expires_at,
            revoked,
            in_effect,
        }
    }

    #[test]
    fn a_pause_that_was_not_read_is_unknown_and_not_not_paused() {
        let (text, tone, _) = pause_summary(None, now());
        assert_eq!((text, tone), ("Unknown", Tone::Neutral));
        let (text, _, sentence) = pause_summary(Some(&PauseRow::NotPaused), now());
        assert_eq!(text, "Not paused");
        assert_eq!(sentence, "No pause is recorded.");
    }

    #[test]
    fn a_pause_states_its_start_and_its_end() {
        let since: SystemTime = now() - Duration::from_mins(10);
        let (text, tone, sentence) =
            pause_summary(Some(&PauseRow::Paused { since, until: None }), now());
        assert_eq!((text, tone), ("Paused", Tone::Warning));
        assert_eq!(
            sentence,
            "Automation was paused 10 min ago. The pause has no end time."
        );
        let (_, _, sentence) = pause_summary(
            Some(&PauseRow::Paused {
                since,
                until: Some(now() + Duration::from_mins(20)),
            }),
            now(),
        );
        assert_eq!(
            sentence,
            "Automation was paused 10 min ago. The pause ends in 20 min."
        );
        let (text, tone, _) = pause_summary(
            Some(&PauseRow::Paused {
                since,
                until: Some(now() - Duration::from_secs(5)),
            }),
            now(),
        );
        assert_eq!((text, tone), ("Pause ended", Tone::Neutral));
    }

    #[test]
    fn a_grant_pill_has_three_states() {
        assert_eq!(grant_pill(&grant(true, false, None)).0, "Revoked");
        assert_eq!(grant_pill(&grant(false, true, None)).0, "In effect");
        assert_eq!(grant_pill(&grant(false, false, None)).0, "Not in effect");
    }

    #[test]
    fn the_expiry_is_none_remaining_or_passed() {
        assert_eq!(expiry_text(&grant(false, true, None), now()), "No expiry");
        assert_eq!(
            expiry_text(
                &grant(false, true, Some(now() + Duration::from_hours(48))),
                now()
            ),
            "in 2 d"
        );
        assert_eq!(
            expiry_text(
                &grant(false, false, Some(now() - Duration::from_hours(3))),
                now()
            ),
            "Expired 3 h ago"
        );
    }

    #[test]
    fn digits_are_in_groups_of_three() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1\u{2009}000");
        assert_eq!(
            grouped(40_000_000_000),
            "40\u{2009}000\u{2009}000\u{2009}000"
        );
    }
}
