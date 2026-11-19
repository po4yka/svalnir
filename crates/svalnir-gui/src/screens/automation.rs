//! The Automation screen: the revision in effect, the recorded pause, and
//! each guard with its standing, its grant, and its thresholds. The pause
//! control, the enable and disable of a guard, and the rearm of an open
//! incident send their change to the agent (`crate::actions`).

use super::agent_state::{
    cooldown_facts, incident_block, span_left, status_age_text, threshold_text,
};
use super::common::{
    CardWidth, Shown, ago, body_line, caption, card, fact, failed_body, inset, problem_lines,
    screen, shown, skeleton_rows, stale_line, until,
};
use super::controls::{action_button, open_enable, open_rearm, slot_status};
use crate::{
    actions::{Action, Slot},
    data::{
        model::{GuardState, Measured},
        records::{
            AutomationSnapshot, ControllerSnapshot, CooldownSubject, FreshMeasurement, GrantRow,
            GuardDetail, IncidentRow, PauseKind, PauseRow, RevisionRow,
        },
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
use std::time::{Duration, SystemTime};
use svalnir_core::policy::PolicyId;

/// The pill text, the tone, and the sentence of the pause at `now`, as the
/// agent decided it at `read_at`. `None` means that the authority record
/// was not read: the state is not known, which is not "not paused".
#[must_use]
pub fn pause_summary(
    pause: Option<&PauseRow>,
    read_at: SystemTime,
    now: SystemTime,
) -> (&'static str, Tone, String) {
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
        Some(PauseRow::Paused {
            since,
            kind,
            remaining,
            until: deadline,
        }) => {
            let started: String = ago(*since, now);
            let sentence: String = match (kind, remaining) {
                (PauseKind::Indefinite, _) => {
                    format!("Automation was paused {started}. The pause has no end time.")
                }
                (PauseKind::Retained, _) => format!(
                    "Automation was paused {started}, in a different boot or clock of the agent. Its end cannot be established, so it stays until you resume."
                ),
                (PauseKind::Timed, Some(remaining)) => {
                    // The monotonic time that remained at the reading, less
                    // the time since the reading.
                    let left: Duration =
                        remaining.saturating_sub(now.duration_since(read_at).unwrap_or_default());
                    if left.as_secs() == 0 {
                        format!("Automation was paused {started}. The pause ends now.")
                    } else {
                        format!(
                            "Automation was paused {started}. The pause ends in {}.",
                            span_left(left)
                        )
                    }
                }
                (PauseKind::Timed, None) => match deadline.and_then(|time| until(time, now)) {
                    Some(text) => {
                        format!("Automation was paused {started}. The pause ends {text}.")
                    }
                    None => format!("Automation was paused {started}. The pause has an end time."),
                },
            };
            ("Paused", Tone::Warning, sentence)
        }
        Some(PauseRow::Expired { since }) => (
            "Pause ended",
            Tone::Neutral,
            format!(
                "A pause from {} reached its end on the clock of the agent. It inhibits nothing, and the agent removes the record.",
                ago(*since, now)
            ),
        ),
    }
}

/// The sentence about a fresh measurement after the end of a pause. `None`
/// when no pause ended.
#[must_use]
pub const fn measurement_sentence(measurement: FreshMeasurement) -> Option<&'static str> {
    match measurement {
        FreshMeasurement::NotNeeded => None,
        FreshMeasurement::Awaiting => {
            Some("Automatic work waits for a measurement that is newer than the end of the pause.")
        }
        FreshMeasurement::NotKnown => Some(
            "Whether the agent has a measurement that is newer than the end of the pause is not known: the journal does not record it.",
        ),
    }
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
        // An expired pause has a record that a resume removes.
        PauseRow::Paused { .. } | PauseRow::Expired { .. } => Some(
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
const PAUSE_HOUR: Duration = Duration::from_secs(3600);

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
            let (text, tone, sentence) =
                pause_summary(value.pause.as_ref(), value.captured_at, now);
            header = header.aside(StatusPill::new(text, tone).id("automation-pause-pill"));
            let mut body = v_flex().gap(tokens::SPACE_2);
            body = body.child(body_line("automation-pause", sentence, stale, tokens));
            if let Some(sentence) = measurement_sentence(value.measurement) {
                body = body.child(caption("automation-pause-measurement", sentence, tokens));
            }
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
#[expect(
    clippy::too_many_arguments,
    reason = "a row builder takes the incident, its context, and the theme values"
)]
fn incident_row(
    guard: &GuardDetail,
    incident: &IncidentRow,
    controller: &Shown<ControllerSnapshot>,
    entity: &Entity<AppModel>,
    model: &AppModel,
    now: SystemTime,
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
        ))
        .child(incident_usage(incident, controller, now, mono, tokens));
    inset(block, tokens)
}

/// The usage of an open incident from the controller record, or the
/// reason that it is not shown.
fn incident_usage(
    incident: &IncidentRow,
    controller: &Shown<ControllerSnapshot>,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let id: &str = incident.id.as_str();
    let missing = |text: String| {
        caption(
            SharedString::from(format!("automation-incident-usage-{id}")),
            text,
            tokens,
        )
    };
    match controller {
        Shown::Loading => skeleton_rows(1),
        Shown::Failed(reason) => missing(format!("The usage is not shown: {reason}")),
        Shown::Data { value, stale_age } => match (&value.rows, value.incident(id)) {
            (Measured::Unavailable(reason), _) => {
                missing(format!("The usage is not shown: {reason}"))
            }
            (Measured::Value(_), None) => missing(
                "The controller record has no entry for this incident, so its usage is not shown."
                    .to_owned(),
            ),
            (Measured::Value(_), Some(usage)) => v_flex()
                .gap(tokens::SPACE_1)
                .child(incident_block(
                    "automation",
                    usage,
                    now,
                    stale_age.is_some(),
                    mono,
                    tokens,
                ))
                .children(status_age_text(value.status_age).map(|text| {
                    caption(
                        SharedString::from(format!("automation-incident-age-{id}")),
                        text,
                        tokens,
                    )
                }))
                .into_any_element(),
        },
    }
}

/// The pass cooldowns of the disk guard from the controller record.
fn disk_cooldowns(
    controller: &Shown<ControllerSnapshot>,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let note = |text: String| vec![caption("automation-disk-cooldown-note", text, tokens)];
    let rows = match controller {
        Shown::Loading => return vec![skeleton_rows(1)],
        Shown::Failed(reason) => {
            return note(format!("The pass cooldowns are not shown: {reason}"));
        }
        Shown::Data { value, .. } => match &value.rows {
            Measured::Unavailable(reason) => {
                return note(format!("The pass cooldowns are not shown: {reason}"));
            }
            Measured::Value(rows) => rows,
        },
    };
    let facts: Vec<AnyElement> = cooldown_facts(
        "automation-disk",
        &rows.cooldowns,
        |subject| matches!(subject, CooldownSubject::DiskPass { .. }),
        stale,
        mono,
        tokens,
    );
    if facts.is_empty() {
        note("The controller record has no pass cooldown.".to_owned())
    } else {
        facts
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "a card builder takes the guard, its context, and the theme values"
)]
fn guard_card(
    guard: &GuardDetail,
    revision: Option<&RevisionRow>,
    controller: &Shown<ControllerSnapshot>,
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
        body = body.child(incident_row(
            guard, incident, controller, entity, model, now, mono, tokens,
        ));
    }
    if guard.policy == PolicyId::DiskGuard {
        body = body.children(disk_cooldowns(controller, stale, mono, tokens));
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
            "Thresholds of the revision, each with the unit of its configuration field.",
            tokens,
        ));
        for threshold in &guard.thresholds {
            let key: &str = threshold.key.as_str();
            list = list.child(fact(
                SharedString::from(format!("automation-threshold-{name}-{key}")),
                key,
                threshold_text(threshold.value),
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
        let controller = shown(&model.controller, now, |controller| controller.captured_at);
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
                        &controller,
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
        let (text, tone, _) = pause_summary(None, now(), now());
        assert_eq!((text, tone), ("Unknown", Tone::Neutral));
        let (text, _, sentence) = pause_summary(Some(&PauseRow::NotPaused), now(), now());
        assert_eq!(text, "Not paused");
        assert_eq!(sentence, "No pause is recorded.");
    }

    fn paused(kind: PauseKind, remaining: Option<Duration>) -> PauseRow {
        PauseRow::Paused {
            since: now() - Duration::from_mins(10),
            remaining,
            until: remaining.map(|remaining| now() + remaining),
            kind,
        }
    }

    #[test]
    fn a_pause_states_its_start_and_its_end_on_the_clock_of_the_agent() {
        let (text, tone, sentence) =
            pause_summary(Some(&paused(PauseKind::Indefinite, None)), now(), now());
        assert_eq!((text, tone), ("Paused", Tone::Warning));
        assert_eq!(
            sentence,
            "Automation was paused 10 min ago. The pause has no end time."
        );
        let timed = paused(PauseKind::Timed, Some(Duration::from_mins(20)));
        let (_, _, sentence) = pause_summary(Some(&timed), now(), now());
        assert_eq!(
            sentence,
            "Automation was paused 10 min ago. The pause ends in 20 min."
        );
        // The time since the reading counts down the monotonic remainder.
        let (_, _, sentence) = pause_summary(Some(&timed), now(), now() + Duration::from_mins(5));
        assert!(
            sentence.ends_with("The pause ends in 15 min."),
            "{sentence}"
        );
        let (_, _, sentence) = pause_summary(Some(&timed), now(), now() + Duration::from_mins(30));
        assert!(sentence.ends_with("The pause ends now."), "{sentence}");
        let (text, _, sentence) =
            pause_summary(Some(&paused(PauseKind::Retained, None)), now(), now());
        assert_eq!(text, "Paused");
        assert!(sentence.contains("stays until you resume"), "{sentence}");
    }

    #[test]
    fn an_expired_pause_inhibits_nothing() {
        let expired = PauseRow::Expired {
            since: now() - Duration::from_hours(2),
        };
        let (text, tone, _) = pause_summary(Some(&expired), now(), now());
        assert_eq!((text, tone), ("Pause ended", Tone::Neutral));
        assert_eq!(measurement_sentence(FreshMeasurement::NotNeeded), None);
        assert!(measurement_sentence(FreshMeasurement::NotKnown).is_some());
        assert!(measurement_sentence(FreshMeasurement::Awaiting).is_some());
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
}
