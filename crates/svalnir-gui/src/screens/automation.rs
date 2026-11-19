//! The Automation screen: the revision in effect, the recorded pause, and
//! each guard with its standing, its grant, and its thresholds. The screen
//! shows state only; it has no control that changes a policy.

use super::common::{
    CardWidth, Shown, ago, body_line, caption, card, fact, failed_body, inset, problem_lines,
    screen, shown, skeleton_rows, stale_line, until,
};
use crate::{
    data::{
        model::GuardState,
        records::{AutomationSnapshot, GrantRow, GuardDetail, PauseRow},
        store::AppModel,
    },
    theme::tokens::{self, Tokens},
    ui::{
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

fn state_card(
    automation: &Shown<AutomationSnapshot>,
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
                let text: &str = if value.journal_present {
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
                "automation-read-only-note",
                "This window sends no request, so it has no control that changes a policy or the pause. Use the commands `svalnir policy` and `svalnir agent`.",
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

fn guard_card(
    guard: &GuardDetail,
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
        ));
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
                SharedString::from(format!("automation-threshold-{key}")),
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
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let automation = shown(&model.automation, now, |automation| automation.captured_at);
        let mut cards: Vec<(CardWidth, AnyElement)> =
            vec![(CardWidth::Full, state_card(&automation, now, &mono, tokens))];
        if let Shown::Data { value, stale_age } = &automation {
            for guard in &value.guards {
                cards.push((
                    CardWidth::Share,
                    guard_card(guard, now, stale_age.is_some(), &mono, tokens),
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
