//! The History screen: the latest operations of the journal with their
//! trigger, their steps, their target results, and the observed change of a
//! resource. The screen shows state only.

use super::common::{
    CardWidth, Shown, ago, body_line, bytes_text, caption, card, cell, failed_body, head,
    mono_text, problem_lines, screen, shown, skeleton_rows, stale_line,
};
use crate::{
    data::{
        model::{Measured, OperationPhase},
        records::{EffectRow, HISTORY_ROWS_MAX, HistorySnapshot, OperationDetail},
        store::AppModel,
    },
    screens::overview::phase_pill,
    theme::tokens::{self, Tokens, to_hsla},
    ui::{
        data_state::format_bytes,
        pill::{StatusPill, Tone},
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, IntoElement, ParentElement, Render, Rgba, Role, SharedString,
    Styled, TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, IconName, Sizable as _,
        table::{Table, TableBody, TableHeader, TableRow},
        v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::time::SystemTime;

/// The tone of one step of an operation, by the table "Operation states" of
/// `DESIGN.md`.
#[must_use]
pub fn step_tone(state: &str) -> Tone {
    match state {
        "Completed" => Tone::Positive,
        "Failed" => Tone::Negative,
        "IntentCommitted" | "DispatchConsumed" | "Verifying" => Tone::Brand,
        "Admitted" | "NoAction" => Tone::Neutral,
        // `Partial`, `Incomplete`, and a state that this build does not
        // know: the outcome is not complete or not known.
        _ => Tone::Warning,
    }
}

/// The text of the steps: the number of steps and the count of each state,
/// in the order of the first occurrence.
#[must_use]
pub fn steps_text(steps: &[String]) -> String {
    if steps.is_empty() {
        return "No step".to_owned();
    }
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for step in steps {
        match counts.iter_mut().find(|(name, _)| *name == step.as_str()) {
            Some((_, count)) => *count += 1,
            None => counts.push((step.as_str(), 1)),
        }
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(name, count)| format!("{count} {name}"))
        .collect();
    let noun: &str = if steps.len() == 1 { "step" } else { "steps" };
    format!("{} {noun}: {}", steps.len(), parts.join(", "))
}

/// The text of the target results: the count of each effect.
#[must_use]
pub fn effects_text(effects: &[(String, usize)]) -> String {
    if effects.is_empty() {
        return "No target result".to_owned();
    }
    effects
        .iter()
        .map(|(name, count)| format!("{count} {name}"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// The text of one resource observation. A change has a value only when the
/// two readings have a value; an unavailable reading is an em dash.
#[must_use]
pub fn resource_text(effect: &EffectRow) -> String {
    match effect {
        EffectRow::Capacity { before, after } => {
            let change: String = match (before, after) {
                (Measured::Value(before), Measured::Value(after)) => {
                    let (sign, bytes) = if after >= before {
                        ("+", after - before)
                    } else {
                        ("\u{2212}", before - after)
                    };
                    let (value, unit) = format_bytes(bytes);
                    format!(", change {sign}{value} {unit}")
                }
                _ => ", change not known".to_owned(),
            };
            format!(
                "Available capacity {} before, {} after{change}",
                bytes_text(before),
                bytes_text(after)
            )
        }
        EffectRow::Pressure { before, after } => {
            let text = |state: &Measured<String>| -> String {
                match state {
                    Measured::Value(name) => name.clone(),
                    Measured::Unavailable(_) => "\u{2014}".to_owned(),
                }
            };
            format!(
                "Memory pressure {} before, {} after",
                text(before),
                text(after)
            )
        }
        EffectRow::Unrecognized => {
            "An observation of a kind that this build does not know".to_owned()
        }
    }
}

/// The lines of the observed change of an operation. With no observation
/// the line says that the journal has no measurement, which is not a
/// measurement of no change.
#[must_use]
pub fn observed_lines(operation: &OperationDetail) -> Vec<String> {
    if operation.resources.is_empty() {
        return vec!["No measurement in the journal".to_owned()];
    }
    operation.resources.iter().map(resource_text).collect()
}

/// The icon of a phase, from the icons that the bundle has.
#[must_use]
pub fn phase_icon(phase: OperationPhase) -> Option<IconName> {
    match phase {
        OperationPhase::Pending => None,
        OperationPhase::Running => Some(IconName::Loader),
        OperationPhase::Completed => Some(IconName::Check),
        OperationPhase::Partial => Some(IconName::CircleAlert),
        OperationPhase::NoAction => Some(IconName::Minus),
        OperationPhase::Failed => Some(IconName::CircleX),
        OperationPhase::Unknown => Some(IconName::TriangleAlert),
    }
}

/// The accessible sentence of one operation row.
#[must_use]
pub fn operation_label(operation: &OperationDetail, now: SystemTime) -> String {
    let (state, _) = phase_pill(operation.phase, &operation.state_text);
    format!(
        "Operation {}, {state}, admitted {}, trigger {}, {}, {}, {}",
        operation.operation_id,
        ago(operation.admitted_at, now),
        operation.trigger,
        steps_text(&operation.steps),
        effects_text(&operation.effects),
        observed_lines(operation).join("; ")
    )
}

/// The History screen entity.
#[derive(Debug)]
pub struct HistoryScreen {
    model: Entity<AppModel>,
    activation: u64,
}

impl HistoryScreen {
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

/// The tick track of an operation: one tick for each step, in the tone of
/// its state. The text of the steps is the label and the caption.
fn tick_track(operation: &OperationDetail, tokens: &Tokens) -> AnyElement {
    let label: String = steps_text(&operation.steps);
    // 2 px: the gap of the ticks of the track, not layout spacing.
    let mut track = div()
        .id(SharedString::from(format!(
            "history-steps-{}",
            operation.operation_id
        )))
        .role(Role::Image)
        .test_support()
        .aria_label(label.clone())
        .flex()
        .flex_wrap()
        .gap(px(2.0));
    for step in &operation.steps {
        let color: Rgba = match step_tone(step) {
            Tone::Positive => tokens.positive,
            Tone::Negative => tokens.negative,
            Tone::Warning => tokens.warning,
            Tone::Brand => tokens.brand,
            Tone::Neutral => tokens.border,
        };
        // A tick of the dense scale of the cell: 4 px wide, 14 px high.
        track = track.child(
            div()
                .w(tokens::SPACE_1)
                .h(tokens::CELL_SIZE)
                .rounded(px(1.0))
                .bg(to_hsla(color)),
        );
    }
    v_flex()
        .gap(tokens::SPACE_1)
        .min_w_0()
        .child(track)
        .child(
            div()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(label),
        )
        .into_any_element()
}

fn two_lines(first: AnyElement, second: impl Into<SharedString>, tokens: &Tokens) -> AnyElement {
    v_flex()
        .gap(tokens::SPACE_1)
        .min_w_0()
        .child(first)
        .child(
            div()
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(second.into()),
        )
        .into_any_element()
}

fn operation_table(
    snapshot: &HistorySnapshot,
    now: SystemTime,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let rows = snapshot.operations.iter().map(|operation| {
        let id: &str = &operation.operation_id;
        let (phase_text, tone) = phase_pill(operation.phase, &operation.state_text);
        let mut pill: StatusPill = StatusPill::new(phase_text.to_owned(), tone)
            .id(SharedString::from(format!("history-state-{id}")));
        if let Some(icon) = phase_icon(operation.phase) {
            pill = pill.icon(icon);
        }
        let origin: &str = if operation.automatic {
            "Started by a guard"
        } else {
            "Started by the user"
        };
        // One class on each line: a class name does not break in a word.
        let mut classes = v_flex().gap(tokens::SPACE_1).min_w_0();
        for class in &operation.action_classes {
            classes = classes.child(mono_text(class.clone(), mono, false, tokens));
        }
        let mut observed = v_flex()
            .id(SharedString::from(format!("history-observed-{id}")))
            .test_support()
            .aria_label(observed_lines(operation).join("; "))
            .gap(tokens::SPACE_1)
            .min_w_0()
            .text_size(px(12.0));
        for line in observed_lines(operation) {
            observed = observed.child(div().child(line));
        }
        observed = observed.child(
            div()
                .text_color(to_hsla(tokens.muted_foreground))
                .child(effects_text(&operation.effects)),
        );
        TableRow::new()
            .id(SharedString::from(format!("history-row-{id}")))
            .child(cell(
                two_lines(
                    div()
                        .id(SharedString::from(format!("history-operation-{id}")))
                        .test_support()
                        .aria_label(operation_label(operation, now))
                        .child(mono_text(id.to_owned(), mono, stale, tokens))
                        .into_any_element(),
                    ago(operation.admitted_at, now),
                    tokens,
                ),
                3,
                false,
            ))
            .child(cell(
                two_lines(
                    mono_text(operation.trigger.clone(), mono, false, tokens),
                    origin,
                    tokens,
                ),
                4,
                false,
            ))
            .child(cell(classes, 4, false))
            .child(cell(tick_track(operation, tokens), 3, false))
            .child(cell(pill, 3, false))
            .child(cell(observed, 4, false))
    });
    Table::new()
        .small()
        .accessibility_label("Operations of the journal, newest first")
        .child(
            TableHeader::new().child(
                TableRow::new()
                    .child(head("Operation", 3, false, tokens))
                    .child(head("Trigger", 4, false, tokens))
                    .child(head("Action classes", 4, false, tokens))
                    .child(head("Steps", 3, false, tokens))
                    .child(head("State", 3, false, tokens))
                    .child(head("Observed change", 4, false, tokens)),
            ),
        )
        .child(TableBody::new().children(rows))
        .into_any_element()
}

fn operations_card(
    history: &Shown<HistorySnapshot>,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::FileText, "Operations").subtitle(format!(
        "The latest {HISTORY_ROWS_MAX} of the journal at most"
    ));
    let body: AnyElement = match history {
        Shown::Loading => skeleton_rows(6),
        Shown::Failed(reason) => failed_body("history-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let mut body = v_flex().gap(tokens::SPACE_3);
            if !value.operations.is_empty() {
                body = body.child(operation_table(
                    value,
                    now,
                    stale_age.is_some(),
                    mono,
                    tokens,
                ));
            } else if value.problems.is_empty() {
                let text: &str = if value.journal_present {
                    "No operation is in the journal."
                } else {
                    "No journal exists in the state directory."
                };
                body = body.child(body_line("history-empty", text, true, tokens));
            } else {
                // A failed read is not an empty journal.
                body = body.child(failed_body(
                    "history-operations",
                    "the operations were not read",
                    tokens,
                ));
            }
            body = body.children(problem_lines("history", &value.problems, tokens));
            if let Some(age) = stale_age {
                body = body.child(stale_line("history-stale", age, tokens));
            }
            body = body.child(caption(
                "history-note",
                "A capacity value is an observation before and after the operation. A move to the Trash has no capacity observation. The journal is a record and not an undo list.",
                tokens,
            ));
            body.into_any_element()
        }
    };
    card(header, body)
}

impl Render for HistoryScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let history = shown(&model.history_records, now, |history| history.captured_at);
        let cards: Vec<(CardWidth, AnyElement)> = vec![(
            CardWidth::Full,
            operations_card(&history, now, &mono, tokens),
        )];
        screen("History", cards, self.activation, cx.reduce_motion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn steps_have_counts_in_the_order_of_the_first_occurrence() {
        assert_eq!(steps_text(&[]), "No step");
        assert_eq!(steps_text(&steps(&["Failed"])), "1 step: 1 Failed");
        assert_eq!(
            steps_text(&steps(&["Completed", "Failed", "Completed", "NoAction"])),
            "4 steps: 2 Completed, 1 Failed, 1 NoAction"
        );
    }

    #[test]
    fn failed_and_unknown_steps_have_different_tones_from_completed() {
        assert_eq!(step_tone("Completed"), Tone::Positive);
        assert_eq!(step_tone("Failed"), Tone::Negative);
        assert_eq!(step_tone("Verifying"), Tone::Brand);
        assert_eq!(step_tone("Incomplete"), Tone::Warning);
        assert_eq!(step_tone("NoAction"), Tone::Neutral);
        assert_eq!(step_tone("SomethingNew"), Tone::Warning);
    }

    #[test]
    fn a_capacity_change_needs_two_values() {
        let effect = EffectRow::Capacity {
            before: Measured::Value(22_000_000_000),
            after: Measured::Value(31_400_000_000),
        };
        assert_eq!(
            resource_text(&effect),
            "Available capacity 22.0 GB before, 31.4 GB after, change +9.4 GB"
        );
        let smaller = EffectRow::Capacity {
            before: Measured::Value(5_000_000_000),
            after: Measured::Value(4_000_000_000),
        };
        assert!(resource_text(&smaller).ends_with("change \u{2212}1.0 GB"));
        let unknown = EffectRow::Capacity {
            before: Measured::Value(22_000_000_000),
            after: Measured::Unavailable("failed".into()),
        };
        assert_eq!(
            resource_text(&unknown),
            "Available capacity 22.0 GB before, \u{2014} after, change not known"
        );
    }

    #[test]
    fn no_observation_is_not_a_change_of_zero() {
        let operation = OperationDetail {
            operation_id: "op".to_owned(),
            phase: OperationPhase::Partial,
            state_text: "Partial".to_owned(),
            admitted_at: SystemTime::UNIX_EPOCH,
            trigger: "manual".to_owned(),
            automatic: false,
            action_classes: Vec::new(),
            steps: Vec::new(),
            effects: Vec::new(),
            resources: Vec::new(),
        };
        assert_eq!(
            observed_lines(&operation),
            ["No measurement in the journal"]
        );
        assert_eq!(effects_text(&operation.effects), "No target result");
    }

    #[test]
    fn failed_and_unknown_outcome_have_different_icons() {
        assert!(matches!(
            phase_icon(OperationPhase::Failed),
            Some(IconName::CircleX)
        ));
        assert!(matches!(
            phase_icon(OperationPhase::Unknown),
            Some(IconName::TriangleAlert)
        ));
    }
}
