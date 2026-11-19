//! The History screen: the latest operations of the journal with their
//! trigger, their steps, their target results, and the observed change of a
//! resource. A row that is not settled has a cancel, and an
//! `UnknownOutcome` row has an acknowledgment (`crate::actions`).

use super::common::{
    CELL_MIN_WIDTH, CardWidth, Shown, ago, body_line, bytes_text, caption, card, cell, fact,
    failed_body, head, inset, mono_text, problem_lines, screen, shown, skeleton_rows, stale_line,
};
use super::controls::{action_button, slot_status};
use crate::{
    actions::{Action, Slot},
    data::{
        model::{Measured, OperationPhase},
        records::{EffectRow, HISTORY_ROWS_MAX, HistorySnapshot, OperationDetail},
        store::AppModel,
    },
    screens::overview::phase_pill,
    theme::tokens::{self, Tokens, to_hsla},
    ui::action_button::{ActionButton, ButtonSize, ButtonVariant},
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
        button::{Toggle, ToggleGroup, ToggleVariants as _},
        h_flex,
        table::{Table, TableBody, TableHead, TableHeader, TableRow},
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

/// A column that the table of operations sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    /// The admission time.
    #[default]
    Admitted,
    /// The trigger class.
    Trigger,
    /// The first action class.
    ActionClass,
    /// The outcome, the most severe first.
    Outcome,
}

impl SortColumn {
    /// The header text of the column.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Admitted => "Operation",
            Self::Trigger => "Trigger",
            Self::ActionClass => "Action classes",
            Self::Outcome => "State",
        }
    }

    /// The stable name of the column, for an element identity.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Trigger => "trigger",
            Self::ActionClass => "class",
            Self::Outcome => "outcome",
        }
    }

    /// The first direction of a sort by the column: the newest operation
    /// first for the admission time, A to Z or the most severe first for
    /// the others.
    #[must_use]
    pub const fn first_ascending(self) -> bool {
        !matches!(self, Self::Admitted)
    }
}

/// The rank of an outcome in a sort: the outcome that needs attention
/// first.
#[must_use]
pub const fn outcome_rank(phase: OperationPhase) -> u8 {
    match phase {
        OperationPhase::Unknown => 0,
        OperationPhase::Failed => 1,
        OperationPhase::Partial => 2,
        OperationPhase::Running => 3,
        OperationPhase::Pending => 4,
        OperationPhase::NoAction => 5,
        OperationPhase::Completed => 6,
    }
}

/// The filter, the sort order, and the selected operation of History.
/// They apply to the bounded read of the journal (the latest
/// [`HISTORY_ROWS_MAX`] operations), not to the whole journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryView {
    /// The trigger class to show. `None`: each one.
    pub trigger: Option<String>,
    /// The action class to show. `None`: each one.
    pub class: Option<String>,
    /// The outcome to show. `None`: each one.
    pub outcome: Option<OperationPhase>,
    /// The sort column.
    pub sort: SortColumn,
    /// True: ascending (oldest first, A to Z, most severe first).
    pub ascending: bool,
    /// The operation of the detail view.
    pub selected: Option<String>,
}

impl HistoryView {
    /// Whether `operation` passes the filter.
    #[must_use]
    pub fn matches(&self, operation: &OperationDetail) -> bool {
        self.trigger
            .as_ref()
            .is_none_or(|trigger| *trigger == operation.trigger)
            && self
                .class
                .as_ref()
                .is_none_or(|class| operation.action_classes.contains(class))
            && self
                .outcome
                .is_none_or(|outcome| outcome == operation.phase)
    }

    /// The operations of `operations` that pass the filter, in the sort
    /// order. A tie keeps the newest operation first.
    #[must_use]
    pub fn visible<'a>(&self, operations: &'a [OperationDetail]) -> Vec<&'a OperationDetail> {
        let mut rows: Vec<&OperationDetail> = operations
            .iter()
            .filter(|operation| self.matches(operation))
            .collect();
        rows.sort_by(|a, b| {
            let newest_first = b.admitted_at.cmp(&a.admitted_at);
            let order = match self.sort {
                SortColumn::Admitted => a.admitted_at.cmp(&b.admitted_at),
                SortColumn::Trigger => a.trigger.cmp(&b.trigger),
                SortColumn::ActionClass => a.action_classes.first().cmp(&b.action_classes.first()),
                SortColumn::Outcome => outcome_rank(a.phase).cmp(&outcome_rank(b.phase)),
            };
            let order = if self.ascending {
                order
            } else {
                order.reverse()
            };
            order.then(newest_first)
        });
        rows
    }

    /// Clears each filter value that `values` does not have: a value that
    /// left the bounded read cannot be shown as a toggle, so it does not
    /// filter in secret. Returns `true` when a value was cleared.
    pub fn keep_values_of(&mut self, values: &FilterValues) -> bool {
        let mut cleared: bool = false;
        if self
            .trigger
            .as_ref()
            .is_some_and(|trigger| !values.triggers.contains(trigger))
        {
            self.trigger = None;
            cleared = true;
        }
        if self
            .class
            .as_ref()
            .is_some_and(|class| !values.classes.contains(class))
        {
            self.class = None;
            cleared = true;
        }
        if self
            .outcome
            .is_some_and(|outcome| !values.outcomes.contains(&outcome))
        {
            self.outcome = None;
            cleared = true;
        }
        cleared
    }

    /// Sorts by `column`: a second press on the same column reverses the
    /// direction.
    pub fn sort_by(&mut self, column: SortColumn) {
        if self.sort == column {
            self.ascending = !self.ascending;
        } else {
            self.sort = column;
            self.ascending = column.first_ascending();
        }
    }

    /// The accessible text of the sort order.
    #[must_use]
    pub fn sort_text(&self) -> String {
        let direction: &str = match (self.sort, self.ascending) {
            (SortColumn::Admitted, false) => "newest first",
            (SortColumn::Admitted, true) => "oldest first",
            (SortColumn::Outcome, true) => "most severe first",
            (SortColumn::Outcome, false) => "least severe first",
            (_, true) => "A to Z",
            (_, false) => "Z to A",
        };
        format!("Sorted by {}, {direction}", self.sort.label())
    }
}

/// The values of the filter in the bounded read, each one time, in the
/// order of the first occurrence (newest operation first).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterValues {
    /// The trigger classes.
    pub triggers: Vec<String>,
    /// The action classes.
    pub classes: Vec<String>,
    /// The outcomes, the most severe first.
    pub outcomes: Vec<OperationPhase>,
}

/// The filter values of `operations`.
#[must_use]
pub fn filter_values(operations: &[OperationDetail]) -> FilterValues {
    let mut values = FilterValues::default();
    for operation in operations {
        if !values.triggers.contains(&operation.trigger) {
            values.triggers.push(operation.trigger.clone());
        }
        for class in &operation.action_classes {
            if !values.classes.contains(class) {
                values.classes.push(class.clone());
            }
        }
        if !values.outcomes.contains(&operation.phase) {
            values.outcomes.push(operation.phase);
        }
    }
    values.outcomes.sort_by_key(|phase| outcome_rank(*phase));
    values
}

/// The History screen entity.
#[derive(Debug)]
pub struct HistoryScreen {
    model: Entity<AppModel>,
    activation: u64,
    view: HistoryView,
}

impl HistoryScreen {
    /// Creates the screen and observes the model.
    pub fn new(model: Entity<AppModel>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            activation: 1,
            view: HistoryView::default(),
        }
    }

    /// Opens the detail of the operation `operation` below its row.
    pub fn show_detail(&mut self, operation: &str, cx: &mut Context<Self>) {
        self.view.selected = Some(operation.to_owned());
        cx.notify();
    }

    /// The filter, the sort order, and the selected operation.
    #[must_use]
    pub const fn view(&self) -> &HistoryView {
        &self.view
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

/// The control of an operation row: a cancel for an operation that is not
/// settled, and an acknowledgment for an `UnknownOutcome` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowControl {
    /// Stop the dispatch of the further steps.
    Cancel,
    /// Acknowledge the unknown outcome and release the leases.
    Acknowledge,
}

/// The control of `operation`, if it has one.
#[must_use]
pub fn row_control(operation: &OperationDetail) -> Option<RowControl> {
    match operation.phase {
        OperationPhase::Pending | OperationPhase::Running => Some(RowControl::Cancel),
        OperationPhase::Unknown if operation.state_text == "UnknownOutcome" => {
            Some(RowControl::Acknowledge)
        }
        _ => None,
    }
}

/// The state cell of a row: the state pill, the control, and the state of
/// its last action.
fn state_cell(
    operation: &OperationDetail,
    pill: StatusPill,
    entity: &Entity<AppModel>,
    model: &AppModel,
    now: SystemTime,
    tokens: &Tokens,
) -> AnyElement {
    let id: &str = &operation.operation_id;
    let slot = Slot::Operation(id.to_owned());
    let busy: bool = model.actions.is_busy(&slot);
    let control = row_control(operation).map(|control| match control {
        RowControl::Cancel => action_button(
            SharedString::from(format!("history-cancel-{id}")),
            "Cancel",
            ButtonVariant::Quiet,
            entity,
            Action::Cancel {
                operation: id.to_owned(),
            },
            busy,
        ),
        RowControl::Acknowledge => action_button(
            SharedString::from(format!("history-acknowledge-{id}")),
            "Acknowledge",
            ButtonVariant::Quiet,
            entity,
            Action::Acknowledge {
                operation: id.to_owned(),
            },
            busy,
        ),
    });
    // The width of the cell bounds the state line, so a long sentence wraps
    // in the cell and does not cover the next column.
    v_flex()
        .w_full()
        .min_w_0()
        .gap(tokens::SPACE_1)
        .items_start()
        .child(pill)
        .children(control)
        .children(slot_status(
            SharedString::from(format!("history-action-{id}")),
            model,
            &slot,
            now,
            tokens,
        ))
        .into_any_element()
}

/// The context of the table: the model, the screen entity for the sort
/// and the detail, and the theme values.
struct TableContext<'a> {
    entity: &'a Entity<AppModel>,
    screen: &'a Entity<HistoryScreen>,
    model: &'a AppModel,
    view: &'a HistoryView,
    now: SystemTime,
    stale: bool,
    mono: &'a SharedString,
    tokens: &'a Tokens,
}

/// A header cell that sorts the table by `column`. The active column has a
/// chevron in the direction of the sort.
fn sort_head(column: SortColumn, span: usize, context: &TableContext<'_>) -> TableHead {
    let active: bool = context.view.sort == column;
    let mut button = ActionButton::new(
        SharedString::from(format!("history-sort-{}", column.key())),
        column.label(),
    )
    .variant(ButtonVariant::Quiet)
    .size(ButtonSize::Sm);
    if active {
        button = button.icon(if context.view.ascending {
            IconName::ChevronUp
        } else {
            IconName::ChevronDown
        });
    }
    let screen: Entity<HistoryScreen> = context.screen.clone();
    TableHead::new()
        .col_span(span)
        .min_w(CELL_MIN_WIDTH)
        .child(button.on_click(move |_, _, cx| {
            screen.update(cx, |screen, cx| {
                screen.view.sort_by(column);
                cx.notify();
            });
        }))
}

/// The sum of the column spans of the table: the span of an expanded row.
const TABLE_SPAN: usize = 21;

/// The button that opens the detail of the operation `id` below its row.
fn details_button(id: &str, selected: bool, screen: &Entity<HistoryScreen>) -> ActionButton {
    let screen: Entity<HistoryScreen> = screen.clone();
    let select_id: String = id.to_owned();
    ActionButton::new(
        SharedString::from(format!("history-details-{id}")),
        if selected { "Details shown" } else { "Details" },
    )
    .variant(ButtonVariant::Quiet)
    .size(ButtonSize::Sm)
    .on_click(move |_, _, cx| {
        let id: String = select_id.clone();
        screen.update(cx, |screen, cx| {
            screen.view.selected = Some(id);
            cx.notify();
        });
    })
}

/// The row of `operation`, and its expanded detail row when it is selected.
fn operation_rows(operation: &OperationDetail, context: &TableContext<'_>) -> Vec<TableRow> {
    let (entity, model, now, stale, mono, tokens) = (
        context.entity,
        context.model,
        context.now,
        context.stale,
        context.mono,
        context.tokens,
    );
    {
        let id: &str = &operation.operation_id;
        let (phase_text, tone) = phase_pill(operation.phase, &operation.state_text);
        let mut pill: StatusPill = StatusPill::new(phase_text.to_owned(), tone)
            .id(SharedString::from(format!("history-state-{id}")));
        if let Some(icon) = phase_icon(operation.phase) {
            pill = pill.icon(icon);
        }
        let state_column: AnyElement = state_cell(operation, pill, entity, model, now, tokens);
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
        let selected: bool = context.view.selected.as_deref() == Some(id);
        let details: ActionButton = details_button(id, selected, context.screen);
        let row: TableRow = TableRow::new()
            .id(SharedString::from(format!("history-row-{id}")))
            .child(cell(
                v_flex()
                    .gap(tokens::SPACE_1)
                    .items_start()
                    .min_w_0()
                    .child(two_lines(
                        div()
                            .id(SharedString::from(format!("history-operation-{id}")))
                            .test_support()
                            .aria_label(operation_label(operation, now))
                            .child(mono_text(id.to_owned(), mono, stale, tokens))
                            .into_any_element(),
                        ago(operation.admitted_at, now),
                        tokens,
                    ))
                    .child(details),
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
            .child(cell(state_column, 3, false))
            .child(cell(observed, 4, false));
        let detail: Option<TableRow> = selected.then(|| {
            TableRow::new()
                .id(SharedString::from(format!("history-detail-row-{id}")))
                .child(cell(
                    detail_body(operation, context.screen, now, mono, tokens),
                    TABLE_SPAN,
                    false,
                ))
        });
        std::iter::once(row).chain(detail).collect()
    }
}

fn operation_table(rows: &[&OperationDetail], context: &TableContext<'_>) -> AnyElement {
    let tokens: &Tokens = context.tokens;
    let rows = rows
        .iter()
        .flat_map(|operation| operation_rows(operation, context));
    Table::new()
        .small()
        .accessibility_label(format!(
            "Operations of the journal. {}",
            context.view.sort_text()
        ))
        .child(
            TableHeader::new().child(
                TableRow::new()
                    .child(sort_head(SortColumn::Admitted, 3, context))
                    .child(sort_head(SortColumn::Trigger, 4, context))
                    .child(sort_head(SortColumn::ActionClass, 4, context))
                    .child(head("Steps", 3, false, tokens))
                    .child(sort_head(SortColumn::Outcome, 3, context))
                    .child(head("Observed change", 4, false, tokens)),
            ),
        )
        .child(TableBody::new().children(rows))
        .into_any_element()
}

/// One filter: a label and a group of toggles with "All" and each value of
/// the bounded read. At most one toggle is on; with none, the filter is
/// "All".
fn filter_group(
    key: &'static str,
    label: &'static str,
    values: Vec<String>,
    active: Option<usize>,
    on_pick: impl Fn(&mut HistoryView, Option<usize>) + 'static,
    screen: &Entity<HistoryScreen>,
    tokens: &Tokens,
) -> AnyElement {
    let screen: Entity<HistoryScreen> = screen.clone();
    let mut group = ToggleGroup::new(SharedString::from(format!("history-filter-{key}")))
        .single()
        .small()
        .outline()
        .flex_wrap()
        .child(
            Toggle::new(SharedString::from(format!("history-filter-{key}-all")))
                .label("All")
                .checked(active.is_none()),
        );
    for (index, value) in values.into_iter().enumerate() {
        group = group.child(
            Toggle::new(SharedString::from(format!("history-filter-{key}-{index}")))
                .label(value)
                .checked(active == Some(index)),
        );
    }
    let group = group.on_click(move |checked: &Vec<bool>, _, cx| {
        // Index 0 is "All"; a cleared group is "All" too.
        let pick: Option<usize> = checked
            .iter()
            .position(|on| *on)
            .and_then(|index| index.checked_sub(1));
        screen.update(cx, |screen, cx| {
            on_pick(&mut screen.view, pick);
            cx.notify();
        });
    });
    h_flex()
        .id(SharedString::from(format!("history-filter-row-{key}")))
        .gap(tokens::SPACE_2)
        .items_start()
        .child(
            div()
                .w(px(96.0))
                .flex_shrink_0()
                .pt(px(4.0))
                .text_size(px(12.0))
                .text_color(to_hsla(tokens.muted_foreground))
                .child(label),
        )
        .child(div().flex_1().min_w_0().child(group))
        .into_any_element()
}

/// The three filters of the bounded read.
fn filter_bar(
    values: &FilterValues,
    view: &HistoryView,
    screen: &Entity<HistoryScreen>,
    tokens: &Tokens,
) -> AnyElement {
    let triggers: Vec<String> = values.triggers.clone();
    let classes: Vec<String> = values.classes.clone();
    let outcomes: Vec<OperationPhase> = values.outcomes.clone();
    let trigger_index: Option<usize> = view
        .trigger
        .as_ref()
        .and_then(|trigger| triggers.iter().position(|value| value == trigger));
    let class_index: Option<usize> = view
        .class
        .as_ref()
        .and_then(|class| classes.iter().position(|value| value == class));
    let outcome_index: Option<usize> = view
        .outcome
        .and_then(|outcome| outcomes.iter().position(|value| *value == outcome));
    let trigger_values: Vec<String> = triggers.clone();
    let class_values: Vec<String> = classes.clone();
    let outcome_values: Vec<OperationPhase> = outcomes.clone();
    v_flex()
        .id("history-filters")
        .gap(tokens::SPACE_2)
        .child(filter_group(
            "trigger",
            "Trigger",
            triggers,
            trigger_index,
            move |view, pick| {
                view.trigger = pick.and_then(|index| trigger_values.get(index).cloned());
            },
            screen,
            tokens,
        ))
        .child(filter_group(
            "class",
            "Action class",
            classes,
            class_index,
            move |view, pick| {
                view.class = pick.and_then(|index| class_values.get(index).cloned());
            },
            screen,
            tokens,
        ))
        .child(filter_group(
            "outcome",
            "Outcome",
            outcomes
                .iter()
                .map(|phase| phase_pill(*phase, phase_name(*phase)).0.to_owned())
                .collect(),
            outcome_index,
            move |view, pick| {
                view.outcome = pick.and_then(|index| outcome_values.get(index).copied());
            },
            screen,
            tokens,
        ))
        .into_any_element()
}

/// The journal name of a phase, for the pill of a filter value.
const fn phase_name(phase: OperationPhase) -> &'static str {
    match phase {
        OperationPhase::Pending => "Pending",
        OperationPhase::Running => "Admitted",
        OperationPhase::Completed => "Completed",
        OperationPhase::Partial => "Partial",
        OperationPhase::NoAction => "NoAction",
        OperationPhase::Failed => "Failed",
        OperationPhase::Unknown => "UnknownOutcome",
    }
}

/// The sentence of the bound: the filter and the sort work on the bounded
/// read, not on the whole journal.
#[must_use]
pub fn bound_text(shown: usize, read: usize) -> String {
    format!(
        "The filter and the sort order apply to the {read} operations that this window read (the latest {HISTORY_ROWS_MAX} of the journal at most), not to the whole journal. {shown} of {read} shown."
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "a card builder takes the readings, the two entities, and the theme values"
)]
fn operations_card(
    history: &Shown<HistorySnapshot>,
    entity: &Entity<AppModel>,
    screen: &Entity<HistoryScreen>,
    view: &HistoryView,
    model: &AppModel,
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
                let rows: Vec<&OperationDetail> = view.visible(&value.operations);
                body = body
                    .child(filter_bar(
                        &filter_values(&value.operations),
                        view,
                        screen,
                        tokens,
                    ))
                    .child(caption(
                        "history-bound",
                        bound_text(rows.len(), value.operations.len()),
                        tokens,
                    ));
                if let Some(id) = view
                    .selected
                    .as_ref()
                    .filter(|id| !rows.iter().any(|row| row.operation_id == **id))
                {
                    body = body.child(caption(
                        "history-detail-hidden",
                        format!("The detail of operation {id} is not shown: the operation is not in the read, or the filter hides it."),
                        tokens,
                    ));
                }
                if rows.is_empty() {
                    body = body.child(body_line(
                        "history-no-match",
                        "No operation of the read matches the filter.",
                        true,
                        tokens,
                    ));
                } else {
                    let context = TableContext {
                        entity,
                        screen,
                        model,
                        view,
                        now,
                        stale: stale_age.is_some(),
                        mono,
                        tokens,
                    };
                    body = body.child(operation_table(&rows, &context));
                }
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
                "A capacity value is an observation before and after the operation. A move to the Trash has no capacity observation. The journal is a record and not an undo list. Cancel stops the dispatch of the further steps; it does not recall a call that was issued.",
                tokens,
            ));
            body.into_any_element()
        }
    };
    card(header, body)
}

/// A labeled block of the detail view.
fn detail_section(
    id: &'static str,
    title: &'static str,
    rows: Vec<AnyElement>,
    tokens: &Tokens,
) -> AnyElement {
    inset(
        v_flex()
            .id(id)
            .gap(tokens::SPACE_1)
            .child(
                div()
                    .id(SharedString::from(format!("{id}-title")))
                    .role(Role::Heading)
                    .test_support()
                    .aria_label(title)
                    .text_size(px(13.0))
                    .text_color(to_hsla(tokens.foreground))
                    .child(title),
            )
            .children(rows),
        tokens,
    )
}

/// The steps of the detail view: the state pill and the step, its action
/// class, its target, and its dispatch.
fn step_rows(operation: &OperationDetail, mono: &SharedString, tokens: &Tokens) -> Vec<AnyElement> {
    if operation.step_details.is_empty() {
        vec![caption(
            "history-detail-no-step",
            "The operation has no step.",
            tokens,
        )]
    } else {
        operation
            .step_details
            .iter()
            .map(|step| {
                let text: String = format!(
                    "{} · {} · target {} · dispatch {}",
                    step.step_id, step.action_class, step.target_id, step.dispatch
                );
                h_flex()
                    .id(SharedString::from(format!(
                        "history-detail-step-{}",
                        step.step_id
                    )))
                    .test_support()
                    .aria_label(format!("Step {}: {}", step.state, text))
                    .gap(tokens::SPACE_2)
                    .items_start()
                    .child(StatusPill::new(step.state.clone(), step_tone(&step.state)))
                    .child(mono_text(text, mono, false, tokens))
                    .into_any_element()
            })
            .collect()
    }
}

/// The target results of the detail view.
fn target_rows(
    operation: &OperationDetail,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    if operation.targets.is_empty() {
        vec![caption(
            "history-detail-no-target",
            "The journal has no target result for the operation.",
            tokens,
        )]
    } else {
        operation
            .targets
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let mut text: String = format!(
                    "{}{} · {} · dispatch {} · stop {} · {}",
                    target.target_id,
                    target
                        .member
                        .as_ref()
                        .map_or_else(String::new, |member| format!(" member {member}")),
                    target.effect,
                    target.dispatch,
                    target.stop_reason,
                    target.attribution
                );
                if let Some(error) = &target.error {
                    text.push_str(" · error ");
                    text.push_str(error);
                }
                div()
                    .id(SharedString::from(format!("history-detail-target-{index}")))
                    .test_support()
                    .aria_label(format!("Target result: {text}"))
                    .child(mono_text(text, mono, false, tokens))
                    .into_any_element()
            })
            .collect()
    }
}

/// The errors of the detail view, or the line that none exists.
fn error_rows(
    operation: &OperationDetail,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let errors: Vec<String> = operation.errors().into_iter().map(str::to_owned).collect();
    if errors.is_empty() {
        vec![caption(
            "history-detail-no-error",
            "No target result has an error.",
            tokens,
        )]
    } else {
        errors
            .into_iter()
            .enumerate()
            .map(|(index, error)| {
                div()
                    .id(SharedString::from(format!("history-detail-error-{index}")))
                    .test_support()
                    .aria_label(format!("Error: {error}"))
                    .child(mono_text(error, mono, false, tokens))
                    .into_any_element()
            })
            .collect()
    }
}

/// The first lines of the detail view: the state, the trigger, the plan,
/// and the admission, with the close button.
fn detail_summary(
    operation: &OperationDetail,
    close: ActionButton,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let (state, tone) = phase_pill(operation.phase, &operation.state_text);
    let origin: &str = if operation.automatic {
        "a guard"
    } else {
        "the user"
    };
    vec![
        h_flex()
            .gap(tokens::SPACE_2)
            .items_center()
            .child(StatusPill::new(state.to_owned(), tone).id("history-detail-state"))
            .child(caption(
                "history-detail-state-text",
                format!(
                    "Detail of operation {}. Journal state: {}",
                    operation.operation_id, operation.state_text
                ),
                tokens,
            ))
            .child(div().flex_1())
            .child(close)
            .into_any_element(),
        fact(
            "history-detail-trigger",
            "Trigger",
            format!("{}, started by {origin}", operation.trigger),
            mono,
            false,
            tokens,
        ),
        fact(
            "history-detail-plan",
            "Plan",
            operation.plan_id.clone(),
            mono,
            false,
            tokens,
        ),
        fact(
            "history-detail-admitted",
            "Admitted",
            ago(operation.admitted_at, now),
            mono,
            false,
            tokens,
        ),
    ]
}

/// The detail of one operation, in an expanded row below its row: each
/// step with its state, each target result, the resource observations, the
/// trigger, and the errors.
fn detail_body(
    operation: &OperationDetail,
    screen: &Entity<HistoryScreen>,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let close_screen: Entity<HistoryScreen> = screen.clone();
    let close = ActionButton::new("history-detail-close", "Close detail")
        .variant(ButtonVariant::Quiet)
        .size(ButtonSize::Sm)
        .on_click(move |_, _, cx| {
            close_screen.update(cx, |screen, cx| {
                screen.view.selected = None;
                cx.notify();
            });
        });
    let summary: Vec<AnyElement> = detail_summary(operation, close, now, mono, tokens);
    let steps: Vec<AnyElement> = step_rows(operation, mono, tokens);
    let targets: Vec<AnyElement> = target_rows(operation, mono, tokens);
    let observed: Vec<AnyElement> = observed_lines(operation)
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            caption(
                SharedString::from(format!("history-detail-observed-{index}")),
                line,
                tokens,
            )
        })
        .collect();
    let error_rows: Vec<AnyElement> = error_rows(operation, mono, tokens);
    let body = v_flex()
        .gap(tokens::SPACE_2)
        .children(summary)
        .child(detail_section(
            "history-detail-steps",
            "Steps",
            steps,
            tokens,
        ))
        .child(detail_section(
            "history-detail-targets",
            "Target results",
            targets,
            tokens,
        ))
        .child(detail_section(
            "history-detail-resources",
            "Resource observations",
            observed,
            tokens,
        ))
        .child(detail_section(
            "history-detail-errors",
            "Errors",
            error_rows,
            tokens,
        ));
    div()
        .id("history-detail")
        .w_full()
        .py(tokens::SPACE_2)
        .child(body)
        .into_any_element()
}

impl Render for HistoryScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let entity: Entity<AppModel> = self.model.clone();
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let history = shown(&model.history_records, now, |history| history.captured_at);
        // A filter value that left the bounded read is cleared, so that the
        // toggles always show the filter in effect.
        if let Shown::Data { value, .. } = &history {
            self.view.keep_values_of(&filter_values(&value.operations));
        }
        let screen_entity: Entity<HistoryScreen> = cx.entity();
        let cards: Vec<(CardWidth, AnyElement)> = vec![(
            CardWidth::Full,
            operations_card(
                &history,
                &entity,
                &screen_entity,
                &self.view,
                model,
                now,
                &mono,
                tokens,
            ),
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
            plan_id: String::new(),
            step_details: Vec::new(),
            targets: Vec::new(),
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

    fn fixture_operations() -> Vec<OperationDetail> {
        use crate::data::{
            DataSource as _,
            fixture::{FixtureScenario, FixtureSource},
        };
        FixtureSource::new(FixtureScenario::Pressure)
            .history()
            .operations
    }

    fn ids(rows: &[&OperationDetail]) -> Vec<String> {
        rows.iter().map(|row| row.operation_id.clone()).collect()
    }

    #[test]
    fn the_default_view_is_the_bounded_read_newest_first() {
        let operations = fixture_operations();
        let view = HistoryView::default();
        let rows = view.visible(&operations);
        assert_eq!(rows.len(), operations.len());
        assert!(
            rows.windows(2)
                .all(|pair| pair[0].admitted_at >= pair[1].admitted_at)
        );
        assert_eq!(view.sort_text(), "Sorted by Operation, newest first");
    }

    #[test]
    fn each_filter_keeps_only_the_matching_operations() {
        let operations = fixture_operations();
        let manual = HistoryView {
            trigger: Some("manual".to_owned()),
            ..HistoryView::default()
        };
        assert!(
            manual
                .visible(&operations)
                .iter()
                .all(|row| row.trigger == "manual")
        );
        assert_eq!(manual.visible(&operations).len(), 2);
        let trash = HistoryView {
            class: Some("MoveToTrash".to_owned()),
            ..HistoryView::default()
        };
        assert_eq!(ids(&trash.visible(&operations)), vec!["op_fixture_0000"]);
        let failed = HistoryView {
            outcome: Some(OperationPhase::Failed),
            ..HistoryView::default()
        };
        assert_eq!(ids(&failed.visible(&operations)), vec!["op_fixture_00yy"]);
        let none = HistoryView {
            trigger: Some("manual".to_owned()),
            outcome: Some(OperationPhase::Completed),
            ..HistoryView::default()
        };
        assert_eq!(ids(&none.visible(&operations)), Vec::<String>::new());
    }

    #[test]
    fn a_second_press_on_a_column_reverses_the_sort() {
        let operations = fixture_operations();
        let mut view = HistoryView::default();
        view.sort_by(SortColumn::Outcome);
        assert!(view.ascending);
        let rows = view.visible(&operations);
        assert_eq!(
            rows.first().map(|row| row.phase),
            Some(OperationPhase::Unknown)
        );
        assert_eq!(
            rows.last().map(|row| row.phase),
            Some(OperationPhase::Completed)
        );
        view.sort_by(SortColumn::Outcome);
        assert!(!view.ascending);
        assert_eq!(
            view.visible(&operations).first().map(|row| row.phase),
            Some(OperationPhase::Completed)
        );
        view.sort_by(SortColumn::Trigger);
        let triggers: Vec<String> = view
            .visible(&operations)
            .iter()
            .map(|row| row.trigger.clone())
            .collect();
        let mut sorted = triggers.clone();
        sorted.sort();
        assert_eq!(triggers, sorted);
        view.sort_by(SortColumn::Admitted);
        assert!(!view.ascending, "the admission time starts newest first");
    }

    #[test]
    fn a_filter_value_that_left_the_read_is_cleared() {
        let operations = fixture_operations();
        let mut view = HistoryView {
            trigger: Some("gone_trigger".to_owned()),
            class: Some("MoveToTrash".to_owned()),
            outcome: Some(OperationPhase::Pending),
            ..HistoryView::default()
        };
        assert!(view.keep_values_of(&filter_values(&operations)));
        assert_eq!(view.trigger, None);
        assert_eq!(view.class.as_deref(), Some("MoveToTrash"));
        assert_eq!(view.outcome, None);
        assert!(!view.keep_values_of(&filter_values(&operations)));
    }

    #[test]
    fn the_filter_values_are_those_of_the_read() {
        let values = filter_values(&fixture_operations());
        assert!(values.triggers.contains(&"manual".to_owned()));
        assert!(values.classes.contains(&"MoveToTrash".to_owned()));
        assert_eq!(values.outcomes.first(), Some(&OperationPhase::Unknown));
        assert_eq!(filter_values(&[]), FilterValues::default());
        assert!(bound_text(2, 6).ends_with("2 of 6 shown."));
        assert!(bound_text(2, 6).contains("not to the whole journal"));
    }

    #[test]
    fn the_errors_of_an_operation_are_each_target_error_one_time() {
        let operations = fixture_operations();
        let partial = operations
            .iter()
            .find(|row| row.operation_id == "op_fixture_0000")
            .unwrap_or_else(|| panic!("partial"));
        assert_eq!(
            partial.errors(),
            vec![
                "target_protected at admission",
                "target_changed at revalidation"
            ]
        );
        assert_eq!(partial.step_details.len(), partial.steps.len());
        let completed = operations
            .iter()
            .find(|row| row.operation_id == "op_fixture_0001")
            .unwrap_or_else(|| panic!("completed"));
        assert_eq!(completed.errors(), Vec::<&str>::new());
    }
}
