//! The Applications screen: the application and job groups with their
//! verified members, their footprint and its growth, and their hard
//! protection with its reason; the application budgets and the relaunch
//! cooldowns of the controller record. A group that the catalog does not
//! protect has a stop control with a confirmation that shows the processes
//! of the plan (`crate::actions`).

use super::agent_state::{budgets_card, controller_body, cooldown_facts, growth_text};
use super::common::{
    CardWidth, Shown, body_line, bytes_text, caption, card, cell, fact, failed_body, head,
    mono_text, screen, shown, skeleton_rows, stale_line,
};
use super::controls::{open_state_detail, open_stop};
use crate::{
    actions::{ActionState, Slot},
    data::{
        model::Measured,
        records::{
            ApplicationRow, ControllerSnapshot, CooldownSubject, Foreground, ProcessesSnapshot,
            Protection,
        },
        store::AppModel,
    },
    theme::tokens::{self, Tokens},
    ui::action_button::{ActionButton, ButtonVariant},
    ui::action_status::{action_status_short, short_caption},
    ui::{
        pill::{MonoTag, StatusPill, Tone},
        provenance::ProvenanceLine,
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, IntoElement, ParentElement, Pixels, Render, SharedString, Styled,
    TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, IconName, Sizable as _, h_flex,
        table::{Table, TableBody, TableHeader, TableRow},
        v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::time::SystemTime;

/// The pill text and tone of a hard protection. `Unknown` is a warning: the
/// lookup gave no result, and automation skips such a target.
#[must_use]
pub const fn protection_pill(protection: Protection) -> (&'static str, Tone) {
    match protection {
        Protection::Protected { .. } => ("Protected", Tone::Brand),
        Protection::NotProtected => ("Not protected", Tone::Neutral),
        Protection::Unknown { .. } => ("Unknown", Tone::Warning),
    }
}

/// The reason of a protection or of an unknown result: the catalog entry
/// that matched, or the cause that the catalog cannot classify the group.
#[must_use]
pub const fn protection_reason(protection: Protection) -> Option<&'static str> {
    match protection {
        Protection::Protected { reason } => Some(reason.text()),
        Protection::NotProtected => None,
        Protection::Unknown { cause } => Some(cause.text()),
    }
}

/// The growth text of a group and whether the sum is partial: a member with
/// no change value is not in the sum.
#[must_use]
pub fn group_growth(row: &ApplicationRow) -> (String, bool) {
    (
        growth_text(&row.growth),
        matches!(row.growth, Measured::Value(_)) && row.growth_missing > 0,
    )
}

/// The text of a foreground state. `Unknown` is not `Background`.
#[must_use]
pub const fn foreground_text(foreground: Foreground) -> &'static str {
    match foreground {
        Foreground::Foreground => "Foreground",
        Foreground::Background => "Background",
        Foreground::Unknown => "Not known",
    }
}

/// The footprint text of a group and whether the sum is partial: a member
/// with no footprint value is not in the sum.
#[must_use]
pub fn group_footprint(row: &ApplicationRow) -> (String, bool) {
    (
        bytes_text(&row.footprint),
        matches!(row.footprint, Measured::Value(_)) && row.unmeasured_members > 0,
    )
}

/// The accessible sentence of one group row.
#[must_use]
pub fn group_label(row: &ApplicationRow) -> String {
    let (footprint, partial) = group_footprint(row);
    let footprint: String = match (&row.footprint, partial) {
        (Measured::Unavailable(reason), _) => format!("footprint not available: {reason}"),
        (Measured::Value(_), true) => format!(
            "footprint {footprint}, partial: {} of {} processes have no value",
            row.unmeasured_members, row.members
        ),
        (Measured::Value(_), false) => format!("footprint {footprint}"),
    };
    let growth: String = match (&row.growth, group_growth(row)) {
        (Measured::Unavailable(reason), _) => format!("growth not available: {reason}"),
        (Measured::Value(_), (text, true)) => format!(
            "growth {text}, partial: {} of {} processes have no value",
            row.growth_missing, row.members
        ),
        (Measured::Value(_), (text, false)) => format!("growth {text}"),
    };
    let protection: String = match protection_reason(row.protection) {
        Some(reason) => format!("{} ({reason})", protection_pill(row.protection).0),
        None => protection_pill(row.protection).0.to_owned(),
    };
    format!(
        "{}, {}, {} processes, {footprint}, {growth}, protection: {protection}",
        row.name,
        row.kind.label(),
        row.members,
    )
}

/// The sentence that says how many groups the table shows.
#[must_use]
pub fn group_summary(snapshot: &ProcessesSnapshot) -> String {
    format!(
        "{} of {} groups with a verified member. {} of {} processes of this user have no verified group and are in no row.",
        snapshot.applications.len(),
        snapshot.application_count,
        snapshot.unattributed,
        snapshot.process_count
    )
}

/// The Applications screen entity.
#[derive(Debug)]
pub struct ApplicationsScreen {
    model: Entity<AppModel>,
    activation: u64,
}

impl ApplicationsScreen {
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

/// Whether the stop control is offered for a group. A protected group and
/// a group whose protection is not known have no stop control; the plan
/// builder and the coordinator refuse them as well.
#[must_use]
pub const fn stop_offered(protection: Protection) -> bool {
    matches!(protection, Protection::NotProtected)
}

/// The reason of a stop control that is off while the stop confirmation of
/// its group is open.
pub const STOP_OPEN: &str =
    "The stop confirmation of this group is open, so each stop control is off until it closes.";

/// The number of columns of the group table: the sum of the spans of its
/// cells.
const TABLE_SPAN: usize = 20;

/// The minimum width of the Stop column. It holds the stop control in its
/// widest state: in the `loading` state the control has a spinner before
/// its label, and a narrower column cut the label to "Stop.." at the right
/// edge of the table (host run 4). The other columns shrink first.
pub const STOP_COLUMN_MIN_WIDTH: Pixels = px(112.0);

/// The state row of the last stop of a group, below the row of the group:
/// the Stop column is too narrow for the pill and the sentence, so the line
/// spans the table. It is the short state line: at most two lines of the
/// sentence, with the full line as its accessible label and, when the
/// sentence is cut, as its tooltip. The Details button is the keyboard path
/// to the full line. While the stop confirmation of the group is open, the
/// row also says that the stop control is off for that reason. `None` when
/// the group has no stop state and no open confirmation.
fn stop_state_row(
    row: &ApplicationRow,
    entity: &Entity<AppModel>,
    model: &AppModel,
    tokens: &Tokens,
) -> Option<TableRow> {
    let slot = Slot::Stop(row.instance.clone());
    let open: bool = model.actions.stop_open() == Some(row.instance.as_str());
    let state = model.actions.state(&slot);
    if state.is_none() && !open {
        return None;
    }
    let mut content = v_flex().w_full().min_w_0().gap(tokens::SPACE_1);
    if open {
        content = content.child(caption(
            SharedString::from(format!("applications-stop-open-{}", row.instance)),
            STOP_OPEN,
            tokens,
        ));
    }
    if let Some(state) = state {
        content = content.child(state_with_details(row, entity, &slot, state, tokens));
    }
    Some(
        TableRow::new()
            .id(SharedString::from(format!(
                "applications-stop-row-{}",
                row.instance
            )))
            .child(cell(content, TABLE_SPAN, false)),
    )
}

/// The short state line of the last stop of `row` and its Details button.
fn state_with_details(
    row: &ApplicationRow,
    entity: &Entity<AppModel>,
    slot: &Slot,
    state: &ActionState,
    tokens: &Tokens,
) -> AnyElement {
    let opener: Entity<AppModel> = entity.clone();
    let slot: Slot = slot.clone();
    let title: String = format!("Last stop of {}", row.name);
    h_flex()
        .w_full()
        .min_w_0()
        .items_start()
        .gap(tokens::SPACE_2)
        .child(div().flex_1().min_w_0().child(action_status_short(
            SharedString::from(format!("applications-stop-state-{}", row.instance)),
            state,
            SystemTime::now(),
            tokens,
        )))
        .child(
            ActionButton::new(
                SharedString::from(format!("applications-stop-details-{}", row.instance)),
                "Details",
            )
            .variant(ButtonVariant::Quiet)
            .on_click(move |_, window, cx| {
                open_state_detail(&opener, slot.clone(), title.clone(), window, cx);
            }),
        )
        .into_any_element()
}

/// The stop cell of a row: the stop control. The state of its last stop is
/// in the row below ([`stop_state_row`]).
fn stop_cell(
    row: &ApplicationRow,
    entity: &Entity<AppModel>,
    model: &AppModel,
    tokens: &Tokens,
) -> AnyElement {
    let slot = Slot::Stop(row.instance.clone());
    let busy: bool = model.actions.is_busy(&slot);
    // The window has at most one stop confirmation: while one is open, each
    // stop control is off, and the row below its group says why.
    let open: Option<&str> = model.actions.stop_open();
    let mut column = v_flex()
        .gap(tokens::SPACE_1)
        .items_start()
        .w_full()
        .min_w_0();
    if stop_offered(row.protection) {
        let opener: Entity<AppModel> = entity.clone();
        let (instance, name) = (row.instance.clone(), row.name.clone());
        column = column.child(
            ActionButton::new(
                SharedString::from(format!("applications-stop-{}", row.instance)),
                "Stop…",
            )
            .variant(ButtonVariant::Quiet)
            .loading(busy)
            .disabled(open.is_some())
            .on_click(move |_, window, cx| {
                open_stop(&opener, &instance, &name, window, cx);
            }),
        );
    } else {
        column = column.child(caption(
            SharedString::from(format!("applications-stop-none-{}", row.instance)),
            "No stop",
            tokens,
        ));
    }
    column.into_any_element()
}

fn group_table(
    snapshot: &ProcessesSnapshot,
    entity: &Entity<AppModel>,
    model: &AppModel,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let rows = snapshot.applications.iter().flat_map(|row| {
        let (footprint, partial) = group_footprint(row);
        let (protection, tone) = protection_pill(row.protection);
        // The reason is a short caption: the cell lets it shrink, so that it
        // wraps inside the column and a longer reason ends with an ellipsis,
        // with the full reason as its label and, when it is cut, its tooltip.
        let mut protection_cell = v_flex()
            .w_full()
            .min_w_0()
            .gap(tokens::SPACE_1)
            .items_start()
            .child(
                StatusPill::new(protection, tone).id(SharedString::from(format!(
                    "applications-protection-{}",
                    row.instance
                ))),
            );
        if let Some(reason) = protection_reason(row.protection) {
            protection_cell = protection_cell.child(short_caption(
                SharedString::from(format!("applications-protection-reason-{}", row.instance)),
                reason,
                tokens,
            ));
        }
        let (growth, growth_partial) = group_growth(row);
        let mut change = v_flex()
            .gap(tokens::SPACE_1)
            .items_end()
            .child(mono_text(growth, mono, true, tokens));
        if growth_partial {
            change = change.child(MonoTag::new(
                SharedString::from(format!("applications-growth-partial-{}", row.instance)),
                "partial",
            ));
        }
        let mut size = v_flex()
            .gap(tokens::SPACE_1)
            .items_end()
            .child(mono_text(footprint, mono, stale, tokens));
        if partial {
            size = size.child(MonoTag::new(
                SharedString::from(format!("applications-partial-{}", row.instance)),
                "partial",
            ));
        }
        let group: TableRow = TableRow::new()
            .id(SharedString::from(format!(
                "applications-row-{}",
                row.instance
            )))
            .child(cell(
                div()
                    .id(SharedString::from(format!(
                        "applications-name-{}",
                        row.instance
                    )))
                    .test_support()
                    .aria_label(group_label(row))
                    .min_w_0()
                    .child(mono_text(row.name.clone(), mono, false, tokens)),
                4,
                false,
            ))
            .child(cell(row.kind.label(), 2, false))
            .child(cell(
                mono_text(row.members.to_string(), mono, true, tokens),
                1,
                true,
            ))
            .child(cell(size, 3, true))
            .child(cell(change, 3, true))
            .child(cell(foreground_text(row.foreground), 2, false))
            .child(cell(protection_cell, 3, false))
            .child(
                cell(stop_cell(row, entity, model, tokens), 2, false).min_w(STOP_COLUMN_MIN_WIDTH),
            );
        std::iter::once(group).chain(stop_state_row(row, entity, model, tokens))
    });
    Table::new()
        .small()
        .accessibility_label("Application and job groups by physical footprint")
        .child(
            TableHeader::new().child(
                TableRow::new()
                    .child(head("Application or job", 4, false, tokens))
                    .child(head("Kind", 2, false, tokens))
                    .child(head("Processes", 1, true, tokens))
                    .child(head("Footprint", 3, true, tokens))
                    .child(head("Growth", 3, true, tokens))
                    .child(head("Foreground", 2, false, tokens))
                    .child(head("Hard protection", 3, false, tokens))
                    .child(head("Stop", 2, false, tokens).min_w(STOP_COLUMN_MIN_WIDTH)),
            ),
        )
        .child(TableBody::new().children(rows))
        .into_any_element()
}

fn groups_card(
    processes: &Shown<ProcessesSnapshot>,
    entity: &Entity<AppModel>,
    model: &AppModel,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::Cpu, "Applications and jobs")
        .subtitle("Sum of the physical footprint of the verified members");
    let body: AnyElement = match processes {
        Shown::Loading => skeleton_rows(6),
        Shown::Failed(reason) => failed_body("applications-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let mut body = v_flex().gap(tokens::SPACE_3);
            if value.applications.is_empty() {
                body = body.child(body_line(
                    "applications-empty",
                    "The reading has no application or job with a verified member.",
                    true,
                    tokens,
                ));
            } else {
                body = body.child(group_table(
                    value,
                    entity,
                    model,
                    stale_age.is_some(),
                    mono,
                    tokens,
                ));
            }
            body = body.child(caption(
                "applications-summary",
                group_summary(value),
                tokens,
            ));
            if let Some(age) = stale_age {
                body = body.child(stale_line("applications-stale", age, tokens));
            }
            body = body.child(
                ProvenanceLine::new(value.source, value.captured_at, "processes of this user")
                    .id("applications-provenance"),
            );
            body.into_any_element()
        }
    };
    card(header, body)
}

fn attribution_card(
    processes: &Shown<ProcessesSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::Network, "Attribution")
        .subtitle("Only positive evidence makes a process a member");
    let body: AnyElement = match processes {
        Shown::Loading => skeleton_rows(4),
        Shown::Failed(reason) => failed_body("attribution-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let stale: bool = stale_age.is_some();
            let mut body = v_flex().gap(tokens::SPACE_2);
            for (id, label, count) in [
                ("attribution-groups", "Groups", value.application_count),
                (
                    "attribution-processes",
                    "Processes of this user",
                    value.process_count,
                ),
                (
                    "attribution-unattributed",
                    "With no verified group",
                    value.unattributed,
                ),
                (
                    "attribution-other-user",
                    "Of other users, not recorded",
                    value.other_user,
                ),
                (
                    "attribution-not-readable",
                    "Not readable",
                    value.not_readable,
                ),
            ] {
                body = body.child(fact(id, label, count.to_string(), mono, stale, tokens));
            }
            for (index, note) in value.notes.iter().enumerate() {
                body = body.child(caption(
                    SharedString::from(format!("attribution-note-{index}")),
                    note.clone(),
                    tokens,
                ));
            }
            body.into_any_element()
        }
    };
    card(header, body)
}

fn control_card(tokens: &Tokens) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::Info, "Protection and control")
        .subtitle("What this screen shows and does not show");
    let lines: [(&str, &str); 5] = [
        (
            "applications-protection-note",
            "\"Protected\" comes from the catalog of hard protections. Automation does not stop a protected group.",
        ),
        (
            "applications-unknown-note",
            "\"Unknown\" means that the lookup gave no result. Automation skips such a group.",
        ),
        (
            "applications-stop-note",
            "Stop makes a quit plan and a force-quit plan for the verified members of the group and shows the processes that they bind. The agent admits the plan that you confirm; with no agent, nothing is sent. A stop is done only when the agent confirms the exit.",
        ),
        (
            "applications-growth-note",
            "Growth is the footprint change since the previous reading of this window. A process that is new since then has no value.",
        ),
        (
            "applications-restart-note",
            "No restart history exists: Svalnir does not start an application again, and the system does not record a relaunch. The relaunch cooldowns show when the memory guard can stop an application again.",
        ),
    ];
    let mut body = v_flex().gap(tokens::SPACE_2);
    for (id, text) in lines {
        body = body.child(caption(id, text, tokens));
    }
    card(header, body)
}

/// The relaunch cooldowns of the controller record: after an intervention,
/// the memory guard does not stop the same application again until the
/// cooldown ends.
fn relaunch_card(
    controller: &Shown<ControllerSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::Info, "Relaunch cooldowns")
        .subtitle("Controller record of the agent");
    let body: AnyElement = controller_body(
        "applications-relaunch",
        controller,
        tokens,
        |rows, stale| {
            let mut lines: Vec<AnyElement> = cooldown_facts(
                "applications-relaunch",
                &rows.cooldowns,
                |subject| matches!(subject, CooldownSubject::Relaunch { .. }),
                stale,
                mono,
                tokens,
            );
            if lines.is_empty() {
                lines.push(caption(
                    "applications-relaunch-empty",
                    "The controller record has no relaunch cooldown.",
                    tokens,
                ));
            }
            lines.push(caption(
                "applications-relaunch-note",
                "A cooldown inhibits an automatic stop only. \"Active (other boot)\" is a cooldown of a different boot or clock of the agent, so its end cannot be established; the agent treats it as active.",
                tokens,
            ));
            lines
        },
    );
    card(header, body)
}

impl Render for ApplicationsScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let entity: Entity<AppModel> = self.model.clone();
        let model: &AppModel = self.model.read(cx);
        let processes = shown(&model.processes, SystemTime::now(), |processes| {
            processes.captured_at
        });
        let controller = shown(&model.controller, SystemTime::now(), |controller| {
            controller.captured_at
        });
        let cards: Vec<(CardWidth, AnyElement)> = vec![
            (
                CardWidth::Full,
                groups_card(&processes, &entity, model, &mono, tokens),
            ),
            (
                CardWidth::Share,
                attribution_card(&processes, &mono, tokens),
            ),
            (
                CardWidth::Share,
                budgets_card(&controller, "applications-budgets", &mono, tokens),
            ),
            (CardWidth::Share, relaunch_card(&controller, &mono, tokens)),
            (CardWidth::Share, control_card(tokens)),
        ];
        screen("Applications", cards, self.activation, cx.reduce_motion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::records::{GroupKind, Growth, ProtectionReason, UnknownCause};

    fn row(footprint: Measured<u64>, unmeasured: usize) -> ApplicationRow {
        ApplicationRow {
            instance: "i".to_owned(),
            name: "com.example.app".to_owned(),
            kind: GroupKind::Application,
            members: 3,
            footprint,
            unmeasured_members: unmeasured,
            foreground: Foreground::Unknown,
            protection: Protection::Unknown {
                cause: UnknownCause::NoExecutableEvidence,
            },
            growth: Measured::Value(Growth {
                delta: 4_000_000,
                elapsed: std::time::Duration::from_secs(5),
            }),
            growth_missing: 1,
        }
    }

    #[test]
    fn unknown_protection_is_a_warning_and_not_not_protected() {
        let unknown = Protection::Unknown {
            cause: UnknownCause::NoMember,
        };
        assert_eq!(protection_pill(unknown), ("Unknown", Tone::Warning));
        assert_eq!(protection_reason(unknown), Some("The group has no member"));
        assert_eq!(
            protection_pill(Protection::NotProtected),
            ("Not protected", Tone::Neutral)
        );
        let protected = Protection::Protected {
            reason: ProtectionReason::SessionApplication,
        };
        assert_eq!(protection_pill(protected), ("Protected", Tone::Brand));
        assert_eq!(
            protection_reason(protected),
            Some("An application of the login session")
        );
        assert_eq!(protection_reason(Protection::NotProtected), None);
        assert_eq!(foreground_text(Foreground::Unknown), "Not known");
    }

    #[test]
    fn a_sum_with_a_member_with_no_value_is_partial() {
        assert_eq!(
            group_footprint(&row(Measured::Value(2_000_000_000), 0)),
            ("2.0 GB".to_owned(), false)
        );
        assert_eq!(
            group_footprint(&row(Measured::Value(2_000_000_000), 1)),
            ("2.0 GB".to_owned(), true)
        );
        // No member has a value: the sum is unavailable, not a partial zero.
        assert_eq!(
            group_footprint(&row(Measured::Unavailable("x".into()), 3)),
            ("\u{2014}".to_owned(), false)
        );
    }

    #[test]
    fn the_label_of_a_group_states_partial_and_unavailable() {
        assert_eq!(
            group_label(&row(Measured::Value(2_000_000_000), 1)),
            "com.example.app, Application, 3 processes, footprint 2.0 GB, partial: 1 of 3 processes have no value, growth +4.0 MB in 5 s, partial: 1 of 3 processes have no value, protection: Unknown (A member has no executable evidence)"
        );
        assert_eq!(
            group_label(&row(Measured::Unavailable("denied".into()), 3)),
            "com.example.app, Application, 3 processes, footprint not available: denied, growth +4.0 MB in 5 s, partial: 1 of 3 processes have no value, protection: Unknown (A member has no executable evidence)"
        );
    }
}
