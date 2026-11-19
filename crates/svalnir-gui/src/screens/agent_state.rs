//! The texts and the cards of the controller record of the agent, which the
//! Memory, Applications, and Automation screens share: the application
//! budgets, the cooldowns, the usage of an incident, the footprint growth,
//! and the value of a threshold with its unit.

use super::common::{
    Shown, ago, caption, card, fact, failed_body, inset, skeleton_rows, stale_line,
};
use crate::{
    data::{
        model::Measured,
        records::{
            BudgetRow, ControllerRows, ControllerSnapshot, CooldownRow, CooldownState,
            CooldownSubject, Growth, IncidentUsage, JournalUsageRow, StatusAge, ThresholdQuantity,
            UsageRow,
        },
    },
    theme::tokens::{self, Tokens},
    ui::{
        data_state::{UNAVAILABLE_TEXT, format_bytes},
        provenance::ProvenanceLine,
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, IntoElement, ParentElement, SharedString, Styled,
    component::{IconName, v_flex},
};
use std::time::{Duration, SystemTime};

/// The label of the source of the controller rows.
const SOURCE: &str = "journal";

/// A time span: "40 s", "9 min", "3 h", "2 d". Less than one second is "0 s".
#[must_use]
pub fn span(duration: Duration) -> String {
    let seconds: u64 = duration.as_secs();
    if seconds < 60 {
        format!("{seconds} s")
    } else if seconds < 3_600 {
        format!("{} min", seconds / 60)
    } else if seconds < 86_400 {
        format!("{} h", seconds / 3_600)
    } else {
        format!("{} d", seconds / 86_400)
    }
}

/// A time that remains, rounded up so that a countdown does not show less
/// than remains: "40 s", "9 min", "3 h", "2 d".
#[must_use]
pub fn span_left(duration: Duration) -> String {
    let seconds: u64 = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
    if seconds < 60 {
        format!("{seconds} s")
    } else if seconds < 3_600 {
        format!("{} min", seconds.div_ceil(60))
    } else if seconds < 86_400 {
        format!("{} h", seconds.div_ceil(3_600))
    } else {
        format!("{} d", seconds.div_ceil(86_400))
    }
}

/// The text of a footprint change: "+24 MB in 5 s", "−3 MB in 5 s", or "No
/// change in 5 s". An unavailable change is an em dash, not zero.
#[must_use]
pub fn growth_text(growth: &Measured<Growth>) -> String {
    match growth {
        Measured::Unavailable(_) => UNAVAILABLE_TEXT.to_owned(),
        Measured::Value(growth) => {
            let elapsed: String = span(growth.elapsed);
            if growth.delta == 0 {
                return format!("No change in {elapsed}");
            }
            let size: u64 = u64::try_from(growth.delta.unsigned_abs()).unwrap_or(u64::MAX);
            let (value, unit) = format_bytes(size);
            let sign: char = if growth.delta > 0 { '+' } else { '\u{2212}' };
            format!("{sign}{value} {unit} in {elapsed}")
        }
    }
}

/// The exact text of `value` with the largest unit of `units` that divides
/// it with no remainder. `units` goes from the largest factor to 1.
fn exact(value: u64, units: &[(u64, &str)]) -> String {
    for (factor, unit) in units {
        if value != 0 && value.is_multiple_of(*factor) {
            return format!("{} {unit}", value / factor);
        }
    }
    let unit: &str = units.last().map_or("", |(_, unit)| unit);
    format!("{value} {unit}")
}

/// The text of a threshold with its unit: "25 GiB", "2 min", or "3". The
/// unit is the largest that gives the stored value with no fraction, so the
/// text is exact. A key with no known unit shows the number and says so.
#[must_use]
pub fn threshold_text(value: ThresholdQuantity) -> String {
    const KIB: u64 = 1024;
    const MILLISECOND: u64 = 1_000_000;
    const SECOND: u64 = 1_000 * MILLISECOND;
    match value {
        ThresholdQuantity::Bytes(bytes) => exact(
            bytes,
            &[
                (KIB * KIB * KIB * KIB, "TiB"),
                (KIB * KIB * KIB, "GiB"),
                (KIB * KIB, "MiB"),
                (KIB, "KiB"),
                (1, "B"),
            ],
        ),
        ThresholdQuantity::Nanoseconds(0) => "0 s".to_owned(),
        ThresholdQuantity::Nanoseconds(time) => exact(
            time,
            &[
                (86_400 * SECOND, "d"),
                (3_600 * SECOND, "h"),
                (60 * SECOND, "min"),
                (SECOND, "s"),
                (MILLISECOND, "ms"),
                (1, "ns"),
            ],
        ),
        ThresholdQuantity::Count(count) => count.to_string(),
        ThresholdQuantity::NoUnit(number) => format!("{number} (unit not known)"),
    }
}

/// The text of the status of a cooldown.
#[must_use]
pub fn cooldown_text(state: CooldownState) -> String {
    match state {
        CooldownState::Active { remaining } => format!("Active, {} left", span_left(remaining)),
        CooldownState::Elapsed => "Ended".to_owned(),
        CooldownState::EarlierBoot => "Active (other boot)".to_owned(),
    }
}

/// The value of a cooldown fact: its status, and its cause when the
/// subject does not name it. A relaunch cooldown has one cause.
#[must_use]
pub fn cooldown_value(row: &CooldownRow) -> String {
    match row.subject {
        CooldownSubject::Relaunch { .. } => cooldown_text(row.state),
        _ => format!(
            "{} ({})",
            cooldown_text(row.state),
            row.cause.to_lowercase()
        ),
    }
}

/// The text of what a cooldown inhibits.
#[must_use]
pub fn subject_text(subject: &CooldownSubject) -> String {
    match subject {
        CooldownSubject::Relaunch { application } => format!("Stop of {application}"),
        CooldownSubject::DiskPass { incident: Some(id) } => format!("Next pass of {id}"),
        CooldownSubject::DiskPass { incident: None } => "Next disk pass".to_owned(),
        CooldownSubject::ObserveAfterAction { incident } => {
            format!("Observation after an action of {incident}")
        }
        CooldownSubject::MemoryBackoff { incident } => {
            format!("Next target of {incident}")
        }
    }
}

fn bytes(value: u64) -> String {
    let (number, unit) = format_bytes(value);
    format!("{number} {unit}")
}

/// The text of the usage of a budget generation, with the reserved part.
#[must_use]
pub fn usage_text(usage: UsageRow) -> String {
    match usage {
        UsageRow::Disk {
            consumed_bytes,
            reserved_bytes,
            consumed_items,
            reserved_items,
            passes,
        } => format!(
            "{} and {consumed_items} items used, {} and {reserved_items} items reserved, {passes} passes",
            bytes(consumed_bytes),
            bytes(reserved_bytes)
        ),
        UsageRow::Memory {
            consumed_slots,
            reserved_slots,
        } => format!("{consumed_slots} application slots used, {reserved_slots} reserved"),
    }
}

/// The text of the consumed usage that the journal records.
#[must_use]
pub fn journal_usage_text(usage: &JournalUsageRow) -> String {
    match usage {
        JournalUsageRow::Recorded {
            slots,
            work_bytes,
            items,
        } => format!(
            "{slots} application slots, {} and {items} items",
            bytes(*work_bytes)
        ),
        JournalUsageRow::NoConsumedDispatch => "No consumed dispatch".to_owned(),
        JournalUsageRow::Unreadable(reason) => format!("{UNAVAILABLE_TEXT} ({reason})"),
    }
}

/// The text of a budget row: the trigger state and whether it is latched.
#[must_use]
pub fn budget_text(budget: &BudgetRow) -> String {
    let trigger: &str = budget
        .trigger
        .map_or("Not in the status", |trigger| trigger.label());
    if budget.latched {
        format!("{trigger} · latched")
    } else {
        trigger.to_owned()
    }
}

/// The sentence about the age of the status record of the agent. `None`
/// when the status is current.
#[must_use]
pub fn status_age_text(age: StatusAge) -> Option<String> {
    match age {
        StatusAge::Current => None,
        StatusAge::Stale { age } => Some(format!(
            "The status of the agent is {} old: the agent does not run, or it does not write. These rows are the state at that time.",
            span(age)
        )),
        StatusAge::Stopped => Some(
            "The agent recorded that it stopped. These rows are the state that its next start restores."
                .to_owned(),
        ),
        StatusAge::Unknown => Some(
            "The journal has no usable status record of the agent, or its time is later than the clock of this window, so the age of these rows is not known."
                .to_owned(),
        ),
    }
}

/// The facts of one open incident: the current usage and each budget
/// generation with the usage of the journal.
pub fn incident_block(
    prefix: &str,
    incident: &IncidentUsage,
    now: SystemTime,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let id: &str = incident.id.as_str();
    let mut block = v_flex().gap(tokens::SPACE_1).child(fact(
        SharedString::from(format!("{prefix}-usage-{id}")),
        "Usage of the current generation",
        incident.current.map_or_else(
            || format!("{UNAVAILABLE_TEXT} (the policy state has no entry)"),
            usage_text,
        ),
        mono,
        stale,
        tokens,
    ));
    for generation in &incident.generations {
        let label: String = format!(
            "Generation {}, {} {}",
            generation.generation,
            if generation.rearmed {
                "rearmed"
            } else {
                "opened"
            },
            ago(generation.started_at, now)
        );
        let value: String = match generation.final_usage {
            Some(usage) => format!(
                "Final: {}. Journal: {}",
                usage_text(usage),
                journal_usage_text(&generation.journal)
            ),
            None => format!("Journal: {}", journal_usage_text(&generation.journal)),
        };
        block = block.child(fact(
            SharedString::from(format!(
                "{prefix}-generation-{id}-{}",
                generation.generation
            )),
            &label,
            value,
            mono,
            stale,
            tokens,
        ));
    }
    if !incident.established {
        block = block.child(caption(
            SharedString::from(format!("{prefix}-not-established-{id}")),
            "Problem: a restart could not establish the usage. The incident permits no automatic work until it closes or you rearm it.",
            tokens,
        ));
    }
    if incident.unknown_outcome {
        block = block.child(caption(
            SharedString::from(format!("{prefix}-unknown-outcome-{id}")),
            "Problem: an operation of the incident has an effect that is not known. See History.",
            tokens,
        ));
    }
    block.into_any_element()
}

/// The cooldown facts of `rows` that `keep` selects.
pub fn cooldown_facts(
    prefix: &str,
    rows: &[CooldownRow],
    keep: impl Fn(&CooldownSubject) -> bool,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    rows.iter()
        .filter(|row| keep(&row.subject))
        .enumerate()
        .map(|(index, row)| {
            fact(
                SharedString::from(format!("{prefix}-cooldown-{index}")),
                &subject_text(&row.subject),
                cooldown_value(row),
                mono,
                stale,
                tokens,
            )
        })
        .collect()
}

/// The lines that close a controller card: the age of the status of the
/// agent, a note for a truncated record, the stale caption, and the
/// provenance.
pub fn controller_footer(
    prefix: &'static str,
    snapshot: &ControllerSnapshot,
    rows: &ControllerRows,
    stale_age: Option<&String>,
    tokens: &Tokens,
) -> Vec<AnyElement> {
    let mut lines: Vec<AnyElement> = Vec::new();
    if let Some(text) = status_age_text(snapshot.status_age) {
        lines.push(caption(
            SharedString::from(format!("{prefix}-status-age")),
            text,
            tokens,
        ));
    }
    if rows.truncated {
        lines.push(caption(
            SharedString::from(format!("{prefix}-truncated")),
            "Partial: the record has more rows than the window shows.",
            tokens,
        ));
    }
    if let Some(age) = stale_age {
        lines.push(stale_line(prefix, age, tokens));
    }
    lines.push(
        ProvenanceLine::new(
            SOURCE,
            snapshot.captured_at,
            "controller record of the agent",
        )
        .id(SharedString::from(format!("{prefix}-provenance")))
        .into_any_element(),
    );
    lines
}

/// The body of a controller card in its data state, or the skeleton, or
/// the reason that it has no rows. `content` makes the rows.
pub fn controller_body(
    prefix: &'static str,
    controller: &Shown<ControllerSnapshot>,
    tokens: &Tokens,
    content: impl FnOnce(&ControllerRows, bool) -> Vec<AnyElement>,
) -> AnyElement {
    match controller {
        Shown::Loading => skeleton_rows(3),
        Shown::Failed(reason) => unavailable(prefix, reason, tokens),
        Shown::Data { value, stale_age } => match &value.rows {
            Measured::Unavailable(reason) => unavailable(prefix, reason, tokens),
            Measured::Value(rows) => v_flex()
                .gap(tokens::SPACE_2)
                .children(content(rows, stale_age.is_some()))
                .children(controller_footer(
                    prefix,
                    value,
                    rows,
                    stale_age.as_ref(),
                    tokens,
                ))
                .into_any_element(),
        },
    }
}

fn unavailable(prefix: &'static str, reason: &str, tokens: &Tokens) -> AnyElement {
    failed_body(prefix, reason, tokens)
}

/// The card of the application budgets of the memory guard.
pub fn budgets_card(
    controller: &Shown<ControllerSnapshot>,
    prefix: &'static str,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::ChartPie, "Application budgets")
        .subtitle("Trigger state at the latest step of the agent");
    let body: AnyElement = controller_body(prefix, controller, tokens, |rows, stale| {
        let mut lines: Vec<AnyElement> = Vec::new();
        if rows.budgets.is_empty() {
            lines.push(caption(
                SharedString::from(format!("{prefix}-empty")),
                "The controller record has no application budget.",
                tokens,
            ));
        }
        for budget in &rows.budgets {
            lines.push(fact(
                SharedString::from(format!("{prefix}-budget-{}", budget.id)),
                &budget.id,
                budget_text(budget),
                mono,
                stale,
                tokens,
            ));
        }
        lines.push(caption(
            SharedString::from(format!("{prefix}-note")),
            "\"Latched\" means that a trigger episode did not recover. A budget alone is not permission to stop an application.",
            tokens,
        ));
        lines
    });
    card(header, body)
}

/// An inset of the facts of one incident.
pub fn incident_inset(
    prefix: &str,
    incident: &IncidentUsage,
    now: SystemTime,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    inset(
        v_flex()
            .gap(tokens::SPACE_1)
            .child(fact(
                SharedString::from(format!("{prefix}-incident-{}", incident.id)),
                "Open incident",
                format!("{} · generation {}", incident.id, incident.generation),
                mono,
                stale,
                tokens,
            ))
            .child(incident_block(prefix, incident, now, stale, mono, tokens)),
        tokens,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_threshold_has_the_exact_unit_of_its_field() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(threshold_text(ThresholdQuantity::Bytes(25 * GIB)), "25 GiB");
        assert_eq!(
            threshold_text(ThresholdQuantity::Bytes(1536 * 1024 * 1024)),
            "1536 MiB"
        );
        assert_eq!(threshold_text(ThresholdQuantity::Bytes(1000)), "1000 B");
        assert_eq!(
            threshold_text(ThresholdQuantity::Nanoseconds(120_000_000_000)),
            "2 min"
        );
        assert_eq!(
            threshold_text(ThresholdQuantity::Nanoseconds(250_000_000)),
            "250 ms"
        );
        assert_eq!(threshold_text(ThresholdQuantity::Nanoseconds(0)), "0 s");
        assert_eq!(threshold_text(ThresholdQuantity::Nanoseconds(7)), "7 ns");
        assert_eq!(threshold_text(ThresholdQuantity::Count(3)), "3");
        assert_eq!(
            threshold_text(ThresholdQuantity::NoUnit(42)),
            "42 (unit not known)"
        );
    }

    #[test]
    fn a_growth_has_its_sign_and_no_value_is_not_zero() {
        let growth = |delta: i128| {
            Measured::Value(Growth {
                delta,
                elapsed: Duration::from_secs(5),
            })
        };
        assert_eq!(growth_text(&growth(24_000_000)), "+24.0 MB in 5 s");
        assert_eq!(growth_text(&growth(-3_000_000)), "\u{2212}3.0 MB in 5 s");
        assert_eq!(growth_text(&growth(0)), "No change in 5 s");
        assert_eq!(
            growth_text(&Measured::Unavailable("new".to_owned())),
            UNAVAILABLE_TEXT
        );
    }

    #[test]
    fn a_time_that_remains_is_rounded_up() {
        assert_eq!(span_left(Duration::from_millis(1_199_900)), "20 min");
        assert_eq!(span_left(Duration::from_mins(20)), "20 min");
        assert_eq!(span_left(Duration::from_millis(500)), "1 s");
        assert_eq!(span_left(Duration::from_secs(7_000)), "2 h");
        assert_eq!(span(Duration::from_millis(1_199_900)), "19 min");
    }

    #[test]
    fn a_cooldown_of_an_earlier_boot_is_active() {
        assert_eq!(
            cooldown_text(CooldownState::Active {
                remaining: Duration::from_secs(540)
            }),
            "Active, 9 min left"
        );
        assert_eq!(cooldown_text(CooldownState::Elapsed), "Ended");
        assert_eq!(
            cooldown_text(CooldownState::EarlierBoot),
            "Active (other boot)"
        );
    }

    #[test]
    fn a_current_status_has_no_age_sentence() {
        assert_eq!(status_age_text(StatusAge::Current), None);
        assert!(
            status_age_text(StatusAge::Stale {
                age: Duration::from_mins(12)
            })
            .is_some_and(|text| text.contains("12 min old"))
        );
        assert!(status_age_text(StatusAge::Unknown).is_some());
    }

    #[test]
    fn the_usage_texts_name_the_reserved_part() {
        assert_eq!(
            usage_text(UsageRow::Memory {
                consumed_slots: 1,
                reserved_slots: 1
            }),
            "1 application slots used, 1 reserved"
        );
        assert_eq!(
            journal_usage_text(&JournalUsageRow::NoConsumedDispatch),
            "No consumed dispatch"
        );
    }
}
