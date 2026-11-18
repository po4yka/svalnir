//! The session chart: a value curve, an event rail, a live head, a sample
//! matrix, and a change strip on one time axis (`DESIGN.md` section 5).
//!
//! `session_model` is pure: it turns the readings of this window into
//! columns and events, and places the labels. `SessionChart` paints the dots
//! from one canvas and places the texts as small elements over it.

use crate::{
    data::model::{HostSample, Measured, OperationRow, PressureLevel},
    theme::{
        glow,
        tokens::{self, Tokens, to_hsla},
    },
    ui::{
        chart_tip::{ChartTip, TipContent},
        data_state::{UNAVAILABLE_TEXT, format_bytes},
    },
    viz::{
        dial::DialColors,
        hover::{FocusTarget, Tween, take_launch_focus},
        led::lit_color,
        runway::{self, Estimate, Trend},
        tick_track::{TickState, state_of, track_label},
    },
};
use gpui_kit::{
    App, BorderStyle, Bounds, BoxShadow, Corners, Edges, Entity, FocusHandle, Hsla,
    InteractiveElement as _, IntoElement, ParentElement as _, Pixels, Point, RenderOnce, Role,
    SharedString, StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window,
    canvas,
    component::{ActiveTheme as _, h_flex, v_flex},
    div, fill, hsla, point, px, quad, size,
};
use std::{
    cell::Cell,
    rc::Rc,
    time::{Instant, SystemTime},
};

/// The rows of the curve part.
pub const CURVE_ROWS: usize = 10;
/// The dots in the height of one matrix row.
pub const MATRIX_DOTS: usize = 4;
/// The dots in the height of the change strip.
pub const STRIP_DOTS: usize = 3;
/// The most flags that show their text.
pub const MAX_FLAGS: usize = 4;
/// The lattice row of the top of the change strip.
const STRIP_ROW: usize = CURVE_ROWS + 1;
/// The lattice row of the top of the disk row of the matrix.
const DISK_ROW: usize = STRIP_ROW + STRIP_DOTS + 1;
/// The lattice row of the top of the swap row.
const SWAP_ROW: usize = DISK_ROW + MATRIX_DOTS + 1;
/// The lattice row of the top of the pressure row.
const PRESSURE_ROW: usize = SWAP_ROW + MATRIX_DOTS + 1;
/// The rows of the whole lattice.
pub const TOTAL_ROWS: usize = PRESSURE_ROW + MATRIX_DOTS;
/// The width of the left gutter with the names of the rows, in pixels.
pub const LEFT_GUTTER: f32 = 56.0;
/// The width of the right gutter with the newest values, in pixels.
pub const RIGHT_GUTTER: f32 = 64.0;
/// The height of one line of a 10 px text, in pixels.
const LABEL_LINE: f32 = 12.0;
/// The height of the zone of the two-line event labels, in pixels.
const LABEL_BAND: f32 = 28.0;
/// The distance from the top of the rail zone to the lattice, in pixels.
const RAIL_TO_LATTICE: f32 = 10.0;
/// The height of the time axis, in pixels.
const AXIS_BAND: f32 = 16.0;
/// The longest text of an operation event, in characters.
const FLAG_TEXT_MAX: usize = 16;
/// The seconds that the ring of the live head takes to expand and fade.
pub const LIVE_PERIOD_SECS: f32 = 1.6;

/// One column: one reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// The offset of the local time from UTC at the reading, when known.
    pub utc_offset: Option<i32>,
    /// When the reading was taken.
    pub at: SystemTime,
    /// The row of the curve dot from the bottom, `0..CURVE_ROWS`; `None`
    /// for an unavailable reading.
    pub curve: Option<usize>,
    /// The dots of the disk row, 1 to 4; `None` for an unavailable reading.
    pub disk: Option<u8>,
    /// The dots of the swap row, 1 to 4; `None` for an unavailable reading.
    pub swap: Option<u8>,
    /// The dots of the pressure row: 1, 2, or 4; `None` when unavailable.
    pub pressure: Option<u8>,
    /// The pressure state of the reading.
    pub state: TickState,
    /// The available space in bytes; `None` when unavailable.
    pub available: Option<u64>,
    /// The used space of the volume in bytes; `None` when unavailable.
    pub disk_used: Option<u64>,
    /// The used swap in bytes; `None` when unavailable.
    pub swap_used: Option<u64>,
    /// The dots of the change strip, 0 to 3.
    pub change: u8,
    /// The row of the trend dot from the bottom, `0..CURVE_ROWS`; `None`
    /// outside the readings that the trend uses.
    pub trend: Option<usize>,
    /// The place of the trend line from the bottom, in thousandths of a
    /// row: `0..=(CURVE_ROWS - 1) * 1000`. The line is straight, so the
    /// paint does not put it on the rows of the lattice.
    pub trend_at: Option<u16>,
}

/// What an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A change of the pressure state; the level is the new one.
    Pressure(PressureLevel),
    /// The admission of the latest operation.
    Operation,
}

/// The box of the label of an event, in the lattice.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LabelBox {
    /// The left edge in pixels.
    pub left: f32,
    /// The width in pixels.
    pub width: f32,
}

/// An event on the time axis.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// The column of the event.
    pub column: usize,
    /// What the event is.
    pub kind: EventKind,
    /// The name: the new state, or the trigger of the operation.
    pub text: String,
    /// Whether `time` is local time. When false it is UTC.
    pub local: bool,
    /// The time of the reading, "HH:MM".
    pub time: String,
    /// The fact of the chip: "after 40 normal readings", or the state text
    /// of the operation.
    pub fact: String,
    /// Whether the event shows its label; an older event keeps its marker and
    /// its guide only.
    pub labeled: bool,
    /// The box of the label, when it shows.
    pub label: Option<LabelBox>,
}

/// The model of the chart.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionModel {
    /// The columns that the chart has; the newest column is at the right.
    pub slots: usize,
    /// The readings on screen, oldest first; at most `slots`.
    pub columns: Vec<Column>,
    /// The smallest and the largest available space on screen.
    pub range: Option<(u64, u64)>,
    /// The events, by column.
    pub events: Vec<Event>,
    /// The lowest available space on screen; `None` with fewer than two
    /// measured readings or a range of one value.
    pub min: Option<MinMark>,
    /// The newest reading; `None` without a reading.
    pub newest: Option<Newest>,
    /// The time labels of the axis.
    pub axis: Vec<AxisLabel>,
    /// Whether the times of the axis are UTC and not local time.
    pub axis_utc: bool,
    /// The runway estimate of the readings; `None` without enough readings.
    pub runway: Option<Estimate>,
}

/// The range of the measured values of `values`.
fn range_of(values: impl Iterator<Item = Option<u64>>) -> Option<(u64, u64)> {
    values.flatten().fold(None, |range, value| match range {
        None => Some((value, value)),
        Some((low, high)) => Some((low.min(value), high.max(value))),
    })
}

/// The position of `value` in `range` as a step `0..=steps`, rounded. A range
/// of one value gives the middle step.
/// The place of `value` in `range` from the bottom, in thousandths of a
/// row: `0..=(CURVE_ROWS - 1) * 1000`. A range of one value gives the middle
/// row, as [`step_in`] does. A value that is not finite gives the lowest row.
fn trend_place(value: f64, range: (u64, u64)) -> u16 {
    let top: f64 = f64::from(u16::try_from(CURVE_ROWS - 1).unwrap_or(0));
    let (low, high): (f64, f64) = (value_f64(range.0), value_f64(range.1));
    let place: f64 = if high > low && value.is_finite() {
        ((value - low) / (high - low)).clamp(0.0, 1.0) * top
    } else if high > low {
        0.0
    } else {
        (top / 2.0).floor()
    };
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the place is clamped to the rows of the curve, at most 9000"
    )]
    let thousandths: u16 = (place * 1000.0).round() as u16;
    thousandths
}

fn step_in(value: u64, range: (u64, u64), steps: usize) -> usize {
    let (low, high) = range;
    let span: u128 = u128::from(high.saturating_sub(low));
    let wide: u128 = u128::try_from(steps).unwrap_or(0);
    if span == 0 {
        return steps / 2;
    }
    let offset: u128 = u128::from(value.saturating_sub(low).min(high - low));
    usize::try_from((offset * wide * 2 + span) / (span * 2)).unwrap_or(steps)
}

/// The dots `1..=4` of `value` in `range`: its quarter. A range of one value
/// gives 1 dot.
fn quarter_dots(value: u64, range: (u64, u64)) -> u8 {
    let (low, high) = range;
    let span: u128 = u128::from(high.saturating_sub(low));
    if span == 0 {
        return 1;
    }
    let offset: u128 = u128::from(value.saturating_sub(low).min(high - low));
    let quarter: u128 = (offset * 4 / span).min(3);
    u8::try_from(quarter + 1).unwrap_or(4)
}

const fn severity(level: PressureLevel) -> u8 {
    match level {
        PressureLevel::Normal => 0,
        PressureLevel::Warning => 1,
        PressureLevel::Critical => 2,
    }
}

/// The text of a flag of an operation: its trigger, else its state, cut short.
fn short_text(operation: &OperationRow) -> String {
    let text: &str = if operation.trigger.is_empty() {
        &operation.state_text
    } else {
        &operation.trigger
    };
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= FLAG_TEXT_MAX {
        text.to_owned()
    } else {
        let head: String = chars[..FLAG_TEXT_MAX - 1].iter().collect();
        format!("{head}\u{2026}")
    }
}

/// Whether `now` is larger than `before`, both measured.
fn grew(now: &Measured<u64>, before: &Measured<u64>) -> bool {
    matches!((now, before), (Measured::Value(a), Measured::Value(b)) if a > b)
}

/// The model of the chart for the newest `slots` readings of `samples`.
#[must_use]
#[expect(clippy::too_many_lines, reason = "one pass over the readings")]
pub fn session_model(
    samples: &[HostSample],
    operation: Option<&OperationRow>,
    slots: usize,
) -> SessionModel {
    let slots: usize = slots.max(1);
    let start: usize = samples.len().saturating_sub(slots);
    let visible: &[HostSample] = &samples[start..];
    let before: Option<&HostSample> = start.checked_sub(1).and_then(|i| samples.get(i));
    let measured = |pick: fn(&HostSample) -> &Measured<u64>| {
        range_of(visible.iter().map(|s| pick(s).value().copied()))
    };
    let available: Option<(u64, u64)> = measured(|s| &s.disk_available);
    let disk: Option<(u64, u64)> = measured(|s| &s.disk_used);
    let swap: Option<(u64, u64)> = measured(|s| &s.swap_used);
    let mut columns: Vec<Column> = Vec::with_capacity(visible.len());
    let fit: Option<Trend> = runway::trend(samples);
    let trend_from: usize = samples.len().saturating_sub(runway::WINDOW);
    for (index, sample) in visible.iter().enumerate() {
        let previous: Option<&HostSample> = if index == 0 {
            before
        } else {
            visible.get(index - 1)
        };
        let change: u8 = previous.map_or(0, |prev| {
            let pressure_up: bool = matches!(
                (&sample.pressure, &prev.pressure),
                (Measured::Value(a), Measured::Value(b)) if severity(*a) > severity(*b)
            );
            u8::from(grew(&sample.disk_used, &prev.disk_used))
                + u8::from(grew(&sample.swap_used, &prev.swap_used))
                + u8::from(pressure_up)
        });
        let dots = |value: &Measured<u64>, range: Option<(u64, u64)>| -> Option<u8> {
            match (value, range) {
                (Measured::Value(v), Some(r)) => Some(quarter_dots(*v, r)),
                _ => None,
            }
        };
        columns.push(Column {
            curve: match (&sample.disk_available, available) {
                (Measured::Value(v), Some(r)) => Some(step_in(*v, r, CURVE_ROWS - 1)),
                _ => None,
            },
            disk: dots(&sample.disk_used, disk),
            swap: dots(&sample.swap_used, swap),
            pressure: match &sample.pressure {
                Measured::Value(PressureLevel::Normal) => Some(1),
                Measured::Value(PressureLevel::Warning) => Some(2),
                Measured::Value(PressureLevel::Critical) => Some(4),
                Measured::Unavailable(_) => None,
            },
            state: state_of(&sample.pressure),
            available: sample.disk_available.value().copied(),
            disk_used: sample.disk_used.value().copied(),
            swap_used: sample.swap_used.value().copied(),
            change,
            trend: fit
                .as_ref()
                .zip(available)
                .filter(|_| start + index >= trend_from)
                .map(|(line, range)| {
                    let value: f64 = line
                        .value_at(sample.at)
                        .clamp(value_f64(range.0), value_f64(range.1));
                    step_in(whole_bytes(value), range, CURVE_ROWS - 1)
                }),
            trend_at: fit
                .as_ref()
                .zip(available)
                .filter(|_| start + index >= trend_from)
                .map(|(line, range)| trend_place(line.value_at(sample.at), range)),
            at: sample.at,
            utc_offset: sample.utc_offset,
        });
    }
    let offset: usize = slots.saturating_sub(visible.len());
    let mut events: Vec<Event> = Vec::new();
    // The last measured state before the window, across unavailable readings.
    let mut last: Option<PressureLevel> = samples
        .get(..start)
        .and_then(|older| older.iter().rev().find_map(|s| s.pressure.value().copied()));
    for (column, sample) in visible.iter().enumerate() {
        if let Measured::Value(level) = &sample.pressure {
            if let Some(old) = last.filter(|old| old != level) {
                events.push(Event {
                    column,
                    kind: EventKind::Pressure(*level),
                    text: level.label().to_owned(),
                    time: clock_text(sample.at, sample.utc_offset),
                    local: sample.utc_offset.is_some(),
                    fact: after_text(readings_before(samples, start + column, old), old),
                    labeled: false,
                    label: None,
                });
            }
            last = Some(*level);
        }
    }
    if let (Some(operation), Some(first), Some(newest)) =
        (operation, visible.first(), visible.last())
        && operation.admitted_at >= first.at
        && operation.admitted_at <= newest.at
        && let Some(column) = visible.iter().rposition(|s| s.at <= operation.admitted_at)
    {
        events.push(Event {
            column,
            kind: EventKind::Operation,
            text: short_text(operation),
            time: clock_text(visible[column].at, visible[column].utc_offset),
            local: visible[column].utc_offset.is_some(),
            fact: operation.state_text.clone(),
            labeled: false,
            label: None,
        });
    }
    events.sort_by_key(|event| event.column);
    place_labels(&mut events, offset, slots);
    let measured: usize = visible
        .iter()
        .filter(|s| s.disk_available.value().is_some())
        .count();
    let min: Option<MinMark> = available
        .filter(|(low, high)| measured >= 2 && low < high)
        .map(|range| MinMark {
            row: CURVE_ROWS - 1 - step_in(range.0, range, CURVE_ROWS - 1),
            value: range.0,
        });
    let newest: Option<Newest> =
        visible
            .last()
            .zip(columns.last())
            .map(|(sample, column)| Newest {
                available: sample.disk_available.value().copied(),
                disk_used: sample.disk_used.value().copied(),
                swap_used: sample.swap_used.value().copied(),
                state: column.state,
            });
    // The axis says "UTC" when a reading on screen has no local offset.
    let axis_utc: bool = columns.iter().any(|column| column.utc_offset.is_none());
    let axis: Vec<AxisLabel> = (0..columns.len())
        .rev()
        .step_by(AXIS_STEP)
        .filter(|index| slot_center(offset + index) >= AXIS_HALF)
        .map(|index| AxisLabel {
            slot: offset + index,
            text: clock_text(columns[index].at, columns[index].utc_offset),
        })
        .collect();
    SessionModel {
        slots,
        columns,
        range: available,
        events,
        min,
        newest,
        axis,
        axis_utc,
        runway: runway::estimate(samples),
    }
}

/// A byte count as a float for the trend; the precision is enough to place a dot.
#[expect(clippy::cast_precision_loss, reason = "the value places a dot")]
const fn value_f64(bytes: u64) -> f64 {
    bytes as f64
}

/// A non-negative float as whole bytes, saturating.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to the range of the readings first"
)]
fn whole_bytes(value: f64) -> u64 {
    value.max(0.0) as u64
}

fn bytes_text(bytes: u64) -> String {
    let (value, unit) = format_bytes(bytes);
    format!("{value} {unit}")
}

/// "1 reading" or "N readings".
#[must_use]
pub fn readings_text(count: usize) -> String {
    format!(
        "{count} {}",
        if count == 1 { "reading" } else { "readings" }
    )
}

/// "1 event" or "N events".
#[must_use]
pub fn events_text(count: usize) -> String {
    format!("{count} {}", if count == 1 { "event" } else { "events" })
}

/// The caption of the range: "12.1 GB to 12.4 GB available".
#[must_use]
pub fn range_caption(range: Option<(u64, u64)>) -> String {
    match range {
        None => format!("{UNAVAILABLE_TEXT} no reading of the available space"),
        Some((low, high)) if low == high => format!("{} available", bytes_text(low)),
        Some((low, high)) => format!("{} to {} available", bytes_text(low), bytes_text(high)),
    }
}

/// The caption of the scale.
pub const SCALE_CAPTION: &str = "1 column = 1 reading";

impl SessionModel {
    /// The pressure states of the columns, for the pressure row.
    #[must_use]
    pub fn states(&self) -> Vec<TickState> {
        self.columns.iter().map(|c| c.state).collect()
    }

    /// The accessible label of the chart: the readings, the range of the
    /// available space, the readings of each pressure state, and the events.
    #[must_use]
    pub fn label(&self) -> String {
        let count = |wanted: TickState| self.columns.iter().filter(|c| c.state == wanted).count();
        let min: String = self.min.map_or_else(String::new, |min| {
            format!(", min {}", bytes_text(min.value))
        });
        let runway: String = self
            .runway_text()
            .map_or_else(String::new, |text| format!(", runway {text} (an estimate)"));
        format!(
            "Session chart: {}, {}, pressure {} normal, {} warning, {} critical{min}, {}{runway}",
            readings_text(self.columns.len()),
            range_caption(self.range),
            count(TickState::Normal),
            count(TickState::Warning),
            count(TickState::Critical),
            events_text(self.events.len()),
        )
    }

    /// The text of the runway, such as "≈ 3 h" or "steady"; `None` without an
    /// estimate.
    #[must_use]
    pub fn runway_text(&self) -> Option<String> {
        self.runway.map(|e| e.text())
    }

    /// The first slot of the newest reading, from the left.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.slots.saturating_sub(self.columns.len())
    }
}

/// The width of one character of a mono text of 10 px, in pixels.
const MONO_10: f32 = 6.0;
/// The half width of an axis label ("12:04"), in pixels.
const AXIS_HALF: f32 = 15.0;
/// The columns between two axis labels: 8 columns of 6 px are 48 px.
pub const AXIS_STEP: usize = 8;
/// The gap that two event labels keep, in pixels.
const LABEL_GAP: f32 = 4.0;
/// The padding of the chip at both sides, in pixels.
const CHIP_PAD: f32 = 8.0;

/// A count as pixels.
#[expect(clippy::cast_precision_loss, reason = "a count is far below 2^24")]
const fn count_px(count: usize) -> f32 {
    count as f32
}

/// The width of a lattice of `slots` columns, in pixels.
#[must_use]
pub const fn lattice_width(slots: usize) -> f32 {
    count_px(slots) * PITCH - (PITCH - DOT)
}

/// The x of the center of column `slot` in the lattice, in pixels.
#[must_use]
pub const fn slot_center(slot: usize) -> f32 {
    count_px(slot) * PITCH + DOT / 2.0
}

/// The span of `width` centered at `center`, moved to lie inside `0..total`.
#[must_use]
pub fn clamp_span(center: f32, width: f32, total: f32) -> f32 {
    (center - width / 2.0).min(total - width).max(0.0)
}

/// The text of a pressure state of a column, or an em dash.
#[must_use]
pub fn state_word(state: TickState) -> &'static str {
    match state {
        TickState::Normal => "Normal",
        TickState::Warning => "Warning",
        TickState::Critical => "Critical",
        TickState::Empty => UNAVAILABLE_TEXT,
    }
}

/// The time of day of `time` as "HH:MM". With `utc_offset`, the seconds east
/// of UTC of the local zone, the text is local time; with `None` it is UTC,
/// and the chart then says "UTC".
#[must_use]
pub fn clock_text(time: SystemTime, utc_offset: Option<i32>) -> String {
    let Ok(since) = time.duration_since(SystemTime::UNIX_EPOCH) else {
        return UNAVAILABLE_TEXT.to_owned();
    };
    let day: i64 = 24 * 3600;
    let utc: i64 = i64::try_from(since.as_secs() % 86_400).unwrap_or(0);
    let seconds: i64 = (utc + i64::from(utc_offset.unwrap_or(0))).rem_euclid(day);
    format!("{:02}:{:02}", seconds / 3600, seconds / 60 % 60)
}

/// The time of day of `time` as "HH:MM:SS" for the title of a card. With
/// `utc_offset` the text is local time; with `None` it is UTC and the text ends
/// with " UTC". A time before the epoch is an em dash.
#[must_use]
pub fn clock_seconds_text(time: SystemTime, utc_offset: Option<i32>) -> String {
    let Ok(since) = time.duration_since(SystemTime::UNIX_EPOCH) else {
        return UNAVAILABLE_TEXT.to_owned();
    };
    let utc: i64 = i64::try_from(since.as_secs() % 86_400).unwrap_or(0);
    let seconds: i64 = (utc + i64::from(utc_offset.unwrap_or(0))).rem_euclid(86_400);
    let text: String = format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    );
    if utc_offset.is_some() {
        text
    } else {
        format!("{text} UTC")
    }
}

/// The count of measured readings of `level` right before `index`, up to the
/// first measured reading of another state. An unavailable reading is skipped.
fn readings_before(samples: &[HostSample], index: usize, level: PressureLevel) -> usize {
    let mut count: usize = 0;
    for sample in samples[..index.min(samples.len())].iter().rev() {
        match &sample.pressure {
            Measured::Value(state) if *state == level => count += 1,
            Measured::Value(_) => break,
            Measured::Unavailable(_) => {}
        }
    }
    count
}

/// The fact of a change: "after 40 normal readings".
fn after_text(count: usize, level: PressureLevel) -> String {
    format!(
        "after {count} {} {}",
        level.label().to_lowercase(),
        if count == 1 { "reading" } else { "readings" }
    )
}

impl EventKind {
    /// The name of the kind, as the second line of a label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pressure(_) => "pressure",
            Self::Operation => "operation",
        }
    }
}

impl Event {
    /// The width of the label of this event: its longer line.
    #[must_use]
    pub fn label_width(&self) -> f32 {
        count_px(
            self.text
                .chars()
                .count()
                .max(self.kind.name().chars().count()),
        ) * MONO_10
    }
}

/// Gives the label to the newest `MAX_FLAGS` events whose label boxes do not
/// overlap. It walks from the newest event to the oldest and skips an event
/// that overlaps a label that is placed already. `events` are sorted by column.
fn place_labels(events: &mut [Event], offset: usize, slots: usize) {
    let lattice: f32 = lattice_width(slots);
    let mut placed: Vec<(f32, f32)> = Vec::new();
    for event in events.iter_mut().rev() {
        if placed.len() >= MAX_FLAGS {
            break;
        }
        let width: f32 = event.label_width();
        if width > lattice {
            continue;
        }
        let left: f32 = clamp_span(slot_center(offset + event.column), width, lattice);
        let overlaps: bool = placed.iter().any(|(other, other_width)| {
            left < other + other_width + LABEL_GAP && *other < left + width + LABEL_GAP
        });
        if !overlaps {
            placed.push((left, width));
            event.label = Some(LabelBox { left, width });
            event.labeled = true;
        }
    }
}

/// The pixel sizes of the chart.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layout {
    /// The height of the label zone above the rail; 0 without a label.
    pub label_band: f32,
    /// The y of the top of the lattice.
    pub band: f32,
    /// The width of the lattice.
    pub lattice: f32,
    /// The width of the chart with both gutters.
    pub width: f32,
    /// The y of the bottom of the matrix.
    pub matrix_bottom: f32,
    /// The height of the chart with the time axis.
    pub height: f32,
}

/// The chip of the newest event.
#[derive(Debug, Clone, PartialEq)]
pub struct Chip {
    /// The index of the event.
    pub event: usize,
    /// The left edge in the lattice, in pixels.
    pub left: f32,
    /// The width in pixels.
    pub width: f32,
    /// The name of the event.
    pub name: String,
    /// The time of the reading, in UTC.
    pub time: String,
    /// The fact.
    pub fact: String,
}

/// A time label of the axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxisLabel {
    /// The slot of the reading.
    pub slot: usize,
    /// The time of the reading, "HH:MM".
    pub text: String,
}

/// The lowest available value on screen and its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinMark {
    /// The row of the curve from the top.
    pub row: usize,
    /// The value in bytes.
    pub value: u64,
}

/// The newest reading of each series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Newest {
    /// The available space.
    pub available: Option<u64>,
    /// The used space of the volume.
    pub disk_used: Option<u64>,
    /// The used swap.
    pub swap_used: Option<u64>,
    /// The pressure state.
    pub state: TickState,
}

/// The texts of the footer tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTags {
    /// "readings N".
    pub readings: String,
    /// "range A-B GB", or an em dash.
    pub range: String,
    /// "events N".
    pub events: String,
    /// "now STATE".
    pub state: String,
    /// "runway ≈ 3 h" or "runway steady"; `None` without an estimate.
    pub runway: Option<String>,
}

/// "260.0-310.2 GB", or the two values with their units.
fn range_tag(range: Option<(u64, u64)>) -> String {
    match range {
        None => UNAVAILABLE_TEXT.to_owned(),
        Some((low, high)) if low == high => bytes_text(low),
        Some((low, high)) => {
            let (a, a_unit) = format_bytes(low);
            let (b, b_unit) = format_bytes(high);
            if a_unit == b_unit {
                format!("{a}\u{2013}{b} {a_unit}")
            } else {
                format!("{a} {a_unit}\u{2013}{b} {b_unit}")
            }
        }
    }
}

impl Chip {
    /// The text after the name: the time and the fact, each with a dot
    /// before it; empty when both are dropped.
    #[must_use]
    pub fn suffix(&self) -> String {
        let mut text: String = String::new();
        for part in [&self.time, &self.fact] {
            if !part.is_empty() {
                text.push_str(" \u{b7} ");
                text.push_str(part);
            }
        }
        text
    }

    /// The accessible label: the name, the time, and the fact that show.
    #[must_use]
    pub fn label_text(&self) -> String {
        let mut parts: Vec<&str> = vec![&self.name];
        parts.extend(
            [&self.time, &self.fact]
                .map(String::as_str)
                .into_iter()
                .filter(|p| !p.is_empty()),
        );
        parts.join(", ")
    }
}

impl SessionModel {
    /// The sizes of the chart.
    #[must_use]
    pub fn layout(&self) -> Layout {
        let label_band: f32 = if self.events.iter().any(|e| e.labeled) {
            LABEL_BAND
        } else {
            0.0
        };
        let band: f32 = label_band + RAIL_TO_LATTICE;
        let lattice: f32 = lattice_width(self.slots);
        let matrix_bottom: f32 = band + lattice_width(TOTAL_ROWS);
        Layout {
            label_band,
            band,
            lattice,
            width: LEFT_GUTTER + lattice + RIGHT_GUTTER,
            matrix_bottom,
            height: matrix_bottom + AXIS_BAND,
        }
    }

    /// The chip of the newest event, clamped inside the lattice.
    #[must_use]
    pub fn chip(&self) -> Option<Chip> {
        self.chip_of(self.events.len().checked_sub(1)?)
    }

    /// The chip of the event at `index`, clamped inside the lattice.
    #[must_use]
    pub fn chip_of(&self, index: usize) -> Option<Chip> {
        let event: &Event = self.events.get(index)?;
        let time: String = if event.time == UNAVAILABLE_TEXT || event.local {
            event.time.clone()
        } else {
            format!("{} UTC", event.time)
        };
        // The chip ends inside the lattice and the right gutter. A chip that
        // is too wide drops the fact first, then the time.
        let room: f32 = lattice_width(self.slots) + RIGHT_GUTTER;
        let name_chars: usize = event.text.chars().count();
        let time_chars: usize = time.chars().count();
        let fact_chars: usize = event.fact.chars().count();
        let candidates: [(usize, bool, bool); 3] = [
            (name_chars + 3 + time_chars + 3 + fact_chars, true, true),
            (name_chars + 3 + time_chars, true, false),
            (name_chars, false, false),
        ];
        let (chars, with_time, with_fact) = candidates
            .into_iter()
            .find(|(chars, _, _)| count_px(*chars) * MONO_10 + 2.0 * CHIP_PAD <= room)?;
        let width: f32 = count_px(chars) * MONO_10 + 2.0 * CHIP_PAD;
        let left: f32 = clamp_span(slot_center(self.offset() + event.column), width, room);
        Some(Chip {
            event: index,
            left,
            width,
            name: event.text.clone(),
            time: if with_time { time } else { String::new() },
            fact: if with_fact {
                event.fact.clone()
            } else {
                String::new()
            },
        })
    }

    /// The lowest value on screen for the label of the right gutter. The
    /// label gives way to the newest value when the live head is at its row;
    /// an unavailable newest reading has no head, so it keeps the label.
    #[must_use]
    pub fn min_label(&self) -> Option<MinMark> {
        let head: Option<usize> = self
            .columns
            .last()
            .and_then(|c| c.curve)
            .map(|value| CURVE_ROWS - 1 - value);
        self.min.filter(|min| head != Some(min.row))
    }

    /// The newest values of the right gutter: the available space, the used
    /// space, the used swap, and the pressure state. An unavailable value is
    /// an em dash.
    #[must_use]
    pub fn newest_texts(&self) -> [String; 4] {
        let text =
            |value: Option<u64>| value.map_or_else(|| UNAVAILABLE_TEXT.to_owned(), bytes_text);
        match self.newest {
            Some(newest) => [
                text(newest.available),
                text(newest.disk_used),
                text(newest.swap_used),
                state_word(newest.state).to_owned(),
            ],
            None => std::array::from_fn(|_| UNAVAILABLE_TEXT.to_owned()),
        }
    }

    /// The texts of the footer tags.
    #[must_use]
    pub fn tags(&self) -> SessionTags {
        SessionTags {
            readings: format!("readings {}", self.columns.len()),
            range: format!("range {}", range_tag(self.range)),
            events: format!("events {}", self.events.len()),
            state: format!(
                "now {}",
                self.newest
                    .map_or(UNAVAILABLE_TEXT, |newest| state_word(newest.state))
            ),
            runway: self.runway_text().map(|text| format!("runway {text}")),
        }
    }
}

/// The distance from an event marker within which the pointer picks it, in
/// pixels.
pub const MARKER_REACH: f32 = 8.0;
/// The side of a pressure marker at rest, in pixels.
const MARKER_REST: f32 = 6.0;
/// The side of a hovered marker, in pixels.
const MARKER_HOT: f32 = 8.0;

/// The mark of the session chart that the pointer or the keyboard picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMark {
    /// The reading with this index in `SessionModel::columns`.
    Column(usize),
    /// The event with this index in `SessionModel::events`.
    Event(usize),
}

impl SessionMark {
    /// The column that the mark stands at.
    #[must_use]
    pub fn column(self, model: &SessionModel) -> Option<usize> {
        match self {
            Self::Column(index) => Some(index),
            Self::Event(index) => model.events.get(index).map(|event| event.column),
        }
    }
}

/// A mark that keeps its reading when new readings arrive. It stores the time
/// of the reading, not the index of its column, because the columns shift left
/// when the chart takes a new reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedMark {
    /// The time of the reading that the mark stands at.
    at: SystemTime,
    /// For an event, its place among the events of that reading.
    event: Option<usize>,
}

impl PinnedMark {
    /// Pins `mark` of `model` to the time of its reading. `None` when the mark
    /// is not in the model.
    #[must_use]
    pub fn pin(model: &SessionModel, mark: SessionMark) -> Option<Self> {
        let column: usize = mark.column(model)?;
        let at: SystemTime = model.columns.get(column)?.at;
        let event: Option<usize> = match mark {
            SessionMark::Column(_) => None,
            SessionMark::Event(index) => Some(
                model
                    .events
                    .iter()
                    .take(index)
                    .filter(|event| event.column == column)
                    .count(),
            ),
        };
        Some(Self { at, event })
    }

    /// The mark in `model`, or `None` when its reading is no longer on screen.
    #[must_use]
    pub fn resolve(self, model: &SessionModel) -> Option<SessionMark> {
        let column: usize = model.columns.iter().position(|c| c.at == self.at)?;
        match self.event {
            None => Some(SessionMark::Column(column)),
            Some(place) => model
                .events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.column == column)
                .nth(place)
                .map(|(index, _)| SessionMark::Event(index)),
        }
    }
}

/// The mark under the point `(x, y)`, in pixels from the top-left corner of the
/// chart. An event marker within `MARKER_REACH` wins over a column. A column is
/// the whole height of the lattice at one reading. The gutters, a slot with no
/// reading, and the zones outside the lattice give `None`.
#[must_use]
pub fn session_mark_at(
    model: &SessionModel,
    layout: &Layout,
    x: f32,
    y: f32,
) -> Option<SessionMark> {
    let rail_y: f32 = layout.label_band + 3.5;
    let near = model
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let mx: f32 = LEFT_GUTTER + slot_center(model.offset() + event.column);
            (index, (x - mx).hypot(y - rail_y))
        })
        .filter(|(_, distance)| *distance <= MARKER_REACH)
        .min_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((index, _)) = near {
        return Some(SessionMark::Event(index));
    }
    let across: f32 = x - LEFT_GUTTER;
    if across < 0.0 || across >= layout.lattice || y < layout.band || y >= layout.matrix_bottom {
        return None;
    }
    let slot: usize = slot_at(across);
    let index: usize = slot.checked_sub(model.offset())?;
    (index < model.columns.len()).then_some(SessionMark::Column(index))
}

/// The slot under `across` pixels from the left edge of the lattice.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is not negative and far below the usize range"
)]
fn slot_at(across: f32) -> usize {
    (across / PITCH).floor().max(0.0) as usize
}

/// The mark after `current` when the keyboard moves by `delta` readings. With
/// no mark, a move to the right picks the oldest reading on screen and a move to
/// the left picks the newest. The move stops at both ends. A marked event moves
/// from the column of the event.
#[must_use]
pub fn step_session_mark(
    model: &SessionModel,
    current: Option<SessionMark>,
    delta: i32,
) -> Option<SessionMark> {
    let last: usize = model.columns.len().checked_sub(1)?;
    let next: usize = match current.and_then(|mark| mark.column(model)) {
        Some(at) => {
            let moved: i64 = i64::try_from(at).unwrap_or(0) + i64::from(delta);
            usize::try_from(moved.max(0)).unwrap_or(0).min(last)
        }
        None if delta >= 0 => 0,
        None => last,
    };
    Some(SessionMark::Column(next))
}

/// The oldest reading on screen, or with `end` true the newest.
#[must_use]
pub fn edge_session_mark(model: &SessionModel, end: bool) -> Option<SessionMark> {
    let last: usize = model.columns.len().checked_sub(1)?;
    Some(SessionMark::Column(if end { last } else { 0 }))
}

/// The card of the reading at column `index`: the local time, the measured
/// values, and the place of the reading on screen. An unavailable value is an
/// em dash.
#[must_use]
pub fn column_tip(model: &SessionModel, index: usize) -> Option<TipContent> {
    let column: &Column = model.columns.get(index)?;
    let bytes = |value: Option<u64>| value.map_or_else(|| UNAVAILABLE_TEXT.to_owned(), bytes_text);
    let nothing: bool = column.available.is_none()
        && column.disk_used.is_none()
        && column.swap_used.is_none()
        && column.state == TickState::Empty;
    let changes: String = if nothing {
        UNAVAILABLE_TEXT.to_owned()
    } else {
        column.change.to_string()
    };
    Some(
        TipContent::new(clock_seconds_text(column.at, column.utc_offset))
            .row("Available", bytes(column.available))
            .row("Disk used", bytes(column.disk_used))
            .row("Swap used", bytes(column.swap_used))
            .row("Pressure", state_word(column.state))
            .row("Changes", changes)
            .note(format!("Reading {} of {}", index + 1, model.columns.len())),
    )
}

/// A time label of the axis as it shows: its left edge in the lattice and
/// whether it is the label of the hovered reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxisSpot {
    /// The slot of the reading.
    pub slot: usize,
    /// The text, "HH:MM".
    pub text: String,
    /// Whether the label is the one of the hovered reading.
    pub hovered: bool,
}

/// The labels of the time axis while `hovered` is the hovered column. The
/// hovered reading gets a label when it has none, and a label that it would
/// overlap is left out.
#[must_use]
pub fn axis_spots(model: &SessionModel, hovered: Option<usize>) -> Vec<AxisSpot> {
    let mut spots: Vec<AxisSpot> = model
        .axis
        .iter()
        .map(|label| AxisSpot {
            slot: label.slot,
            text: label.text.clone(),
            hovered: false,
        })
        .collect();
    let Some(column) = hovered.and_then(|index| model.columns.get(index).map(|c| (index, c)))
    else {
        return spots;
    };
    let slot: usize = model.offset() + column.0;
    if let Some(own) = spots.iter_mut().find(|spot| spot.slot == slot) {
        own.hovered = true;
        return spots;
    }
    let center: f32 = slot_center(slot);
    spots.retain(|spot| (slot_center(spot.slot) - center).abs() >= 2.0 * AXIS_HALF);
    spots.push(AxisSpot {
        slot,
        text: clock_text(column.1.at, column.1.utc_offset),
        hovered: true,
    });
    spots
}

/// The progress `0.0..=1.0` of the ring of the live head at `phase` seconds.
#[must_use]
pub fn live_progress(phase: f32) -> f32 {
    (phase.rem_euclid(LIVE_PERIOD_SECS)) / LIVE_PERIOD_SECS
}

/// The tone color of an event.
fn event_color(kind: EventKind, colors: &DialColors, brand: Hsla) -> Hsla {
    match kind {
        EventKind::Pressure(PressureLevel::Normal) => colors.positive,
        EventKind::Pressure(PressureLevel::Warning) => colors.warning,
        EventKind::Pressure(PressureLevel::Critical) => colors.negative,
        EventKind::Operation => brand,
    }
}

/// Everything one paint of the chart needs.
#[derive(Debug, Clone)]
struct SessionPaint {
    model: SessionModel,
    layout: Layout,
    colors: DialColors,
    brand: Hsla,
    muted_ink: Hsla,
    /// The color of the trend line: the text color, so that the line
    /// differs from the dots of the curve.
    trend_ink: Hsla,
    ink: Hsla,
    glow: bool,
    live: Option<f32>,
    muted: bool,
    /// The hovered column, for the line and the full-strength dots.
    hover_column: Option<usize>,
    /// The hover amount `0.0..=1.0` of each event marker.
    markers: Vec<f32>,
}

const PITCH: f32 = 6.0;
const DOT: f32 = 4.0;

fn dot_at(origin: Point<Pixels>, x: f32, y: f32, side: f32) -> Bounds<Pixels> {
    Bounds::new(
        point(
            origin.x + px(x + (DOT - side) / 2.0),
            origin.y + px(y + (DOT - side) / 2.0),
        ),
        size(px(side), px(side)),
    )
}

/// A rectangle at `x`, `y` in the chart.
fn rect_at(origin: Point<Pixels>, x: f32, y: f32, width: f32, height: f32) -> Bounds<Pixels> {
    Bounds::new(
        point(origin.x + px(x), origin.y + px(y)),
        size(px(width), px(height)),
    )
}

/// A diamond of `side` px (6 px at rest) as five stepped rows.
fn paint_diamond(
    window: &mut Window,
    origin: Point<Pixels>,
    center: (f32, f32),
    side: f32,
    color: Hsla,
) {
    let (cx, cy) = center;
    let unit: f32 = side / MARKER_REST;
    let step: f32 = 1.2 * unit;
    let widths: [f32; 5] = [1.2, 3.6, 6.0, 3.6, 1.2];
    for (index, width) in widths.iter().enumerate() {
        let wide: f32 = width * unit;
        let top: f32 = cy - side / 2.0 + count_px(index) * step;
        window.paint_quad(fill(
            rect_at(origin, cx - wide / 2.0, top, wide, step),
            color,
        ));
    }
}

#[expect(clippy::too_many_lines, reason = "one pass in paint order")]
fn paint_session(paint: &SessionPaint, bounds: Bounds<Pixels>, window: &mut Window) {
    let origin: Point<Pixels> = bounds.origin;
    let model: &SessionModel = &paint.model;
    let layout: Layout = paint.layout;
    let rest: f32 = if paint.muted { 0.6 } else { 1.0 };
    let row_y = |row: usize| -> f32 { layout.band + count_px(row) * PITCH };
    let slot_x = |slot: usize| -> f32 { LEFT_GUTTER + count_px(slot) * PITCH };
    let round: Corners<Pixels> = Corners::all(px(DOT / 2.0));
    let put = |window: &mut Window, slot: usize, row: usize, color: Hsla| {
        window.paint_quad(
            fill(dot_at(origin, slot_x(slot), row_y(row), DOT), color).corner_radii(round),
        );
    };
    let hollow = |window: &mut Window, slot: usize, row: usize| {
        window.paint_quad(quad(
            dot_at(origin, slot_x(slot), row_y(row), DOT),
            round,
            hsla(0.0, 0.0, 0.0, 0.0),
            Edges::all(px(1.0)),
            paint.muted_ink.opacity(0.7),
            BorderStyle::Solid,
        ));
    };
    // The empty lattice under the whole chart.
    let lattice_rows: [(usize, usize); 5] = [
        (0, CURVE_ROWS),
        (STRIP_ROW, STRIP_DOTS),
        (DISK_ROW, MATRIX_DOTS),
        (SWAP_ROW, MATRIX_DOTS),
        (PRESSURE_ROW, MATRIX_DOTS),
    ];
    for slot in 0..model.slots {
        for (top, height) in lattice_rows {
            for row in top..top + height {
                put(window, slot, row, paint.colors.empty);
            }
        }
    }
    let head_slot: Option<usize> = model
        .columns
        .len()
        .checked_sub(1)
        .map(|i| model.offset() + i);
    for (index, column) in model.columns.iter().enumerate() {
        let slot: usize = model.offset() + index;
        let picked: Option<Hsla> = match column.state {
            TickState::Warning => Some(paint.colors.warning),
            TickState::Critical => Some(paint.colors.negative),
            TickState::Normal | TickState::Empty => None,
        };
        let hot: bool = paint.hover_column == Some(index);
        let tone = |base: Hsla| -> Hsla {
            if hot {
                return picked.unwrap_or(base).opacity(rest);
            }
            picked.map_or_else(|| base.opacity(0.6 * rest), |p| p.opacity(rest))
        };
        // The curve: the value dot, and the dots below it at 12%.
        match column.curve {
            Some(value) => {
                for level in 0..=value {
                    let row: usize = CURVE_ROWS - 1 - level;
                    let color: Hsla = if level == value {
                        lit_color(paint.brand).opacity(rest)
                    } else {
                        paint.brand.opacity(0.12 * rest)
                    };
                    put(window, slot, row, color);
                }
            }
            None => hollow(window, slot, CURVE_ROWS - 1),
        }
        // The change strip, filled from the bottom.
        for level in 0..usize::from(column.change) {
            put(
                window,
                slot,
                STRIP_ROW + STRIP_DOTS - 1 - level,
                tone(paint.ink),
            );
        }
        let pressure_color: Hsla = match column.state {
            TickState::Warning => paint.colors.warning,
            TickState::Critical => paint.colors.negative,
            TickState::Normal | TickState::Empty => paint.colors.positive,
        };
        let rows: [(usize, Option<u8>, Hsla); 3] = [
            (DISK_ROW, column.disk, paint.colors.disk),
            (SWAP_ROW, column.swap, paint.colors.swap),
            (PRESSURE_ROW, column.pressure, pressure_color),
        ];
        for (top, dots, base) in rows {
            match dots {
                Some(count) => {
                    for level in 0..usize::from(count) {
                        put(window, slot, top + MATRIX_DOTS - 1 - level, tone(base));
                    }
                }
                None => hollow(window, slot, top + MATRIX_DOTS - 1),
            }
        }
    }
    // The trend line: dots of 2.5 px on a straight line over the columns
    // that the trend uses. The line is not on the rows of the lattice, so it
    // does not hide behind the dots of the curve.
    let top_row: f32 = count_px(CURVE_ROWS - 1);
    for (index, column) in model.columns.iter().enumerate() {
        if let Some(place) = column.trend_at {
            window.paint_quad(
                fill(
                    dot_at(
                        origin,
                        slot_x(model.offset() + index),
                        layout.band + (top_row - f32::from(place) / 1000.0) * PITCH,
                        2.5,
                    ),
                    paint.trend_ink.opacity(0.8 * rest),
                )
                .corner_radii(Corners::all(px(1.25))),
            );
        }
    }
    // The line of the hovered column through the curve and the matrix.
    if let Some(column) = paint.hover_column.filter(|c| *c < model.columns.len()) {
        let x: f32 = slot_x(model.offset() + column) + DOT / 2.0 - 0.5;
        window.paint_quad(fill(
            rect_at(
                origin,
                x,
                layout.band,
                1.0,
                layout.matrix_bottom - layout.band,
            ),
            paint.muted_ink.opacity(0.6 * rest),
        ));
    }
    // The dashed line of the lowest value on screen.
    if let Some(min) = model.min {
        let y: f32 = row_y(min.row) + DOT / 2.0;
        let mut x: f32 = 0.0;
        while x < layout.lattice {
            let length: f32 = (layout.lattice - x).min(4.0);
            window.paint_quad(fill(
                rect_at(origin, LEFT_GUTTER + x, y, length, 1.0),
                paint.muted_ink.opacity(0.5 * rest),
            ));
            x += 7.0;
        }
    }
    // The event rail, the guides, and the markers.
    let rail_y: f32 = layout.label_band + 3.0;
    window.paint_quad(fill(
        rect_at(origin, LEFT_GUTTER, rail_y, layout.lattice, 1.0),
        paint.colors.border.opacity(rest),
    ));
    for (number, event) in model.events.iter().enumerate() {
        let x: f32 = slot_x(model.offset() + event.column) + DOT / 2.0 - 0.5;
        let side: f32 = MARKER_REST
            + (MARKER_HOT - MARKER_REST) * paint.markers.get(number).copied().unwrap_or(0.0);
        let tone: Hsla = event_color(event.kind, &paint.colors, paint.brand);
        let mut y: f32 = rail_y + 4.0;
        while y < layout.matrix_bottom {
            let length: f32 = (layout.matrix_bottom - y).min(2.0);
            window.paint_quad(fill(
                rect_at(origin, x, y, 1.0, length),
                tone.opacity(0.6 * rest),
            ));
            y += 4.0;
        }
        match event.kind {
            EventKind::Pressure(_) => window.paint_quad(
                fill(
                    rect_at(
                        origin,
                        x + 0.5 - side / 2.0,
                        rail_y + 0.5 - side / 2.0,
                        side,
                        side,
                    ),
                    tone.opacity(rest),
                )
                .corner_radii(Corners::all(px(side / 2.0))),
            ),
            EventKind::Operation => {
                paint_diamond(
                    window,
                    origin,
                    (x + 0.5, rail_y + 0.5),
                    side,
                    tone.opacity(rest),
                );
            }
        }
    }
    let head: Option<(usize, usize)> = head_slot.and_then(|slot| {
        model
            .columns
            .last()
            .and_then(|c| c.curve)
            .map(|value| (slot, CURVE_ROWS - 1 - value))
    });
    if let Some((slot, row)) = head {
        let white: Hsla = hsla(0.0, 0.0, 1.0, 1.0);
        let spot: Bounds<Pixels> = dot_at(origin, slot_x(slot), row_y(row), DOT);
        if paint.glow {
            window.paint_drop_shadows(
                spot,
                round,
                &[BoxShadow {
                    color: hsla(0.0, 0.0, 1.0, 0.5),
                    offset: Point::default(),
                    blur_radius: px(8.0),
                    spread_radius: px(0.0),
                    inset: false,
                }],
            );
        }
        window.paint_quad(fill(spot, white.opacity(rest)).corner_radii(round));
        if let Some(t) = paint.live.filter(|_| paint.glow) {
            let side: f32 = DOT + (14.0 - DOT) * t;
            window.paint_quad(quad(
                dot_at(origin, slot_x(slot), row_y(row), side),
                Corners::all(px(side / 2.0)),
                hsla(0.0, 0.0, 0.0, 0.0),
                Edges::all(px(1.0)),
                white.opacity((1.0 - t) * 0.8),
                BorderStyle::Solid,
            ));
        }
    }
}

/// The hover state that the chart keeps between frames.
struct SessionHover {
    /// The mark under the pointer or under the keyboard.
    mark: Option<PinnedMark>,
    /// Whether the keyboard set the mark.
    keyboard: bool,
    /// The hover amount of each event marker.
    tween: Option<Tween>,
    /// The focus of the chart, for Tab and the arrow keys.
    handle: FocusHandle,
    /// The position of the chart in the window, set at each paint.
    origin: Rc<Cell<Point<Pixels>>>,
}

/// Sets the mark of the chart. It redraws the chart only when the mark changes.
fn set_session_mark(
    state: &Entity<SessionHover>,
    mark: Option<PinnedMark>,
    keyboard: bool,
    app: &mut App,
) {
    state.update(app, |s, cx| {
        if s.mark != mark {
            s.mark = mark;
            s.keyboard = keyboard && mark.is_some();
            cx.notify();
        }
    });
}

/// The chart as an element with its key.
#[derive(IntoElement, Debug)]
pub struct SessionChart {
    model: SessionModel,
    live: Option<f32>,
    muted: bool,
    reduce_motion: bool,
    launch: Option<FocusTarget>,
}

impl SessionChart {
    /// Creates the chart for `model`.
    #[must_use]
    pub const fn new(model: SessionModel) -> Self {
        Self {
            model,
            live: None,
            muted: false,
            reduce_motion: false,
            launch: None,
        }
    }

    /// Lets a launch request for `target` focus the chart and pick the newest
    /// reading.
    #[must_use]
    pub const fn launch_focus(mut self, target: FocusTarget) -> Self {
        self.launch = Some(target);
        self
    }

    /// With `reduce` true, hover changes apply in one step.
    #[must_use]
    pub const fn reduce_motion(mut self, reduce: bool) -> Self {
        self.reduce_motion = reduce;
        self
    }

    /// The progress `0.0..=1.0` of the ring of the live head; `None` turns
    /// the ring off.
    #[must_use]
    pub const fn live(mut self, live: Option<f32>) -> Self {
        self.live = live;
        self
    }

    /// Draws the values muted, for stale data.
    #[must_use]
    pub const fn muted(mut self, muted: bool) -> Self {
        self.muted = muted;
        self
    }
}

/// How a small text sits in its box.
#[derive(Clone, Copy)]
enum Align {
    Start,
    Center,
    End,
}

/// A mono text of 10 px in a box of `width` at `left`, `top`.
fn small_text(
    id: SharedString,
    mono: &SharedString,
    spot: (f32, f32, f32),
    align: Align,
    color: Hsla,
    text: impl Into<SharedString>,
) -> gpui_kit::AnyElement {
    let (left, top, width) = spot;
    let text: SharedString = text.into();
    let mut line = div()
        .id(id)
        .test_support()
        .aria_label(text.clone())
        .absolute()
        .left(px(left))
        .top(px(top))
        .w(px(width))
        .h(px(LABEL_LINE))
        .flex()
        .font_family(mono.clone())
        .text_size(px(10.0))
        .line_height(px(LABEL_LINE))
        .text_color(color)
        .whitespace_nowrap();
    line = match align {
        Align::Start => line.justify_start(),
        Align::Center => line.justify_center(),
        Align::End => line.justify_end(),
    };
    line.child(text).into_any_element()
}

impl RenderOnce for SessionChart {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the chart and its texts"
    )]
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let muted_ink: Hsla = to_hsla(tokens.muted_foreground);
        let colors: DialColors = DialColors::for_dark(dark);
        let brand: Hsla = to_hsla(tokens.brand);
        let layout: Layout = self.model.layout();
        let label: SharedString = self.model.label().into();
        let pressure_label: SharedString = track_label(&self.model.states()).into();
        let range: SharedString = range_caption(self.model.range).into();
        let animate: bool = !(self.reduce_motion || cx.reduce_motion());
        let state: Entity<SessionHover> =
            window.use_keyed_state("session-chart-hover", cx, |_, cx| SessionHover {
                mark: None,
                keyboard: false,
                tween: None,
                handle: cx.focus_handle().tab_stop(true),
                origin: Rc::new(Cell::new(Point::default())),
            });
        let handle: FocusHandle = state.read(cx).handle.clone();
        let mut focused: bool = handle.is_focused(window);
        // A launch request waits without cost until the chart has a reading.
        let newest: Option<SessionMark> = edge_session_mark(&self.model, true);
        if newest.is_some()
            && self
                .launch
                .is_some_and(|target| take_launch_focus(target, cx))
        {
            let pinned: Option<PinnedMark> =
                newest.and_then(|mark| PinnedMark::pin(&self.model, mark));
            set_session_mark(&state, pinned, true, cx);
            let to_focus: FocusHandle = handle.clone();
            window.defer(cx, move |window, cx| window.focus(&to_focus, cx));
            // The focus follows after this frame; keep the mark meanwhile.
            focused = true;
        }
        let now: Instant = Instant::now();
        let event_count: usize = self.model.events.len();
        // One pass: the mark, and the eased hover amounts of the markers.
        let (mark, markers, running): (Option<SessionMark>, Vec<f32>, bool) =
            state.update(cx, |s, _| {
                if s.keyboard && !focused {
                    s.mark = None;
                    s.keyboard = false;
                }
                // The mark finds its reading again; it is cleared when that
                // reading is no longer on screen.
                let found: Option<SessionMark> = s.mark.and_then(|pin| pin.resolve(&self.model));
                if found.is_none() {
                    s.mark = None;
                    s.keyboard = false;
                }
                let target: Vec<f32> = (0..event_count)
                    .map(|index| f32::from(u8::from(found == Some(SessionMark::Event(index)))))
                    .collect();
                let tween: &mut Tween = s
                    .tween
                    .get_or_insert_with(|| Tween::new(target.clone(), now));
                tween.retarget(target, now, animate);
                (found, tween.value_at(now), tween.running(now))
            });
        if running {
            window.request_animation_frame();
        }
        let hover_column: Option<usize> = match mark {
            Some(SessionMark::Column(index)) => Some(index),
            _ => None,
        };
        let origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&state.read(cx).origin);
        let row_top = |row: usize| layout.band + count_px(row) * PITCH;
        let center_of = |top_row: usize, dots: usize| row_top(top_row) + lattice_width(dots) / 2.0;
        let mut root = div()
            .id("session-chart")
            .role(Role::Image)
            .test_support()
            .aria_label(label)
            .track_focus(&handle)
            .relative()
            .w(px(layout.width))
            .h(px(layout.height))
            .flex_shrink_0();
        let mut texts: Vec<gpui_kit::AnyElement> = Vec::new();
        // The two-line labels above the rail.
        for (index, event) in self.model.events.iter().enumerate() {
            let Some(place) = event.label else { continue };
            let tone: Hsla = event_color(event.kind, &colors, brand);
            let left: f32 = LEFT_GUTTER + place.left;
            texts.push(
                div()
                    .id(SharedString::from(format!("session-event-{index}")))
                    .test_support()
                    .aria_label(SharedString::from(format!(
                        "{}, {}",
                        event.text,
                        event.kind.name()
                    )))
                    .absolute()
                    .left(px(left))
                    .top(px(layout.label_band - 2.0 * LABEL_LINE - 2.0))
                    .w(px(place.width))
                    .flex()
                    .flex_col()
                    .items_center()
                    .font_family(mono.clone())
                    .text_size(px(10.0))
                    .line_height(px(LABEL_LINE))
                    .whitespace_nowrap()
                    .child(div().text_color(tone).child(event.text.clone()))
                    .child(div().text_color(muted_ink).child(event.kind.name()))
                    .into_any_element(),
            );
        }
        // The chip of the newest event.
        let chip: Option<Chip> = match mark {
            Some(SessionMark::Event(index)) => self.model.chip_of(index),
            _ => self.model.chip(),
        };
        if let Some(chip) = chip
            && let Some(event) = self.model.events.get(chip.event)
        {
            let tone: Hsla = event_color(event.kind, &colors, brand);
            texts.push(
                div()
                    .id("session-chip")
                    .test_support()
                    .aria_label(SharedString::from(chip.label_text()))
                    .absolute()
                    .left(px(LEFT_GUTTER + chip.left))
                    .top(px(layout.label_band + 8.0))
                    .w(px(chip.width))
                    .px(tokens::SPACE_2)
                    .py(tokens::SPACE_1)
                    .rounded(px(6.0))
                    .bg(to_hsla(tokens.surface_raised))
                    .font_family(mono.clone())
                    .text_size(px(10.0))
                    .line_height(px(LABEL_LINE))
                    .whitespace_nowrap()
                    .flex()
                    .child(div().text_color(tone).child(chip.name.clone()))
                    .child(div().text_color(muted_ink).child(chip.suffix()))
                    .into_any_element(),
            );
        }
        // The names of the rows, centered on each row.
        let name_width: f32 = LEFT_GUTTER - 6.0;
        let names: [(&str, f32); 5] = [
            ("avail.", center_of(0, CURVE_ROWS)),
            ("changes", center_of(STRIP_ROW, STRIP_DOTS)),
            ("disk", center_of(DISK_ROW, MATRIX_DOTS)),
            ("swap", center_of(SWAP_ROW, MATRIX_DOTS)),
            ("pressure", center_of(PRESSURE_ROW, MATRIX_DOTS)),
        ];
        for (name, center) in names {
            texts.push(small_text(
                SharedString::from(format!("session-row-{name}")),
                &mono,
                (0.0, center - LABEL_LINE / 2.0, name_width),
                Align::End,
                muted_ink,
                name,
            ));
        }
        // The newest values and the minimum, in the right gutter.
        let value_left: f32 = LEFT_GUTTER + layout.lattice + 6.0;
        let value_width: f32 = RIGHT_GUTTER - 6.0;
        let [available, disk, swap, pressure_text] = self.model.newest_texts();
        let head_row: usize = self
            .model
            .columns
            .last()
            .and_then(|c| c.curve)
            .map_or(CURVE_ROWS - 1, |value| CURVE_ROWS - 1 - value);
        let state_color: Hsla = match self.model.newest.map(|n| n.state) {
            Some(TickState::Warning) => colors.warning,
            Some(TickState::Critical) => colors.negative,
            _ => muted_ink,
        };
        let ink: Hsla = to_hsla(tokens.foreground);
        let values: [(&'static str, f32, String, Hsla); 4] = [
            ("avail", row_top(head_row) + DOT / 2.0, available, ink),
            ("disk", center_of(DISK_ROW, MATRIX_DOTS), disk, ink),
            ("swap", center_of(SWAP_ROW, MATRIX_DOTS), swap, ink),
            (
                "pressure",
                center_of(PRESSURE_ROW, MATRIX_DOTS),
                pressure_text,
                state_color,
            ),
        ];
        for (name, center, text, color) in values {
            texts.push(small_text(
                SharedString::from(format!("session-newest-{name}")),
                &mono,
                (value_left, center - LABEL_LINE / 2.0, value_width),
                Align::Start,
                color,
                text,
            ));
        }
        if let Some(min) = self.model.min_label() {
            texts.push(small_text(
                SharedString::from("session-min"),
                &mono,
                (
                    value_left,
                    row_top(min.row) + DOT / 2.0 - LABEL_LINE / 2.0,
                    value_width,
                ),
                Align::Start,
                muted_ink,
                format!("min {}", bytes_text(min.value)),
            ));
        }
        // The time axis.
        let axis_top: f32 = layout.matrix_bottom + 4.0;
        texts.push(small_text(
            SharedString::from("session-axis-zone"),
            &mono,
            (0.0, axis_top, name_width),
            Align::End,
            muted_ink,
            if self.model.axis_utc { "UTC" } else { "" },
        ));
        for axis in axis_spots(&self.model, hover_column) {
            let left: f32 = clamp_span(slot_center(axis.slot), 2.0 * AXIS_HALF, layout.lattice);
            texts.push(small_text(
                SharedString::from(format!("session-axis-{}", axis.slot)),
                &mono,
                (LEFT_GUTTER + left, axis_top, 2.0 * AXIS_HALF),
                Align::Center,
                if axis.hovered { ink } else { muted_ink },
                axis.text,
            ));
        }
        let trend_ink: Hsla = to_hsla(tokens.foreground);
        // The card of the hovered reading, at its curve dot.
        let tip: Option<ChartTip> = match mark {
            Some(SessionMark::Column(index)) => column_tip(&self.model, index)
                .zip(self.model.columns.get(index))
                .map(|(content, column)| {
                    let row: usize = column.curve.map_or(CURVE_ROWS - 1, |v| CURVE_ROWS - 1 - v);
                    let spot: Point<Pixels> = point(
                        px(LEFT_GUTTER + count_px(self.model.offset() + index) * PITCH),
                        px(row_top(row)),
                    );
                    ChartTip::new(
                        "session-tip",
                        content,
                        Bounds::new(spot, size(px(DOT), px(DOT))),
                        origin.get(),
                        animate,
                    )
                }),
            _ => None,
        };
        let hit: Rc<SessionModel> = Rc::new(self.model.clone());
        let move_hit: Rc<SessionModel> = Rc::clone(&hit);
        let key_hit: Rc<SessionModel> = hit;
        let move_origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
        let paint_origin: Rc<Cell<Point<Pixels>>> = Rc::clone(&origin);
        let move_state: Entity<SessionHover> = state.clone();
        let leave_state: Entity<SessionHover> = state.clone();
        let key_state: Entity<SessionHover> = state;
        let paint: SessionPaint = SessionPaint {
            trend_ink,
            model: self.model,
            layout,
            colors,
            brand,
            muted_ink,
            ink,
            glow: glow::enabled(cx),
            live: self.live,
            muted: self.muted,
            hover_column,
            markers,
        };
        root = root
            .on_mouse_move(move |event, _, app| {
                let at: Point<Pixels> = event.position - move_origin.get();
                let mark: Option<SessionMark> =
                    session_mark_at(&move_hit, &layout, at.x.into(), at.y.into());
                let pinned: Option<PinnedMark> = mark.and_then(|m| PinnedMark::pin(&move_hit, m));
                set_session_mark(&move_state, pinned, false, app);
            })
            .on_hover(move |hovered, _, app| {
                let from_pointer: bool = !leave_state.read(app).keyboard;
                if !*hovered && from_pointer {
                    set_session_mark(&leave_state, None, false, app);
                }
            })
            .on_key_down(move |event, _, app| {
                let current: Option<SessionMark> = key_state
                    .read(app)
                    .mark
                    .and_then(|pin| pin.resolve(&key_hit));
                let next: Option<Option<SessionMark>> = match event.keystroke.key.as_str() {
                    "right" => Some(step_session_mark(&key_hit, current, 1)),
                    "left" => Some(step_session_mark(&key_hit, current, -1)),
                    "home" => Some(edge_session_mark(&key_hit, false)),
                    "end" => Some(edge_session_mark(&key_hit, true)),
                    "escape" => Some(None),
                    _ => None,
                };
                if let Some(mark) = next {
                    let pinned: Option<PinnedMark> =
                        mark.and_then(|m| PinnedMark::pin(&key_hit, m));
                    set_session_mark(&key_state, pinned, true, app);
                    app.stop_propagation();
                }
            })
            .child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .w(px(layout.width))
                    .h(px(layout.height))
                    .child(
                        canvas(
                            move |bounds: Bounds<Pixels>, _, _| paint_origin.set(bounds.origin),
                            move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                                paint_session(&paint, bounds, window);
                            },
                        )
                        .size_full(),
                    ),
            )
            .children(texts)
            .children(tip)
            .child(
                div()
                    .id("pressure-track")
                    .role(Role::Image)
                    .test_support()
                    .aria_label(pressure_label)
                    .absolute()
                    .left(px(LEFT_GUTTER))
                    .top(px(row_top(PRESSURE_ROW)))
                    .w(px(layout.lattice))
                    .h(px(lattice_width(MATRIX_DOTS))),
            );
        let caption = |id: &'static str, text: SharedString| {
            div()
                .id(id)
                .test_support()
                .aria_label(text.clone())
                .text_size(px(11.0))
                .text_color(muted_ink)
                .child(text)
        };
        // A column of `count` dots of the key.
        let key_column = |count: usize, color: Hsla| {
            // 2 px: the gap of the lattice of the chart, not layout spacing.
            let mut column = v_flex().gap(px(PITCH - DOT));
            for _ in 0..count {
                column = column.child(div().size(px(DOT)).rounded_full().bg(color));
            }
            column
        };
        let dot_color: Hsla = muted_ink.opacity(0.8);
        v_flex().gap(tokens::SPACE_3).child(root).child(
            v_flex()
                .gap(tokens::SPACE_1)
                .child(caption("session-range", range))
                .child(
                    h_flex()
                        .id("session-key")
                        .test_support()
                        .aria_label("Key: one column is one reading, fewer to more, not normal")
                        .flex_wrap()
                        .items_center()
                        .gap_x(tokens::SPACE_4)
                        .gap_y(tokens::SPACE_1)
                        .text_size(px(11.0))
                        .text_color(muted_ink)
                        .child(caption("session-scale", SCALE_CAPTION.into()))
                        .child(
                            h_flex()
                                .gap(tokens::SPACE_2)
                                .items_center()
                                .child("Fewer")
                                .child(key_column(1, dot_color))
                                .child(key_column(4, dot_color))
                                .child("More"),
                        )
                        .child(
                            h_flex()
                                .gap(tokens::SPACE_1)
                                .items_center()
                                .child(key_column(1, colors.warning))
                                .child("Not normal"),
                        ),
                ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trend_place_is_not_rounded_to_a_row() {
        // A quarter of the range is a quarter of the 9 row steps.
        assert_eq!(trend_place(25.0, (0, 100)), 2250);
        assert_eq!(trend_place(0.0, (0, 100)), 0);
        assert_eq!(trend_place(100.0, (0, 100)), 9000);
        // Outside the range, and a value that is not a number.
        assert_eq!(trend_place(-5.0, (0, 100)), 0);
        assert_eq!(trend_place(500.0, (0, 100)), 9000);
        assert_eq!(trend_place(f64::NAN, (0, 100)), 0);
        // A range of one value: the middle row, as the curve.
        assert_eq!(trend_place(7.0, (7, 7)), 4000);
    }
    use std::time::{Duration, SystemTime};

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn sample(
        seconds: u64,
        available: Option<u64>,
        pressure: Option<PressureLevel>,
        swap: u64,
    ) -> HostSample {
        fn no<T>() -> Measured<T> {
            Measured::Unavailable("none".to_owned())
        }
        HostSample {
            at: at(seconds),
            pressure: pressure.map_or_else(no, Measured::Value),
            swap_used: Measured::Value(swap),
            disk_available: available.map_or_else(no, Measured::Value),
            disk_used: available.map_or_else(no, |a| Measured::Value(1_000_u64.saturating_sub(a))),
            utc_offset: None,
        }
    }

    fn operation(seconds: u64) -> OperationRow {
        OperationRow {
            operation_id: "op".to_owned(),
            state: crate::data::model::OperationPhase::Completed,
            state_text: "Completed".to_owned(),
            admitted_at: at(seconds),
            trigger: "disk guard".to_owned(),
        }
    }

    #[test]
    fn the_curve_puts_the_smallest_value_low_and_the_largest_high() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            sample(2, Some(200), Some(PressureLevel::Normal), 0),
            sample(3, Some(150), Some(PressureLevel::Normal), 0),
        ];
        let model = session_model(&samples, None, 10);
        assert_eq!(model.range, Some((100, 200)));
        assert_eq!(model.columns[0].curve, Some(0));
        assert_eq!(model.columns[1].curve, Some(CURVE_ROWS - 1));
        assert!(
            model.columns[2]
                .curve
                .is_some_and(|row| (4..=5).contains(&row))
        );
    }

    #[test]
    fn a_range_of_one_value_still_draws_and_the_matrix_shows_one_dot() {
        let samples = [sample(1, Some(100), Some(PressureLevel::Normal), 5)];
        let model = session_model(&samples, None, 10);
        assert_eq!(model.columns.len(), 1);
        assert_eq!(model.range, Some((100, 100)));
        assert!(model.columns[0].curve.is_some());
        assert_eq!(model.columns[0].disk, Some(1));
        assert_eq!(model.columns[0].swap, Some(1));
        assert_eq!(range_caption(model.range), "100 B available");
    }

    #[test]
    fn an_unavailable_reading_is_empty_and_changes_no_range() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            sample(2, None, None, 0),
            sample(3, Some(300), Some(PressureLevel::Normal), 0),
        ];
        let model = session_model(&samples, None, 10);
        assert_eq!(model.range, Some((100, 300)));
        assert_eq!(model.columns[1].curve, None);
        assert_eq!(model.columns[1].disk, None);
        assert_eq!(model.columns[1].pressure, None);
        assert_eq!(model.columns[1].state, TickState::Empty);
    }

    #[test]
    fn only_unavailable_readings_have_no_range() {
        let samples = [sample(1, None, None, 0)];
        let model = session_model(&samples, None, 10);
        assert_eq!(model.range, None);
        assert!(range_caption(None).starts_with('\u{2014}'));
        assert!(!model.label().contains("0 B"), "{}", model.label());
    }

    #[test]
    fn the_matrix_quantizes_to_quarters_and_pressure_to_one_two_four() {
        let samples = [
            sample(1, Some(0), Some(PressureLevel::Normal), 0),
            sample(2, Some(1000), Some(PressureLevel::Warning), 100),
            sample(3, Some(500), Some(PressureLevel::Critical), 50),
        ];
        let model = session_model(&samples, None, 10);
        let disk: Vec<Option<u8>> = model.columns.iter().map(|c| c.disk).collect();
        assert_eq!(disk[0], Some(4), "used 1000 is the largest");
        assert_eq!(disk[1], Some(1), "used 0 is the smallest");
        let pressure: Vec<Option<u8>> = model.columns.iter().map(|c| c.pressure).collect();
        assert_eq!(pressure, vec![Some(1), Some(2), Some(4)]);
        assert_eq!(model.columns[2].swap, Some(3));
    }

    #[test]
    fn only_the_newest_columns_that_fit_show() {
        let samples: Vec<HostSample> = (0..10)
            .map(|n| sample(n, Some(100 + n), Some(PressureLevel::Normal), 0))
            .collect();
        let model = session_model(&samples, None, 4);
        assert_eq!(model.columns.len(), 4);
        assert_eq!(model.range, Some((106, 109)));
        assert_eq!(model.offset(), 0);
        let short = session_model(&samples[..2], None, 4);
        assert_eq!(short.offset(), 2, "the newest reading is at the right");
    }

    #[test]
    fn the_change_strip_counts_the_series_that_grew() {
        let samples = [
            sample(1, Some(900), Some(PressureLevel::Normal), 10),
            sample(2, Some(800), Some(PressureLevel::Normal), 20),
            sample(3, Some(800), Some(PressureLevel::Warning), 20),
            sample(4, Some(700), Some(PressureLevel::Warning), 30),
            sample(5, Some(900), Some(PressureLevel::Normal), 30),
        ];
        let model = session_model(&samples, None, 10);
        let change: Vec<u8> = model.columns.iter().map(|c| c.change).collect();
        // Used grows when available falls: 1000 - available.
        assert_eq!(change, vec![0, 2, 1, 2, 0]);
        assert!(change.iter().all(|c| usize::from(*c) <= STRIP_DOTS));
    }

    #[test]
    fn a_change_across_an_unavailable_reading_at_the_window_edge_is_an_event() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            sample(2, Some(100), None, 0),
            sample(3, Some(100), Some(PressureLevel::Warning), 0),
        ];
        // One column: the reading before the window is unavailable.
        let model = session_model(&samples, None, 1);
        assert_eq!(model.events.len(), 1, "{:?}", model.events);
        assert_eq!(model.events[0].text, "Warning");
    }

    #[test]
    fn a_pressure_change_is_an_event_with_the_new_state() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            sample(2, Some(100), None, 0),
            sample(3, Some(100), Some(PressureLevel::Warning), 0),
            sample(4, Some(100), Some(PressureLevel::Warning), 0),
        ];
        let model = session_model(&samples, None, 10);
        assert_eq!(model.events.len(), 1, "{:?}", model.events);
        assert_eq!(model.events[0].column, 2);
        assert_eq!(model.events[0].text, "Warning");
        assert!(model.events[0].labeled);
    }

    #[test]
    fn the_latest_operation_is_an_event_only_inside_the_time_span() {
        let samples = [
            sample(10, Some(100), Some(PressureLevel::Normal), 0),
            sample(20, Some(100), Some(PressureLevel::Normal), 0),
            sample(30, Some(100), Some(PressureLevel::Normal), 0),
        ];
        let inside = session_model(&samples, Some(&operation(25)), 10);
        assert_eq!(inside.events.len(), 1);
        assert_eq!(inside.events[0].column, 1);
        assert_eq!(inside.events[0].kind, EventKind::Operation);
        assert_eq!(inside.events[0].text, "disk guard");
        let outside = session_model(&samples, Some(&operation(5)), 10);
        assert_eq!(outside.events.len(), 0);
        let outside = session_model(&samples, Some(&operation(31)), 10);
        assert_eq!(outside.events.len(), 0);
    }

    fn normal_then_warning(normal: u64) -> Vec<HostSample> {
        let mut samples: Vec<HostSample> = (0..normal)
            .map(|n| sample(n * 60, Some(100 + n), Some(PressureLevel::Normal), 0))
            .collect();
        samples.push(sample(
            normal * 60,
            Some(100),
            Some(PressureLevel::Warning),
            0,
        ));
        samples
    }

    #[test]
    fn the_fact_of_a_change_counts_the_readings_of_the_old_state() {
        let model = session_model(&normal_then_warning(40), None, 60);
        let event = &model.events[0];
        assert_eq!(event.fact, "after 40 normal readings");
        assert_eq!(model.chip().map(|chip| chip.fact), Some(event.fact.clone()));
        let one = session_model(&normal_then_warning(1), None, 60);
        assert_eq!(one.events[0].fact, "after 1 normal reading");
        // The count reaches back before the window.
        let narrow = session_model(&normal_then_warning(40), None, 5);
        assert_eq!(narrow.events[0].fact, "after 40 normal readings");
    }

    #[test]
    fn an_operation_event_has_its_state_text_as_the_fact() {
        let samples = [
            sample(10, Some(100), Some(PressureLevel::Normal), 0),
            sample(30, Some(100), Some(PressureLevel::Normal), 0),
        ];
        let model = session_model(&samples, Some(&operation(25)), 10);
        assert_eq!(model.events[0].fact, "Completed");
        assert_eq!(model.events[0].kind.name(), "operation");
    }

    #[test]
    fn the_clock_is_hours_and_minutes_in_utc() {
        assert_eq!(clock_text(at(0), None), "00:00");
        assert_eq!(clock_text(at(12 * 3600 + 4 * 60 + 59), None), "12:04");
        assert_eq!(clock_text(at(25 * 3600 + 60), None), "01:01");
        // Local time: east of UTC, west of UTC across midnight, a half hour.
        assert_eq!(clock_text(at(12 * 3600), Some(3 * 3600)), "15:00");
        assert_eq!(clock_text(at(3600), Some(-5 * 3600)), "20:00");
        assert_eq!(clock_text(at(23 * 3600), Some(5 * 3600 + 1800)), "04:30");
    }

    #[test]
    fn labels_go_to_the_newest_events_that_do_not_overlap() {
        let levels = [PressureLevel::Normal, PressureLevel::Warning];
        let samples: Vec<HostSample> = (0..40)
            .map(|n| {
                sample(
                    n,
                    Some(100),
                    Some(levels[usize::try_from(n / 8).unwrap_or(0) % 2]),
                    0,
                )
            })
            .collect();
        let model = session_model(&samples, None, 40);
        let labeled: Vec<&Event> = model.events.iter().filter(|e| e.labeled).collect();
        assert!(!labeled.is_empty() && labeled.len() <= MAX_FLAGS);
        // The newest event always has its label.
        assert!(model.events.last().is_some_and(|e| e.label.is_some()));
        for pair in labeled.windows(2) {
            let (a, b) = (pair[0].label.expect("a"), pair[1].label.expect("b"));
            assert!(a.left + a.width <= b.left, "{a:?} {b:?}");
        }
        for event in &labeled {
            let place = event.label.expect("label");
            assert!(place.left >= 0.0 && place.left + place.width <= lattice_width(40) + 1e-3);
        }
    }

    #[test]
    fn at_most_four_labels_show() {
        let levels = [PressureLevel::Normal, PressureLevel::Warning];
        let samples: Vec<HostSample> = (0..180)
            .map(|n| {
                sample(
                    n,
                    Some(100),
                    Some(levels[usize::try_from(n / 20).unwrap_or(0) % 2]),
                    0,
                )
            })
            .collect();
        let model = session_model(&samples, None, 180);
        assert!(model.events.len() > MAX_FLAGS);
        assert_eq!(model.events.iter().filter(|e| e.labeled).count(), MAX_FLAGS);
        assert!(
            model.events[..model.events.len() - MAX_FLAGS]
                .iter()
                .all(|e| !e.labeled)
        );
    }

    #[test]
    fn a_label_stays_inside_the_lattice() {
        assert!((clamp_span(2.0, 48.0, 200.0)).abs() < 1e-6);
        assert!((clamp_span(199.0, 48.0, 200.0) - 152.0).abs() < 1e-6);
        assert!((clamp_span(100.0, 48.0, 200.0) - 76.0).abs() < 1e-6);
        for slots in [6, 20, 60] {
            let chip = session_model(&normal_then_warning(3), None, slots)
                .chip()
                .expect("chip");
            let room = lattice_width(slots) + RIGHT_GUTTER;
            assert!(chip.left >= 0.0, "{slots}");
            assert!(chip.left + chip.width <= room + 1e-3, "{slots} {chip:?}");
        }
    }

    #[test]
    fn the_min_line_needs_two_readings_and_a_range() {
        let one = session_model(
            &[sample(1, Some(100), Some(PressureLevel::Normal), 0)],
            None,
            10,
        );
        assert_eq!(one.min, None);
        let same = session_model(
            &[
                sample(1, Some(100), Some(PressureLevel::Normal), 0),
                sample(2, Some(100), Some(PressureLevel::Normal), 0),
            ],
            None,
            10,
        );
        assert_eq!(same.min, None);
        let two = session_model(
            &[
                sample(1, Some(300), Some(PressureLevel::Normal), 0),
                sample(2, Some(100), Some(PressureLevel::Normal), 0),
            ],
            None,
            10,
        );
        assert_eq!(
            two.min,
            Some(MinMark {
                row: CURVE_ROWS - 1,
                value: 100
            })
        );
        assert!(two.label().contains("min 100 B"), "{}", two.label());
        assert!(!one.label().contains("min"));
    }

    #[test]
    fn the_axis_labels_keep_48_px_and_include_the_newest_reading() {
        let samples: Vec<HostSample> = (0..40)
            .map(|n| sample(n * 60, Some(100 + n), Some(PressureLevel::Normal), 0))
            .collect();
        let model = session_model(&samples, None, 40);
        assert_eq!(model.axis.first().map(|a| a.slot), Some(39), "newest first");
        assert_eq!(model.axis[0].text, "00:39");
        for pair in model.axis.windows(2) {
            let gap = slot_center(pair[0].slot) - slot_center(pair[1].slot);
            assert!(gap >= 48.0, "{gap}");
        }
    }

    #[test]
    fn the_tags_and_the_newest_values_never_show_zero_for_unknown() {
        let samples = [
            sample(1, Some(1_000_000_000), Some(PressureLevel::Normal), 0),
            sample(2, None, None, 0),
        ];
        let model = session_model(&samples, None, 10);
        let tags = model.tags();
        assert_eq!(tags.readings, "readings 2");
        assert_eq!(tags.range, "range 1.0 GB");
        assert_eq!(tags.events, "events 0");
        assert_eq!(tags.state, "now \u{2014}");
        let newest = model.newest_texts();
        assert_eq!(newest[0], "\u{2014}");
        assert_eq!(newest[3], "\u{2014}");
        let none = session_model(&[], None, 10);
        assert_eq!(none.tags().range, "range \u{2014}");
        assert_eq!(none.newest_texts()[1], "\u{2014}");
        let wide = session_model(
            &[
                sample(1, Some(260_000_000_000), Some(PressureLevel::Normal), 0),
                sample(2, Some(310_200_000_000), Some(PressureLevel::Normal), 0),
            ],
            None,
            10,
        );
        assert_eq!(wide.tags().range, "range 260.0\u{2013}310.2 GB");
    }

    #[test]
    fn the_layout_has_room_for_the_gutters_and_the_labels() {
        let calm = session_model(
            &[sample(1, Some(1), Some(PressureLevel::Normal), 0)],
            None,
            10,
        );
        let layout = calm.layout();
        assert_eq!(layout.label_band, 0.0);
        assert!((layout.width - (LEFT_GUTTER + lattice_width(10) + RIGHT_GUTTER)).abs() < 1e-3);
        let busy = session_model(&normal_then_warning(5), None, 10);
        assert!(busy.layout().label_band > 0.0);
        assert!(busy.layout().height > layout.height);
    }

    #[test]
    fn the_label_counts_readings_states_and_events() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            sample(2, Some(200), Some(PressureLevel::Warning), 0),
        ];
        let model = session_model(&samples, None, 10);
        let label = model.label();
        assert!(label.contains("2 readings"), "{label}");
        assert!(label.contains("100 B to 200 B available"), "{label}");
        assert!(label.contains("1 normal, 1 warning, 0 critical"), "{label}");
        assert!(label.ends_with("1 event"), "{label}");
        let one = session_model(&samples[..1], None, 10).label();
        assert!(one.contains("1 reading,"), "{one}");
        assert!(one.ends_with("0 events"), "{one}");
    }

    #[test]
    fn the_live_ring_cycles_every_1_6_seconds() {
        assert!(live_progress(0.0).abs() < 1e-6);
        assert!((live_progress(0.8) - 0.5).abs() < 1e-5);
        assert!(live_progress(1.6 + 0.4) < 0.3);
    }

    #[test]
    fn the_lattice_has_a_known_height() {
        assert_eq!(TOTAL_ROWS, 29);
    }

    #[test]
    fn a_narrow_chart_drops_the_fact_then_the_time_and_the_chip_stays_inside() {
        let model = session_model(&normal_then_warning(40), None, 20);
        let chip = model.chip().expect("chip");
        assert!(chip.fact.is_empty(), "{chip:?}");
        let layout = model.layout();
        assert!(chip.left + chip.width <= layout.width - LEFT_GUTTER + 1e-3);
        let wide = session_model(&normal_then_warning(40), None, 60)
            .chip()
            .expect("chip");
        assert_eq!(wide.fact, "after 40 normal readings");
        assert_eq!(wide.label_text().matches(", ").count(), 2);
        let tiny = session_model(&normal_then_warning(40), None, 2)
            .chip()
            .expect("chip");
        assert!(tiny.time.is_empty() && tiny.fact.is_empty(), "{tiny:?}");
    }

    #[test]
    fn a_label_wider_than_the_lattice_is_not_placed() {
        let model = session_model(&normal_then_warning(5), None, 6);
        assert!(
            model.events.iter().all(|e| e.label.is_none()),
            "{:?}",
            model.events
        );
        let wide = session_model(&normal_then_warning(5), None, 20);
        assert!(wide.events.iter().all(|e| {
            e.label
                .is_none_or(|l| l.left + l.width <= lattice_width(20) + 1e-3)
        }));
    }

    #[test]
    fn the_min_label_stays_when_the_newest_reading_is_unavailable() {
        let samples = [
            sample(1, Some(300), Some(PressureLevel::Normal), 0),
            sample(2, Some(100), Some(PressureLevel::Normal), 0),
            sample(3, None, None, 0),
        ];
        let model = session_model(&samples, None, 10);
        assert!(model.min.is_some());
        assert_eq!(model.min_label(), model.min);
        let at_min = session_model(&samples[..2], None, 10);
        assert_eq!(
            at_min.min_label(),
            None,
            "the newest value is at the min row"
        );
    }

    #[test]
    fn a_time_before_the_epoch_is_an_em_dash() {
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(5);
        assert_eq!(clock_text(before, None), "\u{2014}");
        assert_eq!(clock_text(before, Some(3600)), "\u{2014}");
    }

    /// Ten readings in 20 slots; the pressure turns Warning at reading 6, so
    /// there is one event.
    fn hover_model() -> SessionModel {
        let samples: Vec<HostSample> = (0..10)
            .map(|n| {
                let level = if n < 6 {
                    PressureLevel::Normal
                } else {
                    PressureLevel::Warning
                };
                sample(n * 60, Some(100 + n), Some(level), 0)
            })
            .collect();
        session_model(&samples, None, 20)
    }

    /// Readings `first..first + 10` in 10 slots: the pressure turns Warning at
    /// the reading with number 6 of the run.
    fn shifted_model(first: u64) -> SessionModel {
        let samples: Vec<HostSample> = (first..first + 10)
            .map(|n| {
                let level = if n < 6 {
                    PressureLevel::Normal
                } else {
                    PressureLevel::Warning
                };
                sample(n * 60, Some(100 + n), Some(level), 0)
            })
            .collect();
        session_model(&samples, None, 10)
    }

    #[test]
    fn a_pinned_mark_follows_its_reading_when_the_columns_shift() {
        let before = shifted_model(0);
        let pin = PinnedMark::pin(&before, SessionMark::Column(4)).expect("pin");
        assert_eq!(pin.resolve(&before), Some(SessionMark::Column(4)));
        // One new reading: the oldest leaves, every column moves left by one.
        let after = shifted_model(1);
        assert_eq!(pin.resolve(&after), Some(SessionMark::Column(3)));
    }

    #[test]
    fn a_pinned_mark_is_cleared_when_its_reading_leaves_the_screen() {
        let before = shifted_model(0);
        let pin = PinnedMark::pin(&before, SessionMark::Column(0)).expect("pin");
        assert_eq!(pin.resolve(&shifted_model(1)), None);
    }

    #[test]
    fn a_pinned_event_follows_its_column() {
        let before = shifted_model(0);
        assert_eq!(before.events.len(), 1);
        let pin = PinnedMark::pin(&before, SessionMark::Event(0)).expect("pin");
        let after = shifted_model(1);
        assert_eq!(pin.resolve(&after), Some(SessionMark::Event(0)));
        assert_eq!(
            SessionMark::Event(0).column(&after),
            before.events[0].column.checked_sub(1)
        );
    }

    #[test]
    fn a_keyboard_step_starts_at_the_position_of_the_pinned_reading() {
        let before = shifted_model(0);
        let pin = PinnedMark::pin(&before, SessionMark::Column(4)).expect("pin");
        let after = shifted_model(1);
        let current = pin.resolve(&after);
        assert_eq!(
            step_session_mark(&after, current, 1),
            Some(SessionMark::Column(4))
        );
    }

    #[test]
    fn the_pointer_picks_the_column_in_the_whole_lattice_height() {
        let model = hover_model();
        let layout = model.layout();
        assert_eq!(model.offset(), 10);
        let x = |slot: usize| LEFT_GUTTER + slot_center(slot);
        let (top, bottom) = (layout.band + 1.0, layout.matrix_bottom - 1.0);
        for y in [top, layout.band + 40.0, bottom] {
            assert_eq!(
                session_mark_at(&model, &layout, x(12), y),
                Some(SessionMark::Column(2)),
                "y {y}"
            );
        }
        assert_eq!(
            session_mark_at(&model, &layout, x(19), top),
            Some(SessionMark::Column(9))
        );
    }

    #[test]
    fn the_gutters_the_empty_slots_and_the_outside_pick_nothing() {
        let model = hover_model();
        let layout = model.layout();
        let y: f32 = layout.band + 20.0;
        assert_eq!(session_mark_at(&model, &layout, 10.0, y), None);
        assert_eq!(
            session_mark_at(&model, &layout, LEFT_GUTTER + layout.lattice + 5.0, y),
            None
        );
        // Slot 3 has no reading: the readings sit at the right.
        assert_eq!(
            session_mark_at(&model, &layout, LEFT_GUTTER + slot_center(3), y),
            None
        );
        let x: f32 = LEFT_GUTTER + slot_center(15);
        assert_eq!(
            session_mark_at(&model, &layout, x, layout.matrix_bottom + 2.0),
            None
        );
        assert_eq!(session_mark_at(&model, &layout, x, -1.0), None);
    }

    #[test]
    fn an_event_marker_within_eight_pixels_wins_over_the_column() {
        let model = hover_model();
        let layout = model.layout();
        assert_eq!(model.events.len(), 1);
        let slot: usize = model.offset() + model.events[0].column;
        let mx: f32 = LEFT_GUTTER + slot_center(slot);
        let my: f32 = layout.label_band + 3.5;
        assert_eq!(
            session_mark_at(&model, &layout, mx, my),
            Some(SessionMark::Event(0))
        );
        assert_eq!(
            session_mark_at(&model, &layout, mx + 5.0, my + 5.0),
            Some(SessionMark::Event(0)),
            "7.1 px away"
        );
        // 9 px below the marker is outside the reach and above the lattice.
        let far = session_mark_at(&model, &layout, mx, my + 9.0);
        assert_ne!(far, Some(SessionMark::Event(0)));
        // The lattice top is 6.5 px under the marker, so the marker still wins
        // there; lower in the lattice the column wins.
        assert_eq!(
            session_mark_at(&model, &layout, mx, layout.band + 1.0),
            Some(SessionMark::Event(0))
        );
        assert_eq!(
            session_mark_at(&model, &layout, mx, layout.band + 6.0),
            Some(SessionMark::Column(model.events[0].column))
        );
    }

    #[test]
    fn the_keyboard_moves_by_one_reading_and_stops_at_the_ends() {
        let model = hover_model();
        let col = SessionMark::Column;
        assert_eq!(step_session_mark(&model, None, 1), Some(col(0)));
        assert_eq!(step_session_mark(&model, None, -1), Some(col(9)));
        assert_eq!(step_session_mark(&model, Some(col(4)), 1), Some(col(5)));
        assert_eq!(step_session_mark(&model, Some(col(4)), -1), Some(col(3)));
        assert_eq!(step_session_mark(&model, Some(col(9)), 1), Some(col(9)));
        assert_eq!(step_session_mark(&model, Some(col(0)), -1), Some(col(0)));
        assert_eq!(edge_session_mark(&model, false), Some(col(0)));
        assert_eq!(edge_session_mark(&model, true), Some(col(9)));
        // From an event the move starts at its column.
        let at: usize = model.events[0].column;
        assert_eq!(
            step_session_mark(&model, Some(SessionMark::Event(0)), 1),
            Some(col(at + 1))
        );
        let empty = session_model(&[], None, 20);
        assert_eq!(step_session_mark(&empty, None, 1), None);
        assert_eq!(edge_session_mark(&empty, true), None);
    }

    #[test]
    fn the_card_time_has_seconds_and_says_utc_without_an_offset() {
        assert_eq!(
            clock_seconds_text(at(12 * 3600 + 4 * 60 + 9), None),
            "12:04:09 UTC"
        );
        assert_eq!(
            clock_seconds_text(at(12 * 3600 + 4 * 60 + 9), Some(3 * 3600)),
            "15:04:09"
        );
        assert_eq!(clock_seconds_text(at(3600), Some(-5 * 3600)), "20:00:00");
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(5);
        assert_eq!(clock_seconds_text(before, Some(3600)), "\u{2014}");
        assert_eq!(clock_seconds_text(before, None), "\u{2014}");
    }

    #[test]
    fn the_card_states_the_measured_values_of_one_reading() {
        let model = hover_model();
        let tip = column_tip(&model, 6).expect("a reading");
        assert_eq!(tip.title, "00:06:00 UTC");
        let rows: Vec<(&str, &str)> = tip
            .rows
            .iter()
            .map(|r| (r.label.as_str(), r.value.as_str()))
            .collect();
        assert_eq!(rows[0], ("Available", "106 B"));
        assert_eq!(rows[1].0, "Disk used");
        assert_eq!(rows[2], ("Swap used", "0 B"));
        assert_eq!(rows[3], ("Pressure", "Warning"));
        assert_eq!(rows[4].0, "Changes");
        assert_eq!(tip.note.as_deref(), Some("Reading 7 of 10"));
        assert!(column_tip(&model, 10).is_none());
    }

    #[test]
    fn an_unavailable_reading_has_em_dashes_and_no_zero() {
        let samples = [
            sample(1, Some(100), Some(PressureLevel::Normal), 0),
            HostSample {
                at: at(2),
                pressure: Measured::Unavailable("none".to_owned()),
                swap_used: Measured::Unavailable("none".to_owned()),
                disk_available: Measured::Unavailable("none".to_owned()),
                disk_used: Measured::Unavailable("none".to_owned()),
                utc_offset: Some(0),
            },
        ];
        let model = session_model(&samples, None, 10);
        let tip = column_tip(&model, 1).expect("a reading");
        assert_eq!(tip.title, "00:00:02");
        for row in &tip.rows {
            assert_eq!(row.value, "\u{2014}", "{}", row.label);
        }
        assert!(!tip.spoken().contains("0 B"), "{}", tip.spoken());
    }

    #[test]
    fn the_hovered_reading_gets_an_axis_label_and_hides_one_it_would_overlap() {
        let model = hover_model();
        let base = axis_spots(&model, None);
        assert!(base.iter().all(|spot| !spot.hovered));
        // A reading that has a label marks it.
        let own: usize = base[0].slot - model.offset();
        let marked = axis_spots(&model, Some(own));
        assert_eq!(marked.len(), base.len());
        assert_eq!(marked.iter().filter(|spot| spot.hovered).count(), 1);
        // A reading next to a label replaces it.
        let near: usize = own.saturating_sub(1);
        let moved = axis_spots(&model, Some(near));
        let hot: Vec<&AxisSpot> = moved.iter().filter(|spot| spot.hovered).collect();
        assert_eq!(hot.len(), 1);
        for pair in moved.windows(2) {
            let gap = slot_center(pair[1].slot) - slot_center(pair[0].slot);
            assert!(gap.abs() >= 2.0 * AXIS_HALF || pair[0].slot == pair[1].slot);
        }
        // A reading far from a label adds one.
        assert!(axis_spots(&model, Some(0)).iter().any(|spot| spot.hovered));
    }
}
