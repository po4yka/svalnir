//! The session chart: a value curve, event flags, a live head, a sample
//! matrix, and a change strip on one time axis (`DESIGN.md` section 5).
//!
//! `session_model` is pure: it turns the readings of this window into
//! columns and events. `SessionChart` paints the dots from one canvas and
//! places the flags as small elements over it.

use crate::{
    data::model::{HostSample, Measured, OperationRow, PressureLevel},
    theme::{
        glow,
        tokens::{self, Tokens, to_hsla},
    },
    ui::data_state::{UNAVAILABLE_TEXT, format_bytes},
    viz::{
        dial::DialColors,
        led::{LedStyle, lit_color},
        tick_track::{TickState, state_of, track_label},
    },
};
use gpui_kit::{
    App, BorderStyle, Bounds, BoxShadow, Corners, Edges, Hsla, InteractiveElement as _,
    IntoElement, ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::{ActiveTheme as _, h_flex, v_flex},
    div, fill, hsla, point, px, quad, size,
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
/// The height of a flag, in pixels.
const FLAG_HEIGHT: f32 = 16.0;
/// The distance between two flag lanes, in pixels.
const LANE_STEP: f32 = 18.0;
/// The estimated width of one character of a flag, in pixels.
const FLAG_CHAR_PX: f32 = 6.6;
/// The padding of a flag at both sides, in pixels.
const FLAG_PAD: f32 = 12.0;
/// The longest flag text, in characters.
const FLAG_TEXT_MAX: usize = 16;
/// The seconds that the ring of the live head takes to expand and fade.
pub const LIVE_PERIOD_SECS: f32 = 1.6;

/// One column: one reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
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
    /// The dots of the change strip, 0 to 3.
    pub change: u8,
}

/// What an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A change of the pressure state; the level is the new one.
    Pressure(PressureLevel),
    /// The admission of the latest operation.
    Operation,
}

/// An event on the time axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The column of the event.
    pub column: usize,
    /// What the event is.
    pub kind: EventKind,
    /// The text of the flag.
    pub text: String,
    /// Whether the flag shows its text; an older event keeps its line only.
    pub labeled: bool,
}

/// The model of the chart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionModel {
    /// The columns that the chart has; the newest column is at the right.
    pub slots: usize,
    /// The readings on screen, oldest first; at most `slots`.
    pub columns: Vec<Column>,
    /// The smallest and the largest available space on screen.
    pub range: Option<(u64, u64)>,
    /// The events, by column.
    pub events: Vec<Event>,
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
            change,
        });
    }
    let mut events: Vec<Event> = Vec::new();
    // The last measured state before the window, across unavailable readings.
    let mut last: Option<PressureLevel> = samples
        .get(..start)
        .and_then(|older| older.iter().rev().find_map(|s| s.pressure.value().copied()));
    for (column, sample) in visible.iter().enumerate() {
        if let Measured::Value(level) = &sample.pressure {
            if last.is_some_and(|old| old != *level) {
                events.push(Event {
                    column,
                    kind: EventKind::Pressure(*level),
                    text: level.label().to_owned(),
                    labeled: false,
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
            labeled: false,
        });
    }
    events.sort_by_key(|event| event.column);
    let count: usize = events.len();
    for event in events.iter_mut().skip(count.saturating_sub(MAX_FLAGS)) {
        event.labeled = true;
    }
    SessionModel {
        slots,
        columns,
        range: available,
        events,
    }
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
/// The caption that names the rows of the sample matrix.
pub const ROWS_CAPTION: &str =
    "Rows from the top: change count, disk used, swap used, memory pressure";

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
        format!(
            "Session chart: {}, {}, pressure {} normal, {} warning, {} critical, {}",
            readings_text(self.columns.len()),
            range_caption(self.range),
            count(TickState::Normal),
            count(TickState::Warning),
            count(TickState::Critical),
            events_text(self.events.len()),
        )
    }

    /// The first slot of the newest reading, from the left.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.slots.saturating_sub(self.columns.len())
    }
}

/// A flag with its place.
#[derive(Debug, Clone, PartialEq)]
pub struct Flag {
    /// The index of the event.
    pub event: usize,
    /// The lane from the top.
    pub lane: usize,
    /// The left edge in pixels.
    pub left: f32,
    /// The width in pixels.
    pub width: f32,
}

/// The x of the line of column `slot`, in pixels.
fn line_x(slot: usize) -> f32 {
    #[expect(clippy::cast_precision_loss, reason = "a slot count is far below 2^24")]
    let x: f32 = slot as f32 * 6.0 + 1.75;
    x
}

/// The places of the flags with text. A flag starts at its line and runs to
/// the right; at the right edge it runs to the left of its line. A flag that
/// would touch a flag in the lane above it goes to the next lane.
#[must_use]
pub fn place_flags(model: &SessionModel, chart_width: f32) -> Vec<Flag> {
    let mut flags: Vec<Flag> = Vec::new();
    let mut lane_ends: Vec<f32> = Vec::new();
    for (index, event) in model.events.iter().enumerate().filter(|(_, e)| e.labeled) {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a flag text is far shorter than 2^24"
        )]
        let width: f32 = event.text.chars().count() as f32 * FLAG_CHAR_PX + FLAG_PAD;
        let x: f32 = line_x(model.offset() + event.column);
        let left: f32 = if x + width > chart_width {
            (x - width + 1.0).max(0.0)
        } else {
            x
        };
        let lane: usize = lane_ends
            .iter()
            .position(|end| left >= *end + 4.0)
            .unwrap_or(lane_ends.len());
        if lane == lane_ends.len() {
            lane_ends.push(left + width);
        } else {
            lane_ends[lane] = left + width;
        }
        flags.push(Flag {
            event: index,
            lane,
            left,
            width,
        });
    }
    flags
}

/// The height of the flag band for `flags`, in pixels.
#[must_use]
pub fn flag_band(flags: &[Flag]) -> f32 {
    flags.iter().map(|f| f.lane).max().map_or(0.0, |lane| {
        #[expect(clippy::cast_precision_loss, reason = "a lane count is at most 4")]
        let lanes: f32 = (lane + 1) as f32;
        lanes * LANE_STEP + 2.0
    })
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
    flags: Vec<Flag>,
    band: f32,
    colors: DialColors,
    brand: Hsla,
    muted_ink: Hsla,
    ink: Hsla,
    glow: bool,
    live: Option<f32>,
    muted: bool,
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

#[expect(clippy::too_many_lines, reason = "one pass in paint order")]
fn paint_session(paint: &SessionPaint, bounds: Bounds<Pixels>, window: &mut Window) {
    let origin: Point<Pixels> = bounds.origin;
    let model: &SessionModel = &paint.model;
    let rest: f32 = if paint.muted { 0.6 } else { 1.0 };
    let row_y = |row: usize| -> f32 {
        #[expect(clippy::cast_precision_loss, reason = "a row index is below 32")]
        let y: f32 = paint.band + row as f32 * PITCH;
        y
    };
    let slot_x = |slot: usize| -> f32 {
        #[expect(clippy::cast_precision_loss, reason = "a slot index is below 2^24")]
        let x: f32 = slot as f32 * PITCH;
        x
    };
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
        let tone = |base: Hsla| -> Hsla {
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
    // The event lines and the live head.
    for (index, event) in model.events.iter().enumerate() {
        let x: f32 = line_x(model.offset() + event.column);
        let top: f32 = paint
            .flags
            .iter()
            .find(|f| f.event == index)
            .map_or(paint.band, |f| {
                #[expect(clippy::cast_precision_loss, reason = "a lane count is at most 4")]
                let lane: f32 = f.lane as f32;
                lane * LANE_STEP + FLAG_HEIGHT
            });
        let height: f32 = row_y(TOTAL_ROWS - 1) + DOT - top;
        window.paint_quad(fill(
            Bounds::new(
                point(origin.x + px(x), origin.y + px(top)),
                size(px(1.0), px(height)),
            ),
            event_color(event.kind, &paint.colors, paint.brand).opacity(0.6 * rest),
        ));
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

/// The chart as an element with its captions.
#[derive(IntoElement, Debug)]
pub struct SessionChart {
    model: SessionModel,
    live: Option<f32>,
    muted: bool,
}

impl SessionChart {
    /// Creates the chart for `model`.
    #[must_use]
    pub const fn new(model: SessionModel) -> Self {
        Self {
            model,
            live: None,
            muted: false,
        }
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

impl RenderOnce for SessionChart {
    #[expect(
        clippy::too_many_lines,
        reason = "one build of the chart and its flags"
    )]
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let style: LedStyle = LedStyle::for_dark(dark);
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let muted_ink: Hsla = to_hsla(tokens.muted_foreground);
        let colors: DialColors = DialColors::for_dark(dark);
        let slots: u16 = u16::try_from(self.model.slots).unwrap_or(u16::MAX);
        let width: f32 = style.span(slots);
        let flags: Vec<Flag> = place_flags(&self.model, width);
        let band: f32 = flag_band(&flags);
        let rows: u16 = u16::try_from(TOTAL_ROWS).unwrap_or(u16::MAX);
        let height: f32 = band + style.span(rows);
        let label: SharedString = self.model.label().into();
        let pressure_label: SharedString = track_label(&self.model.states()).into();
        let range: SharedString = range_caption(self.model.range).into();
        #[expect(clippy::cast_precision_loss, reason = "a row index is below 32")]
        let pressure_top: f32 = band + PRESSURE_ROW as f32 * PITCH;
        let mut root = div()
            .id("session-chart")
            .role(Role::Image)
            .test_support()
            .aria_label(label)
            .relative()
            .w(px(width))
            .h(px(height))
            .flex_shrink_0();
        let mut flag_elements: Vec<gpui_kit::AnyElement> = Vec::new();
        for flag in &flags {
            let event: &Event = &self.model.events[flag.event];
            let tone: Hsla = event_color(event.kind, &colors, to_hsla(tokens.brand));
            let text: SharedString = event.text.clone().into();
            #[expect(clippy::cast_precision_loss, reason = "a lane count is at most 4")]
            let top: f32 = flag.lane as f32 * LANE_STEP;
            flag_elements.push(
                div()
                    .id(SharedString::from(format!("session-flag-{}", flag.event)))
                    .test_support()
                    .aria_label(text.clone())
                    .absolute()
                    .left(px(flag.left))
                    .top(px(top))
                    .h(px(FLAG_HEIGHT))
                    .w(px(flag.width))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_full()
                    .bg(tone.opacity(0.15))
                    .text_color(tone)
                    .font_family(mono.clone())
                    .text_size(px(11.0))
                    .whitespace_nowrap()
                    .child(text)
                    .into_any_element(),
            );
        }
        let paint: SessionPaint = SessionPaint {
            model: self.model,
            flags,
            band,
            colors,
            brand: to_hsla(tokens.brand),
            muted_ink,
            ink: to_hsla(tokens.foreground),
            glow: glow::enabled(cx),
            live: self.live,
            muted: self.muted,
        };
        root = root
            .child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .w(px(width))
                    .h(px(height))
                    .child(
                        canvas(
                            |_, _, _| (),
                            move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                                paint_session(&paint, bounds, window);
                            },
                        )
                        .size_full(),
                    ),
            )
            .children(flag_elements)
            .child(
                div()
                    .id("pressure-track")
                    .role(Role::Image)
                    .test_support()
                    .aria_label(pressure_label)
                    .absolute()
                    .left_0()
                    .top(px(pressure_top))
                    .w(px(width))
                    .h(px(style.span(u16::try_from(MATRIX_DOTS).unwrap_or(4)))),
            );
        let caption = |id: &'static str, text: SharedString| {
            div()
                .id(id)
                .test_support()
                .aria_label(text.clone())
                .text_size(px(12.0))
                .text_color(muted_ink)
                .child(text)
        };
        v_flex().gap(tokens::SPACE_3).child(root).child(
            v_flex()
                .gap(tokens::SPACE_1)
                .child(
                    h_flex()
                        .flex_wrap()
                        .gap_x(tokens::SPACE_4)
                        .gap_y(tokens::SPACE_1)
                        .child(caption("session-range", range))
                        .child(caption("session-scale", SCALE_CAPTION.into())),
                )
                .child(caption("session-rows", ROWS_CAPTION.into())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            disk_used: available.map_or_else(no, |a| Measured::Value(1_000 - a)),
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

    #[test]
    fn at_most_four_flags_show_text_and_the_newest_keep_it() {
        let levels = [PressureLevel::Normal, PressureLevel::Warning];
        let samples: Vec<HostSample> = (0..8)
            .map(|n| {
                sample(
                    n,
                    Some(100),
                    Some(levels[usize::try_from(n).unwrap_or(0) % 2]),
                    0,
                )
            })
            .collect();
        let model = session_model(&samples, None, 20);
        assert_eq!(model.events.len(), 7);
        assert_eq!(model.events.iter().filter(|e| e.labeled).count(), MAX_FLAGS);
        assert!(model.events[..3].iter().all(|e| !e.labeled));
        assert!(model.events[3..].iter().all(|e| e.labeled));
        let flags = place_flags(&model, 500.0);
        assert_eq!(flags.len(), MAX_FLAGS);
    }

    #[test]
    fn flags_that_would_touch_use_another_lane_and_stay_inside_the_chart() {
        let levels = [PressureLevel::Normal, PressureLevel::Critical];
        let samples: Vec<HostSample> = (0..6)
            .map(|n| {
                sample(
                    n,
                    Some(100),
                    Some(levels[usize::try_from(n).unwrap_or(0) % 2]),
                    0,
                )
            })
            .collect();
        let model = session_model(&samples, None, 6);
        let width: f32 = 6.0 * 6.0 - 1.5;
        let flags = place_flags(&model, width);
        assert!(flags.iter().any(|f| f.lane > 0));
        assert!(flags.iter().all(|f| f.left >= 0.0));
        assert!(flag_band(&flags) > 0.0);
        assert_eq!(flag_band(&[]), 0.0);
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
}
