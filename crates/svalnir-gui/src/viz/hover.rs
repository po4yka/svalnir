//! Pure parts of the hover state of a chart: the hit test, the keyboard order,
//! the transition of the marks, and the text of the cards.

use crate::{
    theme::motion::{self, FAST},
    ui::{chart_tip::TipContent, data_state::format_bytes},
    viz::{dial::share_percent_text, led::LedField},
};
use gpui_kit::{App, Bounds, Global, Pixels, point, px, size};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

/// The chart that a launch option gives keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusTarget {
    /// The headroom dial.
    Dial,
    /// The session chart.
    Session,
    /// The volume chart of Storage.
    Volume,
    /// The folder chart of Storage.
    Folders,
}

impl FocusTarget {
    /// The target of a name: "dial", "session", "volume", or "folders".
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "dial" => Some(Self::Dial),
            "session" => Some(Self::Session),
            "volume" => Some(Self::Volume),
            "folders" => Some(Self::Folders),
            _ => None,
        }
    }
}

/// A launch request for chart focus, kept as an app global until the chart
/// takes it.
#[derive(Debug, Default)]
struct LaunchFocus(Cell<Option<FocusTarget>>);

impl Global for LaunchFocus {}

/// Asks the chart of `target` to take keyboard focus and pick its first mark
/// the next time it draws with data.
pub fn request_launch_focus(target: FocusTarget, cx: &mut App) {
    cx.set_global(LaunchFocus(Cell::new(Some(target))));
}

/// Whether a request for `target` is pending. A pending request is taken once.
#[must_use]
pub fn take_launch_focus(target: FocusTarget, cx: &App) -> bool {
    cx.try_global::<LaunchFocus>().is_some_and(|request| {
        let pending: bool = request.0.get() == Some(target);
        if pending {
            request.0.set(None);
        }
        pending
    })
}

/// The mark of a chart that the pointer or the keyboard picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// The segment with this index.
    Segment(usize),
    /// The free region.
    Free,
}

impl Mark {
    /// The index of the segment; `None` for the free region.
    #[must_use]
    pub const fn segment(self) -> Option<usize> {
        match self {
            Self::Segment(index) => Some(index),
            Self::Free => None,
        }
    }
}

/// The mark under the point `(x, y)` of a chart, in pixels from its top-left
/// corner. The later segment wins where two overlap. A point outside each
/// segment and outside the free region gives `None`.
#[must_use]
pub fn mark_at(field: &LedField, x: f32, y: f32, pitch: f32) -> Option<Mark> {
    if x < 0.0 || y < 0.0 || pitch <= 0.0 {
        return None;
    }
    let column: u16 = to_cell(x / pitch);
    let row: u16 = to_cell(y / pitch);
    if let Some(index) = field
        .segments
        .iter()
        .rposition(|s| !s.rect.is_empty() && s.rect.contains(column, row))
    {
        return Some(Mark::Segment(index));
    }
    field
        .free
        .filter(|r| !r.is_empty() && r.contains(column, row))
        .map(|_| Mark::Free)
}

/// A pixel length as whole cells, rounded down and saturating.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to the u16 range first"
)]
fn to_cell(value: f32) -> u16 {
    value.floor().clamp(0.0, f32::from(u16::MAX)) as u16
}

/// The marks of a field in keyboard order: the segments that have cells, then
/// the free region.
#[must_use]
pub fn marks(field: &LedField) -> Vec<Mark> {
    let mut out: Vec<Mark> = field
        .segments
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.rect.is_empty())
        .map(|(index, _)| Mark::Segment(index))
        .collect();
    if field.free.is_some_and(|r| !r.is_empty()) {
        out.push(Mark::Free);
    }
    out
}

/// The mark after `current` when the keyboard moves by `delta` places. With no
/// current mark, a move forward picks the first and a move back picks the
/// last. The move stops at both ends.
#[must_use]
pub fn step_mark(field: &LedField, current: Option<Mark>, delta: i32) -> Option<Mark> {
    let order: Vec<Mark> = marks(field);
    let last: usize = order.len().checked_sub(1)?;
    let next: usize = match current.and_then(|c| order.iter().position(|m| *m == c)) {
        Some(at) => {
            let moved: i64 = i64::try_from(at).unwrap_or(0) + i64::from(delta);
            usize::try_from(moved.max(0)).unwrap_or(0).min(last)
        }
        None if delta >= 0 => 0,
        None => last,
    };
    order.get(next).copied()
}

/// The first or the last mark of a field.
#[must_use]
pub fn edge_mark(field: &LedField, end: bool) -> Option<Mark> {
    let order: Vec<Mark> = marks(field);
    if end {
        order.last().copied()
    } else {
        order.first().copied()
    }
}

/// The rectangle of a mark in pixels from the top-left corner of the chart.
#[must_use]
pub fn mark_rect(field: &LedField, mark: Mark, pitch: f32, cell: f32) -> Option<Bounds<Pixels>> {
    let rect = match mark {
        Mark::Segment(index) => field.segments.get(index)?.rect,
        Mark::Free => field.free?,
    };
    let span = |cells: u16| -> f32 {
        if cells == 0 {
            0.0
        } else {
            f32::from(cells) * pitch - (pitch - cell)
        }
    };
    Some(Bounds::new(
        point(px(f32::from(rect.x) * pitch), px(f32::from(rect.y) * pitch)),
        size(px(span(rect.w)), px(span(rect.h))),
    ))
}

/// Values that move from one target to the next over `FAST`.
#[derive(Debug, Clone, PartialEq)]
pub struct Tween {
    from: Vec<f32>,
    to: Vec<f32>,
    started: Instant,
}

impl Tween {
    /// A tween at rest on `values`.
    #[must_use]
    pub fn new(values: Vec<f32>, now: Instant) -> Self {
        Self {
            from: values.clone(),
            to: values,
            started: now,
        }
    }

    /// The values at `now`, eased with `ease-ui-out`.
    #[must_use]
    pub fn value_at(&self, now: Instant) -> Vec<f32> {
        let elapsed: Duration = now.saturating_duration_since(self.started);
        let t: f32 = motion::ease_ui_out(motion::progress(elapsed, Duration::ZERO, FAST));
        self.from
            .iter()
            .zip(&self.to)
            .map(|(a, b)| a + (b - a) * t)
            .collect()
    }

    /// Whether the values still move at `now`.
    #[must_use]
    pub fn running(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) < FAST && self.from != self.to
    }

    /// Moves toward `to`, from the values of `now`. With `animate` false, or
    /// with a new length, the values jump. The same target changes nothing.
    pub fn retarget(&mut self, to: Vec<f32>, now: Instant, animate: bool) {
        if to == self.to {
            return;
        }
        let jump: bool = !animate || to.len() != self.to.len();
        self.from = if jump { to.clone() } else { self.value_at(now) };
        self.to = to;
        self.started = now;
    }
}

/// The share of `part` in `whole` as the text of a card: "27%" or "<1%".
#[must_use]
pub fn share_text(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0%".to_owned();
    }
    let ppm: u128 = u128::from(part) * 1_000_000 / u128::from(whole);
    share_percent_text(u64::try_from(ppm).unwrap_or(1_000_000))
}

/// The size as "12.3 GB".
#[must_use]
pub fn size_text(bytes: u64) -> String {
    let (value, unit) = format_bytes(bytes);
    format!("{value} {unit}")
}

/// The card of a segment of a Storage chart: the name, the share of the chart
/// total, the size in the metric in use and in the other metric, and a note.
#[must_use]
pub fn segment_tip(
    name: &str,
    bytes: u64,
    total: u64,
    metric: (&str, u64),
    other: Option<(&str, u64)>,
    note: Option<String>,
) -> TipContent {
    let mut tip: TipContent = TipContent::new(name)
        .aside(share_text(bytes, total))
        .row(metric.0, size_text(metric.1));
    if let Some((label, value)) = other {
        tip = tip.row(label, size_text(value));
    }
    if let Some(note) = note {
        tip = tip.note(note);
    }
    tip
}

/// The card of the free region of a volume.
#[must_use]
pub fn free_tip(free: u64, whole: u64) -> TipContent {
    TipContent::new("Free")
        .aside(share_text(free, whole))
        .row("Available", size_text(free))
        .note("Free space of the volume")
}

/// The cards of a volume strip: the used part and the free region. Both show
/// Used, Available, and Total.
#[must_use]
pub fn volume_tips(used: u64, total: u64) -> (TipContent, TipContent) {
    let free: u64 = total.saturating_sub(used);
    let rows = |tip: TipContent| -> TipContent {
        tip.row("Used", size_text(used))
            .row("Available", size_text(free))
            .row("Total", size_text(total))
    };
    (
        rows(TipContent::new("Used").aside(share_text(used, total))),
        rows(TipContent::new("Free").aside(share_text(free, total)))
            .note("Free space of the volume"),
    )
}

/// The note of a folder: the last two parts of its path, as "…/Developer".
#[must_use]
pub fn path_note(path: &std::path::Path) -> String {
    let name: String = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| format!("…/{}", n.to_string_lossy()),
    );
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viz::{
        led::{LedField, LedSegment},
        treemap::CellRect,
    };
    use gpui_kit::hsla;

    fn field() -> LedField {
        let color = hsla(0.5, 0.5, 0.5, 1.0);
        LedField {
            columns: 40,
            rows: 10,
            segments: vec![
                LedSegment::new(CellRect::new(0, 0, 10, 10), color, 1),
                LedSegment::new(CellRect::new(11, 0, 0, 0), color, 2),
                LedSegment::new(CellRect::new(11, 0, 9, 10), color, 3),
            ],
            free: Some(CellRect::new(25, 0, 10, 10)),
            head: None,
            phase: None,
        }
    }

    #[test]
    fn the_pointer_picks_a_segment_the_free_region_or_nothing() {
        let f = field();
        assert_eq!(mark_at(&f, 3.0, 3.0, 6.0), Some(Mark::Segment(0)));
        assert_eq!(mark_at(&f, 12.0 * 6.0, 3.0, 6.0), Some(Mark::Segment(2)));
        assert_eq!(mark_at(&f, 26.0 * 6.0, 30.0, 6.0), Some(Mark::Free));
        assert_eq!(mark_at(&f, 22.0 * 6.0, 3.0, 6.0), None, "between");
        assert_eq!(mark_at(&f, -1.0, 3.0, 6.0), None, "left of the chart");
        assert_eq!(mark_at(&f, 3.0, 99.0 * 6.0, 6.0), None, "below the chart");
    }

    #[test]
    fn the_keyboard_walks_the_marks_and_stops_at_the_ends() {
        let f = field();
        assert_eq!(marks(&f), [Mark::Segment(0), Mark::Segment(2), Mark::Free]);
        assert_eq!(step_mark(&f, None, 1), Some(Mark::Segment(0)));
        assert_eq!(step_mark(&f, None, -1), Some(Mark::Free));
        assert_eq!(
            step_mark(&f, Some(Mark::Segment(0)), 1),
            Some(Mark::Segment(2))
        );
        assert_eq!(step_mark(&f, Some(Mark::Free), 1), Some(Mark::Free));
        assert_eq!(
            step_mark(&f, Some(Mark::Segment(0)), -1),
            Some(Mark::Segment(0))
        );
        assert_eq!(edge_mark(&f, true), Some(Mark::Free));
        assert_eq!(edge_mark(&f, false), Some(Mark::Segment(0)));
    }

    #[test]
    fn the_mark_rectangle_follows_the_cells() {
        let f = field();
        let r = mark_rect(&f, Mark::Segment(0), 6.0, 4.5).expect("rect");
        assert_eq!(r.origin.x, px(0.0));
        assert_eq!(r.size.width, px(10.0 * 6.0 - 1.5));
        assert!(mark_rect(&f, Mark::Segment(9), 6.0, 4.5).is_none());
    }

    #[test]
    fn a_tween_eases_over_fast_and_jumps_without_motion() {
        let t0 = Instant::now();
        let mut tween = Tween::new(vec![0.0, 1.0], t0);
        assert!(!tween.running(t0));
        tween.retarget(vec![1.0, 0.0], t0, true);
        assert!(tween.running(t0));
        assert!((tween.value_at(t0)[0]).abs() < 1e-6);
        let mid = tween.value_at(t0 + FAST / 2)[0];
        assert!(mid > 0.0 && mid < 1.0);
        let end = t0 + FAST;
        assert!((tween.value_at(end)[0] - 1.0).abs() < 1e-6);
        assert!(!tween.running(end));
        tween.retarget(vec![0.0, 1.0], end, false);
        assert!(!tween.running(end));
        assert!((tween.value_at(end)[0]).abs() < 1e-6);
    }

    #[test]
    fn a_share_below_one_percent_reads_less_than_one() {
        assert_eq!(share_text(1, 1000), "<1%");
        assert_eq!(share_text(270, 1000), "27%");
        assert_eq!(share_text(1000, 1000), "100%");
        assert_eq!(share_text(0, 0), "0%");
    }

    #[test]
    fn the_card_of_a_folder_has_the_metric_the_other_metric_and_the_path() {
        let tip = segment_tip(
            "Developer",
            2_000_000_000,
            10_000_000_000,
            ("Allocated", 2_000_000_000),
            Some(("Logical", 1_500_000_000)),
            Some(path_note(std::path::Path::new("/Users/a/Developer"))),
        );
        assert_eq!(tip.title, "Developer");
        assert_eq!(tip.aside.as_deref(), Some("20%"));
        assert_eq!(tip.rows.len(), 2);
        assert_eq!(tip.rows[0].label, "Allocated");
        assert_eq!(tip.note.as_deref(), Some("…/Developer"));
        let free = free_tip(5_000_000_000, 10_000_000_000);
        assert_eq!(free.note.as_deref(), Some("Free space of the volume"));
    }
}
