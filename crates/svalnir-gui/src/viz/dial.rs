//! The headroom dial: three rings of round dots for disk, swap, and memory
//! pressure (`DESIGN.md` section 5, "Dot rings and the session chart").
//!
//! `dial_model` is pure: it turns one host reading into the dots of the
//! rings and the texts. `HeadroomDial` paints the rings from one canvas.
//! `DialLegend` is the legend beside the dial.

use crate::{
    data::model::{HostSnapshot, Measured, PressureLevel},
    theme::{
        glow, motion,
        tokens::{self, Tokens, to_hsla},
    },
    ui::{
        data_state::{UNAVAILABLE_TEXT, format_bytes, used_capacity},
        pill::{StatusPill, Tone},
        ring_center::RingCenter,
    },
    viz::led::{LedStyle, lit_color},
};
use gpui_kit::{
    App, Bounds, BoxShadow, Corners, FocusHandle, Hsla, InteractiveElement as _, IntoElement,
    ParentElement as _, Pixels, Point, RenderOnce, Role, SharedString,
    StatefulInteractiveElement as _, Styled as _, TestSupportExt as _, Window, canvas,
    component::{
        ActiveTheme as _,
        button::{Button, ButtonVariants as _},
        h_flex, v_flex,
    },
    div, fill, hsla, point, px, size,
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

/// The side of the square of the dial, in pixels.
pub const DIAL_SIZE: f32 = 196.0;
/// The radius of each ring, from the outside.
pub const RING_RADII: [f32; 3] = [90.0, 76.0, 62.0];
/// The number of dots of each ring.
pub const RING_DOTS: [usize; 3] = [96, 80, 64];
/// The diameter of one dot, in pixels.
pub const DOT_PX: f32 = 4.0;
/// The delay between the entry of two rings.
pub const RING_STAGGER: Duration = Duration::from_millis(80);
/// The share of full strength that a ring without the pick shows.
const UNPICKED_ALPHA: f32 = 0.55;

/// The resource of a ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingKind {
    /// Used space of the startup volume.
    Disk,
    /// Used swap.
    Swap,
    /// The memory pressure state.
    Pressure,
}

impl RingKind {
    /// The name of the resource, as the legend shows it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Disk => "Disk",
            Self::Swap => "Swap",
            Self::Pressure => "Memory pressure",
        }
    }

    /// The index of the ring, from the outside.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Disk => 0,
            Self::Swap => 1,
            Self::Pressure => 2,
        }
    }
}

/// What one ring shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingState {
    /// No reading: each second dot is empty and the others are not drawn.
    Unavailable,
    /// A used share: `lit` dots of the used part, then `soft` dots of the
    /// part that the system can reclaim.
    Used {
        /// The dots of the used part.
        lit: usize,
        /// The dots of the soft part, after the used part.
        soft: usize,
    },
    /// The pressure state.
    Pressure(PressureLevel),
}

/// One ring of the dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring {
    /// The resource.
    pub kind: RingKind,
    /// The number of dots.
    pub dots: usize,
    /// What the ring shows.
    pub state: RingState,
    /// The value for the legend: a text, or an em dash.
    pub value: String,
    /// A second legend line: the soft part, or the reason.
    pub detail: Option<String>,
    /// The used share in parts per million, for the pick.
    pub share_ppm: Option<u64>,
    /// The center value when this ring is picked.
    pub center_value: String,
    /// The one-line center caption when this ring is picked.
    pub center_caption: String,
}

/// The three rings and the picked ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialModel {
    /// The rings, from the outside: disk, swap, pressure.
    pub rings: [Ring; 3],
    /// The index of the picked ring.
    pub picked: usize,
}

impl DialModel {
    /// The accessible label: the three values in words.
    #[must_use]
    pub fn label(&self) -> String {
        let parts: Vec<String> = self
            .rings
            .iter()
            .map(|ring| match &ring.detail {
                Some(detail) => format!("{}: {}, {detail}", ring.kind.name(), ring.value),
                None => format!("{}: {}", ring.kind.name(), ring.value),
            })
            .collect();
        format!("Headroom. {}.", parts.join(". "))
    }
}

/// The lit dots of `value` in `capacity`, of `dots` dots: the rounded share,
/// at least 1 for a nonzero value, and all dots only when the value reaches
/// the capacity. A capacity of 0 has no lit dot.
#[must_use]
pub fn lit_dots(value: u64, capacity: u64, dots: usize) -> usize {
    if capacity == 0 || value == 0 || dots == 0 {
        return 0;
    }
    if value >= capacity {
        return dots;
    }
    let wide_dots: u128 = u128::try_from(dots).unwrap_or(0);
    let wide_capacity: u128 = u128::from(capacity);
    let rounded: u128 = (u128::from(value) * wide_dots * 2 + wide_capacity) / (wide_capacity * 2);
    let rounded: usize = usize::try_from(rounded).unwrap_or(dots);
    rounded.clamp(1, dots.saturating_sub(1).max(1))
}

/// The share of `value` in `capacity` in parts per million.
fn share_ppm(value: u64, capacity: u64) -> u64 {
    if capacity == 0 {
        return 0;
    }
    let ppm: u128 = u128::from(value.min(capacity)) * 1_000_000 / u128::from(capacity);
    u64::try_from(ppm).unwrap_or(1_000_000)
}

fn bytes_text(bytes: u64) -> String {
    let (value, unit) = format_bytes(bytes);
    format!("{value} {unit}")
}

fn unavailable_ring(kind: RingKind, reason: &str) -> Ring {
    Ring {
        kind,
        dots: RING_DOTS[kind.index()],
        state: RingState::Unavailable,
        value: UNAVAILABLE_TEXT.to_owned(),
        detail: Some(reason.to_owned()),
        share_ppm: None,
        center_value: UNAVAILABLE_TEXT.to_owned(),
        center_caption: format!("{} unavailable", kind.name()),
    }
}

fn disk_ring(host: &HostSnapshot) -> Ring {
    let kind: RingKind = RingKind::Disk;
    let dots: usize = RING_DOTS[kind.index()];
    let used: Measured<u64> = used_capacity(&host.disk_total, &host.disk_available);
    let (Measured::Value(used), Measured::Value(total)) = (&used, &host.disk_total) else {
        let reason: &str = match (&used, &host.disk_total) {
            (Measured::Unavailable(reason), _) | (_, Measured::Unavailable(reason)) => reason,
            _ => "no reading",
        };
        return unavailable_ring(kind, reason);
    };
    if *total == 0 {
        return unavailable_ring(kind, "the volume reports no capacity");
    }
    let lit: usize = lit_dots(*used, *total, dots);
    let soft_bytes: Option<u64> = match (&host.disk_available, &host.disk_free) {
        (Measured::Value(available), Measured::Value(free)) if available > free => {
            Some(available - free)
        }
        _ => None,
    };
    let soft: usize = soft_bytes
        .map_or(0, |bytes| lit_dots(bytes, *total, dots))
        .min(dots - lit);
    Ring {
        kind,
        dots,
        state: RingState::Used { lit, soft },
        value: format!("{} used of {}", bytes_text(*used), bytes_text(*total)),
        detail: soft_bytes.map(|bytes| {
            format!(
                "Soft part: {} that the system can reclaim",
                bytes_text(bytes)
            )
        }),
        share_ppm: Some(share_ppm(*used, *total)),
        center_value: bytes_text(*used),
        center_caption: "Disk used".to_owned(),
    }
}

fn swap_ring(host: &HostSnapshot) -> Ring {
    let kind: RingKind = RingKind::Swap;
    let dots: usize = RING_DOTS[kind.index()];
    let (Measured::Value(used), Measured::Value(total)) = (&host.swap_used, &host.swap_total)
    else {
        let reason: &str = match (&host.swap_used, &host.swap_total) {
            (Measured::Unavailable(reason), _) | (_, Measured::Unavailable(reason)) => reason,
            _ => "no reading",
        };
        return unavailable_ring(kind, reason);
    };
    if *total == 0 {
        if *used > 0 {
            return unavailable_ring(kind, "swap use is reported without swap space");
        }
        return Ring {
            kind,
            dots,
            state: RingState::Used { lit: 0, soft: 0 },
            value: "No swap space".to_owned(),
            detail: None,
            share_ppm: Some(0),
            center_value: "None".to_owned(),
            center_caption: "No swap space".to_owned(),
        };
    }
    if used > total {
        return unavailable_ring(kind, "swap use is larger than the swap space");
    }
    Ring {
        kind,
        dots,
        state: RingState::Used {
            lit: lit_dots(*used, *total, dots),
            soft: 0,
        },
        value: format!("{} used of {}", bytes_text(*used), bytes_text(*total)),
        detail: None,
        share_ppm: Some(share_ppm(*used, *total)),
        center_value: bytes_text(*used),
        center_caption: "Swap used".to_owned(),
    }
}

fn pressure_ring(host: &HostSnapshot) -> Ring {
    let kind: RingKind = RingKind::Pressure;
    match &host.pressure {
        Measured::Value(level) => Ring {
            kind,
            dots: RING_DOTS[kind.index()],
            state: RingState::Pressure(*level),
            value: level.label().to_owned(),
            detail: None,
            share_ppm: None,
            center_value: level.label().to_owned(),
            center_caption: "Memory pressure".to_owned(),
        },
        Measured::Unavailable(reason) => unavailable_ring(kind, reason),
    }
}

/// The index of the picked ring. In this order: the pressure ring while the
/// state is not normal; the ring with the largest used share above 0 (the
/// first of equal shares wins); the pressure ring when it is measured; the
/// first measured ring; ring 0. A ring with no capacity or a share of 0 does
/// not win over a measured ring.
fn pick(rings: &[Ring; 3]) -> usize {
    if matches!(
        rings[2].state,
        RingState::Pressure(PressureLevel::Warning | PressureLevel::Critical)
    ) {
        return 2;
    }
    let mut best: Option<(usize, u64)> = None;
    for (index, ring) in rings.iter().enumerate().take(2) {
        if let Some(share) = ring.share_ppm
            && share > 0
            && best.is_none_or(|(_, top)| share > top)
        {
            best = Some((index, share));
        }
    }
    if let Some((index, _)) = best {
        return index;
    }
    if matches!(rings[2].state, RingState::Pressure(_)) {
        return 2;
    }
    rings
        .iter()
        .position(|ring| ring.state != RingState::Unavailable)
        .unwrap_or(0)
}

/// The model of the dial for one host reading.
#[must_use]
pub fn dial_model(host: &HostSnapshot) -> DialModel {
    let rings: [Ring; 3] = [disk_ring(host), swap_ring(host), pressure_ring(host)];
    let picked: usize = pick(&rings);
    DialModel { rings, picked }
}

/// The lit count that eases from `from` to `to` at `progress`
/// (`0.0..=1.0`) with `ease-ui-out`. It starts at `from` and ends exactly at
/// `to`; a shrink eases down in the same way.
#[must_use]
pub fn eased_count(from: usize, to: usize, progress: f32) -> usize {
    if from == to || progress >= 1.0 {
        return to;
    }
    let eased: f32 = motion::ease_ui_out(progress);
    let span: usize = from.abs_diff(to);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a dot count is far below 2^24; the product is rounded and clamped first"
    )]
    let moved: usize = (span as f32 * eased.clamp(0.0, 1.0)).round() as usize;
    let moved: usize = moved.min(span);
    if to > from {
        from + moved
    } else {
        from - moved
    }
}

/// The lit count of a ring that shows a used share, or `None`.
#[must_use]
pub const fn lit_of(ring: &Ring) -> Option<usize> {
    match ring.state {
        RingState::Used { lit, .. } => Some(lit),
        _ => None,
    }
}

/// The move of the heads of the rings to a new reading: a lit count eases
/// from the count on screen to the new count in `FRONT_EASE`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeadMove {
    from: [Option<usize>; 3],
    target: [Option<usize>; 3],
    start: Option<Instant>,
}

impl HeadMove {
    /// The lit counts on screen at `now`, and whether the move still runs.
    #[must_use]
    pub fn shown(&self, now: Instant) -> ([Option<usize>; 3], bool) {
        let Some(start) = self.start else {
            return (self.target, false);
        };
        let t: f32 = motion::progress(
            now.saturating_duration_since(start),
            Duration::ZERO,
            motion::FRONT_EASE,
        );
        if t >= 1.0 {
            return (self.target, false);
        }
        let mut out: [Option<usize>; 3] = self.target;
        for (slot, (from, to)) in out.iter_mut().zip(self.from.iter().zip(self.target)) {
            if let (Some(from), Some(to)) = (from, to) {
                *slot = Some(eased_count(*from, to, t));
            }
        }
        (out, true)
    }

    /// Takes the measured lit counts of a new reading. When a count changes
    /// and `animate` is true, the move starts from the counts on screen. The
    /// first reading, and any reading with `animate` false, applies at once.
    pub fn observe(&mut self, targets: [Option<usize>; 3], now: Instant, animate: bool) {
        if !animate {
            // Reduce Motion that comes on during a move ends the move.
            self.start = None;
        }
        if targets == self.target {
            return;
        }
        let first: bool = self.target.iter().all(Option::is_none);
        if animate && !first {
            self.from = self.shown(now).0;
            self.start = Some(now);
        } else {
            self.start = None;
        }
        self.target = targets;
    }
}

/// `model` with the lit counts of its used rings replaced by `lit_counts`, where a
/// ring has one. The soft part stays after the lit part, within the ring.
#[must_use]
pub fn with_lit_counts(model: &DialModel, lit_counts: [Option<usize>; 3]) -> DialModel {
    let mut out: DialModel = model.clone();
    for (ring, lit) in out.rings.iter_mut().zip(lit_counts) {
        if let (RingState::Used { lit: old, soft }, Some(lit)) = (&mut ring.state, lit) {
            *old = lit.min(ring.dots);
            *soft = (*soft).min(ring.dots - *old);
        }
    }
    out
}

/// How one dot of a ring is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot {
    /// No dot: a gap between sectors, or a dot of an unavailable ring.
    Skip,
    /// An empty dot of the remaining part.
    Empty,
    /// A dot of the used part.
    Lit,
    /// The last lit dot.
    Head,
    /// A dot of the soft part.
    Soft,
    /// A dot of a pressure sector below the current state.
    Dim,
}

/// The first dot and the end (exclusive) of each pressure sector, with a gap
/// of one dot after each sector.
#[must_use]
pub fn sector_bounds(dots: usize) -> [(usize, usize); 3] {
    let free: usize = dots.saturating_sub(3);
    let base: usize = free / 3;
    let extra: usize = free % 3;
    let mut out: [(usize, usize); 3] = [(0, 0); 3];
    let mut start: usize = 0;
    for (index, slot) in out.iter_mut().enumerate() {
        let len: usize = base + usize::from(index < extra);
        *slot = (start, start + len);
        start += len + 1;
    }
    out
}

/// The sector of dot `index` of a pressure ring, or `None` for a gap.
#[must_use]
pub fn pressure_sector(index: usize, dots: usize) -> Option<usize> {
    sector_bounds(dots)
        .iter()
        .position(|(start, end)| index >= *start && index < *end)
}

/// The sector of a pressure level.
#[must_use]
pub const fn level_sector(level: PressureLevel) -> usize {
    match level {
        PressureLevel::Normal => 0,
        PressureLevel::Warning => 1,
        PressureLevel::Critical => 2,
    }
}

/// `count` scaled by `progress`, rounded; the full count at 1.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "a dot count is far below 2^24; the product is rounded and clamped first"
)]
fn scaled(count: usize, progress: f32) -> usize {
    if progress >= 1.0 {
        return count;
    }
    (count as f32 * progress.clamp(0.0, 1.0)).round() as usize
}

/// The dots of a ring. `sweep` is the progress `0.0..=1.0` of the entry of
/// this ring; it scales the lit count. `None` is the final state.
#[must_use]
pub fn dot_kinds(ring: &Ring, sweep: Option<f32>) -> Vec<Dot> {
    let p: f32 = sweep.unwrap_or(1.0);
    let mut dots: Vec<Dot> = vec![Dot::Empty; ring.dots];
    match ring.state {
        RingState::Unavailable => {
            for (index, dot) in dots.iter_mut().enumerate() {
                *dot = if index % 2 == 0 {
                    Dot::Empty
                } else {
                    Dot::Skip
                };
            }
        }
        RingState::Used { lit, soft } => {
            let reach: usize = scaled(lit + soft, p);
            let shown: usize = reach.min(lit);
            for (index, dot) in dots.iter_mut().enumerate() {
                if index < shown {
                    *dot = Dot::Lit;
                } else if index < reach && (index - lit) % 2 == 0 {
                    *dot = Dot::Soft;
                }
            }
            if shown > 0 {
                dots[shown - 1] = Dot::Head;
            }
        }
        RingState::Pressure(level) => {
            let current: usize = level_sector(level);
            let bounds: [(usize, usize); 3] = sector_bounds(ring.dots);
            let reach: usize = scaled(bounds[current].1, p);
            for (index, dot) in dots.iter_mut().enumerate() {
                *dot = match pressure_sector(index, ring.dots) {
                    None => Dot::Skip,
                    Some(sector) if index < reach && sector == current => Dot::Lit,
                    Some(sector) if index < reach && sector < current => Dot::Dim,
                    Some(_) => Dot::Empty,
                };
            }
            if let Some(last) = (0..reach.min(ring.dots))
                .rev()
                .find(|index| dots[*index] == Dot::Lit)
            {
                dots[last] = Dot::Head;
            }
        }
    }
    dots
}

/// The time that the whole entry of `rings` rings takes.
#[must_use]
pub fn sweep_total(rings: usize) -> Duration {
    motion::SLOW + RING_STAGGER.saturating_mul(u32::try_from(rings.saturating_sub(1)).unwrap_or(0))
}

/// The eased progress of ring `ring` at the overall progress `overall`
/// (`0.0..=1.0` of `sweep_total(rings)`): each ring starts 80 ms after the
/// ring outside it and takes `SLOW`.
#[must_use]
pub fn ring_progress(overall: f32, ring: usize, rings: usize) -> f32 {
    let elapsed: Duration = sweep_total(rings).mul_f32(overall.clamp(0.0, 1.0));
    let delay: Duration = RING_STAGGER.saturating_mul(u32::try_from(ring).unwrap_or(0));
    motion::ease_ui_out(motion::progress(elapsed, delay, motion::SLOW))
}

/// The center of dot `index` of `dots` on a ring of `radius`, from the center
/// of the dial. The first dot is at the top and the ring runs clockwise.
#[must_use]
pub fn dot_center(index: usize, dots: usize, radius: f32) -> (f32, f32) {
    #[expect(clippy::cast_precision_loss, reason = "a dot count is far below 2^24")]
    let turn: f32 = index as f32 / dots.max(1) as f32;
    let angle: f32 = turn * std::f32::consts::TAU - std::f32::consts::FRAC_PI_2;
    (radius * angle.cos(), radius * angle.sin())
}

/// The colors of the dial, from the tokens of one theme.
#[derive(Debug, Clone, Copy)]
pub struct DialColors {
    /// The disk ring.
    pub disk: Hsla,
    /// The swap ring.
    pub swap: Hsla,
    /// The Normal sector.
    pub positive: Hsla,
    /// The Warning sector.
    pub warning: Hsla,
    /// The Critical sector.
    pub negative: Hsla,
    /// An empty dot.
    pub empty: Hsla,
    /// The radial marker.
    pub marker: Hsla,
}

impl DialColors {
    /// The colors of the dark or the light theme.
    #[must_use]
    pub fn for_dark(dark: bool) -> Self {
        let tokens: &Tokens = Tokens::for_dark(dark);
        Self {
            disk: to_hsla(tokens.brand),
            swap: Hsla::from(crate::theme::palette::category_color(1, dark)),
            positive: to_hsla(tokens.positive),
            warning: to_hsla(tokens.warning),
            negative: to_hsla(tokens.negative),
            empty: LedStyle::for_dark(dark).lattice,
            marker: to_hsla(tokens.foreground),
        }
    }

    /// The color of a sector of the pressure ring.
    #[must_use]
    pub const fn sector(&self, sector: usize) -> Hsla {
        match sector {
            0 => self.positive,
            1 => self.warning,
            _ => self.negative,
        }
    }
}

fn dot_bounds(origin: Point<Pixels>, center: (f32, f32), side: f32) -> Bounds<Pixels> {
    Bounds::new(
        point(
            origin.x + px(DIAL_SIZE / 2.0 + center.0 - side / 2.0),
            origin.y + px(DIAL_SIZE / 2.0 + center.1 - side / 2.0),
        ),
        size(px(side), px(side)),
    )
}

/// The inputs of one paint of the dial.
#[derive(Debug, Clone)]
struct DialPaint {
    model: DialModel,
    picked: usize,
    sweep: Option<f32>,
    colors: DialColors,
    glow: bool,
    muted: bool,
}

fn paint_dial(paint: &DialPaint, bounds: Bounds<Pixels>, window: &mut Window) {
    let origin: Point<Pixels> = bounds.origin;
    let white: Hsla = hsla(0.0, 0.0, 1.0, 1.0);
    let rest: f32 = if paint.muted { 0.6 } else { 1.0 };
    let rings: usize = paint.model.rings.len();
    let kinds: Vec<(usize, Vec<Dot>)> = paint
        .model
        .rings
        .iter()
        .enumerate()
        .map(|(index, ring)| {
            let progress: Option<f32> = paint
                .sweep
                .map(|overall| ring_progress(overall, index, rings));
            (index, dot_kinds(ring, progress))
        })
        .collect();
    // The glow of the heads first: the dots cover it.
    if paint.glow {
        for (index, dots) in &kinds {
            let radius: f32 = RING_RADII[*index];
            let dot_count: usize = dots.len();
            for (dot, kind) in dots.iter().enumerate() {
                if *kind == Dot::Head {
                    let shadow: BoxShadow = BoxShadow {
                        color: hsla(0.0, 0.0, 1.0, 0.5),
                        offset: Point::default(),
                        blur_radius: px(8.0),
                        spread_radius: px(0.0),
                        inset: false,
                    };
                    window.paint_drop_shadows(
                        dot_bounds(origin, dot_center(dot, dot_count, radius), DOT_PX),
                        Corners::all(px(DOT_PX / 2.0)),
                        &[shadow],
                    );
                }
            }
        }
    }
    for (index, dots) in &kinds {
        let ring: &Ring = &paint.model.rings[*index];
        let radius: f32 = RING_RADII[*index];
        let strength: f32 = if *index == paint.picked {
            1.0
        } else {
            UNPICKED_ALPHA
        } * rest;
        for (dot, kind) in dots.iter().enumerate() {
            let base: Hsla = match ring.kind {
                RingKind::Disk => paint.colors.disk,
                RingKind::Swap => paint.colors.swap,
                RingKind::Pressure => paint
                    .colors
                    .sector(pressure_sector(dot, ring.dots).unwrap_or(0)),
            };
            let color: Hsla = match kind {
                Dot::Skip => continue,
                Dot::Empty => paint.colors.empty,
                Dot::Lit => lit_color(base).opacity(strength),
                Dot::Head => white.opacity(rest),
                Dot::Soft | Dot::Dim => base.opacity(0.28 * strength),
            };
            window.paint_quad(
                fill(
                    dot_bounds(origin, dot_center(dot, ring.dots, radius), DOT_PX),
                    color,
                )
                .corner_radii(Corners::all(px(DOT_PX / 2.0))),
            );
        }
    }
    // The radial marker of the picked ring at its head: 1.5 px by 8 px,
    // painted as small squares along the radius.
    if let Some((_, dots)) = kinds.get(paint.picked)
        && let Some(head) = dots.iter().position(|kind| *kind == Dot::Head)
    {
        let radius: f32 = RING_RADII[paint.picked];
        for step in 0..8_u8 {
            let along: f32 = radius - 3.5 + f32::from(step);
            let (x, y): (f32, f32) = dot_center(head, dots.len(), along);
            window.paint_quad(
                fill(
                    dot_bounds(origin, (x, y), 1.5),
                    paint.colors.marker.opacity(rest),
                )
                .corner_radii(Corners::all(px(0.5))),
            );
        }
    }
}

/// The dial as an element.
#[derive(IntoElement, Debug)]
pub struct HeadroomDial {
    model: DialModel,
    picked: Option<usize>,
    sweep: Option<f32>,
    muted: bool,
}

impl HeadroomDial {
    /// Creates a dial for `model`.
    #[must_use]
    pub const fn new(model: DialModel) -> Self {
        Self {
            model,
            picked: None,
            sweep: None,
            muted: false,
        }
    }

    /// Picks the ring `index` in place of the ring of the model.
    #[must_use]
    pub const fn picked(mut self, index: Option<usize>) -> Self {
        self.picked = index;
        self
    }

    /// The progress `0.0..=1.0` of the entry animation; `None` is the final
    /// state.
    #[must_use]
    pub const fn sweep(mut self, sweep: Option<f32>) -> Self {
        self.sweep = sweep;
        self
    }

    /// Draws the values muted, for stale data.
    #[must_use]
    pub const fn muted(mut self, muted: bool) -> Self {
        self.muted = muted;
        self
    }
}

impl RenderOnce for HeadroomDial {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let picked: usize = self.picked.unwrap_or(self.model.picked).min(2);
        let label: String = self.model.label();
        let center: &Ring = &self.model.rings[picked];
        let value: SharedString = center.center_value.clone().into();
        let caption: SharedString = center.center_caption.clone().into();
        let center_state: RingState = center.state;
        let center_unavailable: bool = center_state == RingState::Unavailable;
        let colors: DialColors = DialColors::for_dark(dark);
        let paint: DialPaint = DialPaint {
            model: self.model,
            picked,
            sweep: self.sweep,
            colors,
            glow: glow::enabled(cx),
            muted: self.muted,
        };
        div()
            .id("headroom-dial")
            .role(Role::Image)
            .test_support()
            .aria_label(SharedString::from(label))
            .relative()
            .w(px(DIAL_SIZE))
            .h(px(DIAL_SIZE))
            .flex_shrink_0()
            .child(
                div().absolute().top_0().left_0().size_full().child(
                    canvas(
                        |_, _, _| (),
                        move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                            paint_dial(&paint, bounds, window);
                        },
                    )
                    .size_full(),
                ),
            )
            .child({
                let mut center_view = RingCenter::new(
                    "dial-center-value",
                    value,
                    caption,
                    // The inner ring: its diameter without the dot.
                    2.0 * RING_RADII[2] - DOT_PX,
                )
                .caption_id("dial-center-caption")
                .muted(self.muted || center_unavailable);
                if let RingState::Pressure(level) = center_state {
                    center_view = center_view.state(colors.sector(level_sector(level)));
                }
                center_view
            })
    }
}

type PickHandler = Rc<dyn Fn(Option<usize>, &mut Window, &mut App)>;

/// The element ids of the three legend rows.
pub const ROW_IDS: [&str; 3] = ["dial-row-disk", "dial-row-swap", "dial-row-pressure"];

/// The legend of the dial: one button row for each ring.
#[derive(IntoElement)]
pub struct DialLegend {
    model: DialModel,
    pill: (&'static str, Tone),
    muted: bool,
    on_pick: Option<PickHandler>,
    focus: Option<[FocusHandle; 3]>,
}

impl std::fmt::Debug for DialLegend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialLegend").finish_non_exhaustive()
    }
}

impl DialLegend {
    /// Creates the legend. `pill` is the pressure state as a pill.
    #[must_use]
    pub fn new(model: DialModel, pill: (&'static str, Tone)) -> Self {
        Self {
            model,
            pill,
            muted: false,
            on_pick: None,
            focus: None,
        }
    }

    /// Draws the values muted, for stale data.
    #[must_use]
    pub const fn muted(mut self, muted: bool) -> Self {
        self.muted = muted;
        self
    }

    /// Sets the focus handles of the three row buttons, so the caller can
    /// read which row has the keyboard focus.
    #[must_use]
    pub fn focus_handles(mut self, handles: [FocusHandle; 3]) -> Self {
        self.focus = Some(handles);
        self
    }

    /// Sets the handler for the hover or the activation of a row; it gets
    /// the index of the ring, and `None` when the pointer leaves.
    #[must_use]
    pub fn on_pick(mut self, f: impl Fn(Option<usize>, &mut Window, &mut App) + 'static) -> Self {
        self.on_pick = Some(Rc::new(f));
        self
    }
}

impl RenderOnce for DialLegend {
    #[expect(clippy::too_many_lines, reason = "one build of the three rows")]
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let colors: DialColors = DialColors::for_dark(dark);
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let muted: Hsla = to_hsla(tokens.muted_foreground);
        let value_color: Hsla = if self.muted {
            muted
        } else {
            to_hsla(tokens.foreground)
        };
        let sans: SharedString = cx.theme().font_family.clone();
        // The name column is as wide as the widest name (about 7 px a letter at 13 px).
        let name_width: f32 = self
            .model
            .rings
            .iter()
            .map(|ring| ring.kind.name().chars().count())
            .max()
            .map_or(0.0, |count| count_f32(count) * 7.0);
        let mut rows = v_flex().gap(tokens::SPACE_3).min_w(px(0.0));
        for (index, ring) in self.model.rings.iter().enumerate() {
            let swatch: Hsla = match ring.kind {
                RingKind::Disk => colors.disk,
                RingKind::Swap => colors.swap,
                RingKind::Pressure => match ring.state {
                    RingState::Pressure(level) => colors.sector(level_sector(level)),
                    _ => muted,
                },
            };
            let label: String = match &ring.detail {
                Some(detail) => format!("{}: {}, {detail}", ring.kind.name(), ring.value),
                None => format!("{}: {}", ring.kind.name(), ring.value),
            };
            let hover: Option<PickHandler> = self.on_pick.clone();
            let click: Option<PickHandler> = self.on_pick.clone();
            // The whole row is the target: an empty button covers it, so the
            // click and the keyboard focus pick the ring.
            let mut target = Button::new(SharedString::from(format!("{}-button", ROW_IDS[index])))
                .ghost()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .on_click(move |_, window, cx| {
                    if let Some(pick) = &click {
                        pick(Some(index), window, cx);
                    }
                });
            if let Some(handles) = &self.focus {
                target = target.track_focus(&handles[index]);
            }
            let value: gpui_kit::AnyElement = if ring.kind == RingKind::Pressure {
                StatusPill::new(self.pill.0, self.pill.1)
                    .id("pressure-pill")
                    .into_any_element()
            } else if let Some((used, total)) = ring.value.split_once(" used of ") {
                h_flex()
                    .items_baseline()
                    .gap(tokens::SPACE_1)
                    .text_size(px(12.0))
                    .child(
                        div()
                            .font_family(mono.clone())
                            .text_color(value_color)
                            .child(used.to_owned()),
                    )
                    .child(
                        div()
                            .font_family(sans.clone())
                            .text_color(muted)
                            .child("used of"),
                    )
                    .child(
                        div()
                            .font_family(mono.clone())
                            .text_color(value_color)
                            .child(total.to_owned()),
                    )
                    .into_any_element()
            } else if ring.value == UNAVAILABLE_TEXT {
                div()
                    .font_family(mono.clone())
                    .text_size(px(12.0))
                    .text_color(value_color)
                    .child(ring.value.clone())
                    .into_any_element()
            } else {
                div()
                    .font_family(sans.clone())
                    .text_size(px(12.0))
                    .text_color(value_color)
                    .child(ring.value.clone())
                    .into_any_element()
            };
            let detail: Option<SharedString> = ring.detail.clone().map(Into::into);
            rows = rows.child(
                v_flex()
                    .id(ROW_IDS[index])
                    .test_support()
                    .aria_label(SharedString::from(label))
                    .relative()
                    .gap(tokens::SPACE_1)
                    .on_hover(move |hovered, window, cx| {
                        if let Some(pick) = &hover {
                            pick(hovered.then_some(index), window, cx);
                        }
                    })
                    .child(
                        h_flex()
                            .items_center()
                            .child(
                                div()
                                    .size(px(COLOR_DOT))
                                    .flex_shrink_0()
                                    .rounded_full()
                                    .bg(swatch),
                            )
                            .child(
                                div()
                                    .ml(tokens::SPACE_2)
                                    .w(px(name_width))
                                    .flex_shrink_0()
                                    .text_size(px(13.0))
                                    .whitespace_nowrap()
                                    .child(ring.kind.name()),
                            )
                            .child(div().ml(tokens::SPACE_3).child(value)),
                    )
                    .children(detail.map(|text| {
                        div()
                            .ml(px(COLOR_DOT) + tokens::SPACE_2)
                            .text_size(px(12.0))
                            .text_color(muted)
                            .child(text)
                    }))
                    .child(target),
            );
        }
        rows
    }
}

/// The diameter of the color dot of a legend row, in pixels.
const COLOR_DOT: f32 = 8.0;

#[expect(
    clippy::cast_precision_loss,
    reason = "a name length is far below 2^24"
)]
const fn count_f32(count: usize) -> f32 {
    count as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    const GB: u64 = 1_000_000_000;

    fn host() -> HostSnapshot {
        HostSnapshot {
            captured_at: SystemTime::UNIX_EPOCH,
            volume_name: None,
            disk_total: Measured::Value(512 * GB),
            disk_available: Measured::Value(256 * GB),
            disk_free: Measured::Value(200 * GB),
            pressure: Measured::Value(PressureLevel::Normal),
            memory_total: Measured::Value(32 * GB),
            swap_used: Measured::Value(GB),
            swap_total: Measured::Value(4 * GB),
            source: "test",
        }
    }

    fn lit(ring: &Ring) -> usize {
        dot_kinds(ring, None)
            .iter()
            .filter(|d| matches!(d, Dot::Lit | Dot::Head))
            .count()
    }

    #[test]
    fn lit_dots_rounds_and_keeps_the_edges() {
        assert_eq!(lit_dots(0, 100, 96), 0);
        assert_eq!(lit_dots(1, 1_000_000, 96), 1, "a tiny value shows one dot");
        assert_eq!(lit_dots(50, 100, 96), 48);
        assert_eq!(
            lit_dots(999_999, 1_000_000, 96),
            95,
            "never full below full"
        );
        assert_eq!(lit_dots(100, 100, 96), 96);
        assert_eq!(lit_dots(5, 0, 96), 0);
    }

    #[test]
    fn disk_ring_has_used_and_soft_parts() {
        let model = dial_model(&host());
        let RingState::Used { lit, soft } = model.rings[0].state else {
            panic!("disk ring is not a used ring")
        };
        assert_eq!(lit, 48);
        assert!(soft > 0 && lit + soft <= 96, "{soft}");
        assert!(
            model.rings[0]
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("Soft part"))
        );
        let kinds = dot_kinds(&model.rings[0], None);
        assert_eq!(kinds[lit - 1], Dot::Head);
        assert_eq!(kinds[lit], Dot::Soft);
        assert_eq!(kinds[lit + 1], Dot::Empty, "each second dot is soft");
    }

    #[test]
    fn no_soft_part_when_free_is_unknown() {
        let mut snapshot = host();
        snapshot.disk_free = Measured::Unavailable("x".into());
        let model = dial_model(&snapshot);
        assert!(matches!(
            model.rings[0].state,
            RingState::Used { soft: 0, .. }
        ));
        assert!(model.rings[0].detail.is_none());
    }

    #[test]
    fn unavailable_ring_draws_each_second_dot_and_a_dash() {
        let mut snapshot = host();
        snapshot.disk_total = Measured::Unavailable("no total".into());
        let model = dial_model(&snapshot);
        let ring = &model.rings[0];
        assert_eq!(ring.value, "\u{2014}");
        assert_eq!(ring.detail.as_deref(), Some("no total"));
        let kinds = dot_kinds(ring, None);
        assert_eq!(kinds.iter().filter(|d| **d == Dot::Empty).count(), 48);
        assert_eq!(kinds.iter().filter(|d| **d == Dot::Skip).count(), 48);
        assert!(!model.label().contains("0 B"), "{}", model.label());
    }

    #[test]
    fn swap_total_zero_has_no_lit_dot_and_says_so() {
        let mut snapshot = host();
        snapshot.swap_used = Measured::Value(0);
        snapshot.swap_total = Measured::Value(0);
        let model = dial_model(&snapshot);
        assert_eq!(lit(&model.rings[1]), 0);
        assert!(model.rings[1].value.contains("No swap space"));
        snapshot.swap_used = Measured::Value(5);
        let model = dial_model(&snapshot);
        assert_eq!(model.rings[1].state, RingState::Unavailable);
    }

    #[test]
    fn a_full_disk_lights_every_dot() {
        let mut snapshot = host();
        snapshot.disk_available = Measured::Value(0);
        snapshot.disk_free = Measured::Value(0);
        let model = dial_model(&snapshot);
        assert_eq!(lit(&model.rings[0]), 96);
    }

    #[test]
    fn pressure_sectors_have_a_gap_of_one_dot() {
        let bounds = sector_bounds(64);
        assert_eq!(bounds, [(0, 21), (22, 42), (43, 63)]);
        assert_eq!(pressure_sector(21, 64), None);
        assert_eq!(pressure_sector(63, 64), None);
        assert_eq!(pressure_sector(22, 64), Some(1));
    }

    #[test]
    fn pressure_ring_lights_the_current_sector_and_dims_the_lower_ones() {
        let mut snapshot = host();
        snapshot.pressure = Measured::Value(PressureLevel::Critical);
        let model = dial_model(&snapshot);
        let kinds = dot_kinds(&model.rings[2], None);
        assert_eq!(kinds[0], Dot::Dim);
        assert_eq!(kinds[30], Dot::Dim);
        assert_eq!(kinds[43], Dot::Lit);
        assert_eq!(kinds[62], Dot::Head);
        assert_eq!(kinds[21], Dot::Skip);
        let normal = dial_model(&host());
        let kinds = dot_kinds(&normal.rings[2], None);
        assert_eq!(kinds[20], Dot::Head);
        assert_eq!(kinds[30], Dot::Empty);
    }

    #[test]
    fn the_pick_follows_pressure_then_the_largest_share() {
        let mut snapshot = host();
        // Disk 50%, swap 25%: disk.
        assert_eq!(dial_model(&snapshot).picked, 0);
        snapshot.swap_used = Measured::Value(3 * GB);
        assert_eq!(dial_model(&snapshot).picked, 1);
        snapshot.pressure = Measured::Value(PressureLevel::Warning);
        assert_eq!(dial_model(&snapshot).picked, 2);
        // Only pressure is measured and normal: the pressure ring.
        snapshot.pressure = Measured::Value(PressureLevel::Normal);
        snapshot.disk_total = Measured::Unavailable("x".into());
        snapshot.swap_used = Measured::Unavailable("x".into());
        assert_eq!(dial_model(&snapshot).picked, 2);
        snapshot.pressure = Measured::Unavailable("x".into());
        assert_eq!(dial_model(&snapshot).picked, 0);
    }

    #[test]
    fn a_ring_without_capacity_or_share_does_not_win_the_pick() {
        let mut snapshot = host();
        // Swap has no capacity; disk is measured: disk wins, not ring 1.
        snapshot.swap_used = Measured::Value(0);
        snapshot.swap_total = Measured::Value(0);
        snapshot.disk_available = Measured::Value(512 * GB - GB);
        assert_eq!(dial_model(&snapshot).picked, 0);
        // Disk unavailable, swap with no capacity, pressure measured: pressure.
        snapshot.disk_total = Measured::Unavailable("x".into());
        assert_eq!(dial_model(&snapshot).picked, 2);
        // Pressure unavailable too: the first measured ring is swap (share 0).
        snapshot.pressure = Measured::Unavailable("x".into());
        assert_eq!(dial_model(&snapshot).picked, 1);
        // A swap with a share beats a disk with share 0.
        snapshot.disk_total = Measured::Value(512 * GB);
        snapshot.disk_available = Measured::Value(512 * GB);
        snapshot.swap_total = Measured::Value(4 * GB);
        snapshot.swap_used = Measured::Value(GB);
        assert_eq!(dial_model(&snapshot).picked, 1);
        // All shares are 0 and pressure is measured: pressure.
        snapshot.swap_used = Measured::Value(0);
        snapshot.pressure = Measured::Value(PressureLevel::Normal);
        assert_eq!(dial_model(&snapshot).picked, 2);
    }

    #[test]
    fn the_count_eases_from_the_old_to_the_new_value() {
        assert_eq!(eased_count(10, 50, 0.0), 10, "start");
        let middle: usize = eased_count(10, 50, 0.3);
        assert!(middle > 10 && middle < 50, "{middle}");
        assert_eq!(eased_count(10, 50, 1.0), 50, "end");
        assert_eq!(eased_count(10, 50, 2.0), 50, "past the end");
        assert_eq!(eased_count(7, 7, 0.4), 7, "equal values");
        let down: usize = eased_count(50, 10, 0.3);
        assert!(down < 50 && down > 10, "shrink {down}");
        assert_eq!(eased_count(50, 10, 0.0), 50);
        assert_eq!(eased_count(50, 10, 1.0), 10);
    }

    #[test]
    fn the_head_move_runs_for_the_front_ease_and_ends_at_the_target() {
        let t0: Instant = Instant::now();
        let mut head: HeadMove = HeadMove::default();
        head.observe([Some(10), Some(5), None], t0, true);
        assert_eq!(head.shown(t0), ([Some(10), Some(5), None], false), "first");
        head.observe([Some(40), Some(5), None], t0, true);
        let (mid, running) = head.shown(t0 + motion::FRONT_EASE / 4);
        assert!(running);
        assert!(mid[0].is_some_and(|v| v > 10 && v < 40), "{mid:?}");
        assert_eq!(mid[1], Some(5));
        let (end, running) = head.shown(t0 + motion::FRONT_EASE);
        assert_eq!((end[0], running), (Some(40), false));
        // Without transitions the count applies at once.
        head.observe([Some(20), Some(5), None], t0, false);
        assert_eq!(head.shown(t0), ([Some(20), Some(5), None], false));
    }

    #[test]
    fn lit_counts_replace_only_used_rings() {
        let model = dial_model(&host());
        let shown = with_lit_counts(&model, [Some(10), None, Some(3)]);
        assert_eq!(lit_of(&shown.rings[0]), Some(10));
        assert_eq!(lit_of(&shown.rings[1]), lit_of(&model.rings[1]));
        assert_eq!(shown.rings[2].state, model.rings[2].state);
    }

    #[test]
    fn the_center_follows_the_picked_ring() {
        let model = dial_model(&host());
        assert_eq!(model.rings[0].center_value, "256.0 GB");
        assert_eq!(model.rings[2].center_value, "Normal");
        assert_eq!(model.rings[1].center_caption, "Swap used");
    }

    #[test]
    fn the_sweep_scales_the_lit_count_and_ends_at_the_final_state() {
        let model = dial_model(&host());
        let full: usize = lit(&model.rings[0]);
        let half: usize = dot_kinds(&model.rings[0], Some(0.5))
            .iter()
            .filter(|d| matches!(d, Dot::Lit | Dot::Head))
            .count();
        assert!(half < full && half > 0, "{half} {full}");
        assert_eq!(
            dot_kinds(&model.rings[0], Some(1.0)),
            dot_kinds(&model.rings[0], None)
        );
        assert!(
            dot_kinds(&model.rings[0], Some(0.0))
                .iter()
                .all(|d| *d == Dot::Empty)
        );
    }

    #[test]
    fn the_rings_enter_one_after_the_other() {
        assert_eq!(ring_progress(0.0, 0, 3), 0.0);
        assert!(ring_progress(0.3, 0, 3) > ring_progress(0.3, 2, 3));
        assert!((ring_progress(1.0, 2, 3) - 1.0).abs() < 1e-6);
        assert_eq!(sweep_total(3), motion::SLOW + RING_STAGGER * 2);
    }

    #[test]
    fn the_first_dot_is_at_the_top_and_the_ring_runs_clockwise() {
        let (x, y) = dot_center(0, 96, 90.0);
        assert!(x.abs() < 1e-3 && (y + 90.0).abs() < 1e-3);
        let (x, _) = dot_center(24, 96, 90.0);
        assert!((x - 90.0).abs() < 1e-3, "a quarter turn is at the right");
    }
}
