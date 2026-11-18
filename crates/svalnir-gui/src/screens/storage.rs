//! The read-only Storage screen: the volume and the folder sizes of a scan.

use crate::{
    data::{
        model::{
            HostSnapshot, Loadable, Measured, PressureLevel, ScanEnd, ScanProgress, ScanState,
            ScanSummary, SizeMetric,
        },
        store::AppModel,
    },
    theme::{
        motion, palette,
        tokens::{self, Tokens, to_hsla},
    },
    ui::{
        action_button::{ActionButton, ButtonVariant},
        data_state::{format_age, format_bytes, used_capacity},
        entry::card_entry,
        legend::{Legend, LegendRow},
        pill::{StatusPill, Tone},
        provenance::ProvenanceLine,
        rolling::RollingNumber,
        segmented::SegmentedControl,
        stat_row::{StatItem, StatRow},
        surface::{Panel, Shell, ShellHeader},
        value::DisplayValue,
    },
    viz::{
        breakdown::{DEFAULT_SEGMENTS, Segment, breakdown},
        capacity_grid::CapacityGrid,
        cell_ring::{CellRing, STEPS},
        dial::sweep_total,
        led::{FillAxis, LedChart, LedField, LedHead, LedSegment, TileLabel},
        storage_layouts::{
            BAND_ROWS, CHART_ROWS, ChartItem, STRIP_ROWS, StorageLayout, apply_focus,
            bytes_per_cell, chart_label, layout_field, scale_caption,
        },
        treemap::CellRect,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, FontWeight, Hsla, IntoElement, ParentElement, Render, Role,
    SharedString, Styled, TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, Disableable as _, IconName, Sizable as _,
        button::{Button, ButtonVariants as _},
        h_flex,
        skeleton::Skeleton,
        v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

/// The time source of the animations; a test replaces it.
#[derive(Clone)]
pub struct Clock(Rc<dyn Fn() -> Instant>);

impl Clock {
    /// The wall clock.
    #[must_use]
    pub fn system() -> Self {
        Self(Rc::new(Instant::now))
    }

    /// A clock that reads `now`.
    pub fn new(now: impl Fn() -> Instant + 'static) -> Self {
        Self(Rc::new(now))
    }

    fn now(&self) -> Instant {
        (self.0)()
    }
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}

/// What a fill-in belongs to: a new result, layout, or metric restarts it.
#[derive(Debug, Clone, PartialEq)]
struct FillKey {
    finished_at: SystemTime,
    root: PathBuf,
    layout: StorageLayout,
    metric: SizeMetric,
}

/// The cells of the head of the scan front.
const HEAD_COLUMNS: u16 = 3;

/// Opens the folder of a chart item.
type OpenFn = Rc<dyn Fn(usize, &mut gpui_kit::App)>;

/// The width that the viewport gives to the cards, less than the viewport.
const CHROME_WIDTH: f32 = 340.0;
/// The longest path text before the middle is cut.
const MAX_PATH_CHARS: usize = 56;

/// Cuts the middle of a long text: `start…end`.
#[must_use]
pub fn middle_ellipsis(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max || max < 3 {
        return text.to_owned();
    }
    let head: usize = (max - 1).div_ceil(2);
    let tail: usize = max - 1 - head;
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{start}…{end}")
}

/// The name that the scan button shows for `root`.
fn last_component(root: &Path) -> String {
    root.file_name().map_or_else(
        || root.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// The Storage screen entity.
#[derive(Debug)]
pub struct StorageScreen {
    model: Entity<AppModel>,
    metric: SizeMetric,
    layout: StorageLayout,
    focused: Option<usize>,
    path_stack: Vec<PathBuf>,
    /// The size of the folder in the scan, as the parent level measured it.
    scale: Option<u64>,
    clock: Clock,
    fill_key: Option<FillKey>,
    fill_start: Instant,
    last_fill: f32,
    front_from: u64,
    front_target: u64,
    front_at: Instant,
    roll_total: Entity<RollingNumber>,
    roll_used: Entity<RollingNumber>,
    activation: u64,
    phase: f32,
    twinkle: Option<gpui_kit::Task<()>>,
    last_render: Instant,
}

impl StorageScreen {
    /// Creates the screen and observes the model.
    pub fn new(model: Entity<AppModel>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            metric: SizeMetric::Allocated,
            layout: StorageLayout::Tiles,
            focused: None,
            path_stack: Vec::new(),
            scale: None,
            clock: Clock::system(),
            fill_key: None,
            fill_start: Instant::now(),
            last_fill: 1.0,
            front_from: 0,
            front_target: 0,
            front_at: Instant::now(),
            roll_total: RollingNumber::new("scan-total-roll", cx),
            roll_used: RollingNumber::new("volume-value-roll", cx),
            activation: 1,
            phase: 0.0,
            twinkle: None,
            last_render: Instant::now(),
        }
    }

    /// Marks a new activation of the screen: the cards enter again.
    pub fn activate(&mut self, cx: &mut Context<Self>) {
        self.activation += 1;
        cx.notify();
    }

    /// Runs the twinkle timer at about 12 Hz while the screen renders; the
    /// timer ends when the screen stops rendering.
    fn start_twinkle(&mut self, cx: &mut Context<Self>) {
        if self.twinkle.is_some() {
            return;
        }
        self.twinkle = Some(cx.spawn(async move |this, cx: &mut gpui_kit::AsyncApp| {
            loop {
                cx.background_executor().timer(motion::TWINKLE_TICK).await;
                let alive: bool = this
                    .update(cx, |screen, cx| {
                        if screen.last_render.elapsed() > motion::TWINKLE_TICK * 6 {
                            screen.twinkle = None;
                            return false;
                        }
                        screen.phase = (screen.phase + motion::TWINKLE_TICK.as_secs_f32()) % 600.0;
                        cx.notify();
                        true
                    })
                    .unwrap_or(false);
                if !alive {
                    break;
                }
            }
        }));
    }

    /// Replaces the time source of the animations.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The fill of the last segment of the Done chart at the latest render.
    #[must_use]
    pub const fn chart_fill(&self) -> f32 {
        self.last_fill
    }

    fn gate(&self, window: &Window, cx: &Context<Self>) -> motion::Gate {
        let normal: bool = !matches!(
            &self.model.read(cx).host,
            Loadable::Ready(h) | Loadable::Stale(h)
                if matches!(h.pressure, Measured::Value(p) if p != PressureLevel::Normal)
        );
        motion::Gate {
            reduce_motion: cx.reduce_motion(),
            window_active: window.is_window_active(),
            pressure_normal: normal,
        }
    }

    /// The root of the next scan: the top of the path stack, else the default.
    fn root(&self, cx: &Context<Self>) -> Option<PathBuf> {
        self.path_stack
            .last()
            .cloned()
            .or_else(|| self.model.read(cx).default_scan_root())
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if let Some(root) = self.root(cx) {
            self.focused = None;
            self.model
                .update(cx, |model, cx| model.start_scan(&root, cx));
        }
    }

    /// Opens the folder `path` below the current root and scans it.
    pub fn push(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        self.push_with_scale(path, None, cx);
    }

    /// Like [`Self::push`]; `expected` is the size that the parent level
    /// measured for the folder, in the shown metric.
    pub fn push_with_scale(
        &mut self,
        path: PathBuf,
        expected: Option<u64>,
        cx: &mut Context<Self>,
    ) {
        self.path_stack.push(path);
        self.scale = expected;
        self.start(cx);
    }

    /// Pops to `level` (0 is the default root) and scans that folder.
    pub fn pop_to(&mut self, level: usize, cx: &mut Context<Self>) {
        self.path_stack.truncate(level);
        self.scale = None;
        self.start(cx);
    }
}

/// The content width from which the ring has its legend at the right.
const RING_SIDE_WIDTH: f32 = 640.0;

fn caption(id: &'static str, text: impl Into<SharedString>, tokens: &Tokens) -> AnyElement {
    let text: SharedString = text.into();
    div()
        .id(id)
        .test_support()
        .aria_label(text.clone())
        .text_size(px(12.0))
        .text_color(to_hsla(tokens.muted_foreground))
        .child(text)
        .into_any_element()
}

fn card(header: ShellHeader, body: impl IntoElement) -> AnyElement {
    Shell::new()
        .child(header)
        .child(Panel::new().child(v_flex().gap(tokens::SPACE_3).child(body)))
        .into_any_element()
}

fn volume_card(
    host: &Loadable<HostSnapshot>,
    roll: &Entity<RollingNumber>,
    tokens: &Tokens,
    width: f32,
    dark: bool,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::HardDrive, "Startup volume");
    let body: AnyElement = match host {
        Loadable::Loading => Skeleton::new().w(px(140.0)).h(px(30.0)).into_any_element(),
        Loadable::Unavailable(reason) => v_flex()
            .gap(tokens::SPACE_2)
            .child(DisplayValue::unavailable(reason.clone()).id("volume-value"))
            .child(caption(
                "volume-unavailable-note",
                "Nothing is shown as zero.",
                tokens,
            ))
            .into_any_element(),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            let stale: bool = matches!(host, Loadable::Stale(_));
            if let Some(name) = &snapshot.volume_name {
                header = header.subtitle(name.clone());
            }
            let used: Measured<u64> = used_capacity(&snapshot.disk_total, &snapshot.disk_available);
            let value: DisplayValue = match (&used, &snapshot.disk_total) {
                (Measured::Value(used), Measured::Value(total)) => {
                    let (used_text, used_unit) = format_bytes(*used);
                    let (total_text, total_unit) = format_bytes(*total);
                    DisplayValue::new(used_text, used_unit)
                        .id("volume-value")
                        .rolling(roll.clone())
                        .muted(stale)
                        .context(format!("used of {total_text} {total_unit}"))
                }
                (Measured::Unavailable(reason), _) | (_, Measured::Unavailable(reason)) => {
                    DisplayValue::unavailable(reason.clone()).id("volume-value")
                }
            };
            v_flex()
                .gap(tokens::SPACE_3)
                .child(value)
                .child(volume_strip(&used, &snapshot.disk_total, width, dark))
                .children(stale.then(|| {
                    caption(
                        "volume-stale",
                        format_age(
                            SystemTime::now()
                                .duration_since(snapshot.captured_at)
                                .unwrap_or_default(),
                        ),
                        tokens,
                    )
                }))
                .child(
                    ProvenanceLine::new(
                        snapshot.source,
                        snapshot.captured_at,
                        "startup data volume",
                    )
                    .id("volume-provenance"),
                )
                .into_any_element()
        }
    };
    card(header, body)
}

/// The LED strip of the volume: used space, then the free region.
fn volume_strip(used: &Measured<u64>, total: &Measured<u64>, width: f32, dark: bool) -> AnyElement {
    let (Measured::Value(used), Measured::Value(total)) = (used, total) else {
        return CapacityGrid::new(used.clone(), total.clone())
            .id("volume-grid")
            .into_any_element();
    };
    let items: Vec<ChartItem> = vec![ChartItem {
        label: "Used".to_owned(),
        bytes: *used,
        color: Hsla::from(palette::category_color(0, dark)),
        activatable: false,
        inert: false,
    }];
    let free: u64 = total.saturating_sub(*used);
    let (field, labels) = layout_field(
        &items,
        *used,
        Some(free),
        StorageLayout::Band,
        lattice_columns(width),
        STRIP_ROWS,
    );
    let (used_text, used_unit) = format_bytes(*used);
    let (total_text, total_unit) = format_bytes(*total);
    LedChart::new(
        field,
        labels,
        "volume-grid",
        format!("Used {used_text} {used_unit} of {total_text} {total_unit}"),
    )
    .into_any_element()
}

/// The columns of a chart that fits `width` pixels.
fn lattice_columns(width: f32) -> u16 {
    let columns: f32 = (width / 6.0).clamp(20.0, 400.0).floor();
    (0..=400_u16)
        .rev()
        .find(|&n| f32::from(n) <= columns)
        .unwrap_or(20)
}

fn size_value(bytes: u64, id: &'static str, roll: &Entity<RollingNumber>) -> DisplayValue {
    let (text, unit) = format_bytes(bytes);
    DisplayValue::new(text, unit).id(id).rolling(roll.clone())
}

fn done_footer(summary: &ScanSummary) -> String {
    let elapsed: String = summary.elapsed.map_or_else(
        || "an unknown time".to_owned(),
        |e| format!("{:.1} s", e.as_secs_f64()),
    );
    let age: String = format_age(
        SystemTime::now()
            .duration_since(summary.finished_at)
            .unwrap_or_default(),
    );
    format!(
        "Scanned {} entries in {elapsed} · {age}",
        summary.entries_examined
    )
}

/// The band of a running scan. `shown` is the eased front and never passes
/// `measured`; each block is scaled by `shown / measured`. With a `scale` the
/// band spans it and the rest is lattice; the second value tells that the
/// measurement exceeds the scale.
fn running_field(
    children: &[crate::data::model::ChildSize],
    metric: SizeMetric,
    shown: u64,
    measured: u64,
    scale: Option<u64>,
    width: f32,
    dark: bool,
) -> (LedField, bool) {
    let columns: u16 = lattice_columns(width);
    let larger: bool = scale.is_some_and(|s| s > 0 && shown > s);
    let ratio = |bytes: u64| -> u64 {
        if measured == 0 {
            return 0;
        }
        u64::try_from(u128::from(bytes) * u128::from(shown.min(measured)) / u128::from(measured))
            .unwrap_or(u64::MAX)
    };
    let items: Vec<ChartItem> = children
        .iter()
        .enumerate()
        .map(|(index, child)| ChartItem {
            label: child.name.clone(),
            bytes: ratio(child.size(metric)),
            color: Hsla::from(palette::category_color(index, dark)),
            activatable: false,
            inert: false,
        })
        .filter(|item| item.bytes > 0)
        .collect();
    let total: u64 = items.iter().map(|i| i.bytes).fold(0, u64::saturating_add);
    let scale: Option<u64> = scale.filter(|s| *s > 0);
    let mut field: LedField = if items.is_empty() || total == 0 {
        LedField {
            columns,
            rows: BAND_ROWS,
            segments: Vec::new(),
            free: None,
            head: None,
            phase: None,
        }
    } else {
        let free: Option<u64> = scale.map(|s| s.saturating_sub(total)).filter(|f| *f > 0);
        layout_field(&items, total, free, StorageLayout::Band, columns, BAND_ROWS).0
    };
    field.free = None;
    let color: Hsla = field.segments.last().map_or_else(
        || Hsla::from(palette::neutral_color(dark)),
        |segment: &LedSegment| segment.color,
    );
    let x: u16 = match scale {
        Some(_) => field
            .segments
            .iter()
            .rfind(|segment| !segment.rect.is_empty())
            .map_or(0, |segment| segment.rect.x + segment.rect.w + 1),
        None => field.columns.saturating_sub(HEAD_COLUMNS),
    }
    .min(field.columns.saturating_sub(HEAD_COLUMNS));
    field.head = Some(LedHead {
        rect: CellRect::new(x, 0, HEAD_COLUMNS.min(field.columns), field.rows),
        color,
    });
    (field, larger)
}

impl StorageScreen {
    /// Sets the fill of each segment of the Done chart: 0 to 1 in palette
    /// order, then idle. Reduce Motion applies the full fill at once.
    fn apply_fill_in(
        &mut self,
        field: &mut LedField,
        summary: &ScanSummary,
        window: &Window,
        cx: &Context<Self>,
    ) {
        let key = FillKey {
            finished_at: summary.finished_at,
            root: summary.root.clone(),
            layout: self.layout,
            metric: self.metric,
        };
        let now: Instant = self.clock.now();
        if self.fill_key.as_ref() != Some(&key) {
            self.fill_key = Some(key);
            self.fill_start = now;
        }
        let gate: motion::Gate = self.gate(window, cx);
        let elapsed: Duration = now.saturating_duration_since(self.fill_start);
        let count: usize = field.segments.len();
        let running: bool = gate.transitions() && elapsed < motion::fill_in_total(count);
        let axis = if self.layout == StorageLayout::Band {
            FillAxis::Horizontal
        } else {
            FillAxis::Vertical
        };
        for (index, segment) in field.segments.iter_mut().enumerate() {
            segment.axis = axis;
            segment.fill = if gate.transitions() {
                if running {
                    motion::fill_in(elapsed, index)
                } else {
                    1.0
                }
            } else {
                1.0
            };
        }
        self.last_fill = field.segments.last().map_or(1.0, |s| s.fill);
        if running {
            window.request_animation_frame();
        }
    }

    /// The progress of the entry sweep of the ring layout, or `None` for the
    /// final state (Reduce Motion, or the sweep is over).
    fn ring_sweep(
        &mut self,
        summary: &ScanSummary,
        window: &Window,
        cx: &Context<Self>,
    ) -> Option<f32> {
        let key = FillKey {
            finished_at: summary.finished_at,
            root: summary.root.clone(),
            layout: self.layout,
            metric: self.metric,
        };
        let now: Instant = self.clock.now();
        if self.fill_key.as_ref() != Some(&key) {
            self.fill_key = Some(key);
            self.fill_start = now;
        }
        if !self.gate(window, cx).transitions() {
            return None;
        }
        let total: Duration = sweep_total(4);
        let elapsed: Duration = now.saturating_duration_since(self.fill_start);
        if elapsed >= total {
            return None;
        }
        window.request_animation_frame();
        Some(elapsed.as_secs_f32() / total.as_secs_f32())
    }

    fn metric_control(&self, cx: &mut Context<Self>) -> AnyElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let metrics: [(&'static str, &'static str, SizeMetric); 2] = [
            ("metric-allocated", "Allocated", SizeMetric::Allocated),
            ("metric-logical", "Logical", SizeMetric::Logical),
        ];
        let active: usize = metrics.iter().position(|m| m.2 == self.metric).unwrap_or(0);
        let entity = cx.entity();
        SegmentedControl::new(
            "metric-control",
            metrics
                .iter()
                .map(|m| (SharedString::from(m.0), SharedString::from(m.1)))
                .collect(),
            active,
        )
        .track(to_hsla(tokens.surface_inset))
        .on_change(move |index, _, cx| {
            if let Some(m) = metrics.get(index) {
                entity.update(cx, |screen, cx| {
                    screen.metric = m.2;
                    cx.notify();
                });
            }
        })
        .into_any_element()
    }

    /// Selects the layout of the folder chart.
    pub fn set_layout(&mut self, layout: StorageLayout, cx: &mut Context<Self>) {
        if self.layout != layout {
            self.layout = layout;
            cx.notify();
        }
    }

    fn layout_control(&self, cx: &mut Context<Self>) -> AnyElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let layouts: [(&'static str, StorageLayout); 4] = [
            ("layout-tiles", StorageLayout::Tiles),
            ("layout-band", StorageLayout::Band),
            ("layout-columns", StorageLayout::Columns),
            ("layout-ring", StorageLayout::Ring),
        ];
        let active: usize = layouts.iter().position(|l| l.1 == self.layout).unwrap_or(0);
        let entity = cx.entity();
        SegmentedControl::new(
            "layout-control",
            layouts
                .iter()
                .map(|l| (SharedString::from(l.0), SharedString::from(l.1.name())))
                .collect(),
            active,
        )
        .track(to_hsla(tokens.surface_inset))
        .on_change(move |index, _, cx| {
            if let Some(l) = layouts.get(index) {
                entity.update(cx, |screen, cx| {
                    screen.layout = l.1;
                    cx.notify();
                });
            }
        })
        .into_any_element()
    }

    fn breadcrumb(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.path_stack.is_empty() {
            return None;
        }
        let mut row = h_flex().gap(tokens::SPACE_1).items_center().flex_wrap();
        let default: String = self
            .model
            .read(cx)
            .default_scan_root()
            .map_or_else(|| "Root".to_owned(), |p| last_component(&p));
        let mut levels: Vec<(usize, String)> = vec![(0, default)];
        levels.extend(
            self.path_stack
                .iter()
                .enumerate()
                .map(|(i, p)| (i + 1, last_component(p))),
        );
        let last: usize = self.path_stack.len();
        for (level, name) in levels {
            if level > 0 {
                row = row.child("›");
            }
            row = row.child(
                Button::new(SharedString::from(format!("crumb-{level}")))
                    .ghost()
                    .small()
                    .label(name)
                    .disabled(level == last)
                    .on_click(cx.listener(move |screen, _, _, cx| screen.pop_to(level, cx))),
            );
        }
        Some(row.into_any_element())
    }

    fn idle_body(root: &Path, cx: &mut Context<Self>, id: &'static str) -> AnyElement {
        let name: String = last_component(root);
        v_flex()
            .gap(tokens::SPACE_3)
            .child(div().id(id).child(format!(
                "Measure the folders of {}. The scan reads sizes only and changes nothing.",
                root.display()
            )))
            .child(
                h_flex().child(
                    ActionButton::new("scan-start", format!("Scan {name}"))
                        .variant(ButtonVariant::Primary)
                        .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                ),
            )
            .into_any_element()
    }

    /// The running view: the total, the path, and the band that fills.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one build of the running view"
    )]
    fn running_body(
        &mut self,
        progress: &ScanProgress,
        started: Instant,
        mono: &SharedString,
        width: f32,
        dark: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
        tokens: &Tokens,
    ) -> AnyElement {
        let metric: SizeMetric = self.metric;
        let measured: u64 = match metric {
            SizeMetric::Allocated => progress.allocated,
            SizeMetric::Logical => progress.logical,
        };
        let gate: motion::Gate = self.gate(window, cx);
        let now: Instant = self.clock.now();
        if self.front_target != measured {
            self.front_from = if gate.transitions() {
                motion::eased_front(
                    self.front_from,
                    self.front_target,
                    now.saturating_duration_since(self.front_at),
                )
            } else {
                measured
            };
            self.front_target = measured;
            self.front_at = now;
        }
        let shown: u64 = if gate.transitions() {
            motion::eased_front(
                self.front_from,
                self.front_target,
                now.saturating_duration_since(self.front_at),
            )
        } else {
            measured
        };
        if shown < measured {
            window.request_animation_frame();
        }
        let scale: Option<u64> = self.scale.or_else(|| {
            if !self.path_stack.is_empty() {
                return None;
            }
            match &self.model.read(cx).host {
                Loadable::Ready(h) | Loadable::Stale(h) => {
                    match used_capacity(&h.disk_total, &h.disk_available) {
                        Measured::Value(used) => Some(used),
                        Measured::Unavailable(_) => None,
                    }
                }
                _ => None,
            }
        });
        let (field, larger): (LedField, bool) = running_field(
            &progress.children,
            metric,
            shown,
            measured,
            scale,
            width,
            dark,
        );
        let path: String = progress
            .current_path
            .as_ref()
            .map_or_else(String::new, |p| {
                middle_ellipsis(&p.display().to_string(), MAX_PATH_CHARS)
            });
        let label: String = format!("Scanning, {} entries read", progress.entries);
        v_flex()
            .gap(tokens::SPACE_3)
            .child(
                h_flex()
                    .items_start()
                    .justify_between()
                    .child(size_value(shown, "scan-running-total", &self.roll_total))
                    .child(
                        v_flex()
                            .items_end()
                            .child(caption(
                                "scan-running-entries",
                                format!("{} entries", progress.entries),
                                tokens,
                            ))
                            .child(
                                div()
                                    .id("scan-running-elapsed")
                                    .font_family(mono.clone())
                                    .text_size(px(12.0))
                                    .child(format!("{} s", started.elapsed().as_secs())),
                            ),
                    ),
            )
            .child(
                h_flex().gap(tokens::SPACE_2).child("Scanning").child(
                    div()
                        .id("scan-running-path")
                        .font_family(mono.clone())
                        .text_size(px(12.0))
                        .text_color(to_hsla(tokens.muted_foreground))
                        .child(path),
                ),
            )
            .child(LedChart::new(field, Vec::new(), "scan-band", label))
            .children(larger.then(|| {
                caption(
                    "scan-larger",
                    "Larger than the earlier measurement.",
                    tokens,
                )
            }))
            .child(
                h_flex().child(
                    ActionButton::new("scan-cancel", "Cancel").on_click(cx.listener(
                        |screen, _, _, cx| {
                            screen.model.update(cx, |model, _| model.cancel_scan());
                        },
                    )),
                ),
            )
            .into_any_element()
    }

    #[expect(clippy::too_many_lines, reason = "one build of the done view")]
    #[expect(clippy::too_many_arguments, reason = "the render state of one screen")]
    fn done_body(
        &mut self,
        summary: &Arc<ScanSummary>,
        width: f32,
        dark: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
        tokens: &Tokens,
        metric_caption: AnyElement,
    ) -> AnyElement {
        let segments: Vec<Segment> = breakdown(&summary.children, self.metric, DEFAULT_SEGMENTS);
        let mut color_index: usize = 0;
        let mut items: Vec<ChartItem> = segments
            .iter()
            .map(|segment| {
                let color: Hsla = if segment.is_other {
                    Hsla::from(palette::neutral_color(dark))
                } else {
                    let c = Hsla::from(palette::category_color(color_index, dark));
                    color_index += 1;
                    c
                };
                ChartItem {
                    label: segment.label.clone(),
                    bytes: segment.bytes,
                    color,
                    activatable: segment
                        .source_index
                        .is_some_and(|i| summary.children[i].is_directory),
                    inert: false,
                }
            })
            .collect();
        // Free space and "Not scanned" only for the default root, with a
        // measured volume.
        let mut free_bytes: Option<u64> = None;
        let at_default_root: bool =
            self.model.read(cx).default_scan_root().as_deref() == Some(summary.root.as_path());
        if at_default_root && self.path_stack.is_empty() {
            let host: Loadable<HostSnapshot> = self.model.read(cx).host.clone();
            if let Loadable::Ready(snapshot) | Loadable::Stale(snapshot) = host
                && let (Measured::Value(total), Measured::Value(available)) =
                    (&snapshot.disk_total, &snapshot.disk_available)
            {
                free_bytes = Some(*available);
                let used: u64 = total.saturating_sub(*available);
                let unscanned: u64 = used.saturating_sub(summary.total(self.metric));
                if unscanned > 0 {
                    items.push(ChartItem {
                        label: "Not scanned".to_owned(),
                        bytes: unscanned,
                        color: Hsla::from(palette::neutral_color(dark)),
                        activatable: false,
                        inert: true,
                    });
                }
            }
        }
        let rows: Vec<LegendRow> = items
            .iter()
            .map(|item| {
                let (text, unit) = format_bytes(item.bytes);
                LegendRow {
                    name: item.label.clone().into(),
                    size: format!("{text} {unit}").into(),
                    color: item.color,
                    activatable: item.activatable,
                }
            })
            .collect();
        let this: Entity<Self> = cx.entity();
        let ring_this: Entity<Self> = this.clone();
        let select_this: Entity<Self> = this.clone();
        let select_metric: SizeMetric = self.metric;
        let select_summary: Arc<ScanSummary> = Arc::clone(summary);
        let select_segments: Vec<Segment> = segments.clone();
        let open: OpenFn = Rc::new(move |index, app| {
            let Some(segment) = select_segments.get(index) else {
                return;
            };
            let Some(child) = segment
                .source_index
                .and_then(|i| select_summary.children.get(i))
            else {
                return;
            };
            if child.is_directory {
                let path: PathBuf = child.path.clone();
                let expected: u64 = child.size(select_metric);
                select_this.update(app, |screen, cx| {
                    screen.push_with_scale(path, Some(expected), cx);
                });
            }
        });
        let legend_open = Rc::clone(&open);
        // From 640 px of content the ring has its legend at the right.
        let side_by_side: bool = self.layout == StorageLayout::Ring && width >= RING_SIDE_WIDTH;
        let legend_width: f32 = if side_by_side { 0.0 } else { width };
        let legend: Legend = Legend::new(rows, legend_width, "storage-legend")
            .on_select(move |index, _, app| legend_open(index, app))
            .on_hover(move |index, _, app| {
                this.update(app, |screen, cx| {
                    if screen.focused != index {
                        screen.focused = index;
                        cx.notify();
                    }
                });
            });
        let total_items: u64 = items.iter().map(|i| i.bytes).fold(0, u64::saturating_add);
        let chart_rows: u16 = if self.layout == StorageLayout::Band {
            BAND_ROWS
        } else {
            CHART_ROWS
        };
        let chart: AnyElement = if total_items == 0 {
            self.twinkle = None;
            caption("storage-band-scale", scale_caption(0, 0), tokens)
        } else if self.layout == StorageLayout::Ring {
            // The ring has no idle field, so the twinkle timer stops.
            self.twinkle = None;
            let sweep: Option<f32> = self.ring_sweep(summary, window, cx);
            let label: String =
                chart_label(self.layout, &summary.root.display().to_string(), &items);
            let chart_open = Rc::clone(&open);
            let (used_text, used_unit) = format_bytes(total_items);
            // Round up: a step of a chart that has bytes is not 0 B.
            let step_bytes: u64 = total_items
                .saturating_add(free_bytes.unwrap_or(0))
                .div_ceil(u64::try_from(STEPS).unwrap_or(1).max(1));
            let (step_text, step_unit) = format_bytes(step_bytes);
            v_flex()
                .gap(tokens::SPACE_2)
                .child(
                    CellRing::new(
                        items.clone(),
                        free_bytes,
                        "storage-band",
                        label,
                        (format!("{used_text} {used_unit}"), "used".to_owned()),
                    )
                    .focus(self.focused)
                    .sweep(sweep)
                    .on_hover(move |index, _, app| {
                        ring_this.update(app, |screen, cx| {
                            if screen.focused != index {
                                screen.focused = index;
                                cx.notify();
                            }
                        });
                    })
                    .on_select(move |index, _, app| chart_open(index, app)),
                )
                .child(caption(
                    "storage-band-scale",
                    format!("1 step = {step_text} {step_unit}"),
                    tokens,
                ))
                .into_any_element()
        } else {
            let (mut field, labels): (LedField, Vec<TileLabel>) = layout_field(
                &items,
                total_items,
                free_bytes,
                self.layout,
                lattice_columns(width),
                chart_rows,
            );
            let per_cell: u64 = bytes_per_cell(&items, &field);
            apply_focus(&mut field, self.focused);
            self.apply_fill_in(&mut field, summary, window, cx);
            if self.gate(window, cx).continuous() {
                field.phase = Some(self.phase);
                self.start_twinkle(cx);
            } else {
                self.twinkle = None;
            }
            let label: String =
                chart_label(self.layout, &summary.root.display().to_string(), &items);
            let chart_open = Rc::clone(&open);
            v_flex()
                .gap(tokens::SPACE_2)
                .child(
                    LedChart::new(field, labels, "storage-band", label)
                        .on_select(move |index, _, app| chart_open(index, app)),
                )
                .child(caption(
                    "storage-band-scale",
                    scale_caption(per_cell, total_items),
                    tokens,
                ))
                .into_any_element()
        };
        let mut value_row = h_flex()
            .items_center()
            .gap(tokens::SPACE_3)
            .child(size_value(
                summary.total(self.metric),
                "scan-total",
                &self.roll_total,
            ));
        let mut notes = v_flex().gap(tokens::SPACE_1);
        if summary.ended == ScanEnd::Cancelled {
            value_row =
                value_row.child(StatusPill::new("Cancelled", Tone::Neutral).id("scan-pill"));
            notes = notes.child(caption(
                "scan-cancelled-note",
                "The scan stopped before the end. The sizes cover the part that it read.",
                tokens,
            ));
        } else if !summary.complete {
            value_row = value_row.child(StatusPill::new("Partial", Tone::Warning).id("scan-pill"));
        }
        if !summary.complete {
            for (index, gap) in summary.gaps.iter().enumerate() {
                notes = notes.child(
                    div()
                        .id(SharedString::from(format!("scan-gap-{index}")))
                        .text_size(px(12.0))
                        .child(format!("{} × {}", gap.cause_text, gap.count)),
                );
            }
            if summary.ended != ScanEnd::Cancelled {
                notes = notes.child(caption(
                    "scan-partial-note",
                    "The total covers only what the scan could read.",
                    tokens,
                ));
            }
        }
        // The metric, its value, and the causes of a gap form one group;
        // SPACE_4 separates the group from the chart.
        let head = v_flex()
            .gap(tokens::SPACE_2)
            .mb(tokens::SPACE_1)
            .child(
                v_flex()
                    .gap(tokens::SPACE_1)
                    .child(metric_caption)
                    .child(value_row),
            )
            .child(notes);
        let mut col = v_flex().gap(tokens::SPACE_3).child(head);
        col = col.children(self.breadcrumb(cx));
        if side_by_side && total_items > 0 {
            col = col.child(
                h_flex()
                    .items_center()
                    .gap(tokens::SPACE_6)
                    .child(chart)
                    .child(div().flex_1().min_w(px(0.0)).child(legend)),
            );
        } else {
            col = col.child(chart).child(legend);
        }
        let (scanned, scanned_unit) = format_bytes(summary.total(self.metric));
        let mut stats: StatRow = StatRow::new("storage-stat-").item(
            StatItem::new("scanned", "Scanned", Some(scanned), to_hsla(tokens.brand))
                .suffix(scanned_unit),
        );
        if let Some(free) = free_bytes {
            let (text, unit) = format_bytes(free);
            stats = stats.item(
                StatItem::new("free", "Free", Some(text), to_hsla(tokens.muted_foreground))
                    .suffix(unit),
            );
        }
        if !summary.gaps.is_empty() {
            let causes: usize = summary.gaps.len();
            stats = stats.item(
                StatItem::new(
                    "unread",
                    "Not read",
                    Some(causes.to_string()),
                    to_hsla(tokens.warning),
                )
                .suffix(if causes == 1 { "cause" } else { "causes" }),
            );
        }
        col = col.child(stats);
        col.child(caption("scan-footer", done_footer(summary), tokens))
            .child(
                h_flex().child(
                    ActionButton::new("scan-rescan", "Rescan")
                        .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                ),
            )
            .into_any_element()
    }
}

impl Render for StorageScreen {
    #[expect(clippy::too_many_lines, reason = "one build of the screen")]
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dark: bool = cx.theme().is_dark();
        let tokens: &Tokens = Tokens::for_dark(dark);
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let width: f32 = (f32::from(window.viewport_size().width) - CHROME_WIDTH).max(0.0);
        let (host, scan, notice): (Loadable<HostSnapshot>, ScanState, Option<String>) = {
            let model: &AppModel = self.model.read(cx);
            (
                model.host.clone(),
                model.scan.clone(),
                model.scan_notice.clone(),
            )
        };
        let root: Option<PathBuf> = self.root(cx);
        let shown_root: String = match &scan {
            ScanState::Running { root, .. } | ScanState::Failed { root, .. } => {
                root.display().to_string()
            }
            ScanState::Done(summary) => summary.root.display().to_string(),
            ScanState::Idle => root
                .as_ref()
                .map_or_else(|| "no folder".to_owned(), |p| p.display().to_string()),
        };
        let crumb: Option<AnyElement> = match &scan {
            ScanState::Running { .. } | ScanState::Failed { .. } => self.breadcrumb(cx),
            ScanState::Idle | ScanState::Done(_) => None,
        };
        self.last_render = Instant::now();
        if !matches!(scan, ScanState::Done(_)) {
            self.twinkle = None;
        }
        if !matches!(scan, ScanState::Running { .. }) {
            self.front_from = 0;
            self.front_target = 0;
        }
        let body: AnyElement = match &scan {
            ScanState::Idle => match &root {
                Some(root) => Self::idle_body(root, cx, "scan-idle"),
                None => caption("scan-no-root", "No folder is available to scan.", tokens),
            },
            ScanState::Running {
                progress, started, ..
            } => self.running_body(progress, *started, &mono, width, dark, window, cx, tokens),
            ScanState::Done(summary) => {
                let metric_caption: AnyElement =
                    caption("scan-metric", self.metric.caption(), tokens);
                self.done_body(summary, width, dark, window, cx, tokens, metric_caption)
            }
            ScanState::Failed { reason, .. } => v_flex()
                .gap(tokens::SPACE_3)
                .child(
                    div()
                        .id("scan-failed")
                        .test_support()
                        .aria_label(reason.clone())
                        .child(reason.clone()),
                )
                .child(
                    h_flex().child(
                        ActionButton::new("scan-retry", "Try again")
                            .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                    ),
                )
                .into_any_element(),
        };
        let header: ShellHeader = ShellHeader::new(IconName::Folder, "Folder sizes")
            .subtitle(shown_root)
            .aside(
                h_flex()
                    .gap(tokens::SPACE_3)
                    .child(self.layout_control(cx))
                    .child(self.metric_control(cx)),
            );
        let metric_caption: Option<AnyElement> = (!matches!(scan, ScanState::Done(_)))
            .then(|| caption("scan-metric", self.metric.caption(), tokens));
        let reduce: bool = cx.reduce_motion();
        let title: &'static str = "Storage";
        div()
            .flex()
            .flex_col()
            .gap(tokens::GRID_GAP)
            .child(
                div()
                    .id("screen-title")
                    .role(Role::Heading)
                    .test_support()
                    .aria_label(title)
                    .text_size(px(24.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(card_entry(
                volume_card(&host, &self.roll_used, tokens, width, dark),
                0,
                self.activation,
                reduce,
            ))
            .child(card_entry(
                card(
                    header,
                    v_flex()
                        .gap(tokens::SPACE_3)
                        .children(notice.map(|text| caption("scan-notice", text, tokens)))
                        .children(metric_caption)
                        .children(crumb)
                        .child(body),
                ),
                1,
                self.activation,
                reduce,
            ))
    }
}
