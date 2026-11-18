//! The read-only Storage screen: the volume and the folder sizes of a scan.

use crate::{
    data::{
        model::{
            HostSnapshot, Loadable, Measured, ScanEnd, ScanProgress, ScanState, ScanSummary,
            SizeMetric,
        },
        store::AppModel,
    },
    theme::{
        palette,
        tokens::{self, Tokens, to_hsla},
    },
    ui::{
        data_state::{format_age, format_bytes, used_capacity},
        legend::{Legend, LegendRow},
        pill::{StatusPill, Tone},
        provenance::ProvenanceLine,
        surface::{Panel, Shell, ShellHeader},
        value::DisplayValue,
    },
    viz::{
        breakdown::{DEFAULT_SEGMENTS, Segment, breakdown},
        capacity_grid::CapacityGrid,
        led::{LedChart, LedField, TileLabel},
        storage_layouts::{
            BAND_ROWS, CHART_ROWS, ChartItem, STRIP_ROWS, StorageLayout, apply_focus,
            bytes_per_cell, chart_label, layout_field, scale_caption,
        },
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
        spinner::Spinner,
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
    time::SystemTime,
};

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
        self.path_stack.push(path);
        self.start(cx);
    }

    /// Pops to `level` (0 is the default root) and scans that folder.
    pub fn pop_to(&mut self, level: usize, cx: &mut Context<Self>) {
        self.path_stack.truncate(level);
        self.start(cx);
    }
}

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
        .child(Panel::new().child(v_flex().gap(px(12.0)).child(body)))
        .into_any_element()
}

fn volume_card(
    host: &Loadable<HostSnapshot>,
    tokens: &Tokens,
    width: f32,
    dark: bool,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::HardDrive, "Startup volume");
    let body: AnyElement = match host {
        Loadable::Loading => Skeleton::new().w(px(140.0)).h(px(30.0)).into_any_element(),
        Loadable::Unavailable(reason) => v_flex()
            .gap(px(8.0))
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
                        .muted(stale)
                        .context(format!("used of {total_text} {total_unit}"))
                }
                (Measured::Unavailable(reason), _) | (_, Measured::Unavailable(reason)) => {
                    DisplayValue::unavailable(reason.clone()).id("volume-value")
                }
            };
            v_flex()
                .gap(px(12.0))
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

fn size_value(bytes: u64, id: &'static str) -> DisplayValue {
    let (text, unit) = format_bytes(bytes);
    DisplayValue::new(text, unit).id(id)
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

impl StorageScreen {
    fn metric_control(&self, cx: &mut Context<Self>) -> AnyElement {
        let button = |id: &'static str,
                      label: &'static str,
                      metric: SizeMetric,
                      this: &Self,
                      cx: &mut Context<Self>| {
            let base = Button::new(id).label(label).small();
            let base = if this.metric == metric {
                base.primary()
            } else {
                base.outline()
            };
            base.on_click(cx.listener(move |screen, _, _, cx| {
                screen.metric = metric;
                cx.notify();
            }))
        };
        h_flex()
            .gap(px(4.0))
            .child(button(
                "metric-allocated",
                "Allocated",
                SizeMetric::Allocated,
                self,
                cx,
            ))
            .child(button(
                "metric-logical",
                "Logical",
                SizeMetric::Logical,
                self,
                cx,
            ))
            .into_any_element()
    }

    fn layout_control(&self, cx: &mut Context<Self>) -> AnyElement {
        let button =
            |id: &'static str, layout: StorageLayout, this: &Self, cx: &mut Context<Self>| {
                let base = Button::new(id).label(layout.name()).small();
                let base = if this.layout == layout {
                    base.primary()
                } else {
                    base.outline()
                };
                base.on_click(cx.listener(move |screen, _, _, cx| {
                    screen.layout = layout;
                    cx.notify();
                }))
            };
        h_flex()
            .gap(px(4.0))
            .child(button("layout-tiles", StorageLayout::Tiles, self, cx))
            .child(button("layout-band", StorageLayout::Band, self, cx))
            .child(button("layout-columns", StorageLayout::Columns, self, cx))
            .into_any_element()
    }

    fn breadcrumb(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if self.path_stack.is_empty() {
            return None;
        }
        let mut row = h_flex().gap(px(4.0)).items_center().flex_wrap();
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
            .gap(px(12.0))
            .child(div().id(id).child(format!(
                "Measure the folders of {}. The scan reads sizes only and changes nothing.",
                root.display()
            )))
            .child(
                h_flex().child(
                    Button::new("scan-start")
                        .primary()
                        .label(format!("Scan {name}"))
                        .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                ),
            )
            .into_any_element()
    }

    fn running_body(
        progress: &ScanProgress,
        started: std::time::Instant,
        mono: &SharedString,
        metric: SizeMetric,
        cx: &mut Context<Self>,
        tokens: &Tokens,
    ) -> AnyElement {
        let total: u64 = match metric {
            SizeMetric::Allocated => progress.allocated,
            SizeMetric::Logical => progress.logical,
        };
        let path: String = progress
            .current_path
            .as_ref()
            .map_or_else(String::new, |p| {
                middle_ellipsis(&p.display().to_string(), MAX_PATH_CHARS)
            });
        v_flex()
            .gap(px(12.0))
            .child(
                h_flex()
                    .gap(px(8.0))
                    .items_center()
                    .child(Spinner::new())
                    .child("Scanning"),
            )
            .child(
                div()
                    .font_family(mono.clone())
                    .text_size(px(12.0))
                    .child(path),
            )
            .child(size_value(total, "scan-running-total"))
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
            )
            .child(
                h_flex().child(
                    Button::new("scan-cancel")
                        .outline()
                        .label("Cancel")
                        .on_click(cx.listener(|screen, _, _, cx| {
                            screen.model.update(cx, |model, _| model.cancel_scan());
                        })),
                ),
            )
            .into_any_element()
    }

    #[expect(clippy::too_many_lines, reason = "one build of the done view")]
    fn done_body(
        &self,
        summary: &Arc<ScanSummary>,
        width: f32,
        dark: bool,
        cx: &mut Context<Self>,
        tokens: &Tokens,
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
        let select_this: Entity<Self> = this.clone();
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
                select_this.update(app, |screen, cx| screen.push(path, cx));
            }
        });
        let legend_open = Rc::clone(&open);
        let legend: Legend = Legend::new(rows, width, "storage-legend")
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
            caption("storage-band-scale", scale_caption(0, 0), tokens)
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
            let label: String =
                chart_label(self.layout, &summary.root.display().to_string(), &items);
            let chart_open = Rc::clone(&open);
            v_flex()
                .gap(px(8.0))
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
        let mut col = v_flex()
            .gap(px(12.0))
            .child(size_value(summary.total(self.metric), "scan-total"));
        if summary.ended == ScanEnd::Cancelled {
            col = col
                .child(StatusPill::new("Cancelled", Tone::Neutral).id("scan-pill"))
                .child(caption(
                    "scan-cancelled-note",
                    "The scan stopped before the end. The sizes cover the part that it read.",
                    tokens,
                ));
        } else if !summary.complete {
            col = col.child(StatusPill::new("Partial", Tone::Warning).id("scan-pill"));
        }
        if !summary.complete {
            for (index, gap) in summary.gaps.iter().enumerate() {
                col = col.child(
                    div()
                        .id(SharedString::from(format!("scan-gap-{index}")))
                        .text_size(px(12.0))
                        .child(format!("{} × {}", gap.cause_text, gap.count)),
                );
            }
            if summary.ended != ScanEnd::Cancelled {
                col = col.child(caption(
                    "scan-partial-note",
                    "The total covers only what the scan could read.",
                    tokens,
                ));
            }
        }
        col.children(self.breadcrumb(cx))
            .child(chart)
            .child(legend)
            .child(caption("scan-footer", done_footer(summary), tokens))
            .child(
                h_flex().child(
                    Button::new("scan-rescan")
                        .outline()
                        .label("Rescan")
                        .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                ),
            )
            .into_any_element()
    }
}

impl Render for StorageScreen {
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
        let body: AnyElement = match &scan {
            ScanState::Idle => match &root {
                Some(root) => Self::idle_body(root, cx, "scan-idle"),
                None => caption("scan-no-root", "No folder is available to scan.", tokens),
            },
            ScanState::Running {
                progress, started, ..
            } => Self::running_body(progress, *started, &mono, self.metric, cx, tokens),
            ScanState::Done(summary) => self.done_body(summary, width, dark, cx, tokens),
            ScanState::Failed { reason, .. } => v_flex()
                .gap(px(12.0))
                .child(
                    div()
                        .id("scan-failed")
                        .test_support()
                        .aria_label(reason.clone())
                        .child(reason.clone()),
                )
                .child(
                    h_flex().child(
                        Button::new("scan-retry")
                            .outline()
                            .label("Try again")
                            .on_click(cx.listener(|screen, _, _, cx| screen.start(cx))),
                    ),
                )
                .into_any_element(),
        };
        let header: ShellHeader = ShellHeader::new(IconName::Folder, "Folder sizes")
            .subtitle(shown_root)
            .aside(
                h_flex()
                    .gap(px(12.0))
                    .child(self.layout_control(cx))
                    .child(self.metric_control(cx)),
            );
        let metric_caption: AnyElement = caption("scan-metric", self.metric.caption(), tokens);
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
            .child(volume_card(&host, tokens, width, dark))
            .child(card(
                header,
                v_flex()
                    .gap(px(12.0))
                    .children(notice.map(|text| caption("scan-notice", text, tokens)))
                    .child(metric_caption)
                    .children(crumb)
                    .child(body),
            ))
    }
}
