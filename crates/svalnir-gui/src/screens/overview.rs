//! The Overview screen: the headroom dial, the session chart, the startup
//! volume, the agent, the policies, and the latest intervention.

use crate::{
    data::{
        model::{
            AgentSnapshot, AgentState, GuardState, HostSample, HostSnapshot, Loadable, Measured,
            OperationPhase, OperationRow, PressureLevel, ServiceSnapshot,
        },
        store::AppModel,
    },
    theme::{
        motion,
        tokens::{self, Tokens, to_hsla},
    },
    ui::{
        data_state::{format_age, format_bytes, used_capacity},
        entry::card_entry,
        pill::{MonoTag, StatusPill, Tone},
        provenance::ProvenanceLine,
        rolling::RollingNumber,
        stat_row::{StatItem, StatRow},
        surface::{Panel, Shell, ShellHeader},
        value::DisplayValue,
    },
    viz::{
        alloc::count_f32,
        capacity_grid::{capacity_label, known_capacity},
        dial::{
            DialColors, DialDetail, DialKey, DialLegend, DialModel, HeadMove, HeadroomDial,
            dial_model, level_sector, lit_of, names_hidden, share_percent_text, share_ppm,
            sweep_total, with_lit_counts,
        },
        led::{LedChart, LedField, LedSegment},
        session::{LEFT_GUTTER, RIGHT_GUTTER, SessionChart, live_progress, session_model},
        treemap::CellRect,
    },
};
use gpui_kit::{
    AnyElement, BoxShadow, Context, Entity, FocusHandle, FontWeight, Hsla, IntoElement,
    ParentElement, Pixels, Render, Role, SharedString, Styled, TestSupportExt as _, Window,
    component::{ActiveTheme as _, IconName, h_flex, skeleton::Skeleton, v_flex},
    div, point,
    prelude::*,
    px,
};
use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

const MIN_CARD_WIDTH: f32 = 320.0;
/// The width of the dial card when it shares a row with the session chart.
const DIAL_CARD_WIDTH: f32 = 610.0;
/// The least content width at which the two cards share a row: the dial card,
/// the gap, and a session chart of 60 columns with its gutters and padding.
const PAIR_MIN_WIDTH: f32 = 1150.0;
/// The sidebar width at full size and collapsed, and the content padding.
const SIDEBAR_FULL: f32 = 256.0;
const SIDEBAR_COLLAPSED: f32 = 49.0;

/// The number of grid columns for a content width in pixels.
#[must_use]
pub fn columns_for(content_width: f32) -> usize {
    if content_width >= 1100.0 {
        3
    } else if content_width >= 720.0 {
        2
    } else {
        1
    }
}

/// The pill text and tone of a pressure reading.
#[must_use]
pub fn pressure_pill(pressure: &Measured<PressureLevel>) -> (&'static str, Tone) {
    match pressure {
        Measured::Value(PressureLevel::Normal) => ("Normal", Tone::Positive),
        Measured::Value(PressureLevel::Warning) => ("Warning", Tone::Warning),
        Measured::Value(PressureLevel::Critical) => ("Critical", Tone::Negative),
        Measured::Unavailable(_) => ("Unavailable", Tone::Neutral),
    }
}

/// The pill text, tone, and sentence of an agent state at `now`.
#[must_use]
pub fn agent_summary(state: &AgentState, now: SystemTime) -> (&'static str, Tone, String) {
    let age =
        |time: SystemTime| -> String { format_age(now.duration_since(time).unwrap_or_default()) };
    match state {
        AgentState::Reporting { since } => (
            "Reporting",
            Tone::Brand,
            format!("The agent wrote its status {}.", age(*since)),
        ),
        AgentState::Silent { last } => (
            "Not reporting",
            Tone::Warning,
            format!(
                "The agent wrote its last status {}. It is not known whether an agent runs.",
                age(*last)
            ),
        ),
        AgentState::NoRecord => (
            "Not running",
            Tone::Warning,
            "The journal has no status of an agent. No automatic protection is active.".to_owned(),
        ),
        AgentState::NoJournal => (
            "Not running",
            Tone::Warning,
            "No journal exists. No automatic protection is active. This window measures the host itself."
                .to_owned(),
        ),
        AgentState::Unknown(reason) => (
            "Unknown",
            Tone::Neutral,
            format!("The status of the agent cannot be read: {reason}."),
        ),
    }
}

/// How a card reads the host.
enum View {
    Loading,
    Failed(String),
    Data {
        host: Arc<HostSnapshot>,
        stale: bool,
    },
}

/// The Overview screen entity.
#[derive(Debug)]
pub struct OverviewScreen {
    model: Entity<AppModel>,
    roll_disk: Entity<RollingNumber>,
    dial_pick: Option<usize>,
    row_focus: [FocusHandle; 3],
    head: HeadMove,
    live_start: Instant,
    sweep_start: Option<Instant>,
    activation: u64,
    phase: f32,
    last_render: Instant,
    twinkle: Option<gpui_kit::Task<()>>,
}

impl OverviewScreen {
    /// Creates the screen and observes the model.
    pub fn new(model: Entity<AppModel>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            roll_disk: RollingNumber::new("disk-value-roll", cx),
            dial_pick: None,
            row_focus: [cx.focus_handle(), cx.focus_handle(), cx.focus_handle()],
            head: HeadMove::default(),
            live_start: Instant::now(),
            sweep_start: None,
            activation: 1,
            phase: 0.0,
            last_render: Instant::now(),
            twinkle: None,
        }
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

    /// Marks a new activation of the screen: the cards enter again.
    pub fn activate(&mut self, cx: &mut Context<Self>) {
        self.activation += 1;
        // The dial sweeps again with the entry of the cards.
        self.sweep_start = None;
        cx.notify();
    }
}

fn skeleton_value() -> AnyElement {
    v_flex()
        .gap(tokens::SPACE_2)
        .child(Skeleton::new().w(px(140.0)).h(px(30.0)))
        .child(Skeleton::new().w_full().h(px(8.0)))
        .into_any_element()
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

/// The age caption of stale data, or `None`.
fn stale_caption(host: &HostSnapshot) -> String {
    format_age(
        SystemTime::now()
            .duration_since(host.captured_at)
            .unwrap_or_default(),
    )
}

fn unavailable_body(id: &'static str, reason: &str, tokens: &Tokens) -> AnyElement {
    v_flex()
        .gap(tokens::SPACE_2)
        .child(DisplayValue::unavailable(reason.to_owned()).id(id))
        .child(caption(
            "overview-unavailable-note",
            "Nothing is shown as zero.",
            tokens,
        ))
        .into_any_element()
}

fn card(header: ShellHeader, body: impl IntoElement) -> AnyElement {
    card_aligned(header, body, false)
}

/// A card whose content is centered in the height of its panel when
/// `centered` is true, and starts at the top otherwise.
fn card_aligned(header: ShellHeader, body: impl IntoElement, centered: bool) -> AnyElement {
    card_full(header, body, None, centered)
}

/// A card with an optional footer in the shell, below the panel.
fn card_full(
    header: ShellHeader,
    body: impl IntoElement,
    footer: Option<AnyElement>,
    centered: bool,
) -> AnyElement {
    let mut content = v_flex().flex_1().gap(tokens::SPACE_3);
    if centered {
        content = content.justify_center();
    }
    Shell::new()
        .grow()
        .child(header)
        .child(Panel::new().grow().child(content.child(body)))
        .children(footer.map(|row| {
            // The inner padding of a control, like the header, not a layout gap.
            div().px(px(10.0)).py(tokens::SPACE_3).child(row)
        }))
        .into_any_element()
}

/// The LED field of the hero chart: the used capacity as one `brand`
/// segment and the free region after it. An unknown capacity is an empty lattice.
fn hero_field(
    used: &Measured<u64>,
    total: &Measured<u64>,
    columns: u16,
    tokens: &Tokens,
) -> LedField {
    let rows: u16 = 10;
    let mut field: LedField = LedField {
        columns,
        rows,
        segments: Vec::new(),
        free: None,
        head: None,
        phase: None,
    };
    if let Some((used, total)) = known_capacity(used, total) {
        let wanted: u64 = (used.saturating_mul(u64::from(columns)) + total / 2) / total;
        let used_cols: u16 = u16::try_from(wanted.min(u64::from(columns))).unwrap_or(columns);
        field.segments.push(LedSegment::new(
            CellRect::new(0, 0, used_cols, rows),
            to_hsla(tokens.brand),
            1,
        ));
        if used_cols < columns {
            field.free = Some(CellRect::new(used_cols, 0, columns - used_cols, rows));
        }
    }
    field
}

fn hero_card(
    phase: Option<f32>,
    view: &View,
    roll: &Entity<RollingNumber>,
    tokens: &Tokens,
    width: f32,
    mono: &SharedString,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::HardDrive, "Startup volume");
    let body: AnyElement = match view {
        View::Loading => skeleton_value(),
        View::Failed(reason) => unavailable_body("disk-value", reason, tokens),
        View::Data { host, stale } => {
            if let Some(name) = &host.volume_name {
                header = header.subtitle(name.clone());
            }
            let used: Measured<u64> = used_capacity(&host.disk_total, &host.disk_available);
            if let Some((u, t)) = known_capacity(&used, &host.disk_total) {
                let percent: u64 = u.saturating_mul(100) / t;
                header = header.aside(
                    div()
                        .font_family(mono.clone())
                        .text_size(px(12.0))
                        .text_color(to_hsla(tokens.muted_foreground))
                        .child(format!("{percent}% used")),
                );
            }
            let value: DisplayValue = match &host.disk_available {
                Measured::Value(available) => {
                    let (text, unit) = format_bytes(*available);
                    let value: DisplayValue = DisplayValue::new(text, unit)
                        .id("disk-value")
                        .rolling(roll.clone())
                        .muted(*stale);
                    match &host.disk_total {
                        Measured::Value(total) => {
                            let (total_text, total_unit) = format_bytes(*total);
                            value.context(format!("available of {total_text} {total_unit}"))
                        }
                        Measured::Unavailable(_) => value.context("available"),
                    }
                }
                Measured::Unavailable(reason) => {
                    DisplayValue::unavailable(reason.clone()).id("disk-value")
                }
            };
            let columns: u16 = {
                let inner: f32 = (width - 32.0 - 12.0).max(120.0);
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "the value is clamped to 20..=200 first"
                )]
                let cells: u16 = (inner / 6.0).floor().clamp(20.0, 200.0) as u16;
                cells
            };
            let mut field: LedField = hero_field(&used, &host.disk_total, columns, tokens);
            field.phase = phase;
            let scale: Option<String> = match &host.disk_total {
                Measured::Value(total) if *total > 0 => {
                    let (v, unit) = format_bytes(*total / u64::from(columns));
                    Some(format!("1 cell = {v} {unit}"))
                }
                _ => None,
            };
            v_flex()
                .gap(tokens::SPACE_3)
                .child(value)
                .child(LedChart::new(
                    field,
                    Vec::new(),
                    "disk-grid",
                    capacity_label(&used, &host.disk_total),
                ))
                .children(scale.map(|text| caption("disk-grid-scale", text, tokens)))
                .children(stale.then(|| caption("disk-stale", stale_caption(host), tokens)))
                .child(
                    ProvenanceLine::new(host.source, host.captured_at, "startup data volume")
                        .id("disk-provenance"),
                )
                .into_any_element()
        }
    };
    card(header, body)
}

/// The aside of the Headroom card: the memory pressure while it is not
/// normal, otherwise the used share of the startup volume. `None` when the
/// disk is not measured and the pressure is normal or unavailable.
#[must_use]
pub fn headroom_aside(host: &HostSnapshot) -> Option<(String, Tone)> {
    if matches!(
        host.pressure,
        Measured::Value(PressureLevel::Warning | PressureLevel::Critical)
    ) {
        let (text, tone) = pressure_pill(&host.pressure);
        return Some((text.to_owned(), tone));
    }
    let used: Measured<u64> = used_capacity(&host.disk_total, &host.disk_available);
    let (used, total) = known_capacity(&used, &host.disk_total)?;
    Some((
        format!("{} disk used", share_percent_text(share_ppm(used, total))),
        Tone::Neutral,
    ))
}

/// The value and the suffix of the swap item of the stat row. It follows the
/// rule of the swap ring: a use that cannot be in the space is an em dash
/// (no value), and a swap with no space and no use is "None".
#[must_use]
pub fn swap_stat(host: &HostSnapshot) -> (Option<String>, Option<String>) {
    let split = |value: &Measured<u64>| -> Option<(String, &'static str)> {
        value.value().map(|bytes| format_bytes(*bytes))
    };
    match (&host.swap_used, &host.swap_total) {
        (Measured::Value(0), Measured::Value(0)) => (Some("None".to_owned()), None),
        (Measured::Value(used), Measured::Value(total)) if used > total || *total == 0 => {
            (None, None)
        }
        (Measured::Value(_), Measured::Value(_)) => {
            match (split(&host.swap_used), split(&host.swap_total)) {
                (Some((text, unit)), Some((total, total_unit))) => {
                    (Some(text), Some(format!("{unit} of {total} {total_unit}")))
                }
                _ => (None, None),
            }
        }
        (used, _) => match split(used) {
            Some((text, unit)) => (Some(text), Some(unit.to_owned())),
            None => (None, None),
        },
    }
}

/// The stat row of the Headroom card: the available disk space, the used
/// swap, and the pressure state. An unavailable value is an em dash.
fn headroom_stats(host: &HostSnapshot, dark: bool) -> StatRow {
    let colors: DialColors = DialColors::for_dark(dark);
    let split = |value: &Measured<u64>| -> Option<(String, &'static str)> {
        value.value().map(|bytes| format_bytes(*bytes))
    };
    let mut disk: StatItem = StatItem::new(
        "disk",
        "Disk available",
        split(&host.disk_available).map(|(text, _)| text),
        colors.disk,
    );
    if let Some((_, unit)) = split(&host.disk_available) {
        disk = disk.suffix(unit);
    }
    let (swap_value, swap_suffix): (Option<String>, Option<String>) = swap_stat(host);
    let mut swap: StatItem = StatItem::new("swap", "Swap used", swap_value, colors.swap);
    if let Some(suffix) = swap_suffix {
        swap = swap.suffix(suffix);
    }
    let (state, color): (Option<&str>, _) = match &host.pressure {
        Measured::Value(level) => (Some(level.label()), colors.sector(level_sector(*level))),
        Measured::Unavailable(_) => (None, colors.muted),
    };
    StatRow::new("headroom-stat-")
        .item(disk)
        .item(swap)
        .item(StatItem::new("pressure", "Pressure", state, color))
}

/// The Headroom card: the dial, its legend, the detail panel, and the
/// provenance line.
#[expect(clippy::too_many_arguments, reason = "one card of the screen")]
fn headroom_card(
    view: &View,
    pick: Option<usize>,
    sweep: Option<f32>,
    lit_counts: Option<[Option<usize>; 3]>,
    focus: [FocusHandle; 3],
    on_pick: impl Fn(Option<usize>, &mut Window, &mut gpui_kit::App) + 'static,
    tokens: &Tokens,
    dark: bool,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::MemoryStick, "Headroom");
    let (body, footer): (AnyElement, Option<AnyElement>) = match view {
        View::Loading => (skeleton_value(), None),
        View::Failed(reason) => (unavailable_body("headroom-value", reason, tokens), None),
        View::Data { host, stale } => {
            let model: DialModel = dial_model(host);
            let shown: DialModel =
                lit_counts.map_or_else(|| model.clone(), |counts| with_lit_counts(&model, counts));
            let pill: (&'static str, Tone) = pressure_pill(&host.pressure);
            if let Some((text, tone)) = headroom_aside(host) {
                header = header.aside(StatusPill::new(text, tone).id("headroom-aside"));
            }
            let effective: usize = pick.unwrap_or(model.picked).min(2);
            let detail: DialDetail = DialDetail::new(model.rings[effective].clone()).muted(*stale);
            let body: AnyElement = v_flex()
                .gap(tokens::SPACE_3)
                .child(
                    h_flex()
                        .flex_wrap()
                        .items_start()
                        .gap(tokens::SPACE_6)
                        .child(
                            v_flex()
                                .gap(tokens::SPACE_3)
                                .child(
                                    HeadroomDial::new(shown)
                                        .hidden_names(names_hidden(&model))
                                        .picked(pick)
                                        .sweep(sweep)
                                        .muted(*stale),
                                )
                                .child(DialKey),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .min_w(px(300.0))
                                .gap(tokens::SPACE_3)
                                .child(
                                    DialLegend::new(model, pill)
                                        .muted(*stale)
                                        .focus_handles(focus)
                                        .on_pick(on_pick),
                                )
                                .child(detail)
                                .children(stale.then(|| {
                                    caption("headroom-stale", stale_caption(host), tokens)
                                }))
                                .child(
                                    ProvenanceLine::new(
                                        host.source,
                                        host.captured_at,
                                        "startup volume and host memory",
                                    )
                                    .id("headroom-provenance"),
                                ),
                        ),
                )
                .into_any_element();
            (body, Some(headroom_stats(host, dark).into_any_element()))
        }
    };
    card_full(header, body, footer, true)
}

/// The columns of the session chart that fit `width` pixels.
#[must_use]
pub fn session_slots(width: f32) -> usize {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the value is clamped to 1..=180 first"
    )]
    let slots: usize = ((width + 1.5) / 6.0).floor().clamp(1.0, 180.0) as usize;
    slots
}

/// The This session card: the session chart of the readings of this window.
fn session_card(
    view: &View,
    history: &[HostSample],
    operation: Option<&OperationRow>,
    width: f32,
    live: Option<f32>,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::HardDrive, "This session")
        .subtitle("Readings since this window opened");
    let mut footer: Option<AnyElement> = None;
    let body: AnyElement = match view {
        View::Loading => skeleton_value(),
        View::Failed(reason) => unavailable_body("session-value", reason, tokens),
        View::Data { host, stale } => {
            // The shell and the panel pad the chart on both sides; the chart
            // has a gutter of names and a gutter of newest values.
            let padding: f32 = 2.0 * f32::from(tokens::SHELL_PADDING + tokens::PANEL_PADDING)
                + LEFT_GUTTER
                + RIGHT_GUTTER;
            let slots: usize = session_slots((width - padding).max(0.0));
            let model = session_model(history, operation, slots);
            let tags = model.tags();
            footer = Some(
                h_flex()
                    .flex_wrap()
                    .gap(tokens::SPACE_2)
                    .child(MonoTag::new("session-tag-readings", tags.readings))
                    .child(MonoTag::new("session-tag-range", tags.range))
                    .child(MonoTag::new("session-tag-events", tags.events))
                    .child(MonoTag::new("session-tag-state", tags.state))
                    .into_any_element(),
            );
            v_flex()
                .gap(tokens::SPACE_3)
                .child(SessionChart::new(model).live(live).muted(*stale))
                .children(stale.then(|| caption("session-stale", stale_caption(host), tokens)))
                .child(
                    ProvenanceLine::new(host.source, host.captured_at, "host readings")
                        .id("session-provenance"),
                )
                .into_any_element()
        }
    };
    card_full(header, body, footer, false)
}

fn agent_card(agent: &Loadable<AgentSnapshot>, glow: bool, tokens: &Tokens) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::Cpu, "Agent");
    let body: AnyElement = match agent {
        Loadable::Loading => skeleton_value(),
        Loadable::Unavailable(reason) => unavailable_body("agent-value", reason, tokens),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            let (text, tone, sentence) = agent_summary(&snapshot.state, SystemTime::now());
            header = header.aside(StatusPill::new(text, tone).id("agent-pill"));
            let stale: bool = matches!(agent, Loadable::Stale(_));
            v_flex()
                .gap(tokens::SPACE_2)
                .child(inset_row(
                    h_flex()
                        .gap(tokens::SPACE_2)
                        .items_center()
                        .child(guard_led(
                            matches!(snapshot.state, AgentState::Reporting { .. }),
                            glow,
                            tokens,
                        ))
                        .child(caption("agent-sentence", sentence, tokens)),
                    tokens,
                ))
                .children(stale.then(|| {
                    caption(
                        "agent-stale",
                        format_age(
                            SystemTime::now()
                                .duration_since(snapshot.captured_at)
                                .unwrap_or_default(),
                        ),
                        tokens,
                    )
                }))
                .into_any_element()
        }
    };
    card(header, body)
}

/// The pill text and tone of an operation phase.
#[must_use]
pub const fn phase_pill(phase: OperationPhase, state_text: &str) -> (&str, Tone) {
    match phase {
        OperationPhase::Pending => ("Pending", Tone::Neutral),
        OperationPhase::Running => ("Running", Tone::Brand),
        OperationPhase::Completed => ("Completed", Tone::Positive),
        OperationPhase::Partial => (state_text, Tone::Warning),
        OperationPhase::NoAction => ("No action", Tone::Neutral),
        OperationPhase::Failed => ("Failed", Tone::Negative),
        OperationPhase::Unknown => ("Unknown outcome", Tone::Warning),
    }
}

/// A 3 by 3 lattice block: lit with a glow for an active guard.
fn guard_led(active: bool, glow: bool, tokens: &Tokens) -> AnyElement {
    let color: Hsla = to_hsla(tokens.positive);
    // 1 px: the gap of the cells of the guard indicator, not layout spacing.
    let mut block = div().flex().flex_col().gap(px(1.0)).flex_shrink_0();
    if active && glow {
        block = block.shadow(vec![BoxShadow {
            color: color.opacity(0.5),
            offset: point(px(0.0), px(0.0)),
            blur_radius: px(6.0),
            spread_radius: px(0.0),
            inset: false,
        }]);
    }
    for _ in 0..3 {
        // 1 px: the gap of the cells of the guard indicator, not layout spacing.
        let mut line = h_flex().gap(px(1.0));
        for _ in 0..3 {
            line = line.child(div().size(px(3.0)).rounded(px(0.5)).bg(if active {
                color
            } else {
                to_hsla(tokens.border)
            }));
        }
        block = block.child(line);
    }
    block.into_any_element()
}

fn policies_card(
    service: &Loadable<ServiceSnapshot>,
    mono: &SharedString,
    glow: bool,
    tokens: &Tokens,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::Settings, "Policies");
    let body: AnyElement = match service {
        Loadable::Loading => skeleton_value(),
        Loadable::Unavailable(reason) => unavailable_body("policies-value", reason, tokens),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            header = header.subtitle(match &snapshot.active_revision {
                Some(id) => format!("Revision {id}"),
                None => "No revision in effect".to_owned(),
            });
            let mut body = v_flex().gap(tokens::SPACE_3);
            for row in &snapshot.guards {
                let (text, tone) = match row.standing {
                    GuardState::Active => ("Active", Tone::Positive),
                    GuardState::Inactive => ("Inactive", Tone::Neutral),
                };
                body = body.child(
                    v_flex()
                        .gap(tokens::SPACE_1)
                        .child(
                            h_flex()
                                .gap(tokens::SPACE_2)
                                .items_center()
                                .child(guard_led(row.standing == GuardState::Active, glow, tokens))
                                .child(div().font_family(mono.clone()).child(row.name))
                                .child(
                                    StatusPill::new(text, tone).id(format!("guard-{}", row.name)),
                                ),
                        )
                        .child(caption("guard-detail", row.detail, tokens)),
                );
            }
            if !snapshot
                .guards
                .iter()
                .any(|row| row.standing == GuardState::Active)
            {
                body = body.child(caption(
                    "policies-no-guard",
                    "No guard can act. No automatic cleanup and no automatic application control can occur.",
                    tokens,
                ));
            }
            for problem in &snapshot.problems {
                body = body.child(caption("policies-problem", problem.clone(), tokens));
            }
            if matches!(service, Loadable::Stale(_)) {
                body = body.child(caption(
                    "policies-stale",
                    format_age(
                        SystemTime::now()
                            .duration_since(snapshot.captured_at)
                            .unwrap_or_default(),
                    ),
                    tokens,
                ));
            }
            body.into_any_element()
        }
    };
    card(header, body)
}

/// A compact row: an inset block with the tint of `DESIGN.md` section 4.
fn inset_row(content: impl IntoElement, tokens: &Tokens) -> AnyElement {
    div()
        .rounded(tokens::INSET_RADIUS)
        .bg(to_hsla(tokens.inset_tint))
        .px(tokens::INSET_PADDING_X)
        .py(tokens::INSET_PADDING_Y)
        .child(content)
        .into_any_element()
}

fn intervention_card(
    service: &Loadable<ServiceSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::Bell, "Latest intervention");
    let body: AnyElement = match service {
        Loadable::Loading => skeleton_value(),
        Loadable::Unavailable(reason) => unavailable_body("intervention-value", reason, tokens),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            if let Some(operation) = &snapshot.latest_operation {
                let (text, tone) = phase_pill(operation.state, &operation.state_text);
                header = header.aside(StatusPill::new(text.to_owned(), tone).id("operation-pill"));
                let age: String = format_age(
                    SystemTime::now()
                        .duration_since(operation.admitted_at)
                        .unwrap_or_default(),
                );
                inset_row(
                    v_flex()
                        .gap(tokens::SPACE_1)
                        .child(
                            h_flex()
                                .justify_between()
                                .gap(tokens::SPACE_2)
                                .child(
                                    div()
                                        .id("operation-id")
                                        .font_family(mono.clone())
                                        .text_size(px(12.0))
                                        .child(operation.operation_id.clone()),
                                )
                                .child(caption("operation-age", age, tokens)),
                        )
                        .child(caption(
                            "operation-trigger",
                            format!("Trigger: {}", operation.trigger),
                            tokens,
                        )),
                    tokens,
                )
            } else {
                let text: &str = if snapshot.journal_present {
                    "No operation is in the journal."
                } else {
                    "No journal exists in the state directory."
                };
                caption("intervention-empty", text, tokens)
            }
        }
    };
    card(header, body)
}

impl Render for OverviewScreen {
    #[expect(clippy::too_many_lines, reason = "one build of the screen")]
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let model: &AppModel = self.model.read(cx);
        let view: View = match &model.host {
            Loadable::Loading => View::Loading,
            Loadable::Unavailable(reason) => View::Failed(reason.clone()),
            Loadable::Ready(host) => View::Data {
                host: Arc::clone(host),
                stale: false,
            },
            Loadable::Stale(host) => View::Data {
                host: Arc::clone(host),
                stale: true,
            },
        };
        let history: Vec<HostSample> = model.history.iter().cloned().collect();
        let agent: Loadable<AgentSnapshot> = model.agent.clone();
        let service: Loadable<ServiceSnapshot> = model.service.clone();
        self.last_render = Instant::now();
        let gate: motion::Gate = motion::Gate {
            reduce_motion: cx.reduce_motion(),
            window_active: window.is_window_active(),
            pressure_normal: !matches!(&view, View::Data { host, .. }
                if matches!(host.pressure, Measured::Value(p) if p != PressureLevel::Normal)),
        };
        let phase: Option<f32> = if gate.continuous() {
            self.start_twinkle(cx);
            Some(self.phase)
        } else {
            self.twinkle = None;
            None
        };
        let mono: SharedString = cx.theme().mono_font_family.clone();
        // The live head moves per frame, from its own start instant. The
        // frames stop with the continuous effects or when this screen is not
        // rendered.
        // The chart draws the ring only with the glow and only with data, so
        // no frame is requested without them.
        let glow_on: bool = crate::theme::glow::enabled(cx);
        let live_shown: bool = gate.continuous() && glow_on && matches!(view, View::Data { .. });
        let live: Option<f32> = live_shown.then(|| {
            window.request_animation_frame();
            live_progress(self.live_start.elapsed().as_secs_f32())
        });
        // The ring sweep runs once, when the screen first shows data.
        let sweep: Option<f32> = if matches!(view, View::Data { .. }) {
            // The start is set also with Reduce Motion on, so a later change
            // of that setting does not replay the sweep.
            let start: Instant = *self.sweep_start.get_or_insert_with(Instant::now);
            let total = sweep_total(3);
            let elapsed = start.elapsed();
            if gate.transitions() && elapsed < total {
                window.request_animation_frame();
                Some(elapsed.as_secs_f32() / total.as_secs_f32())
            } else {
                None
            }
        } else {
            None
        };
        // The head move: the lit counts ease to the new reading.
        let now: Instant = Instant::now();
        let lit_counts: Option<[Option<usize>; 3]> = if let View::Data { host, .. } = &view {
            let model: DialModel = dial_model(host);
            let targets: [Option<usize>; 3] = [
                lit_of(&model.rings[0]),
                lit_of(&model.rings[1]),
                lit_of(&model.rings[2]),
            ];
            self.head.observe(targets, now, gate.transitions());
            let (counts, running) = self.head.shown(now);
            if running {
                window.request_animation_frame();
            }
            running.then_some(counts)
        } else {
            None
        };
        // The keyboard focus picks a ring like the pointer does; blur clears it.
        let focused: Option<usize> = self
            .row_focus
            .iter()
            .position(|handle| handle.is_focused(window));
        let pick: Option<usize> = self.dial_pick.or(focused);
        let operation: Option<OperationRow> = service
            .value()
            .and_then(|snapshot| snapshot.latest_operation.clone());
        let this: Entity<Self> = cx.entity();

        let viewport: f32 = window.viewport_size().width.into();
        let sidebar: f32 = if viewport < 900.0 {
            SIDEBAR_COLLAPSED
        } else {
            SIDEBAR_FULL
        };
        let content: f32 = (viewport - sidebar - 2.0 * f32::from(tokens::CONTENT_PADDING)).max(0.0);
        let gap: f32 = f32::from(tokens::GRID_GAP);
        let columns: usize = columns_for(content);
        let card_width: Pixels = px(((content - gap * (count_f32(columns) - 1.0))
            / count_f32(columns))
        .max(MIN_CARD_WIDTH));

        let full_width: Pixels = px(content.max(MIN_CARD_WIDTH));
        // On a wide window the dial and the session chart share one row.
        let paired: bool = content >= PAIR_MIN_WIDTH;
        let (dial_width, session_width): (f32, f32) = if paired {
            (DIAL_CARD_WIDTH, content - gap - DIAL_CARD_WIDTH)
        } else {
            (content.max(MIN_CARD_WIDTH), content.max(MIN_CARD_WIDTH))
        };
        let cards: Vec<AnyElement> = vec![
            headroom_card(
                &view,
                pick,
                sweep,
                lit_counts,
                self.row_focus.clone(),
                move |index, _, app| {
                    this.update(app, |screen, cx| {
                        if screen.dial_pick != index {
                            screen.dial_pick = index;
                            cx.notify();
                        }
                    });
                },
                tokens,
                cx.theme().is_dark(),
            ),
            session_card(
                &view,
                &history,
                operation.as_ref(),
                session_width,
                live,
                tokens,
            ),
            hero_card(
                phase,
                &view,
                &self.roll_disk,
                tokens,
                content.max(MIN_CARD_WIDTH),
                &mono,
            ),
            agent_card(&agent, glow_on, tokens),
            policies_card(&service, &mono, glow_on, tokens),
            intervention_card(&service, &mono, tokens),
        ];
        let reduce: bool = cx.reduce_motion();
        let cards: Vec<AnyElement> = cards
            .into_iter()
            .enumerate()
            .map(|(index, card)| card_entry(card, index, self.activation, reduce))
            .collect();
        let title: &'static str = "Overview";
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
            .child(div().flex().flex_wrap().gap(tokens::GRID_GAP).children(
                cards.into_iter().enumerate().map(|(index, card)| {
                    div()
                        .flex()
                        .flex_col()
                        .w(match index {
                            0 => px(dial_width),
                            1 => px(session_width),
                            2 => full_width,
                            _ => card_width,
                        })
                        .min_w(px(MIN_CARD_WIDTH))
                        .flex_shrink_0()
                        .child(card)
                }),
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_follow_the_content_width() {
        assert_eq!(columns_for(1100.0), 3);
        assert_eq!(columns_for(1099.0), 2);
        assert_eq!(columns_for(720.0), 2);
        assert_eq!(columns_for(719.0), 1);
    }

    #[test]
    fn pressure_pill_never_hides_unavailable() {
        assert_eq!(
            pressure_pill(&Measured::Unavailable("x".into())).0,
            "Unavailable"
        );
        assert_eq!(
            pressure_pill(&Measured::Value(PressureLevel::Warning)).0,
            "Warning"
        );
    }

    #[test]
    fn agent_summary_names_the_evidence() {
        let now: SystemTime = SystemTime::now();
        assert_eq!(agent_summary(&AgentState::NoJournal, now).0, "Not running");
        assert_eq!(agent_summary(&AgentState::NoRecord, now).0, "Not running");
        let (text, _, sentence) = agent_summary(&AgentState::Reporting { since: now }, now);
        assert_eq!(text, "Reporting");
        assert!(
            sentence.starts_with("The agent wrote its status "),
            "{sentence}"
        );
        let (text, _, sentence) = agent_summary(&AgentState::Silent { last: now }, now);
        assert_eq!(text, "Not reporting");
        assert!(
            sentence.contains("not known whether an agent runs"),
            "{sentence}"
        );
    }

    #[test]
    fn the_aside_shows_pressure_when_not_normal_else_the_disk_share() {
        let mut host = HostSnapshot {
            captured_at: SystemTime::UNIX_EPOCH,
            utc_offset: None,
            volume_name: None,
            disk_total: Measured::Value(1000),
            disk_available: Measured::Value(510),
            disk_free: Measured::Value(500),
            pressure: Measured::Value(PressureLevel::Normal),
            memory_total: Measured::Value(1),
            swap_used: Measured::Value(0),
            swap_total: Measured::Value(0),
            source: "test",
        };
        let (text, tone) = headroom_aside(&host).expect("aside");
        assert_eq!((text.as_str(), tone), ("49% disk used", Tone::Neutral));
        host.pressure = Measured::Value(PressureLevel::Warning);
        assert_eq!(headroom_aside(&host).expect("aside").0, "Warning");
        host.pressure = Measured::Unavailable("x".into());
        host.disk_total = Measured::Unavailable("x".into());
        assert!(headroom_aside(&host).is_none());
    }

    fn host_with(swap_used: u64, swap_total: u64) -> HostSnapshot {
        HostSnapshot {
            captured_at: SystemTime::UNIX_EPOCH,
            utc_offset: None,
            volume_name: None,
            disk_total: Measured::Value(1_000_000_000),
            disk_available: Measured::Value(999_999_999),
            disk_free: Measured::Value(999_999_999),
            pressure: Measured::Value(PressureLevel::Normal),
            memory_total: Measured::Value(1),
            swap_used: Measured::Value(swap_used),
            swap_total: Measured::Value(swap_total),
            source: "test",
        }
    }

    #[test]
    fn the_swap_stat_follows_the_rule_of_the_swap_ring() {
        assert_eq!(swap_stat(&host_with(0, 0)), (Some("None".to_owned()), None));
        assert_eq!(swap_stat(&host_with(2_000_000_000, 0)), (None, None));
        assert_eq!(swap_stat(&host_with(5, 4)), (None, None));
        let (value, suffix) = swap_stat(&host_with(1_000_000_000, 4_000_000_000));
        assert_eq!(value.as_deref(), Some("1.0"));
        assert_eq!(suffix.as_deref(), Some("GB of 4.0 GB"));
    }

    #[test]
    fn a_small_disk_share_is_not_zero_and_a_nearly_full_disk_is_not_full() {
        let host = host_with(0, 0);
        assert_eq!(headroom_aside(&host).expect("aside").0, "<1% disk used");
        let mut full = host_with(0, 0);
        full.disk_available = Measured::Value(1);
        assert_eq!(headroom_aside(&full).expect("aside").0, "99% disk used");
        full.disk_available = Measured::Value(0);
        assert_eq!(headroom_aside(&full).expect("aside").0, "100% disk used");
    }
}
