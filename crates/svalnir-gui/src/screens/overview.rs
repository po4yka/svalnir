//! The Overview screen: disk headroom, memory pressure, swap, the agent, the
//! policies, and the latest intervention.

use crate::{
    data::{
        model::{
            AgentSnapshot, AgentState, GuardState, HostSample, HostSnapshot, Loadable, Measured,
            OperationPhase, PressureLevel, ServiceSnapshot,
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
        pill::{StatusPill, Tone},
        provenance::ProvenanceLine,
        rolling::RollingNumber,
        surface::{Panel, Shell, ShellHeader},
        value::DisplayValue,
    },
    viz::{
        alloc::count_f32,
        capacity_grid::{capacity_label, known_capacity},
        led::{LedChart, LedField, LedSegment},
        spark::{Sparkline, level_changes},
        tick_gauge::{PRESSURE_TICKS, PressureTone, TickGauge, pressure_gauge},
        tick_track::{TRACK_TICKS, TickTrack, track_states},
        treemap::CellRect,
    },
};
use gpui_kit::{
    AnyElement, BoxShadow, Context, Entity, FontWeight, Hsla, IntoElement, ParentElement, Pixels,
    Render, Role, SharedString, Styled, TestSupportExt as _, Window,
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
    roll_swap: Entity<RollingNumber>,
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
            roll_swap: RollingNumber::new("swap-value-roll", cx),
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
        cx.notify();
    }
}

fn skeleton_value() -> AnyElement {
    v_flex()
        .gap(px(8.0))
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
        .gap(px(8.0))
        .child(DisplayValue::unavailable(reason.to_owned()).id(id))
        .child(caption(
            "overview-unavailable-note",
            "Nothing is shown as zero.",
            tokens,
        ))
        .into_any_element()
}

fn card(header: ShellHeader, body: impl IntoElement) -> AnyElement {
    Shell::new()
        .child(header)
        .child(Panel::new().child(v_flex().gap(px(12.0)).child(body)))
        .into_any_element()
}

fn tone_color(tone: PressureTone, tokens: &Tokens) -> Hsla {
    to_hsla(match tone {
        PressureTone::Positive => tokens.positive,
        PressureTone::Warning => tokens.warning,
        PressureTone::Negative => tokens.negative,
    })
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
                .gap(px(12.0))
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

fn pressure_card(view: &View, history: &[HostSample], tokens: &Tokens) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::MemoryStick, "Memory pressure");
    let body: AnyElement = match view {
        View::Loading => skeleton_value(),
        View::Failed(reason) => unavailable_body("pressure-value", reason, tokens),
        View::Data { host, stale } => {
            let (text, tone) = pressure_pill(&host.pressure);
            header = header.aside(StatusPill::new(text, tone).id("pressure-pill"));
            let gauge: Option<(usize, PressureTone)> =
                pressure_gauge(&host.pressure, PRESSURE_TICKS);
            let mut tick_gauge: TickGauge = TickGauge::new(gauge.map(|g| g.0), PRESSURE_TICKS)
                .id("pressure-gauge")
                .label(format!("Memory pressure: {text}"))
                .threshold(PRESSURE_TICKS / 3, "Warning")
                .threshold(PRESSURE_TICKS * 2 / 3, "Critical");
            if let Some((_, tone)) = gauge {
                tick_gauge = tick_gauge.tone(tone_color(tone, tokens));
            }
            let note: String = match &host.pressure {
                Measured::Unavailable(reason) => reason.clone(),
                Measured::Value(_) => {
                    "System memory pressure state, as macOS reports it.".to_owned()
                }
            };
            v_flex()
                .gap(px(12.0))
                .child(tick_gauge)
                .child(TickTrack::new(
                    "pressure-track",
                    track_states(history.iter(), TRACK_TICKS),
                    history.len(),
                ))
                .child(caption("pressure-caption", note, tokens))
                .children(stale.then(|| caption("pressure-stale", stale_caption(host), tokens)))
                .child(
                    ProvenanceLine::new(host.source, host.captured_at, "host memory")
                        .id("pressure-provenance"),
                )
                .into_any_element()
        }
    };
    card(header, body)
}

fn swap_spark(host: &HostSnapshot, history: &[HostSample], tokens: &Tokens) -> AnyElement {
    let values: Vec<Option<u64>> = history
        .iter()
        .map(|s| match &s.swap_used {
            Measured::Value(v) => Some(*v),
            Measured::Unavailable(_) => None,
        })
        .collect();
    if values.iter().flatten().count() < 2 {
        return caption("swap-spark-note", "Collecting samples\u{2026}", tokens);
    }
    let largest: u64 = values.iter().flatten().copied().max().unwrap_or(0);
    let max: u64 = match &host.swap_total {
        Measured::Value(total) => (*total).max(largest),
        Measured::Unavailable(_) => largest,
    }
    .max(1);
    let (text, unit) = format_bytes(max);
    v_flex()
        .gap(px(6.0))
        .child(
            div()
                .id("swap-spark")
                .test_support()
                .aria_label(format!("Swap in use over {} samples", values.len()))
                .child(Sparkline::new(
                    values,
                    max,
                    level_changes(history),
                    to_hsla(tokens.brand),
                )),
        )
        .child(caption(
            "swap-spark-scale",
            format!("0 \u{2013} {text} {unit}"),
            tokens,
        ))
        .into_any_element()
}

fn swap_card(
    view: &View,
    history: &[HostSample],
    roll: &Entity<RollingNumber>,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::MemoryStick, "Swap");
    let body: AnyElement = match view {
        View::Loading => skeleton_value(),
        View::Failed(reason) => unavailable_body("swap-value", reason, tokens),
        View::Data { host, stale } => {
            let value: DisplayValue = match &host.swap_used {
                Measured::Value(used) => {
                    let (text, unit) = format_bytes(*used);
                    let value: DisplayValue = DisplayValue::new(text, unit)
                        .id("swap-value")
                        .rolling(roll.clone())
                        .muted(*stale);
                    match &host.swap_total {
                        Measured::Value(total) => {
                            let (total_text, total_unit) = format_bytes(*total);
                            value.context(format!("of {total_text} {total_unit} allocated"))
                        }
                        Measured::Unavailable(_) => value,
                    }
                }
                Measured::Unavailable(reason) => {
                    DisplayValue::unavailable(reason.clone()).id("swap-value")
                }
            };
            v_flex()
                .gap(px(12.0))
                .child(value)
                .child(swap_spark(host, history, tokens))
                .child(caption(
                    "swap-caption",
                    "Swap in use. Nonzero swap alone is not a problem.",
                    tokens,
                ))
                .children(stale.then(|| caption("swap-stale", stale_caption(host), tokens)))
                .child(
                    ProvenanceLine::new(host.source, host.captured_at, "host memory")
                        .id("swap-provenance"),
                )
                .into_any_element()
        }
    };
    card(header, body)
}

fn agent_card(agent: &Loadable<AgentSnapshot>, tokens: &Tokens) -> AnyElement {
    let mut header: ShellHeader = ShellHeader::new(IconName::Cpu, "Agent");
    let body: AnyElement = match agent {
        Loadable::Loading => skeleton_value(),
        Loadable::Unavailable(reason) => unavailable_body("agent-value", reason, tokens),
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
            let (text, tone, sentence) = agent_summary(&snapshot.state, SystemTime::now());
            header = header.aside(StatusPill::new(text, tone).id("agent-pill"));
            let stale: bool = matches!(agent, Loadable::Stale(_));
            v_flex()
                .gap(px(8.0))
                .child(inset_row(
                    h_flex()
                        .gap(px(10.0))
                        .items_center()
                        .child(guard_led(
                            matches!(snapshot.state, AgentState::Reporting { .. }),
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
fn guard_led(active: bool, tokens: &Tokens) -> AnyElement {
    let color: Hsla = to_hsla(tokens.positive);
    let mut block = div().flex().flex_col().gap(px(1.0)).flex_shrink_0();
    if active {
        block = block.shadow(vec![BoxShadow {
            color: color.opacity(0.5),
            offset: point(px(0.0), px(0.0)),
            blur_radius: px(6.0),
            spread_radius: px(0.0),
            inset: false,
        }]);
    }
    for _ in 0..3 {
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
            let mut body = v_flex().gap(px(12.0));
            for row in &snapshot.guards {
                let (text, tone) = match row.standing {
                    GuardState::Active => ("Active", Tone::Positive),
                    GuardState::Inactive => ("Inactive", Tone::Neutral),
                };
                body = body.child(
                    v_flex()
                        .gap(px(4.0))
                        .child(
                            h_flex()
                                .gap(px(8.0))
                                .items_center()
                                .child(guard_led(row.standing == GuardState::Active, tokens))
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
        .px(px(12.0))
        .py(px(10.0))
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
                        .gap(px(4.0))
                        .child(
                            h_flex()
                                .justify_between()
                                .gap(px(8.0))
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
        let cards: Vec<AnyElement> = vec![
            hero_card(
                phase,
                &view,
                &self.roll_disk,
                tokens,
                content.max(MIN_CARD_WIDTH),
                &mono,
            ),
            pressure_card(&view, &history, tokens),
            swap_card(&view, &history, &self.roll_swap, tokens),
            agent_card(&agent, tokens),
            policies_card(&service, &mono, tokens),
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
                        .w(if index == 0 { full_width } else { card_width })
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
}
