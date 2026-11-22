//! The Memory screen: the pressure readings of this window, the memory and
//! swap quantities of the host, the processes with the largest footprint
//! and their growth, and the application budgets and the memory incident of
//! the controller record. The screen shows state only.

use super::agent_state::{
    budgets_card, controller_body, cooldown_facts, growth_text, incident_inset,
};
use super::common::{
    CardWidth, Shown, body_line, bytes_text, caption, card, cell, fact, failed_body, head,
    mono_text, screen, shown, skeleton_rows, stale_line,
};
use crate::{
    data::{
        model::{HostSample, HostSnapshot, Measured, PressureLevel},
        records::{
            ControllerSnapshot, CooldownSubject, IncidentUsage, MemorySnapshot, ProcessRow,
            ProcessesSnapshot,
        },
        store::AppModel,
    },
    screens::overview::pressure_pill,
    theme::tokens::{self, Tokens, to_hsla},
    ui::{
        data_state::UNAVAILABLE_TEXT, pill::StatusPill, provenance::ProvenanceLine,
        surface::ShellHeader,
    },
};
use gpui_kit::{
    AnyElement, Context, Entity, IntoElement, ParentElement, Render, Role, SharedString, Styled,
    TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, IconName, Sizable as _,
        table::{Table, TableBody, TableHeader, TableRow},
        v_flex,
    },
    div,
    prelude::*,
    px,
};
use std::time::SystemTime;
use svalnir_core::policy::PolicyId;

/// The number of readings of each pressure state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PressureCounts {
    /// Readings with the state Normal.
    pub normal: usize,
    /// Readings with the state Warning.
    pub warning: usize,
    /// Readings with the state Critical.
    pub critical: usize,
    /// Readings with no pressure value. They are not Normal readings.
    pub unavailable: usize,
}

impl PressureCounts {
    /// The counts of `history`.
    #[must_use]
    pub fn of<'a>(history: impl IntoIterator<Item = &'a HostSample>) -> Self {
        let mut counts = Self::default();
        for sample in history {
            match sample.pressure {
                Measured::Value(PressureLevel::Normal) => counts.normal += 1,
                Measured::Value(PressureLevel::Warning) => counts.warning += 1,
                Measured::Value(PressureLevel::Critical) => counts.critical += 1,
                Measured::Unavailable(_) => counts.unavailable += 1,
            }
        }
        counts
    }

    /// The number of readings.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.normal + self.warning + self.critical + self.unavailable
    }

    /// The caption of the history track: the number of readings, their
    /// source, and the count of each state.
    #[must_use]
    pub fn caption(&self) -> String {
        format!(
            "{} readings of this window: {} normal, {} warning, {} critical, {} unavailable",
            self.total(),
            self.normal,
            self.warning,
            self.critical,
            self.unavailable
        )
    }
}

/// The sentence below the process table: how many processes the table shows
/// and which processes the reading does not have.
#[must_use]
pub fn process_summary(snapshot: &ProcessesSnapshot) -> String {
    let mut text: String = format!(
        "{} of {} processes of this user, by physical footprint.",
        snapshot.processes.len(),
        snapshot.process_count
    );
    if snapshot.other_user > 0 {
        text = format!(
            "{text} {} processes of other users are not recorded.",
            snapshot.other_user
        );
    }
    if snapshot.not_readable > 0 {
        text = format!(
            "{text} {} processes could not be read.",
            snapshot.not_readable
        );
    }
    text
}

/// The accessible sentence of one process row. An unavailable footprint is
/// "not available", never zero.
#[must_use]
pub fn process_label(row: &ProcessRow) -> String {
    let name: &str = row.name.as_deref().unwrap_or("Process with no name");
    let footprint: String = match &row.footprint {
        Measured::Value(_) => format!("footprint {}", bytes_text(&row.footprint)),
        Measured::Unavailable(reason) => format!("footprint not available: {reason}"),
    };
    let growth: String = match &row.growth {
        Measured::Value(_) => format!("growth {}", growth_text(&row.growth)),
        Measured::Unavailable(reason) => format!("growth not available: {reason}"),
    };
    format!("{name}, process {}, {footprint}, {growth}", row.pid)
}

/// The Memory screen entity.
#[derive(Debug)]
pub struct MemoryScreen {
    model: Entity<AppModel>,
    activation: u64,
}

impl MemoryScreen {
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

/// The history track: one tick for each reading, the newest at the right.
fn history_track(history: &[HostSample], tokens: &Tokens) -> AnyElement {
    let counts: PressureCounts = PressureCounts::of(history);
    let label: String = counts.caption();
    // 2 px: the gap of the ticks of the track, not layout spacing.
    let mut track = div()
        .id("memory-pressure-track")
        .role(Role::Image)
        .test_support()
        .aria_label(label.clone())
        .flex()
        .flex_wrap()
        .gap(px(2.0));
    for sample in history {
        let color = match sample.pressure {
            Measured::Value(PressureLevel::Normal) => tokens.positive,
            Measured::Value(PressureLevel::Warning) => tokens.warning,
            Measured::Value(PressureLevel::Critical) => tokens.negative,
            Measured::Unavailable(_) => tokens.border,
        };
        // A tick of the dense scale of the cell: 3 px wide, 14 px high.
        track = track.child(
            div()
                .w(px(3.0))
                .h(tokens::CELL_SIZE)
                .rounded(px(1.0))
                .bg(to_hsla(color)),
        );
    }
    v_flex()
        .gap(tokens::SPACE_2)
        .child(track)
        .child(caption("memory-pressure-caption", label, tokens))
        .into_any_element()
}

fn pressure_card(
    host: &Shown<HostSnapshot>,
    history: &[HostSample],
    tokens: &Tokens,
) -> AnyElement {
    let mut header: ShellHeader =
        ShellHeader::new(IconName::ChartPie, "Memory pressure").subtitle("State of the system");
    let body: AnyElement = match host {
        Shown::Loading => skeleton_rows(2),
        Shown::Failed(reason) => failed_body("memory-pressure-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let (text, tone) = pressure_pill(&value.pressure);
            header = header.aside(StatusPill::new(text, tone).id("memory-pressure-pill"));
            let mut body = v_flex().gap(tokens::SPACE_3);
            if let Measured::Unavailable(reason) = &value.pressure {
                body = body.child(caption(
                    "memory-pressure-reason",
                    format!("The pressure state is not available: {reason}."),
                    tokens,
                ));
            }
            body = body.child(history_track(history, tokens));
            if let Some(age) = stale_age {
                body = body.child(stale_line("memory-pressure-stale", age, tokens));
            }
            body.into_any_element()
        }
    };
    card(header, body)
}

fn quantities_card(
    host: &Shown<HostSnapshot>,
    memory: &Shown<MemorySnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::MemoryStick, "Memory and swap")
        .subtitle("Each row is a different quantity");
    let mut body = v_flex().gap(tokens::SPACE_2);
    let mut any: bool = false;
    // The provenance lines close the card, after the note.
    let mut provenance: Vec<ProvenanceLine> = Vec::new();
    match host {
        Shown::Loading => body = body.child(skeleton_rows(3)),
        Shown::Failed(reason) => {
            body = body.child(failed_body("memory-host-value", reason, tokens));
        }
        Shown::Data { value, stale_age } => {
            any = true;
            let stale: bool = stale_age.is_some();
            for (id, label, measured) in [
                ("memory-physical", "Physical memory", &value.memory_total),
                ("memory-swap-used", "Swap used", &value.swap_used),
                ("memory-swap-allocated", "Swap allocated", &value.swap_total),
            ] {
                body = body.child(fact(id, label, bytes_text(measured), mono, stale, tokens));
            }
            // The host rows have their own reading, so they have their own
            // stale line and provenance; the lines of the memory reading do
            // not cover them. The provenance closes the card.
            if let Some(age) = stale_age {
                body = body.child(stale_line("memory-host-stale", age, tokens));
            }
            provenance.push(
                ProvenanceLine::new(value.source, value.captured_at, "host readings")
                    .id("memory-host-provenance"),
            );
        }
    }
    match memory {
        Shown::Loading => body = body.child(skeleton_rows(4)),
        Shown::Failed(reason) => {
            body = body.child(failed_body("memory-detail-value", reason, tokens));
        }
        Shown::Data { value, stale_age } => {
            any = true;
            let stale: bool = stale_age.is_some();
            for (id, label, measured) in [
                ("memory-wired", "Wired", &value.wired),
                (
                    "memory-compressor",
                    "Occupied by the compressor",
                    &value.compressor,
                ),
                (
                    "memory-compressed-data",
                    "Data held in the compressor",
                    &value.compressed_data,
                ),
                ("memory-free", "Free", &value.free),
            ] {
                body = body.child(fact(id, label, bytes_text(measured), mono, stale, tokens));
            }
            if let Some(age) = stale_age {
                body = body.child(stale_line("memory-detail-stale", age, tokens));
            }
            provenance.push(
                ProvenanceLine::new(value.source, value.captured_at, "memory detail")
                    .id("memory-provenance"),
            );
        }
    }
    if any {
        body = body.child(caption(
            "memory-quantities-note",
            format!("{UNAVAILABLE_TEXT} marks a value that the host did not give. It is not zero."),
            tokens,
        ));
    }
    body = body.children(provenance);
    card(header, body)
}

fn process_table(
    snapshot: &ProcessesSnapshot,
    stale: bool,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let rows = snapshot.processes.iter().map(|row| {
        let label: String = process_label(row);
        let name: SharedString = row
            .name
            .clone()
            .unwrap_or_else(|| UNAVAILABLE_TEXT.to_owned())
            .into();
        TableRow::new()
            .id(SharedString::from(format!("memory-process-{}", row.pid)))
            .child(cell(
                div()
                    .id(SharedString::from(format!(
                        "memory-process-name-{}",
                        row.pid
                    )))
                    .test_support()
                    .aria_label(label)
                    .min_w_0()
                    .child(name),
                3,
                false,
            ))
            .child(cell(
                mono_text(row.pid.to_string(), mono, true, tokens),
                1,
                true,
            ))
            .child(cell(
                mono_text(
                    row.group
                        .clone()
                        .unwrap_or_else(|| "No verified group".to_owned()),
                    mono,
                    true,
                    tokens,
                ),
                3,
                false,
            ))
            .child(cell(
                mono_text(bytes_text(&row.footprint), mono, stale, tokens),
                2,
                true,
            ))
            .child(cell(
                mono_text(growth_text(&row.growth), mono, true, tokens),
                2,
                true,
            ))
            .child(cell(
                mono_text(bytes_text(&row.resident), mono, true, tokens),
                2,
                true,
            ))
    });
    Table::new()
        .small()
        .accessibility_label("Processes by physical footprint")
        .child(
            TableHeader::new().child(
                TableRow::new()
                    .child(head("Process", 3, false, tokens))
                    .child(head("PID", 1, true, tokens))
                    .child(head("Application or job", 3, false, tokens))
                    .child(head("Footprint", 2, true, tokens))
                    .child(head("Growth", 2, true, tokens))
                    .child(head("Resident", 2, true, tokens)),
            ),
        )
        .child(TableBody::new().children(rows))
        .into_any_element()
}

fn processes_card(
    processes: &Shown<ProcessesSnapshot>,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::Cpu, "Process footprint")
        .subtitle("Physical footprint; resident size is a different quantity");
    let body: AnyElement = match processes {
        Shown::Loading => skeleton_rows(6),
        Shown::Failed(reason) => failed_body("memory-processes-value", reason, tokens),
        Shown::Data { value, stale_age } => {
            let mut body = v_flex().gap(tokens::SPACE_3);
            if value.processes.is_empty() {
                body = body.child(body_line(
                    "memory-processes-empty",
                    "The reading has no process of this user.",
                    true,
                    tokens,
                ));
            } else {
                body = body.child(process_table(value, stale_age.is_some(), mono, tokens));
            }
            body = body.child(caption(
                "memory-processes-summary",
                process_summary(value),
                tokens,
            ));
            body = body.child(caption(
                "memory-growth-note",
                "Growth is the footprint change since the previous reading of this window. A process that is new since then has no value. Growth alone is not evidence of a leak.",
                tokens,
            ));
            if let Some(age) = stale_age {
                body = body.child(stale_line("memory-processes-stale", age, tokens));
            }
            body = body.child(
                ProvenanceLine::new(value.source, value.captured_at, "processes of this user")
                    .id("memory-processes-provenance"),
            );
            body.into_any_element()
        }
    };
    card(header, body)
}

/// The memory incident of the controller record with its budget
/// generations, and the cooldowns of the memory guard.
fn incident_card(
    controller: &Shown<ControllerSnapshot>,
    now: SystemTime,
    mono: &SharedString,
    tokens: &Tokens,
) -> AnyElement {
    let header: ShellHeader = ShellHeader::new(IconName::CircleAlert, "Memory incident")
        .subtitle("Usage of each budget generation");
    let body: AnyElement = controller_body("memory-incident", controller, tokens, |rows, stale| {
        let mut lines: Vec<AnyElement> = Vec::new();
        let incidents: Vec<&IncidentUsage> = rows
            .incidents
            .iter()
            .filter(|incident| incident.policy == PolicyId::MemoryGuard)
            .collect();
        if incidents.is_empty() {
            lines.push(caption(
                "memory-incident-empty",
                "The controller record has no open memory incident.",
                tokens,
            ));
        }
        for incident in &incidents {
            lines.push(incident_inset("memory", incident, now, stale, mono, tokens));
        }
        // The cooldowns of the memory incident: its observation after an
        // action and its back-off.
        let of_memory = |id: &String| incidents.iter().any(|incident| incident.id == *id);
        lines.extend(cooldown_facts(
            "memory-incident",
            &rows.cooldowns,
            |subject| match subject {
                CooldownSubject::MemoryBackoff { incident }
                | CooldownSubject::ObserveAfterAction { incident } => of_memory(incident),
                CooldownSubject::Relaunch { .. } | CooldownSubject::DiskPass { .. } => false,
            },
            stale,
            mono,
            tokens,
        ));
        lines
    });
    card(header, body)
}

impl Render for MemoryScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let mono: SharedString = cx.theme().mono_font_family.clone();
        let model: &AppModel = self.model.read(cx);
        let now: SystemTime = SystemTime::now();
        let host = shown(&model.host, now, |host| host.captured_at);
        let memory = shown(&model.memory, now, |memory| memory.captured_at);
        let processes = shown(&model.processes, now, |processes| processes.captured_at);
        let controller = shown(&model.controller, now, |controller| controller.captured_at);
        let history: Vec<HostSample> = model.history.iter().cloned().collect();
        let cards: Vec<(CardWidth, AnyElement)> = vec![
            (CardWidth::Share, pressure_card(&host, &history, tokens)),
            (
                CardWidth::Share,
                quantities_card(&host, &memory, &mono, tokens),
            ),
            (
                CardWidth::Share,
                budgets_card(&controller, "memory-budgets", &mono, tokens),
            ),
            (
                CardWidth::Share,
                incident_card(&controller, now, &mono, tokens),
            ),
            (CardWidth::Full, processes_card(&processes, &mono, tokens)),
        ];
        screen("Memory", cards, self.activation, cx.reduce_motion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn sample(pressure: Measured<PressureLevel>) -> HostSample {
        HostSample {
            at: SystemTime::UNIX_EPOCH,
            pressure,
            swap_used: Measured::Unavailable("x".into()),
            disk_available: Measured::Unavailable("x".into()),
            disk_used: Measured::Unavailable("x".into()),
            utc_offset: None,
        }
    }

    #[test]
    fn an_unavailable_reading_is_not_a_normal_reading() {
        let history = [
            sample(Measured::Value(PressureLevel::Normal)),
            sample(Measured::Unavailable("x".into())),
            sample(Measured::Value(PressureLevel::Critical)),
            sample(Measured::Value(PressureLevel::Warning)),
            sample(Measured::Unavailable("x".into())),
        ];
        let counts = PressureCounts::of(&history);
        assert_eq!(
            counts,
            PressureCounts {
                normal: 1,
                warning: 1,
                critical: 1,
                unavailable: 2
            }
        );
        assert_eq!(
            counts.caption(),
            "5 readings of this window: 1 normal, 1 warning, 1 critical, 2 unavailable"
        );
    }

    #[test]
    fn the_label_of_a_process_with_no_footprint_has_the_reason() {
        let mut row = ProcessRow {
            pid: 7,
            name: Some("sync-agent".to_owned()),
            group: None,
            footprint: Measured::Value(96_000_000),
            resident: Measured::Value(1),
            growth: Measured::Value(crate::data::records::Growth {
                delta: -2_000_000,
                elapsed: std::time::Duration::from_secs(5),
            }),
        };
        assert_eq!(
            process_label(&row),
            "sync-agent, process 7, footprint 96.0 MB, growth \u{2212}2.0 MB in 5 s"
        );
        row.footprint = Measured::Unavailable("exited".to_owned());
        row.growth = Measured::Unavailable("exited".to_owned());
        row.name = None;
        assert_eq!(
            process_label(&row),
            "Process with no name, process 7, footprint not available: exited, growth not available: exited"
        );
    }

    #[test]
    fn the_summary_names_the_processes_that_the_reading_does_not_have() {
        let mut snapshot = ProcessesSnapshot {
            captured_at: SystemTime::UNIX_EPOCH,
            processes: Vec::new(),
            process_count: 0,
            applications: Vec::new(),
            application_count: 0,
            unattributed: 0,
            other_user: 0,
            not_readable: 0,
            notes: Vec::new(),
            source: "test",
        };
        assert_eq!(
            process_summary(&snapshot),
            "0 of 0 processes of this user, by physical footprint."
        );
        snapshot.process_count = 300;
        snapshot.other_user = 148;
        snapshot.not_readable = 2;
        assert_eq!(
            process_summary(&snapshot),
            "0 of 300 processes of this user, by physical footprint. 148 processes of other users are not recorded. 2 processes could not be read."
        );
    }
}
