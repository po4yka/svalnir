//! The menu bar item: the inline capacity grid, the memory pressure state,
//! and the pause control (`DESIGN.md` §9 and §11).
//!
//! The pinned `gpui-kit` and its GPUI have no status item API, so the item is
//! an `NSStatusItem` of `AppKit` (`native`), beside the GPUI application in
//! the same process. This module has the part that has no `AppKit` type: the
//! [`StatusView`] that a model gives, which the tests check, and the commands
//! of the menu, which go through the same model actions as the Automation
//! screen. The item reads the app-level model, so it shows readings while no
//! window is open.

#[cfg(target_os = "macos")]
mod native;

use crate::{
    actions::{Action, Slot},
    data::{
        model::{AgentSnapshot, AgentState, HostSnapshot, Loadable, Measured, PressureLevel},
        records::{PauseRow, ThresholdQuantity},
        store::{AppModel, Topic},
    },
    screens::automation::{PAUSE_HOUR, pause_summary},
    theme::tokens::Tokens,
    ui::data_state::used_capacity,
    viz::{
        alloc::{used_cells, zone_start},
        capacity_grid::{INLINE_CELLS, capacity_label},
    },
};
use gpui_kit::{App, Entity, Global, Subscription};
use std::{rc::Rc, time::SystemTime};
use svalnir_core::policy::PolicyId;

/// A command of the menu of the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommand {
    /// Pause automation for one hour.
    PauseHour,
    /// Pause automation until a resume.
    PauseOpen,
    /// Resume automation.
    Resume,
    /// Open the main window, or bring it to the front.
    OpenWindow,
    /// Quit the client. The agent continues.
    Quit,
}

impl MenuCommand {
    /// Each command, in the order of its tag.
    pub const ALL: [Self; 5] = [
        Self::PauseHour,
        Self::PauseOpen,
        Self::Resume,
        Self::OpenWindow,
        Self::Quit,
    ];

    /// The tag of the native menu item: the index in [`Self::ALL`] plus 1,
    /// so that the default tag 0 is no command.
    #[must_use]
    pub fn tag(self) -> isize {
        Self::ALL
            .iter()
            .position(|command| *command == self)
            .and_then(|index| isize::try_from(index + 1).ok())
            .unwrap_or(0)
    }

    /// The command of a tag; `None` for a tag of no command.
    #[must_use]
    pub fn from_tag(tag: isize) -> Option<Self> {
        let index: usize = usize::try_from(tag).ok()?.checked_sub(1)?;
        Self::ALL.get(index).copied()
    }
}

/// One row of the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuRow {
    /// A line of state that cannot be chosen. `detail` is its tooltip.
    Info {
        /// The text of the line.
        title: String,
        /// The longer sentence, when there is one.
        detail: Option<String>,
    },
    /// A command.
    Command {
        /// The text of the item.
        title: &'static str,
        /// What the item does.
        command: MenuCommand,
        /// Whether the item can be chosen now.
        enabled: bool,
    },
    /// A separator line.
    Separator,
}

/// A tone of the item: a color token of `DESIGN.md` §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemTone {
    /// `brand`: used space outside a zone.
    Brand,
    /// `positive`: the Normal memory pressure.
    Positive,
    /// `warning`: the warning zone of the disk guard, and the Warning pressure.
    Warning,
    /// `negative`: the critical zone of the disk guard, and the Critical
    /// pressure.
    Negative,
}

/// How one cell of the inline grid is painted (`DESIGN.md` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellPaint {
    /// A used cell in the tone of its zone, or in `brand`.
    Filled(ItemTone),
    /// A free cell in a zone: a tint of the zone tone.
    Tint(ItemTone),
    /// A free cell outside the zones.
    Empty,
    /// A used cell of a stale reading: the color of the menu bar text, with
    /// no tone (`DESIGN.md` §8: a stale value is muted).
    Muted,
}

/// The appearance that the menu bar draws the item in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuBarLook {
    /// Whether the menu bar has the dark appearance.
    pub dark: bool,
    /// Whether Increase Contrast is on.
    pub increase_contrast: bool,
}

/// The alpha of a tint and of an empty cell, and the same with Increase
/// Contrast. A tint is 25% as in the window grid (`viz::cells`).
const TINT_ALPHA: [f64; 2] = [0.25, 0.5];
/// An empty cell is the color of the menu bar text at this alpha, so it is
/// visible on the light and the dark menu bar.
const EMPTY_ALPHA: [f64; 2] = [0.3, 0.55];
/// The alpha of a used cell of a stale reading.
const MUTED_ALPHA: [f64; 2] = [0.65, 0.85];

/// The color of `tone` in the theme of `dark`, as red, green, blue.
#[must_use]
pub fn tone_rgb(tone: ItemTone, dark: bool) -> [f64; 3] {
    let tokens: &Tokens = Tokens::for_dark(dark);
    let color = match tone {
        ItemTone::Brand => tokens.brand,
        ItemTone::Positive => tokens.positive,
        ItemTone::Warning => tokens.warning,
        ItemTone::Negative => tokens.negative,
    };
    [f64::from(color.r), f64::from(color.g), f64::from(color.b)]
}

/// The color of `paint` on the menu bar `look`, as red, green, blue, alpha.
#[must_use]
pub fn paint_rgba(paint: CellPaint, look: MenuBarLook) -> [f64; 4] {
    let contrast: usize = usize::from(look.increase_contrast);
    match paint {
        CellPaint::Filled(tone) => {
            let [r, g, b] = tone_rgb(tone, look.dark);
            [r, g, b, 1.0]
        }
        CellPaint::Tint(tone) => {
            let [r, g, b] = tone_rgb(tone, look.dark);
            [r, g, b, TINT_ALPHA[contrast]]
        }
        CellPaint::Empty => {
            let text: f64 = if look.dark { 1.0 } else { 0.0 };
            [text, text, text, EMPTY_ALPHA[contrast]]
        }
        CellPaint::Muted => {
            let text: f64 = if look.dark { 1.0 } else { 0.0 };
            [text, text, text, MUTED_ALPHA[contrast]]
        }
    }
}

/// The outline of the pressure dot on the menu bar `look`, as red, green,
/// blue, alpha: with Increase Contrast, a 1 px outline in the color of the
/// menu bar text (`DESIGN.md` §9: surfaces get an outline), so that the dot
/// keeps an edge on a menu bar of a similar color. `None` without it.
#[must_use]
pub fn dot_outline_rgba(look: MenuBarLook) -> Option<[f64; 4]> {
    look.increase_contrast.then(|| {
        let text: f64 = if look.dark { 1.0 } else { 0.0 };
        [text, text, text, MUTED_ALPHA[1]]
    })
}

/// The paint of the 20 cells for `used` of `total`, with the zones that
/// start at the cells `warning` and `critical` (`DESIGN.md` §5: the zones of
/// the disk policy are tinted cells at the end).
#[must_use]
pub fn grid_paints(
    used: u64,
    total: u64,
    warning: Option<usize>,
    critical: Option<usize>,
) -> [CellPaint; INLINE_CELLS] {
    let filled: usize = used_cells(used, total, INLINE_CELLS);
    let mut paints: [CellPaint; INLINE_CELLS] = [CellPaint::Empty; INLINE_CELLS];
    for (index, paint) in paints.iter_mut().enumerate() {
        let zone: Option<ItemTone> = if critical.is_some_and(|start| index >= start) {
            Some(ItemTone::Negative)
        } else if warning.is_some_and(|start| index >= start) {
            Some(ItemTone::Warning)
        } else {
            None
        };
        *paint = match (index < filled, zone) {
            (true, zone) => CellPaint::Filled(zone.unwrap_or(ItemTone::Brand)),
            (false, Some(zone)) => CellPaint::Tint(zone),
            (false, None) => CellPaint::Empty,
        };
    }
    paints
}

/// The paint of a stale reading: the used cells muted, with no zone.
#[must_use]
pub fn stale_paints(used: u64, total: u64) -> [CellPaint; INLINE_CELLS] {
    let filled: usize = used_cells(used, total, INLINE_CELLS);
    let mut paints: [CellPaint; INLINE_CELLS] = [CellPaint::Empty; INLINE_CELLS];
    for paint in paints.iter_mut().take(filled) {
        *paint = CellPaint::Muted;
    }
    paints
}

/// The first cell of the zone where less than `below` bytes of `total` are
/// free; `None` when the zone is empty or the total is not known. A zone
/// that is not empty has at least the last cell, also when it is less than
/// half a cell: the default `emergency_below` of 2 GiB is 0.2% of a 1 TB
/// volume, and rounding would hide it.
#[must_use]
pub fn free_zone_start(below: u64, total: u64) -> Option<usize> {
    if total == 0 || below == 0 {
        return None;
    }
    let below: u64 = below.min(total);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a share of the volume for a grid of 20 cells"
    )]
    let fraction: f32 = 1.0 - (below as f32 / total as f32);
    Some(zone_start(fraction, INLINE_CELLS).min(INLINE_CELLS - 1))
}

/// The starts of the warning and the critical zone, with the warning zone
/// before the critical zone when both have cells, so that each shows.
#[must_use]
pub fn zone_starts(
    warning: Option<usize>,
    critical: Option<usize>,
) -> (Option<usize>, Option<usize>) {
    match (warning, critical) {
        (Some(warning), Some(critical)) if critical > 0 => {
            (Some(warning.min(critical - 1)), Some(critical))
        }
        pair => pair,
    }
}

/// The bytes of the disk guard threshold `field` in the revision in effect,
/// from the automation reading; `None` when it was not read.
fn disk_threshold(model: &AppModel, field: &str) -> Option<u64> {
    let snapshot = match &model.automation {
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => snapshot,
        Loadable::Loading | Loadable::Unavailable(_) => return None,
    };
    let key: String = format!("disk_guard.{field}");
    snapshot
        .guards
        .iter()
        .find(|guard| guard.policy == PolicyId::DiskGuard)?
        .thresholds
        .iter()
        .find(|row| row.key == key)
        .and_then(|row| match row.value {
            ThresholdQuantity::Bytes(bytes) => Some(bytes),
            ThresholdQuantity::Nanoseconds(_)
            | ThresholdQuantity::Count(_)
            | ThresholdQuantity::NoUnit(_) => None,
        })
}

/// The tone of a measured pressure; `None` for a value that is not known or
/// is stale, which has no tone.
#[must_use]
pub const fn pressure_tone(level: PressureLevel) -> ItemTone {
    match level {
        PressureLevel::Normal => ItemTone::Positive,
        PressureLevel::Warning => ItemTone::Warning,
        PressureLevel::Critical => ItemTone::Negative,
    }
}

/// What the item shows. Two equal views draw the same item, so the item
/// changes only when the view changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    /// The paint of each of the 20 cells of the inline capacity grid, or
    /// `None` when the used capacity is not known (no grid is drawn).
    pub grid: Option<[CellPaint; INLINE_CELLS]>,
    /// The tone of the dot of the pressure state beside the grid: the tone
    /// and the text of [`Self::title`] are its two signals. `None` when the
    /// pressure is not known or is stale: then the text alone shows it.
    pub pressure: Option<ItemTone>,
    /// The text beside the grid: the memory pressure state.
    pub title: String,
    /// The accessible label and tooltip of the item: the whole state as text,
    /// because the grid image has no text.
    pub label: String,
    /// The rows of the menu, top first.
    pub rows: Vec<MenuRow>,
}

/// The text of the memory pressure state, and whether the value is stale.
/// A reading that failed or did not come yet is an em dash.
fn pressure_text(host: &Loadable<HostSnapshot>) -> (String, bool) {
    let (snapshot, stale) = match host {
        Loadable::Ready(snapshot) => (snapshot, false),
        Loadable::Stale(snapshot) => (snapshot, true),
        Loadable::Loading | Loadable::Unavailable(_) => return ("\u{2014}".to_owned(), false),
    };
    match &snapshot.pressure {
        Measured::Value(level) => (PressureLevel::label(*level).to_owned(), stale),
        Measured::Unavailable(_) => ("\u{2014}".to_owned(), stale),
    }
}

/// The sentence for an agent state that gives no protection that is known,
/// as in the banner of the window.
const NO_PROTECTION: &str =
    "No recent status of an agent. No automatic protection is known to be active.";

/// The line of the agent state, and the sentence of its tooltip. Only a
/// current status record of a running agent (`Reporting`) has no warning: a
/// stopped, silent, or absent agent, and a reading that failed or did not
/// come, never read as a normal state.
#[must_use]
pub fn agent_line(agent: &Loadable<AgentSnapshot>) -> (String, Option<&'static str>) {
    let (snapshot, stale) = match agent {
        Loadable::Ready(snapshot) => (snapshot, false),
        Loadable::Stale(snapshot) => (snapshot, true),
        Loadable::Loading => return ("Agent: not read yet".to_owned(), None),
        Loadable::Unavailable(_) => {
            return (
                "Agent: unavailable".to_owned(),
                Some("The records of the agent cannot be read."),
            );
        }
    };
    let detail: Option<&'static str> = match snapshot.state {
        AgentState::Reporting { .. } => None,
        AgentState::NoJournal
        | AgentState::NoRecord
        | AgentState::Silent { .. }
        | AgentState::Stopped { .. } => Some(NO_PROTECTION),
        AgentState::Unknown(_) => Some("The records of the agent cannot be read."),
    };
    let suffix: &str = if stale { " (stale)" } else { "" };
    (format!("Agent: {}{suffix}", snapshot.state.label()), detail)
}

/// Adds the rows of the pause: its state, its commands, and the state of
/// the last pause request. Returns the text of the pause state, with
/// "(stale)" after a stale authority record.
fn push_pause_rows(model: &AppModel, now: SystemTime, rows: &mut Vec<MenuRow>) -> String {
    let stale: bool = matches!(model.automation, Loadable::Stale(_));
    let automation = match &model.automation {
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => Some(snapshot),
        Loadable::Loading | Loadable::Unavailable(_) => None,
    };
    let pause: Option<&PauseRow> = automation.and_then(|snapshot| snapshot.pause.as_ref());
    let read_at: SystemTime = automation.map_or(now, |snapshot| snapshot.captured_at);
    let (pause_text, _tone, pause_sentence) = pause_summary(pause, read_at, now);
    let pause_text: String = if stale {
        format!("{pause_text} (stale)")
    } else {
        pause_text.to_owned()
    };
    rows.push(MenuRow::Info {
        title: format!("Automation: {pause_text}"),
        detail: Some(pause_sentence),
    });
    let busy: bool = model.actions.is_busy(&Slot::Pause);
    match pause {
        // An expired pause has a record that a resume removes.
        Some(PauseRow::Paused { .. } | PauseRow::Expired { .. }) => rows.push(MenuRow::Command {
            title: "Resume automation",
            command: MenuCommand::Resume,
            enabled: !busy,
        }),
        Some(PauseRow::NotPaused) => {
            rows.push(MenuRow::Command {
                title: "Pause automation for 1 hour",
                command: MenuCommand::PauseHour,
                enabled: !busy,
            });
            rows.push(MenuRow::Command {
                title: "Pause until resumed",
                command: MenuCommand::PauseOpen,
                enabled: !busy,
            });
        }
        // With no authority record read, the control is absent, as on the
        // Automation screen.
        None => {}
    }
    if let Some(state) = model.actions.state(&Slot::Pause) {
        let (text, _tone, _icon) = state.pill();
        rows.push(MenuRow::Info {
            title: request_line(model.actions.verb(&Slot::Pause), text),
            detail: Some(state.sentence(std::time::Instant::now())),
        });
    }
    pause_text
}

/// The title of the state line of the last request of the pause slot: it is
/// named after the last command, because a pause and a resume share the
/// slot. "Last request" when the command is not known.
#[must_use]
pub fn request_line(verb: Option<&str>, pill: &str) -> String {
    match verb {
        Some(verb) => format!("{verb} request: {pill}"),
        None => format!("Last request: {pill}"),
    }
}

/// The paint of the grid and the tone of the pressure dot of `model`.
fn grid_and_tone(
    model: &AppModel,
    used: &Measured<u64>,
    total: &Measured<u64>,
) -> (Option<[CellPaint; INLINE_CELLS]>, Option<ItemTone>) {
    let stale: bool = matches!(model.host, Loadable::Stale(_));
    let grid: Option<[CellPaint; INLINE_CELLS]> = match (used, total) {
        (Measured::Value(used), Measured::Value(total)) if *total > 0 && stale => {
            Some(stale_paints(*used, *total))
        }
        (Measured::Value(used), Measured::Value(total)) if *total > 0 => {
            let (warning, critical) = zone_starts(
                disk_threshold(model, "warn_below")
                    .and_then(|below| free_zone_start(below, *total)),
                disk_threshold(model, "emergency_below")
                    .and_then(|below| free_zone_start(below, *total)),
            );
            Some(grid_paints(*used, *total, warning, critical))
        }
        _ => None,
    };
    let pressure_level: Option<ItemTone> = match &model.host {
        Loadable::Ready(snapshot) => match &snapshot.pressure {
            Measured::Value(level) => Some(pressure_tone(*level)),
            Measured::Unavailable(_) => None,
        },
        Loadable::Stale(_) | Loadable::Loading | Loadable::Unavailable(_) => None,
    };
    (grid, pressure_level)
}

/// The view of the item for `model` at `now`.
#[must_use]
pub fn status_view(model: &AppModel, now: SystemTime) -> StatusView {
    let snapshot = match &model.host {
        Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => Some(snapshot),
        Loadable::Loading | Loadable::Unavailable(_) => None,
    };
    let (used, total): (Measured<u64>, Measured<u64>) = snapshot.map_or_else(
        || {
            let reason: String = match &model.host {
                Loadable::Unavailable(reason) => reason.clone(),
                _ => "not read yet".to_owned(),
            };
            (
                Measured::Unavailable(reason.clone()),
                Measured::Unavailable(reason),
            )
        },
        |snapshot| {
            (
                used_capacity(&snapshot.disk_total, &snapshot.disk_available),
                snapshot.disk_total.clone(),
            )
        },
    );
    let (grid, pressure_level) = grid_and_tone(model, &used, &total);
    let disk: String = capacity_label(&used, &total);
    let (pressure, stale): (String, bool) = pressure_text(&model.host);
    let title: String = if stale {
        format!("{pressure} (stale)")
    } else {
        pressure.clone()
    };
    let stale_note: &str = if stale { " The reading is stale." } else { "" };
    let pressure_line: String = format!("Memory pressure: {pressure}");
    let (agent, agent_detail): (String, Option<&'static str>) = agent_line(&model.agent);
    let fixture: Option<String> = model
        .fixture_name()
        .map(|name| format!("Fixture data: {name}. Values are not measurements."));

    let mut rows: Vec<MenuRow> = Vec::new();
    if let Some(fixture) = &fixture {
        rows.push(MenuRow::Info {
            title: fixture.clone(),
            detail: None,
        });
    }
    rows.extend([
        MenuRow::Info {
            title: if stale {
                format!("{disk} (stale)")
            } else {
                disk.clone()
            },
            detail: None,
        },
        MenuRow::Info {
            title: if stale {
                format!("{pressure_line} (stale)")
            } else {
                pressure_line.clone()
            },
            detail: None,
        },
        MenuRow::Info {
            title: agent.clone(),
            detail: agent_detail.map(str::to_owned),
        },
        MenuRow::Separator,
    ]);

    let pause_text: String = push_pause_rows(model, now, &mut rows);
    rows.push(MenuRow::Separator);
    rows.push(MenuRow::Command {
        title: "Open Svalnir",
        command: MenuCommand::OpenWindow,
        enabled: true,
    });
    rows.push(MenuRow::Command {
        title: "Quit Svalnir",
        command: MenuCommand::Quit,
        enabled: true,
    });

    let fixture_note: String = fixture.map_or_else(String::new, |text| format!(" {text}"));
    let protection_note: String = agent_detail.map_or_else(String::new, |text| format!(" {text}"));
    let label: String = format!(
        "Svalnir.{fixture_note} {disk}. {pressure_line}.{stale_note} {agent}.{protection_note} Automation: {pause_text}."
    );
    StatusView {
        grid,
        pressure: pressure_level,
        title,
        label,
        rows,
    }
}

/// The action of a pause command; `None` for a command that is not one.
#[must_use]
pub const fn pause_action(command: MenuCommand) -> Option<Action> {
    match command {
        MenuCommand::PauseHour => Some(Action::Pause {
            duration: Some(PAUSE_HOUR),
        }),
        MenuCommand::PauseOpen => Some(Action::Pause { duration: None }),
        MenuCommand::Resume => Some(Action::Resume),
        MenuCommand::OpenWindow | MenuCommand::Quit => None,
    }
}

/// The surface that draws a [`StatusView`]: the native item on macOS, or a
/// test surface.
pub trait Surface {
    /// Shows `view`. Returns `false` when the surface cannot show all of it
    /// now (the menu is open): the item applies the view again at the next
    /// update.
    fn apply(&self, view: &StatusView) -> bool;
}

/// The installed item: the surface, the model that it shows, and the
/// function that opens or focuses the main window.
struct StatusItem {
    model: Entity<AppModel>,
    show_window: Rc<dyn Fn(&mut App)>,
    surface: Box<dyn Surface>,
    /// The last view that the surface showed in full.
    last: Option<StatusView>,
    /// The last view that the surface got while its menu was open, so
    /// that the same view is not drawn again at each poll.
    pending: Option<StatusView>,
    _observe: Subscription,
}

impl Global for StatusItem {}

/// Runs `command` of the menu. The surface calls it in a later turn of the
/// main run loop, never inside an update of the application. With no item
/// installed it does nothing.
pub fn run_command(command: MenuCommand, cx: &mut App) {
    let Some(item) = cx.try_global::<StatusItem>() else {
        return;
    };
    let model: Entity<AppModel> = item.model.clone();
    let show_window: Rc<dyn Fn(&mut App)> = Rc::clone(&item.show_window);
    if let Some(action) = pause_action(command) {
        model.update(cx, |model, cx| model.run_action(action, cx));
        return;
    }
    match command {
        MenuCommand::OpenWindow => show_window(cx),
        MenuCommand::Quit => cx.quit(),
        MenuCommand::PauseHour | MenuCommand::PauseOpen | MenuCommand::Resume => {}
    }
}

/// Opens the main window, or brings it to the front, through the installed
/// item. With no item it does nothing: the client then quits when its last
/// window closes, so no window is to open again.
pub fn show_window(cx: &mut App) {
    let Some(item) = cx.try_global::<StatusItem>() else {
        return;
    };
    let show_window: Rc<dyn Fn(&mut App)> = Rc::clone(&item.show_window);
    show_window(cx);
}

/// Puts the view of the model on the surface when it changed.
pub fn update_item(cx: &mut App) {
    let Some(item) = cx.try_global::<StatusItem>() else {
        return;
    };
    let view: StatusView = status_view(item.model.read(cx), SystemTime::now());
    if item.last.as_ref() == Some(&view) || item.pending.as_ref() == Some(&view) {
        return;
    }
    let item: &mut StatusItem = cx.global_mut::<StatusItem>();
    let applied: bool = item.surface.apply(&view);
    // A view that waits for the menu to close is not the last view, so the
    // update after the close applies it.
    if applied {
        item.last = Some(view);
        item.pending = None;
    } else {
        item.last = None;
        item.pending = Some(view);
    }
}

/// Applies the view after the menu closed: the view that waited for the
/// close, or a newer one.
pub fn menu_closed(cx: &mut App) {
    if !cx.has_global::<StatusItem>() {
        return;
    }
    cx.global_mut::<StatusItem>().pending = None;
    update_item(cx);
}

/// Adds the item to the menu bar for `model`. `show_window` opens the main
/// window, or brings it to the front. Returns whether the item exists: on a
/// host that is not macOS, or off the main thread, there is none.
///
/// The model then reads the authority record at each poll, for the pause.
pub fn install(model: Entity<AppModel>, show_window: Rc<dyn Fn(&mut App)>, cx: &mut App) -> bool {
    #[cfg(target_os = "macos")]
    {
        let async_app = cx.to_async();
        let closed_app = cx.to_async();
        let on_closed: Rc<dyn Fn()> = Rc::new(move || {
            let app = closed_app.clone();
            closed_app
                .foreground_executor()
                .spawn(async move { app.update(menu_closed) })
                .detach();
        });
        let on_command: Rc<dyn Fn(MenuCommand)> = Rc::new(move |command: MenuCommand| {
            let app = async_app.clone();
            // The menu calls this from AppKit. A later turn of the run loop
            // runs the command, so that no update of the application is
            // open when it borrows the application.
            async_app
                .foreground_executor()
                .spawn(async move { app.update(|cx| run_command(command, cx)) })
                .detach();
        });
        let Some(surface) = native::StatusSurface::new(on_command, on_closed) else {
            tracing::warn!("the menu bar item needs the main thread; it is not shown");
            return false;
        };
        install_surface(model, show_window, Box::new(surface), cx);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _unused = (model, show_window, cx);
        false
    }
}

/// Installs the item on `surface`: the model reads the authority record at
/// each poll, the surface shows each new view, and the item is removed when
/// the application quits, before GPUI stops its executor, so that no menu
/// callback reaches the application after that.
pub fn install_surface(
    model: Entity<AppModel>,
    show_window: Rc<dyn Fn(&mut App)>,
    surface: Box<dyn Surface>,
    cx: &mut App,
) {
    model.update(cx, |model, cx| {
        model.set_standing_topics(&[Topic::Automation], cx);
    });
    let observe: Subscription = cx.observe(&model, |_, cx| update_item(cx));
    cx.set_global(StatusItem {
        model,
        show_window,
        surface,
        last: None,
        pending: None,
        _observe: observe,
    });
    cx.on_app_quit(|cx| {
        remove(cx);
        async {}
    })
    .detach();
    update_item(cx);
}

/// Removes the item: the surface drops, which takes the native item off
/// the menu bar. Returns whether an item was installed.
pub fn remove(cx: &mut App) -> bool {
    if cx.has_global::<StatusItem>() {
        drop(cx.remove_global::<StatusItem>());
        true
    } else {
        false
    }
}

/// Whether an item is installed.
#[must_use]
pub fn is_installed(cx: &App) -> bool {
    cx.has_global::<StatusItem>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(state: AgentState, old: bool) -> Loadable<AgentSnapshot> {
        let snapshot = std::sync::Arc::new(AgentSnapshot {
            state,
            captured_at: SystemTime::UNIX_EPOCH,
        });
        if old {
            Loadable::Stale(snapshot)
        } else {
            Loadable::Ready(snapshot)
        }
    }

    #[test]
    fn only_a_reporting_agent_has_no_warning() {
        let at = SystemTime::UNIX_EPOCH;
        let (line, detail) = agent_line(&reading(AgentState::Stopped { at }, false));
        assert_eq!(line, "Agent: stopped");
        assert_eq!(detail, Some(NO_PROTECTION));
        let (line, detail) = agent_line(&reading(AgentState::Silent { last: at }, true));
        assert_eq!(line, "Agent: silent (stale)");
        assert_eq!(detail, Some(NO_PROTECTION));
        assert_eq!(
            agent_line(&reading(AgentState::Reporting { since: at }, false)),
            ("Agent: reporting".to_owned(), None)
        );
        assert!(
            agent_line(&Loadable::Unavailable("x".to_owned()))
                .1
                .is_some()
        );
        assert_eq!(agent_line(&Loadable::Loading).0, "Agent: not read yet");
    }

    #[test]
    fn a_tag_maps_back_to_its_command() {
        for command in MenuCommand::ALL {
            assert_eq!(MenuCommand::from_tag(command.tag()), Some(command));
        }
        assert_eq!(MenuCommand::from_tag(0), None);
        assert_eq!(MenuCommand::from_tag(-1), None);
        assert_eq!(MenuCommand::from_tag(6), None);
    }

    fn filled(paints: &[CellPaint]) -> usize {
        paints
            .iter()
            .filter(|paint| matches!(paint, CellPaint::Filled(_)))
            .count()
    }

    #[test]
    fn the_grid_fills_the_rounded_share() {
        let paints = grid_paints(60, 100, None, None);
        assert_eq!(filled(&paints), 12);
        assert_eq!(paints[11], CellPaint::Filled(ItemTone::Brand));
        assert_eq!(paints[12], CellPaint::Empty);
        assert_eq!(filled(&grid_paints(0, 100, None, None)), 0);
        assert_eq!(filled(&grid_paints(100, 100, None, None)), INLINE_CELLS);
    }

    #[test]
    fn the_zones_of_the_disk_guard_tint_the_end_of_the_grid() {
        // 90% used; warning below 20% free (cell 16), critical below 5% free
        // (cell 19).
        let warning = free_zone_start(20, 100);
        let critical = free_zone_start(5, 100);
        assert_eq!((warning, critical), (Some(16), Some(19)));
        let paints = grid_paints(90, 100, warning, critical);
        assert_eq!(paints[15], CellPaint::Filled(ItemTone::Brand));
        assert_eq!(paints[16], CellPaint::Filled(ItemTone::Warning));
        assert_eq!(paints[17], CellPaint::Filled(ItemTone::Warning));
        assert_eq!(paints[18], CellPaint::Tint(ItemTone::Warning));
        assert_eq!(paints[19], CellPaint::Tint(ItemTone::Negative));
        assert_eq!(free_zone_start(0, 100), None);
        assert_eq!(free_zone_start(10, 0), None);
    }

    #[test]
    fn the_default_zones_show_on_a_large_volume() {
        // The defaults: warning below 20 GiB, emergency below 2 GiB, on a
        // volume of 1 TB. Each zone is less than half a cell.
        const GIB: u64 = 1024 * 1024 * 1024;
        let total: u64 = 1_000_000_000_000;
        let warning = free_zone_start(20 * GIB, total);
        let critical = free_zone_start(2 * GIB, total);
        assert_eq!((warning, critical), (Some(19), Some(19)));
        let (warning, critical) = zone_starts(warning, critical);
        assert_eq!((warning, critical), (Some(18), Some(19)));
        let paints = grid_paints(total / 2, total, warning, critical);
        assert_eq!(paints[17], CellPaint::Empty);
        assert_eq!(paints[18], CellPaint::Tint(ItemTone::Warning));
        assert_eq!(paints[19], CellPaint::Tint(ItemTone::Negative));
        assert_eq!(zone_starts(Some(5), Some(0)), (Some(5), Some(0)));
        assert_eq!(zone_starts(Some(19), None), (Some(19), None));
    }

    #[test]
    fn a_stale_grid_is_muted_with_no_zone() {
        let paints = stale_paints(60, 100);
        assert_eq!(paints[11], CellPaint::Muted);
        assert_eq!(paints[12], CellPaint::Empty);
        assert!(
            !paints
                .iter()
                .any(|paint| matches!(paint, CellPaint::Filled(_) | CellPaint::Tint(_)))
        );
    }

    #[test]
    fn each_paint_has_a_color_for_each_menu_bar() {
        let light = MenuBarLook {
            dark: false,
            increase_contrast: false,
        };
        let dark = MenuBarLook {
            dark: true,
            increase_contrast: false,
        };
        let contrast = MenuBarLook {
            dark: true,
            increase_contrast: true,
        };
        // The tones of DESIGN.md §2: brand #0071E3 light, #0A84FF dark.
        let brand_light = paint_rgba(CellPaint::Filled(ItemTone::Brand), light);
        assert!((brand_light[2] - f64::from(0xe3_u8) / 255.0).abs() < 1e-3);
        let brand_dark = paint_rgba(CellPaint::Filled(ItemTone::Brand), dark);
        assert!((brand_dark[2] - 1.0).abs() < 1e-3);
        // An empty cell has the color of the menu bar text.
        assert_eq!(paint_rgba(CellPaint::Empty, light)[..3], [0.0, 0.0, 0.0]);
        assert_eq!(paint_rgba(CellPaint::Empty, dark)[..3], [1.0, 1.0, 1.0]);
        // Increase Contrast makes a tint and an empty cell stronger.
        let tint = CellPaint::Tint(ItemTone::Warning);
        assert!(paint_rgba(tint, contrast)[3] > paint_rgba(tint, dark)[3]);
        assert!(paint_rgba(CellPaint::Empty, contrast)[3] > paint_rgba(CellPaint::Empty, dark)[3]);
        // Increase Contrast gives the dot an outline in the text color.
        assert_eq!(dot_outline_rgba(dark), None);
        assert_eq!(
            dot_outline_rgba(contrast).map(|[r, g, b, _]| [r, g, b]),
            Some([1.0, 1.0, 1.0])
        );
        assert_eq!(pressure_tone(PressureLevel::Critical), ItemTone::Negative);
    }

    #[test]
    fn each_pause_command_has_its_action() {
        assert!(matches!(
            pause_action(MenuCommand::PauseHour),
            Some(Action::Pause { duration: Some(d) }) if d == PAUSE_HOUR
        ));
        assert!(matches!(
            pause_action(MenuCommand::PauseOpen),
            Some(Action::Pause { duration: None })
        ));
        assert!(matches!(
            pause_action(MenuCommand::Resume),
            Some(Action::Resume)
        ));
        assert!(pause_action(MenuCommand::OpenWindow).is_none());
        assert!(pause_action(MenuCommand::Quit).is_none());
    }
}
