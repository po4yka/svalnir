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
        model::{Loadable, Measured, PressureLevel},
        records::PauseRow,
        store::{AppModel, Topic},
    },
    screens::automation::{PAUSE_HOUR, pause_summary},
    ui::data_state::used_capacity,
    viz::{
        alloc::used_cells,
        capacity_grid::{INLINE_CELLS, capacity_label},
    },
};
use gpui_kit::{App, Entity, Global, Subscription};
use std::{rc::Rc, time::SystemTime};

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

/// What the item shows. Two equal views draw the same item, so the item
/// changes only when the view changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    /// The filled state of each of the 20 cells of the inline capacity grid,
    /// or `None` when the used capacity is not known (no grid is drawn).
    pub cells: Option<[bool; INLINE_CELLS]>,
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
fn pressure_text(host: &Loadable<crate::data::model::HostSnapshot>) -> (String, bool) {
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

/// The filled cells of the inline grid for `used` of `total`.
#[must_use]
pub fn grid_cells(used: u64, total: u64) -> [bool; INLINE_CELLS] {
    let filled: usize = used_cells(used, total, INLINE_CELLS);
    let mut cells: [bool; INLINE_CELLS] = [false; INLINE_CELLS];
    for cell in cells.iter_mut().take(filled) {
        *cell = true;
    }
    cells
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
            title: format!("Pause request: {text}"),
            detail: Some(state.sentence(now)),
        });
    }
    pause_text
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
    let cells: Option<[bool; INLINE_CELLS]> = match (&used, &total) {
        (Measured::Value(used), Measured::Value(total)) if *total > 0 => {
            Some(grid_cells(*used, *total))
        }
        _ => None,
    };
    let disk: String = capacity_label(&used, &total);
    let (pressure, stale): (String, bool) = pressure_text(&model.host);
    let title: String = if stale {
        format!("{pressure} (stale)")
    } else {
        pressure.clone()
    };
    let stale_note: &str = if stale { " The reading is stale." } else { "" };
    let pressure_line: String = format!("Memory pressure: {pressure}");

    let mut rows: Vec<MenuRow> = vec![
        MenuRow::Info {
            title: disk.clone(),
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
        MenuRow::Separator,
    ];

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

    let label: String =
        format!("Svalnir. {disk}. {pressure_line}.{stale_note} Automation: {pause_text}.");
    StatusView {
        cells,
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

/// The installed item: the native surface, the model that it shows, and
/// the function that opens or focuses the main window.
struct StatusItem {
    model: Entity<AppModel>,
    show_window: Rc<dyn Fn(&mut App)>,
    #[cfg(target_os = "macos")]
    surface: native::StatusSurface,
    last: Option<StatusView>,
    _observe: Option<Subscription>,
}

impl Global for StatusItem {}

/// Runs `command` of the menu. The surface calls it in a later turn of the
/// main run loop, never inside an update of the application.
fn run_command(command: MenuCommand, cx: &mut App) {
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
fn update_item(cx: &mut App) {
    let Some(item) = cx.try_global::<StatusItem>() else {
        return;
    };
    let view: StatusView = status_view(item.model.read(cx), SystemTime::now());
    if item.last.as_ref() == Some(&view) {
        return;
    }
    let item: &mut StatusItem = cx.global_mut::<StatusItem>();
    #[cfg(target_os = "macos")]
    let applied: bool = item.surface.apply(&view);
    #[cfg(not(target_os = "macos"))]
    let applied: bool = true;
    // A view that waits for the menu to close is not the last view, so the
    // update after the close applies it.
    item.last = applied.then_some(view);
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
                .spawn(async move { app.update(update_item) })
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
        model.update(cx, |model, cx| {
            model.set_standing_topics(&[Topic::Automation], cx);
        });
        let observe: Subscription = cx.observe(&model, |_, cx| update_item(cx));
        cx.set_global(StatusItem {
            model,
            show_window,
            surface,
            last: None,
            _observe: Some(observe),
        });
        update_item(cx);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _unused = (model, show_window, cx);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_maps_back_to_its_command() {
        for command in MenuCommand::ALL {
            assert_eq!(MenuCommand::from_tag(command.tag()), Some(command));
        }
        assert_eq!(MenuCommand::from_tag(0), None);
        assert_eq!(MenuCommand::from_tag(-1), None);
        assert_eq!(MenuCommand::from_tag(6), None);
    }

    #[test]
    fn the_grid_fills_the_rounded_share() {
        let cells = grid_cells(60, 100);
        assert_eq!(cells.iter().filter(|cell| **cell).count(), 12);
        assert!(cells[11] && !cells[12]);
        assert!(grid_cells(0, 100).iter().all(|cell| !cell));
        assert!(grid_cells(100, 100).iter().all(|cell| *cell));
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
