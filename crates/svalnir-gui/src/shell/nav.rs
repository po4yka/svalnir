//! Screens, navigation actions, and key bindings.

use gpui_kit::{
    Action, App, KeyBinding, Pixels, Styled as _, actions, canvas, component::IconName, px,
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// A screen of the client, in sidebar order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Screen {
    /// Overview.
    Overview,
    /// Storage.
    Storage,
    /// Memory.
    Memory,
    /// Applications.
    Applications,
    /// Automation.
    Automation,
    /// History.
    History,
    /// Diagnostics.
    Diagnostics,
}

impl Screen {
    /// All screens in sidebar order.
    pub const ALL: [Self; 7] = [
        Self::Overview,
        Self::Storage,
        Self::Memory,
        Self::Applications,
        Self::Automation,
        Self::History,
        Self::Diagnostics,
    ];

    /// Visible title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Storage => "Storage",
            Self::Memory => "Memory",
            Self::Applications => "Applications",
            Self::Automation => "Automation",
            Self::History => "History",
            Self::Diagnostics => "Diagnostics",
        }
    }

    /// Lucide icon from the default `gpui-kit` bundle.
    pub fn icon(self) -> IconName {
        match self {
            Self::Overview => IconName::LayoutDashboard,
            Self::Storage => IconName::HardDrive,
            Self::Memory => IconName::MemoryStick,
            Self::Applications => IconName::Cpu,
            Self::Automation => IconName::Settings2,
            Self::History => IconName::FileText,
            Self::Diagnostics => IconName::Inspector,
        }
    }

    /// The group of the sidebar that holds the screen.
    pub const fn group(self) -> NavGroup {
        match self {
            Self::Overview | Self::Storage | Self::Memory | Self::Applications => NavGroup::Monitor,
            Self::Automation => NavGroup::Control,
            Self::History | Self::Diagnostics => NavGroup::Records,
        }
    }

    /// The sections of the screen, in the order of the page.
    pub const fn sections(self) -> &'static [Section] {
        match self {
            Self::Overview => &[
                Section::Headroom,
                Section::ThisSession,
                Section::StartupVolume,
                Section::Agent,
                Section::Policies,
                Section::LatestIntervention,
            ],
            Self::Storage => &[Section::StorageStartupVolume, Section::FolderSizes],
            _ => &[],
        }
    }

    /// Position in [`Screen::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Storage => 1,
            Self::Memory => 2,
            Self::Applications => 3,
            Self::Automation => 4,
            Self::History => 5,
            Self::Diagnostics => 6,
        }
    }
}

/// A group of screens in the sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NavGroup {
    /// Screens that show the state of the host.
    Monitor,
    /// Screens that change how the agent acts.
    Control,
    /// Screens that show what happened.
    Records,
}

impl NavGroup {
    /// All groups in sidebar order.
    pub const ALL: [Self; 3] = [Self::Monitor, Self::Control, Self::Records];

    /// Visible label of the group.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Monitor => "Monitor",
            Self::Control => "Control",
            Self::Records => "Records",
        }
    }

    /// The screens of the group, in order.
    pub const fn screens(self) -> &'static [Screen] {
        match self {
            Self::Monitor => &[
                Screen::Overview,
                Screen::Storage,
                Screen::Memory,
                Screen::Applications,
            ],
            Self::Control => &[Screen::Automation],
            Self::Records => &[Screen::History, Screen::Diagnostics],
        }
    }
}

/// A section of a screen: one card that the sidebar can scroll to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Section {
    /// Overview: the headroom dial.
    Headroom,
    /// Overview: the session chart.
    ThisSession,
    /// Overview: the startup volume.
    StartupVolume,
    /// Overview: the agent.
    Agent,
    /// Overview: the policies.
    Policies,
    /// Overview: the latest intervention.
    LatestIntervention,
    /// Storage: the startup volume.
    StorageStartupVolume,
    /// Storage: the folder sizes.
    FolderSizes,
}

impl Section {
    /// Visible title of the section.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Headroom => "Headroom",
            Self::ThisSession => "This session",
            Self::StartupVolume | Self::StorageStartupVolume => "Startup volume",
            Self::Agent => "Agent",
            Self::Policies => "Policies",
            Self::LatestIntervention => "Latest intervention",
            Self::FolderSizes => "Folder sizes",
        }
    }

    /// The screen that holds the section.
    pub const fn screen(self) -> Screen {
        match self {
            Self::Headroom
            | Self::ThisSession
            | Self::StartupVolume
            | Self::Agent
            | Self::Policies
            | Self::LatestIntervention => Screen::Overview,
            Self::StorageStartupVolume | Self::FolderSizes => Screen::Storage,
        }
    }

    /// Stable id of the section. It is the element id of the card wrapper on
    /// the screen, so tests can find the card. The nested sidebar item has no
    /// such id, because the component sets the ids of its rows.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Headroom => "nav-overview-headroom",
            Self::ThisSession => "nav-overview-this-session",
            Self::StartupVolume => "nav-overview-startup-volume",
            Self::Agent => "nav-overview-agent",
            Self::Policies => "nav-overview-policies",
            Self::LatestIntervention => "nav-overview-latest-intervention",
            Self::StorageStartupVolume => "nav-storage-startup-volume",
            Self::FolderSizes => "nav-storage-folder-sizes",
        }
    }
}

/// The label of a sidebar row. A narrow row shows no text; the component
/// uses the label as the tooltip, so the label carries the name, the key, and
/// the text of the status mark.
pub fn item_label(screen: Screen, narrow: bool, mark: Option<&str>) -> String {
    if !narrow {
        return screen.title().to_owned();
    }
    let mut label: String = format!("{}  \u{2318}{}", screen.title(), screen.index() + 1);
    if let Some(mark) = mark {
        label.push_str(" \u{b7} ");
        label.push_str(mark);
    }
    label
}

/// The accessible label of a sidebar row.
pub fn item_accessible_label(screen: Screen, mark: Option<&str>) -> String {
    match mark {
        Some(mark) => format!("Show {}, {mark}", screen.title()),
        None => format!("Show {}", screen.title()),
    }
}

/// The screen after `current`, or `None` at the end. The order does not wrap.
pub fn next_screen(current: Screen) -> Option<Screen> {
    Screen::ALL.get(current.index() + 1).copied()
}

/// The screen before `current`, or `None` at the start. The order does not wrap.
pub fn previous_screen(current: Screen) -> Option<Screen> {
    current
        .index()
        .checked_sub(1)
        .and_then(|index| Screen::ALL.get(index).copied())
}

/// Window width in points below which the sidebar is narrow by default.
pub const NARROW_BELOW: f32 = 900.0;
/// Width of the wide sidebar in points.
pub const SIDEBAR_WIDE_WIDTH: f32 = 256.0;
/// Width of the narrow sidebar in points.
pub const SIDEBAR_NARROW_WIDTH: f32 = 48.0;

/// Whether the sidebar is narrow. `choice` is the choice of the user:
/// `Some(true)` is narrow and `Some(false)` is wide.
pub fn sidebar_narrow(window_width: f32, choice: Option<bool>) -> bool {
    choice.unwrap_or(window_width < NARROW_BELOW)
}

/// The choice of the user after the window width changed from `previous` to
/// `new`. The choice ends when the width crosses [`NARROW_BELOW`].
pub fn choice_after_resize(choice: Option<bool>, previous: f32, new: f32) -> Option<bool> {
    if (previous < NARROW_BELOW) == (new < NARROW_BELOW) {
        choice
    } else {
        None
    }
}

/// The scroll offset that puts a card `padding` below the top of the content
/// area. All values are in points; `current` is the offset now (zero or
/// negative), `card_top` and `area_top` are in window coordinates, and
/// `max_offset` is the scroll range (zero or positive).
pub fn scroll_offset_for(
    current: f32,
    card_top: f32,
    area_top: f32,
    padding: f32,
    max_offset: f32,
) -> f32 {
    (current + area_top + padding - card_top)
        .max(-max_offset.max(0.0))
        .min(0.0)
}

#[derive(Debug, Default)]
struct NavLayoutState {
    tops: HashMap<Section, Pixels>,
    narrow: bool,
}

/// State that the window shares with its screens: the top of each section
/// card in window coordinates, and whether the sidebar is narrow.
#[derive(Clone, Debug, Default)]
pub struct NavLayout(Rc<RefCell<NavLayoutState>>);

impl NavLayout {
    /// Records the top of a section card.
    pub fn set_top(&self, section: Section, top: Pixels) {
        self.0.borrow_mut().tops.insert(section, top);
    }

    /// The last recorded top of a section card.
    pub fn top(&self, section: Section) -> Option<Pixels> {
        self.0.borrow().tops.get(&section).copied()
    }

    /// Forgets the recorded tops of the sections of `screen`. Its cards
    /// record them again when they paint.
    pub fn clear_screen(&self, screen: Screen) {
        self.0
            .borrow_mut()
            .tops
            .retain(|section, _| section.screen() != screen);
    }

    /// Records whether the sidebar is narrow.
    pub fn set_narrow(&self, narrow: bool) {
        self.0.borrow_mut().narrow = narrow;
    }

    /// The width of the sidebar in points, with its border.
    pub fn sidebar_width(&self) -> f32 {
        // The border is inside the width: the component sets the width and
        // the border on the same element.
        if self.0.borrow().narrow {
            SIDEBAR_NARROW_WIDTH
        } else {
            SIDEBAR_WIDE_WIDTH
        }
    }

    /// A zero-size element for the start of a card wrapper. It records the
    /// top of the card when the frame is prepared.
    pub fn marker(&self, section: Section) -> impl gpui_kit::IntoElement + use<> {
        let layout: Self = self.clone();
        canvas(
            move |bounds, _, _| layout.set_top(section, bounds.origin.y),
            |_, (), _, _| {},
        )
        .absolute()
        .top(px(0.0))
        .left(px(0.0))
        .size(px(0.0))
    }
}

/// Selects a screen (Cmd+1 to Cmd+7).
#[derive(Clone, Debug, PartialEq, Eq, Action)]
#[action(namespace = svalnir, no_json)]
pub struct SelectScreen {
    /// The screen to show.
    pub screen: Screen,
}

actions!(
    svalnir,
    [
        /// Refreshes the data of the active screen (Cmd+R).
        Refresh,
        /// Closes the window (Cmd+W).
        CloseWindow,
        /// Collapses or expands the sidebar (Ctrl+Cmd+S).
        ToggleSidebar,
        /// Shows the next screen (Cmd+]).
        NextScreen,
        /// Shows the screen before (Cmd+[).
        PreviousScreen
    ]
);

/// Key context of the main window.
pub const KEY_CONTEXT: &str = "SvalnirMainWindow";

/// Registers the key bindings of the main window.
pub fn bind_keys(cx: &mut App) {
    const SELECT_KEYS: [&str; 7] = [
        "cmd-1", "cmd-2", "cmd-3", "cmd-4", "cmd-5", "cmd-6", "cmd-7",
    ];
    let mut bindings: Vec<KeyBinding> = Screen::ALL
        .iter()
        .zip(SELECT_KEYS)
        .map(|(&screen, keys)| KeyBinding::new(keys, SelectScreen { screen }, Some(KEY_CONTEXT)))
        .collect();
    bindings.push(KeyBinding::new("cmd-r", Refresh, Some(KEY_CONTEXT)));
    bindings.push(KeyBinding::new("cmd-w", CloseWindow, Some(KEY_CONTEXT)));
    bindings.push(KeyBinding::new(
        "ctrl-cmd-s",
        ToggleSidebar,
        Some(KEY_CONTEXT),
    ));
    bindings.push(KeyBinding::new("cmd-]", NextScreen, Some(KEY_CONTEXT)));
    bindings.push(KeyBinding::new("cmd-[", PreviousScreen, Some(KEY_CONTEXT)));
    cx.bind_keys(bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_matches_all() {
        for (position, screen) in Screen::ALL.iter().enumerate() {
            assert_eq!(screen.index(), position);
        }
    }

    #[test]
    fn groups_hold_every_screen_once_in_order() {
        let listed: Vec<Screen> = NavGroup::ALL
            .iter()
            .flat_map(|group| group.screens().iter().copied())
            .collect();
        assert_eq!(listed, Screen::ALL.to_vec());
        for group in NavGroup::ALL {
            for screen in group.screens() {
                assert_eq!(screen.group(), group);
            }
        }
        let labels: Vec<&str> = NavGroup::ALL.iter().map(|group| group.label()).collect();
        assert_eq!(labels, ["Monitor", "Control", "Records"]);
    }

    #[test]
    fn sections_belong_to_their_screen_and_have_unique_ids() {
        let mut ids: Vec<&str> = Vec::new();
        for screen in Screen::ALL {
            for section in screen.sections() {
                assert_eq!(section.screen(), screen);
                ids.push(section.id());
            }
        }
        assert_eq!(ids.len(), 8);
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 8);
        let titles: Vec<&str> = Screen::Overview
            .sections()
            .iter()
            .map(|section| section.title())
            .collect();
        assert_eq!(
            titles,
            [
                "Headroom",
                "This session",
                "Startup volume",
                "Agent",
                "Policies",
                "Latest intervention"
            ]
        );
    }

    #[test]
    fn next_and_previous_stop_at_the_ends() {
        assert_eq!(next_screen(Screen::Overview), Some(Screen::Storage));
        assert_eq!(next_screen(Screen::Diagnostics), None);
        assert_eq!(previous_screen(Screen::Storage), Some(Screen::Overview));
        assert_eq!(previous_screen(Screen::Overview), None);
    }

    #[test]
    fn the_default_width_follows_900() {
        assert!(sidebar_narrow(899.0, None));
        assert!(!sidebar_narrow(900.0, None));
    }

    #[test]
    fn the_choice_wins_on_both_sides() {
        assert!(sidebar_narrow(1200.0, Some(true)));
        assert!(!sidebar_narrow(800.0, Some(false)));
    }

    #[test]
    fn the_choice_ends_only_when_the_width_crosses_900() {
        assert_eq!(choice_after_resize(Some(true), 1000.0, 800.0), None);
        assert_eq!(choice_after_resize(Some(false), 800.0, 1000.0), None);
        assert_eq!(choice_after_resize(Some(true), 1000.0, 950.0), Some(true));
        assert_eq!(choice_after_resize(Some(false), 800.0, 700.0), Some(false));
        assert_eq!(choice_after_resize(Some(true), 899.0, 900.0), None);
        assert_eq!(choice_after_resize(None, 1000.0, 800.0), None);
    }

    #[test]
    fn the_scroll_offset_puts_the_card_below_the_padding_and_clamps() {
        // The card is 500 below the area top at offset 0.
        assert!((scroll_offset_for(0.0, 600.0, 100.0, 24.0, 1000.0) + 476.0).abs() < 1e-3);
        // The range ends the scroll.
        assert!((scroll_offset_for(0.0, 600.0, 100.0, 24.0, 200.0) + 200.0).abs() < 1e-3);
        // A card above the wanted place never gives a positive offset.
        assert!(scroll_offset_for(0.0, 110.0, 100.0, 24.0, 200.0).abs() < 1e-3);
        // From a scrolled position the offset is relative to it.
        assert!((scroll_offset_for(-300.0, 300.0, 100.0, 24.0, 1000.0) + 476.0).abs() < 1e-3);
    }

    #[test]
    fn row_labels_carry_name_key_and_mark() {
        assert_eq!(item_label(Screen::Overview, false, None), "Overview");
        assert_eq!(
            item_label(Screen::Overview, true, None),
            "Overview  \u{2318}1"
        );
        assert_eq!(
            item_label(Screen::Memory, true, Some("Memory pressure: Warning")),
            "Memory  \u{2318}3 \u{b7} Memory pressure: Warning"
        );
        assert_eq!(
            item_label(Screen::Storage, true, Some("Scan in progress")),
            "Storage  \u{2318}2 \u{b7} Scan in progress"
        );
        assert_eq!(item_accessible_label(Screen::Memory, None), "Show Memory");
        assert_eq!(
            item_accessible_label(Screen::Storage, Some("Scan in progress")),
            "Show Storage, Scan in progress"
        );
    }

    #[test]
    fn clear_screen_forgets_only_that_screen() {
        let layout = NavLayout::default();
        layout.set_top(Section::Headroom, px(1.0));
        layout.set_top(Section::FolderSizes, px(2.0));
        layout.clear_screen(Screen::Storage);
        assert!(layout.top(Section::Headroom).is_some());
        assert!(layout.top(Section::FolderSizes).is_none());
    }
}
