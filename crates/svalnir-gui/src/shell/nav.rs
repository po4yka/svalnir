//! Screens, navigation actions, and key bindings.

use gpui_kit::{Action, App, KeyBinding, actions, component::IconName};

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
        CloseWindow
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
}
