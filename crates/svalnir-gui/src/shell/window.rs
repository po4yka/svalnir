//! The root view: title bar, sidebar, content area, and status line.

use super::nav::{
    self, CloseWindow, KEY_CONTEXT, NavGroup, NavLayout, NextScreen, PreviousScreen, Refresh,
    Screen, Section, SelectScreen, ToggleSidebar, choice_after_resize, item_accessible_label,
    item_label, next_screen, previous_screen, scroll_offset_for, sidebar_narrow,
};
use crate::{
    data::{
        model::{AgentState, Loadable, Measured, PressureLevel, ScanState},
        store::{AppModel, Topic},
    },
    platform::DisplayAccessibility,
    screens::{
        applications::ApplicationsScreen, automation::AutomationScreen,
        diagnostics::DiagnosticsScreen, history::HistoryScreen, memory::MemoryScreen,
        overview::OverviewScreen, storage::StorageScreen,
    },
    theme::{
        glow,
        tokens::{self, Tokens, to_hsla},
    },
    ui::data_state::capture_age_text,
};
use gpui_kit::{
    AnyElement, AnyView, AppContext as _, ClickEvent, Context, Entity, EntityId, FocusHandle,
    FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, Render, Rgba, Role,
    ScrollHandle, StatefulInteractiveElement, Styled, TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, Icon, IconName, Sizable as _, TitleBar, h_flex,
        sidebar::{Sidebar, SidebarGroup, SidebarMenu, SidebarMenuItem, SidebarToggleButton},
        spinner::Spinner,
        tooltip::Tooltip,
        v_flex,
    },
    div, point, px,
};
use std::time::SystemTime;

/// The main window view. It keeps one entity per screen so that screen state
/// survives navigation.
#[derive(Debug)]
pub struct MainWindow {
    active: Screen,
    screens: Vec<AnyView>,
    focus: FocusHandle,
    model: Entity<AppModel>,
    /// The display settings, read when the window becomes active.
    display: DisplayAccessibility,
    overview: Entity<OverviewScreen>,
    storage: Entity<StorageScreen>,
    memory: Entity<MemoryScreen>,
    applications: Entity<ApplicationsScreen>,
    automation: Entity<AutomationScreen>,
    history: Entity<HistoryScreen>,
    diagnostics: Entity<DiagnosticsScreen>,
    /// The choice of the user for the sidebar width: `Some(true)` is narrow.
    sidebar_choice: Option<bool>,
    /// The window width at the last render.
    last_width: f32,
    scroll: ScrollHandle,
    nav: NavLayout,
    /// A section scroll that waits for the card tops, with the frames left.
    pending_scroll: Option<(Section, u8)>,
    /// The scroll offset of each screen that is not shown, in points.
    offsets: [f32; 7],
}

impl MainWindow {
    /// Creates the view with all screens built; Overview is active.
    pub fn new(model: Entity<AppModel>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let overview: Entity<OverviewScreen> = cx.new(|cx| OverviewScreen::new(model.clone(), cx));
        let storage: Entity<StorageScreen> = cx.new(|cx| StorageScreen::new(model.clone(), cx));
        let nav: NavLayout = NavLayout::default();
        overview.update(cx, |screen, _| screen.set_nav(nav.clone()));
        storage.update(cx, |screen, _| screen.set_nav(nav.clone()));
        let memory: Entity<MemoryScreen> = cx.new(|cx| MemoryScreen::new(model.clone(), cx));
        let applications: Entity<ApplicationsScreen> =
            cx.new(|cx| ApplicationsScreen::new(model.clone(), cx));
        let automation: Entity<AutomationScreen> =
            cx.new(|cx| AutomationScreen::new(model.clone(), cx));
        let history: Entity<HistoryScreen> = cx.new(|cx| HistoryScreen::new(model.clone(), cx));
        let diagnostics: Entity<DiagnosticsScreen> =
            cx.new(|cx| DiagnosticsScreen::new(model.clone(), cx));
        let screens: Vec<AnyView> = Screen::ALL
            .iter()
            .map(|&screen| match screen {
                Screen::Overview => AnyView::from(overview.clone()),
                Screen::Storage => AnyView::from(storage.clone()),
                Screen::Memory => AnyView::from(memory.clone()),
                Screen::Applications => AnyView::from(applications.clone()),
                Screen::Automation => AnyView::from(automation.clone()),
                Screen::History => AnyView::from(history.clone()),
                Screen::Diagnostics => AnyView::from(diagnostics.clone()),
            })
            .collect();
        let focus: FocusHandle = cx.focus_handle();
        window.focus(&focus, cx);
        cx.observe(&model, |this, _, cx| {
            this.update_glow(cx);
            cx.notify();
        })
        .detach();
        let active: bool = window.is_window_active();
        model.update(cx, |model, cx| {
            model.set_active(active, cx);
            // The window opens on Overview; `select` sets the topics of each
            // later screen.
            model.set_topics(topics_of(Screen::Overview), cx);
        });
        cx.observe_window_activation(window, |this, window, cx| {
            let active: bool = window.is_window_active();
            this.model
                .update(cx, |model, cx| model.set_active(active, cx));
            // The user changes a display setting in a different application,
            // so the window reads the settings when it becomes active.
            if active {
                this.display = DisplayAccessibility::read();
                this.update_glow(cx);
            }
        })
        .detach();
        let display: DisplayAccessibility = DisplayAccessibility::read();
        glow::set(glow::decide(display, true), cx);
        Self {
            active: Screen::Overview,
            screens,
            focus,
            model,
            display,
            overview,
            storage,
            memory,
            applications,
            automation,
            history,
            diagnostics,
            sidebar_choice: None,
            last_width: f32::from(window.viewport_size().width),
            scroll: ScrollHandle::new(),
            nav,
            pending_scroll: None,
            offsets: [0.0; 7],
        }
    }

    /// Sets the choice of the user for the sidebar width (`Some(true)` is
    /// narrow). A launch option uses it.
    pub fn set_sidebar_choice(&mut self, choice: Option<bool>, cx: &mut Context<Self>) {
        self.sidebar_choice = choice;
        cx.notify();
    }

    /// Whether the sidebar is narrow in `window` now.
    pub fn sidebar_narrow(&self, window: &Window) -> bool {
        sidebar_narrow(f32::from(window.viewport_size().width), self.sidebar_choice)
    }

    fn toggle_sidebar(&mut self, window: &Window, cx: &mut Context<Self>) {
        self.sidebar_choice = Some(!self.sidebar_narrow(window));
        cx.notify();
    }

    /// The vertical scroll offset of the content in points (zero or negative).
    pub fn scroll_offset_y(&self) -> f32 {
        f32::from(self.scroll.offset().y)
    }

    /// Shows the screen of `section` and scrolls the content so that the
    /// card of the section starts below the padding. The card tops of a
    /// screen are known after it paints, so the scroll waits in
    /// `pending_scroll` and `render` retries it for at most
    /// `SCROLL_TRIES` frames.
    pub fn scroll_to_section(
        &mut self,
        section: Section,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.select(section.screen(), cx);
        self.pending_scroll = Some((section, SCROLL_TRIES));
        cx.notify();
    }

    /// One step of the pending scroll, before a frame is laid out. The tops
    /// are from the last paint. A screen that just opened has none, so the
    /// step asks for one more frame and tries again.
    fn step_pending_scroll(&mut self, window: &mut Window) {
        let Some((section, left)) = self.pending_scroll else {
            return;
        };
        if self.active != section.screen() || self.apply_scroll(section) || left <= 1 {
            self.pending_scroll = None;
        } else {
            self.pending_scroll = Some((section, left - 1));
            window.request_animation_frame();
        }
    }

    /// Scrolls to the card of `section` from the current offset. Returns
    /// false when the card top is not known.
    fn apply_scroll(&self, section: Section) -> bool {
        let Some(top) = self.nav.top(section) else {
            return false;
        };
        let offset = self.scroll.offset();
        let y: f32 = scroll_offset_for(
            f32::from(offset.y),
            f32::from(top),
            f32::from(self.scroll.bounds().origin.y),
            f32::from(tokens::CONTENT_PADDING),
            f32::from(self.scroll.max_offset().y),
        );
        self.scroll.set_offset(point(offset.x, px(y)));
        true
    }

    /// The status line: source, agent state, and the age of the data.
    fn status_text(&self, cx: &Context<Self>) -> String {
        let model: &AppModel = self.model.read(cx);
        let agent: &str = match &model.agent {
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => snapshot.state.predicate(),
            Loadable::Loading => "loading",
            Loadable::Unavailable(_) => "unavailable",
        };
        let updated: String = match &model.host {
            // The age rule of the screens: a capture time well in the future
            // has no known age, and is not shown as 0 s.
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => {
                capture_age_text(snapshot.captured_at, SystemTime::now())
            }
            Loadable::Loading | Loadable::Unavailable(_) => "no data".to_owned(),
        };
        format!(
            "{} \u{b7} agent {agent} \u{b7} updated {updated}",
            model.source_label()
        )
    }

    /// The text of the banner above the content, when one applies.
    fn banner_text(&self, cx: &Context<Self>) -> Option<String> {
        let model: &AppModel = self.model.read(cx);
        if let Some(name) = model.fixture_name() {
            return Some(format!(
                "Fixture data: {name}. Values are not measurements."
            ));
        }
        match &model.agent {
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot)
                if matches!(
                    snapshot.state,
                    AgentState::NoJournal
                        | AgentState::NoRecord
                        | AgentState::Silent { .. }
                        | AgentState::Stopped { .. }
                ) =>
            {
                Some(
                    "No recent status of an agent. Values come from this window's own measurement; no automatic protection is known to be active."
                        .to_owned(),
                )
            }
            _ => None,
        }
    }

    fn banner(text: String, tokens: &Tokens) -> AnyElement {
        h_flex()
            .id("data-banner")
            .role(Role::Status)
            .test_support()
            .aria_label(text.clone())
            .gap(tokens::SPACE_2)
            .items_center()
            .px(tokens::SPACE_3)
            .py(tokens::SPACE_2)
            .mb(tokens::SPACE_3)
            .rounded(px(12.0))
            .bg(to_hsla(tokens.surface))
            .text_size(px(13.0))
            .text_color(to_hsla(tokens.warning))
            .child(Icon::new(IconName::TriangleAlert).size_4())
            .child(text)
            .into_any_element()
    }

    /// Decides the glow from the display settings and the memory pressure.
    fn update_glow(&self, cx: &mut Context<Self>) {
        let pressure_normal: bool = self.model.read(cx).host.value().is_none_or(|host| {
            !matches!(
                host.pressure,
                Measured::Value(PressureLevel::Warning | PressureLevel::Critical)
            )
        });
        glow::set(glow::decide(self.display, pressure_normal), cx);
    }

    /// Sets the display settings and decides the glow again. The window
    /// reads the settings of the host when it becomes active; a test gives
    /// fixed settings.
    pub fn set_display(&mut self, display: DisplayAccessibility, cx: &mut Context<Self>) {
        self.display = display;
        self.update_glow(cx);
        cx.notify();
    }

    /// The model that the window reads.
    #[must_use]
    pub fn model(&self) -> &Entity<AppModel> {
        &self.model
    }

    /// The active screen.
    pub fn active(&self) -> Screen {
        self.active
    }

    /// The id of the retained entity of `screen`.
    pub fn screen_entity_id(&self, screen: Screen) -> Option<EntityId> {
        self.screens.get(screen.index()).map(AnyView::entity_id)
    }

    /// Selects the layout of the folder chart of the Storage screen.
    pub fn set_storage_layout(
        &mut self,
        layout: crate::viz::storage_layouts::StorageLayout,
        cx: &mut Context<Self>,
    ) {
        self.storage
            .update(cx, |storage, cx| storage.set_layout(layout, cx));
    }

    /// Opens the detail of the operation `operation` on History.
    pub fn show_history_detail(&mut self, operation: &str, cx: &mut Context<Self>) {
        self.history
            .update(cx, |history, cx| history.show_detail(operation, cx));
    }

    /// Shows `screen`.
    pub fn select(&mut self, screen: Screen, cx: &mut Context<Self>) {
        if self.active != screen {
            // Each screen keeps its own scroll position.
            let offset = self.scroll.offset();
            self.offsets[self.active.index()] = f32::from(offset.y);
            self.scroll
                .set_offset(point(offset.x, px(self.offsets[screen.index()])));
            // The tops of the incoming screen are from an older paint.
            self.nav.clear_screen(screen);
            if self
                .pending_scroll
                .is_some_and(|(section, _)| section.screen() != screen)
            {
                self.pending_scroll = None;
            }
            self.active = screen;
            match screen {
                Screen::Overview => self.overview.update(cx, OverviewScreen::activate),
                Screen::Storage => self.storage.update(cx, StorageScreen::activate),
                Screen::Memory => self.memory.update(cx, MemoryScreen::activate),
                Screen::Applications => self.applications.update(cx, ApplicationsScreen::activate),
                Screen::Automation => self.automation.update(cx, AutomationScreen::activate),
                Screen::History => self.history.update(cx, HistoryScreen::activate),
                Screen::Diagnostics => self.diagnostics.update(cx, DiagnosticsScreen::activate),
            }
            // The model reads the topics of a screen only while it is in front.
            self.model
                .update(cx, |model, cx| model.set_topics(topics_of(screen), cx));
            cx.notify();
        }
    }

    /// The status mark of a screen: the accessible label and the element.
    fn mark(&self, screen: Screen, cx: &Context<Self>, tokens: &Tokens) -> Option<(String, Mark)> {
        let model: &AppModel = self.model.read(cx);
        match screen {
            Screen::Storage if matches!(model.scan, ScanState::Running { .. }) => Some((
                "Scan in progress".to_owned(),
                Mark::Spinner(to_hsla(tokens.brand)),
            )),
            Screen::Memory => {
                let Loadable::Ready(host) = &model.host else {
                    return None;
                };
                let name: &str = pressure_mark_name(&host.pressure)?;
                let color: Hsla = if name == "Critical" {
                    to_hsla(tokens.negative)
                } else {
                    to_hsla(tokens.warning)
                };
                Some((format!("Memory pressure: {name}"), Mark::Dot(color)))
            }
            _ => None,
        }
    }

    fn nav_item(
        &self,
        screen: Screen,
        narrow: bool,
        tokens: &Tokens,
        cx: &mut Context<Self>,
    ) -> SidebarMenuItem {
        let mark: Option<(String, Mark)> = self.mark(screen, cx, tokens);
        let mark_text: Option<&str> = mark.as_ref().map(|(text, _)| text.as_str());
        let label: String = item_label(screen, narrow, mark_text);
        let accessible: String = item_accessible_label(screen, mark_text);
        let mut item: SidebarMenuItem = SidebarMenuItem::new(label)
            .icon(screen.icon())
            .active(self.active == screen)
            .accessibility_label(accessible)
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.select(screen, cx);
            }));
        if let Some((text, mark)) = mark {
            let id: &'static str = match screen {
                Screen::Storage => "nav-mark-storage",
                _ => "nav-mark-memory",
            };
            item = item.suffix(move |_, _| mark.element(id, &text));
        }
        if !screen.sections().is_empty() {
            item = item
                .default_open(self.active == screen)
                .click_to_open(true)
                .children(screen.sections().iter().map(|&section| {
                    SidebarMenuItem::new(section.title())
                        .accessibility_label(format!(
                            "Show {} in {}",
                            section.title(),
                            screen.title()
                        ))
                        .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                            this.scroll_to_section(section, window, cx);
                        }))
                }));
        }
        item
    }

    fn sidebar_header(narrow: bool, cx: &mut Context<Self>) -> AnyElement {
        let name = div()
            .id("nav-app-name")
            .text_size(px(14.0))
            .font_weight(FontWeight::SEMIBOLD)
            .child("Svalnir");
        h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .children((!narrow).then_some(name))
            .child(
                SidebarToggleButton::new()
                    .collapsed(narrow)
                    .accessibility_label(if narrow {
                        "Expand sidebar"
                    } else {
                        "Collapse sidebar"
                    })
                    .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                        this.toggle_sidebar(window, cx);
                    })),
            )
            .into_any_element()
    }

    /// The footer row: a dot in the tone of the agent state and one line.
    fn agent_footer(&self, narrow: bool, tokens: &Tokens, cx: &Context<Self>) -> AnyElement {
        let model: &AppModel = self.model.read(cx);
        let (text, color): (String, Rgba) = match &model.agent {
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => (
                agent_line(
                    snapshot.state.predicate(),
                    matches!(model.agent, Loadable::Stale(_)),
                ),
                match snapshot.state {
                    _ if matches!(model.agent, Loadable::Stale(_)) => tokens.muted_foreground,
                    AgentState::Reporting { .. } => tokens.positive,
                    AgentState::NoJournal
                    | AgentState::NoRecord
                    | AgentState::Silent { .. }
                    | AgentState::Stopped { .. } => tokens.warning,
                    AgentState::Unknown(_) => tokens.muted_foreground,
                },
            ),
            Loadable::Loading => ("Agent loading".to_owned(), tokens.muted_foreground),
            Loadable::Unavailable(_) => ("Agent unavailable".to_owned(), tokens.muted_foreground),
        };
        let tip: String = text.clone();
        let row = h_flex()
            .id("nav-agent")
            .role(Role::Status)
            .test_support()
            .aria_label(text.clone())
            .w_full()
            .h(px(24.0))
            .items_center()
            .gap(tokens::SPACE_2)
            .text_size(px(12.0))
            .text_color(to_hsla(tokens.muted_foreground))
            .child(
                div()
                    .flex_shrink_0()
                    .size(px(8.0))
                    .rounded_full()
                    .bg(to_hsla(color)),
            );
        if narrow {
            row.justify_center()
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .into_any_element()
        } else {
            row.child(text).into_any_element()
        }
    }
}

/// The reads that only `screen` needs. The capability probes of Diagnostics
/// run when the screen comes to the front and at an explicit refresh.
/// Overview and Storage read the controller record for its open incidents,
/// which stop their continuous effects.
#[must_use]
pub const fn topics_of(screen: Screen) -> &'static [Topic] {
    match screen {
        Screen::Overview | Screen::Storage => &[Topic::Controller],
        Screen::Memory => &[Topic::Memory, Topic::Processes, Topic::Controller],
        Screen::Applications => &[Topic::Processes, Topic::Controller],
        Screen::Automation => &[Topic::Automation, Topic::Controller],
        Screen::History => &[Topic::History],
        Screen::Diagnostics => &[Topic::Diagnostics],
    }
}

/// The frames that a section scroll waits for the card tops.
const SCROLL_TRIES: u8 = 3;

/// The footer text of the agent state. Stale data says so.
fn agent_line(label: &str, stale: bool) -> String {
    if stale {
        format!("Agent {label} (stale)")
    } else {
        format!("Agent {label}")
    }
}

/// The name of the pressure for the Memory mark, or `None` when the reading
/// is not a measured Warning or Critical.
fn pressure_mark_name(pressure: &Measured<PressureLevel>) -> Option<&'static str> {
    match pressure {
        Measured::Value(PressureLevel::Warning) => Some("Warning"),
        Measured::Value(PressureLevel::Critical) => Some("Critical"),
        _ => None,
    }
}

/// A status mark at the right end of a sidebar item.
#[derive(Clone, Copy, Debug)]
enum Mark {
    /// A small spinner in the color.
    Spinner(Hsla),
    /// A 6 px dot in the color.
    Dot(Hsla),
}

impl Mark {
    fn element(self, id: &'static str, label: &str) -> AnyElement {
        let base = div()
            .id(id)
            .role(Role::Status)
            .test_support()
            .aria_label(label.to_owned())
            .flex_shrink_0();
        match self {
            Self::Spinner(color) => base
                .child(Spinner::new().color(color).xsmall())
                .into_any_element(),
            Self::Dot(color) => base
                .size(px(6.0))
                .rounded_full()
                .bg(color)
                .into_any_element(),
        }
    }
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let width: f32 = f32::from(window.viewport_size().width);
        self.sidebar_choice = choice_after_resize(self.sidebar_choice, self.last_width, width);
        self.last_width = width;
        let collapsed: bool = sidebar_narrow(width, self.sidebar_choice);
        self.nav.set_narrow(collapsed);
        self.step_pending_scroll(window);
        let content: Option<AnyView> = self.screens.get(self.active.index()).cloned();
        let groups: Vec<SidebarGroup<SidebarMenu>> = NavGroup::ALL
            .iter()
            .map(|&group| {
                let items: Vec<SidebarMenuItem> = group
                    .screens()
                    .iter()
                    .map(|&screen| self.nav_item(screen, collapsed, tokens, cx))
                    .collect();
                SidebarGroup::new(group.label()).child(SidebarMenu::new().children(items))
            })
            .collect();
        let header: AnyElement = Self::sidebar_header(collapsed, cx);
        let footer: AnyElement = self.agent_footer(collapsed, tokens, cx);
        let status: String = self.status_text(cx);
        let banner: Option<AnyElement> =
            self.banner_text(cx).map(|text| Self::banner(text, tokens));

        v_flex()
            .size_full()
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .bg(to_hsla(tokens.background))
            .text_color(to_hsla(tokens.foreground))
            .on_action(cx.listener(|this, action: &SelectScreen, _, cx| {
                this.select(action.screen, cx);
            }))
            .on_action(cx.listener(|this, _: &Refresh, _, cx| {
                this.model.update(cx, AppModel::refresh);
            }))
            .on_action(cx.listener(|this, _: &ToggleSidebar, window, cx| {
                this.toggle_sidebar(window, cx);
            }))
            .on_action(cx.listener(|this, _: &NextScreen, _, cx| {
                if let Some(screen) = next_screen(this.active) {
                    this.select(screen, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &PreviousScreen, _, cx| {
                if let Some(screen) = previous_screen(this.active) {
                    this.select(screen, cx);
                }
            }))
            .on_action(cx.listener(|_, _: &CloseWindow, window, _| {
                window.remove_window();
            }))
            .child(TitleBar::new().child("Svalnir"))
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(
                        Sidebar::<SidebarGroup<SidebarMenu>>::new("navigation")
                            .w(px(nav::SIDEBAR_WIDE_WIDTH))
                            .collapsed(collapsed)
                            .header(header)
                            .footer(footer)
                            .children(groups),
                    )
                    .child(
                        div()
                            .id("content")
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scroll()
                            .track_scroll(&self.scroll)
                            .p(tokens::CONTENT_PADDING)
                            .children(banner)
                            .children(content),
                    ),
            )
            .child(
                h_flex()
                    .id("status-line")
                    .role(Role::Status)
                    .test_support()
                    .aria_label(status.clone())
                    .h(tokens::STATUS_LINE_HEIGHT)
                    .flex_shrink_0()
                    .items_center()
                    .px(tokens::SPACE_3)
                    .bg(to_hsla(tokens.surface))
                    .text_size(px(12.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(status),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_agent_line_says_so() {
        assert_eq!(agent_line("reporting", false), "Agent reporting");
        assert_eq!(agent_line("reporting", true), "Agent reporting (stale)");
    }

    /// D-12 of host run 4: the footer joined "Agent" and a noun label, so it
    /// showed "Agent no journal" and "Agent no status".
    #[test]
    fn each_agent_line_reads_as_a_sentence() {
        let at = SystemTime::UNIX_EPOCH;
        let cases: [(AgentState, &str); 6] = [
            (AgentState::NoJournal, "Agent has no journal"),
            (AgentState::NoRecord, "Agent has no status record"),
            (AgentState::Reporting { since: at }, "Agent reporting"),
            (AgentState::Silent { last: at }, "Agent silent"),
            (AgentState::Stopped { at }, "Agent stopped"),
            (AgentState::Unknown("x".to_owned()), "Agent state unknown"),
        ];
        for (state, line) in cases {
            assert_eq!(agent_line(state.predicate(), false), line);
        }
    }

    #[test]
    fn the_memory_mark_needs_a_measured_warning_or_critical() {
        assert_eq!(
            pressure_mark_name(&Measured::Value(PressureLevel::Warning)),
            Some("Warning")
        );
        assert_eq!(
            pressure_mark_name(&Measured::Value(PressureLevel::Critical)),
            Some("Critical")
        );
        assert_eq!(
            pressure_mark_name(&Measured::Value(PressureLevel::Normal)),
            None
        );
        assert_eq!(pressure_mark_name(&Measured::Unavailable("x".into())), None);
    }
}
