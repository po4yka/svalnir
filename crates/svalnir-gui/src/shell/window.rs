//! The root view: title bar, sidebar, content area, and status line.

use super::nav::{CloseWindow, KEY_CONTEXT, Refresh, Screen, SelectScreen};
use crate::{
    data::{
        model::{AgentState, Loadable, Measured, PressureLevel},
        store::AppModel,
    },
    platform::DisplayAccessibility,
    screens::{overview::OverviewScreen, placeholder::Placeholder, storage::StorageScreen},
    theme::{
        glow,
        tokens::{self, Tokens, to_hsla},
    },
    ui::data_state::format_age,
};
use gpui_kit::{
    AnyElement, AnyView, AppContext as _, ClickEvent, Context, Entity, EntityId, FocusHandle,
    InteractiveElement, IntoElement, ParentElement, Render, Role, StatefulInteractiveElement,
    Styled, TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, Icon, IconName, TitleBar, h_flex,
        sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
        v_flex,
    },
    div, px,
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
}

impl MainWindow {
    /// Creates the view with all screens built; Overview is active.
    pub fn new(model: Entity<AppModel>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let overview: Entity<OverviewScreen> = cx.new(|cx| OverviewScreen::new(model.clone(), cx));
        let storage: Entity<StorageScreen> = cx.new(|cx| StorageScreen::new(model.clone(), cx));
        let screens: Vec<AnyView> = Screen::ALL
            .iter()
            .map(|&screen| {
                if screen == Screen::Overview {
                    AnyView::from(overview.clone())
                } else if screen == Screen::Storage {
                    AnyView::from(storage.clone())
                } else {
                    let view: Entity<Placeholder> = cx.new(|_| Placeholder::new(screen));
                    AnyView::from(view)
                }
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
        model.update(cx, |model, cx| model.set_active(active, cx));
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
        }
    }

    /// The status line: source, agent state, and the age of the data.
    fn status_text(&self, cx: &Context<Self>) -> String {
        let model: &AppModel = self.model.read(cx);
        let agent: &str = match &model.agent {
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => snapshot.state.label(),
            Loadable::Loading => "loading",
            Loadable::Unavailable(_) => "unavailable",
        };
        let updated: String = match &model.host {
            Loadable::Ready(snapshot) | Loadable::Stale(snapshot) => format_age(
                SystemTime::now()
                    .duration_since(snapshot.captured_at)
                    .unwrap_or_default(),
            ),
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
                    AgentState::NoJournal | AgentState::NoRecord | AgentState::Silent { .. }
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
            .gap(px(8.0))
            .items_center()
            .px(px(12.0))
            .py(px(8.0))
            .mb(px(12.0))
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

    /// Shows `screen`.
    pub fn select(&mut self, screen: Screen, cx: &mut Context<Self>) {
        if self.active != screen {
            self.active = screen;
            match screen {
                Screen::Overview => self.overview.update(cx, OverviewScreen::activate),
                Screen::Storage => self.storage.update(cx, StorageScreen::activate),
                _ => {}
            }
            cx.notify();
        }
    }

    fn nav_items(&self, cx: &mut Context<Self>) -> Vec<SidebarMenuItem> {
        Screen::ALL
            .iter()
            .map(|&screen| {
                SidebarMenuItem::new(screen.title())
                    .icon(screen.icon())
                    .active(self.active == screen)
                    .accessibility_label(format!("Show {}", screen.title()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.select(screen, cx);
                    }))
            })
            .collect()
    }
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let collapsed: bool = window.viewport_size().width < tokens::SIDEBAR_COLLAPSE_WIDTH;
        let content: Option<AnyView> = self.screens.get(self.active.index()).cloned();
        let items: Vec<SidebarMenuItem> = self.nav_items(cx);
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
            .on_action(cx.listener(|_, _: &CloseWindow, window, _| {
                window.remove_window();
            }))
            .child(TitleBar::new().child("Svalnir"))
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(
                        Sidebar::<SidebarMenu>::new("navigation")
                            .collapsed(collapsed)
                            .child(SidebarMenu::new().children(items)),
                    )
                    .child(
                        div()
                            .id("content")
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scroll()
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
                    .px(px(12.0))
                    .bg(to_hsla(tokens.surface))
                    .text_size(px(12.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(status),
            )
    }
}
