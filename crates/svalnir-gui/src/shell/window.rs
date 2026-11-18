//! The root view: title bar, sidebar, content area, and status line.

use super::nav::{CloseWindow, KEY_CONTEXT, Refresh, Screen, SelectScreen};
use crate::{
    screens::placeholder::Placeholder,
    theme::tokens::{self, Tokens, to_hsla},
};
use gpui_kit::{
    AnyView, AppContext as _, ClickEvent, Context, Entity, EntityId, FocusHandle,
    InteractiveElement, IntoElement, ParentElement, Render, SharedString,
    StatefulInteractiveElement, Styled, Window,
    component::{
        ActiveTheme as _, TitleBar, h_flex,
        sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
        v_flex,
    },
    div, px,
};

/// The main window view. It keeps one entity per screen so that screen state
/// survives navigation.
#[derive(Debug)]
pub struct MainWindow {
    active: Screen,
    screens: Vec<AnyView>,
    focus: FocusHandle,
    status: SharedString,
}

impl MainWindow {
    /// Creates the view with all screens built; Overview is active.
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let screens: Vec<AnyView> = Screen::ALL
            .iter()
            .map(|&screen| {
                let view: Entity<Placeholder> = cx.new(|_| Placeholder::new(screen));
                AnyView::from(view)
            })
            .collect();
        let focus: FocusHandle = cx.focus_handle();
        window.focus(&focus, cx);
        Self {
            active: Screen::Overview,
            screens,
            focus,
            // TODO(npochaev): a later step replaces this with the agent state
            // and the age of the data.
            status: "No data source".into(),
        }
    }

    /// The active screen.
    pub fn active(&self) -> Screen {
        self.active
    }

    /// The id of the retained entity of `screen`.
    pub fn screen_entity_id(&self, screen: Screen) -> Option<EntityId> {
        self.screens.get(screen.index()).map(AnyView::entity_id)
    }

    /// Shows `screen`.
    pub fn select(&mut self, screen: Screen, cx: &mut Context<Self>) {
        if self.active != screen {
            self.active = screen;
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

        v_flex()
            .size_full()
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .bg(to_hsla(tokens.background))
            .text_color(to_hsla(tokens.foreground))
            .on_action(cx.listener(|this, action: &SelectScreen, _, cx| {
                this.select(action.screen, cx);
            }))
            // TODO(npochaev): a later step wires Refresh to the data layer.
            .on_action(cx.listener(|_, _: &Refresh, _, _| {}))
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
                            .children(content),
                    ),
            )
            .child(
                h_flex()
                    .h(tokens::STATUS_LINE_HEIGHT)
                    .flex_shrink_0()
                    .items_center()
                    .px(px(12.0))
                    .bg(to_hsla(tokens.surface))
                    .text_size(px(12.0))
                    .text_color(to_hsla(tokens.muted_foreground))
                    .child(self.status.clone()),
            )
    }
}
