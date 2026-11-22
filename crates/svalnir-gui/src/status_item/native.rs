//! The `AppKit` side of the menu bar item: one `NSStatusItem`, its `NSMenu`,
//! and the Objective-C object that receives the menu actions.
//!
//! Each object here is main-thread only (`MainThreadMarker`). GPUI runs the
//! `NSApplication` run loop on the main thread, and the application context
//! of GPUI is on the same thread, so the surface is created and changed from
//! there. GPUI does not change a menu that it did not build, so the menu of
//! the item has its own target.
//!
//! The menu is not rebuilt while it is open: GPUI runs its tasks on the main
//! dispatch queue, which also runs while `AppKit` tracks a menu, and a
//! rebuild under the pointer can move a row. The target is the delegate of
//! the menu, and when the menu closes it asks for the latest view.

use super::{
    CellPaint, ItemTone, MenuBarLook, MenuCommand, MenuRow, StatusView, Surface, dot_outline_rgba,
    paint_rgba, tone_rgb,
};
use crate::viz::capacity_grid::INLINE_CELLS;
use block2::RcBlock;
use objc2::{
    DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send,
    rc::Retained,
    runtime::{AnyObject, Bool, NSObject, NSObjectProtocol, ProtocolObject},
    sel,
};
use objc2_app_kit::{
    NSAccessibility as _, NSAppearance, NSBezierPath, NSCellImagePosition, NSColor, NSImage,
    NSMenu, NSMenuDelegate, NSMenuItem, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
    NSWorkspace,
};
use objc2_foundation::{NSArray, NSPoint, NSRect, NSSize, NSString};
use std::{cell::Cell, rc::Rc};

/// The width of one cell of the grid image, in points.
const CELL_WIDTH: f64 = 2.0;
/// The space between two cells, in points.
const CELL_GAP: f64 = 1.0;
/// The height of the grid image, in points. The menu bar is 22 points high
/// or more.
const CELL_HEIGHT: f64 = 12.0;
/// The diameter of the dot of the pressure state, in points.
const DOT: f64 = 6.0;
/// The space between the grid and the dot, in points.
const DOT_GAP: f64 = 4.0;

/// The ivars of [`MenuTarget`].
struct TargetIvars {
    on_command: Rc<dyn Fn(MenuCommand)>,
    /// Called when the menu closes, so that the view can be applied.
    on_closed: Rc<dyn Fn()>,
    /// Whether the menu is open now.
    open: Cell<bool>,
}

define_class!(
    // SAFETY: `NSObject` has no subclassing requirements. The class is
    // main-thread only, and `new` sets the ivars before `init`.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = TargetIvars]
    struct MenuTarget;

    // SAFETY: `NSObjectProtocol` has no requirement beyond `NSObject`.
    unsafe impl NSObjectProtocol for MenuTarget {}

    impl MenuTarget {
        /// The action of each command item. The tag names the command.
        // SAFETY: the selector is `-(void)svalnirMenuCommand:(id)sender`.
        // The argument is any object or nil (`Option<&AnyObject>`), and the
        // method reads it only after a checked downcast to `NSMenuItem`.
        #[unsafe(method(svalnirMenuCommand:))]
        fn menu_command(&self, sender: Option<&AnyObject>) {
            let Some(item) = sender.and_then(|sender| sender.downcast_ref::<NSMenuItem>()) else {
                return;
            };
            if let Some(command) = MenuCommand::from_tag(item.tag()) {
                (self.ivars().on_command)(command);
            }
        }
    }

    // SAFETY: the two methods have the signatures of `NSMenuDelegate`, and
    // the class is main-thread only, as the protocol requires.
    unsafe impl NSMenuDelegate for MenuTarget {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            self.ivars().open.set(true);
        }

        #[unsafe(method(menuDidClose:))]
        fn menu_did_close(&self, _menu: &NSMenu) {
            self.ivars().open.set(false);
            (self.ivars().on_closed)();
        }
    }
);

impl MenuTarget {
    fn new(
        mtm: MainThreadMarker,
        on_command: Rc<dyn Fn(MenuCommand)>,
        on_closed: Rc<dyn Fn()>,
    ) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(TargetIvars {
            on_command,
            on_closed,
            open: Cell::new(false),
        });
        // SAFETY: `init` of `NSObject` takes no argument and returns the
        // initialized object.
        unsafe { msg_send![super(this), init] }
    }
}

/// The native item. It removes itself from the menu bar when it drops.
pub(super) struct StatusSurface {
    mtm: MainThreadMarker,
    item: Retained<NSStatusItem>,
    menu: Retained<NSMenu>,
    /// The target of each command item and the delegate of the menu. The
    /// menu and its items keep only a weak reference to it, so the surface
    /// owns it for as long as the menu.
    target: Retained<MenuTarget>,
}

impl std::fmt::Debug for StatusSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusSurface").finish_non_exhaustive()
    }
}

impl StatusSurface {
    /// Adds an empty item to the menu bar. `on_command` runs a chosen
    /// command, and `on_closed` asks for the view when the menu closes.
    /// `None` off the main thread.
    pub(super) fn new(
        on_command: Rc<dyn Fn(MenuCommand)>,
        on_closed: Rc<dyn Fn()>,
    ) -> Option<Self> {
        let mtm: MainThreadMarker = MainThreadMarker::new()?;
        let item: Retained<NSStatusItem> =
            NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        let menu: Retained<NSMenu> = NSMenu::new(mtm);
        // The enabled state of each item is the state of the view.
        menu.setAutoenablesItems(false);
        item.setMenu(Some(&menu));
        if let Some(button) = item.button(mtm) {
            button.setImagePosition(NSCellImagePosition::ImageLeft);
        }
        let target: Retained<MenuTarget> = MenuTarget::new(mtm, on_command, on_closed);
        menu.setDelegate(Some(ProtocolObject::from_ref(&*target)));
        Some(Self {
            mtm,
            item,
            menu,
            target,
        })
    }

    fn menu_item(&self, row: &MenuRow) -> Retained<NSMenuItem> {
        match row {
            MenuRow::Separator => NSMenuItem::separatorItem(self.mtm),
            MenuRow::Info { title, detail } => {
                // SAFETY: an item with no action selector sends nothing.
                let item: Retained<NSMenuItem> = unsafe {
                    NSMenuItem::initWithTitle_action_keyEquivalent(
                        NSMenuItem::alloc(self.mtm),
                        &NSString::from_str(title),
                        None,
                        &NSString::new(),
                    )
                };
                item.setEnabled(false);
                if let Some(detail) = detail {
                    let detail: Retained<NSString> = NSString::from_str(detail);
                    item.setToolTip(Some(&detail));
                    // A tooltip is not read by VoiceOver; the help text is.
                    item.setAccessibilityHelp(Some(&detail));
                }
                item
            }
            MenuRow::Command {
                title,
                command,
                enabled,
            } => {
                // SAFETY: `MenuTarget` implements the selector with one
                // object argument, the sending item.
                let item: Retained<NSMenuItem> = unsafe {
                    NSMenuItem::initWithTitle_action_keyEquivalent(
                        NSMenuItem::alloc(self.mtm),
                        &NSString::from_str(title),
                        Some(sel!(svalnirMenuCommand:)),
                        &NSString::new(),
                    )
                };
                item.setTag(command.tag());
                item.setEnabled(*enabled);
                // SAFETY: the target is a `MenuTarget`, which implements
                // `svalnirMenuCommand:`, the action of this item. The
                // property is weak, so a target that drops is nil.
                unsafe { item.setTarget(Some(&self.target)) };
                item
            }
        }
    }
}

impl Surface for StatusSurface {
    /// Shows `view`: the grid image, the title, the label, and the menu.
    /// While the menu is open, only the button changes, and the result is
    /// `false`: apply the view again when the menu closes.
    fn apply(&self, view: &StatusView) -> bool {
        if let Some(button) = self.item.button(self.mtm) {
            let image: Option<Retained<NSImage>> = grid_image(view.grid, view.pressure);
            button.setImage(image.as_deref());
            button.setTitle(&NSString::from_str(&view.title));
            let label: Retained<NSString> = NSString::from_str(&view.label);
            button.setAccessibilityLabel(Some(&label));
            button.setToolTip(Some(&label));
        }
        if self.target.ivars().open.get() {
            return false;
        }
        self.menu.removeAllItems();
        for row in &view.rows {
            self.menu.addItem(&self.menu_item(row));
        }
        true
    }
}

impl Drop for StatusSurface {
    /// Takes the item off the menu bar and disconnects the menu from the
    /// target, so that no callback reaches the target after it drops.
    fn drop(&mut self) {
        self.menu.setDelegate(None);
        self.menu.removeAllItems();
        self.item.setMenu(None);
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
    }
}

/// The look of the menu bar at draw time: the appearance that `AppKit`
/// draws the image in, and Increase Contrast.
fn current_look() -> MenuBarLook {
    // The names are the string values of `NSAppearanceNameAqua` and
    // `NSAppearanceNameDarkAqua`; `bestMatchFromAppearancesWithNames:`
    // compares names as strings, so no extern static is read.
    let names: Retained<NSArray<NSString>> = NSArray::from_retained_slice(&[
        NSString::from_str("NSAppearanceNameAqua"),
        NSString::from_str("NSAppearanceNameDarkAqua"),
    ]);
    let dark: bool = NSAppearance::currentDrawingAppearance()
        .bestMatchFromAppearancesWithNames(&names)
        .is_some_and(|name| name.to_string() == "NSAppearanceNameDarkAqua");
    let increase_contrast: bool =
        NSWorkspace::sharedWorkspace().accessibilityDisplayShouldIncreaseContrast();
    MenuBarLook {
        dark,
        increase_contrast,
    }
}

fn set_color([r, g, b, a]: [f64; 4]) {
    NSColor::colorWithSRGBRed_green_blue_alpha(r, g, b, a).set();
}

/// The image of the inline capacity grid in the tokens of `DESIGN.md`, with
/// the dot of the pressure state after it. It is not a template image: the
/// drawing handler runs each time `AppKit` draws the image, so it reads the
/// appearance of the menu bar and Increase Contrast then, and the colors
/// follow a change of either with no new view.
fn grid_image(
    paints: Option<[CellPaint; INLINE_CELLS]>,
    pressure: Option<ItemTone>,
) -> Option<Retained<NSImage>> {
    if paints.is_none() && pressure.is_none() {
        return None;
    }
    let count: f64 = f64::from(u8::try_from(INLINE_CELLS).unwrap_or(u8::MAX));
    let grid_width: f64 = if paints.is_some() {
        count * CELL_WIDTH + (count - 1.0) * CELL_GAP
    } else {
        0.0
    };
    let dot_width: f64 = match (paints.is_some(), pressure.is_some()) {
        (true, true) => DOT_GAP + DOT,
        (false, true) => DOT,
        (_, false) => 0.0,
    };
    let size: NSSize = NSSize::new(grid_width + dot_width, CELL_HEIGHT);
    let draw = RcBlock::new(move |_bounds: NSRect| -> Bool {
        let look: MenuBarLook = current_look();
        let mut x: f64 = 0.0;
        if let Some(paints) = paints {
            for paint in paints {
                set_color(paint_rgba(paint, look));
                NSBezierPath::fillRect(NSRect::new(
                    NSPoint::new(x, 0.0),
                    NSSize::new(CELL_WIDTH, CELL_HEIGHT),
                ));
                x += CELL_WIDTH + CELL_GAP;
            }
            x += DOT_GAP - CELL_GAP;
        }
        if let Some(tone) = pressure {
            let [r, g, b] = tone_rgb(tone, look.dark);
            set_color([r, g, b, 1.0]);
            let origin: NSPoint = NSPoint::new(x.max(0.0), (CELL_HEIGHT - DOT) / 2.0);
            NSBezierPath::bezierPathWithOvalInRect(NSRect::new(origin, NSSize::new(DOT, DOT)))
                .fill();
            if let Some(outline) = dot_outline_rgba(look) {
                // The stroke is centered on the path, so the path is inset
                // by half the line to keep the outline inside the image.
                set_color(outline);
                let ring = NSBezierPath::bezierPathWithOvalInRect(NSRect::new(
                    NSPoint::new(origin.x + 0.5, origin.y + 0.5),
                    NSSize::new(DOT - 1.0, DOT - 1.0),
                ));
                ring.setLineWidth(1.0);
                ring.stroke();
            }
        }
        Bool::YES
    });
    let image: Retained<NSImage> =
        NSImage::imageWithSize_flipped_drawingHandler(size, false, &draw);
    image.setTemplate(false);
    Some(image)
}
