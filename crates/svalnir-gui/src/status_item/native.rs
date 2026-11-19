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

use super::{MenuCommand, MenuRow, StatusView};
use crate::viz::capacity_grid::INLINE_CELLS;
use block2::RcBlock;
use objc2::{
    DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send,
    rc::Retained,
    runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject},
    sel,
};
use objc2_app_kit::{
    NSAccessibility as _, NSBezierPath, NSCellImagePosition, NSColor, NSImage, NSMenu,
    NSMenuDelegate, NSMenuItem, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use std::{cell::Cell, rc::Rc};

/// The width of one cell of the grid image, in points.
const CELL_WIDTH: f64 = 2.0;
/// The space between two cells, in points.
const CELL_GAP: f64 = 1.0;
/// The height of the grid image, in points. The menu bar is 22 points high
/// or more.
const CELL_HEIGHT: f64 = 12.0;
/// The alpha of an empty cell of the template image. The system draws a
/// template image in the color of the menu bar, so an empty cell is a
/// lighter cell of the same color, like the `border` color of a cell.
const EMPTY_ALPHA: f64 = 0.3;

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
        // SAFETY: the selector takes one object argument, which can be nil
        // or any object when a caller other than a menu item sends it, and
        // returns nothing. The argument is optional, and only a menu item
        // is read.
        #[unsafe(method(svalnirMenuCommand:))]
        fn menu_command(&self, sender: Option<&NSObject>) {
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

    /// Shows `view`: the grid image, the title, the label, and the menu.
    /// While the menu is open, only the button changes, and the result is
    /// `false`: apply the view again when the menu closes.
    pub(super) fn apply(&self, view: &StatusView) -> bool {
        if let Some(button) = self.item.button(self.mtm) {
            let image: Option<Retained<NSImage>> = view.cells.map(grid_image);
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
                    item.setToolTip(Some(&NSString::from_str(detail)));
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
                // SAFETY: the surface owns the target for as long as the
                // menu and its items exist.
                unsafe { item.setTarget(Some(&self.target)) };
                item
            }
        }
    }
}

impl Drop for StatusSurface {
    fn drop(&mut self) {
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
    }
}

/// The template image of the inline capacity grid: one cell for each 5% of
/// the volume, a filled cell opaque, an empty cell at [`EMPTY_ALPHA`].
fn grid_image(cells: [bool; INLINE_CELLS]) -> Retained<NSImage> {
    let count: f64 = f64::from(u8::try_from(INLINE_CELLS).unwrap_or(u8::MAX));
    let size: NSSize = NSSize::new(count * CELL_WIDTH + (count - 1.0) * CELL_GAP, CELL_HEIGHT);
    let draw = RcBlock::new(move |_bounds: NSRect| -> Bool {
        let mut x: f64 = 0.0;
        for filled in cells {
            let alpha: f64 = if filled { 1.0 } else { EMPTY_ALPHA };
            NSColor::colorWithWhite_alpha(0.0, alpha).set();
            NSBezierPath::fillRect(NSRect::new(
                NSPoint::new(x, 0.0),
                NSSize::new(CELL_WIDTH, CELL_HEIGHT),
            ));
            x += CELL_WIDTH + CELL_GAP;
        }
        Bool::YES
    });
    let image: Retained<NSImage> =
        NSImage::imageWithSize_flipped_drawingHandler(size, false, &draw);
    // The system draws a template image in the color of the menu bar, for
    // the light and dark menu bar and for Increase Contrast.
    image.setTemplate(true);
    image
}
