//! X11 requests GPUI does not make: pointer state and window placement.
//!
//! The window manager takes keyboard focus while it moves a window by its title
//! bar, so the window reads as inactive for the whole drag. And GPUI gives the
//! window manager no position hint, so a new window lands wherever it chooses.

use std::sync::OnceLock;

use gpui::{px, Pixels, Point};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ClientMessageEvent, ConnectionExt, EventMask, KeyButMask, Window};
use x11rb::rust_connection::RustConnection;

static X: OnceLock<Option<(RustConnection, Window)>> = OnceLock::new();

fn x() -> Option<&'static (RustConnection, Window)> {
    X.get_or_init(|| {
        let (conn, screen) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        Some((conn, root))
    })
    .as_ref()
}

pub fn button_held() -> bool {
    let Some((conn, root)) = x() else { return false };
    let held = KeyButMask::BUTTON1 | KeyButMask::BUTTON2 | KeyButMask::BUTTON3;
    conn.query_pointer(*root)
        .ok()
        .and_then(|cookie| cookie.reply().ok())
        .is_some_and(|reply| reply.mask.intersects(held))
}

fn x_window(window: &gpui::Window) -> Option<Window> {
    match HasWindowHandle::window_handle(window).ok()?.as_raw() {
        RawWindowHandle::Xcb(h) => Some(h.window.get()),
        RawWindowHandle::Xlib(h) => Some(h.window as Window),
        _ => None,
    }
}

/// Top-left corner of the window's content on screen, in logical pixels.
pub fn origin(window: &gpui::Window) -> Option<Point<Pixels>> {
    let (conn, root) = x()?;
    let reply = conn.translate_coordinates(x_window(window)?, *root, 0, 0).ok()?.reply().ok()?;
    let scale = window.scale_factor();
    Some(Point::new(px(reply.dst_x as f32 / scale), px(reply.dst_y as f32 / scale)))
}

/// Asks the window manager to put the window's content at `origin`.
///
/// Uses `_NET_MOVERESIZE_WINDOW` with static gravity, so the point is the
/// content's corner rather than the title bar's.
pub fn move_to(window: &gpui::Window, origin: Point<Pixels>) {
    let Some((conn, root)) = x() else { return };
    let Some(win) = x_window(window) else { return };
    let Some(atom) = conn
        .intern_atom(false, b"_NET_MOVERESIZE_WINDOW")
        .ok()
        .and_then(|c| c.reply().ok())
        .map(|r| r.atom)
    else {
        return;
    };
    const STATIC_GRAVITY: u32 = 10;
    const X_AND_Y: u32 = (1 << 8) | (1 << 9);
    const FROM_PAGER: u32 = 2 << 12;
    let scale = window.scale_factor();
    let event = ClientMessageEvent::new(
        32,
        win,
        atom,
        [
            STATIC_GRAVITY | X_AND_Y | FROM_PAGER,
            (f32::from(origin.x) * scale).round() as i32 as u32,
            (f32::from(origin.y) * scale).round() as i32 as u32,
            0,
            0,
        ],
    );
    let mask = EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY;
    if conn.send_event(false, *root, mask, event).is_ok() {
        let _ = conn.flush();
    }
}
