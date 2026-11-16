//! Whether a mouse button is held, asked of the X server.
//!
//! The window manager takes keyboard focus while it moves a window by its title
//! bar, so the window reads as inactive for the whole drag.

use std::sync::OnceLock;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, KeyButMask, Window};
use x11rb::rust_connection::RustConnection;

static X: OnceLock<Option<(RustConnection, Window)>> = OnceLock::new();

pub fn button_held() -> bool {
    let Some((conn, root)) = X.get_or_init(|| {
        let (conn, screen) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        Some((conn, root))
    }) else {
        return false;
    };
    let held = KeyButMask::BUTTON1 | KeyButMask::BUTTON2 | KeyButMask::BUTTON3;
    conn.query_pointer(*root)
        .ok()
        .and_then(|cookie| cookie.reply().ok())
        .is_some_and(|reply| reply.mask.intersects(held))
}
