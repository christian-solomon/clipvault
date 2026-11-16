//! Watches the X11 CLIPBOARD selection for changes.
//!
//! This deliberately does not touch the keyboard. Grabbing Ctrl+C would steal
//! the keystroke from the focused application and would still miss every copy
//! that does not come from that shortcut (context menus, app buttons, scripts).
//! XFixes tells us whenever the selection owner changes, which covers all of
//! them, and requires no access to what the user types.

use anyhow::{anyhow, bail, Result};
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::xfixes::{self, ConnectionExt as XfixesConnectionExt, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as XprotoConnectionExt, CreateWindowAux, EventMask, PropMode,
    Property, SelectionNotifyEvent, Window, WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

const FETCH_TIMEOUT: Duration = Duration::from_millis(500);
/// A whole INCR transfer gets longer than a single round trip; a full-screen
/// screenshot arrives in a few hundred chunks.
const INCR_TIMEOUT: Duration = Duration::from_secs(10);
/// Anything larger is almost certainly not something you want in a history list.
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
/// Generous enough for a 4K screenshot.
const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
/// TARGETS lists and the password-manager hint are a few dozen bytes; anything
/// near this size is an owner misbehaving.
const MAX_META_BYTES: usize = 64 * 1024;

/// `GetProperty` counts in 32-bit units. Asking for one unit more than the cap
/// lets `bytes_after` reveal an oversized value without transferring all of it.
fn units_for(max_bytes: usize) -> u32 {
    u32::try_from(max_bytes / 4 + 1).unwrap_or(u32::MAX)
}

/// What came off the clipboard, still undecoded.
pub enum Captured {
    Text(String),
    Image(Vec<u8>),
}

struct Atoms {
    clipboard: Atom,
    targets: Atom,
    incr: Atom,
    prop: Atom,
    time_probe: Atom,
    password_hint: Atom,
    text_targets: Vec<Atom>,
    image_targets: Vec<Atom>,
}

struct Watcher {
    conn: RustConnection,
    win: Window,
    atoms: Atoms,
    queued: VecDeque<Event>,
}

fn intern(conn: &RustConnection, name: &str) -> Result<Atom> {
    Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom)
}

impl Watcher {
    fn new() -> Result<Self> {
        let (conn, screen_num) = x11rb::connect(None)
            .map_err(|e| anyhow!("cannot connect to the X server: {e}"))?;
        let root = conn.setup().roots[screen_num].root;

        // XFixes requires a version handshake before any of its requests work.
        xfixes::query_version(&conn, 5, 0)?.reply()?;

        let win = conn.generate_id()?;
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )?;

        let atoms = Atoms {
            clipboard: intern(&conn, "CLIPBOARD")?,
            targets: intern(&conn, "TARGETS")?,
            incr: intern(&conn, "INCR")?,
            prop: intern(&conn, "CLIPVAULT_SELECTION")?,
            time_probe: intern(&conn, "CLIPVAULT_TIME_PROBE")?,
            password_hint: intern(&conn, "x-kde-passwordManagerHint")?,
            text_targets: vec![
                intern(&conn, "text/plain;charset=utf-8")?,
                intern(&conn, "UTF8_STRING")?,
                intern(&conn, "text/plain")?,
                Atom::from(AtomEnum::STRING),
            ],
            image_targets: vec![
                intern(&conn, "image/png")?,
                intern(&conn, "image/jpeg")?,
                intern(&conn, "image/bmp")?,
                intern(&conn, "image/gif")?,
            ],
        };

        conn.xfixes_select_selection_input(
            win,
            atoms.clipboard,
            SelectionEventMask::SET_SELECTION_OWNER
                | SelectionEventMask::SELECTION_WINDOW_DESTROY
                | SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )?;
        conn.flush()?;

        Ok(Watcher { conn, win, atoms, queued: VecDeque::new() })
    }

    fn next_event(&mut self) -> Result<Event> {
        if let Some(e) = self.queued.pop_front() {
            return Ok(e);
        }
        Ok(self.conn.wait_for_event()?)
    }

    /// Waits for the SelectionNotify answering a ConvertSelection, holding on to
    /// any other events that arrive meanwhile so they are not lost.
    fn await_notify(&mut self, deadline: Instant) -> Result<Option<SelectionNotifyEvent>> {
        loop {
            if Instant::now() > deadline {
                return Ok(None);
            }
            match self.conn.poll_for_event()? {
                Some(Event::SelectionNotify(e)) if e.requestor == self.win => return Ok(Some(e)),
                Some(other) => self.queued.push_back(other),
                None => std::thread::sleep(Duration::from_millis(4)),
            }
        }
    }

    /// Obtains a current server timestamp the ICCCM way: a zero-length append
    /// to a property on our own window comes back as a PropertyNotify carrying
    /// the server's clock.
    ///
    /// ConvertSelection wants the timestamp of the event that prompted it, and
    /// owners may refuse a time that predates their ownership. Since we only ask
    /// after seeing the ownership change, a timestamp fetched here is always
    /// late enough, which the XFixes event time is not guaranteed to be.
    fn server_time(&mut self) -> Result<u32> {
        self.conn.change_property8(
            PropMode::APPEND,
            self.win,
            self.atoms.time_probe,
            AtomEnum::STRING,
            &[],
        )?;
        self.conn.flush()?;

        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            if Instant::now() > deadline {
                return Ok(x11rb::CURRENT_TIME);
            }
            match self.conn.poll_for_event()? {
                Some(Event::PropertyNotify(e))
                    if e.window == self.win && e.atom == self.atoms.time_probe =>
                {
                    return Ok(e.time)
                }
                Some(other) => self.queued.push_back(other),
                None => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    }

    /// Asks the current owner for the selection in `target`, giving up on
    /// anything larger than `max_bytes` rather than buffering it first.
    fn fetch(&mut self, target: Atom, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        let time = self.server_time()?;
        for attempt in 0..2 {
            self.conn.delete_property(self.win, self.atoms.prop)?;
            self.conn.convert_selection(
                self.win,
                self.atoms.clipboard,
                target,
                self.atoms.prop,
                time,
            )?;
            self.conn.flush()?;

            let notify = match self.await_notify(Instant::now() + FETCH_TIMEOUT)? {
                Some(n) => n,
                None => {
                    log::debug!("selection fetch timed out (target {target})");
                    return Ok(None);
                }
            };
            if notify.property == x11rb::NONE {
                // An owner that is still starting up can refuse the first ask.
                if attempt == 0 {
                    std::thread::sleep(Duration::from_millis(60));
                    continue;
                }
                log::debug!("owner refused target {target}");
                return Ok(None);
            }

            // Peek without deleting: an INCR handshake needs the delete to be
            // the signal that we are ready for the first chunk.
            let reply = self
                .conn
                .get_property(
                    false,
                    self.win,
                    self.atoms.prop,
                    AtomEnum::ANY,
                    0,
                    units_for(max_bytes),
                )?
                .reply()?;

            if reply.type_ == self.atoms.incr {
                self.conn.delete_property(self.win, self.atoms.prop)?;
                self.conn.flush()?;
                return self.read_incr(max_bytes);
            }

            self.conn.delete_property(self.win, self.atoms.prop)?;
            self.conn.flush()?;
            if reply.bytes_after > 0 || reply.value.len() > max_bytes {
                log::debug!("skipping oversized value for target {target}");
                return Ok(None);
            }
            return Ok(Some(reply.value));
        }
        Ok(None)
    }

    /// Reads an incremental transfer. The owner writes one chunk at a time and
    /// waits for us to delete the property before writing the next; a
    /// zero-length chunk ends it. Large images always arrive this way, because
    /// they do not fit in a single property.
    fn read_incr(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + INCR_TIMEOUT;
        let mut out: Vec<u8> = Vec::new();

        loop {
            if !self.await_property_notify(deadline)? {
                log::warn!("incremental clipboard transfer stalled");
                return Ok(None);
            }
            let chunk = self
                .conn
                .get_property(
                    true,
                    self.win,
                    self.atoms.prop,
                    AtomEnum::ANY,
                    0,
                    units_for(max_bytes),
                )?
                .reply()?;
            // Deleting the property is what tells the owner to send the next one.
            self.conn.flush()?;

            if chunk.value.is_empty() {
                log::debug!("incremental transfer complete: {} bytes", out.len());
                return Ok(Some(out));
            }
            out.extend_from_slice(&chunk.value);
            if chunk.bytes_after > 0 || out.len() > max_bytes {
                log::debug!("abandoning oversized incremental transfer");
                return Ok(None);
            }
        }
    }

    /// Waits for the owner to write the next INCR chunk onto our property.
    fn await_property_notify(&mut self, deadline: Instant) -> Result<bool> {
        loop {
            if Instant::now() > deadline {
                return Ok(false);
            }
            match self.conn.poll_for_event()? {
                Some(Event::PropertyNotify(e))
                    if e.window == self.win
                        && e.atom == self.atoms.prop
                        && e.state == Property::NEW_VALUE =>
                {
                    return Ok(true)
                }
                Some(other) => self.queued.push_back(other),
                None => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    }

    fn targets(&mut self) -> Result<Vec<Atom>> {
        let raw = match self.fetch(self.atoms.targets, MAX_META_BYTES)? {
            Some(v) => v,
            None => return Ok(vec![]),
        };
        Ok(raw
            .chunks_exact(4)
            .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }

    /// Returns whatever is worth keeping, or None when the clipboard holds
    /// something we skip: an unsupported format, an oversized payload, or a
    /// password manager's secret.
    fn read_clip(&mut self) -> Result<Option<Captured>> {
        let targets = self.targets()?;
        if targets.is_empty() {
            return Ok(None);
        }

        // Password managers tag their copies so that history tools leave them
        // alone. Honour that - those belong in the vault, by hand, not here.
        if targets.contains(&self.atoms.password_hint) {
            if let Some(v) = self.fetch(self.atoms.password_hint, MAX_META_BYTES)? {
                if v.eq_ignore_ascii_case(b"secret") {
                    log::info!("skipped a copy flagged as a password manager secret");
                    return Ok(None);
                }
            }
        }

        // Text wins when both are offered: copying a file in a file manager or
        // rich content in a browser offers an image alongside the text, and the
        // text is what you actually wanted.
        if let Some(target) = self.atoms.text_targets.iter().copied().find(|t| targets.contains(t))
        {
            let Some(bytes) = self.fetch(target, MAX_TEXT_BYTES)? else {
                return Ok(None);
            };
            if bytes.len() > MAX_TEXT_BYTES {
                log::debug!("skipping {} byte text payload", bytes.len());
                return Ok(None);
            }
            // STRING is latin-1 by spec; everything else we ask for is UTF-8.
            let text = if target == Atom::from(AtomEnum::STRING) {
                bytes.iter().map(|&b| b as char).collect()
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            };
            return Ok(Some(Captured::Text(text)));
        }

        if let Some(target) = self.atoms.image_targets.iter().copied().find(|t| targets.contains(t))
        {
            let Some(bytes) = self.fetch(target, MAX_IMAGE_BYTES)? else {
                return Ok(None);
            };
            if bytes.len() > MAX_IMAGE_BYTES {
                log::debug!("skipping {} byte image payload", bytes.len());
                return Ok(None);
            }
            return Ok(Some(Captured::Image(bytes)));
        }

        Ok(None) // file list or some app-private format
    }

    fn run(&mut self, tx: Sender<Captured>) -> Result<()> {
        loop {
            let event = self.next_event()?;
            let Event::XfixesSelectionNotify(e) = event else { continue };
            // owner == NONE is the previous owner going away, not a new copy.
            if e.owner == self.win || e.owner == x11rb::NONE {
                continue;
            }

            // The new owner has just taken the selection; give it a moment to be
            // ready to answer ConvertSelection.
            std::thread::sleep(Duration::from_millis(20));

            let captured = match self.read_clip() {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(err) => {
                    log::warn!("clipboard read failed: {err}");
                    continue;
                }
            };
            if let Captured::Text(t) = &captured {
                if t.trim().is_empty() {
                    continue;
                }
            }
            if tx.send(captured).is_err() {
                bail!("clipboard consumer went away");
            }
        }
    }
}

/// Starts the watcher on its own thread with its own X connection.
pub fn spawn(tx: Sender<Captured>) {
    std::thread::Builder::new()
        .name("clipboard-watcher".into())
        .spawn(move || match Watcher::new() {
            Ok(mut w) => {
                log::info!("clipboard watcher running");
                if let Err(e) = w.run(tx) {
                    log::error!("clipboard watcher stopped: {e}");
                }
            }
            Err(e) => log::error!("clipboard watcher failed to start: {e}"),
        })
        .expect("failed to spawn clipboard watcher thread");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_reads_ask_for_one_unit_past_the_cap() {
        assert_eq!(units_for(8), 3);
        assert_eq!(units_for(MAX_TEXT_BYTES), (MAX_TEXT_BYTES / 4 + 1) as u32);
        assert_eq!(units_for(usize::MAX), u32::MAX);
    }
}
