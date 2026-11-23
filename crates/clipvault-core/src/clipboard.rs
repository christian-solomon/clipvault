//! Writing to the clipboard, and keeping our own writes out of history.
//!
//! Every write fires our own watcher. History copies are skipped by content
//! hash, and a lapse there only bumps an existing row, since history dedupes.
//! Vault copies must never be recorded, whatever the timing, so they get two
//! independent guards:
//!
//! 1. The write advertises `x-kde-passwordManagerHint: secret`. The watcher
//!    skips any clipboard carrying it, at the moment it reads the clipboard,
//!    and so do other clipboard managers.
//! 2. A keyed hash of the secret stays on a deny list until the clipboard is
//!    cleared. The recorder drops any capture matching it, however late or out
//!    of order the capture arrives.
//!
//! Neither guard depends on when or in what order captures arrive: an INCR
//! image transfer can hold the watcher for seconds.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::media;
use crate::store::hash_of;

/// How long a history copy's hash is honoured. A lapse is harmless.
const HISTORY_ECHO_WINDOW: Duration = Duration::from_secs(3);
/// Extra time a secret stays on the deny list past its clipboard clear, to
/// cover a capture that is read just before the clear and recorded after it.
const SECRET_GRACE: Duration = Duration::from_secs(15);
/// Bound on remembered secrets when they are never cleared.
const MAX_GUARDED: usize = 32;

type Tag = [u8; 32];

/// Shared between the thread that writes the clipboard and the thread that
/// records captures.
pub struct EchoGuard {
    key: Zeroizing<[u8; 32]>,
    history: Mutex<Option<(String, Instant)>>,
    secrets: Mutex<Vec<(Tag, Option<Instant>)>>,
}

impl Default for EchoGuard {
    fn default() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        EchoGuard { key, history: Mutex::new(None), secrets: Mutex::new(Vec::new()) }
    }
}

impl EchoGuard {
    /// A keyed hash, so the deny list cannot be brute-forced back into
    /// secrets by anyone who reads it without also holding the key.
    fn tag(&self, text: &str) -> Tag {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref()).expect("any key length");
        mac.update(text.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Skip the next capture if it hashes to `hash`.
    pub fn expect_history(&self, hash: &str) {
        *self.history.lock().unwrap() =
            Some((hash.to_string(), Instant::now() + HISTORY_ECHO_WINDOW));
    }

    /// Drop every capture of `secret` until `until`, or for the rest of the
    /// process when `None`.
    pub fn guard_secret(&self, secret: &str, until: Option<Instant>) -> Tag {
        let tag = self.tag(secret);
        let mut list = self.secrets.lock().unwrap();
        let now = Instant::now();
        list.retain(|(t, exp)| *t != tag && exp.map(|e| e > now).unwrap_or(true));
        list.push((tag, until));
        if list.len() > MAX_GUARDED {
            list.remove(0);
        }
        tag
    }

    pub fn is_guarded_secret(&self, text: &str) -> bool {
        let tag = self.tag(text);
        let now = Instant::now();
        self.secrets
            .lock()
            .unwrap()
            .iter()
            .any(|(t, exp)| *t == tag && exp.map(|e| e > now).unwrap_or(true))
    }

    /// Whether the recorder must drop a capture. `text` is the captured text,
    /// or `None` for an image; `hash` is the capture's content hash.
    pub fn should_drop(&self, text: Option<&str>, hash: &str) -> bool {
        if let Some(t) = text {
            if self.is_guarded_secret(t) {
                return true;
            }
        }
        let mut history = self.history.lock().unwrap();
        match history.as_ref() {
            Some((_, deadline)) if Instant::now() > *deadline => {
                *history = None;
                false
            }
            Some((expected, _)) if expected == hash => {
                *history = None;
                true
            }
            _ => false,
        }
    }
}

/// The app's single handle on the clipboard. arboard serves our selection
/// from a background thread that lives as long as this value, so it is kept
/// for the whole run rather than created per copy.
pub struct ClipboardWriter {
    board: arboard::Clipboard,
    guard: std::sync::Arc<EchoGuard>,
    last_secret: Option<Tag>,
}

impl ClipboardWriter {
    pub fn new(guard: std::sync::Arc<EchoGuard>) -> Result<Self> {
        Ok(ClipboardWriter {
            board: arboard::Clipboard::new().map_err(|e| anyhow!("clipboard: {e}"))?,
            guard,
            last_secret: None,
        })
    }

    pub fn copy_text(&mut self, text: &str) -> Result<()> {
        self.guard.expect_history(&hash_of(text));
        self.last_secret = None;
        self.board.set_text(text).map_err(|e| anyhow!("clipboard: {e}"))
    }

    pub fn copy_image(&mut self, png: &[u8]) -> Result<()> {
        // The hash is over pixels, so it still matches after arboard re-encodes
        // the image on its way back onto the clipboard.
        let clip = media::prepare(png)?;
        let (w, h, rgba) = media::to_rgba(png)?;
        self.guard.expect_history(&clip.hash);
        self.last_secret = None;
        self.board
            .set_image(arboard::ImageData {
                width: w as usize,
                height: h as usize,
                bytes: rgba.into(),
            })
            .map_err(|e| anyhow!("clipboard: {e}"))
    }

    /// Puts a secret on the clipboard, marked so that clipboard managers
    /// (this one included) leave it alone. `clear_after` is how long the caller
    /// intends to wait before `clear_secret_if_unchanged`; zero means never.
    pub fn copy_secret(&mut self, secret: &str, clear_after: Duration) -> Result<()> {
        let until = (!clear_after.is_zero()).then(|| Instant::now() + clear_after + SECRET_GRACE);
        // Guard first: the watcher may see the new owner before set returns.
        let tag = self.guard.guard_secret(secret, until);
        self.last_secret = Some(tag);

        #[cfg(target_os = "linux")]
        use arboard::SetExtLinux;
        self.board.set().exclude_from_history().text(secret).map_err(|e| anyhow!("clipboard: {e}"))
    }

    /// Clears the clipboard if it still holds the last secret we copied.
    /// Returns whether it cleared. Anything the user copied since is left be.
    pub fn clear_secret_if_unchanged(&mut self) -> Result<bool> {
        let Some(tag) = self.last_secret else {
            return Ok(false);
        };
        let current = match self.board.get_text() {
            Ok(t) => Zeroizing::new(t),
            // An image or nothing at all: not ours any more.
            Err(_) => {
                self.last_secret = None;
                return Ok(false);
            }
        };
        if self.guard.tag(&current) != tag {
            self.last_secret = None;
            return Ok(false);
        }
        self.board.clear().map_err(|e| anyhow!("clipboard: {e}"))?;
        self.last_secret = None;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_echo_skips_only_the_matching_hash_once() {
        let g = EchoGuard::default();
        g.expect_history(&hash_of("ours"));
        assert!(!g.should_drop(Some("someone else's"), &hash_of("someone else's")));
        g.expect_history(&hash_of("ours"));
        assert!(g.should_drop(Some("ours"), &hash_of("ours")));
        assert!(!g.should_drop(Some("ours"), &hash_of("ours")), "must not swallow a real re-copy");
    }

    #[test]
    fn a_stale_history_echo_does_not_eat_a_later_copy() {
        let g = EchoGuard::default();
        *g.history.lock().unwrap() = Some((hash_of("x"), Instant::now() - Duration::from_secs(1)));
        assert!(!g.should_drop(Some("x"), &hash_of("x")));
    }

    #[test]
    fn a_guarded_secret_is_dropped_every_time_and_in_any_order() {
        let g = EchoGuard::default();
        g.guard_secret("hunter2-vault", Some(Instant::now() + Duration::from_secs(60)));
        // An unrelated copy queued ahead of ours must not use the guard up.
        assert!(!g.should_drop(Some("unrelated"), &hash_of("unrelated")));
        assert!(g.should_drop(Some("hunter2-vault"), &hash_of("hunter2-vault")));
        assert!(g.should_drop(Some("hunter2-vault"), &hash_of("hunter2-vault")), "not consumed");
    }

    #[test]
    fn a_secret_guard_expires() {
        let g = EchoGuard::default();
        g.guard_secret("old", Some(Instant::now() - Duration::from_secs(1)));
        assert!(!g.is_guarded_secret("old"));
    }

    #[test]
    fn a_secret_that_is_never_cleared_stays_guarded() {
        let g = EchoGuard::default();
        g.guard_secret("forever", None);
        assert!(g.is_guarded_secret("forever"));
    }

    #[test]
    fn the_guard_list_is_bounded() {
        let g = EchoGuard::default();
        for i in 0..MAX_GUARDED + 10 {
            g.guard_secret(&format!("s{i}"), None);
        }
        assert_eq!(g.secrets.lock().unwrap().len(), MAX_GUARDED);
        assert!(g.is_guarded_secret(&format!("s{}", MAX_GUARDED + 9)), "newest kept");
    }

    #[test]
    fn tags_are_keyed_per_process() {
        let (a, b) = (EchoGuard::default(), EchoGuard::default());
        assert_ne!(a.tag("same"), b.tag("same"));
        assert_eq!(a.tag("same"), a.tag("same"));
    }
}
