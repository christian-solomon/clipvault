//! Decides where each capture goes: dropped, memory-only, or history.

use anyhow::Result;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use zeroize::Zeroizing;

use crate::clipboard::EchoGuard;
use crate::ephemeral::Ephemeral;
use crate::media;
use crate::secrets;
use crate::store::{hash_of, Clip, Store};
use crate::watcher::Captured;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// Written to history, with its row id.
    History(i64),
    /// Looked like a credential; held in memory only, with its clip id.
    Sensitive(u64),
}

#[derive(Clone)]
pub struct Recorder {
    pub store: Arc<Mutex<Store>>,
    pub ephemeral: Arc<Mutex<Ephemeral>>,
    pub guard: Arc<EchoGuard>,
}

impl Recorder {
    pub fn handle(&self, captured: Captured) -> Option<Recorded> {
        match captured {
            Captured::Text(text) => {
                // Wiped on drop, whichever branch below lets go of it.
                let text = Zeroizing::new(text);
                if text.trim().is_empty() || self.guard.should_drop(Some(&text), &hash_of(&text)) {
                    return None;
                }
                if let Some(kind) = secrets::detect(&text) {
                    log::info!("kept a copy in memory only: it looks like a {}", kind.describe());
                    let id = self.ephemeral.lock().unwrap().add(text, kind);
                    return Some(Recorded::Sensitive(id));
                }
                self.record(Clip::Text(text.to_string()))
            }
            Captured::Image(bytes) => {
                // Decoding and hashing happen here rather than on the X thread,
                // so a multi-megabyte screenshot cannot delay the next capture.
                let img = match media::prepare(&bytes) {
                    Ok(img) => img,
                    Err(e) => {
                        log::warn!("ignoring unreadable image on clipboard: {e}");
                        return None;
                    }
                };
                if self.guard.should_drop(None, &img.hash) {
                    return None;
                }
                self.record(Clip::Image(img))
            }
        }
    }

    fn record(&self, clip: Clip) -> Option<Recorded> {
        match self.store.lock().unwrap().record(&clip) {
            Ok(Some(id)) => Some(Recorded::History(id)),
            Ok(None) => None,
            Err(e) => {
                log::error!("failed to record clipboard entry: {e}");
                None
            }
        }
    }

    /// Runs on its own thread until the watcher hangs up.
    pub fn spawn(
        self,
        rx: Receiver<Captured>,
        notify: impl Fn(Recorded) + Send + 'static,
    ) -> Result<JoinHandle<()>> {
        Ok(std::thread::Builder::new().name("clipboard-recorder".into()).spawn(move || {
            while let Ok(captured) = rx.recv() {
                if let Some(event) = self.handle(captured) {
                    notify(event);
                }
            }
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tempdir::Dir;
    use std::time::{Duration, Instant};

    fn recorder() -> (Recorder, Dir) {
        let dir = Dir::new();
        let store = Store::open(&dir.path().join("r.db")).unwrap();
        (
            Recorder {
                store: Arc::new(Mutex::new(store)),
                ephemeral: Arc::new(Mutex::new(Ephemeral::new(Duration::from_secs(60)))),
                guard: Arc::new(EchoGuard::default()),
            },
            dir,
        )
    }

    fn on_disk(dir: &Dir, needle: &str) -> bool {
        ["r.db", "r.db-wal"].iter().any(|f| {
            std::fs::read(dir.path().join(f))
                .map(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes()))
                .unwrap_or(false)
        })
    }

    #[test]
    fn ordinary_text_goes_to_history() {
        let (r, _d) = recorder();
        let got = r.handle(Captured::Text("plain text".into()));
        assert!(matches!(got, Some(Recorded::History(_))));
        assert_eq!(r.store.lock().unwrap().list("", 10).unwrap().len(), 1);
    }

    #[test]
    fn a_credential_stays_in_memory_and_off_disk() {
        let (r, d) = recorder();
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let got = r.handle(Captured::Text(key.clone()));
        assert!(matches!(got, Some(Recorded::Sensitive(_))));
        assert!(r.store.lock().unwrap().list("", 10).unwrap().is_empty());
        assert_eq!(*r.ephemeral.lock().unwrap().items()[0].text, key);
        assert!(!on_disk(&d, &key));
    }

    #[test]
    fn a_vault_copy_is_dropped_even_after_other_captures() {
        let (r, d) = recorder();
        r.guard.guard_secret("vault-only value 42", Some(Instant::now() + Duration::from_secs(60)));
        // The race the old flag lost: something else arrives first.
        assert!(r.handle(Captured::Text("copied just before".into())).is_some());
        assert_eq!(r.handle(Captured::Text("vault-only value 42".into())), None);
        assert_eq!(r.handle(Captured::Text("vault-only value 42".into())), None);
        assert!(!on_disk(&d, "vault-only value 42"));
    }

    #[test]
    fn blank_copies_are_ignored() {
        let (r, _d) = recorder();
        assert_eq!(r.handle(Captured::Text("  \n ".into())), None);
    }

    #[test]
    fn unreadable_images_are_ignored() {
        let (r, _d) = recorder();
        assert_eq!(r.handle(Captured::Image(b"not a png".to_vec())), None);
    }
}
