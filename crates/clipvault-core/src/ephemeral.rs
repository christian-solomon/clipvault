//! Copies that look like credentials, held in memory only.
//!
//! They show in the list like any other clip, expire after a configurable
//! time, and wipe themselves on removal. Keeping one means moving it into the
//! vault, or explicitly choosing to store it in plaintext history.

use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::secrets::Kind;
use crate::store::now;

/// Oldest entries are dropped beyond this, whatever their age.
const MAX_ITEMS: usize = 50;

pub struct SensitiveClip {
    pub id: u64,
    pub text: Zeroizing<String>,
    pub kind: Kind,
    /// Wall-clock time of the latest copy, for display.
    pub copied_at: i64,
    expires: Instant,
}

impl SensitiveClip {
    pub fn remaining(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }
}

pub struct Ephemeral {
    items: Vec<SensitiveClip>,
    next_id: u64,
    ttl: Duration,
}

impl Ephemeral {
    pub fn new(ttl: Duration) -> Self {
        Ephemeral { items: Vec::new(), next_id: 1, ttl }
    }

    /// Adds a clip, or refreshes and moves an identical one to the front.
    pub fn add(&mut self, text: Zeroizing<String>, kind: Kind) -> u64 {
        let expires = Instant::now() + self.ttl;
        if let Some(pos) = self.items.iter().position(|c| *c.text == *text) {
            let mut item = self.items.remove(pos);
            item.expires = expires;
            item.copied_at = now();
            let id = item.id;
            self.items.insert(0, item);
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.items.insert(0, SensitiveClip { id, text, kind, copied_at: now(), expires });
        self.items.truncate(MAX_ITEMS);
        id
    }

    /// Drops expired clips. Returns whether anything went.
    pub fn expire(&mut self) -> bool {
        let before = self.items.len();
        let now = Instant::now();
        self.items.retain(|c| c.expires > now);
        self.items.len() != before
    }

    /// Time until the next clip expires, for scheduling the next sweep.
    pub fn next_expiry(&self) -> Option<Duration> {
        self.items.iter().map(SensitiveClip::remaining).min()
    }

    /// Newest first.
    pub fn items(&self) -> &[SensitiveClip] {
        &self.items
    }

    pub fn get(&self, id: u64) -> Option<&SensitiveClip> {
        self.items.iter().find(|c| c.id == id)
    }

    pub fn remove(&mut self, id: u64) -> Option<Zeroizing<String>> {
        let pos = self.items.iter().position(|c| c.id == id)?;
        Some(self.items.remove(pos).text)
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn newest_first_and_identical_copies_merge() {
        let mut e = Ephemeral::new(Duration::from_secs(60));
        let a = e.add(z("one"), Kind::Jwt);
        e.add(z("two"), Kind::Jwt);
        assert_eq!(e.add(z("one"), Kind::Jwt), a, "same text keeps its id");
        let order: Vec<&str> = e.items().iter().map(|c| c.text.as_str()).collect();
        assert_eq!(order, ["one", "two"]);
    }

    #[test]
    fn clips_expire() {
        let mut e = Ephemeral::new(Duration::ZERO);
        e.add(z("gone"), Kind::RandomToken);
        assert!(e.expire());
        assert!(e.items().is_empty());
        assert!(!e.expire(), "nothing left to drop");
    }

    #[test]
    fn removal_hands_the_text_back_once() {
        let mut e = Ephemeral::new(Duration::from_secs(60));
        let id = e.add(z("secret"), Kind::GitHubToken);
        assert_eq!(e.remove(id).as_deref().map(String::as_str), Some("secret"));
        assert!(e.remove(id).is_none());
    }

    #[test]
    fn the_list_is_bounded() {
        let mut e = Ephemeral::new(Duration::from_secs(60));
        for i in 0..MAX_ITEMS + 5 {
            e.add(z(&format!("s{i}")), Kind::RandomToken);
        }
        assert_eq!(e.items().len(), MAX_ITEMS);
        assert_eq!(*e.items()[0].text, format!("s{}", MAX_ITEMS + 4));
    }

    #[test]
    fn next_expiry_tracks_the_soonest() {
        let mut e = Ephemeral::new(Duration::from_secs(60));
        assert!(e.next_expiry().is_none());
        e.add(z("x"), Kind::Jwt);
        assert!(e.next_expiry().unwrap() <= Duration::from_secs(60));
    }
}
