//! Runtime configuration, read from the environment and nowhere else.
//!
//! Every knob has a default that matches how ClipVault behaved before it was
//! configurable, so an empty environment is a valid one. A variable that is set
//! but unparseable is an error rather than a silent fallback.

use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;
use std::time::Duration;

/// Directory name under `$XDG_DATA_HOME`. Kept from the Tauri build so an
/// existing history and vault are picked up in place.
pub const APP_DIR: &str = "dev.local.clipvault";
const DB_FILE: &str = "clipvault.db";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `CLIPVAULT_DATA_DIR`. Holds the SQLite database.
    pub data_dir: PathBuf,
    /// `CLIPVAULT_HISTORY_MAX_ENTRIES`. Unpinned entries beyond this are evicted.
    pub history_max_entries: usize,
    /// `CLIPVAULT_HISTORY_MAX_BYTES`. Byte budget for unpinned entries.
    pub history_max_bytes: i64,
    /// `CLIPVAULT_AUTOLOCK_MINUTES`. Idle time before the vault key is dropped.
    pub autolock: Duration,
    /// `CLIPVAULT_CLIPBOARD_CLEAR_SECONDS`. How long a secret copied out of the
    /// vault stays on the clipboard. Zero leaves it there.
    pub clipboard_clear: Duration,
    /// `CLIPVAULT_SENSITIVE_TTL_SECONDS`. How long a copy that looks like a
    /// secret stays in the in-memory list.
    pub sensitive_ttl: Duration,
    /// `CLIPVAULT_HOTKEY`. `None` when set to `none` or empty.
    pub hotkey: Option<String>,
    /// `CLIPVAULT_ALLOW_DEBUGGER=1` keeps the process dumpable and traceable.
    pub allow_debugger: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Builds a config from any key lookup, so tests need not touch the
    /// process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());

        let data_dir = match set("CLIPVAULT_DATA_DIR") {
            Some(d) => PathBuf::from(d),
            None => {
                let base = set("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .or_else(|| set("HOME").map(|h| PathBuf::from(h).join(".local/share")))
                    .ok_or_else(|| {
                        anyhow!("cannot locate a data directory: set CLIPVAULT_DATA_DIR or HOME")
                    })?;
                base.join(APP_DIR)
            }
        };
        if !data_dir.is_absolute() {
            bail!("CLIPVAULT_DATA_DIR must be an absolute path");
        }

        let hotkey = match get("CLIPVAULT_HOTKEY") {
            None => Some("super+v".to_string()),
            Some(v) if v.trim().is_empty() || v.trim().eq_ignore_ascii_case("none") => None,
            Some(v) => Some(v.trim().to_lowercase()),
        };

        Ok(Config {
            data_dir,
            history_max_entries: parse(&set, "CLIPVAULT_HISTORY_MAX_ENTRIES", 500usize)?,
            history_max_bytes: parse(&set, "CLIPVAULT_HISTORY_MAX_BYTES", 256 * 1024 * 1024i64)?,
            autolock: Duration::from_secs(60 * parse(&set, "CLIPVAULT_AUTOLOCK_MINUTES", 10u64)?),
            clipboard_clear: Duration::from_secs(parse(
                &set,
                "CLIPVAULT_CLIPBOARD_CLEAR_SECONDS",
                30u64,
            )?),
            sensitive_ttl: Duration::from_secs(parse(
                &set,
                "CLIPVAULT_SENSITIVE_TTL_SECONDS",
                300u64,
            )?),
            hotkey,
            allow_debugger: set("CLIPVAULT_ALLOW_DEBUGGER").as_deref() == Some("1"),
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE)
    }
}

fn parse<T: std::str::FromStr>(
    set: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: T,
) -> Result<T> {
    match set(key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| anyhow!("{key}={v:?} is not a valid non-negative number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_match_the_original_constants() {
        let c = cfg(&[("HOME", "/home/u")]).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/home/u/.local/share/dev.local.clipvault"));
        assert_eq!(c.db_path(), PathBuf::from("/home/u/.local/share/dev.local.clipvault/clipvault.db"));
        assert_eq!(c.history_max_entries, 500);
        assert_eq!(c.history_max_bytes, 256 * 1024 * 1024);
        assert_eq!(c.autolock, Duration::from_secs(600));
        assert_eq!(c.clipboard_clear, Duration::from_secs(30));
        assert_eq!(c.hotkey.as_deref(), Some("super+v"));
        assert!(!c.allow_debugger);
    }

    #[test]
    fn xdg_data_home_wins_over_home() {
        let c = cfg(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "/data")]).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/data/dev.local.clipvault"));
    }

    #[test]
    fn explicit_data_dir_wins_over_everything() {
        let c = cfg(&[("HOME", "/home/u"), ("CLIPVAULT_DATA_DIR", "/tmp/cv")]).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/tmp/cv"));
    }

    #[test]
    fn relative_data_dir_is_rejected() {
        assert!(cfg(&[("CLIPVAULT_DATA_DIR", "relative/dir")]).is_err());
    }

    #[test]
    fn no_home_and_no_override_is_an_error() {
        assert!(cfg(&[]).is_err());
    }

    #[test]
    fn numbers_are_parsed_and_garbage_is_refused() {
        let c = cfg(&[("HOME", "/h"), ("CLIPVAULT_AUTOLOCK_MINUTES", "2")]).unwrap();
        assert_eq!(c.autolock, Duration::from_secs(120));
        let e = cfg(&[("HOME", "/h"), ("CLIPVAULT_AUTOLOCK_MINUTES", "ten")]).unwrap_err();
        assert!(e.to_string().contains("CLIPVAULT_AUTOLOCK_MINUTES"), "names the bad variable");
        assert!(cfg(&[("HOME", "/h"), ("CLIPVAULT_HISTORY_MAX_ENTRIES", "-1")]).is_err());
    }

    #[test]
    fn hotkey_can_be_disabled() {
        assert_eq!(cfg(&[("HOME", "/h"), ("CLIPVAULT_HOTKEY", "none")]).unwrap().hotkey, None);
        assert_eq!(cfg(&[("HOME", "/h"), ("CLIPVAULT_HOTKEY", "")]).unwrap().hotkey, None);
        assert_eq!(
            cfg(&[("HOME", "/h"), ("CLIPVAULT_HOTKEY", "Ctrl+Alt+V")]).unwrap().hotkey.as_deref(),
            Some("ctrl+alt+v")
        );
    }
}
