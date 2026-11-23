//! Runtime configuration, read from the environment and nowhere else.
//!
//! Every knob has a default that matches how ClipVault behaved before it was
//! configurable, so an empty environment is a valid one. A variable that is set
//! but unparseable is an error rather than a silent fallback.

use anyhow::{anyhow, bail, Result};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Directory name under `$XDG_DATA_HOME`, shared with earlier releases so
/// existing history and vault are found in place.
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
    /// Set when `CLIPVAULT_MONGODB_URL` is; without it ClipVault is local-only.
    pub sync: Option<SyncSettings>,
}

/// Where and how to sync. The URL carries the database password, so `Debug`
/// shows only its scheme and host.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncSettings {
    /// `CLIPVAULT_MONGODB_URL`: `mongodb://` or `mongodb+srv://`.
    pub url: String,
    /// `CLIPVAULT_MONGODB_DB`, else the database named in the URL, else
    /// `clipvault`.
    pub database: String,
    /// `CLIPVAULT_DEVICE_NAME`, default the host name. Shown on other devices.
    pub device_name: String,
    /// `CLIPVAULT_SYNC_ADOPT=0` stops clips copied elsewhere landing on this
    /// clipboard; they still appear in history.
    pub adopt: bool,
}

impl SyncSettings {
    /// `scheme://host`, without user, password or options.
    pub fn redacted_url(&self) -> String {
        let (scheme, rest) = self.url.split_once("://").unwrap_or(("?", &self.url));
        let host = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
        let host = host.split(['/', '?']).next().unwrap_or("");
        format!("{scheme}://{host}")
    }
}

impl fmt::Debug for SyncSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncSettings")
            .field("url", &self.redacted_url())
            .field("database", &self.database)
            .field("device_name", &self.device_name)
            .field("adopt", &self.adopt)
            .finish()
    }
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
            sync: sync_settings(&set)?,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE)
    }
}

/// The database in a connection string's path: `…@host/<db>?options`.
fn url_database(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let rest = rest.split('?').next()?;
    let hosts_and_path = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let db = hosts_and_path.split_once('/')?.1;
    (!db.is_empty()).then(|| db.to_string())
}

fn sync_settings(set: &impl Fn(&str) -> Option<String>) -> Result<Option<SyncSettings>> {
    let Some(url) = set("CLIPVAULT_MONGODB_URL").map(|u| u.trim().to_string()) else {
        return Ok(None);
    };
    if !(url.starts_with("mongodb://") || url.starts_with("mongodb+srv://")) {
        bail!("CLIPVAULT_MONGODB_URL must start with mongodb:// or mongodb+srv://");
    }
    let adopt = match set("CLIPVAULT_SYNC_ADOPT").map(|v| v.trim().to_ascii_lowercase()) {
        None => true,
        Some(v) if ["1", "true", "yes", "on"].contains(&v.as_str()) => true,
        Some(v) if ["0", "false", "no", "off"].contains(&v.as_str()) => false,
        Some(v) => bail!("CLIPVAULT_SYNC_ADOPT={v:?} is not 0 or 1"),
    };
    let device_name = set("CLIPVAULT_DEVICE_NAME")
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "this computer".into());
    let database = set("CLIPVAULT_MONGODB_DB")
        .or_else(|| url_database(&url))
        .unwrap_or_else(|| "clipvault".into());
    Ok(Some(SyncSettings {
        url,
        database,
        device_name,
        adopt,
    }))
}

fn parse<T: std::str::FromStr>(
    set: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: T,
) -> Result<T> {
    match set(key) {
        None => Ok(default),
        Some(v) => {
            v.trim().parse().map_err(|_| anyhow!("{key}={v:?} is not a valid non-negative number"))
        }
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
        assert_eq!(
            c.db_path(),
            PathBuf::from("/home/u/.local/share/dev.local.clipvault/clipvault.db")
        );
        assert_eq!(c.history_max_entries, 500);
        assert_eq!(c.history_max_bytes, 256 * 1024 * 1024);
        assert_eq!(c.autolock, Duration::from_secs(600));
        assert_eq!(c.clipboard_clear, Duration::from_secs(30));
        assert_eq!(c.hotkey.as_deref(), Some("super+v"));
        assert!(!c.allow_debugger);
        assert!(c.sync.is_none(), "local-only unless a URL is given");
    }

    #[test]
    fn sync_settings_come_from_the_environment_and_hide_the_password() {
        let c = cfg(&[
            ("HOME", "/home/u"),
            (
                "CLIPVAULT_MONGODB_URL",
                "mongodb+srv://app:hunter2@cv.abc.mongodb.net/?retryWrites=true",
            ),
            ("CLIPVAULT_DEVICE_NAME", "laptop"),
            ("CLIPVAULT_SYNC_ADOPT", "0"),
        ])
        .unwrap();
        let sync = c.sync.unwrap();
        assert_eq!(sync.database, "clipvault");
        assert_eq!(sync.device_name, "laptop");
        assert!(!sync.adopt);
        assert_eq!(sync.redacted_url(), "mongodb+srv://cv.abc.mongodb.net");
        let shown = format!("{sync:?}");
        assert!(!shown.contains("hunter2") && !shown.contains("app:"), "{shown}");
    }

    #[test]
    fn the_database_comes_from_the_variable_then_the_url() {
        let db = |vars: &[(&str, &str)]| {
            let mut all = vec![("HOME", "/h")];
            all.extend_from_slice(vars);
            cfg(&all).unwrap().sync.unwrap().database
        };
        let url = "mongodb+srv://app:p%2Fw@cv.abc.mongodb.net/fromurl?retryWrites=true";
        assert_eq!(db(&[("CLIPVAULT_MONGODB_URL", url)]), "fromurl");
        assert_eq!(
            db(&[("CLIPVAULT_MONGODB_URL", url), ("CLIPVAULT_MONGODB_DB", "override")]),
            "override"
        );
        assert_eq!(db(&[("CLIPVAULT_MONGODB_URL", "mongodb://h1,h2/?w=1")]), "clipvault");
        assert_eq!(db(&[("CLIPVAULT_MONGODB_URL", "mongodb://u:p@h:27017")]), "clipvault");
    }

    #[test]
    fn a_bad_sync_url_or_flag_is_an_error() {
        assert!(cfg(&[("HOME", "/h"), ("CLIPVAULT_MONGODB_URL", "https://x")]).is_err());
        assert!(cfg(&[
            ("HOME", "/h"),
            ("CLIPVAULT_MONGODB_URL", "mongodb://x"),
            ("CLIPVAULT_SYNC_ADOPT", "maybe")
        ])
        .is_err());
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
