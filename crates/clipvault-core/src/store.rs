use crate::account::AccountKeys;
use crate::harden;
use crate::media::{human_size, ImageClip};
use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension, ToSql};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default cap on unpinned entries, dropped oldest first. Pins never expire.
const MAX_UNPINNED: usize = 500;
/// Unpinned entries are also held to a byte budget, because a few dozen
/// screenshots outweigh thousands of text clips and the count alone will not
/// notice. Pins are exempt from both limits: keeping them is a deliberate act.
const MAX_UNPINNED_BYTES: i64 = 256 * 1024 * 1024;
const PREVIEW_CHARS: usize = 220;

/// Schema history, tracked in `PRAGMA user_version`:
///
/// - 1: history with images, and the first vault (plaintext labels, entries
///   sealed directly with the password key). The Tauri releases shipped this
///   but never set `user_version`, so their databases read as 0.
/// - 2: `entries.sensitive`, and the vault tables `vault_key` and
///   `vault_items` (wrapped data key, sealed labels, AAD per row). A first-
///   generation vault is converted on its next unlock, since that needs the
///   password.
/// - 3: rows recorded before secret detection existed are scanned once, and
///   matches are flagged for review.
const SCHEMA_VERSION: i64 = 4;

/// Whether an entry looks like a credential, and whether anyone decided so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sensitivity {
    None,
    /// Found by the upgrade scan; nobody has looked at it yet.
    Flagged,
    /// Kept in history on purpose, in plaintext.
    Kept,
}

impl Sensitivity {
    pub fn from_db(v: i64) -> Self {
        match v {
            1 => Sensitivity::Flagged,
            2 => Sensitivity::Kept,
            _ => Sensitivity::None,
        }
    }

    pub fn to_db(self) -> i64 {
        match self {
            Sensitivity::None => 0,
            Sensitivity::Flagged => 1,
            Sensitivity::Kept => 2,
        }
    }
}

pub struct Entry {
    pub id: i64,
    pub kind: String,
    pub preview: String,
    pub truncated: bool,
    pub bytes: i64,
    pub pinned: bool,
    pub created_at: i64,
    pub last_used_at: i64,
    pub use_count: i64,
    pub width: Option<i64>,
    pub height: Option<i64>,
    /// PNG bytes for the list thumbnail; images only.
    pub thumb: Option<Vec<u8>>,
    /// Only rows kept on purpose, or recorded before detection existed, can
    /// be anything but `None`: new credentials never reach disk.
    pub sensitivity: Sensitivity,
    /// The device a synced entry was first copied on; `None` for this one.
    pub origin: Option<String>,
}

/// Something worth remembering off the clipboard.
pub enum Clip {
    Text(String),
    Image(ImageClip),
}

impl Clip {
    pub fn hash(&self) -> String {
        match self {
            Clip::Text(t) => hash_of(t),
            Clip::Image(i) => i.hash.clone(),
        }
    }
}

/// An AEAD output: the nonce it was sealed under and the ciphertext with tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
}

/// The vault's key record: KDF inputs plus the data key wrapped by the
/// password-derived key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKeyRow {
    pub salt: Vec<u8>,
    pub kdf_mem_kib: u32,
    pub kdf_passes: u32,
    pub kdf_lanes: u32,
    pub wrapped_dek: Sealed,
}

/// A vault row with its label still sealed.
pub struct SealedItem {
    pub id: i64,
    pub uid: Vec<u8>,
    pub label: Sealed,
    pub created_at: i64,
}

/// A row about to be written to `vault_items`.
pub struct NewSealedItem {
    pub uid: Vec<u8>,
    pub label: Sealed,
    pub secret: Sealed,
    pub created_at: i64,
}

/// A first-generation vault, read so it can be converted.
pub struct LegacyVault {
    pub salt: Vec<u8>,
    pub verifier: Sealed,
    pub entries: Vec<LegacyEntry>,
}

pub struct LegacyEntry {
    pub label: String,
    pub secret: Sealed,
    pub created_at: i64,
}

pub struct Store {
    conn: Connection,
    max_unpinned: usize,
    max_unpinned_bytes: i64,
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Milliseconds since the epoch: the clock sync orders changes by.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn hash_of(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    format!("{:x}", h.finalize())
}

fn preview_of(text: &str) -> (String, bool) {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let src = if collapsed.is_empty() { text.trim() } else { &collapsed };
    let mut out = String::new();
    for (i, c) in src.chars().enumerate() {
        if i >= PREVIEW_CHARS {
            return (out, true);
        }
        out.push(c);
    }
    (out, false)
}

impl Store {
    /// Opens or creates the database. The directory is made 0700 and the
    /// database with its WAL and shared-memory files 0600, tightening files
    /// left world-readable by earlier versions.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            harden::private_dir(dir)?;
        }
        // Tighten before SQLite opens it: SQLite gives the -wal and -shm files
        // the same mode as the database file.
        harden::private_file(path)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Overwrite deleted content with zeros instead of leaving it in free
        // pages, where a secret moved into the vault would otherwise survive.
        conn.pragma_update(None, "secure_delete", "ON")?;
        let store =
            Store { conn, max_unpinned: MAX_UNPINNED, max_unpinned_bytes: MAX_UNPINNED_BYTES };
        store.migrate()?;
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            harden::private_file(Path::new(&p))?;
        }
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }

    /// Replaces the default history limits, e.g. with values from `Config`.
    pub fn set_limits(&mut self, max_unpinned: usize, max_unpinned_bytes: i64) {
        self.max_unpinned = max_unpinned;
        self.max_unpinned_bytes = max_unpinned_bytes;
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            bail!(
                "this database was written by a newer ClipVault (schema {version}, \
                 this build understands up to {SCHEMA_VERSION})"
            );
        }
        if version < 1 {
            self.migrate_v1()?;
        }
        if version < 2 {
            self.migrate_v2()?;
        }
        if version < 3 {
            self.migrate_v3()?;
        }
        if version < 4 {
            self.migrate_v4()?;
        }
        Ok(())
    }

    /// Creates the original schema, or completes one written by a Tauri
    /// release from before images.
    fn migrate_v1(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS entries (
                id           INTEGER PRIMARY KEY,
                content      TEXT    NOT NULL,
                hash         TEXT    NOT NULL UNIQUE,
                preview      TEXT    NOT NULL,
                truncated    INTEGER NOT NULL DEFAULT 0,
                bytes        INTEGER NOT NULL,
                pinned       INTEGER NOT NULL DEFAULT 0,
                created_at   INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL,
                use_count    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_entries_recent
                ON entries (pinned DESC, last_used_at DESC);

            CREATE TABLE IF NOT EXISTS vault_meta (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                salt          BLOB NOT NULL,
                verify_nonce  BLOB NOT NULL,
                verify_ct     BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_entries (
                id         INTEGER PRIMARY KEY,
                label      TEXT NOT NULL,
                nonce      BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            "#,
        )?;
        self.add_image_columns()?;
        self.conn.pragma_update(None, "user_version", 1)?;
        Ok(())
    }

    /// Images arrived after the first release, so the columns are added to
    /// whatever table is already on disk rather than assumed present.
    fn add_image_columns(&self) -> Result<()> {
        let existing: Vec<String> = self
            .conn
            .prepare("SELECT name FROM pragma_table_info('entries')")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;

        for (name, decl) in [
            ("kind", "TEXT NOT NULL DEFAULT 'text'"),
            ("blob", "BLOB"),
            ("thumb", "BLOB"),
            ("width", "INTEGER"),
            ("height", "INTEGER"),
        ] {
            if !existing.iter().any(|c| c == name) {
                self.conn.execute(&format!("ALTER TABLE entries ADD COLUMN {name} {decl}"), [])?;
            }
        }
        Ok(())
    }

    fn migrate_v2(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            r#"
            ALTER TABLE entries ADD COLUMN sensitive INTEGER NOT NULL DEFAULT 0;

            CREATE TABLE vault_key (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                salt         BLOB    NOT NULL,
                kdf_mem_kib  INTEGER NOT NULL,
                kdf_passes   INTEGER NOT NULL,
                kdf_lanes    INTEGER NOT NULL,
                dek_nonce    BLOB    NOT NULL,
                dek_wrapped  BLOB    NOT NULL
            );
            CREATE TABLE vault_items (
                id            INTEGER PRIMARY KEY,
                uid           BLOB    NOT NULL UNIQUE,
                label_nonce   BLOB    NOT NULL,
                label_ct      BLOB    NOT NULL,
                secret_nonce  BLOB    NOT NULL,
                secret_ct     BLOB    NOT NULL,
                created_at    INTEGER NOT NULL
            );
            "#,
        )?;
        // A first-generation vault needs the password to convert, so its
        // tables stay until the next unlock. Without one they are dead weight.
        let legacy: bool =
            tx.query_row("SELECT EXISTS (SELECT 1 FROM vault_meta)", [], |r| r.get(0))?;
        if !legacy {
            tx.execute_batch("DROP TABLE vault_entries; DROP TABLE vault_meta;")?;
        }
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;

        // Anything deleted before secure_delete was turned on still sits in
        // free pages. Rebuilding the file is the only way to drop it.
        self.compact()
    }

    /// History recorded before detection existed may hold credentials. They
    /// are flagged rather than deleted: the user decides.
    fn migrate_v3(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let hits: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT id, content FROM entries WHERE kind = 'text'")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
            let mut hits = Vec::new();
            for row in rows {
                let (id, content) = row?;
                if crate::secrets::detect(&content).is_some() {
                    hits.push(id);
                }
            }
            hits
        };
        for id in &hits {
            tx.execute("UPDATE entries SET sensitive = 1 WHERE id = ?1", params![id])?;
        }
        tx.pragma_update(None, "user_version", 3)?;
        tx.commit()?;
        if !hits.is_empty() {
            log::info!(
                "{} history entries look like credentials and are flagged for review",
                hits.len()
            );
        }
        Ok(())
    }

    /// Change tracking for sync. Every row starts dirty, so the first sync
    /// uploads what is already here; deletes of synced rows leave tombstones.
    /// Columns are added only where missing, so a rerun is harmless.
    fn migrate_v4(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        add_missing_columns(
            &tx,
            "entries",
            &[
                ("fp", "TEXT"),
                ("updated_at", "INTEGER NOT NULL DEFAULT 0"),
                ("dirty", "INTEGER NOT NULL DEFAULT 1"),
                ("origin", "TEXT"),
            ],
        )?;
        add_missing_columns(
            &tx,
            "vault_items",
            &[
                ("updated_at", "INTEGER NOT NULL DEFAULT 0"),
                ("dirty", "INTEGER NOT NULL DEFAULT 1"),
            ],
        )?;
        add_missing_columns(
            &tx,
            "vault_key",
            &[
                ("account_id", "BLOB"),
                ("hist_nonce", "BLOB"),
                ("hist_ct", "BLOB"),
                ("hist_check", "BLOB"),
                ("updated_at", "INTEGER NOT NULL DEFAULT 0"),
                ("dirty", "INTEGER NOT NULL DEFAULT 0"),
            ],
        )?;
        tx.execute_batch(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_fp ON entries (fp) WHERE fp IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_entries_dirty ON entries (dirty) WHERE dirty = 1;
            UPDATE entries SET updated_at = last_used_at * 1000 WHERE updated_at = 0;
            UPDATE vault_items SET updated_at = created_at * 1000 WHERE updated_at = 0;
            CREATE TABLE IF NOT EXISTS tombstones (
                kind       TEXT    NOT NULL,
                id         TEXT    NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (kind, id)
            );
            CREATE TABLE IF NOT EXISTS sync_state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        tx.pragma_update(None, "user_version", 4)?;
        tx.commit()?;
        Ok(())
    }

    /// Folds the WAL back into the database and truncates it, so content
    /// removed by a delete does not linger in old WAL frames.
    pub fn scrub(&self) -> Result<()> {
        let busy: i64 = self.conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            log::warn!("WAL checkpoint was blocked; deleted content may linger until the next one");
        }
        Ok(())
    }

    /// Rebuilds the database file without its free pages, then scrubs the WAL.
    pub fn compact(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM")?;
        self.scrub()
    }

    // ---- history -------------------------------------------------------

    /// Returns the row id, or None when there was nothing worth keeping.
    pub fn record(&self, clip: &Clip) -> Result<Option<i64>> {
        if let Clip::Text(t) = clip {
            if t.trim().is_empty() {
                return Ok(None);
            }
        }
        let hash = clip.hash();
        let ts = now();

        // Re-copying something already in history moves it back to the top
        // rather than creating a duplicate row.
        let existing: Option<i64> = self
            .conn
            .query_row("SELECT id FROM entries WHERE hash = ?1", params![hash], |r| r.get(0))
            .optional()?;

        if let Some(id) = existing {
            self.conn.execute(
                "UPDATE entries SET last_used_at = ?1, use_count = use_count + 1,
                        dirty = 1, updated_at = ?2
                 WHERE id = ?3",
                params![ts, now_ms(), id],
            )?;
            return Ok(Some(id));
        }

        match clip {
            Clip::Text(text) => {
                let (preview, truncated) = preview_of(text);
                self.conn.execute(
                    "INSERT INTO entries
                       (kind, content, hash, preview, truncated, bytes, created_at, last_used_at,
                        updated_at)
                     VALUES ('text', ?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
                    params![text, hash, preview, truncated as i64, text.len() as i64, ts, now_ms()],
                )?;
            }
            Clip::Image(img) => {
                let preview =
                    format!("Image {}x{} - {}", img.width, img.height, human_size(img.png.len()));
                self.conn.execute(
                    "INSERT INTO entries
                       (kind, content, hash, preview, truncated, bytes, created_at, last_used_at,
                        blob, thumb, width, height, updated_at)
                     VALUES ('image', '', ?1, ?2, 0, ?3, ?4, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        hash,
                        preview,
                        img.png.len() as i64,
                        ts,
                        img.png,
                        img.thumb_png,
                        img.width as i64,
                        img.height as i64,
                        now_ms()
                    ],
                )?;
            }
        }

        let id = self.conn.last_insert_rowid();
        self.trim()?;
        Ok(Some(id))
    }

    fn trim(&self) -> Result<()> {
        self.trim_to(self.max_unpinned, self.max_unpinned_bytes)
    }

    fn trim_to(&self, max_unpinned: usize, max_bytes: i64) -> Result<()> {
        self.remove_entries(
            "SELECT id FROM entries WHERE pinned = 0 AND id NOT IN (
                 SELECT id FROM entries WHERE pinned = 0
                 ORDER BY last_used_at DESC LIMIT ?1
             )",
            &[&(max_unpinned as i64)],
        )?;

        // Walk newest to oldest and drop everything past the budget. The sum
        // excludes the row itself, so the most recent entry always survives even
        // if it alone is larger than the budget - having just copied something
        // and finding it already gone would be worse than briefly overshooting.
        self.remove_entries(
            "SELECT id FROM (
                 SELECT id, SUM(bytes) OVER (
                     ORDER BY last_used_at DESC, id DESC
                     ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                 ) AS preceding_bytes
                 FROM entries WHERE pinned = 0
             ) WHERE preceding_bytes >= ?1",
            &[&max_bytes],
        )?;
        Ok(())
    }

    /// Deletes the entries a subquery selects. Those already synced leave a
    /// tombstone, so the deletion reaches every device.
    fn remove_entries(&self, ids: &str, params: &[&dyn ToSql]) -> Result<usize> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            &format!(
                "INSERT OR REPLACE INTO tombstones (kind, id, updated_at)
                 SELECT 'clip', fp, {} FROM entries WHERE fp IS NOT NULL AND id IN ({ids})",
                now_ms()
            ),
            params,
        )?;
        let n = tx.execute(&format!("DELETE FROM entries WHERE id IN ({ids})"), params)?;
        tx.commit()?;
        Ok(n)
    }

    pub fn list(&self, query: &str, limit: i64) -> Result<Vec<Entry>> {
        let q = query.trim();
        // Substring match, not full-text: clipboard searches are things like
        // "AKIA" inside a key or a fragment of a URL, which a word tokenizer
        // would never match.
        let (sql, like) = if q.is_empty() {
            (
                "SELECT id, kind, preview, truncated, bytes, pinned, created_at, last_used_at,
                        use_count, width, height, thumb, sensitive, origin
                 FROM entries
                 ORDER BY pinned DESC, last_used_at DESC LIMIT ?1"
                    .to_string(),
                None,
            )
        } else {
            (
                "SELECT id, kind, preview, truncated, bytes, pinned, created_at, last_used_at,
                        use_count, width, height, thumb, sensitive, origin
                 FROM entries
                 WHERE (content LIKE ?2 ESCAPE '\\' OR (kind = 'image' AND preview LIKE ?2 ESCAPE '\\'))
                 ORDER BY pinned DESC, last_used_at DESC LIMIT ?1"
                    .to_string(),
                Some(format!(
                    "%{}%",
                    q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
                )),
            )
        };

        let mut stmt = self.conn.prepare(&sql)?;
        let map = |r: &rusqlite::Row| -> rusqlite::Result<Entry> {
            Ok(Entry {
                id: r.get(0)?,
                kind: r.get(1)?,
                preview: r.get(2)?,
                truncated: r.get::<_, i64>(3)? != 0,
                bytes: r.get(4)?,
                pinned: r.get::<_, i64>(5)? != 0,
                created_at: r.get(6)?,
                last_used_at: r.get(7)?,
                use_count: r.get(8)?,
                width: r.get(9)?,
                height: r.get(10)?,
                thumb: r.get(11)?,
                sensitivity: Sensitivity::from_db(r.get(12)?),
                origin: r.get(13)?,
            })
        };
        let rows = match like {
            Some(l) => stmt.query_map(params![limit, l], map)?.collect::<Result<Vec<_>, _>>()?,
            None => stmt.query_map(params![limit], map)?.collect::<Result<Vec<_>, _>>()?,
        };
        Ok(rows)
    }

    pub fn content(&self, id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT content FROM entries WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?)
    }

    pub fn image_png(&self, id: i64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT blob FROM entries WHERE id = ?1 AND kind = 'image'",
                params![id],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    pub fn kind(&self, id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT kind FROM entries WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?)
    }

    pub fn mark_used(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET last_used_at = ?1, use_count = use_count + 1,
                    dirty = 1, updated_at = ?2
             WHERE id = ?3",
            params![now(), now_ms(), id],
        )?;
        Ok(())
    }

    pub fn set_pinned(&self, id: i64, pinned: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET pinned = ?1, dirty = 1, updated_at = ?2 WHERE id = ?3",
            params![pinned as i64, now_ms(), id],
        )?;
        Ok(())
    }

    pub fn set_sensitivity(&self, id: i64, s: Sensitivity) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET sensitive = ?1, dirty = 1, updated_at = ?2 WHERE id = ?3",
            params![s.to_db(), now_ms(), id],
        )?;
        Ok(())
    }

    /// Stores a credential in plaintext history because the user chose to,
    /// pinned so it is not quietly evicted.
    pub fn keep_sensitive(&self, text: &str) -> Result<i64> {
        let id = self
            .record(&Clip::Text(text.to_string()))?
            .ok_or_else(|| anyhow::anyhow!("nothing to keep"))?;
        self.set_pinned(id, true)?;
        self.set_sensitivity(id, Sensitivity::Kept)?;
        Ok(id)
    }

    /// Rows the upgrade scan flagged and nobody has reviewed.
    pub fn flagged_count(&self) -> Result<usize> {
        let n: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM entries WHERE sensitive = 1", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn delete_flagged(&self) -> Result<usize> {
        let n = self.remove_entries("SELECT id FROM entries WHERE sensitive = 1", &[])?;
        self.scrub()?;
        Ok(n)
    }

    pub fn delete(&self, id: i64) -> Result<()> {
        self.remove_entries("SELECT ?1", &[&id])?;
        self.scrub()
    }

    /// Clears history and returns how many entries went. Pinned entries
    /// survive unless `include_pinned`; the vault is not history.
    pub fn clear(&self, include_pinned: bool) -> Result<usize> {
        let n = if include_pinned {
            self.remove_entries("SELECT id FROM entries", &[])?
        } else {
            self.remove_entries("SELECT id FROM entries WHERE pinned = 0", &[])?
        };
        self.scrub()?;
        Ok(n)
    }

    /// Unpinned and pinned history entries.
    pub fn history_counts(&self) -> Result<(usize, usize)> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE pinned = 0), COUNT(*) FILTER (WHERE pinned != 0)
             FROM entries",
            [],
            |r| Ok((r.get::<_, i64>(0)? as usize, r.get::<_, i64>(1)? as usize)),
        )?)
    }

    // ---- vault ---------------------------------------------------------
    //
    // The store only moves sealed bytes around; `vault.rs` owns every key.

    pub fn vault_key(&self) -> Result<Option<VaultKeyRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT salt, kdf_mem_kib, kdf_passes, kdf_lanes, dek_nonce, dek_wrapped
                 FROM vault_key WHERE id = 1",
                [],
                |r| {
                    Ok(VaultKeyRow {
                        salt: r.get(0)?,
                        kdf_mem_kib: r.get(1)?,
                        kdf_passes: r.get(2)?,
                        kdf_lanes: r.get(3)?,
                        wrapped_dek: Sealed { nonce: r.get(4)?, ct: r.get(5)? },
                    })
                },
            )
            .optional()?)
    }

    /// Writes the key record. Used on creation and on a password change, which
    /// rewraps the same data key, so no item needs re-encrypting.
    pub fn set_vault_key(&self, key: &VaultKeyRow) -> Result<()> {
        if self.account()?.is_some() {
            bail!("the vault key belongs to the sync account; change it through the account");
        }
        insert_key(&self.conn, key, "INSERT OR REPLACE")?;
        // The old wrapping is as good as the old password; do not keep it.
        self.scrub()
    }

    fn has_table(&self, name: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            params![name],
            |r| r.get(0),
        )?)
    }

    /// The first-generation vault, if this database still holds one.
    pub fn legacy_vault(&self) -> Result<Option<LegacyVault>> {
        if !self.has_table("vault_meta")? {
            return Ok(None);
        }
        let meta = self
            .conn
            .query_row(
                "SELECT salt, verify_nonce, verify_ct FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, Sealed { nonce: r.get(1)?, ct: r.get(2)? })),
            )
            .optional()?;
        let Some((salt, verifier)) = meta else {
            return Ok(None);
        };
        let entries = self
            .conn
            .prepare("SELECT label, nonce, ciphertext, created_at FROM vault_entries ORDER BY id")?
            .query_map([], |r| {
                Ok(LegacyEntry {
                    label: r.get(0)?,
                    secret: Sealed { nonce: r.get(1)?, ct: r.get(2)? },
                    created_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(LegacyVault { salt, verifier, entries }))
    }

    /// Swaps a first-generation vault for its converted form in one
    /// transaction, then rebuilds the file so the plaintext labels are gone
    /// from it rather than merely unreferenced.
    pub fn replace_legacy_vault(&self, key: &VaultKeyRow, items: &[NewSealedItem]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        insert_key(&tx, key, "INSERT")?;
        for item in items {
            insert_item(&tx, item)?;
        }
        tx.execute_batch("DROP TABLE vault_entries; DROP TABLE vault_meta;")?;
        tx.commit()?;
        self.compact()
    }

    pub fn vault_count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM vault_items", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn vault_items(&self) -> Result<Vec<SealedItem>> {
        let rows = self
            .conn
            .prepare(
                "SELECT id, uid, label_nonce, label_ct, created_at FROM vault_items ORDER BY id",
            )?
            .query_map([], |r| {
                Ok(SealedItem {
                    id: r.get(0)?,
                    uid: r.get(1)?,
                    label: Sealed { nonce: r.get(2)?, ct: r.get(3)? },
                    created_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The row's uid (its AAD) and sealed secret.
    pub fn vault_secret(&self, id: i64) -> Result<Option<(Vec<u8>, Sealed)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT uid, secret_nonce, secret_ct FROM vault_items WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, Sealed { nonce: r.get(1)?, ct: r.get(2)? })),
            )
            .optional()?)
    }

    pub fn vault_insert(&self, item: &NewSealedItem) -> Result<i64> {
        insert_item(&self.conn, item)?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts the sealed copy and deletes the plaintext history row together,
    /// so a crash cannot leave the secret in both places or in neither.
    pub fn move_entry_into_vault(&self, entry_id: i64, item: &NewSealedItem) -> Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        insert_item(&tx, item)?;
        let new_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT OR REPLACE INTO tombstones (kind, id, updated_at)
             SELECT 'clip', fp, ?2 FROM entries WHERE id = ?1 AND fp IS NOT NULL",
            params![entry_id, now_ms()],
        )?;
        let gone = tx.execute("DELETE FROM entries WHERE id = ?1", params![entry_id])?;
        if gone != 1 {
            bail!("entry no longer exists");
        }
        tx.commit()?;
        self.scrub()?;
        Ok(new_id)
    }

    pub fn vault_delete(&self, id: i64) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tombstone_vault_items(&tx, "SELECT ?1", &[&id])?;
        tx.execute("DELETE FROM vault_items WHERE id = ?1", params![id])?;
        tx.commit()?;
        self.scrub()
    }

    /// Removes the vault, either generation, and rebuilds the file so none of
    /// it, the first generation's plaintext labels included, stays on disk.
    pub fn reset_vault(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tombstone_vault_items(&tx, "SELECT id FROM vault_items", &[])?;
        tx.execute_batch(
            "DELETE FROM vault_items;
             DELETE FROM vault_key;
             DROP TABLE IF EXISTS vault_entries;
             DROP TABLE IF EXISTS vault_meta;",
        )?;
        tx.commit()?;
        self.compact()
    }

    // ---- sync bookkeeping ------------------------------------------------

    /// The sync account mirrored in the vault key row, if this device has one.
    pub fn account(&self) -> Result<Option<AccountKeys>> {
        Ok(self
            .conn
            .query_row(
                "SELECT account_id, salt, kdf_mem_kib, kdf_passes, kdf_lanes,
                        dek_nonce, dek_wrapped, hist_nonce, hist_ct, hist_check
                 FROM vault_key WHERE id = 1 AND account_id IS NOT NULL",
                [],
                |r| {
                    Ok(AccountKeys {
                        account_id: r.get(0)?,
                        salt: r.get(1)?,
                        kdf_mem_kib: r.get(2)?,
                        kdf_passes: r.get(3)?,
                        kdf_lanes: r.get(4)?,
                        vault_dek: Sealed { nonce: r.get(5)?, ct: r.get(6)? },
                        history_key: Sealed { nonce: r.get(7)?, ct: r.get(8)? },
                        history_check: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// Stores the account as this device's vault key row. `dirty` when the
    /// change is this device's and still has to reach the other devices.
    pub fn set_account(&self, keys: &AccountKeys, updated_at: i64, dirty: bool) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_key
               (id, salt, kdf_mem_kib, kdf_passes, kdf_lanes, dek_nonce, dek_wrapped,
                account_id, hist_nonce, hist_ct, hist_check, updated_at, dirty)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                keys.salt,
                keys.kdf_mem_kib,
                keys.kdf_passes,
                keys.kdf_lanes,
                keys.vault_dek.nonce,
                keys.vault_dek.ct,
                keys.account_id,
                keys.history_key.nonce,
                keys.history_key.ct,
                keys.history_check,
                updated_at,
                dirty as i64
            ],
        )?;
        self.scrub()
    }

    /// Deletes every vault item, leaving tombstones so other devices follow,
    /// and marks the vault for a fresh start. The account row stays.
    pub fn reset_synced_vault(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tombstone_vault_items(&tx, "SELECT id FROM vault_items", &[])?;
        tx.execute_batch(
            "DELETE FROM vault_items;
             INSERT OR REPLACE INTO sync_state (key, value) VALUES ('vault_reset', '1');",
        )?;
        tx.commit()?;
        self.compact()
    }

    pub fn vault_was_reset(&self) -> Result<bool> {
        Ok(self.sync_value("vault_reset")?.is_some())
    }

    pub fn clear_vault_reset(&self) -> Result<()> {
        self.conn.execute("DELETE FROM sync_state WHERE key = 'vault_reset'", [])?;
        Ok(())
    }

    pub fn sync_value(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM sync_state WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_sync_value(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_state (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// This install's random ID, made on first use. Remote changes carry the
    /// ID of the device that made them.
    pub fn device_id(&self) -> Result<String> {
        if let Some(id) = self.sync_value("device_id")? {
            return Ok(id);
        }
        let id = crate::crypto::hex(&crate::crypto::random::<16>());
        self.set_sync_value("device_id", &id)?;
        Ok(id)
    }
}

/// A history row as the sync engine uploads it.
pub struct LocalClip {
    pub id: i64,
    pub fp: Option<String>,
    pub kind: String,
    /// The identity hash dedupe uses: SHA-256 of the text, or of the pixels.
    pub hash: String,
    pub content: String,
    pub blob: Option<Vec<u8>>,
    pub thumb: Option<Vec<u8>>,
    pub preview: String,
    pub truncated: bool,
    pub bytes: i64,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub pinned: bool,
    pub created_at: i64,
    pub last_used_at: i64,
    pub use_count: i64,
    pub sensitivity: Sensitivity,
    pub updated_at: i64,
}

/// The fields of a synced clip that change after it is first copied.
pub struct ClipState {
    pub pinned: bool,
    pub last_used_at: i64,
    pub use_count: i64,
    pub sensitivity: Sensitivity,
    pub updated_at: i64,
}

/// A vault row as the sync engine uploads it; the ciphertext travels as is.
pub struct LocalVaultItem {
    pub uid: Vec<u8>,
    pub label: Sealed,
    pub secret: Sealed,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    pub kind: String,
    pub id: String,
    pub updated_at: i64,
}

/// Reads and writes for the sync engine. Applying a remote change never marks
/// anything dirty or leaves a tombstone: it came from elsewhere already.
impl Store {
    pub fn dirty_clips(&self, limit: i64) -> Result<Vec<LocalClip>> {
        let rows = self
            .conn
            .prepare(
                "SELECT id, fp, kind, hash, content, blob, thumb, preview, truncated, bytes,
                        width, height, pinned, created_at, last_used_at, use_count, sensitive,
                        updated_at
                 FROM entries WHERE dirty = 1 ORDER BY updated_at LIMIT ?1",
            )?
            .query_map(params![limit], |r| {
                Ok(LocalClip {
                    id: r.get(0)?,
                    fp: r.get(1)?,
                    kind: r.get(2)?,
                    hash: r.get(3)?,
                    content: r.get(4)?,
                    blob: r.get(5)?,
                    thumb: r.get(6)?,
                    preview: r.get(7)?,
                    truncated: r.get::<_, i64>(8)? != 0,
                    bytes: r.get(9)?,
                    width: r.get(10)?,
                    height: r.get(11)?,
                    pinned: r.get::<_, i64>(12)? != 0,
                    created_at: r.get(13)?,
                    last_used_at: r.get(14)?,
                    use_count: r.get(15)?,
                    sensitivity: Sensitivity::from_db(r.get(16)?),
                    updated_at: r.get(17)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn set_fp(&self, id: i64, fp: &str) -> Result<()> {
        self.conn.execute("UPDATE entries SET fp = ?1 WHERE id = ?2", params![fp, id])?;
        Ok(())
    }

    /// Clears the flag unless the row changed again since it was read.
    pub fn mark_clip_clean(&self, id: i64, updated_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET dirty = 0 WHERE id = ?1 AND updated_at = ?2",
            params![id, updated_at],
        )?;
        Ok(())
    }

    /// The local row a fingerprint names, with its last change time.
    pub fn clip_by_fp(&self, fp: &str) -> Result<Option<(i64, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT id, updated_at FROM entries WHERE fp = ?1", params![fp], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
    }

    /// A row with the same content recorded here before it had a fingerprint.
    pub fn clip_by_hash(&self, hash: &str) -> Result<Option<(i64, Option<String>, i64)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, fp, updated_at FROM entries WHERE hash = ?1",
                params![hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Inserts a clip another device copied. Returns the new row id.
    pub fn insert_remote_clip(
        &self,
        fp: &str,
        clip: &Clip,
        state: &ClipState,
        created_at: i64,
        origin: Option<&str>,
    ) -> Result<i64> {
        let id = self
            .record(clip)?
            .ok_or_else(|| anyhow::anyhow!("remote clip {fp} has nothing in it"))?;
        self.conn.execute(
            "UPDATE entries SET fp = ?1, created_at = ?2, origin = ?3 WHERE id = ?4",
            params![fp, created_at, origin, id],
        )?;
        self.apply_clip_state(id, state)?;
        Ok(id)
    }

    /// Takes the remote side's pinned, last-used and flag state.
    pub fn apply_clip_state(&self, id: i64, state: &ClipState) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET pinned = ?1, last_used_at = ?2, use_count = ?3, sensitive = ?4,
                    updated_at = ?5, dirty = 0
             WHERE id = ?6",
            params![
                state.pinned as i64,
                state.last_used_at,
                state.use_count,
                state.sensitivity.to_db(),
                state.updated_at,
                id
            ],
        )?;
        Ok(())
    }

    /// Removes a clip another device deleted, without a tombstone of its own.
    pub fn delete_remote_clip(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        self.scrub()
    }

    /// Applies the history limits, e.g. after pulling another device's copies.
    pub fn enforce_limits(&self) -> Result<()> {
        self.trim()
    }

    pub fn dirty_vault_items(&self) -> Result<Vec<LocalVaultItem>> {
        let rows = self
            .conn
            .prepare(
                "SELECT uid, label_nonce, label_ct, secret_nonce, secret_ct, created_at, updated_at
                 FROM vault_items WHERE dirty = 1 ORDER BY updated_at",
            )?
            .query_map([], |r| {
                Ok(LocalVaultItem {
                    uid: r.get(0)?,
                    label: Sealed { nonce: r.get(1)?, ct: r.get(2)? },
                    secret: Sealed { nonce: r.get(3)?, ct: r.get(4)? },
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn mark_vault_item_clean(&self, uid: &[u8], updated_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE vault_items SET dirty = 0 WHERE uid = ?1 AND updated_at = ?2",
            params![uid, updated_at],
        )?;
        Ok(())
    }

    pub fn vault_item_updated_at(&self, uid: &[u8]) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT updated_at FROM vault_items WHERE uid = ?1", params![uid], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn upsert_remote_vault_item(&self, item: &LocalVaultItem) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vault_items
               (uid, label_nonce, label_ct, secret_nonce, secret_ct, created_at, updated_at, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
             ON CONFLICT (uid) DO UPDATE SET
               label_nonce = excluded.label_nonce, label_ct = excluded.label_ct,
               secret_nonce = excluded.secret_nonce, secret_ct = excluded.secret_ct,
               updated_at = excluded.updated_at, dirty = 0",
            params![
                item.uid,
                item.label.nonce,
                item.label.ct,
                item.secret.nonce,
                item.secret.ct,
                item.created_at,
                item.updated_at
            ],
        )?;
        Ok(())
    }

    /// Replaces an item's ciphertexts after a key change; it then needs upload.
    pub fn reseal_vault_item(&self, uid: &[u8], label: &Sealed, secret: &Sealed) -> Result<()> {
        self.conn.execute(
            "UPDATE vault_items SET label_nonce = ?1, label_ct = ?2, secret_nonce = ?3,
                    secret_ct = ?4, updated_at = ?5, dirty = 1
             WHERE uid = ?6",
            params![label.nonce, label.ct, secret.nonce, secret.ct, now_ms(), uid],
        )?;
        Ok(())
    }

    pub fn delete_remote_vault_item(&self, uid: &[u8]) -> Result<()> {
        self.conn.execute("DELETE FROM vault_items WHERE uid = ?1", params![uid])?;
        self.scrub()
    }

    pub fn tombstones(&self) -> Result<Vec<Tombstone>> {
        let rows = self
            .conn
            .prepare("SELECT kind, id, updated_at FROM tombstones ORDER BY updated_at")?
            .query_map([], |r| {
                Ok(Tombstone { kind: r.get(0)?, id: r.get(1)?, updated_at: r.get(2)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn drop_tombstone(&self, t: &Tombstone) -> Result<()> {
        self.conn.execute(
            "DELETE FROM tombstones WHERE kind = ?1 AND id = ?2 AND updated_at = ?3",
            params![t.kind, t.id, t.updated_at],
        )?;
        Ok(())
    }

    /// When this device changed the account and has not uploaded it yet.
    pub fn account_change(&self) -> Result<Option<(AccountKeys, i64, bool)>> {
        let Some(keys) = self.account()? else { return Ok(None) };
        let (updated_at, dirty): (i64, i64) = self.conn.query_row(
            "SELECT updated_at, dirty FROM vault_key WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(Some((keys, updated_at, dirty != 0)))
    }

    pub fn mark_account_clean(&self, updated_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE vault_key SET dirty = 0 WHERE id = 1 AND updated_at = ?1",
            params![updated_at],
        )?;
        Ok(())
    }
}

fn add_missing_columns(conn: &Connection, table: &str, columns: &[(&str, &str)]) -> Result<()> {
    let existing: Vec<String> = conn
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for (name, decl) in columns {
        if !existing.iter().any(|c| c == name) {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {name} {decl}"), [])?;
        }
    }
    Ok(())
}

fn tombstone_vault_items(conn: &Connection, ids: &str, params: &[&dyn ToSql]) -> Result<()> {
    let uids: Vec<Vec<u8>> = conn
        .prepare(&format!("SELECT uid FROM vault_items WHERE id IN ({ids})"))?
        .query_map(params, |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let ts = now_ms();
    for uid in uids {
        conn.execute(
            "INSERT OR REPLACE INTO tombstones (kind, id, updated_at) VALUES ('vault', ?1, ?2)",
            params![crate::crypto::hex(&uid), ts],
        )?;
    }
    Ok(())
}

fn insert_key(conn: &Connection, key: &VaultKeyRow, verb: &str) -> Result<()> {
    conn.execute(
        &format!(
            "{verb} INTO vault_key
               (id, salt, kdf_mem_kib, kdf_passes, kdf_lanes, dek_nonce, dek_wrapped)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)"
        ),
        params![
            key.salt,
            key.kdf_mem_kib,
            key.kdf_passes,
            key.kdf_lanes,
            key.wrapped_dek.nonce,
            key.wrapped_dek.ct
        ],
    )?;
    Ok(())
}

fn insert_item(conn: &Connection, item: &NewSealedItem) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_items
           (uid, label_nonce, label_ct, secret_nonce, secret_ct, created_at, updated_at, dirty)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
        params![
            item.uid,
            item.label.nonce,
            item.label.ct,
            item.secret.nonce,
            item.secret.ct,
            item.created_at,
            now_ms()
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (Store, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let s = Store::open(&dir.path().join("t.db")).unwrap();
        (s, dir)
    }

    #[test]
    fn records_and_reads_back() {
        let (s, _d) = store();
        let id = s.record(&Clip::Text("hello world".into())).unwrap().unwrap();
        assert_eq!(s.content(id).unwrap().as_deref(), Some("hello world"));
    }

    #[test]
    fn ignores_blank_copies() {
        let (s, _d) = store();
        assert!(s.record(&Clip::Text("   \n\t ".into())).unwrap().is_none());
        assert_eq!(s.list("", 10).unwrap().len(), 0);
    }

    #[test]
    fn recopying_moves_to_top_instead_of_duplicating() {
        let (s, _d) = store();
        let first = s.record(&Clip::Text("repeated".into())).unwrap().unwrap();
        s.record(&Clip::Text("other".into())).unwrap();
        let again = s.record(&Clip::Text("repeated".into())).unwrap().unwrap();

        assert_eq!(first, again, "same text should reuse the row");
        let rows = s.list("", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, first, "the re-copied entry comes back first");
        assert_eq!(rows[0].use_count, 1);
    }

    #[test]
    fn search_matches_inside_words() {
        let (s, _d) = store();
        s.record(&Clip::Text("https://example.com/p?token=AKIAIOSFODNN7EXAMPLE".into())).unwrap();
        s.record(&Clip::Text("nothing to see".into())).unwrap();

        // The substring is mid-token - a word tokenizer would miss this.
        assert_eq!(s.list("AKIA", 10).unwrap().len(), 1);
        assert_eq!(s.list("token=", 10).unwrap().len(), 1);
        assert_eq!(s.list("absent", 10).unwrap().len(), 0);
    }

    #[test]
    fn search_treats_wildcards_literally() {
        let (s, _d) = store();
        s.record(&Clip::Text("plain text".into())).unwrap();
        s.record(&Clip::Text("50% off".into())).unwrap();
        // '%' must not act as a LIKE wildcard matching everything.
        let hits = s.list("%", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].preview.contains("50%"));
    }

    #[test]
    fn pinned_entries_sort_first_and_survive_clear() {
        let (s, _d) = store();
        let old = s.record(&Clip::Text("pin me".into())).unwrap().unwrap();
        s.record(&Clip::Text("newer".into())).unwrap();
        s.set_pinned(old, true).unwrap();

        assert_eq!(s.list("", 10).unwrap()[0].id, old);

        s.clear(false).unwrap();
        let left = s.list("", 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, old);

        s.clear(true).unwrap();
        assert_eq!(s.list("", 10).unwrap().len(), 0);
    }

    #[test]
    fn trim_drops_oldest_unpinned_but_keeps_pins() {
        let (s, _d) = store();
        let pinned = s.record(&Clip::Text("keep forever".into())).unwrap().unwrap();
        s.set_pinned(pinned, true).unwrap();
        for i in 0..MAX_UNPINNED + 25 {
            s.record(&Clip::Text(format!("entry {i}"))).unwrap();
        }
        let all = s.list("", 2000).unwrap();
        assert_eq!(all.len(), MAX_UNPINNED + 1, "pin plus the capped unpinned set");
        assert!(all.iter().any(|e| e.id == pinned));
    }

    fn image_clip(w: u32, h: u32, shade: u8) -> Clip {
        use std::io::Cursor;
        let img =
            image::RgbaImage::from_fn(w, h, |x, _| image::Rgba([shade, (x % 256) as u8, 64, 255]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        Clip::Image(crate::media::prepare(&png).unwrap())
    }

    #[test]
    fn records_an_image_with_dimensions_and_thumbnail() {
        let (s, _d) = store();
        let id = s.record(&image_clip(120, 80, 5)).unwrap().unwrap();
        let row = s.list("", 10).unwrap().into_iter().find(|e| e.id == id).unwrap();

        assert_eq!(row.kind, "image");
        assert_eq!((row.width, row.height), (Some(120), Some(80)));
        assert!(row.preview.contains("120x80"));
        assert!(row.thumb.unwrap().starts_with(b"\x89PNG"));
        assert!(s.image_png(id).unwrap().is_some());
    }

    #[test]
    fn recopying_an_image_does_not_duplicate_it() {
        let (s, _d) = store();
        let first = s.record(&image_clip(60, 60, 9)).unwrap().unwrap();
        let again = s.record(&image_clip(60, 60, 9)).unwrap().unwrap();
        assert_eq!(first, again);
        assert_eq!(s.list("", 10).unwrap().len(), 1);
    }

    #[test]
    fn images_and_text_coexist() {
        let (s, _d) = store();
        s.record(&Clip::Text("some text".into())).unwrap();
        s.record(&image_clip(40, 40, 2)).unwrap();
        let rows = s.list("", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().filter(|e| e.kind == "image").count(), 1);
    }

    #[test]
    fn searching_for_image_finds_image_rows_only() {
        let (s, _d) = store();
        s.record(&Clip::Text("ordinary text".into())).unwrap();
        s.record(&image_clip(40, 40, 2)).unwrap();
        let hits = s.list("Image", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "image");
    }

    #[test]
    fn text_search_does_not_match_image_blobs() {
        let (s, _d) = store();
        s.record(&image_clip(40, 40, 2)).unwrap();
        // Images store an empty content string; a search must not match them
        // just because the LIKE pattern is permissive.
        assert_eq!(s.list("ordinary", 10).unwrap().len(), 0);
    }

    #[test]
    fn opens_a_database_written_before_images_existed() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("old.db");
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE entries (
                     id INTEGER PRIMARY KEY, content TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
                     preview TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0,
                     bytes INTEGER NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
                     created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
                     use_count INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO entries (content, hash, preview, bytes, created_at, last_used_at)
                 VALUES ('from the old schema', 'oldhash', 'from the old schema', 19, 1, 1);",
            )
            .unwrap();
        }

        let s = Store::open(&path).unwrap();
        let rows = s.list("", 10).unwrap();
        assert_eq!(rows.len(), 1, "the existing entry survives the migration");
        assert_eq!(rows[0].kind, "text", "rows written before images default to text");

        // And the upgraded table takes images.
        s.record(&image_clip(30, 30, 1)).unwrap();
        assert_eq!(s.list("", 10).unwrap().len(), 2);
    }

    fn user_version(s: &Store) -> i64 {
        s.conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_new_database_is_at_the_current_schema() {
        let (s, _d) = store();
        assert_eq!(user_version(&s), SCHEMA_VERSION);
        assert!(s.has_table("vault_items").unwrap() && s.has_table("vault_key").unwrap());
        assert!(!s.has_table("vault_meta").unwrap(), "no empty first-generation tables left");
    }

    #[test]
    fn a_tauri_database_is_upgraded_and_keeps_its_vault_tables() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("tauri.db");
        {
            // What a Tauri release left: full v1 schema, user_version never
            // set, and a vault that can only be converted with the password.
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE entries (
                     id INTEGER PRIMARY KEY, content TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
                     preview TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0,
                     bytes INTEGER NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
                     created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
                     use_count INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'text',
                     blob BLOB, thumb BLOB, width INTEGER, height INTEGER);
                 CREATE TABLE vault_meta (id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL,
                     verify_nonce BLOB NOT NULL, verify_ct BLOB NOT NULL);
                 CREATE TABLE vault_entries (id INTEGER PRIMARY KEY, label TEXT NOT NULL,
                     nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL);
                 INSERT INTO vault_meta VALUES (1, x'00', x'00', x'00');
                 INSERT INTO entries (content, hash, preview, bytes, created_at, last_used_at)
                 VALUES ('kept', 'h1', 'kept', 4, 1, 1);",
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(user_version(&s), SCHEMA_VERSION);
        let rows = s.list("", 10).unwrap();
        assert_eq!(rows[0].preview, "kept");
        assert_eq!(rows[0].sensitivity, Sensitivity::None);
        assert!(s.legacy_vault().unwrap().is_some(), "the vault waits for its password");
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("future.db");
        drop(Store::open(&path).unwrap());
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let err = Store::open(&path).err().expect("must refuse").to_string();
        assert!(err.contains("newer ClipVault"), "{err}");
    }

    fn disk_contains(dir: &tempdir::Dir, file: &str, needle: &str) -> bool {
        ["", "-wal"].iter().any(|suffix| {
            std::fs::read(dir.path().join(format!("{file}{suffix}")))
                .map(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes()))
                .unwrap_or(false)
        })
    }

    #[test]
    fn deleting_an_entry_removes_it_from_the_files() {
        let (s, d) = store();
        let small = "SMALL-MARKER-AKIAIOSFODNN7EXAMPLE";
        // Large enough to spill onto overflow pages, which are freed separately.
        let large = format!("LARGE-MARKER-{}", "q".repeat(20_000));
        let a = s.record(&Clip::Text(small.into())).unwrap().unwrap();
        let b = s.record(&Clip::Text(large)).unwrap().unwrap();
        s.record(&Clip::Text("unrelated".into())).unwrap();
        assert!(disk_contains(&d, "t.db", small), "precondition: it was written");

        s.delete(a).unwrap();
        s.delete(b).unwrap();
        assert!(!disk_contains(&d, "t.db", small));
        assert!(!disk_contains(&d, "t.db", "LARGE-MARKER-"));
    }

    #[test]
    fn the_upgrade_scan_flags_old_credentials_for_review() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("old.db");
        let key = ["ghp_", &"a1B2".repeat(9)].concat();
        {
            let s = Store::open(&path).unwrap();
            s.record(&Clip::Text(key.clone())).unwrap();
            s.record(&Clip::Text("harmless".into())).unwrap();
            // Pretend this database predates detection.
            s.conn.execute("UPDATE entries SET sensitive = 0", []).unwrap();
            s.conn.pragma_update(None, "user_version", 2).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.flagged_count().unwrap(), 1);
        let rows = s.list("", 10).unwrap();
        let flagged = rows.iter().find(|e| e.sensitivity == Sensitivity::Flagged).unwrap();
        assert_eq!(flagged.preview, key);

        assert_eq!(s.delete_flagged().unwrap(), 1);
        assert_eq!(s.list("", 10).unwrap().len(), 1);
        assert!(!disk_contains(&dir, "old.db", &key));
    }

    #[test]
    fn keeping_a_credential_pins_and_marks_it() {
        let (s, _d) = store();
        let id = s.keep_sensitive("deliberately kept").unwrap();
        let row = s.list("", 10).unwrap().into_iter().find(|e| e.id == id).unwrap();
        assert!(row.pinned);
        assert_eq!(row.sensitivity, Sensitivity::Kept);
        assert_eq!(s.flagged_count().unwrap(), 0, "kept is not awaiting review");
    }

    #[test]
    fn clearing_history_removes_it_from_the_files() {
        let (s, d) = store();
        s.record(&Clip::Text("CLEAR-MARKER-one".into())).unwrap();
        s.clear(false).unwrap();
        assert!(!disk_contains(&d, "t.db", "CLEAR-MARKER-one"));
    }

    #[test]
    fn clearing_keeps_pinned_entries_unless_asked() {
        let (s, _d) = store();
        let keep = s.record(&Clip::Text("pinned one".into())).unwrap().unwrap();
        s.record(&Clip::Text("loose one".into())).unwrap();
        s.record(&Clip::Text("loose two".into())).unwrap();
        s.set_pinned(keep, true).unwrap();
        assert_eq!(s.history_counts().unwrap(), (2, 1));

        assert_eq!(s.clear(false).unwrap(), 2);
        assert_eq!(s.history_counts().unwrap(), (0, 1));
        assert_eq!(s.list("", 10).unwrap()[0].id, keep);

        assert_eq!(s.clear(true).unwrap(), 1);
        assert_eq!(s.history_counts().unwrap(), (0, 0));
    }

    #[test]
    fn clearing_history_leaves_the_vault_alone() {
        let (s, _d) = store();
        s.record(&Clip::Text("history".into())).unwrap();
        let mut vault = crate::vault::Vault::default();
        vault.init(&s, "a password").unwrap();
        vault.add(&s, "label", "vault secret").unwrap();

        s.clear(true).unwrap();
        assert_eq!(crate::vault::Vault::count(&s).unwrap(), 1);
        assert_eq!(&*vault.reveal(&s, vault.items(&s).unwrap()[0].id).unwrap(), "vault secret");
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("twice.db");
        Store::open(&path).unwrap().record(&Clip::Text("hi".into())).unwrap();
        let s = Store::open(&path).unwrap();
        assert_eq!(s.list("", 10).unwrap().len(), 1);
    }

    /// Records an entry whose `bytes` is predictable, for budget tests.
    fn sized(s: &Store, label: &str, bytes: usize) -> i64 {
        let text = format!("{label}{}", "x".repeat(bytes.saturating_sub(label.len())));
        s.record(&Clip::Text(text)).unwrap().unwrap()
    }

    #[test]
    fn byte_budget_drops_oldest_unpinned() {
        let (s, _d) = store();
        let oldest = sized(&s, "a", 400);
        let middle = sized(&s, "b", 400);
        let newest = sized(&s, "c", 400);

        // Budget counts the bytes ahead of each entry: the newest sees 0, the
        // middle 400, the oldest 800. A 700 budget therefore keeps two.
        s.trim_to(1000, 700).unwrap();

        let left: Vec<i64> = s.list("", 10).unwrap().into_iter().map(|e| e.id).collect();
        assert!(left.contains(&newest));
        assert!(left.contains(&middle));
        assert!(!left.contains(&oldest), "the oldest should go first");
    }

    #[test]
    fn newest_entry_survives_even_if_it_alone_exceeds_the_budget() {
        let (s, _d) = store();
        let big = sized(&s, "big", 5000);
        s.trim_to(1000, 100).unwrap();
        let left = s.list("", 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, big, "copying something must not immediately lose it");
    }

    #[test]
    fn pins_are_exempt_from_the_byte_budget() {
        let (s, _d) = store();
        let pinned = sized(&s, "keep", 5000);
        s.set_pinned(pinned, true).unwrap();
        for i in 0..5 {
            sized(&s, &format!("junk{i}"), 2000);
        }
        s.trim_to(1000, 1000).unwrap();

        let left = s.list("", 20).unwrap();
        assert!(left.iter().any(|e| e.id == pinned), "a pin outlives the budget");
    }

    #[test]
    fn budget_and_count_limits_both_apply() {
        let (s, _d) = store();
        for i in 0..20 {
            sized(&s, &format!("e{i}"), 100);
        }
        // Count allows 5, budget allows about 3.
        s.trim_to(5, 300).unwrap();
        assert!(s.list("", 50).unwrap().len() <= 3);
    }

    #[test]
    fn database_files_are_private_even_if_they_were_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir::Dir::new();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o775)).unwrap();
        let path = data.join("p.db");
        // A database left behind by the Tauri build, created under umask 022.
        Store::open(&path).unwrap().record(&Clip::Text("seed".into())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let s = Store::open(&path).unwrap();
        s.record(&Clip::Text("after reopen".into())).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&data.join("p.db-wal")), 0o600);
        assert_eq!(mode(&data.join("p.db-shm")), 0o600);
    }

    #[test]
    fn configured_limits_replace_the_defaults() {
        let (mut s, _d) = store();
        s.set_limits(3, i64::MAX);
        for i in 0..10 {
            s.record(&Clip::Text(format!("entry {i}"))).unwrap();
        }
        assert_eq!(s.list("", 50).unwrap().len(), 3);
    }

    #[test]
    fn preview_is_truncated_and_flagged() {
        let (s, _d) = store();
        let long = "x".repeat(PREVIEW_CHARS + 50);
        let id = s.record(&Clip::Text(long.clone())).unwrap().unwrap();
        let row = s.list("", 10).unwrap().into_iter().find(|e| e.id == id).unwrap();
        assert!(row.truncated);
        assert_eq!(row.preview.chars().count(), PREVIEW_CHARS);
        // The full text is still retrievable even though the preview is cut.
        assert_eq!(s.content(id).unwrap().unwrap().len(), long.len());
    }

    // ---- sync change tracking -------------------------------------------

    fn dirty(s: &Store, id: i64) -> (bool, i64) {
        s.conn
            .query_row("SELECT dirty, updated_at FROM entries WHERE id = ?1", params![id], |r| {
                Ok((r.get::<_, i64>(0)? != 0, r.get(1)?))
            })
            .unwrap()
    }

    fn tombstones(s: &Store) -> Vec<(String, String)> {
        s.conn
            .prepare("SELECT kind, id FROM tombstones ORDER BY kind, id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn give_fp(s: &Store, id: i64, fp: &str) {
        s.conn
            .execute("UPDATE entries SET fp = ?1, dirty = 0 WHERE id = ?2", params![fp, id])
            .unwrap();
    }

    #[test]
    fn local_changes_mark_rows_for_upload() {
        let (s, _d) = store();
        let id = s.record(&Clip::Text("hello".into())).unwrap().unwrap();
        let (is_dirty, first) = dirty(&s, id);
        assert!(is_dirty && first > 0);

        give_fp(&s, id, "fp-hello");
        std::thread::sleep(std::time::Duration::from_millis(2));
        s.record(&Clip::Text("hello".into())).unwrap();
        let (is_dirty, second) = dirty(&s, id);
        assert!(is_dirty && second > first, "a re-copy is a change");

        give_fp(&s, id, "fp-hello");
        s.set_pinned(id, true).unwrap();
        assert!(dirty(&s, id).0, "pinning is a change");
        give_fp(&s, id, "fp-hello");
        s.mark_used(id).unwrap();
        assert!(dirty(&s, id).0, "using it is a change");
    }

    #[test]
    fn deleting_a_synced_entry_leaves_a_tombstone_and_an_unsynced_one_does_not() {
        let (s, _d) = store();
        let synced = s.record(&Clip::Text("synced".into())).unwrap().unwrap();
        let local = s.record(&Clip::Text("local only".into())).unwrap().unwrap();
        give_fp(&s, synced, "fp-synced");
        s.delete(synced).unwrap();
        s.delete(local).unwrap();
        assert_eq!(tombstones(&s), [("clip".into(), "fp-synced".into())]);
    }

    #[test]
    fn clearing_and_trimming_leave_tombstones() {
        let (mut s, _d) = store();
        s.set_limits(2, i64::MAX);
        let ids: Vec<i64> = (0..3)
            .map(|i| {
                let id = s.record(&Clip::Text(format!("entry {i}"))).unwrap().unwrap();
                give_fp(&s, id, &format!("fp-{i}"));
                // Distinct last_used_at seconds keep the eviction order certain.
                s.conn
                    .execute("UPDATE entries SET last_used_at = ?1 WHERE id = ?2", params![i, id])
                    .unwrap();
                id
            })
            .collect();
        s.record(&Clip::Text("newest".into())).unwrap();
        assert!(tombstones(&s).contains(&("clip".into(), "fp-0".into())), "trimmed");
        assert!(s.content(ids[0]).unwrap().is_none());

        s.clear(true).unwrap();
        let t = tombstones(&s);
        assert!(
            t.contains(&("clip".into(), "fp-1".into()))
                && t.contains(&("clip".into(), "fp-2".into()))
        );
    }

    #[test]
    fn vault_changes_are_tracked() {
        let (s, _d) = store();
        let mut v = crate::vault::Vault::default();
        v.init(&s, "a long password").unwrap();
        let id = v.add(&s, "label", "secret").unwrap();
        let (is_dirty, uid): (bool, Vec<u8>) = s
            .conn
            .query_row("SELECT dirty, uid FROM vault_items WHERE id = ?1", params![id], |r| {
                Ok((r.get::<_, i64>(0)? != 0, r.get(1)?))
            })
            .unwrap();
        assert!(is_dirty);
        v.delete(&s, id).unwrap();
        assert_eq!(tombstones(&s), [("vault".into(), crate::crypto::hex(&uid))]);
    }

    #[test]
    fn the_account_mirror_round_trips_and_guards_the_key_row() {
        let (s, _d) = store();
        assert!(s.account().unwrap().is_none());
        let dek = crate::crypto::random::<32>();
        let (keys, _) = AccountKeys::create("a long password", &dek).unwrap();
        s.set_account(&keys, 123, true).unwrap();
        assert_eq!(s.account().unwrap().unwrap(), keys);
        assert_eq!(s.vault_key().unwrap().unwrap(), keys.vault_key_row());
        assert!(s.set_vault_key(&keys.vault_key_row()).is_err(), "would split the account");

        // A password change through the vault reseals the history key too.
        let mut v = crate::vault::Vault::default();
        v.unlock(&s, "a long password").unwrap();
        v.change_password(&s, "a long password", "another long password").unwrap();
        let changed = s.account().unwrap().unwrap();
        assert!(changed.unlock_history("another long password").is_ok());
        assert!(changed.unlock_history("a long password").is_err());
        v.lock();
        v.unlock(&s, "another long password").unwrap();
    }

    #[test]
    fn the_device_id_is_made_once() {
        let (s, _d) = store();
        let id = s.device_id().unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(s.device_id().unwrap(), id);
    }

    #[test]
    fn upgrading_to_v4_marks_existing_history_for_upload() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("v3.db");
        {
            let s = Store::open(&path).unwrap();
            s.record(&Clip::Text("from before sync".into())).unwrap();
            s.conn
                .execute_batch(
                    "UPDATE entries SET dirty = 0, updated_at = 0, last_used_at = 1700000000;
                     PRAGMA user_version = 3;",
                )
                .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let updated: i64 =
            s.conn.query_row("SELECT updated_at FROM entries", [], |r| r.get(0)).unwrap();
        assert_eq!(updated, 1_700_000_000_000, "seconds become milliseconds");
        let v: i64 = s.conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, 4);
    }
}

/// Minimal self-cleaning temp directory for the tests.
#[cfg(test)]
pub mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "clipvault-test-{}-{:?}-{}",
                std::process::id(),
                std::thread::current().id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
