use crate::harden;
use crate::media::{human_size, ImageClip};
use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
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
const SCHEMA_VERSION: i64 = 3;

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
    fn from_db(v: i64) -> Self {
        match v {
            1 => Sensitivity::Flagged,
            2 => Sensitivity::Kept,
            _ => Sensitivity::None,
        }
    }

    fn to_db(self) -> i64 {
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
                "UPDATE entries SET last_used_at = ?1, use_count = use_count + 1 WHERE id = ?2",
                params![ts, id],
            )?;
            return Ok(Some(id));
        }

        match clip {
            Clip::Text(text) => {
                let (preview, truncated) = preview_of(text);
                self.conn.execute(
                    "INSERT INTO entries
                       (kind, content, hash, preview, truncated, bytes, created_at, last_used_at)
                     VALUES ('text', ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![text, hash, preview, truncated as i64, text.len() as i64, ts],
                )?;
            }
            Clip::Image(img) => {
                let preview =
                    format!("Image {}x{} - {}", img.width, img.height, human_size(img.png.len()));
                self.conn.execute(
                    "INSERT INTO entries
                       (kind, content, hash, preview, truncated, bytes, created_at, last_used_at,
                        blob, thumb, width, height)
                     VALUES ('image', '', ?1, ?2, 0, ?3, ?4, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        hash,
                        preview,
                        img.png.len() as i64,
                        ts,
                        img.png,
                        img.thumb_png,
                        img.width as i64,
                        img.height as i64
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
        self.conn.execute(
            "DELETE FROM entries WHERE pinned = 0 AND id NOT IN (
                 SELECT id FROM entries WHERE pinned = 0
                 ORDER BY last_used_at DESC LIMIT ?1
             )",
            params![max_unpinned as i64],
        )?;

        // Walk newest to oldest and drop everything past the budget. The sum
        // excludes the row itself, so the most recent entry always survives even
        // if it alone is larger than the budget - having just copied something
        // and finding it already gone would be worse than briefly overshooting.
        self.conn.execute(
            "DELETE FROM entries WHERE id IN (
                 SELECT id FROM (
                     SELECT id, SUM(bytes) OVER (
                         ORDER BY last_used_at DESC, id DESC
                         ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                     ) AS preceding_bytes
                     FROM entries WHERE pinned = 0
                 ) WHERE preceding_bytes >= ?1
             )",
            params![max_bytes],
        )?;
        Ok(())
    }

    pub fn list(&self, query: &str, limit: i64) -> Result<Vec<Entry>> {
        let q = query.trim();
        // Substring match, not full-text: clipboard searches are things like
        // "AKIA" inside a key or a fragment of a URL, which a word tokenizer
        // would never match.
        let (sql, like) = if q.is_empty() {
            (
                "SELECT id, kind, preview, truncated, bytes, pinned, created_at, last_used_at,
                        use_count, width, height, thumb, sensitive
                 FROM entries
                 ORDER BY pinned DESC, last_used_at DESC LIMIT ?1"
                    .to_string(),
                None,
            )
        } else {
            (
                "SELECT id, kind, preview, truncated, bytes, pinned, created_at, last_used_at,
                        use_count, width, height, thumb, sensitive
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
            "UPDATE entries SET last_used_at = ?1, use_count = use_count + 1 WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }

    pub fn set_pinned(&self, id: i64, pinned: bool) -> Result<()> {
        self.conn
            .execute("UPDATE entries SET pinned = ?1 WHERE id = ?2", params![pinned as i64, id])?;
        Ok(())
    }

    pub fn set_sensitivity(&self, id: i64, s: Sensitivity) -> Result<()> {
        self.conn
            .execute("UPDATE entries SET sensitive = ?1 WHERE id = ?2", params![s.to_db(), id])?;
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
        let n = self.conn.execute("DELETE FROM entries WHERE sensitive = 1", [])?;
        self.scrub()?;
        Ok(n)
    }

    pub fn delete(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        self.scrub()
    }

    /// Clears history. Pinned entries survive unless `include_pinned`.
    pub fn clear(&self, include_pinned: bool) -> Result<()> {
        if include_pinned {
            self.conn.execute("DELETE FROM entries", [])?;
        } else {
            self.conn.execute("DELETE FROM entries WHERE pinned = 0", [])?;
        }
        self.scrub()
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
        let gone = tx.execute("DELETE FROM entries WHERE id = ?1", params![entry_id])?;
        if gone != 1 {
            bail!("entry no longer exists");
        }
        tx.commit()?;
        self.scrub()?;
        Ok(new_id)
    }

    pub fn vault_delete(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM vault_items WHERE id = ?1", params![id])?;
        self.scrub()
    }
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
           (uid, label_nonce, label_ct, secret_nonce, secret_ct, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            item.uid,
            item.label.nonce,
            item.label.ct,
            item.secret.nonce,
            item.secret.ct,
            item.created_at
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
}

/// Minimal self-cleaning temp directory for the tests.
#[cfg(test)]
pub mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "clipvault-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
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
