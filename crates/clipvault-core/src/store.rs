use crate::media::{human_size, ImageClip};
use anyhow::Result;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Unpinned entries beyond this count are dropped, oldest first. Pins never expire.
const MAX_UNPINNED: usize = 500;
/// Unpinned entries are also held to a byte budget, because a few dozen
/// screenshots outweigh thousands of text clips and the count alone will not
/// notice. Pins are exempt from both limits: keeping them is a deliberate act.
const MAX_UNPINNED_BYTES: i64 = 256 * 1024 * 1024;
const PREVIEW_CHARS: usize = 220;

#[derive(Serialize)]
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
    /// Data URL for the list thumbnail; images only.
    pub thumb: Option<String>,
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

#[derive(Serialize)]
pub struct VaultItem {
    pub id: i64,
    pub label: String,
    pub created_at: i64,
}

pub struct Store {
    conn: Connection,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let store = Store { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
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
                self.conn
                    .execute(&format!("ALTER TABLE entries ADD COLUMN {name} {decl}"), [])?;
            }
        }
        Ok(())
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
                let preview = format!(
                    "Image {}x{} - {}",
                    img.width,
                    img.height,
                    human_size(img.png.len())
                );
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
        self.trim_to(MAX_UNPINNED, MAX_UNPINNED_BYTES)
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
                        use_count, width, height, thumb
                 FROM entries
                 ORDER BY pinned DESC, last_used_at DESC LIMIT ?1"
                    .to_string(),
                None,
            )
        } else {
            (
                "SELECT id, kind, preview, truncated, bytes, pinned, created_at, last_used_at,
                        use_count, width, height, thumb
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
            let thumb: Option<Vec<u8>> = r.get(11)?;
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
                thumb: thumb.map(|b| {
                    format!(
                        "data:image/png;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(b)
                    )
                }),
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
        self.conn.execute(
            "UPDATE entries SET pinned = ?1 WHERE id = ?2",
            params![pinned as i64, id],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Clears history. Pinned entries survive unless `include_pinned`.
    pub fn clear(&self, include_pinned: bool) -> Result<()> {
        if include_pinned {
            self.conn.execute("DELETE FROM entries", [])?;
        } else {
            self.conn.execute("DELETE FROM entries WHERE pinned = 0", [])?;
        }
        Ok(())
    }

    // ---- vault ---------------------------------------------------------

    pub fn vault_meta(&self) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT salt, verify_nonce, verify_ct FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    pub fn set_vault_meta(&self, salt: &[u8], nonce: &[u8], ct: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta (id, salt, verify_nonce, verify_ct)
             VALUES (1, ?1, ?2, ?3)",
            params![salt, nonce, ct],
        )?;
        Ok(())
    }

    pub fn vault_list(&self) -> Result<Vec<VaultItem>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label, created_at FROM vault_entries ORDER BY label COLLATE NOCASE")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(VaultItem { id: r.get(0)?, label: r.get(1)?, created_at: r.get(2)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn vault_insert(&self, label: &str, nonce: &[u8], ct: &[u8]) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO vault_entries (label, nonce, ciphertext, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![label, nonce, ct, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn vault_get(&self, id: i64) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM vault_entries WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn vault_delete(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM vault_entries WHERE id = ?1", params![id])?;
        Ok(())
    }
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
        let img = image::RgbaImage::from_fn(w, h, |x, _| {
            image::Rgba([shade, (x % 256) as u8, 64, 255])
        });
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
        assert!(row.thumb.unwrap().starts_with("data:image/png;base64,"));
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
