//! The MongoDB side: document format, push and pull. `docs/sync.md` is the
//! same format written down for other clients.
//!
//! Collections in the account's database:
//! - `keys`: one document, `_id: "account"`, the sealed account keys;
//! - `clips`: one per distinct content, `_id` = fingerprint;
//! - `vault`: one per vault item, `_id` = hex uid;
//! - GridFS bucket `images`: encrypted PNGs named by fingerprint.
//!
//! Every write sets `synced_at` from the server clock, and pulls page by it,
//! so a device with a slow clock cannot slip changes past another's cursor.
//! Conflicts are settled by `updated_at`, the writer's own clock: the newer
//! change wins and an older write is refused.

use anyhow::{anyhow, Context, Result};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Bson, DateTime, Document};
use mongodb::error::{ErrorKind, WriteFailure};
use mongodb::gridfs::GridFsBucket;
use mongodb::options::GridFsBucketOptions;
use mongodb::{Collection, Database};
use zeroize::Zeroizing;

use crate::account::{AccountKeys, HistoryKeys};
use crate::media;
use crate::store::{
    now, ClipState, LocalClip, LocalVaultItem, Sealed, Sensitivity, Store, Tombstone,
};

pub(super) const CLIPS: &str = "clips";
pub(super) const VAULT: &str = "vault";
pub(super) const KEYS: &str = "keys";
const ACCOUNT_ID: &str = "account";
const BATCH: i64 = 50;
/// A clip another device copied this recently goes onto this clipboard.
const ADOPT_WITHIN_SECS: i64 = 120;
/// Deleted clips and vault items are kept this long as tombstones, so a device
/// that was offline still learns of the deletion.
const TOMBSTONE_DAYS: i64 = 30;

pub(super) struct Remote {
    pub db: Database,
    clips: Collection<Document>,
    vault: Collection<Document>,
    keys: Collection<Document>,
    images: GridFsBucket,
}

/// Something pulled that this device should act on beyond its database.
pub(super) enum Pulled {
    /// Another device just copied this.
    Text {
        text: Zeroizing<String>,
        from: Option<String>,
    },
    Image {
        png: Vec<u8>,
        from: Option<String>,
    },
}

impl Remote {
    pub fn new(db: Database) -> Self {
        Remote {
            clips: db.collection(CLIPS),
            vault: db.collection(VAULT),
            keys: db.collection(KEYS),
            images: db.gridfs_bucket(
                GridFsBucketOptions::builder().bucket_name("images".to_string()).build(),
            ),
            db,
        }
    }

    pub async fn ensure_indexes(&self) -> Result<()> {
        for coll in [&self.clips, &self.vault] {
            coll.create_index(mongodb::IndexModel::builder().keys(doc! { "synced_at": 1 }).build())
                .await?;
        }
        Ok(())
    }

    // ---- account -------------------------------------------------------

    pub async fn account(&self) -> Result<Option<(AccountKeys, i64)>> {
        let Some(d) = self.keys.find_one(doc! { "_id": ACCOUNT_ID }).await? else {
            return Ok(None);
        };
        Ok(Some((account_from(&d)?, d.get_i64("updated_at")?)))
    }

    /// Creates the account. False if another device created one first.
    pub async fn create_account(&self, keys: &AccountKeys, updated_at: i64) -> Result<bool> {
        let mut d = account_doc(keys, updated_at);
        d.insert("_id", ACCOUNT_ID);
        d.insert("synced_at", DateTime::now());
        match self.keys.insert_one(d).await {
            Ok(_) => Ok(true),
            Err(e) if is_duplicate_key(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn push_account(&self, keys: &AccountKeys, updated_at: i64) -> Result<()> {
        let r = self
            .keys
            .update_one(
                doc! { "_id": ACCOUNT_ID, "updated_at": { "$lt": updated_at } },
                doc! { "$set": account_doc(keys, updated_at), "$currentDate": { "synced_at": true } },
            )
            .upsert(true)
            .await;
        ignore_newer(r)
    }

    // ---- push ----------------------------------------------------------

    pub async fn push(&self, store: &Store, keys: &HistoryKeys, device: &str) -> Result<usize> {
        let mut sent = 0;
        if let Some((account, updated_at, true)) = store.account_change()? {
            self.push_account(&account, updated_at).await?;
            store.mark_account_clean(updated_at)?;
            sent += 1;
        }
        // Rows changed while a batch is out stay dirty; a few rounds catch
        // them without spinning forever on a busy clipboard.
        for _ in 0..20 {
            let batch = store.dirty_clips(BATCH)?;
            if batch.is_empty() {
                break;
            }
            for clip in &batch {
                let fp = match &clip.fp {
                    Some(fp) => fp.clone(),
                    None => {
                        let fp = keys.fingerprint(&clip.kind, clip.hash.as_bytes());
                        store.set_fp(clip.id, &fp)?;
                        fp
                    }
                };
                self.push_clip(clip, &fp, keys, device)
                    .await
                    .with_context(|| format!("uploading clip {}", clip.id))?;
                store.mark_clip_clean(clip.id, clip.updated_at)?;
                sent += 1;
            }
        }
        for item in store.dirty_vault_items()? {
            self.push_vault_item(&item, device).await?;
            store.mark_vault_item_clean(&item.uid, item.updated_at)?;
            sent += 1;
        }
        for t in store.tombstones()? {
            self.push_tombstone(&t, device).await?;
            store.drop_tombstone(&t)?;
            sent += 1;
        }
        Ok(sent)
    }

    async fn push_clip(
        &self,
        clip: &LocalClip,
        fp: &str,
        keys: &HistoryKeys,
        device: &str,
    ) -> Result<()> {
        let sens = keys.seal_field(fp, "sens", &[clip.sensitivity.to_db() as u8])?;
        let state = doc! {
            "pinned": clip.pinned,
            "last_used_at": clip.last_used_at,
            "use_count": clip.use_count,
            "updated_at": clip.updated_at,
            "origin": device,
            "sens": sealed_doc(&sens),
        };
        // Usually the content is already there and only the state moved.
        let r = self
            .clips
            .update_one(
                doc! { "_id": fp, "deleted": false, "updated_at": { "$lt": clip.updated_at } },
                doc! { "$set": state.clone(), "$currentDate": { "synced_at": true } },
            )
            .await?;
        if r.matched_count == 1 {
            return Ok(());
        }

        // New here, or revived after a delete: send the content too.
        let mut full = state;
        full.insert("created_at", clip.created_at);
        full.insert("deleted", false);
        let meta = serde_json::json!({ "kind": clip.kind, "from": device_name() });
        full.insert("meta", sealed_doc(&keys.seal_field(fp, "meta", meta.to_string().as_bytes())?));
        match clip.kind.as_str() {
            "image" => {
                let png = clip.blob.as_deref().ok_or_else(|| anyhow!("image without pixels"))?;
                self.upload_image(fp, png, keys).await?;
                let thumb = clip.thumb.as_deref().unwrap_or_default();
                full.insert("thumb", sealed_doc(&keys.seal_field(fp, "thumb", thumb)?));
            }
            _ => {
                full.insert(
                    "text",
                    sealed_doc(&keys.seal_field(fp, "text", clip.content.as_bytes())?),
                );
            }
        }
        let r = self
            .clips
            .update_one(
                doc! { "_id": fp, "updated_at": { "$lt": clip.updated_at } },
                doc! { "$set": full, "$currentDate": { "synced_at": true } },
            )
            .upsert(true)
            .await;
        ignore_newer(r)
    }

    async fn upload_image(&self, fp: &str, png: &[u8], keys: &HistoryKeys) -> Result<()> {
        if self.images.find(doc! { "filename": fp }).limit(1).await?.try_next().await?.is_some() {
            return Ok(());
        }
        let sealed = keys.seal_image(fp, png)?;
        let mut up =
            self.images.open_upload_stream(fp).metadata(doc! { "n": bin(&sealed.nonce) }).await?;
        up.write_all(&sealed.ct).await?;
        up.close().await?;
        Ok(())
    }

    async fn download_image(&self, fp: &str, keys: &HistoryKeys) -> Result<Zeroizing<Vec<u8>>> {
        let file = self
            .images
            .find(doc! { "filename": fp })
            .sort(doc! { "uploadDate": -1 })
            .limit(1)
            .await?
            .try_next()
            .await?
            .ok_or_else(|| anyhow!("image {fp} is missing"))?;
        let nonce = file
            .metadata
            .as_ref()
            .and_then(|m| m.get_binary_generic("n").ok())
            .ok_or_else(|| anyhow!("image {fp} has no nonce"))?
            .clone();
        let mut ct = Vec::new();
        self.images.open_download_stream(file.id).await?.read_to_end(&mut ct).await?;
        keys.open_image(fp, &Sealed { nonce, ct })
    }

    async fn delete_images(&self, fp: &str) -> Result<()> {
        let mut files = self.images.find(doc! { "filename": fp }).await?;
        while let Some(f) = files.try_next().await? {
            self.images.delete(f.id).await?;
        }
        Ok(())
    }

    async fn push_vault_item(&self, item: &LocalVaultItem, device: &str) -> Result<()> {
        let r = self
            .vault
            .update_one(
                doc! { "_id": crate::crypto::hex(&item.uid), "updated_at": { "$lt": item.updated_at } },
                doc! {
                    "$set": {
                        "label": sealed_doc(&item.label),
                        "secret": sealed_doc(&item.secret),
                        "created_at": item.created_at,
                        "updated_at": item.updated_at,
                        "deleted": false,
                        "origin": device,
                    },
                    "$currentDate": { "synced_at": true },
                },
            )
            .upsert(true)
            .await;
        ignore_newer(r)
    }

    async fn push_tombstone(&self, t: &Tombstone, device: &str) -> Result<()> {
        let (coll, unset) = match t.kind.as_str() {
            "clip" => (&self.clips, doc! { "meta": "", "text": "", "thumb": "", "sens": "" }),
            "vault" => (&self.vault, doc! { "label": "", "secret": "" }),
            other => return Err(anyhow!("unknown tombstone kind {other}")),
        };
        coll.update_one(
            doc! { "_id": &t.id, "updated_at": { "$lt": t.updated_at } },
            doc! {
                "$set": { "deleted": true, "updated_at": t.updated_at, "origin": device },
                "$unset": unset,
                "$currentDate": { "synced_at": true },
            },
        )
        .await?;
        if t.kind == "clip" {
            self.delete_images(&t.id).await?;
        }
        Ok(())
    }

    /// Drops tombstones old enough that every device has seen them.
    pub async fn purge_tombstones(&self) -> Result<()> {
        let cutoff = crate::store::now_ms() - TOMBSTONE_DAYS * 24 * 3600 * 1000;
        for coll in [&self.clips, &self.vault] {
            coll.delete_many(doc! { "deleted": true, "updated_at": { "$lt": cutoff } }).await?;
        }
        Ok(())
    }

    // ---- pull ----------------------------------------------------------

    /// Applies everything changed since the last pull. Returns whether the
    /// local database changed, and what this device should put on its
    /// clipboard.
    pub async fn pull(
        &self,
        store: &Store,
        keys: &HistoryKeys,
        device: &str,
        adopt: bool,
    ) -> Result<(bool, Vec<Pulled>)> {
        let mut changed = false;
        let mut adopted = Vec::new();

        let since = cursor(store, CLIPS)?;
        let mut docs = self
            .clips
            .find(doc! { "synced_at": { "$gte": since } })
            .sort(doc! { "synced_at": 1 })
            .await?;
        let mut last = since;
        let mut inserted = false;
        while let Some(d) = docs.try_next().await? {
            last = d.get_datetime("synced_at").copied().unwrap_or(last);
            match self.apply_clip(store, keys, &d, device, adopt).await {
                Ok(Applied::Nothing) => {}
                Ok(Applied::Changed) => changed = true,
                Ok(Applied::Inserted(p)) => {
                    changed = true;
                    inserted = true;
                    adopted.extend(p);
                }
                // One bad document must not stop the rest from syncing.
                Err(e) => log::warn!("skipping a synced clip: {e:#}"),
            }
        }
        set_cursor(store, CLIPS, last)?;
        if inserted {
            store.enforce_limits()?;
        }

        let since = cursor(store, VAULT)?;
        let mut docs = self
            .vault
            .find(doc! { "synced_at": { "$gte": since } })
            .sort(doc! { "synced_at": 1 })
            .await?;
        let mut last = since;
        while let Some(d) = docs.try_next().await? {
            last = d.get_datetime("synced_at").copied().unwrap_or(last);
            match apply_vault_item(store, &d) {
                Ok(c) => changed |= c,
                Err(e) => log::warn!("skipping a synced vault item: {e:#}"),
            }
        }
        set_cursor(store, VAULT, last)?;
        Ok((changed, adopted))
    }

    async fn apply_clip(
        &self,
        store: &Store,
        keys: &HistoryKeys,
        d: &Document,
        device: &str,
        adopt: bool,
    ) -> Result<Applied> {
        let fp = d.get_str("_id")?;
        let updated_at = d.get_i64("updated_at")?;
        let deleted = d.get_bool("deleted").unwrap_or(false);

        if let Some((id, local)) = store.clip_by_fp(fp)? {
            if updated_at <= local {
                return Ok(Applied::Nothing);
            }
            if deleted {
                store.delete_remote_clip(id)?;
            } else {
                store.apply_clip_state(id, &state_of(d, fp, keys)?)?;
            }
            return Ok(Applied::Changed);
        }
        if deleted {
            return Ok(Applied::Nothing);
        }

        let meta: serde_json::Value =
            serde_json::from_slice(&keys.open_field(fp, "meta", &sealed_of(d, "meta")?)?)?;
        let kind = meta["kind"].as_str().unwrap_or("text").to_string();
        let from = meta["from"].as_str().map(str::to_string);
        let state = state_of(d, fp, keys)?;
        let created_at = d.get_i64("created_at").unwrap_or(state.last_used_at);

        let (clip, pulled) = if kind == "image" {
            let png = self.download_image(fp, keys).await?;
            let img = media::prepare(&png)?;
            let pulled = Pulled::Image { png: img.png.clone(), from: from.clone() };
            (crate::store::Clip::Image(img), pulled)
        } else {
            let text =
                crate::crypto::into_string(keys.open_field(fp, "text", &sealed_of(d, "text")?)?)?;
            let pulled = Pulled::Text { text: text.clone(), from: from.clone() };
            (crate::store::Clip::Text(text.to_string()), pulled)
        };

        // The same thing copied here before it had a fingerprint: link them.
        if let Some((id, None, local)) = store.clip_by_hash(&clip.hash())? {
            store.set_fp(id, fp)?;
            if updated_at > local {
                store.apply_clip_state(id, &state)?;
            }
            return Ok(Applied::Changed);
        }

        store.insert_remote_clip(fp, &clip, &state, created_at, from.as_deref())?;
        let theirs = d.get_str("origin").map(|o| o != device).unwrap_or(true);
        let fresh = now() - created_at <= ADOPT_WITHIN_SECS;
        Ok(Applied::Inserted((adopt && theirs && fresh).then_some(pulled)))
    }
}

enum Applied {
    Nothing,
    Changed,
    Inserted(Option<Pulled>),
}

fn apply_vault_item(store: &Store, d: &Document) -> Result<bool> {
    let uid = unhex(d.get_str("_id")?)?;
    let updated_at = d.get_i64("updated_at")?;
    if let Some(local) = store.vault_item_updated_at(&uid)? {
        if updated_at <= local {
            return Ok(false);
        }
    }
    if d.get_bool("deleted").unwrap_or(false) {
        store.delete_remote_vault_item(&uid)?;
    } else {
        store.upsert_remote_vault_item(&LocalVaultItem {
            uid,
            label: sealed_of(d, "label")?,
            secret: sealed_of(d, "secret")?,
            created_at: d.get_i64("created_at")?,
            updated_at,
        })?;
    }
    Ok(true)
}

fn state_of(d: &Document, fp: &str, keys: &HistoryKeys) -> Result<ClipState> {
    let sens = keys.open_field(fp, "sens", &sealed_of(d, "sens")?)?;
    Ok(ClipState {
        pinned: d.get_bool("pinned").unwrap_or(false),
        last_used_at: d.get_i64("last_used_at")?,
        use_count: d.get_i64("use_count").unwrap_or(0),
        sensitivity: Sensitivity::from_db(sens.first().copied().unwrap_or(0) as i64),
        updated_at: d.get_i64("updated_at")?,
    })
}

// ---- encoding --------------------------------------------------------

fn bin(bytes: &[u8]) -> Bson {
    Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: bytes.to_vec() })
}

fn sealed_doc(s: &Sealed) -> Document {
    doc! { "n": bin(&s.nonce), "c": bin(&s.ct) }
}

fn sealed_of(d: &Document, field: &str) -> Result<Sealed> {
    let s = d.get_document(field).with_context(|| format!("{field} is missing"))?;
    Ok(Sealed { nonce: s.get_binary_generic("n")?.clone(), ct: s.get_binary_generic("c")?.clone() })
}

fn account_doc(k: &AccountKeys, updated_at: i64) -> Document {
    doc! {
        "v": 1,
        "account_id": bin(&k.account_id),
        "salt": bin(&k.salt),
        "kdf": { "alg": "argon2id", "m_kib": k.kdf_mem_kib as i64, "t": k.kdf_passes as i64, "p": k.kdf_lanes as i64 },
        "vault_dek": sealed_doc(&k.vault_dek),
        "history_key": sealed_doc(&k.history_key),
        "history_check": bin(&k.history_check),
        "updated_at": updated_at,
    }
}

fn account_from(d: &Document) -> Result<AccountKeys> {
    let kdf = d.get_document("kdf")?;
    let int = |k: &str| -> Result<u32> { Ok(u32::try_from(kdf.get_i64(k)?)?) };
    Ok(AccountKeys {
        account_id: d.get_binary_generic("account_id")?.clone(),
        salt: d.get_binary_generic("salt")?.clone(),
        kdf_mem_kib: int("m_kib")?,
        kdf_passes: int("t")?,
        kdf_lanes: int("p")?,
        vault_dek: sealed_of(d, "vault_dek")?,
        history_key: sealed_of(d, "history_key")?,
        history_check: d.get_binary_generic("history_check")?.clone(),
    })
}

fn cursor(store: &Store, coll: &str) -> Result<DateTime> {
    let ms = store.sync_value(&format!("cursor.{coll}"))?.and_then(|v| v.parse().ok()).unwrap_or(0);
    Ok(DateTime::from_millis(ms))
}

fn set_cursor(store: &Store, coll: &str, at: DateTime) -> Result<()> {
    store.set_sync_value(&format!("cursor.{coll}"), &at.timestamp_millis().to_string())
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex"));
    }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?)).collect()
}

/// The name shown on other devices next to clips copied here.
pub(super) fn device_name() -> String {
    std::env::var("CLIPVAULT_DEVICE_NAME")
        .ok()
        .filter(|n| !n.trim().is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|h| h.trim().to_string()))
        .unwrap_or_else(|| "this computer".into())
}

fn is_duplicate_key(e: &mongodb::error::Error) -> bool {
    matches!(&*e.kind, ErrorKind::Write(WriteFailure::WriteError(w)) if w.code == 11000)
        || matches!(&*e.kind, ErrorKind::Command(c) if c.code == 11000)
}

/// A conditional upsert that matched nothing collides with the newer copy's
/// `_id`. That newer copy wins, and the next pull brings it here.
fn ignore_newer<T>(r: mongodb::error::Result<T>) -> Result<()> {
    match r {
        Ok(_) => Ok(()),
        Err(e) if is_duplicate_key(&e) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&crate::crypto::hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_err());
    }

    #[test]
    fn the_account_document_round_trips() {
        let (keys, _) = AccountKeys::create("a long password", &[3u8; 32]).unwrap();
        assert_eq!(account_from(&account_doc(&keys, 5)).unwrap(), keys);
    }
}
