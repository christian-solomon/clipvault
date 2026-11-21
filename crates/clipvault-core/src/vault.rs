//! The encrypted vault.
//!
//! Key hierarchy: a random 32-byte data key (DEK) encrypts every label and
//! secret. The DEK is stored wrapped by a key derived from the master password
//! (KEK, argon2id). Unwrapping the DEK is the password check, and changing the
//! password only rewraps the DEK.
//!
//! Every ciphertext is XChaCha20-Poly1305 with associated data naming exactly
//! what it is (`clipvault/v2/<uid>/label`, `.../secret`, `clipvault/v2/dek`).
//! Swapping two rows' ciphertexts in the database therefore fails to decrypt
//! instead of quietly handing back the wrong secret under a trusted label.

use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use crate::store::{now, LegacyVault, NewSealedItem, Sealed, Store, VaultKeyRow};

const SALT_LEN: usize = 16;
const UID_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_LABEL_CHARS: usize = 200;
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Plaintext sealed under the first-generation key to check the password.
const LEGACY_VERIFIER: &[u8] = b"clipvault-verify-v1";
const AAD_DEK: &[u8] = b"clipvault/v2/dek";

/// After this many wrong passwords in a row, each further attempt waits.
const FREE_ATTEMPTS: u32 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// argon2id cost. ~64 MiB and 3 passes is roughly a quarter second on a
/// laptop: cheap once per unlock, expensive a few billion times offline.
/// Stored with the vault so it can be raised later without locking anyone out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    mem_kib: u32,
    passes: u32,
    lanes: u32,
}

impl KdfParams {
    const CURRENT: KdfParams = KdfParams { mem_kib: 65536, passes: 3, lanes: 4 };
    /// What the first-generation vault used, before parameters were stored.
    const LEGACY: KdfParams = KdfParams { mem_kib: 65536, passes: 3, lanes: 4 };

    fn of(row: &VaultKeyRow) -> Self {
        KdfParams { mem_kib: row.kdf_mem_kib, passes: row.kdf_passes, lanes: row.kdf_lanes }
    }

    /// Bounds the stored values, so an edited database cannot make an unlock
    /// allocate gigabytes or spin for minutes, nor drop the cost to nothing.
    fn checked(self) -> Result<Self> {
        let ok = (8 * 1024..=1024 * 1024).contains(&self.mem_kib)
            && (1..=16).contains(&self.passes)
            && (1..=16).contains(&self.lanes);
        if !ok {
            bail!(
                "vault key parameters are out of range; the database may have been tampered with"
            );
        }
        Ok(self)
    }
}

fn kdf(password: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.mem_kib, p.passes, p.lanes, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

fn seal(key: &[u8; 32], msg: &[u8], aad: &[u8]) -> Result<Sealed> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher(key)
        .encrypt(&nonce, Payload { msg, aad })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed { nonce: nonce.to_vec(), ct })
}

/// `None` means the tag did not verify: wrong key, wrong AAD, or tampering.
fn open(key: &[u8; 32], sealed: &Sealed, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != NONCE_LEN {
        return None;
    }
    cipher(key)
        .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ct, aad })
        .ok()
        .map(Zeroizing::new)
}

fn item_aad(uid: &[u8], field: &str) -> Vec<u8> {
    let mut aad = b"clipvault/v2/".to_vec();
    for b in uid {
        aad.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    aad.push(b'/');
    aad.extend_from_slice(field.as_bytes());
    aad
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Moves decrypted bytes into a self-wiping String without another copy.
fn into_string(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            bail!("stored value is not valid UTF-8")
        }
    }
}

fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        bail!("master password must be at least {MIN_PASSWORD_CHARS} characters");
    }
    Ok(())
}

fn check_label(label: &str) -> Result<&str> {
    let label = label.trim();
    if label.is_empty() {
        bail!("give the entry a label");
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        bail!("labels are limited to {MAX_LABEL_CHARS} characters");
    }
    Ok(label)
}

fn check_secret(secret: &str) -> Result<()> {
    if secret.is_empty() {
        bail!("nothing to store");
    }
    if secret.len() > MAX_SECRET_BYTES {
        bail!("secrets are limited to {} KiB", MAX_SECRET_BYTES / 1024);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// No vault has been created.
    Absent,
    Locked,
    Unlocked,
}

/// A decrypted listing row. The label is not the secret, but it is only
/// readable while unlocked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultItem {
    pub id: i64,
    pub label: String,
    pub created_at: i64,
}

#[derive(Default)]
pub struct Vault {
    dek: Option<Zeroizing<[u8; 32]>>,
    touched: Option<Instant>,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Vault {
    pub fn exists(store: &Store) -> Result<bool> {
        Ok(store.vault_key()?.is_some() || store.legacy_vault()?.is_some())
    }

    pub fn status(&self, store: &Store) -> Result<Status> {
        Ok(if self.dek.is_some() {
            Status::Unlocked
        } else if Self::exists(store)? {
            Status::Locked
        } else {
            Status::Absent
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    pub fn lock(&mut self) {
        // Zeroizing wipes the key bytes as it drops.
        self.dek = None;
        self.touched = None;
    }

    pub fn touch(&mut self) {
        if self.dek.is_some() {
            self.touched = Some(Instant::now());
        }
    }

    /// Drops the key if the vault has gone untouched for `idle`. Returns true
    /// when this call actually locked it.
    pub fn lock_if_idle(&mut self, idle: Duration) -> bool {
        let expired = self.touched.map(|t| t.elapsed() >= idle).unwrap_or(false);
        if expired && self.dek.is_some() {
            self.lock();
            return true;
        }
        false
    }

    /// Time left before `lock_if_idle(idle)` would lock.
    pub fn remaining(&self, idle: Duration) -> Option<Duration> {
        let t = self.touched?;
        self.dek.as_ref()?;
        Some(idle.saturating_sub(t.elapsed()))
    }

    fn dek(&self) -> Result<&[u8; 32]> {
        self.dek.as_deref().ok_or_else(|| anyhow!("vault is locked"))
    }

    pub fn init(&mut self, store: &Store, password: &str) -> Result<()> {
        if Self::exists(store)? {
            bail!("vault already exists");
        }
        check_password(password)?;
        let dek = Zeroizing::new(random::<32>());
        let key = wrap(&dek, password, KdfParams::CURRENT)?;
        store.set_vault_key(&key)?;
        self.dek = Some(dek);
        self.touch();
        Ok(())
    }

    pub fn unlock(&mut self, store: &Store, password: &str) -> Result<()> {
        if let Some(at) = self.retry_at {
            let now = Instant::now();
            if now < at {
                let secs = (at - now).as_secs() + 1;
                bail!("too many wrong passwords; try again in {secs}s");
            }
        }

        let dek = if let Some(key) = store.vault_key()? {
            unwrap(&key, password)?
        } else if let Some(legacy) = store.legacy_vault()? {
            upgrade_legacy(store, legacy, password)?
        } else {
            bail!("vault has not been set up yet");
        };

        match dek {
            Some(dek) => {
                self.failures = 0;
                self.retry_at = None;
                self.dek = Some(dek);
                self.touch();
                Ok(())
            }
            None => {
                self.failures += 1;
                if self.failures >= FREE_ATTEMPTS {
                    let wait = Duration::from_secs(1 << (self.failures - FREE_ATTEMPTS).min(5));
                    self.retry_at = Some(Instant::now() + wait.min(MAX_BACKOFF));
                }
                bail!("wrong password")
            }
        }
    }

    /// Rewraps the data key under a new password. The current password is
    /// required even while unlocked, so a walk-up at an unlocked desktop
    /// cannot take the vault over.
    pub fn change_password(&mut self, store: &Store, current: &str, new: &str) -> Result<()> {
        self.dek()?;
        check_password(new)?;
        let key = store.vault_key()?.ok_or_else(|| anyhow!("vault has not been set up yet"))?;
        let dek = unwrap(&key, current)?.ok_or_else(|| anyhow!("current password is wrong"))?;
        store.set_vault_key(&wrap(&dek, new, KdfParams::CURRENT)?)?;
        self.touch();
        Ok(())
    }

    /// Item count, readable while locked. Labels are not.
    pub fn count(store: &Store) -> Result<usize> {
        if store.vault_key()?.is_some() {
            store.vault_count()
        } else {
            Ok(store.legacy_vault()?.map(|l| l.entries.len()).unwrap_or(0))
        }
    }

    pub fn items(&self, store: &Store) -> Result<Vec<VaultItem>> {
        let dek = self.dek()?;
        let mut out = Vec::new();
        for row in store.vault_items()? {
            let label = open(dek, &row.label, &item_aad(&row.uid, "label"))
                .ok_or_else(|| anyhow!("vault entry {} failed to decrypt", row.id))?;
            out.push(VaultItem {
                id: row.id,
                label: into_string(label)?.to_string(),
                created_at: row.created_at,
            });
        }
        out.sort_by_key(|i| i.label.to_lowercase());
        Ok(out)
    }

    fn sealed_item(&self, label: &str, secret: &[u8]) -> Result<NewSealedItem> {
        let dek = self.dek()?;
        let uid = random::<UID_LEN>().to_vec();
        Ok(NewSealedItem {
            label: seal(dek, label.as_bytes(), &item_aad(&uid, "label"))?,
            secret: seal(dek, secret, &item_aad(&uid, "secret"))?,
            uid,
            created_at: now(),
        })
    }

    pub fn add(&mut self, store: &Store, label: &str, secret: &str) -> Result<i64> {
        let label = check_label(label)?;
        check_secret(secret)?;
        let id = store.vault_insert(&self.sealed_item(label, secret.as_bytes())?)?;
        self.touch();
        Ok(id)
    }

    /// Moves a text history entry into the vault, so the secret exists in one
    /// place only.
    pub fn absorb(&mut self, store: &Store, entry_id: i64, label: &str) -> Result<i64> {
        let label = check_label(label)?;
        self.dek()?;
        if store.kind(entry_id)?.as_deref() == Some("image") {
            bail!("the vault holds text secrets, not images");
        }
        let content = Zeroizing::new(
            store.content(entry_id)?.ok_or_else(|| anyhow!("entry no longer exists"))?,
        );
        check_secret(&content)?;
        let item = self.sealed_item(label, content.as_bytes())?;
        let id = store.move_entry_into_vault(entry_id, &item)?;
        self.touch();
        Ok(id)
    }

    pub fn reveal(&mut self, store: &Store, id: i64) -> Result<Zeroizing<String>> {
        let dek = self.dek()?;
        let (uid, sealed) =
            store.vault_secret(id)?.ok_or_else(|| anyhow!("vault entry no longer exists"))?;
        let plain = open(dek, &sealed, &item_aad(&uid, "secret"))
            .ok_or_else(|| anyhow!("vault entry failed to decrypt - the data may be corrupt"))?;
        self.touch();
        into_string(plain)
    }

    /// Deleting needs the vault open: destroying secrets is no less sensitive
    /// than reading them.
    pub fn delete(&mut self, store: &Store, id: i64) -> Result<()> {
        self.dek()?;
        store.vault_delete(id)?;
        self.touch();
        Ok(())
    }

    /// Destroys the whole vault without its password, the way out when the
    /// password is lost. It reveals nothing, so it does not need one.
    pub fn reset(&mut self, store: &Store) -> Result<()> {
        self.lock();
        self.failures = 0;
        self.retry_at = None;
        store.reset_vault()
    }
}

fn wrap(dek: &[u8; 32], password: &str, params: KdfParams) -> Result<VaultKeyRow> {
    let salt = random::<SALT_LEN>().to_vec();
    let kek = kdf(password, &salt, params)?;
    Ok(VaultKeyRow {
        wrapped_dek: seal(&kek, dek, AAD_DEK)?,
        salt,
        kdf_mem_kib: params.mem_kib,
        kdf_passes: params.passes,
        kdf_lanes: params.lanes,
    })
}

/// `Ok(None)` is a wrong password; `Err` is anything else.
fn unwrap(key: &VaultKeyRow, password: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let kek = kdf(password, &key.salt, KdfParams::of(key).checked()?)?;
    let Some(plain) = open(&kek, &key.wrapped_dek, AAD_DEK) else {
        return Ok(None);
    };
    let bytes: [u8; 32] =
        plain.as_slice().try_into().map_err(|_| anyhow!("stored vault key is malformed"))?;
    Ok(Some(Zeroizing::new(bytes)))
}

/// Converts a first-generation vault: checks the password against its
/// verifier, decrypts each entry, and re-seals labels and secrets under a new
/// data key with per-row AAD. The legacy tables, plaintext labels included,
/// are dropped and the file is rebuilt. Nothing changes on a wrong password
/// or if any entry fails to decrypt.
fn upgrade_legacy(
    store: &Store,
    legacy: LegacyVault,
    password: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let params = KdfParams::LEGACY;
    let kek = kdf(password, &legacy.salt, params)?;
    match open(&kek, &legacy.verifier, b"") {
        Some(v) if v.as_slice() == LEGACY_VERIFIER => {}
        _ => return Ok(None),
    }

    let dek = Zeroizing::new(random::<32>());
    let mut items = Vec::with_capacity(legacy.entries.len());
    for entry in &legacy.entries {
        let secret = open(&kek, &entry.secret, b"")
            .ok_or_else(|| anyhow!("a vault entry failed to decrypt; the vault was left as is"))?;
        let uid = random::<UID_LEN>().to_vec();
        items.push(NewSealedItem {
            label: seal(&dek, entry.label.as_bytes(), &item_aad(&uid, "label"))?,
            secret: seal(&dek, &secret, &item_aad(&uid, "secret"))?,
            uid,
            created_at: entry.created_at,
        });
    }

    // The password key and salt carry over; only the layer beneath changes.
    let key = VaultKeyRow {
        wrapped_dek: seal(&kek, &dek[..], AAD_DEK)?,
        salt: legacy.salt.clone(),
        kdf_mem_kib: params.mem_kib,
        kdf_passes: params.passes,
        kdf_lanes: params.lanes,
    };
    store.replace_legacy_vault(&key, &items)?;
    log::info!("converted the vault to the current format ({} entries)", items.len());
    Ok(Some(dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tempdir::Dir;
    use crate::store::Clip;

    const PW: &str = "correct horse battery";

    fn fixture() -> (Store, Vault, Dir) {
        let dir = Dir::new();
        let store = Store::open(&dir.path().join("v.db")).unwrap();
        (store, Vault::default(), dir)
    }

    /// Every byte of the database and its WAL, for checking what reached disk.
    fn disk_bytes(dir: &Dir) -> Vec<u8> {
        let mut all = Vec::new();
        for f in ["v.db", "v.db-wal"] {
            if let Ok(b) = std::fs::read(dir.path().join(f)) {
                all.extend(b);
            }
        }
        all
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn starts_absent_and_locked() {
        let (s, mut v, _d) = fixture();
        assert_eq!(v.status(&s).unwrap(), Status::Absent);
        assert!(v.add(&s, "x", "nope").is_err(), "a locked vault must not encrypt");
    }

    #[test]
    fn init_then_roundtrip() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        assert_eq!(v.status(&s).unwrap(), Status::Unlocked);

        let id = v.add(&s, "stripe", "sk-live-abc123").unwrap();
        assert_eq!(&*v.reveal(&s, id).unwrap(), "sk-live-abc123");
        assert_eq!(v.items(&s).unwrap()[0].label, "stripe");
    }

    #[test]
    fn rejects_short_password() {
        let (s, mut v, _d) = fixture();
        assert!(v.init(&s, "short").is_err());
        assert!(!v.is_unlocked());
        assert_eq!(v.status(&s).unwrap(), Status::Absent);
    }

    #[test]
    fn unlock_requires_the_right_password() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let id = v.add(&s, "label", "my secret").unwrap();
        v.lock();
        assert_eq!(v.status(&s).unwrap(), Status::Locked);

        assert!(v.unlock(&s, "wrong password here").is_err());
        assert!(!v.is_unlocked(), "a failed unlock must leave it locked");

        v.unlock(&s, PW).unwrap();
        assert_eq!(&*v.reveal(&s, id).unwrap(), "my secret");
    }

    #[test]
    fn locking_forgets_the_key() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let id = v.add(&s, "label", "my secret").unwrap();
        v.lock();
        assert!(v.reveal(&s, id).is_err());
        assert!(v.items(&s).is_err(), "labels are not listable while locked");
        assert_eq!(Vault::count(&s).unwrap(), 1, "but the count is");
    }

    #[test]
    fn nonces_differ_per_encryption() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let a = v.sealed_item("same", b"same text").unwrap();
        let b = v.sealed_item("same", b"same text").unwrap();
        assert_ne!(a.secret.nonce, b.secret.nonce, "reusing a nonce would leak the plaintext");
        assert_ne!(a.secret.ct, b.secret.ct);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let id = v.add(&s, "label", "my secret").unwrap();
        s.conn_for_tests()
            .execute(
                "UPDATE vault_items SET secret_ct = randomblob(length(secret_ct)) WHERE id = ?1",
                [id],
            )
            .unwrap();
        assert!(v.reveal(&s, id).is_err(), "AEAD must catch the edit");
    }

    #[test]
    fn swapping_rows_is_detected() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let a = v.add(&s, "harmless", "public value").unwrap();
        let b = v.add(&s, "bank", "hunter2-bank").unwrap();
        // Someone with write access to the file moves bank's ciphertext under
        // the harmless label, hoping it gets pasted somewhere careless.
        s.conn_for_tests()
            .execute(
                "UPDATE vault_items SET
                   secret_nonce = (SELECT secret_nonce FROM vault_items WHERE id = ?2),
                   secret_ct    = (SELECT secret_ct    FROM vault_items WHERE id = ?2)
                 WHERE id = ?1",
                [a, b],
            )
            .unwrap();
        assert!(v.reveal(&s, a).is_err(), "AAD binds each secret to its own row");
    }

    #[test]
    fn cannot_init_twice() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let mut other = Vault::default();
        assert!(other.init(&s, "a different one").is_err());
    }

    #[test]
    fn idle_timeout_locks() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        assert!(!v.lock_if_idle(Duration::from_secs(600)), "not idle yet");
        assert!(v.remaining(Duration::from_secs(600)).unwrap() > Duration::from_secs(590));
        assert!(v.lock_if_idle(Duration::ZERO), "zero timeout locks immediately");
        assert!(!v.is_unlocked());
        assert!(!v.lock_if_idle(Duration::ZERO), "already locked, nothing to do");
        assert_eq!(v.remaining(Duration::from_secs(600)), None);
    }

    #[test]
    fn labels_and_secrets_never_reach_disk_in_plaintext() {
        let (s, mut v, d) = fixture();
        v.init(&s, PW).unwrap();
        v.add(&s, "LABEL-MARKER-AWS-PROD-ROOT", "SECRET-MARKER-x9x9").unwrap();
        let disk = disk_bytes(&d);
        assert!(!contains(&disk, "LABEL-MARKER-AWS-PROD-ROOT"));
        assert!(!contains(&disk, "SECRET-MARKER-x9x9"));
    }

    #[test]
    fn password_change_keeps_items_and_retires_the_old_password() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let id = v.add(&s, "label", "kept across the change").unwrap();

        assert!(v.change_password(&s, "not the password", "new password 123").is_err());
        assert!(v.change_password(&s, PW, "short").is_err());
        v.change_password(&s, PW, "new password 123").unwrap();
        v.lock();

        assert!(v.unlock(&s, PW).is_err(), "the old password no longer opens it");
        v.unlock(&s, "new password 123").unwrap();
        assert_eq!(&*v.reveal(&s, id).unwrap(), "kept across the change");
    }

    #[test]
    fn change_password_needs_an_unlocked_vault() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        v.lock();
        assert!(v.change_password(&s, PW, "new password 123").is_err());
    }

    #[test]
    fn repeated_failures_back_off_then_recover() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        v.lock();
        for _ in 0..FREE_ATTEMPTS {
            assert!(v.unlock(&s, "wrong password!").unwrap_err().to_string().contains("wrong"));
        }
        let err = v.unlock(&s, PW).unwrap_err().to_string();
        assert!(err.contains("try again"), "even the right password waits: {err}");

        v.retry_at = Some(Instant::now() - Duration::from_secs(1));
        v.unlock(&s, PW).unwrap();
        assert_eq!(v.failures, 0, "success resets the count");
    }

    #[test]
    fn delete_needs_the_vault_open() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        let id = v.add(&s, "label", "value").unwrap();
        v.lock();
        assert!(v.delete(&s, id).is_err());
        assert_eq!(Vault::count(&s).unwrap(), 1);
        v.unlock(&s, PW).unwrap();
        v.delete(&s, id).unwrap();
        assert_eq!(Vault::count(&s).unwrap(), 0);
    }

    #[test]
    fn absorb_moves_a_history_entry_and_scrubs_it() {
        let (s, mut v, d) = fixture();
        v.init(&s, PW).unwrap();
        let entry = s.record(&Clip::Text("ABSORB-MARKER-ghp_0000".into())).unwrap().unwrap();
        let id = v.absorb(&s, entry, "github").unwrap();

        assert!(s.content(entry).unwrap().is_none(), "the plaintext row is gone");
        assert_eq!(&*v.reveal(&s, id).unwrap(), "ABSORB-MARKER-ghp_0000");
        assert!(!contains(&disk_bytes(&d), "ABSORB-MARKER-ghp_0000"), "and not left on disk");
    }

    #[test]
    fn stored_kdf_params_are_bounded() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        v.lock();
        s.conn_for_tests().execute("UPDATE vault_key SET kdf_mem_kib = 4000000000", []).unwrap();
        let err = v.unlock(&s, PW).unwrap_err().to_string();
        assert!(err.contains("out of range"), "{err}");
    }

    // ---- first-generation vaults -------------------------------------

    /// Writes a vault the way the Tauri release did: plaintext labels, entries
    /// sealed straight under the password key with no AAD.
    fn write_legacy_vault(s: &Store, password: &str, entries: &[(&str, &str)]) {
        let salt = random::<SALT_LEN>();
        let kek = kdf(password, &salt, KdfParams::LEGACY).unwrap();
        let verifier = seal(&kek, LEGACY_VERIFIER, b"").unwrap();
        let c = s.conn_for_tests();
        c.execute_batch(
            "CREATE TABLE vault_meta (id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL,
                 verify_nonce BLOB NOT NULL, verify_ct BLOB NOT NULL);
             CREATE TABLE vault_entries (id INTEGER PRIMARY KEY, label TEXT NOT NULL,
                 nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL);",
        )
        .unwrap();
        c.execute(
            "INSERT INTO vault_meta VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![salt.to_vec(), verifier.nonce, verifier.ct],
        )
        .unwrap();
        for (label, secret) in entries {
            let sealed = seal(&kek, secret.as_bytes(), b"").unwrap();
            c.execute(
                "INSERT INTO vault_entries (label, nonce, ciphertext, created_at)
                 VALUES (?1, ?2, ?3, 7)",
                rusqlite::params![label, sealed.nonce, sealed.ct],
            )
            .unwrap();
        }
    }

    #[test]
    fn reset_removes_a_legacy_vault_without_its_password() {
        let (s, mut v, d) = fixture();
        write_legacy_vault(&s, PW, &[("LEGACY-LABEL-forgotten", "pg-password-1")]);
        for _ in 0..3 {
            assert!(v.unlock(&s, "not the password").is_err());
        }

        v.reset(&s).unwrap();
        assert_eq!(v.status(&s).unwrap(), Status::Absent);
        assert_eq!(Vault::count(&s).unwrap(), 0);
        assert!(s.legacy_vault().unwrap().is_none());
        assert!(!contains(&disk_bytes(&d), "LEGACY-LABEL-forgotten"), "plaintext label purged");

        // A fresh vault works at once: the back-off from the failures is gone.
        v.init(&s, "a new password").unwrap();
        v.add(&s, "fresh", "new secret").unwrap();
        v.lock();
        v.unlock(&s, "a new password").unwrap();
        assert_eq!(v.items(&s).unwrap()[0].label, "fresh");
    }

    #[test]
    fn reset_removes_a_current_vault_and_locks_it() {
        let (s, mut v, _d) = fixture();
        v.init(&s, PW).unwrap();
        v.add(&s, "one", "secret one").unwrap();
        v.add(&s, "two", "secret two").unwrap();

        v.reset(&s).unwrap();
        assert!(!v.is_unlocked(), "the old key is dropped");
        assert_eq!(v.status(&s).unwrap(), Status::Absent);
        assert_eq!(Vault::count(&s).unwrap(), 0);
        assert!(v.unlock(&s, PW).is_err(), "the old password opens nothing");
    }

    #[test]
    fn legacy_vault_converts_on_first_unlock() {
        let (s, mut v, d) = fixture();
        write_legacy_vault(&s, PW, &[("LEGACY-LABEL-prod-db", "pg-password-1"), ("api", "k2")]);
        assert_eq!(v.status(&s).unwrap(), Status::Locked);
        assert_eq!(Vault::count(&s).unwrap(), 2);

        assert!(v.unlock(&s, "wrong password!").is_err());
        assert!(s.legacy_vault().unwrap().is_some(), "a wrong password changes nothing");

        v.unlock(&s, PW).unwrap();
        assert!(s.legacy_vault().unwrap().is_none(), "legacy tables are gone");
        let items = v.items(&s).unwrap();
        assert_eq!(
            items.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(),
            ["api", "LEGACY-LABEL-prod-db"]
        );
        let db = items.iter().find(|i| i.label.starts_with("LEGACY")).unwrap();
        assert_eq!(&*v.reveal(&s, db.id).unwrap(), "pg-password-1");
        assert_eq!(items[0].created_at, 7, "creation time carries over");
        assert!(!contains(&disk_bytes(&d), "LEGACY-LABEL-prod-db"), "old plaintext label purged");

        v.lock();
        v.unlock(&s, PW).unwrap();
        assert_eq!(v.items(&s).unwrap().len(), 2, "and the converted vault reopens");
    }

    #[test]
    fn legacy_conversion_is_all_or_nothing() {
        let (s, mut v, _d) = fixture();
        write_legacy_vault(&s, PW, &[("good", "fine"), ("bad", "will be corrupted")]);
        s.conn_for_tests()
            .execute("UPDATE vault_entries SET ciphertext = zeroblob(40) WHERE label = 'bad'", [])
            .unwrap();
        assert!(v.unlock(&s, PW).is_err());
        assert!(!v.is_unlocked());
        let legacy = s.legacy_vault().unwrap().expect("left in place");
        assert_eq!(legacy.entries.len(), 2);
        assert!(s.vault_key().unwrap().is_none());
    }
}
