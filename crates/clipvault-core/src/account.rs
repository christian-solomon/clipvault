//! The sync account: keys every device shares, stored in MongoDB sealed
//! under the master password, so the database alone can decrypt nothing.
//!
//! One record holds a salt and argon2id parameters, and two keys sealed under
//! the password-derived key:
//!
//! - the vault data key, sealed exactly as the local vault seals it
//!   (`clipvault/v2/dek`), so a local vault and the account share one format;
//! - the history key, from which every history field, image and fingerprint
//!   key is derived. A device keeps it in the OS keyring after the first
//!   unlock, so history syncs without asking again. The vault key is never
//!   kept: each vault unlock takes the password.
//!
//! The byte-level format is specified in `docs/sync.md` for other clients.

use anyhow::{anyhow, bail, Result};
use zeroize::Zeroizing;

use crate::crypto::{derive, hex, hmac, kdf, open, random, seal, KdfParams, SALT_LEN};
use crate::store::{Sealed, VaultKeyRow};
use crate::vault::AAD_DEK;

pub const AAD_HISTORY_KEY: &[u8] = b"clipvault/sync/v1/history-key";
const CHECK_INPUT: &[u8] = b"clipvault/sync/v1/check";
const CHECK_LEN: usize = 16;
const KEYRING_SERVICE: &str = "dev.local.clipvault";

/// The account record as MongoDB and the local cache hold it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeys {
    pub account_id: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_mem_kib: u32,
    pub kdf_passes: u32,
    pub kdf_lanes: u32,
    pub vault_dek: Sealed,
    pub history_key: Sealed,
    /// A keyed checksum of the history key, so a device can tell whether the
    /// key in its keyring belongs to this account without the password.
    pub history_check: Vec<u8>,
}

/// The unwrapped history key and the keys derived from it.
pub struct HistoryKeys {
    root: Zeroizing<[u8; 32]>,
    fields: Zeroizing<[u8; 32]>,
    images: Zeroizing<[u8; 32]>,
    fingerprints: Zeroizing<[u8; 32]>,
}

impl HistoryKeys {
    pub fn from_root(root: Zeroizing<[u8; 32]>) -> Self {
        HistoryKeys {
            fields: derive(&root, "clipvault/sync/v1/fields"),
            images: derive(&root, "clipvault/sync/v1/images"),
            fingerprints: derive(&root, "clipvault/sync/v1/fingerprints"),
            root,
        }
    }

    fn check(&self) -> Vec<u8> {
        hmac(&self.root, CHECK_INPUT)[..CHECK_LEN].to_vec()
    }

    /// The clip's ID on every device: a keyed hash, so the database sees when
    /// the same thing is copied twice but not what it is.
    pub fn fingerprint(&self, kind: &str, content: &[u8]) -> String {
        let mut msg = Vec::with_capacity(kind.len() + 1 + content.len());
        msg.extend_from_slice(kind.as_bytes());
        msg.push(0);
        msg.extend_from_slice(content);
        hex(&hmac(&self.fingerprints, &msg))
    }

    pub fn seal_field(&self, id: &str, field: &str, msg: &[u8]) -> Result<Sealed> {
        seal(&self.fields, msg, &field_aad(id, field))
    }

    pub fn open_field(&self, id: &str, field: &str, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        open(&self.fields, sealed, &field_aad(id, field))
            .ok_or_else(|| anyhow!("clip {id}: {field} does not decrypt"))
    }

    pub fn seal_image(&self, fp: &str, png: &[u8]) -> Result<Sealed> {
        seal(&self.images, png, &image_aad(fp))
    }

    pub fn open_image(&self, fp: &str, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        open(&self.images, sealed, &image_aad(fp))
            .ok_or_else(|| anyhow!("image {fp} does not decrypt"))
    }
}

fn field_aad(id: &str, field: &str) -> Vec<u8> {
    format!("clipvault/sync/v1/clip/{id}/{field}").into_bytes()
}

fn image_aad(fp: &str) -> Vec<u8> {
    format!("clipvault/sync/v1/image/{fp}").into_bytes()
}

impl AccountKeys {
    /// A new account around an existing vault data key (a local vault's, or
    /// a fresh one), with a fresh history key.
    pub fn create(password: &str, vault_dek: &[u8; 32]) -> Result<(AccountKeys, HistoryKeys)> {
        let history = HistoryKeys::from_root(Zeroizing::new(random::<32>()));
        let keys = Self::with_history(password, vault_dek, &history, random::<16>().to_vec())?;
        Ok((keys, history))
    }

    /// Seals a vault key and an existing history key under a password. Used
    /// when the vault starts over but every device keeps its history key.
    pub fn with_history(
        password: &str,
        vault_dek: &[u8; 32],
        history: &HistoryKeys,
        account_id: Vec<u8>,
    ) -> Result<AccountKeys> {
        let params = KdfParams::CURRENT;
        let salt = random::<SALT_LEN>().to_vec();
        let kek = kdf(password, &salt, params)?;
        Ok(AccountKeys {
            account_id,
            salt,
            kdf_mem_kib: params.mem_kib,
            kdf_passes: params.passes,
            kdf_lanes: params.lanes,
            vault_dek: seal(&kek, vault_dek, AAD_DEK)?,
            history_key: seal(&kek, history.root.as_ref(), AAD_HISTORY_KEY)?,
            history_check: history.check(),
        })
    }

    fn params(&self) -> Result<KdfParams> {
        KdfParams { mem_kib: self.kdf_mem_kib, passes: self.kdf_passes, lanes: self.kdf_lanes }
            .checked()
    }

    fn kek(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        kdf(password, &self.salt, self.params()?)
    }

    /// Unwraps the history key. A wrong password fails here.
    pub fn unlock_history(&self, password: &str) -> Result<HistoryKeys> {
        let kek = self.kek(password)?;
        let root = open(&kek, &self.history_key, AAD_HISTORY_KEY)
            .ok_or_else(|| anyhow!("wrong password"))?;
        self.history_from_bytes(&root)
    }

    fn history_from_bytes(&self, bytes: &[u8]) -> Result<HistoryKeys> {
        let root: [u8; 32] =
            bytes.try_into().map_err(|_| anyhow!("the history key has the wrong length"))?;
        let history = HistoryKeys::from_root(Zeroizing::new(root));
        if !self.matches(&history) {
            bail!("the history key does not belong to this account");
        }
        Ok(history)
    }

    pub fn matches(&self, history: &HistoryKeys) -> bool {
        self.history_check == history.check()
    }

    /// Seals both keys under a new password and salt. The keys themselves do
    /// not change, so nothing else needs re-encrypting and devices that hold
    /// the history key keep working.
    pub fn change_password(&self, old: &str, new: &str) -> Result<AccountKeys> {
        let kek = self.kek(old)?;
        let dek = open(&kek, &self.vault_dek, AAD_DEK).ok_or_else(|| anyhow!("wrong password"))?;
        let dek: [u8; 32] =
            dek.as_slice().try_into().map_err(|_| anyhow!("the vault key has the wrong length"))?;
        let dek = Zeroizing::new(dek);
        let history = self.unlock_history(old)?;
        Self::with_history(new, &dek, &history, self.account_id.clone())
    }

    /// The local vault's key row for this account: same salt, parameters and
    /// sealed data key, so the vault unlocks with the account password offline.
    pub fn vault_key_row(&self) -> VaultKeyRow {
        VaultKeyRow {
            salt: self.salt.clone(),
            kdf_mem_kib: self.kdf_mem_kib,
            kdf_passes: self.kdf_passes,
            kdf_lanes: self.kdf_lanes,
            wrapped_dek: self.vault_dek.clone(),
        }
    }

    fn keyring_user(&self) -> String {
        format!("history-key/{}", hex(&self.account_id))
    }
}

/// Where a device keeps the history key between runs.
pub trait SecretStore {
    fn get(&self, user: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, user: &str, secret: &[u8]) -> Result<()>;
    fn delete(&self, user: &str) -> Result<()>;
}

/// The OS keyring: Secret Service on Linux, Credential Manager on Windows,
/// the Keychain on macOS.
pub struct OsKeyring;

impl SecretStore for OsKeyring {
    fn get(&self, user: &str) -> Result<Option<Vec<u8>>> {
        match keyring::Entry::new(KEYRING_SERVICE, user)?.get_secret() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, user: &str, secret: &[u8]) -> Result<()> {
        Ok(keyring::Entry::new(KEYRING_SERVICE, user)?.set_secret(secret)?)
    }

    fn delete(&self, user: &str) -> Result<()> {
        match keyring::Entry::new(KEYRING_SERVICE, user)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl AccountKeys {
    /// The history key this device saved earlier, if it still fits.
    pub fn saved_history(&self, store: &dyn SecretStore) -> Result<Option<HistoryKeys>> {
        let Some(bytes) = store.get(&self.keyring_user())? else { return Ok(None) };
        let bytes = Zeroizing::new(bytes);
        match self.history_from_bytes(&bytes) {
            Ok(h) => Ok(Some(h)),
            Err(e) => {
                log::warn!("ignoring the saved history key: {e:#}");
                Ok(None)
            }
        }
    }

    pub fn save_history(&self, history: &HistoryKeys, store: &dyn SecretStore) -> Result<()> {
        store.set(&self.keyring_user(), history.root.as_ref())
    }

    pub fn forget_history(&self, store: &dyn SecretStore) -> Result<()> {
        store.delete(&self.keyring_user())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const PW: &str = "correct horse battery";

    #[derive(Default)]
    pub(crate) struct MemoryStore(RefCell<HashMap<String, Vec<u8>>>);

    impl SecretStore for MemoryStore {
        fn get(&self, user: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.borrow().get(user).cloned())
        }
        fn set(&self, user: &str, secret: &[u8]) -> Result<()> {
            self.0.borrow_mut().insert(user.into(), secret.to_vec());
            Ok(())
        }
        fn delete(&self, user: &str) -> Result<()> {
            self.0.borrow_mut().remove(user);
            Ok(())
        }
    }

    fn account() -> (AccountKeys, HistoryKeys, [u8; 32]) {
        let dek = random::<32>();
        let (keys, history) = AccountKeys::create(PW, &dek).unwrap();
        (keys, history, dek)
    }

    #[test]
    fn the_password_unlocks_the_same_history_key_on_another_device() {
        let (keys, here, _) = account();
        let there = keys.unlock_history(PW).unwrap();
        assert_eq!(here.fingerprint("text", b"x"), there.fingerprint("text", b"x"));
        let sealed = here.seal_field("id1", "text", b"hello").unwrap();
        assert_eq!(&**there.open_field("id1", "text", &sealed).unwrap(), b"hello");
    }

    #[test]
    fn a_wrong_password_unlocks_nothing() {
        let (keys, _, _) = account();
        assert!(keys.unlock_history("not the password").is_err());
    }

    #[test]
    fn the_vault_key_seals_like_the_local_vault() {
        // The account's vault key row opens with the password through the
        // ordinary local vault, so the two formats are one.
        let (keys, _, dek) = account();
        let dir = crate::store::tempdir::Dir::new();
        let store = crate::store::Store::open(&dir.path().join("a.db")).unwrap();
        store.set_vault_key(&keys.vault_key_row()).unwrap();
        let mut vault = crate::vault::Vault::default();
        vault.unlock(&store, PW).unwrap();
        assert_eq!(vault.dek_for_tests(), dek);
    }

    #[test]
    fn fields_are_bound_to_their_clip_and_name() {
        let (_, h, _) = account();
        let sealed = h.seal_field("clip-a", "text", b"secret").unwrap();
        assert!(h.open_field("clip-b", "text", &sealed).is_err(), "moved to another clip");
        assert!(h.open_field("clip-a", "meta", &sealed).is_err(), "moved to another field");
        let img = h.seal_image("fp1", b"png").unwrap();
        assert!(h.open_image("fp2", &img).is_err());
        assert!(h.open_field("fp1", "image", &img).is_err(), "image key is not the field key");
    }

    #[test]
    fn fingerprints_are_stable_keyed_and_kind_separated() {
        let (_, a, _) = account();
        let (_, b, _) = account();
        assert_eq!(a.fingerprint("text", b"same"), a.fingerprint("text", b"same"));
        assert_ne!(a.fingerprint("text", b"same"), b.fingerprint("text", b"same"), "keyed");
        assert_ne!(a.fingerprint("text", b"same"), a.fingerprint("image", b"same"));
        assert_eq!(a.fingerprint("text", b"x").len(), 64);
    }

    #[test]
    fn changing_the_password_keeps_both_keys() {
        let (keys, history, dek) = account();
        let changed = keys.change_password(PW, "a different password").unwrap();
        assert_eq!(changed.account_id, keys.account_id);
        assert!(changed.unlock_history(PW).is_err());
        let after = changed.unlock_history("a different password").unwrap();
        assert_eq!(after.fingerprint("text", b"x"), history.fingerprint("text", b"x"));
        assert!(changed.matches(&history), "devices holding the key keep working");

        let dir = crate::store::tempdir::Dir::new();
        let store = crate::store::Store::open(&dir.path().join("a.db")).unwrap();
        store.set_vault_key(&changed.vault_key_row()).unwrap();
        let mut vault = crate::vault::Vault::default();
        vault.unlock(&store, "a different password").unwrap();
        assert_eq!(vault.dek_for_tests(), dek);
    }

    #[test]
    fn the_keyring_round_trip_checks_the_key_belongs_to_the_account() {
        let (keys, history, _) = account();
        let store = MemoryStore::default();
        assert!(keys.saved_history(&store).unwrap().is_none());
        keys.save_history(&history, &store).unwrap();
        let back = keys.saved_history(&store).unwrap().unwrap();
        assert_eq!(back.fingerprint("text", b"x"), history.fingerprint("text", b"x"));

        // Another account's key under this account's name is ignored.
        let (other, other_history, _) = account();
        store.set(&keys.keyring_user(), other_history.root.as_ref()).unwrap();
        assert!(keys.saved_history(&store).unwrap().is_none());
        let _ = other;

        keys.forget_history(&store).unwrap();
        assert!(keys.saved_history(&store).unwrap().is_none());
    }

    #[test]
    fn tampered_kdf_parameters_are_refused() {
        let (mut keys, _, _) = account();
        keys.kdf_mem_kib = u32::MAX;
        assert!(keys.unlock_history(PW).is_err());
    }
}
