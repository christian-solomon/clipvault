use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::time::Instant;
use zeroize::Zeroizing;

use crate::store::Store;

const VERIFIER: &[u8] = b"clipvault-verify-v1";
const SALT_LEN: usize = 16;

// ~64 MiB, 3 passes. Tuned to cost roughly a quarter second on a laptop, which
// is cheap once per unlock and expensive to do a few billion times offline.
const KDF_MEM_KIB: u32 = 65536;
const KDF_PASSES: u32 = 3;
const KDF_LANES: u32 = 4;

/// Minutes of inactivity after which the key is dropped from memory.
pub const AUTO_LOCK_MINUTES: u64 = 10;

fn kdf(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(KDF_MEM_KIB, KDF_PASSES, KDF_LANES, Some(32))
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

#[derive(Default)]
pub struct Vault {
    key: Option<Zeroizing<[u8; 32]>>,
    touched: Option<Instant>,
}

impl Vault {
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    pub fn lock(&mut self) {
        // Zeroizing wipes the key bytes as it drops.
        self.key = None;
        self.touched = None;
    }

    pub fn touch(&mut self) {
        if self.key.is_some() {
            self.touched = Some(Instant::now());
        }
    }

    /// Drops the key if the vault has gone untouched past the timeout.
    /// Returns true when this call actually locked it.
    pub fn lock_if_idle(&mut self, minutes: u64) -> bool {
        let idle = self
            .touched
            .map(|t| t.elapsed().as_secs() >= minutes * 60)
            .unwrap_or(false);
        if idle && self.key.is_some() {
            self.lock();
            return true;
        }
        false
    }

    pub fn seconds_until_lock(&self, minutes: u64) -> Option<u64> {
        let t = self.touched?;
        Some((minutes * 60).saturating_sub(t.elapsed().as_secs()))
    }

    pub fn init(&mut self, store: &Store, password: &str) -> Result<()> {
        if store.vault_meta()?.is_some() {
            bail!("vault already exists");
        }
        if password.chars().count() < 8 {
            bail!("master password must be at least 8 characters");
        }
        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);

        let key = kdf(password, &salt)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher(&key)
            .encrypt(&nonce, VERIFIER)
            .map_err(|_| anyhow!("failed to seal verifier"))?;

        store.set_vault_meta(&salt, nonce.as_slice(), &ct)?;
        self.key = Some(key);
        self.touch();
        Ok(())
    }

    pub fn unlock(&mut self, store: &Store, password: &str) -> Result<()> {
        let (salt, nonce, ct) = store
            .vault_meta()?
            .ok_or_else(|| anyhow!("vault has not been set up yet"))?;

        let key = kdf(password, &salt)?;
        let plain = cipher(&key)
            .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| anyhow!("wrong password"))?;

        if plain != VERIFIER {
            bail!("wrong password");
        }
        self.key = Some(key);
        self.touch();
        Ok(())
    }

    fn key(&self) -> Result<&[u8; 32]> {
        self.key.as_deref().ok_or_else(|| anyhow!("vault is locked"))
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = self.key()?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher(key)
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow!("encryption failed"))?;
        Ok((nonce.to_vec(), ct))
    }

    pub fn decrypt(&self, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<String>> {
        let key = self.key()?;
        let plain = cipher(key)
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("decryption failed - data may be corrupt"))?;
        // Both the intermediate buffer and the returned String wipe themselves
        // on drop; the Vec is moved into the String rather than copied again.
        let plain = Zeroizing::new(plain);
        Ok(Zeroizing::new(
            String::from_utf8(plain.to_vec()).map_err(|_| anyhow!("secret is not valid UTF-8"))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tempdir::Dir;

    fn fixture() -> (Store, Vault, Dir) {
        let dir = Dir::new();
        let store = Store::open(&dir.path().join("v.db")).unwrap();
        (store, Vault::default(), dir)
    }

    #[test]
    fn starts_locked() {
        let (_s, v, _d) = fixture();
        assert!(!v.is_unlocked());
        assert!(v.encrypt("nope").is_err(), "a locked vault must not encrypt");
    }

    #[test]
    fn init_then_roundtrip() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        assert!(v.is_unlocked());

        let (nonce, ct) = v.encrypt("sk-live-abc123").unwrap();
        assert_ne!(ct, b"sk-live-abc123", "ciphertext must not be the plaintext");
        assert_eq!(&*v.decrypt(&nonce, &ct).unwrap(), "sk-live-abc123");
    }

    #[test]
    fn rejects_short_password() {
        let (s, mut v, _d) = fixture();
        assert!(v.init(&s, "short").is_err());
        assert!(!v.is_unlocked());
    }

    #[test]
    fn unlock_requires_the_right_password() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        let (nonce, ct) = v.encrypt("my secret").unwrap();
        v.lock();
        assert!(!v.is_unlocked());

        assert!(v.unlock(&s, "wrong password here").is_err());
        assert!(!v.is_unlocked(), "a failed unlock must leave it locked");

        v.unlock(&s, "correct horse battery").unwrap();
        assert_eq!(&*v.decrypt(&nonce, &ct).unwrap(), "my secret");
    }

    #[test]
    fn locking_forgets_the_key() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        let (nonce, ct) = v.encrypt("my secret").unwrap();
        v.lock();
        assert!(v.decrypt(&nonce, &ct).is_err());
    }

    #[test]
    fn nonces_differ_per_encryption() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        let (n1, c1) = v.encrypt("same text").unwrap();
        let (n2, c2) = v.encrypt("same text").unwrap();
        assert_ne!(n1, n2, "reusing a nonce would leak the plaintext");
        assert_ne!(c1, c2);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        let (nonce, mut ct) = v.encrypt("my secret").unwrap();
        ct[0] ^= 0xFF;
        assert!(v.decrypt(&nonce, &ct).is_err(), "AEAD must catch the edit");
    }

    #[test]
    fn cannot_init_twice() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        let mut other = Vault::default();
        assert!(other.init(&s, "a different one").is_err());
    }

    #[test]
    fn idle_timeout_locks() {
        let (s, mut v, _d) = fixture();
        v.init(&s, "correct horse battery").unwrap();
        assert!(!v.lock_if_idle(10), "not idle yet");
        assert!(v.lock_if_idle(0), "zero-minute timeout locks immediately");
        assert!(!v.is_unlocked());
        assert!(!v.lock_if_idle(0), "already locked, nothing to do");
    }
}
