//! Primitives shared by the vault and the sync account: argon2id for
//! passwords, XChaCha20-Poly1305 for everything sealed, HKDF and HMAC for
//! derived keys and fingerprints.

use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::store::{Sealed, VaultKeyRow};

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;

/// argon2id cost. ~64 MiB and 3 passes is roughly a quarter second on a
/// laptop: cheap once per unlock, expensive a few billion times offline.
/// Stored with each key so it can be raised later without locking anyone out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub mem_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl KdfParams {
    pub const CURRENT: KdfParams = KdfParams { mem_kib: 65536, passes: 3, lanes: 4 };
    /// What the first-generation vault used, before parameters were stored.
    pub const LEGACY: KdfParams = KdfParams { mem_kib: 65536, passes: 3, lanes: 4 };

    pub fn of(row: &VaultKeyRow) -> Self {
        KdfParams { mem_kib: row.kdf_mem_kib, passes: row.kdf_passes, lanes: row.kdf_lanes }
    }

    /// Bounds the stored values, so an edited database cannot make an unlock
    /// allocate gigabytes or spin for minutes, nor drop the cost to nothing.
    pub fn checked(self) -> Result<Self> {
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

pub(crate) fn kdf(password: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
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

pub(crate) fn seal(key: &[u8; 32], msg: &[u8], aad: &[u8]) -> Result<Sealed> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher(key)
        .encrypt(&nonce, Payload { msg, aad })
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed { nonce: nonce.to_vec(), ct })
}

/// `None` means the tag did not verify: wrong key, wrong AAD, or tampering.
pub(crate) fn open(key: &[u8; 32], sealed: &Sealed, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != NONCE_LEN {
        return None;
    }
    cipher(key)
        .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ct, aad })
        .ok()
        .map(Zeroizing::new)
}

/// A 32-byte key for one purpose, derived from a root key with HKDF-SHA256.
pub(crate) fn derive(root: &[u8; 32], purpose: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, root)
        .expand(purpose.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub(crate) fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Moves decrypted bytes into a self-wiping String without another copy.
pub(crate) fn into_string(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            bail!("stored value is not valid UTF-8")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_differ_by_purpose_and_are_stable() {
        let root = [7u8; 32];
        assert_eq!(*derive(&root, "a"), *derive(&root, "a"));
        assert_ne!(*derive(&root, "a"), *derive(&root, "b"));
        assert_ne!(*derive(&root, "a"), *derive(&[8u8; 32], "a"));
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        // RFC 4231 test case 2 uses a 4-byte key; pad-free keys are accepted.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_seal_opens_only_with_its_key_and_aad() {
        let key = random::<32>();
        let sealed = seal(&key, b"msg", b"aad").unwrap();
        assert_eq!(&**open(&key, &sealed, b"aad").unwrap(), b"msg");
        assert!(open(&key, &sealed, b"other").is_none());
        assert!(open(&random::<32>(), &sealed, b"aad").is_none());
    }
}
