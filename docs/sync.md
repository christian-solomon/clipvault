# ClipVault sync protocol, version 1

What a ClipVault client stores in MongoDB and how it encrypts it. A Windows,
mobile or relay implementation that follows this document can share an
account with the Linux client. The reference implementation is
`crates/clipvault-core/src/{account,crypto}.rs` and `src/sync/`.

Everything a person would recognise (text, images, vault labels and secrets,
the device name) is encrypted on the device. The database sees timestamps,
pin and use counts, sizes, fingerprints and device IDs.

## Primitives

| | |
|---|---|
| Password KDF | Argon2id, version 0x13, 32-byte output |
| AEAD | XChaCha20-Poly1305, 24-byte random nonce |
| Key derivation | HKDF-SHA256, no salt |
| MAC | HMAC-SHA256 |

A sealed value is stored as `{ n: <binary nonce>, c: <binary ciphertext+tag> }`.
Every seal names what it is in its associated data (AAD, the ASCII strings
below), so a ciphertext moved to another field or document fails to open.

## Keys

```
KEK          = Argon2id(password UTF-8, salt, m_kib, t, p)
vault_dek    = 32 random bytes     sealed under KEK, AAD "clipvault/v2/dek"
history_root = 32 random bytes     sealed under KEK, AAD "clipvault/sync/v1/history-key"

fields_key   = HKDF(history_root, info "clipvault/sync/v1/fields")
images_key   = HKDF(history_root, info "clipvault/sync/v1/images")
fp_key       = HKDF(history_root, info "clipvault/sync/v1/fingerprints")
check        = HMAC(history_root, "clipvault/sync/v1/check")[0..16]
```

The password check is unwrapping: a wrong password fails the AEAD tag.

A device stores `history_root` in its OS key store after the first unlock,
under service `dev.local.clipvault` and user `history-key/<hex account_id>`,
and on later starts confirms it against `check`. `vault_dek` is never stored;
each vault unlock derives the KEK again.

Changing the password reseals both keys under a new salt. Neither key
changes, so no other document is touched.

Bounds a client must enforce on stored parameters before running the KDF:
`8192 ≤ m_kib ≤ 1048576`, `1 ≤ t ≤ 16`, `1 ≤ p ≤ 16`. Current values:
`m_kib 65536, t 3, p 4`.

## Collections

The database name is the account's (default `clipvault`).

### `keys`

One document:

```
{
  _id: "account",
  v: 1,
  account_id: <binary, 16 random bytes>,
  salt: <binary, 16 bytes>,
  kdf: { alg: "argon2id", m_kib: <int64>, t: <int64>, p: <int64> },
  vault_dek: <sealed>,
  history_key: <sealed>,
  history_check: <binary, 16 bytes>,
  updated_at: <int64 ms>,
  synced_at: <date, set by the server>
}
```

### `clips`

One document per distinct content.

```
{
  _id: <fingerprint, 64 hex chars>,
  created_at: <int64 seconds>,
  last_used_at: <int64 seconds>,
  use_count: <int64>,
  pinned: <bool>,
  deleted: <bool>,
  updated_at: <int64 ms>,
  origin: <device ID, 32 hex chars>,
  synced_at: <date, set by the server>,
  sens: <sealed>,           // 1 byte: 0 none, 1 flagged, 2 kept on purpose
  meta: <sealed>,           // JSON {"kind": "text" | "image", "from": <device name>}
  text: <sealed>,           // text clips: UTF-8, at most 2 MiB
  thumb: <sealed>           // image clips: PNG, at most 160 px a side
}
```

AAD for a field is `clipvault/sync/v1/clip/<_id>/<field>`, sealed with
`fields_key`.

**Fingerprint.** `hex(HMAC(fp_key, kind || 0x00 || identity))`, where `kind` is
`text` or `image`, and `identity` is the lowercase hex SHA-256 of:

- text: the UTF-8 bytes;
- image: the decoded pixels, `width (u32 LE) || height (u32 LE) || RGBA8`.

Pixels rather than file bytes, because the same picture is re-encoded on its
way through clipboards. Clients that decode identically therefore agree on
one document per picture.

**Images.** The full image is a PNG in the GridFS bucket `images`. The file
is named by the fingerprint, holds the ciphertext, and has metadata
`{ n: <nonce> }`. It is sealed with `images_key` and AAD
`clipvault/sync/v1/image/<fingerprint>`. Duplicate uploads of one
fingerprint are harmless; read the newest.

### `vault`

```
{
  _id: <uid as 32 hex chars>,
  label: <sealed>,
  secret: <sealed>,
  created_at: <int64 seconds>,
  updated_at: <int64 ms>,
  deleted: <bool>,
  origin: <device ID>,
  synced_at: <date, set by the server>
}
```

Sealed with `vault_dek`, with AAD `clipvault/v2/<uid hex>/label` and
`.../secret`. This is the local vault's own format, so ciphertexts move
between a device and the database unchanged.

## Rules

**Writes win by `updated_at`.** Every write filters on
`updated_at < <the new value>`, so an older write changes nothing. A
conditional upsert that matches nothing collides on `_id` (error 11000).
That means a newer copy is already there, and is not an error.

**Content goes up once.** A clip whose live document exists only updates
`pinned`, `last_used_at`, `use_count`, `updated_at`, `origin` and `sens`.
`meta`, `text` or `thumb` and the image are sent when the document is new,
or when it was deleted and is copied again.

**Every write sets `synced_at`** with `$currentDate`.

**Pulls page by `synced_at`.** Each collection's cursor is stored as the
largest value seen. Pulls ask for `synced_at >= cursor`, so a boundary
document is read again, and applying it twice is harmless. The server
clock orders pulls, so a device whose clock is behind cannot write
somewhere another device's cursor has already passed.

**Applying a pulled document.** If the local copy is as new or newer, by
`updated_at`, nothing happens. Otherwise:

- a deleted document deletes the local copy;
- a live one updates its state, or inserts it.

A pulled clip whose identity hash matches a local entry that has no
fingerprint yet is the same copy made on both devices. The two are linked,
not duplicated.

**Deletes.** A delete sets `deleted: true` and `updated_at`, unsets the
sealed fields, and removes the clip's GridFS files. Documents deleted more
than 30 days ago are removed, so a device offline longer than that keeps
what it had.

**History limits.** Each device trims its own history to its limits, newest
by `last_used_at` first. What it trims, it deletes as above.

**Copies from other devices.** A clip inserted by a pull, with `origin`
another device and `created_at` within the last 120 seconds, goes onto the
receiving device's clipboard. It must not then be recorded there as a new
copy.

**Not synced.** Copies that look like credentials are kept in memory only on
the device that saw them and never written anywhere.

## Notes for other clients

- Phones should not hold the database password. MongoDB retired Device Sync
  and its HTTP Data API on 30 September 2025. A small relay (for example
  an AWS Lambda) between phones and the cluster sees only what the
  database sees, and keeps the connection string off devices that are
  easily lost.
- iOS and Android only let an app read the clipboard while it is in the
  foreground, so capturing on a phone goes through the app or a share
  action. Pasting from synced history works normally.
- Change streams wake the Linux client within seconds. A client without
  them should poll; the reference client also polls every 60 seconds.
