# ClipVault

Clipboard history with an encrypted secrets vault, for X11 on Linux. Pure Rust:
the UI is [GPUI](https://www.gpui.rs) (Zed's framework) with
[gpui-component](https://github.com/longbridge/gpui-kit); there is no WebView,
Node or JavaScript.

```
crates/clipvault-core   capture, history store, vault, detection, IPC — no UI, all the tests
crates/clipvault        the binary: GPUI window, tray, hotkey, lock listeners
```

## Building

```bash
sudo apt install build-essential pkg-config libxcb1-dev libxkbcommon-dev \
    libxkbcommon-x11-dev libfontconfig-dev libfreetype-dev
cargo build --release            # target/release/clipvault
cargo test --workspace
cargo install cargo-deb && cargo deb -p clipvault   # .deb in target/debian
```

The package is named `clip-vault`, as the Tauri build's was, so installing it
upgrades that package in place. At runtime it needs a Vulkan driver, or EGL as
the fallback.

GPUI is pinned exactly (`gpui-pre =0.3.12`, the snapshot `gpui-component
=0.10.0` requires); upgrade the two together.

## Using it

Only one copy runs; launching it again signals the running one.

```
clipvault              # start in the tray, or toggle the window if running
clipvault ui           # open the window, starting the app first if needed
clipvault --toggle     # show, or hide if already showing
clipvault --no-hotkey  # do not grab the hotkey
```

For Super+V, either clear GNOME's message-tray binding
(`gsettings set org.gnome.shell.keybindings toggle-message-tray "[]"`) and let
the app grab it, or bind `clipvault ui` under Settings > Keyboard > Custom
Shortcuts and run the app with `--no-hotkey`. The second does not depend on
winning the X grab at login.

To start at login, put a desktop entry in `~/.config/autostart/` with
`Exec=/usr/bin/clipvault` (plus `--no-hotkey` if the desktop owns the key).

| Key | History | Vault |
|---|---|---|
| `↑` `↓` | select | select |
| `Enter` | copy and close | copy (cleared later) |
| `Ctrl+P` | pin / unpin | |
| `Ctrl+S` | move into the vault | |
| `Ctrl+R` | show a masked credential | reveal for 10 s |
| `Ctrl+N` | | new secret |
| `Ctrl+L` | lock the vault | lock the vault |
| `Shift+Delete` | delete (asks first) | delete (asks first) |
| `Tab` | switch tab | switch tab |
| `Esc` | close | close |

History cards also have buttons for copy, pin, move into the vault and delete,
shown on the selected or hovered card. **Clear history** deletes every unpinned
entry, pinned ones too if you tick the box, and never touches the vault.

The window is created when shown and destroyed when hidden, and it hides when
it loses focus.

Resident memory, measured on an Intel Iris Xe laptop (Mesa Vulkan):

| | |
|---|---|
| started, window never opened | 24 MB |
| window open | 124 MB |
| after hiding | 124 MB |
| Tauri build, idle (process + WebKit helpers) | 304 MB |

Hiding destroys the window and its surface, but the GPU driver and renderer
state loaded on first show stay mapped until the app exits.

## Theme

The look is the shadcn/ui preset `b3ezFPvD9s`: the vega style, the mist palette
(a cool blue-grey), Inter for text, Geist for headings, and a 10 px base radius.
`assets/themes/mist.json` holds its light and dark tokens as a gpui-component
theme, and follows the desktop's light or dark setting.

Regenerate it from this or another preset (shadcn's public init endpoint
supplies the tokens):

```bash
python3 scripts/shadcn-theme.py b3ezFPvD9s assets/themes/mist.json
```

Inter and Geist are embedded in the binary (`assets/fonts`, SIL Open Font
License). Icons stay Lucide, the set gpui-component draws its own controls
with, rather than the preset's Hugeicons.

## Configuration

Everything comes from the environment; an unset variable takes the default and
an invalid one stops startup with an error naming it.

| Variable | Default | |
|---|---|---|
| `CLIPVAULT_DATA_DIR` | `$XDG_DATA_HOME/dev.local.clipvault` | database directory |
| `CLIPVAULT_HOTKEY` | `super+v` | global hotkey, `none` to disable |
| `CLIPVAULT_AUTOLOCK_MINUTES` | `10` | idle time before the vault locks |
| `CLIPVAULT_CLIPBOARD_CLEAR_SECONDS` | `30` | how long a copied secret stays on the clipboard; `0` keeps it |
| `CLIPVAULT_SENSITIVE_TTL_SECONDS` | `300` | lifetime of memory-only credential clips |
| `CLIPVAULT_HISTORY_MAX_ENTRIES` | `500` | unpinned entries kept |
| `CLIPVAULT_HISTORY_MAX_BYTES` | `268435456` | byte budget for unpinned entries |
| `CLIPVAULT_ALLOW_DEBUGGER` | unset | `1` keeps the process dumpable |
| `CLIPVAULT_MONGODB_URL` | unset | sync database; without it ClipVault is local-only |
| `CLIPVAULT_MONGODB_DB` | the URL's database, else `clipvault` | database name within it |
| `CLIPVAULT_DEVICE_NAME` | host name | shown on other devices next to clips copied here |
| `CLIPVAULT_SYNC_ADOPT` | `1` | `0` stops other devices' copies landing on this clipboard |
| `RUST_LOG` | `warn,clipvault=info,clipvault_core=info` | log filter; logs go to stdout |

The history database is local state by design: a clipboard manager that forgot
everything on restart would not be one. Its location is configuration like any
other. With sync on it is a working copy of the account. A synced device also
keeps one key in the OS keyring (see Sync).

## Sync

With `CLIPVAULT_MONGODB_URL` set, history and the vault sync through MongoDB
between every device that uses the account. Copying on one device puts the
copy on the others' clipboards within seconds. Each device keeps its full
local copy, so search stays instant and nothing stops working offline.

Everything readable is encrypted on the device before it is sent. The
database holds a single account record with two keys, both sealed under
the master password:
- the **vault key**, which never leaves memory and is needed afresh for each
  vault unlock;
- the **history key**, which a device keeps in its OS keyring after the first
  unlock, so history syncs without asking again.

The format is specified in [`docs/sync.md`](docs/sync.md), for the Windows and
mobile clients.

Setting up:

1. Store the connection string, with the database in its path
   (`…mongodb.net/clipvault?…`), as `CLIPVAULT_MONGODB_URL` in an Infisical
   project. Its user needs `readWrite` on that database and nothing more.
2. Start ClipVault through `clipvault-infisical`, which reads the URL from
   Infisical into ClipVault's environment and starts local-only when it
   can't (signed out, or offline with nothing cached). For the login
   autostart entry:

   ```ini
   Exec=env CLIPVAULT_INFISICAL_PROJECT=<project id> clipvault-infisical --no-hotkey
   ```

   `CLIPVAULT_INFISICAL_ENV` picks the environment (default `prod`).

3. The header chip says **Set up sync** on the first device. Choose the
   master password there, or use the vault's password if this device
   already has a vault. On every other device the chip says **Unlock sync**:
   enter the same password once.

The vault's password and the sync password are the same password. Changing
it on one device reaches the others. A reset of a forgotten vault password
deletes the vault on every device, but keeps the account, so history keeps
syncing.

Copies that look like credentials are still kept in memory only, and never
synced.

## Security

### What is protected

**Vault.** A random 256-bit data key encrypts every label and secret with
XChaCha20-Poly1305. The data key is stored wrapped by a key derived from the
master password with argon2id (64 MiB, 3 passes, 4 lanes; the parameters are
stored and bounded on read). Each ciphertext's associated data names its row and
field, so ciphertexts swapped between rows fail to decrypt. Labels are
encrypted: while locked, only the number of secrets is visible. Changing the
password rewraps the data key. Deleting needs the vault unlocked, and repeated
wrong passwords back off.
A lost password cannot be recovered. The unlock screen's reset deletes the whole
vault so a new one can be made; it needs no password because it reveals
nothing.

The vault locks after `CLIPVAULT_AUTOLOCK_MINUTES` idle, when the screen locks
(GNOME and freedesktop screensaver signals, logind `Lock`) and before suspend
(logind `PrepareForSleep`). Locking drops the key from memory.

**Copying secrets out.** A vault copy carries `x-kde-passwordManagerHint:
secret`, which this app and other clipboard managers skip. A keyed hash of it
also stays on a deny list until it is cleared, so it cannot reach history even
if the watcher reads it late. After `CLIPVAULT_CLIPBOARD_CLEAR_SECONDS` the
clipboard is cleared, if it still holds that secret.

**Credentials in history.** A copy that looks like a credential (private keys;
AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI and Anthropic keys; JWTs;
storage connection strings; URLs with a password; random-looking tokens) is kept
in memory only, expires, and is never written to the database. `Ctrl+S` moves it
into the vault; `Ctrl+P` stores it in plaintext history only after asking.
History recorded before detection existed is scanned once and matches are
flagged, with a banner to delete them.

**Files.** The data directory is 0700 and the database, WAL and shared-memory
files 0600; looser permissions from older versions are tightened on start.
SQLite `secure_delete` is on, every delete ends with a truncating WAL
checkpoint, and the upgrade to this version rebuilds the file once, so deleted
or vaulted content is not left in the database files.

**Process.** Release builds set `PR_SET_DUMPABLE=0` and a zero core-size limit:
no core dumps, and other processes of the same user cannot ptrace it or read its
memory. The single-instance socket sits in a 0700 directory under
`$XDG_RUNTIME_DIR` and checks the peer's uid.

### What is not

- **History is plaintext on disk** apart from the detection above. A credential
  that matches no pattern is stored like any other text. In the sync database
  it is encrypted. What the database does see:
  - when each item was copied and last used, and how often;
  - whether it is pinned;
  - its size;
  - which device made each change;
  - that the same item was copied twice.
- **X11 has no isolation between clients.** Any program on the same display can
  read the clipboard and the keyboard. ClipVault cannot change that.
- **Deleted data on the disk itself.** The database files are scrubbed, but
  SSDs and copy-on-write filesystems keep old blocks. Use full-disk encryption.
- **Memory that is not ours to wipe.** Passwords and secrets are held in
  self-wiping buffers, but GPUI's text input and text layout keep their own
  copies of what is typed or shown, and arboard keeps a copy of what is on the
  clipboard until it changes.
- **Root, or a compromised session.** Out of scope.

## How it captures copies

It watches the X11 CLIPBOARD selection through XFixes rather than hooking keys.
Ctrl+C, a context menu, an in-app copy button and `xdotool` all change the
selection owner, so all are captured, and nothing reads the keyboard.

Text and images are captured, screenshots included. Text wins when an app offers
both, since copying a file or rich content offers an image alongside the text
you wanted.

- A `ConvertSelection` must carry a timestamp the owner accepts, and owners may
  refuse one that predates their ownership. `server_time()` in `watcher.rs` asks
  the server for a fresh timestamp with a zero-length property append; the
  XFixes event time is not guaranteed to be late enough.
- Each clipboard target has its own size cap (64 KiB for metadata, 2 MiB for
  text, 32 MiB for images), checked before buffering, and image decoding is
  bounded to 16384 px per edge.

## Testing the watcher by hand

`scripts/gtkcopy.py` and `scripts/gtkpaste.py` act as a real GTK clipboard owner
and consumer. arboard's X11 owner refuses our `ConvertSelection` even though
GTK and Qt apps serve it, so an arboard-based helper makes a working watcher
look broken.

```bash
python3 scripts/gtkcopy.py "hello"          # text
python3 scripts/gtkcopyimage.py 1200 900    # large image, forces an INCR transfer
python3 scripts/gtkpasteimage.py            # read an image back
```

`gtkcopyimage.py` uses random pixels so the PNG stays large enough for `INCR`.

Point a test run at a throwaway directory so it leaves your history alone:

```bash
CLIPVAULT_DATA_DIR=/tmp/cv-test cargo run -p clipvault -- ui --no-hotkey
```

## Limits

- X11 only. The window would run on Wayland, but the XFixes watcher and the
  global hotkey would not; Wayland needs a portal or a compositor protocol.
- Text and images (PNG, JPEG, BMP, GIF, stored as PNG). File lists are skipped.
- Unpinned history is capped at 500 entries and 256 MiB by default, oldest
  evicted first.
