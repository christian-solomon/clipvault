//! Sync with MongoDB. The local database stays the working copy; this engine
//! uploads local changes and applies everyone else's, encrypted end to end.
//!
//! It runs on its own thread with its own tokio runtime and its own database
//! connection, so the UI never waits on the network. The UI talks to it with
//! [`SyncHandle`] and hears back through [`SyncEvent`]s.

mod remote;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use mongodb::bson::doc;
use mongodb::options::ClientOptions;
use mongodb::Client;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::account::{AccountKeys, HistoryKeys, SecretStore};
use crate::crypto::random;
use crate::store::{now_ms, Store};
use crate::vault;
use remote::{Pulled, Remote};

pub struct SyncConfig {
    /// `mongodb+srv://…`, with the credentials of a user limited to `database`.
    pub url: String,
    pub database: String,
    pub db_path: PathBuf,
    pub limits: (usize, i64),
    /// Put clips copied on other devices onto this clipboard.
    pub adopt: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Connecting,
    /// No account yet: the first device chooses the master password.
    NeedsSetup,
    /// An account exists; this device needs the master password once.
    NeedsUnlock,
    Syncing,
    Synced {
        at_ms: i64,
    },
    Offline {
        reason: String,
    },
}

pub enum SyncEvent {
    Status(SyncStatus),
    /// The local database changed from a pull; views should reload.
    Changed,
    /// Another device just copied this text; it belongs on this clipboard.
    AdoptText {
        text: Zeroizing<String>,
        from: Option<String>,
    },
    AdoptImage {
        png: Vec<u8>,
        from: Option<String>,
    },
    /// A setup or unlock attempt failed, e.g. a wrong password.
    Rejected(String),
}

enum Command {
    /// Something changed locally.
    Changed,
    Setup(Zeroizing<String>),
    Unlock(Zeroizing<String>),
    Stop,
}

pub struct SyncHandle {
    tx: mpsc::UnboundedSender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl SyncHandle {
    /// Tells the engine a local change is waiting to go up.
    pub fn changed(&self) {
        let _ = self.tx.send(Command::Changed);
    }

    pub fn setup(&self, password: Zeroizing<String>) {
        let _ = self.tx.send(Command::Setup(password));
    }

    pub fn unlock(&self, password: Zeroizing<String>) {
        let _ = self.tx.send(Command::Unlock(password));
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

type Emit = Arc<dyn Fn(SyncEvent) + Send + Sync>;

pub fn spawn(
    cfg: SyncConfig,
    secrets: Box<dyn SecretStore + Send>,
    on_event: impl Fn(SyncEvent) + Send + Sync + 'static,
) -> Result<SyncHandle> {
    let (tx, rx) = mpsc::unbounded_channel();
    let emit: Emit = Arc::new(on_event);
    let thread = std::thread::Builder::new().name("sync".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("sync cannot start: {e}");
                return;
            }
        };
        rt.block_on(run(cfg, secrets, emit, rx));
    })?;
    Ok(SyncHandle { tx, thread: Some(thread) })
}

async fn run(
    cfg: SyncConfig,
    secrets: Box<dyn SecretStore + Send>,
    emit: Emit,
    mut rx: mpsc::UnboundedReceiver<Command>,
) {
    let mut backoff = Duration::from_secs(2);
    loop {
        match session(&cfg, &*secrets, &emit, &mut rx).await {
            Ok(()) => return,
            Err(e) => {
                log::warn!("sync: {e:#}");
                emit(SyncEvent::Status(SyncStatus::Offline { reason: short(&e) }));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            cmd = rx.recv() => {
                if matches!(cmd, None | Some(Command::Stop)) {
                    return;
                }
            }
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// One connection's worth of syncing. Returns Ok only when told to stop.
async fn session(
    cfg: &SyncConfig,
    secrets: &dyn SecretStore,
    emit: &Emit,
    rx: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    emit(SyncEvent::Status(SyncStatus::Connecting));
    let mut opts = ClientOptions::parse(&cfg.url).await?;
    opts.app_name = Some("clipvault".into());
    opts.server_selection_timeout = Some(Duration::from_secs(15));
    opts.connect_timeout = Some(Duration::from_secs(10));
    let remote = Remote::new(Client::with_options(opts)?.database(&cfg.database));
    remote.db.run_command(doc! { "ping": 1 }).await?;
    remote.ensure_indexes().await?;

    let mut store = Store::open(&cfg.db_path)?;
    store.set_limits(cfg.limits.0, cfg.limits.1);
    let device = store.device_id()?;

    let keys = loop {
        match ready(&remote, &store, secrets).await? {
            Ok(keys) => break keys,
            Err(status) => {
                emit(SyncEvent::Status(status));
                let attempt = match rx.recv().await {
                    None | Some(Command::Stop) => return Ok(()),
                    Some(Command::Changed) => continue,
                    Some(Command::Setup(pw)) => setup(&remote, &store, secrets, &pw).await,
                    Some(Command::Unlock(pw)) => unlock(&remote, &store, secrets, &pw).await,
                };
                match attempt {
                    Ok(keys) => break keys,
                    Err(e) => emit(SyncEvent::Rejected(short(&e))),
                }
            }
        }
    };

    // A change stream wakes the loop the moment another device writes; the
    // timer covers a stream that cannot be opened or drops.
    let mut stream = match remote
        .db
        .watch()
        .pipeline([doc! { "$match": { "ns.coll": { "$in": [remote::CLIPS, remote::VAULT, remote::KEYS] } } }])
        .await
    {
        Ok(s) => Some(s),
        Err(e) => {
            log::info!("no change stream ({e}); polling instead");
            None
        }
    };
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    let mut rounds = 0u64;
    loop {
        emit(SyncEvent::Status(SyncStatus::Syncing));
        let (changed, pulled) = round(&remote, &store, &keys, &device, cfg.adopt).await?;
        if rounds.is_multiple_of(60) {
            remote.purge_tombstones().await?;
        }
        rounds += 1;
        emit(SyncEvent::Status(SyncStatus::Synced { at_ms: now_ms() }));
        if changed {
            emit(SyncEvent::Changed);
        }
        for p in pulled {
            emit(match p {
                Pulled::Text { text, from } => SyncEvent::AdoptText { text, from },
                Pulled::Image { png, from } => SyncEvent::AdoptImage { png, from },
            });
        }

        tokio::select! {
            _ = tick.tick() => {}
            ev = async { match stream.as_mut() { Some(s) => s.next().await, None => std::future::pending().await } } => {
                if !matches!(ev, Some(Ok(_))) {
                    log::info!("change stream ended; polling until reconnect");
                    stream = None;
                }
            }
            cmd = rx.recv() => match cmd {
                None | Some(Command::Stop) => return Ok(()),
                // Let a burst of local changes settle into one upload.
                Some(Command::Changed) => tokio::time::sleep(Duration::from_millis(300)).await,
                Some(_) => {}
            }
        }
        // Collapse whatever else queued up meanwhile into this round.
        while let Ok(cmd) = rx.try_recv() {
            if matches!(cmd, Command::Stop) {
                return Ok(());
            }
        }
    }
}

/// One exchange: upload what changed here, follow the account, then apply
/// what changed elsewhere.
async fn round(
    remote: &Remote,
    store: &Store,
    keys: &HistoryKeys,
    device: &str,
    adopt: bool,
) -> Result<(bool, Vec<Pulled>)> {
    remote.push(store, keys, device).await?;
    if let Some((theirs, their_at)) = remote.account().await? {
        if !theirs.matches(keys) {
            bail!("the sync account was replaced; unlock it again");
        }
        follow_account(store, &theirs, their_at)?;
    }
    remote.pull(store, keys, device, adopt).await
}

/// The history keys if this device can sync now, or what it needs first.
async fn ready(
    remote: &Remote,
    store: &Store,
    secrets: &dyn SecretStore,
) -> Result<std::result::Result<HistoryKeys, SyncStatus>> {
    let theirs = remote.account().await?;
    let mine = store.account()?;
    Ok(match (theirs, mine) {
        (None, None) => Err(SyncStatus::NeedsSetup),
        (None, Some(mine)) => {
            // The database was emptied or is new; this device still has the
            // account and the key, so it seeds it again.
            match mine.saved_history(secrets)? {
                Some(keys) => {
                    let (_, updated_at, _) = store.account_change()?.expect("account exists");
                    remote.push_account(&mine, updated_at).await?;
                    Ok(keys)
                }
                None => Err(SyncStatus::NeedsSetup),
            }
        }
        (Some((theirs, _)), mine) => {
            let same = mine.as_ref().is_some_and(|m| m.account_id == theirs.account_id);
            match (same, mine.and_then(|m| m.saved_history(secrets).transpose())) {
                (true, Some(Ok(keys))) if theirs.matches(&keys) => {
                    let (_, their_at) = remote.account().await?.expect("just read");
                    follow_account(store, &theirs, their_at)?;
                    Ok(keys)
                }
                _ => Err(SyncStatus::NeedsUnlock),
            }
        }
    })
}

/// Takes a newer account record, e.g. after a password change elsewhere.
fn follow_account(store: &Store, theirs: &AccountKeys, their_at: i64) -> Result<()> {
    if let Some((mine, my_at, _)) = store.account_change()? {
        if mine.account_id == theirs.account_id && their_at > my_at {
            store.set_account(theirs, their_at, false)?;
        }
    }
    Ok(())
}

/// The first device: creates the account around this device's vault key, or
/// a new one when there is no vault yet.
async fn setup(
    remote: &Remote,
    store: &Store,
    secrets: &dyn SecretStore,
    password: &str,
) -> Result<HistoryKeys> {
    vault::check_password(password)?;
    if remote.account().await?.is_some() {
        bail!("another device has already set up sync; unlock it with the master password");
    }
    if store.legacy_vault()?.is_some() {
        bail!("this device's vault is in the old format; unlock it once or reset it first");
    }
    let dek = match store.vault_key()? {
        Some(row) => vault::unwrap(&row, password)?
            .ok_or_else(|| anyhow!("use the vault's master password, or reset the vault first"))?,
        None => Zeroizing::new(random::<32>()),
    };
    let (keys, history) = AccountKeys::create(password, &dek)?;
    let at = now_ms();
    if !remote.create_account(&keys, at).await? {
        bail!("another device set up sync at the same moment; unlock it instead");
    }
    store.set_account(&keys, at, false)?;
    keys.save_history(&history, secrets)?;
    Ok(history)
}

/// Any later device: unlocks the account and brings this device's own vault,
/// if it has one, under the account's key.
async fn unlock(
    remote: &Remote,
    store: &Store,
    secrets: &dyn SecretStore,
    password: &str,
) -> Result<HistoryKeys> {
    let (theirs, at) =
        remote.account().await?.ok_or_else(|| anyhow!("sync has not been set up yet"))?;
    let history = theirs.unlock_history(password)?;
    let account_dek = vault::unwrap(&theirs.vault_key_row(), password)?
        .ok_or_else(|| anyhow!("wrong password"))?;

    let mine = store.account()?;
    let joining_same = mine.as_ref().is_some_and(|m| m.account_id == theirs.account_id);
    if !joining_same {
        if store.legacy_vault()?.is_some() {
            bail!("this device's vault is in the old format; unlock it once or reset it first");
        }
        if store.vault_count()? > 0 {
            let row = store.vault_key()?.expect("items imply a key");
            let own = vault::unwrap(&row, password)?.ok_or_else(|| {
                anyhow!(
                    "this device's own vault has a different password; \
                     change it to the master password first, or reset it"
                )
            })?;
            vault::reseal_items(store, &own, &account_dek)?;
        }
    }
    store.set_account(&theirs, at, false)?;
    theirs.save_history(&history, secrets)?;
    Ok(history)
}

fn short(e: &anyhow::Error) -> String {
    let s = format!("{e:#}");
    s.chars().take(200).collect()
}
