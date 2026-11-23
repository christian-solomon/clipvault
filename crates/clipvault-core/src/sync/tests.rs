//! The engine against a throwaway single-node replica set of the local
//! `mongod`, two simulated devices sharing one database. Skipped when there
//! is no `mongod` on PATH.
//!
//! With `CLIPVAULT_TEST_MONGODB_URL` set they run against that cluster
//! instead. Each test then uses databases named `cvt_<random>_…`, dropped
//! when it ends.

use std::collections::HashMap;
use std::process::{Child, Command as Proc, Stdio};
use std::sync::Mutex;

use futures_util::TryStreamExt;
use mongodb::bson::Document;

use super::*;
use crate::store::tempdir::Dir;
use crate::store::Clip;
use crate::vault::Vault;

const PW: &str = "correct horse battery";

struct Mongo {
    /// The local `mongod`; `None` for a cluster named by URL.
    child: Option<Child>,
    url: String,
    prefix: String,
    _dir: Option<Dir>,
}

impl Mongo {
    fn db(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }
}

impl Drop for Mongo {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        // The test's runtime may be the one dropping this; use another.
        let (url, prefix) = (self.url.clone(), self.prefix.clone());
        let dropped = std::thread::spawn(move || {
            let prefix = prefix.as_str();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            rt.block_on(async {
                let client = Client::with_uri_str(&url).await?;
                for name in client.list_database_names().await? {
                    if name.starts_with(prefix) {
                        client.database(&name).drop().await?;
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("could not drop the {}* test databases", self.prefix);
        }
    }
}

async fn mongo() -> Option<Mongo> {
    if let Ok(url) = std::env::var("CLIPVAULT_TEST_MONGODB_URL") {
        let prefix = format!("cvt_{}_", crate::crypto::hex(&random::<3>()));
        return Some(Mongo { child: None, url, prefix, _dir: None });
    }
    if Proc::new("mongod").arg("--version").stdout(Stdio::null()).status().is_err() {
        eprintln!("skipping: no mongod on PATH");
        return None;
    }
    let dir = Dir::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let child = Proc::new("mongod")
        .args(["--replSet", "rs0", "--bind_ip", "127.0.0.1", "--nounixsocket", "--quiet"])
        .args(["--port", &port.to_string()])
        .arg("--dbpath")
        .arg(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The guard stops mongod however this function or the test ends.
    let guard = Mongo {
        child: Some(child),
        url: format!("mongodb://127.0.0.1:{port}/?directConnection=true"),
        prefix: String::new(),
        _dir: Some(dir),
    };
    let client = Client::with_uri_str(&guard.url).await.unwrap();
    let admin = client.database("admin");
    let mut ok = false;
    for _ in 0..100 {
        if admin.run_command(doc! { "ping": 1 }).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "mongod did not start");
    admin
        .run_command(doc! { "replSetInitiate": {
            "_id": "rs0", "members": [ { "_id": 0, "host": format!("127.0.0.1:{port}") } ]
        } })
        .await
        .unwrap();
    for _ in 0..100 {
        let hello = admin.run_command(doc! { "hello": 1 }).await.unwrap();
        if hello.get_bool("isWritablePrimary").unwrap_or(false) {
            return Some(guard);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("replica set did not elect a primary");
}

#[derive(Default)]
struct Keyring(Mutex<HashMap<String, Vec<u8>>>);

impl SecretStore for Keyring {
    fn get(&self, user: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(user).cloned())
    }
    fn set(&self, user: &str, secret: &[u8]) -> Result<()> {
        self.0.lock().unwrap().insert(user.into(), secret.to_vec());
        Ok(())
    }
    fn delete(&self, user: &str) -> Result<()> {
        self.0.lock().unwrap().remove(user);
        Ok(())
    }
}

struct Device {
    store: Store,
    keyring: Keyring,
    id: String,
    _dir: Dir,
}

fn device() -> Device {
    let dir = Dir::new();
    let store = Store::open(&dir.path().join("d.db")).unwrap();
    let id = store.device_id().unwrap();
    Device { store, keyring: Keyring::default(), id, _dir: dir }
}

async fn remote(m: &Mongo, db: &str) -> Remote {
    let r = Remote::new(Client::with_uri_str(&m.url).await.unwrap().database(&m.db(db)), "test device");
    r.ensure_indexes().await.unwrap();
    r
}

async fn sync(r: &Remote, d: &Device, keys: &HistoryKeys) -> (bool, Vec<Pulled>) {
    round(r, &d.store, keys, &d.id, true).await.unwrap()
}

fn texts(d: &Device) -> Vec<String> {
    let mut v: Vec<String> = d
        .store
        .list("", 100)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "text")
        .map(|e| d.store.content(e.id).unwrap().unwrap())
        .collect();
    v.sort();
    v
}

async fn all_docs(r: &Remote, coll: &str) -> Vec<Document> {
    r.db.collection::<Document>(coll).find(doc! {}).await.unwrap().try_collect().await.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn two_devices_share_history_images_and_the_vault() {
    let Some(m) = mongo().await else { return };
    let r = remote(&m, "two_devices").await;
    let (a, b) = (device(), device());

    // A sets up the account; B cannot sync until it unlocks.
    assert_eq!(ready(&r, &a.store, &a.keyring).await.unwrap().err(), Some(SyncStatus::NeedsSetup));
    let ka = setup(&r, &a.store, &a.keyring, PW).await.unwrap();
    assert_eq!(ready(&r, &b.store, &b.keyring).await.unwrap().err(), Some(SyncStatus::NeedsUnlock));
    assert!(unlock(&r, &b.store, &b.keyring, "not the password").await.is_err());
    let kb = unlock(&r, &b.store, &b.keyring, PW).await.unwrap();
    // Next start, both are ready from their keyrings alone.
    assert!(ready(&r, &a.store, &a.keyring).await.unwrap().is_ok());
    assert!(ready(&r, &b.store, &b.keyring).await.unwrap().is_ok());

    // Text and an image copied on A arrive on B, the text for its clipboard.
    a.store.record(&Clip::Text("hello from A".into())).unwrap();
    let png = {
        let mut img = image::RgbaImage::new(40, 30);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgba([x as u8 * 6, y as u8 * 8, 90, 255]);
        }
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    };
    let img = crate::media::prepare(&png).unwrap();
    let img_hash = img.hash.clone();
    a.store.record(&Clip::Image(img)).unwrap();
    sync(&r, &a, &ka).await;
    let (changed, pulled) = sync(&r, &b, &kb).await;
    assert!(changed);
    assert_eq!(texts(&b), ["hello from A"]);
    let b_img = b.store.list("", 10).unwrap().into_iter().find(|e| e.kind == "image").unwrap();
    let b_png = b.store.image_png(b_img.id).unwrap().unwrap();
    assert_eq!(crate::media::prepare(&b_png).unwrap().hash, img_hash, "same pixels");
    assert!(pulled
        .iter()
        .any(|p| matches!(p, Pulled::Text { text, .. } if **text == *"hello from A")));

    // Nothing readable reached the database.
    for coll in [remote::CLIPS, remote::VAULT, remote::KEYS, "images.chunks"] {
        for d in all_docs(&r, coll).await {
            let raw = d.to_vec().unwrap();
            assert!(!raw.windows(12).any(|w| w == b"hello from A"), "{coll} leaks text");
            assert!(!raw.windows(png.len().min(64)).any(|w| w == &png[..png.len().min(64)]));
        }
    }

    // A pin on B shows on A.
    let on_b = b.store.list("", 10).unwrap().into_iter().find(|e| e.kind == "text").unwrap();
    std::thread::sleep(Duration::from_millis(2));
    b.store.set_pinned(on_b.id, true).unwrap();
    sync(&r, &b, &kb).await;
    sync(&r, &a, &ka).await;
    assert!(a.store.list("", 10).unwrap().iter().any(|e| e.kind == "text" && e.pinned));

    // Deleting the image on A removes it, and its stored file, everywhere.
    let on_a = a.store.list("", 10).unwrap().into_iter().find(|e| e.kind == "image").unwrap();
    a.store.delete(on_a.id).unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    assert!(b.store.list("", 10).unwrap().iter().all(|e| e.kind != "image"));
    assert!(all_docs(&r, "images.files").await.is_empty());

    // A vault item added on A opens on B with the master password.
    let mut va = Vault::default();
    va.unlock(&a.store, PW).unwrap();
    va.add(&a.store, "db password", "s3cr3t-value").unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    let mut vb = Vault::default();
    vb.unlock(&b.store, PW).unwrap();
    let items = vb.items(&b.store).unwrap();
    assert_eq!(items[0].label, "db password");
    assert_eq!(&*vb.reveal(&b.store, items[0].id).unwrap(), "s3cr3t-value");

    // A password change on B carries to A; the history keeps syncing.
    vb.change_password(&b.store, PW, "a brand new password").unwrap();
    sync(&r, &b, &kb).await;
    sync(&r, &a, &ka).await;
    va.lock();
    assert!(va.unlock(&a.store, PW).is_err());
    va.unlock(&a.store, "a brand new password").unwrap();

    // Clearing on B empties A.
    b.store.clear(true).unwrap();
    sync(&r, &b, &kb).await;
    sync(&r, &a, &ka).await;
    assert!(a.store.list("", 10).unwrap().is_empty());
    assert_eq!(va.items(&a.store).unwrap().len(), 1, "the vault is not history");
}

#[tokio::test(flavor = "current_thread")]
async fn the_newer_change_wins_and_offline_devices_catch_up() {
    let Some(m) = mongo().await else { return };
    let r = remote(&m, "conflicts").await;
    let (a, b) = (device(), device());
    let ka = setup(&r, &a.store, &a.keyring, PW).await.unwrap();
    let kb = unlock(&r, &b.store, &b.keyring, PW).await.unwrap();

    let id_a = a.store.record(&Clip::Text("shared".into())).unwrap().unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    let id_b = b.store.list("", 10).unwrap()[0].id;

    // Both edit while apart; B's edit is later and wins on both.
    a.store.set_pinned(id_a, true).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    b.store.set_pinned(id_b, false).unwrap();
    b.store.mark_used(id_b).unwrap();
    sync(&r, &b, &kb).await;
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    assert!(!a.store.list("", 10).unwrap()[0].pinned);
    assert!(!b.store.list("", 10).unwrap()[0].pinned);

    // The same text copied on both before syncing becomes one clip.
    a.store.record(&Clip::Text("copied twice".into())).unwrap();
    b.store.record(&Clip::Text("copied twice".into())).unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    sync(&r, &a, &ka).await;
    assert_eq!(texts(&a), ["copied twice", "shared"]);
    assert_eq!(texts(&b), ["copied twice", "shared"]);
    assert_eq!(all_docs(&r, remote::CLIPS).await.len(), 2);

    // A device that was away for many changes gets all of them in one pull.
    for i in 0..30 {
        a.store.record(&Clip::Text(format!("while B was away {i}"))).unwrap();
    }
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    assert_eq!(texts(&b).len(), 32);
    assert_eq!(texts(&a), texts(&b));
}

#[tokio::test(flavor = "current_thread")]
async fn a_device_with_its_own_vault_joins_without_losing_it() {
    let Some(m) = mongo().await else { return };
    let r = remote(&m, "joining").await;
    let (a, b) = (device(), device());
    setup(&r, &a.store, &a.keyring, PW).await.unwrap();

    // B had a vault of its own, with the same password, before joining.
    let mut vb = Vault::default();
    vb.init(&b.store, PW).unwrap();
    vb.add(&b.store, "kept on B", "b-secret").unwrap();
    vb.lock();

    let kb = unlock(&r, &b.store, &b.keyring, PW).await.unwrap();
    vb.unlock(&b.store, PW).unwrap();
    let items = vb.items(&b.store).unwrap();
    assert_eq!(&*vb.reveal(&b.store, items[0].id).unwrap(), "b-secret");

    // And A can read it after a sync.
    sync(&r, &b, &kb).await;
    let ka = a.store.account().unwrap().unwrap().saved_history(&a.keyring).unwrap().unwrap();
    sync(&r, &a, &ka).await;
    let mut va = Vault::default();
    va.unlock(&a.store, PW).unwrap();
    let items = va.items(&a.store).unwrap();
    assert_eq!(items[0].label, "kept on B");
    assert_eq!(&*va.reveal(&a.store, items[0].id).unwrap(), "b-secret");
}

#[tokio::test(flavor = "current_thread")]
async fn setup_refuses_a_password_that_does_not_open_the_local_vault() {
    let Some(m) = mongo().await else { return };
    let r = remote(&m, "setup_guard").await;
    let a = device();
    let mut v = Vault::default();
    v.init(&a.store, PW).unwrap();
    assert!(setup(&r, &a.store, &a.keyring, "some other password").await.is_err());
    assert!(r.account().await.unwrap().is_none(), "nothing was created");
    setup(&r, &a.store, &a.keyring, PW).await.unwrap();
}

/// Waits for an event the predicate accepts.
fn wait_for(
    rx: &std::sync::mpsc::Receiver<SyncEvent>,
    secs: u64,
    mut pred: impl FnMut(&SyncEvent) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ev) if pred(&ev) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

fn synced(ev: &SyncEvent) -> bool {
    matches!(ev, SyncEvent::Status(SyncStatus::Synced { .. }))
}

#[tokio::test(flavor = "current_thread")]
async fn running_engines_wake_each_other_through_the_change_stream() {
    let Some(m) = mongo().await else { return };
    let (a, b) = (device(), device());
    let config = |d: &Device| SyncConfig {
        url: m.url.clone(),
        database: m.db("engines"),
        device_name: "engine".into(),
        db_path: d._dir.path().join("d.db"),
        limits: (500, i64::MAX),
        adopt: true,
    };
    let (ta, ra) = std::sync::mpsc::channel();
    let (tb, rb) = std::sync::mpsc::channel();
    let ha = spawn(config(&a), Box::new(Keyring::default()), move |e| {
        let _ = ta.send(e);
    })
    .unwrap();
    assert!(wait_for(&ra, 20, |e| matches!(e, SyncEvent::Status(SyncStatus::NeedsSetup))));
    ha.setup(Zeroizing::new(PW.into()));
    assert!(wait_for(&ra, 20, synced));

    let hb = spawn(config(&b), Box::new(Keyring::default()), move |e| {
        let _ = tb.send(e);
    })
    .unwrap();
    assert!(wait_for(&rb, 20, |e| matches!(e, SyncEvent::Status(SyncStatus::NeedsUnlock))));
    hb.unlock(Zeroizing::new("not the password".into()));
    assert!(wait_for(&rb, 20, |e| matches!(e, SyncEvent::Rejected(_))));
    hb.unlock(Zeroizing::new(PW.into()));
    assert!(wait_for(&rb, 20, synced));

    // Copied on A; B hears of it through the change stream, well inside the
    // 60 s poll, and is asked to put it on its clipboard.
    a.store.record(&Clip::Text("over the change stream".into())).unwrap();
    ha.changed();
    assert!(wait_for(&rb, 10, |e| matches!(
        e,
        SyncEvent::AdoptText { text, .. } if **text == *"over the change stream"
    )));
    assert!(texts(&b).contains(&"over the change stream".to_string()));
    drop(ha);
    drop(hb);
}

#[tokio::test(flavor = "current_thread")]
async fn a_forgotten_vault_password_resets_on_every_device_and_history_carries_on() {
    let Some(m) = mongo().await else { return };
    let r = remote(&m, "reset").await;
    let (a, b) = (device(), device());
    let ka = setup(&r, &a.store, &a.keyring, PW).await.unwrap();
    let kb = unlock(&r, &b.store, &b.keyring, PW).await.unwrap();
    let mut va = Vault::default();
    va.unlock(&a.store, PW).unwrap();
    va.add(&a.store, "old item", "old secret").unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;

    // The password is forgotten on A: reset, then start the vault over.
    va.reset(&a.store).unwrap();
    assert_eq!(va.status(&a.store).unwrap(), crate::vault::Status::Absent);
    assert!(va.unlock(&a.store, PW).is_err(), "the old password opens nothing now");
    va.init_synced(&a.store, "a fresh password", &a.keyring).unwrap();
    va.add(&a.store, "new item", "new secret").unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;

    // B follows: the old item is gone, the new password opens the new one.
    let mut vb = Vault::default();
    assert!(vb.unlock(&b.store, PW).is_err());
    vb.unlock(&b.store, "a fresh password").unwrap();
    let items = vb.items(&b.store).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(&*vb.reveal(&b.store, items[0].id).unwrap(), "new secret");

    // History keeps syncing on the keys both devices already hold.
    a.store.record(&Clip::Text("after the reset".into())).unwrap();
    sync(&r, &a, &ka).await;
    sync(&r, &b, &kb).await;
    assert!(texts(&b).contains(&"after the reset".to_string()));
    assert!(ready(&r, &b.store, &b.keyring).await.unwrap().is_ok(), "no new unlock needed");
}
