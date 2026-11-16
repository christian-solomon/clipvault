//! Application state that outlives any one window.
//!
//! The window is created on show and destroyed on hide, so nothing here may
//! depend on a window existing. While hidden the app is the clipboard
//! recorder, the tray and a few timers, with no GPU surface.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use gpui::*;
use gpui_component::{Root, WindowExt};
use zeroize::Zeroizing;

use clipvault_core::clipboard::ClipboardWriter;
use clipvault_core::config::Config;
use clipvault_core::ephemeral::Ephemeral;
use clipvault_core::media::human_size;
use clipvault_core::recorder::Recorded;
use clipvault_core::store::{now, Sensitivity, Store};
use clipvault_core::vault::{Status, Vault, VaultItem};

use crate::ui::Palette;

/// Everything that reaches the UI thread from elsewhere.
pub enum AppEvent {
    Show,
    Toggle,
    Lock(&'static str),
    Recorded(Recorded),
    Quit,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    History,
    Vault,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowId {
    Entry(i64),
    /// A memory-only clip that looks like a credential.
    Sensitive(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Badge {
    None,
    /// Memory only, expiring.
    Sensitive,
    /// Found in old history by the upgrade scan.
    Flagged,
    /// A credential kept in history on purpose.
    Kept,
}

#[derive(Clone)]
pub struct Row {
    pub id: RowId,
    pub image: bool,
    pub title: SharedString,
    pub meta: SharedString,
    pub pinned: bool,
    pub badge: Badge,
    pub thumb: Option<Arc<Image>>,
    pub dims: (i64, i64),
}

#[derive(Clone)]
pub enum Preview {
    Empty,
    Text { body: SharedString, cut: usize },
    Image { image: Arc<Image>, width: i64, height: i64 },
    Masked { kind: &'static str },
}

/// Text longer than this is cut in the preview pane (it is still copied whole).
const PREVIEW_LIMIT: usize = 64 * 1024;
const LIST_LIMIT: i64 = 300;
/// A revealed vault secret hides itself after this long.
const REVEAL_FOR: Duration = Duration::from_secs(10);

pub struct AppState {
    pub cfg: Config,
    store: Arc<Mutex<Store>>,
    ephemeral: Arc<Mutex<Ephemeral>>,
    /// Shared with background tasks, which run the password KDF off the UI
    /// thread.
    vault: Arc<Mutex<Vault>>,
    /// A KDF is running; the gate shows progress instead of accepting input.
    pub busy: bool,
    clipboard: Option<ClipboardWriter>,

    pub window: Option<WindowHandle<Root>>,
    pub tab: Tab,
    query: String,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub preview: Preview,
    /// Show the selected memory-only clip instead of its mask.
    pub show_sensitive: bool,
    pub flagged: usize,

    pub vault_status: Status,
    pub vault_count: usize,
    pub vault_items: Vec<VaultItem>,
    pub vault_selected: usize,
    revealed: Option<(i64, Zeroizing<String>)>,

    /// The memory-only clip last announced, so a re-copy does not toast again.
    announced: Option<u64>,
    thumbs: HashMap<i64, Arc<Image>>,
    preview_image: Option<Arc<Image>>,
    clear_task: Option<Task<()>>,
    reveal_task: Option<Task<()>>,
    _ticker: Task<()>,
}

impl AppState {
    pub fn new(
        cfg: Config,
        store: Arc<Mutex<Store>>,
        ephemeral: Arc<Mutex<Ephemeral>>,
        clipboard: Option<ClipboardWriter>,
        cx: &mut Context<Self>,
    ) -> Self {
        // One timer drives expiry, auto-lock and the visible countdowns.
        let ticker = cx.spawn(async move |this, cx| loop {
            cx.background_executor().timer(Duration::from_secs(1)).await;
            if this.update(cx, |s, cx| s.tick(cx)).is_err() {
                break;
            }
        });
        let mut s = AppState {
            cfg,
            store,
            ephemeral,
            vault: Arc::new(Mutex::new(Vault::default())),
            busy: false,
            clipboard,
            window: None,
            tab: Tab::History,
            query: String::new(),
            rows: Vec::new(),
            selected: 0,
            preview: Preview::Empty,
            show_sensitive: false,
            flagged: 0,
            vault_status: Status::Absent,
            vault_count: 0,
            vault_items: Vec::new(),
            vault_selected: 0,
            revealed: None,
            announced: None,
            thumbs: HashMap::new(),
            preview_image: None,
            clear_task: None,
            reveal_task: None,
            _ticker: ticker,
        };
        s.refresh_vault();
        s
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let expired = self.ephemeral.lock().unwrap().expire();
        // try_lock: a KDF may be running on a background thread.
        let locked = match self.vault.try_lock() {
            Ok(mut v) => v.lock_if_idle(self.cfg.autolock),
            Err(_) => false,
        };
        if locked {
            log::info!("vault auto-locked after {:?} idle", self.cfg.autolock);
            self.after_lock(cx);
            self.toast(cx, "Vault locked after inactivity");
        }
        if expired && self.window.is_some() {
            self.refresh(cx);
        }
        // Countdowns on screen: memory-only clips and the vault timer.
        let counting =
            self.vault_unlocked() || self.rows.iter().any(|r| r.badge == Badge::Sensitive);
        if self.window.is_some() && counting {
            cx.notify();
        }
    }

    /// Shows a toast in the window, if there is one.
    pub fn toast(&self, cx: &mut App, message: impl Into<SharedString>) {
        let message = message.into();
        // update_window, not h.update: the notification layer reads the Root
        // entity, which h.update would hold leased.
        if let Some(h) = self.window {
            let _ =
                cx.update_window(h.into(), |_, window, cx| window.push_notification(message, cx));
        }
    }

    // ---- history ----------------------------------------------------------

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn set_query(&mut self, query: String, cx: &mut Context<Self>) {
        if query != self.query {
            self.query = query;
            self.selected = 0;
            self.refresh(cx);
        }
    }

    /// Rebuilds the visible rows from the store and the memory-only list.
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        let q = self.query.trim().to_lowercase();
        let mut rows = Vec::new();

        for c in self.ephemeral.lock().unwrap().items() {
            if !q.is_empty()
                && !c.text.to_lowercase().contains(&q)
                && !c.kind.describe().contains(&q)
            {
                continue;
            }
            let left = c.remaining().as_secs();
            rows.push(Row {
                id: RowId::Sensitive(c.id),
                image: false,
                title: format!("{} · {} characters", c.kind.describe(), c.text.chars().count())
                    .into(),
                meta: format!("{}:{:02} left", left / 60, left % 60).into(),
                pinned: false,
                badge: Badge::Sensitive,
                thumb: None,
                dims: (0, 0),
            });
        }

        let entries = match self.store.lock().unwrap().list(&self.query, LIST_LIMIT) {
            Ok(e) => e,
            Err(e) => {
                log::error!("listing history: {e:#}");
                Vec::new()
            }
        };
        let mut live = std::collections::HashSet::new();
        for e in entries {
            live.insert(e.id);
            let image = e.kind == "image";
            let thumb = match (&e.thumb, image) {
                (Some(bytes), true) => Some(
                    self.thumbs
                        .entry(e.id)
                        .or_insert_with(|| {
                            Arc::new(Image::from_bytes(ImageFormat::Png, bytes.clone()))
                        })
                        .clone(),
                ),
                _ => None,
            };
            let mut meta = format!("{} · {}", human_size(e.bytes as usize), ago(e.last_used_at));
            if e.use_count > 0 {
                meta.push_str(&format!(" · used {}×", e.use_count + 1));
            }
            rows.push(Row {
                id: RowId::Entry(e.id),
                image,
                title: if e.truncated {
                    format!("{}…", e.preview).into()
                } else {
                    e.preview.into()
                },
                meta: meta.into(),
                pinned: e.pinned,
                badge: match e.sensitivity {
                    Sensitivity::None => Badge::None,
                    Sensitivity::Flagged => Badge::Flagged,
                    Sensitivity::Kept => Badge::Kept,
                },
                thumb,
                dims: (e.width.unwrap_or(0), e.height.unwrap_or(0)),
            });
        }
        // Thumbnails of rows that left the list are dropped from GPUI's cache.
        let gone: Vec<i64> = self.thumbs.keys().copied().filter(|id| !live.contains(id)).collect();
        for id in gone {
            if let Some(img) = self.thumbs.remove(&id) {
                img.remove_asset(cx);
            }
        }

        self.rows = rows;
        self.flagged = self.store.lock().unwrap().flagged_count().unwrap_or(0);
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
        self.load_preview(cx);
        cx.notify();
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn select(&mut self, ix: usize, cx: &mut Context<Self>) {
        if ix < self.rows.len() && ix != self.selected {
            self.selected = ix;
            self.show_sensitive = false;
            self.load_preview(cx);
            cx.notify();
        }
    }

    pub fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        match self.tab {
            Tab::History => {
                if self.rows.is_empty() {
                    return;
                }
                let ix = (self.selected as isize + delta).clamp(0, self.rows.len() as isize - 1);
                self.select(ix as usize, cx);
            }
            Tab::Vault => {
                if self.vault_items.is_empty() {
                    return;
                }
                let ix = (self.vault_selected as isize + delta)
                    .clamp(0, self.vault_items.len() as isize - 1);
                if ix as usize != self.vault_selected {
                    self.vault_selected = ix as usize;
                    self.revealed = None;
                    cx.notify();
                }
            }
        }
    }

    fn load_preview(&mut self, cx: &mut Context<Self>) {
        if let Some(old) = self.preview_image.take() {
            old.remove_asset(cx);
        }
        let Some(row) = self.rows.get(self.selected) else {
            self.preview = Preview::Empty;
            return;
        };
        self.preview = match row.id {
            RowId::Sensitive(id) => {
                let eph = self.ephemeral.lock().unwrap();
                match eph.get(id) {
                    Some(c) if self.show_sensitive => {
                        Preview::Text { body: c.text.as_str().to_string().into(), cut: 0 }
                    }
                    Some(c) => Preview::Masked { kind: c.kind.describe() },
                    None => Preview::Empty,
                }
            }
            RowId::Entry(id) if row.image => {
                let (w, h) = row.dims;
                match self.store.lock().unwrap().image_png(id) {
                    Ok(Some(png)) => {
                        let image = Arc::new(Image::from_bytes(ImageFormat::Png, png));
                        self.preview_image = Some(image.clone());
                        Preview::Image { image, width: w, height: h }
                    }
                    _ => Preview::Empty,
                }
            }
            RowId::Entry(id) => match self.store.lock().unwrap().content(id) {
                Ok(Some(text)) => {
                    let cut = text.len().saturating_sub(PREVIEW_LIMIT);
                    let mut end = text.len().min(PREVIEW_LIMIT);
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    Preview::Text { body: text[..end].to_string().into(), cut }
                }
                _ => Preview::Empty,
            },
        };
    }

    pub fn toggle_show_sensitive(&mut self, cx: &mut Context<Self>) {
        if matches!(self.selected_row(), Some(Row { id: RowId::Sensitive(_), .. })) {
            self.show_sensitive = !self.show_sensitive;
            self.load_preview(cx);
            cx.notify();
        }
    }

    /// Copies the selected row. Memory-only clips go back out the way vault
    /// secrets do: hidden from clipboard managers and cleared later.
    pub fn copy_selected(&mut self, cx: &mut Context<Self>) -> Result<()> {
        let row = self.selected_row().cloned().ok_or_else(|| anyhow!("nothing selected"))?;
        let clipboard =
            self.clipboard.as_mut().ok_or_else(|| anyhow!("no clipboard connection"))?;
        match row.id {
            RowId::Sensitive(id) => {
                let text = Zeroizing::new(
                    self.ephemeral
                        .lock()
                        .unwrap()
                        .get(id)
                        .map(|c| c.text.as_str().to_string())
                        .ok_or_else(|| anyhow!("that clip has expired"))?,
                );
                clipboard.copy_secret(&text, self.cfg.clipboard_clear)?;
                self.schedule_clear(cx);
            }
            RowId::Entry(id) => {
                let store = self.store.lock().unwrap();
                if row.image {
                    let png = store.image_png(id)?.ok_or_else(|| anyhow!("image is missing"))?;
                    clipboard.copy_image(&png)?;
                } else {
                    let text =
                        store.content(id)?.ok_or_else(|| anyhow!("entry no longer exists"))?;
                    clipboard.copy_text(&text)?;
                }
                store.mark_used(id)?;
            }
        }
        Ok(())
    }

    pub fn toggle_pin(&mut self, cx: &mut Context<Self>) -> Result<()> {
        let Some(row) = self.selected_row().cloned() else {
            return Ok(());
        };
        if let RowId::Entry(id) = row.id {
            self.store.lock().unwrap().set_pinned(id, !row.pinned)?;
            self.refresh(cx);
        }
        Ok(())
    }

    /// Stores a memory-only clip in plaintext history, because the user said so.
    pub fn keep_sensitive(&mut self, id: u64, cx: &mut Context<Self>) -> Result<()> {
        let text = self
            .ephemeral
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| anyhow!("that clip has expired"))?;
        self.store.lock().unwrap().keep_sensitive(&text)?;
        self.refresh(cx);
        Ok(())
    }

    pub fn delete_row(&mut self, id: RowId, cx: &mut Context<Self>) -> Result<()> {
        match id {
            RowId::Entry(id) => self.store.lock().unwrap().delete(id)?,
            RowId::Sensitive(id) => {
                self.ephemeral.lock().unwrap().remove(id);
            }
        }
        self.refresh(cx);
        Ok(())
    }

    pub fn delete_flagged(&mut self, cx: &mut Context<Self>) -> Result<usize> {
        let n = self.store.lock().unwrap().delete_flagged()?;
        self.refresh(cx);
        Ok(n)
    }

    /// Suggested label when moving a row into the vault.
    pub fn suggested_label(&self, id: RowId) -> String {
        match id {
            RowId::Sensitive(id) => self
                .ephemeral
                .lock()
                .unwrap()
                .get(id)
                .map(|c| c.kind.describe().to_string())
                .unwrap_or_default(),
            RowId::Entry(_) => self
                .rows
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.title.chars().take(40).collect())
                .unwrap_or_default(),
        }
    }

    pub fn move_to_vault(&mut self, id: RowId, label: &str, cx: &mut Context<Self>) -> Result<()> {
        if !self.vault_unlocked() {
            bail!("unlock the vault first");
        }
        let store = self.store.lock().unwrap();
        match id {
            RowId::Entry(id) => {
                self.vault.lock().unwrap().absorb(&store, id, label)?;
            }
            RowId::Sensitive(id) => {
                let text = self
                    .ephemeral
                    .lock()
                    .unwrap()
                    .get(id)
                    .map(|c| Zeroizing::new(c.text.as_str().to_string()))
                    .ok_or_else(|| anyhow!("that clip has expired"))?;
                self.vault.lock().unwrap().add(&store, label, &text)?;
                self.ephemeral.lock().unwrap().remove(id);
            }
        }
        drop(store);
        self.refresh(cx);
        self.refresh_vault();
        Ok(())
    }

    // ---- vault ------------------------------------------------------------

    /// From the cached status, so rendering never waits on a running KDF.
    pub fn vault_unlocked(&self) -> bool {
        self.vault_status == Status::Unlocked
    }

    pub fn vault_remaining(&self) -> Option<Duration> {
        self.vault.try_lock().ok()?.remaining(self.cfg.autolock)
    }

    pub fn refresh_vault(&mut self) {
        if self.busy {
            return;
        }
        let store = self.store.lock().unwrap();
        let vault = self.vault.lock().unwrap();
        self.vault_status = vault.status(&store).unwrap_or(Status::Absent);
        self.vault_count = Vault::count(&store).unwrap_or(0);
        self.vault_items = if vault.is_unlocked() {
            vault.items(&store).unwrap_or_else(|e| {
                log::error!("listing the vault: {e:#}");
                Vec::new()
            })
        } else {
            Vec::new()
        };
        if self.vault_selected >= self.vault_items.len() {
            self.vault_selected = self.vault_items.len().saturating_sub(1);
        }
    }

    /// Creates the vault (`confirm` is `Some`) or unlocks it, running the
    /// deliberately slow KDF on a background thread.
    pub fn open_vault(
        &mut self,
        password: Zeroizing<String>,
        confirm: Option<Zeroizing<String>>,
        cx: &mut Context<Self>,
    ) -> Task<Result<()>> {
        let (vault, db) = (self.vault.clone(), self.cfg.db_path());
        self.busy = true;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    // Its own connection, so history keeps working meanwhile.
                    let store = Store::open(&db)?;
                    let mut vault = vault.lock().unwrap();
                    match confirm {
                        Some(again) if *again != *password => bail!("the passwords do not match"),
                        Some(_) => vault.init(&store, &password),
                        None => vault.unlock(&store, &password),
                    }
                })
                .await;
            this.update(cx, |s, cx| {
                s.busy = false;
                s.refresh_vault();
                cx.notify();
            })?;
            result
        })
    }

    pub fn lock_vault(&mut self, cx: &mut Context<Self>) {
        let was_open = {
            let mut vault = self.vault.lock().unwrap();
            let open = vault.is_unlocked();
            vault.lock();
            open
        };
        if was_open {
            self.after_lock(cx);
        }
    }

    fn after_lock(&mut self, cx: &mut Context<Self>) {
        self.revealed = None;
        self.reveal_task = None;
        self.refresh_vault();
        cx.notify();
    }

    pub fn selected_vault_item(&self) -> Option<&VaultItem> {
        self.vault_items.get(self.vault_selected)
    }

    pub fn select_vault(&mut self, ix: usize, cx: &mut Context<Self>) {
        if ix < self.vault_items.len() && ix != self.vault_selected {
            self.vault_selected = ix;
            self.revealed = None;
            cx.notify();
        }
    }

    pub fn revealed(&self, id: i64) -> Option<&str> {
        self.revealed.as_ref().filter(|(rid, _)| *rid == id).map(|(_, s)| s.as_str())
    }

    pub fn vault_copy_selected(&mut self, cx: &mut Context<Self>) -> Result<()> {
        let id =
            self.selected_vault_item().map(|i| i.id).ok_or_else(|| anyhow!("nothing selected"))?;
        let store = self.store.lock().unwrap();
        let secret = self.vault.lock().unwrap().reveal(&store, id)?;
        drop(store);
        self.clipboard
            .as_mut()
            .ok_or_else(|| anyhow!("no clipboard connection"))?
            .copy_secret(&secret, self.cfg.clipboard_clear)?;
        self.schedule_clear(cx);
        Ok(())
    }

    pub fn vault_toggle_reveal(&mut self, cx: &mut Context<Self>) -> Result<()> {
        let id =
            self.selected_vault_item().map(|i| i.id).ok_or_else(|| anyhow!("nothing selected"))?;
        if self.revealed(id).is_some() {
            self.revealed = None;
            self.reveal_task = None;
        } else {
            let store = self.store.lock().unwrap();
            let secret = self.vault.lock().unwrap().reveal(&store, id)?;
            drop(store);
            self.revealed = Some((id, secret));
            self.reveal_task = Some(cx.spawn(async move |this, cx| {
                cx.background_executor().timer(REVEAL_FOR).await;
                let _ = this.update(cx, |s, cx| {
                    s.revealed = None;
                    cx.notify();
                });
            }));
        }
        cx.notify();
        Ok(())
    }

    pub fn vault_add(&mut self, label: &str, secret: &str, cx: &mut Context<Self>) -> Result<()> {
        let store = self.store.lock().unwrap();
        self.vault.lock().unwrap().add(&store, label, secret)?;
        drop(store);
        self.refresh_vault();
        cx.notify();
        Ok(())
    }

    pub fn vault_delete(&mut self, id: i64, cx: &mut Context<Self>) -> Result<()> {
        let store = self.store.lock().unwrap();
        self.vault.lock().unwrap().delete(&store, id)?;
        drop(store);
        self.revealed = None;
        self.refresh_vault();
        cx.notify();
        Ok(())
    }

    pub fn vault_change_password(
        &mut self,
        current: Zeroizing<String>,
        new: Zeroizing<String>,
        again: Zeroizing<String>,
        cx: &mut Context<Self>,
    ) -> Task<Result<()>> {
        let (vault, db) = (self.vault.clone(), self.cfg.db_path());
        self.busy = true;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    if *new != *again {
                        bail!("the new passwords do not match");
                    }
                    let store = Store::open(&db)?;
                    let result = vault.lock().unwrap().change_password(&store, &current, &new);
                    result
                })
                .await;
            this.update(cx, |s, cx| {
                s.busy = false;
                cx.notify();
            })?;
            result
        })
    }

    /// Clears a copied secret from the clipboard after the configured delay,
    /// unless something else has been copied since.
    fn schedule_clear(&mut self, cx: &mut Context<Self>) {
        let after = self.cfg.clipboard_clear;
        if after.is_zero() {
            self.clear_task = None;
            return;
        }
        self.clear_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(after).await;
            let _ = this.update(cx, |s, _| {
                if let Some(cb) = s.clipboard.as_mut() {
                    match cb.clear_secret_if_unchanged() {
                        Ok(true) => log::info!("cleared a copied secret from the clipboard"),
                        Ok(false) => {}
                        Err(e) => log::warn!("could not clear the clipboard: {e:#}"),
                    }
                }
            });
        }));
    }

    // ---- window -------------------------------------------------------------

    /// Forgets anything that should not outlive the window being on screen.
    pub fn on_hidden(&mut self) {
        self.window = None;
        self.revealed = None;
        self.reveal_task = None;
        self.show_sensitive = false;
        self.query.clear();
        self.selected = 0;
        self.tab = Tab::History;
    }
}

pub fn ago(ts: i64) -> String {
    let s = (now() - ts).max(0);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", s / 60),
        3600..=86_399 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

// ---- show / hide -------------------------------------------------------------

pub fn show_window(state: &Entity<AppState>, cx: &mut App) {
    if let Some(h) = state.read(cx).window {
        if h.update(cx, |_, window, _| window.activate_window()).is_ok() {
            log::debug!("window already open; raised it");
            return;
        }
    }
    log::debug!("opening the window");
    state.update(cx, |s, cx| {
        s.refresh_vault();
        s.refresh(cx);
    });

    let options = WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(820.), px(540.)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some("ClipVault".into()),
            appears_transparent: true,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        focus: true,
        show: true,
        is_resizable: false,
        is_minimizable: false,
        app_id: Some("clipvault".into()),
        window_decorations: Some(WindowDecorations::Client),
        ..Default::default()
    };
    let st = state.clone();
    match cx.open_window(options, move |window, cx| {
        let view = cx.new(|cx| Palette::new(st.clone(), window, cx));
        cx.new(|cx| Root::new(view, window, cx))
    }) {
        Ok(h) => state.update(cx, |s, _| s.window = Some(h)),
        Err(e) => log::error!("could not open the window: {e:#}"),
    }
}

pub fn hide_window(state: &Entity<AppState>, cx: &mut App) {
    let handle = state.update(cx, |s, _| {
        let h = s.window;
        s.on_hidden();
        h
    });
    if let Some(h) = handle {
        let _ = h.update(cx, |_, window, _| window.remove_window());
    }
}

pub fn toggle_window(state: &Entity<AppState>, cx: &mut App) {
    let active = state
        .read(cx)
        .window
        .and_then(|h| h.update(cx, |_, window, _| window.is_window_active()).ok())
        .unwrap_or(false);
    if active {
        hide_window(state, cx);
    } else {
        show_window(state, cx);
    }
}

pub fn handle_event(state: &Entity<AppState>, event: AppEvent, cx: &mut App) {
    match event {
        AppEvent::Show => show_window(state, cx),
        AppEvent::Toggle => toggle_window(state, cx),
        AppEvent::Lock(reason) => state.update(cx, |s, cx| {
            if s.vault_unlocked() {
                log::info!("vault locked: {reason}");
                s.lock_vault(cx);
            }
        }),
        AppEvent::Recorded(recorded) => state.update(cx, |s, cx| {
            if s.window.is_some() {
                s.refresh(cx);
                if let Recorded::Sensitive(id) = recorded {
                    if s.announced.replace(id) != Some(id) {
                        s.toast(cx, "That copy looks like a credential: kept in memory only");
                    }
                }
            }
        }),
        AppEvent::Quit => cx.quit(),
    }
}
