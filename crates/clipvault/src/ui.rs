//! The palette window: search on top, list on the left, preview on the right.

use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::{Button, ButtonVariant, ButtonVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::{
    h_flex, v_flex, ActiveTheme, Icon, IconName, Sizable, Theme, ThemeMode, WindowExt,
};
use gpui_kit_assets::IconName as AssetIcon;
use zeroize::Zeroizing;

use clipvault_core::vault::Status;

use crate::app::{AppState, Badge, Preview, RowId, Tab};
use crate::{theme, x11};

actions!(
    clipvault,
    [
        SelectPrev,
        SelectNext,
        Confirm,
        Hide,
        SwitchTab,
        TogglePin,
        MoveToVault,
        DeleteSelected,
        LockVault,
        Reveal,
        NewSecret,
    ]
);

const CONTEXT: &str = "ClipVault";
const ROW_HEIGHT: f32 = 46.;
const BLUR_GRACE: std::time::Duration = std::time::Duration::from_millis(300);

pub fn bind_keys(cx: &mut App) {
    // Each binding is repeated for "ClipVault > Input" so that it wins over
    // the text input's own binding for the same key while the search box or
    // a password field has focus.
    macro_rules! everywhere {
        ($keys:expr, $action:expr) => {
            [
                KeyBinding::new($keys, $action, Some(CONTEXT)),
                KeyBinding::new($keys, $action, Some("ClipVault > Input")),
            ]
        };
    }
    let mut bindings = Vec::new();
    bindings.extend(everywhere!("escape", Hide));
    bindings.extend(everywhere!("tab", SwitchTab));
    bindings.extend(everywhere!("up", SelectPrev));
    bindings.extend(everywhere!("down", SelectNext));
    bindings.extend(everywhere!("ctrl-p", TogglePin));
    bindings.extend(everywhere!("ctrl-s", MoveToVault));
    bindings.extend(everywhere!("shift-delete", DeleteSelected));
    bindings.extend(everywhere!("ctrl-l", LockVault));
    bindings.extend(everywhere!("ctrl-r", Reveal));
    bindings.extend(everywhere!("ctrl-n", NewSecret));
    // Enter copies in the lists but stays "submit" in password fields, which
    // sit deeper than the root and so keep their own binding.
    for ctx in ["History", "History > Input", "Vault"] {
        bindings.push(KeyBinding::new("enter", Confirm, Some(ctx)));
    }
    cx.bind_keys(bindings);
}

/// Follows the desktop's light or dark setting.
pub(crate) fn apply_theme(dark: Option<bool>, window: &mut Window, cx: &mut App) {
    match dark {
        Some(true) => Theme::change(ThemeMode::Dark, Some(window), cx),
        Some(false) => Theme::change(ThemeMode::Light, Some(window), cx),
        None => Theme::sync_system_appearance(Some(window), cx),
    }
    window.refresh();
}

fn with_article(noun: &str) -> String {
    let vowel = noun.chars().next().is_some_and(|c| "AEIOUaeiou".contains(c));
    format!("{} {noun}", if vowel { "an" } else { "a" })
}

/// A dialog builder runs on every rebuild and the dialog takes focus as it
/// opens, so its first field is focused from inside the builder, once.
fn focus_once() -> impl Fn(&Entity<InputState>, &mut Window, &mut App) {
    let pending = std::cell::Cell::new(true);
    move |field, window, cx| {
        if pending.replace(false) {
            field.update(cx, |s, cx| s.focus(window, cx));
        }
    }
}

/// Focuses the first empty field. Returns true when every field has a value,
/// so Enter walks through a form before it submits.
fn all_filled(fields: &[&Entity<InputState>], window: &mut Window, cx: &mut App) -> bool {
    for field in fields {
        if field.read(cx).value().is_empty() {
            // Deferred: the dialog settles its own focus after on_ok returns.
            let field = (*field).clone();
            window.defer(cx, move |window, cx| field.update(cx, |s, cx| s.focus(window, cx)));
            return false;
        }
    }
    true
}

pub struct Palette {
    state: Entity<AppState>,
    search: Entity<InputState>,
    password: Entity<InputState>,
    confirm: Entity<InputState>,
    focus: FocusHandle,
    list_scroll: UniformListScrollHandle,
    vault_scroll: UniformListScrollHandle,
    gate_error: Option<SharedString>,
    was_active: bool,
    pending_hide: Option<Task<()>>,
    last_status: Status,
    _subs: Vec<Subscription>,
}

impl Palette {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search =
            cx.new(|cx| InputState::new(window, cx).placeholder("Search clipboard history…"));
        let password =
            cx.new(|cx| InputState::new(window, cx).masked(true).placeholder("Master password"));
        let confirm =
            cx.new(|cx| InputState::new(window, cx).masked(true).placeholder("Confirm password"));

        let subs = vec![
            cx.subscribe_in(&search, window, |this, input, ev: &InputEvent, _, cx| {
                if let InputEvent::Change = ev {
                    let q = input.read(cx).value().to_string();
                    this.state.update(cx, |s, cx| s.set_query(q, cx));
                    this.list_scroll.scroll_to_item(0, ScrollStrategy::Top);
                }
            }),
            cx.subscribe_in(&password, window, |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit_gate(window, cx);
                }
            }),
            cx.subscribe_in(&confirm, window, |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit_gate(window, cx);
                }
            }),
            cx.observe_in(&state, window, |this, state, window, cx| {
                // Locked from elsewhere (timer, screen lock, tray): put the
                // cursor where the password goes.
                let (tab, status) = {
                    let s = state.read(cx);
                    (s.tab, s.vault_status)
                };
                if this.last_status == Status::Unlocked
                    && status == Status::Locked
                    && tab == Tab::Vault
                {
                    this.password.update(cx, |s, cx| s.focus(window, cx));
                }
                this.last_status = status;
                cx.notify();
            }),
            // A palette gets out of the way once you click elsewhere. Focus also
            // blinks away for a moment whenever the window manager's own key
            // grabs fire (GNOME's locate-pointer grabs Ctrl), so only a loss
            // that lasts counts, and none while a button is held: a title-bar
            // drag holds focus until it ends.
            cx.observe_window_activation(window, |this, window, cx| {
                if window.is_window_active() {
                    this.was_active = true;
                    this.pending_hide = None;
                } else if this.was_active {
                    this.pending_hide = Some(cx.spawn_in(window, async move |this, cx| {
                        cx.background_executor().timer(BLUR_GRACE).await;
                        while x11::button_held() {
                            cx.background_executor().timer(BLUR_GRACE / 3).await;
                        }
                        let _ = this.update_in(cx, |this, window, cx| {
                            if !window.is_window_active() && !window.has_active_dialog(cx) {
                                this.hide(window, cx);
                            }
                        });
                    }));
                }
            }),
            cx.observe_window_appearance(window, {
                let state = state.clone();
                move |_, window, cx| apply_theme(state.read(cx).dark, window, cx)
            }),
        ];

        apply_theme(state.read(cx).dark, window, cx);
        let st = state.clone();
        window.on_window_should_close(cx, move |window, cx| {
            let origin = x11::origin(window);
            st.update(cx, |s, _| s.on_hidden(origin));
            true
        });
        search.update(cx, |s, cx| s.focus(window, cx));

        Palette {
            state,
            search,
            password,
            confirm,
            focus: cx.focus_handle(),
            list_scroll: UniformListScrollHandle::new(),
            vault_scroll: UniformListScrollHandle::new(),
            gate_error: None,
            was_active: false,
            pending_hide: None,
            last_status: Status::Absent,
            _subs: subs,
        }
    }

    fn hide(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        log::debug!("hiding the window");
        self.clear_passwords(window, cx);
        let origin = x11::origin(window);
        self.state.update(cx, |s, _| s.on_hidden(origin));
        window.remove_window();
    }

    fn clear_passwords(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [&self.password, &self.confirm] {
            input.update(cx, |s, cx| s.set_value("", window, cx));
        }
    }

    fn toast(&self, window: &mut Window, cx: &mut App, msg: impl Into<SharedString>) {
        window.push_notification(msg.into(), cx);
    }

    fn tab(&self, cx: &App) -> Tab {
        self.state.read(cx).tab
    }

    // ---- actions ------------------------------------------------------------

    fn on_hide(&mut self, _: &Hide, window: &mut Window, cx: &mut Context<Self>) {
        self.hide(window, cx);
    }

    fn on_switch_tab(&mut self, _: &SwitchTab, window: &mut Window, cx: &mut Context<Self>) {
        let next = match self.tab(cx) {
            Tab::History => Tab::Vault,
            Tab::Vault => Tab::History,
        };
        self.set_tab(next, window, cx);
    }

    fn set_tab(&mut self, tab: Tab, window: &mut Window, cx: &mut Context<Self>) {
        self.state.update(cx, |s, cx| {
            s.tab = tab;
            s.refresh_vault();
            cx.notify();
        });
        self.focus_for_tab(window, cx);
    }

    fn focus_for_tab(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (tab, status) = {
            let s = self.state.read(cx);
            (s.tab, s.vault_status)
        };
        match (tab, status) {
            (Tab::History, _) => self.search.update(cx, |s, cx| s.focus(window, cx)),
            (Tab::Vault, Status::Unlocked) => window.focus(&self.focus, cx),
            (Tab::Vault, _) => self.password.update(cx, |s, cx| s.focus(window, cx)),
        }
    }

    fn on_prev(&mut self, _: &SelectPrev, _: &mut Window, cx: &mut Context<Self>) {
        self.step(-1, cx);
    }

    fn on_next(&mut self, _: &SelectNext, _: &mut Window, cx: &mut Context<Self>) {
        self.step(1, cx);
    }

    fn step(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.state.update(cx, |s, cx| s.move_selection(delta, cx));
        let s = self.state.read(cx);
        match s.tab {
            Tab::History => self.list_scroll.scroll_to_item(s.selected, ScrollStrategy::Nearest),
            Tab::Vault => {
                self.vault_scroll.scroll_to_item(s.vault_selected, ScrollStrategy::Nearest)
            }
        }
    }

    fn on_confirm(&mut self, _: &Confirm, window: &mut Window, cx: &mut Context<Self>) {
        match self.tab(cx) {
            Tab::History => match self.state.update(cx, |s, cx| s.copy_selected(cx)) {
                Ok(()) => self.hide(window, cx),
                Err(e) => self.toast(window, cx, format!("{e:#}")),
            },
            // In the gate, Enter belongs to the password field.
            Tab::Vault if self.state.read(cx).vault_unlocked() => self.copy_vault(window, cx),
            Tab::Vault => {}
        }
    }

    fn copy_vault(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.state.update(cx, |s, cx| s.vault_copy_selected(cx)) {
            Ok(()) => {
                let secs = self.state.read(cx).cfg.clipboard_clear.as_secs();
                let msg = if secs > 0 {
                    format!("Copied. Not saved to history; clears in {secs}s.")
                } else {
                    "Copied. Not saved to history.".into()
                };
                self.toast(window, cx, msg);
            }
            Err(e) => self.toast(window, cx, format!("{e:#}")),
        }
    }

    fn on_toggle_pin(&mut self, _: &TogglePin, window: &mut Window, cx: &mut Context<Self>) {
        if self.tab(cx) != Tab::History {
            return;
        }
        let row = self.state.read(cx).selected_row().cloned();
        match row.map(|r| r.id) {
            Some(RowId::Sensitive(id)) => self.ask_keep_sensitive(id, window, cx),
            Some(RowId::Entry(_)) => {
                if let Err(e) = self.state.update(cx, |s, cx| s.toggle_pin(cx)) {
                    self.toast(window, cx, format!("{e:#}"));
                }
            }
            None => {}
        }
    }

    /// Pinning a memory-only clip means writing it to disk; say so first.
    fn ask_keep_sensitive(&mut self, id: u64, window: &mut Window, cx: &mut Context<Self>) {
        let state = self.state.clone();
        window.open_alert_dialog(cx, move |alert, _, _| {
            let state = state.clone();
            alert
                .confirm()
                .title(theme::heading("Keep this in history?"))
                .description(
                    "It looks like a credential. History is stored unencrypted on disk. \
                     Ctrl+S moves it into the vault instead.",
                )
                .ok_text("Keep in plaintext history")
                .on_ok(move |_, window, cx| {
                    if let Err(e) = state.update(cx, |s, cx| s.keep_sensitive(id, cx)) {
                        window.push_notification(format!("{e:#}"), cx);
                    }
                    true
                })
        });
    }

    fn on_move_to_vault(&mut self, _: &MoveToVault, window: &mut Window, cx: &mut Context<Self>) {
        if self.tab(cx) != Tab::History {
            return;
        }
        let (row, unlocked, status) = {
            let s = self.state.read(cx);
            (s.selected_row().cloned(), s.vault_unlocked(), s.vault_status)
        };
        let Some(row) = row else { return };
        if row.image {
            self.toast(window, cx, "The vault holds text, not images");
            return;
        }
        if !unlocked {
            let msg = if status == Status::Absent {
                "Create the vault first"
            } else {
                "Unlock the vault first"
            };
            self.toast(window, cx, msg);
            self.set_tab(Tab::Vault, window, cx);
            return;
        }
        let suggestion = self.state.read(cx).suggested_label(row.id);
        let label = cx.new(|cx| InputState::new(window, cx).default_value(suggestion));
        let state = self.state.clone();
        let first = focus_once();
        window.open_alert_dialog(cx, move |alert, window, cx| {
            first(&label, window, cx);
            let (state, label) = (state.clone(), label.clone());
            alert
                .confirm()
                .title(theme::heading("Move into the vault"))
                .description(
                    v_flex()
                        .gap_2()
                        .child("The entry is encrypted, and its plaintext copy is deleted.")
                        .child(Input::new(&label)),
                )
                .ok_text("Move")
                .on_ok(move |_, window, cx| {
                    if !all_filled(&[&label], window, cx) {
                        return false;
                    }
                    let name = label.read(cx).value().to_string();
                    match state.update(cx, |s, cx| s.move_to_vault(row.id, &name, cx)) {
                        Ok(()) => {
                            window.push_notification("Moved into the vault", cx);
                            true
                        }
                        Err(e) => {
                            window.push_notification(format!("{e:#}"), cx);
                            false
                        }
                    }
                })
        });
    }

    fn on_delete(&mut self, _: &DeleteSelected, window: &mut Window, cx: &mut Context<Self>) {
        match self.tab(cx) {
            Tab::History => {
                let Some(row) = self.state.read(cx).selected_row().cloned() else {
                    return;
                };
                let what: SharedString = if row.image {
                    "this image".into()
                } else {
                    format!("\"{}\"", row.title.chars().take(60).collect::<String>()).into()
                };
                let state = self.state.clone();
                window.open_alert_dialog(cx, move |alert, _, _| {
                    let state = state.clone();
                    alert
                        .confirm()
                        .title(theme::heading("Delete from history?"))
                        .description(format!("Delete {what}? This cannot be undone."))
                        .ok_text("Delete")
                        .ok_variant(ButtonVariant::Danger)
                        .on_ok(move |_, window, cx| {
                            if let Err(e) = state.update(cx, |s, cx| s.delete_row(row.id, cx)) {
                                window.push_notification(format!("{e:#}"), cx);
                            }
                            true
                        })
                });
            }
            Tab::Vault => {
                let Some(item) = self.state.read(cx).selected_vault_item().cloned() else {
                    return;
                };
                let state = self.state.clone();
                window.open_alert_dialog(cx, move |alert, _, _| {
                    let (state, item) = (state.clone(), item.clone());
                    alert
                        .confirm()
                        .title(theme::heading("Delete from the vault?"))
                        .description(format!("Delete \"{}\"? This cannot be undone.", item.label))
                        .ok_text("Delete")
                        .ok_variant(ButtonVariant::Danger)
                        .on_ok(move |_, window, cx| {
                            if let Err(e) = state.update(cx, |s, cx| s.vault_delete(item.id, cx)) {
                                window.push_notification(format!("{e:#}"), cx);
                            }
                            true
                        })
                });
            }
        }
    }

    fn on_lock(&mut self, _: &LockVault, window: &mut Window, cx: &mut Context<Self>) {
        self.state.update(cx, |s, cx| s.lock_vault(cx));
        if self.tab(cx) == Tab::Vault {
            self.focus_for_tab(window, cx);
        }
        self.toast(window, cx, "Vault locked");
    }

    fn on_reveal(&mut self, _: &Reveal, window: &mut Window, cx: &mut Context<Self>) {
        match self.tab(cx) {
            Tab::History => self.state.update(cx, |s, cx| s.toggle_show_sensitive(cx)),
            Tab::Vault => {
                if let Err(e) = self.state.update(cx, |s, cx| s.vault_toggle_reveal(cx)) {
                    self.toast(window, cx, format!("{e:#}"));
                }
            }
        }
    }

    fn on_new_secret(&mut self, _: &NewSecret, window: &mut Window, cx: &mut Context<Self>) {
        if !self.state.read(cx).vault_unlocked() {
            self.toast(window, cx, "Unlock the vault first");
            return;
        }
        let label = cx.new(|cx| InputState::new(window, cx).placeholder("Label, e.g. Staging DB"));
        let secret =
            cx.new(|cx| InputState::new(window, cx).masked(true).placeholder("Secret value"));
        let state = self.state.clone();
        let first = focus_once();
        window.open_alert_dialog(cx, move |alert, window, cx| {
            first(&label, window, cx);
            let (state, label, secret) = (state.clone(), label.clone(), secret.clone());
            alert
                .confirm()
                .title(theme::heading("New secret"))
                .description(
                    v_flex()
                        .gap_2()
                        .child(Input::new(&label).tab_index(0))
                        .child(Input::new(&secret).mask_toggle().tab_index(1)),
                )
                .ok_text("Save")
                .on_ok(move |_, window, cx| {
                    if !all_filled(&[&label, &secret], window, cx) {
                        return false;
                    }
                    let name = label.read(cx).value().to_string();
                    let value = Zeroizing::new(secret.read(cx).value().to_string());
                    match state.update(cx, |s, cx| s.vault_add(&name, &value, cx)) {
                        Ok(()) => {
                            secret.update(cx, |s, cx| s.set_value("", window, cx));
                            true
                        }
                        Err(e) => {
                            window.push_notification(format!("{e:#}"), cx);
                            false
                        }
                    }
                })
        });
    }

    fn change_password(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let make = |placeholder: &'static str, window: &mut Window, cx: &mut Context<Self>| {
            cx.new(|cx| InputState::new(window, cx).masked(true).placeholder(placeholder))
        };
        let current = make("Current password", window, cx);
        let new = make("New password", window, cx);
        let again = make("New password again", window, cx);
        let state = self.state.clone();
        let first = focus_once();
        window.open_alert_dialog(cx, move |alert, window, cx| {
            first(&current, window, cx);
            let (state, current, new, again) =
                (state.clone(), current.clone(), new.clone(), again.clone());
            alert
                .confirm()
                .title(theme::heading("Change master password"))
                .description(
                    v_flex()
                        .gap_2()
                        .child(Input::new(&current).tab_index(0))
                        .child(Input::new(&new).tab_index(1))
                        .child(Input::new(&again).tab_index(2)),
                )
                .ok_text("Change")
                .on_ok(move |_, window, cx| {
                    if !all_filled(&[&current, &new, &again], window, cx) {
                        return false;
                    }
                    let c = Zeroizing::new(current.read(cx).value().to_string());
                    let n = Zeroizing::new(new.read(cx).value().to_string());
                    let a = Zeroizing::new(again.read(cx).value().to_string());
                    for input in [&current, &new, &again] {
                        input.update(cx, |s, cx| s.set_value("", window, cx));
                    }
                    let task = state.update(cx, |s, cx| s.vault_change_password(c, n, a, cx));
                    window
                        .spawn(cx, async move |cx| {
                            let result = task.await;
                            let _ = cx.update(|window, cx| {
                                let msg = match result {
                                    Ok(()) => "Master password changed".to_string(),
                                    Err(e) => format!("Password not changed: {e:#}"),
                                };
                                window.push_notification(msg, cx);
                            });
                        })
                        .detach();
                    true
                })
        });
    }

    /// Unlock, or create the vault. The password is read once into a
    /// self-wiping string and the fields are emptied straight away; the KDF
    /// runs in the background.
    fn submit_gate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (creating, busy) = {
            let s = self.state.read(cx);
            (s.vault_status == Status::Absent, s.busy)
        };
        if busy {
            return;
        }
        let pw = Zeroizing::new(self.password.read(cx).value().to_string());
        let again = Zeroizing::new(self.confirm.read(cx).value().to_string());
        if pw.is_empty() {
            return;
        }
        if creating && again.is_empty() {
            self.confirm.update(cx, |s, cx| s.focus(window, cx));
            return;
        }
        self.clear_passwords(window, cx);
        self.gate_error = None;
        let task = self.state.update(cx, |s, cx| s.open_vault(pw, creating.then_some(again), cx));
        cx.spawn_in(window, async move |this, cx| {
            let result = task.await;
            let _ = this.update_in(cx, |this, window, cx| {
                match result {
                    Ok(()) => this.focus_for_tab(window, cx),
                    Err(e) => {
                        this.gate_error = Some(format!("{e:#}").into());
                        this.password.update(cx, |s, cx| s.focus(window, cx));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    // ---- rendering ----------------------------------------------------------

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let tab = self.tab(cx);
        let dark = theme.mode.is_dark();
        // shadcn's tabs: a muted track; the active tab is lifted out of it.
        let tab_button = |id: &'static str, label: &'static str, this_tab: Tab| {
            let active = tab == this_tab;
            div()
                .id(id)
                .px_2p5()
                .py_0p5()
                .rounded(theme.radius)
                .border_1()
                .border_color(gpui::transparent_black())
                .text_sm()
                .font_weight(FontWeight::MEDIUM)
                .cursor_pointer()
                .when(active, |d| {
                    d.bg(theme.tab_active)
                        .text_color(theme.tab_active_foreground)
                        .when(dark, |d| d.border_color(theme.input))
                        .when(!dark, |d| d.shadow_xs())
                })
                .when(!active, |d| {
                    d.text_color(theme.tab_foreground).hover(|d| d.text_color(theme.foreground))
                })
                .child(label)
                .on_click(
                    cx.listener(move |this, _, window, cx| this.set_tab(this_tab, window, cx)),
                )
        };
        h_flex()
            .gap_3()
            .px_3()
            .py_2()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex_1()
                    .when(tab == Tab::History, |d| {
                        d.child(Input::new(&self.search).cleanable(true).appearance(false))
                    })
                    .when(tab == Tab::Vault, |d| d.child(theme::heading("Vault").text_sm())),
            )
            .child(
                h_flex()
                    .p(px(3.))
                    .rounded(theme::radius_lg(theme))
                    .bg(theme.tab_bar_segmented)
                    .child(tab_button("tab-history", "History", Tab::History))
                    .child(tab_button("tab-vault", "Vault", Tab::Vault)),
            )
    }

    fn render_history(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let s = self.state.read(cx);
        let count = s.rows.len();
        let flagged = s.flagged;

        let list = if count == 0 {
            v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(if s.query().is_empty() {
                    "Nothing here yet. Copy something."
                } else {
                    "No matches."
                })
                .into_any_element()
        } else {
            uniform_list(
                "history",
                count,
                cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                    let theme = cx.theme().clone();
                    let s = this.state.read(cx);
                    range
                        .filter_map(|ix| s.rows.get(ix).cloned().map(|r| (ix, r)))
                        .map(|(ix, row)| {
                            let selected = ix == s.selected;
                            let badge = match row.badge {
                                Badge::Sensitive => Some(("memory only", theme.warning)),
                                Badge::Flagged => Some(("looks secret", theme.danger)),
                                Badge::Kept => Some(("kept secret", theme.warning)),
                                Badge::None => None,
                            };
                            // Shown on the selected or hovered row; a set pin always.
                            let action = |name: &'static str,
                                          icon: Icon,
                                          tip: &'static str,
                                          shown: bool,
                                          act: fn(&mut Self, &mut Window, &mut Context<Self>)| {
                                div()
                                    .when(!shown, |d| {
                                        d.invisible().group_hover("row", |s| s.visible())
                                    })
                                    .child(
                                        Button::new((name, ix))
                                            .ghost()
                                            .xsmall()
                                            .icon(icon)
                                            .tooltip(tip)
                                            .on_click(cx.listener(
                                                move |this, _: &ClickEvent, window, cx| {
                                                    cx.stop_propagation();
                                                    this.state.update(cx, |s, cx| s.select(ix, cx));
                                                    act(this, window, cx);
                                                },
                                            )),
                                    )
                            };
                            let pin_icon = if row.pinned {
                                Icon::new(IconName::StarFill).text_color(theme.warning)
                            } else {
                                Icon::new(IconName::Star)
                            };
                            let actions = h_flex()
                                .flex_none()
                                .child(action(
                                    "pin",
                                    pin_icon,
                                    if row.pinned { "Unpin (Ctrl+P)" } else { "Pin (Ctrl+P)" },
                                    selected || row.pinned,
                                    |this, window, cx| this.on_toggle_pin(&TogglePin, window, cx),
                                ))
                                .when(!row.image, |d| {
                                    d.child(action(
                                        "vault",
                                        Icon::new(AssetIcon::Lock),
                                        "Move into the vault (Ctrl+S)",
                                        selected,
                                        |this, window, cx| {
                                            this.on_move_to_vault(&MoveToVault, window, cx)
                                        },
                                    ))
                                })
                                .child(action(
                                    "delete",
                                    Icon::new(AssetIcon::Trash),
                                    "Delete (Shift+Delete)",
                                    selected,
                                    |this, window, cx| this.on_delete(&DeleteSelected, window, cx),
                                ));
                            h_flex()
                                .id(("row", ix))
                                .group("row")
                                .w_full()
                                .h(px(ROW_HEIGHT))
                                .pl_3()
                                .pr_1()
                                .gap_2()
                                .rounded(theme.radius)
                                .cursor_pointer()
                                .when(selected, |d| d.bg(theme.accent))
                                .when(!selected, |d| d.hover(|d| d.bg(theme.list_hover)))
                                .when_some(row.thumb.clone(), |d, thumb| {
                                    d.child(
                                        img(thumb)
                                            .h(px(32.))
                                            .w(px(48.))
                                            .rounded_sm()
                                            .object_fit(ObjectFit::Cover),
                                    )
                                })
                                .child(
                                    v_flex()
                                        .flex_1()
                                        .min_w_0()
                                        .child(
                                            div()
                                                .text_sm()
                                                .truncate()
                                                .when(row.image, |d| d.italic())
                                                .child(row.title.clone()),
                                        )
                                        .child(
                                            h_flex()
                                                .gap_2()
                                                .text_xs()
                                                .text_color(theme.muted_foreground)
                                                .when_some(badge, |d, (text, color)| {
                                                    d.child(theme::badge(
                                                        text,
                                                        color,
                                                        theme.mode.is_dark(),
                                                    ))
                                                })
                                                .child(row.meta.clone()),
                                        ),
                                )
                                .child(actions)
                                .on_click(cx.listener(move |this, ev: &ClickEvent, window, cx| {
                                    this.state.update(cx, |s, cx| s.select(ix, cx));
                                    if ev.click_count() >= 2 {
                                        this.on_confirm(&Confirm, window, cx);
                                    }
                                }))
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(&self.list_scroll)
            .flex_1()
            .p_1()
            .into_any_element()
        };

        v_flex()
            .size_full()
            .when(flagged > 0, |d| {
                d.child(
                    h_flex()
                        .gap_2()
                        .px_3()
                        .py_1p5()
                        .bg(theme.danger.opacity(0.06))
                        .text_color(theme.danger)
                        .text_xs()
                        .child(div().flex_1().child(format!(
                            "{flagged} saved {} from before this update look like credentials.",
                            if flagged == 1 { "entry" } else { "entries" }
                        )))
                        .child(
                            Button::new("delete-flagged")
                                .danger()
                                .xsmall()
                                .label("Delete them")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    match this.state.update(cx, |s, cx| s.delete_flagged(cx)) {
                                        Ok(n) => this.toast(window, cx, format!("Deleted {n}")),
                                        Err(e) => this.toast(window, cx, format!("{e:#}")),
                                    }
                                })),
                        ),
                )
            })
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(v_flex().w(px(400.)).flex_none().h_full().overflow_hidden().child(list))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_hidden()
                            .border_l_1()
                            .border_color(theme.border)
                            .child(self.render_preview(cx)),
                    ),
            )
    }

    fn render_preview(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let s = self.state.read(cx);
        let meta = s.selected_row().map(|r| r.meta.clone());
        let body = match &s.preview {
            Preview::Empty => div().into_any_element(),
            Preview::Text { body, cut } => div()
                .id("preview-text")
                .flex_1()
                .overflow_y_scroll()
                .p_3()
                .font_family(theme.mono_font_family.clone())
                .text_size(theme.mono_font_size)
                .whitespace_normal()
                .child(body.clone())
                .when(*cut > 0, |d| {
                    d.child(
                        div()
                            .pt_2()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(format!("… {} more bytes, copied in full", cut)),
                    )
                })
                .into_any_element(),
            Preview::Image { image, width, height } => v_flex()
                .flex_1()
                .min_h_0()
                .p_3()
                .gap_2()
                .child(
                    div()
                        .flex_1()
                        .min_h_0()
                        .w_full()
                        .overflow_hidden()
                        .child(img(image.clone()).size_full().object_fit(ObjectFit::Contain)),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(format!("{width} × {height}")),
                )
                .into_any_element(),
            Preview::Masked { kind } => v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .gap_2()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(
                    div()
                        .text_color(theme.warning)
                        .child(format!("Looks like {}", with_article(kind))),
                )
                .child("Kept in memory only and never written to disk.")
                .child("Ctrl+S moves it into the vault · Ctrl+R shows it")
                .into_any_element(),
        };
        v_flex().size_full().min_h_0().child(body).when_some(meta, |d, meta| {
            d.child(
                div()
                    .px_3()
                    .py_1p5()
                    .border_t_1()
                    .border_color(theme.border)
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(meta),
            )
        })
    }

    fn render_vault(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let s = self.state.read(cx);
        match s.vault_status {
            Status::Absent | Status::Locked => {
                let creating = s.vault_status == Status::Absent;
                let count = s.vault_count;
                v_flex()
                    .size_full()
                    .items_center()
                    .justify_center()
                    .gap_3()
                    .child(
                        theme::heading(if creating {
                            "Create your vault"
                        } else {
                            "Unlock the vault"
                        })
                        .text_lg(),
                    )
                    .child(
                        div()
                            .max_w(px(420.))
                            .text_sm()
                            .text_center()
                            .text_color(theme.muted_foreground)
                            .child(if creating {
                                "Pick a master password. It is never stored, and there is no way \
                                 to recover the vault without it."
                                    .to_string()
                            } else {
                                format!(
                                    "{count} {} encrypted. Names stay hidden until you unlock.",
                                    if count == 1 { "secret" } else { "secrets" }
                                )
                            }),
                    )
                    .child(
                        v_flex()
                            .w(px(320.))
                            .gap_2()
                            .child(Input::new(&self.password).mask_toggle())
                            .when(creating, |d| d.child(Input::new(&self.confirm).mask_toggle()))
                            .child(
                                Button::new("gate-submit")
                                    .primary()
                                    .loading(s.busy)
                                    .label(match (s.busy, creating) {
                                        (true, true) => "Creating…",
                                        (true, false) => "Unlocking…",
                                        (false, true) => "Create vault",
                                        (false, false) => "Unlock",
                                    })
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.submit_gate(window, cx)
                                    })),
                            ),
                    )
                    .when_some(self.gate_error.clone(), |d, err| {
                        d.child(div().text_sm().text_color(theme.danger).child(err))
                    })
                    .into_any_element()
            }
            Status::Unlocked => {
                let count = s.vault_items.len();
                let left = s.vault_remaining().map(|d| d.as_secs()).unwrap_or(0);
                let list = if count == 0 {
                    v_flex()
                        .flex_1()
                        .items_center()
                        .justify_center()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child("The vault is empty. Ctrl+N adds a secret; Ctrl+S on a history entry moves it here.")
                        .into_any_element()
                } else {
                    uniform_list(
                        "vault",
                        count,
                        cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                            let theme = cx.theme().clone();
                            let s = this.state.read(cx);
                            range
                                .filter_map(|ix| s.vault_items.get(ix).cloned().map(|i| (ix, i)))
                                .map(|(ix, item)| {
                                    let selected = ix == s.vault_selected;
                                    let shown: SharedString = s
                                        .revealed(item.id)
                                        .map(|v| v.to_string())
                                        .unwrap_or_else(|| "••••••••".into())
                                        .into();
                                    h_flex()
                                        .id(("vault-row", ix))
                                        .w_full()
                                        .h(px(ROW_HEIGHT))
                                        .px_3()
                                        .gap_3()
                                        .rounded(theme.radius)
                                        .cursor_pointer()
                                        .when(selected, |d| d.bg(theme.accent))
                                        .when(!selected, |d| d.hover(|d| d.bg(theme.list_hover)))
                                        .child(
                                            div()
                                                .w(px(220.))
                                                .text_sm()
                                                .truncate()
                                                .child(item.label.clone()),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .truncate()
                                                .font_family(theme.mono_font_family.clone())
                                                .text_xs()
                                                .text_color(theme.muted_foreground)
                                                .child(shown),
                                        )
                                        .on_click(cx.listener(
                                            move |this, ev: &ClickEvent, window, cx| {
                                                this.state
                                                    .update(cx, |s, cx| s.select_vault(ix, cx));
                                                if ev.click_count() >= 2 {
                                                    this.copy_vault(window, cx);
                                                }
                                            },
                                        ))
                                })
                                .collect::<Vec<_>>()
                        }),
                    )
                    .track_scroll(&self.vault_scroll)
                    .flex_1()
                    .p_1()
                    .into_any_element()
                };
                v_flex()
                    .size_full()
                    .child(
                        h_flex()
                            .gap_2()
                            .px_3()
                            .py_1p5()
                            .border_b_1()
                            .border_color(theme.border)
                            .child(Button::new("vault-new").small().label("New secret").on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.on_new_secret(&NewSecret, window, cx)
                                }),
                            ))
                            .child(
                                Button::new("vault-password")
                                    .small()
                                    .ghost()
                                    .label("Change password")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.change_password(window, cx)
                                    })),
                            )
                            .child(
                                Button::new("vault-lock")
                                    .small()
                                    .ghost()
                                    .label("Lock now")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.on_lock(&LockVault, window, cx)
                                    })),
                            )
                            .child(div().flex_1())
                            .child(
                                div().text_xs().text_color(theme.muted_foreground).child(format!(
                                    "locks in {}:{:02}",
                                    left / 60,
                                    left % 60
                                )),
                            ),
                    )
                    .child(list)
                    .into_any_element()
            }
        }
    }

    fn render_footer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let hints: &[(&str, &str)] = match self.tab(cx) {
            Tab::History => &[
                ("↵", "copy"),
                ("^P", "pin"),
                ("^S", "to vault"),
                ("^R", "show"),
                ("⇧Del", "delete"),
                ("Tab", "vault"),
                ("Esc", "close"),
            ],
            Tab::Vault => &[
                ("↵", "copy"),
                ("^R", "reveal"),
                ("^N", "new"),
                ("^L", "lock"),
                ("⇧Del", "delete"),
                ("Tab", "history"),
                ("Esc", "close"),
            ],
        };
        h_flex()
            .gap_4()
            .px_3()
            .py_1p5()
            .border_t_1()
            .border_color(theme.border)
            .text_xs()
            .text_color(theme.muted_foreground)
            .children(hints.iter().map(|(k, v)| {
                h_flex()
                    .gap_1()
                    .child(
                        div()
                            .h(px(20.))
                            .min_w(px(20.))
                            .px_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(theme::radius_sm(theme))
                            .bg(theme.muted)
                            .font_weight(FontWeight::MEDIUM)
                            .child(*k),
                    )
                    .child(*v)
            }))
    }
}

impl Focusable for Palette {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Palette {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let tab = self.tab(cx);
        // The tab is part of the root's key context, so tab-specific bindings
        // also cover the search box in the header.
        let context = match tab {
            Tab::History => "ClipVault History",
            Tab::Vault => "ClipVault Vault",
        };
        v_flex()
            .key_context(context)
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::on_hide))
            .on_action(cx.listener(Self::on_switch_tab))
            .on_action(cx.listener(Self::on_prev))
            .on_action(cx.listener(Self::on_next))
            .on_action(cx.listener(Self::on_confirm))
            .on_action(cx.listener(Self::on_toggle_pin))
            .on_action(cx.listener(Self::on_move_to_vault))
            .on_action(cx.listener(Self::on_delete))
            .on_action(cx.listener(Self::on_lock))
            .on_action(cx.listener(Self::on_reveal))
            .on_action(cx.listener(Self::on_new_secret))
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(self.render_header(cx))
            .child(div().flex_1().min_h_0().map(|d| match tab {
                Tab::History => d.child(self.render_history(cx)),
                Tab::Vault => d.child(self.render_vault(cx)),
            }))
            .child(self.render_footer(cx))
    }
}
