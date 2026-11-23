//! The global show/hide hotkey, grabbed on the X root window.

use async_channel::Sender;
use global_hotkey::hotkey::HotKey;
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};

use crate::app::AppEvent;

/// Registers `spec` (e.g. `super+v`) and forwards presses as `Toggle`.
/// Returns the manager, which must stay alive for the grab to last.
pub fn register(spec: &str, tx: Sender<AppEvent>) -> Option<GlobalHotKeyManager> {
    let hotkey: HotKey = match spec.parse() {
        Ok(h) => h,
        Err(e) => {
            log::warn!("CLIPVAULT_HOTKEY={spec:?} is not a valid hotkey ({e}); none registered");
            return None;
        }
    };
    let manager = match GlobalHotKeyManager::new() {
        Ok(m) => m,
        Err(e) => {
            log::warn!("global hotkeys unavailable: {e}");
            return None;
        }
    };
    if let Err(e) = manager.register(hotkey) {
        log::warn!(
            "could not grab {spec} ({e}); bind `clipvault ui` in your desktop's keyboard \
             settings, or open from the tray icon"
        );
        return None;
    }
    let id = hotkey.id();
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == id && event.state == HotKeyState::Pressed {
            let _ = tx.send_blocking(AppEvent::Toggle);
        }
    }));
    log::info!("listening for {spec}");
    Some(manager)
}
