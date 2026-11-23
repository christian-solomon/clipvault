//! Tray icon over D-Bus StatusNotifierItem (Ubuntu's AppIndicator extension
//! shows these). Pure Rust; no GTK.

use async_channel::Sender;
use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};

use crate::app::AppEvent;

const ICON_PNG: &[u8] = include_bytes!("../../../assets/icons/32x32.png");

struct Tray {
    tx: Sender<AppEvent>,
    icon: Vec<ksni::Icon>,
}

impl Tray {
    fn send(&self, event: AppEvent) {
        let _ = self.tx.send_blocking(event);
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "clipvault".into()
    }

    fn title(&self) -> String {
        "ClipVault".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icon.clone()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(AppEvent::Toggle);
    }

    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        log::info!("no tray host right now; the icon appears when one starts");
        true
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open ClipVault".into(),
                activate: Box::new(|t: &mut Self| t.send(AppEvent::Show)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Lock vault".into(),
                activate: Box::new(|t: &mut Self| t.send(AppEvent::Lock("tray"))),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut Self| t.send(AppEvent::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// SNI wants ARGB32 in network byte order.
fn icon() -> Vec<ksni::Icon> {
    match clipvault_core::media::to_rgba(ICON_PNG) {
        Ok((w, h, rgba)) => {
            let data = rgba.chunks_exact(4).flat_map(|p| [p[3], p[0], p[1], p[2]]).collect();
            vec![ksni::Icon { width: w as i32, height: h as i32, data }]
        }
        Err(e) => {
            log::warn!("tray icon: {e}");
            Vec::new()
        }
    }
}

/// Starts the tray service. It registers whenever a StatusNotifier host
/// appears: at login the AppIndicator extension may start after autostart
/// apps, and GNOME disables it on the lock screen. Without one the app still
/// works through the hotkey and `clipvault ui`.
pub fn spawn(tx: Sender<AppEvent>) -> Option<ksni::blocking::Handle<impl ksni::Tray>> {
    match (Tray { tx, icon: icon() }).assume_sni_available(true).spawn() {
        Ok(handle) => Some(handle),
        Err(e) => {
            log::warn!("no tray icon ({e}); use the hotkey or `clipvault ui`");
            None
        }
    }
}
