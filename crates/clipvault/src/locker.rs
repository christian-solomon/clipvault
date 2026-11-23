//! Locks the vault when the screen locks or the machine is about to sleep.
//!
//! Listens on D-Bus for GNOME's and freedesktop's screensaver signals on the
//! session bus, and logind's Lock and PrepareForSleep on the system bus. Each
//! is optional: a missing bus or service just means one trigger fewer.

use async_channel::Sender;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;
use zbus::MatchRule;

use crate::app::AppEvent;

struct Watch {
    system: bool,
    interface: &'static str,
    member: &'static str,
    /// Signals carrying a bool only lock on `true` (screen locked, going to
    /// sleep); `false` is the matching wake-up.
    bool_arg: bool,
    reason: &'static str,
}

const WATCHES: &[Watch] = &[
    Watch {
        system: false,
        interface: "org.gnome.ScreenSaver",
        member: "ActiveChanged",
        bool_arg: true,
        reason: "screen locked",
    },
    Watch {
        system: false,
        interface: "org.freedesktop.ScreenSaver",
        member: "ActiveChanged",
        bool_arg: true,
        reason: "screen locked",
    },
    Watch {
        system: true,
        interface: "org.freedesktop.login1.Session",
        member: "Lock",
        bool_arg: false,
        reason: "session locked",
    },
    Watch {
        system: true,
        interface: "org.freedesktop.login1.Manager",
        member: "PrepareForSleep",
        bool_arg: true,
        reason: "going to sleep",
    },
];

pub fn spawn(tx: Sender<AppEvent>) {
    for w in WATCHES {
        let tx = tx.clone();
        let _ = std::thread::Builder::new().name("vault-lock-signal".into()).spawn(move || {
            if let Err(e) = watch(w, &tx) {
                log::debug!("not watching {}.{}: {e}", w.interface, w.member);
            }
        });
    }
}

fn watch(w: &'static Watch, tx: &Sender<AppEvent>) -> zbus::Result<()> {
    let conn = if w.system { Connection::system()? } else { Connection::session()? };
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(w.interface)?
        .member(w.member)?
        .build();
    for msg in MessageIterator::for_match_rule(rule, &conn, Some(8))? {
        let msg = msg?;
        let fire = !w.bool_arg || msg.body().deserialize::<bool>().unwrap_or(false);
        if fire && tx.send_blocking(AppEvent::Lock(w.reason)).is_err() {
            break;
        }
    }
    Ok(())
}
