//! Light or dark, from the desktop portal's `color-scheme` setting.
//!
//! GPUI reads this setting itself, but the portal refuses method calls from a
//! non-dumpable process (it cannot open `/proc/<pid>/root`). So the first value
//! is read here before hardening, and changes are followed through the
//! `SettingChanged` signal, which needs no such check.

use async_channel::Sender;
use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::message::Type;
use zbus::zvariant::{OwnedValue, Value};
use zbus::MatchRule;

use crate::app::AppEvent;

const DEST: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const IFACE: &str = "org.freedesktop.portal.Settings";
const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";

/// `Some(true)` for dark; `None` when no portal answers.
pub fn current() -> Option<bool> {
    match read() {
        Ok(dark) => Some(dark),
        Err(e) => {
            log::debug!("no colour scheme from the desktop portal: {e}");
            None
        }
    }
}

fn read() -> zbus::Result<bool> {
    let conn = Connection::session()?;
    let proxy = Proxy::new(&conn, DEST, PATH, IFACE)?;
    // `ReadOne` arrived in portal version 2; `Read` wraps the value in a
    // second variant.
    let value: OwnedValue = proxy
        .call("ReadOne", &(NAMESPACE, KEY))
        .or_else(|_| proxy.call("Read", &(NAMESPACE, KEY)))?;
    Ok(is_dark(&value))
}

/// The portal's scheme: 0 no preference, 1 dark, 2 light.
fn is_dark(value: &Value) -> bool {
    match value {
        Value::U32(scheme) => *scheme == 1,
        Value::Value(inner) => is_dark(inner),
        _ => false,
    }
}

pub fn spawn(tx: Sender<AppEvent>) {
    let _ = std::thread::Builder::new().name("colour-scheme".into()).spawn(move || {
        if let Err(e) = watch(&tx) {
            log::debug!("not following colour scheme changes: {e}");
        }
    });
}

fn watch(tx: &Sender<AppEvent>) -> zbus::Result<()> {
    let conn = Connection::session()?;
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(IFACE)?
        .member("SettingChanged")?
        .arg(0, NAMESPACE)?
        .arg(1, KEY)?
        .build();
    for msg in MessageIterator::for_match_rule(rule, &conn, Some(8))? {
        let msg = msg?;
        let Ok((_, _, value)) = msg.body().deserialize::<(String, String, OwnedValue)>() else {
            continue;
        };
        if tx.send_blocking(AppEvent::Appearance(is_dark(&value))).is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_scheme_one_is_dark() {
        assert!(is_dark(&Value::U32(1)));
        assert!(!is_dark(&Value::U32(0)));
        assert!(!is_dark(&Value::U32(2)));
        assert!(!is_dark(&Value::Str("prefer-dark".into())));
    }

    #[test]
    fn the_legacy_read_reply_is_unwrapped() {
        assert!(is_dark(&Value::Value(Box::new(Value::U32(1)))));
    }
}
