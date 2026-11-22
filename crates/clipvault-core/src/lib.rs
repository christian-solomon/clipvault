//! Everything ClipVault does that is not drawing pixels: watching the X11
//! clipboard, keeping history in SQLite, and the encrypted vault.

pub mod account;
pub mod clipboard;
pub mod config;
mod crypto;
pub mod ephemeral;
pub mod harden;
pub mod ipc;
pub mod media;
pub mod recorder;
pub mod secrets;
pub mod store;
pub mod vault;
pub mod watcher;
