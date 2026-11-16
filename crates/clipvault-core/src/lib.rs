//! Everything ClipVault does that is not drawing pixels: watching the X11
//! clipboard, keeping history in SQLite, and the encrypted vault.

pub mod config;
pub mod harden;
pub mod media;
pub mod store;
pub mod vault;
pub mod watcher;
