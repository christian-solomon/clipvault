//! Single instance: the first launch listens on a Unix socket, later launches
//! hand it a one-byte command and exit.
//!
//! The socket lives in a 0700 directory under `$XDG_RUNTIME_DIR`, and each
//! connection's peer uid is checked as well, so only the same user can drive
//! the running copy. Commands are a fixed set of single bytes; nothing from
//! the socket is parsed beyond that.

use anyhow::{anyhow, bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::harden;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Bring the window up.
    Show,
    /// Show the window, or hide it if it is up.
    Toggle,
}

impl Command {
    fn byte(self) -> u8 {
        match self {
            Command::Show => b'S',
            Command::Toggle => b'T',
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'S' => Some(Command::Show),
            b'T' => Some(Command::Toggle),
            _ => None,
        }
    }
}

pub enum Instance {
    /// We are the running copy. Keep this alive for as long as the app runs.
    Primary(Primary),
    /// Another copy already runs and has been told what to do.
    Secondary,
}

pub struct Primary {
    listener: UnixListener,
    // Holding the flock is what makes us primary; it is released on exit,
    // including a crash, so a stale socket never blocks the next start.
    _lock: File,
}

/// `$XDG_RUNTIME_DIR/clipvault`, falling back to a per-uid directory in /tmp.
pub fn default_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d).join("clipvault"),
        // SAFETY: getuid cannot fail.
        None => std::env::temp_dir().join(format!("clipvault-{}", unsafe { libc::getuid() })),
    }
}

/// Becomes the primary instance, or delivers `command` to the existing one.
pub fn claim(dir: &Path, command: Command) -> Result<Instance> {
    harden::private_dir(dir)?;
    let lock_path = dir.join("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    // SAFETY: flock on a file descriptor we own.
    let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    let sock = dir.join("ctl.sock");

    if locked {
        // Whatever socket is there belonged to a copy that no longer holds
        // the lock, so it is dead.
        let _ = std::fs::remove_file(&sock);
        let listener =
            UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        return Ok(Instance::Primary(Primary { listener, _lock: lock }));
    }

    // The primary may hold the lock but not have bound the socket yet.
    let mut last = None;
    for _ in 0..20 {
        match UnixStream::connect(&sock) {
            Ok(mut stream) => {
                stream.write_all(&[command.byte()])?;
                return Ok(Instance::Secondary);
            }
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(anyhow!("another ClipVault is starting but not answering: {}", last.unwrap()))
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        bail!("SO_PEERCRED: {}", std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

impl Primary {
    /// Serves commands on a background thread until the process exits.
    pub fn serve(self, on_command: impl Fn(Command) + Send + 'static) -> Result<()> {
        std::thread::Builder::new().name("clipvault-ipc".into()).spawn(move || {
            let _lock = self._lock;
            // SAFETY: getuid cannot fail.
            let me = unsafe { libc::getuid() };
            for stream in self.listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                match peer_uid(&stream) {
                    Ok(uid) if uid == me => {}
                    Ok(uid) => {
                        log::warn!("ignoring a control connection from uid {uid}");
                        continue;
                    }
                    Err(e) => {
                        log::warn!("ignoring a control connection: {e}");
                        continue;
                    }
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).is_ok() {
                    match Command::from_byte(byte[0]) {
                        Some(cmd) => on_command(cmd),
                        None => log::warn!("ignoring an unknown control command"),
                    }
                }
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tempdir::Dir;
    use std::sync::mpsc;

    #[test]
    fn first_claim_is_primary_and_the_second_reaches_it() {
        let d = Dir::new();
        let dir = d.path().join("rt");
        let Instance::Primary(primary) = claim(&dir, Command::Show).unwrap() else {
            panic!("first claim must be primary");
        };
        let (tx, rx) = mpsc::channel();
        primary.serve(move |c| tx.send(c).unwrap()).unwrap();

        assert!(matches!(claim(&dir, Command::Toggle).unwrap(), Instance::Secondary));
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), Command::Toggle);
        assert!(matches!(claim(&dir, Command::Show).unwrap(), Instance::Secondary));
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), Command::Show);
    }

    #[test]
    fn the_runtime_dir_and_socket_are_private() {
        let d = Dir::new();
        let dir = d.path().join("rt");
        let _primary = claim(&dir, Command::Show).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("ctl.sock")), 0o600);
    }

    #[test]
    fn a_stale_socket_from_a_dead_copy_is_replaced() {
        let d = Dir::new();
        let dir = d.path().join("rt");
        {
            let _gone = claim(&dir, Command::Show).unwrap();
        }
        assert!(dir.join("ctl.sock").exists(), "left behind, as after a crash");
        assert!(matches!(claim(&dir, Command::Show).unwrap(), Instance::Primary(_)));
    }

    #[test]
    fn unknown_bytes_are_not_commands() {
        assert_eq!(Command::from_byte(b'x'), None);
        assert_eq!(Command::from_byte(Command::Toggle.byte()), Some(Command::Toggle));
    }
}
