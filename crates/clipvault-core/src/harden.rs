//! Process and filesystem hardening.
//!
//! Clipboard history and the vault key are the two things worth stealing from
//! this process. These calls keep the files private to the user and keep the
//! unlocked key out of core dumps and away from same-user debuggers.

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Makes every file this process creates from here on private to its owner,
/// including the `-wal` and `-shm` files SQLite creates behind our back.
pub fn private_umask() {
    // SAFETY: umask only swaps an integer in the process's credentials.
    unsafe {
        libc::umask(0o077);
    }
}

/// Stops the kernel writing core dumps, and stops processes running as the same
/// user from attaching with ptrace or reading /proc/<pid>/mem. Both would
/// otherwise hand over the vault key while it is unlocked.
pub fn undumpable() -> Result<()> {
    // SAFETY: plain syscalls with integer arguments and a stack struct.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            bail!("prctl(PR_SET_DUMPABLE): {}", std::io::Error::last_os_error());
        }
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            bail!("setrlimit(RLIMIT_CORE): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Creates `dir` as 0700 if missing, tightens it to 0700 if it exists, and
/// refuses to use a directory owned by someone else.
pub fn private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let meta = fs::metadata(dir).with_context(|| format!("reading {}", dir.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        bail!("{} is owned by uid {}, not by us ({uid})", dir.display(), meta.uid());
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// Tightens an existing file to 0600. Missing files are fine.
pub fn private_file(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(meta) if meta.permissions().mode() & 0o777 != 0o600 => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting {}", path.display()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tempdir::Dir;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_a_missing_dir_private() {
        let d = Dir::new();
        let target = d.path().join("a/b");
        private_dir(&target).unwrap();
        assert_eq!(mode(&target), 0o700);
    }

    #[test]
    fn tightens_an_existing_open_dir() {
        let d = Dir::new();
        let target = d.path().join("open");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o775)).unwrap();
        private_dir(&target).unwrap();
        assert_eq!(mode(&target), 0o700);
    }

    #[test]
    fn tightens_a_world_readable_file_and_ignores_missing_ones() {
        let d = Dir::new();
        let f = d.path().join("db");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        private_file(&f).unwrap();
        assert_eq!(mode(&f), 0o600);
        private_file(&d.path().join("absent")).unwrap();
    }

    #[test]
    fn refuses_a_file_where_a_dir_should_be() {
        let d = Dir::new();
        let f = d.path().join("file");
        fs::write(&f, b"x").unwrap();
        assert!(private_dir(&f).is_err());
    }
}
