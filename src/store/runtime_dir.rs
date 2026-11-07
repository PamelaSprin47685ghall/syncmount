//! Per-mount runtime directory: instance lock and status file.
//!
//! Layout: `/run/syncmount/<mount_id>/` (mode 0700), containing:
//!
//! | file | mode | purpose |
//! |---|---|---|
//! | `lock` | 0600 | `flock(LOCK_EX | LOCK_NB)`, held for the process lifetime |
//! | `status.json` | 0600 | atomically replaced companion of the status document |
//!
//! The documented status file is `/run/syncmount/<mount_id>.json` (mode
//! 0600); [`RuntimeDir::write_status`] replaces it atomically as well, so both
//! the documented path and the per-mount companion always carry a complete
//! snapshot.
//!
//! `SYNCMOUNT_RUN_DIR` overrides the base directory (tests, and hosts where
//! `/run/syncmount` is not writable). The mount id is validated as a single
//! path component, so it can never escape the base.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::{Errno, Result};

/// Default base directory.
pub const DEFAULT_BASE: &str = "/run/syncmount";

/// Environment override for the base directory.
pub const BASE_ENV: &str = "SYNCMOUNT_RUN_DIR";

/// Status file name inside the per-mount directory.
pub const STATUS_FILE: &str = "status.json";

/// Lock file name inside the per-mount directory.
pub const LOCK_FILE: &str = "lock";

/// Upper bound on a status file read (defensive: it is our own file).
const MAX_STATUS_BYTES: u64 = 1024 * 1024;

/// One mounted instance's runtime directory.
#[derive(Debug)]
pub struct RuntimeDir {
    base: PathBuf,
    mount_id: String,
    dir: PathBuf,
}

impl RuntimeDir {
    /// The base directory: `SYNCMOUNT_RUN_DIR` or [`DEFAULT_BASE`].
    pub fn base() -> PathBuf {
        match std::env::var_os(BASE_ENV) {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => PathBuf::from(DEFAULT_BASE),
        }
    }

    /// Create (or reuse) `<base>/<mount_id>/` with mode 0700.
    pub fn create(mount_id: &str) -> Result<Self> {
        Self::create_in(&Self::base(), mount_id)
    }

    /// Create (or reuse) `<base>/<mount_id>/` with mode 0700.
    ///
    /// The base itself is created when missing, but its mode is only tightened
    /// when this process owns it; a shared `/run/syncmount` owned by root is
    /// left alone.
    pub fn create_in(base: &Path, mount_id: &str) -> Result<Self> {
        validate_mount_id(mount_id)?;
        ensure_dir(base, 0o700, false)?;
        let dir = base.join(mount_id);
        ensure_dir(&dir, 0o700, true)?;
        Ok(Self {
            base: base.to_path_buf(),
            mount_id: mount_id.to_owned(),
            dir,
        })
    }

    /// The per-mount directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `<dir>/status.json`.
    pub fn status_path(&self) -> PathBuf {
        self.dir.join(STATUS_FILE)
    }

    /// The documented status document: `<base>/<mount_id>.json`.
    ///
    /// Design 41 §2.8 and 27 §4.2 name this path; the per-mount directory
    /// keeps the companion `status.json` and the instance lock.
    pub fn document_path(&self) -> PathBuf {
        self.base.join(format!("{}.json", self.mount_id))
    }

    /// `<dir>/lock`.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    /// Open (creating if needed) the companion `status.json` for writing,
    /// mode 0600. Prefer [`RuntimeDir::write_status`], which also publishes
    /// the documented `<mount_id>.json` atomically.
    pub fn create_status_file(&self) -> Result<OwnedFd> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.status_path())
            .map_err(Errno::from)?;
        let fd: OwnedFd = file.into();
        tighten_mode(&fd, 0o600)?;
        Ok(fd)
    }

    /// Atomically replace the status document with `data`.
    ///
    /// Two names carry the same snapshot: `<base>/<mount_id>.json` (the
    /// documented path) and `<base>/<mount_id>/status.json` (the companion in
    /// the lock directory). Each is written to a sibling temporary file,
    /// `fsync`ed, renamed, and its directory `fsync`ed, so a reader of either
    /// name sees the previous complete document or the new one.
    pub fn write_status(&self, data: &[u8]) -> Result<()> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .dir
            .join(format!(".status.{}.{}.tmp", std::process::id(), seq));
        if let Err(err) = write_atomic(&temp, &self.status_path(), data) {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        let temp = self.base.join(format!(
            ".{}.{}.{}.tmp",
            self.mount_id,
            std::process::id(),
            seq
        ));
        if let Err(err) = write_atomic(&temp, &self.document_path(), data) {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        Ok(())
    }

    /// Read `status.json`, refusing a file that is not mode 0600.
    pub fn read_status(&self) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.status_path())
            .map_err(Errno::from)?;
        let stat = rustix::fs::fstat(&file).map_err(Errno::from)?;
        if stat.st_mode & 0o777 != 0o600 {
            return Err(Errno::EACCES);
        }
        let mut data = Vec::new();
        file.take(MAX_STATUS_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(Errno::from)?;
        if data.len() as u64 > MAX_STATUS_BYTES {
            return Err(Errno::EOVERFLOW);
        }
        Ok(data)
    }

    /// Acquire the single-instance lock.
    ///
    /// Returns the locked descriptor; the lock lives until it is dropped. A
    /// second acquisition in the same process fails with `EAGAIN` because
    /// `flock` locks belong to the open file description.
    pub fn acquire_lock(&self) -> Result<OwnedFd> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.lock_path())
            .map_err(Errno::from)?;
        let fd: OwnedFd = file.into();
        tighten_mode(&fd, 0o600)?;
        rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |err| {
                if err == rustix::io::Errno::AGAIN {
                    Errno::EAGAIN
                } else {
                    Errno::from(err)
                }
            },
        )?;
        Ok(fd)
    }

    /// Remove the per-mount directory and its files.
    pub fn remove(self) -> Result<()> {
        let document = self.document_path();
        let mut result = fs::remove_dir_all(&self.dir).map_err(Errno::from);
        match fs::remove_file(&document) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                if result.is_ok() {
                    result = Err(Errno::from(err));
                }
            }
        }
        result
    }
}

fn validate_mount_id(mount_id: &str) -> Result<()> {
    if mount_id.is_empty()
        || mount_id.len() > 128
        || mount_id == "."
        || mount_id == ".."
        || !mount_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn ensure_dir(path: &Path, mode: u32, require_owner: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(Errno::ENOTDIR);
            }
            let owned = metadata.uid() == rustix::process::geteuid().as_raw();
            if require_owner && !owned {
                return Err(Errno::EACCES);
            }
            if !owned && metadata.permissions().mode() & 0o022 != 0 {
                // A shared base directory must not be writable by other users:
                // they could pre-create a mount id and hijack the lock file.
                return Err(Errno::EACCES);
            }
            if metadata.permissions().mode() & 0o777 != mode && (owned || require_owner) {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Errno::from)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(mode);
            builder.create(path).map_err(Errno::from)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Errno::from)?;
            Ok(())
        }
        Err(err) => Err(Errno::from(err)),
    }
}

fn tighten_mode(fd: &OwnedFd, mode: u32) -> Result<()> {
    let stat = rustix::fs::fstat(fd).map_err(Errno::from)?;
    if stat.st_mode & 0o777 != mode {
        rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode(mode)).map_err(Errno::from)?;
    }
    Ok(())
}

fn write_atomic(temp: &Path, destination: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(Errno::from)?;
    file.write_all(data).map_err(Errno::from)?;
    file.sync_all().map_err(Errno::from)?;
    drop(file);
    fs::rename(temp, destination).map_err(Errno::from)?;
    let parent = destination.parent().ok_or(Errno::EINVAL)?;
    let dir = OpenOptions::new()
        .read(true)
        .open(parent)
        .map_err(Errno::from)?;
    dir.sync_all().map_err(Errno::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_base() -> TempDir {
        TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"))
    }

    fn err<T: std::fmt::Debug>(result: Result<T>) -> Errno {
        match result {
            Ok(value) => panic!("expected an error, got {value:?}"),
            Err(err) => err,
        }
    }

    /// 31:M1-4
    #[test]
    fn u_store_runtime_dir_permissions_and_status() {
        let base = temp_base();
        let runtime = RuntimeDir::create_in(base.path(), "mnt-abc")
            .unwrap_or_else(|err| panic!("create: {err:?}"));
        let metadata = fs::metadata(runtime.path()).unwrap_or_else(|err| panic!("metadata: {err}"));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        runtime
            .write_status(br#"{"state":"steady","applied_seq":7}"#)
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        let metadata =
            fs::metadata(runtime.status_path()).unwrap_or_else(|err| panic!("metadata: {err}"));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            runtime
                .read_status()
                .unwrap_or_else(|err| panic!("read: {err:?}")),
            br#"{"state":"steady","applied_seq":7}"#
        );

        runtime
            .write_status(b"{\"state\":\"joining\"}")
            .unwrap_or_else(|err| panic!("rewrite: {err:?}"));
        assert_eq!(
            runtime
                .read_status()
                .unwrap_or_else(|err| panic!("read: {err:?}")),
            b"{\"state\":\"joining\"}"
        );
        let leftovers: Vec<_> = fs::read_dir(runtime.path())
            .unwrap_or_else(|err| panic!("read_dir: {err}"))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(".status."))
            .collect();
        assert!(leftovers.is_empty());
    }

    /// 31:M1-4
    #[test]
    fn u_store_runtime_dir_lock_is_exclusive() {
        let base = temp_base();
        let runtime = RuntimeDir::create_in(base.path(), "mnt-lock")
            .unwrap_or_else(|err| panic!("create: {err:?}"));
        let first = runtime
            .acquire_lock()
            .unwrap_or_else(|err| panic!("lock: {err:?}"));
        assert_eq!(err(runtime.acquire_lock()), Errno::EAGAIN);
        drop(first);
        runtime
            .acquire_lock()
            .unwrap_or_else(|err| panic!("relock: {err:?}"));
    }

    /// 31:M1-4
    #[test]
    fn u_store_runtime_dir_rejects_bad_mount_id() {
        let base = temp_base();
        for mount_id in ["", ".", "..", "a/b", "../x", "a b", "x\0y", "a.b"] {
            assert_eq!(
                err(RuntimeDir::create_in(base.path(), mount_id)),
                Errno::EINVAL,
                "mount id {mount_id:?} must be rejected"
            );
        }
        assert!(!base.path().join("x").exists());
    }

    /// 41 §2.8 / 27 §4.2: the documented status document is
    /// `<base>/<mount_id>.json`, written atomically alongside its companion.
    #[test]
    fn u_store_runtime_dir_writes_documented_document() {
        let base = temp_base();
        let runtime = RuntimeDir::create_in(base.path(), "mnt-doc")
            .unwrap_or_else(|err| panic!("create: {err:?}"));
        assert_eq!(
            runtime.document_path(),
            base.path().join("mnt-doc.json"),
            "document path"
        );

        runtime
            .write_status(br#"{"state":"steady","applied_seq":1}"#)
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        for path in [runtime.status_path(), runtime.document_path()] {
            let metadata = fs::metadata(&path).unwrap_or_else(|err| panic!("metadata: {err}"));
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                fs::read(&path).unwrap_or_else(|err| panic!("read: {err}")),
                br#"{"state":"steady","applied_seq":1}"#
            );
        }

        runtime
            .write_status(br#"{"state":"joining","applied_seq":2}"#)
            .unwrap_or_else(|err| panic!("rewrite: {err:?}"));
        assert_eq!(
            fs::read(runtime.document_path()).unwrap_or_else(|err| panic!("read: {err}")),
            br#"{"state":"joining","applied_seq":2}"#
        );

        let leftovers: Vec<_> = fs::read_dir(base.path())
            .unwrap_or_else(|err| panic!("read_dir: {err}"))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

        let document = runtime.document_path();
        runtime
            .remove()
            .unwrap_or_else(|err| panic!("remove: {err:?}"));
        assert!(!base.path().join("mnt-doc").exists());
        assert!(!document.exists());
    }

    /// 31:M1-4
    #[test]
    fn u_store_runtime_dir_reuses_directory_and_tightens_mode() {
        let base = temp_base();
        let path = base.path().join("mnt-reuse");
        fs::create_dir(&path).unwrap_or_else(|err| panic!("mkdir: {err}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|err| panic!("chmod: {err}"));
        let runtime = RuntimeDir::create_in(base.path(), "mnt-reuse")
            .unwrap_or_else(|err| panic!("create: {err:?}"));
        assert_eq!(runtime.path(), path);
        let mode = fs::metadata(&path)
            .unwrap_or_else(|err| panic!("metadata: {err}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
