//! FUSE-over-shadow for the 1.1 `--mmap` client.
//!
//! The mount point holds no live tree of its own. Direct file contents live in
//! `objects/<ino>/v<N>` and appear in `dirs/<dir_ino>/<name>` as hard links.
//! Metadata lives in `shadow.db`, which is a foundation mm database extended
//! with shadow-only tables. The FUSE layer is a thin adapter over the
//! operations in this module.
//!
//! # Consistency unit
//!
//! Checkout replaces one directory's direct entries; upload commits one
//! directory's full manifest. Child directory contents are never recursive.
//! `open` may fetch a directory's bodies once; the final close or an explicit
//! `fsync` uploads the directory's frozen dirty files and never touches a
//! clean file's bytes.
//!
//! # Versioned inodes
//!
//! A file inode has one or more content versions. A remote refresh creates a
//! new version and a new kernel inode; old descriptors and mappings keep the
//! old version. A local write stays on the current version and inode, so page
//! cache and `mmap` remain coherent. The final `release` drops the reference
//! and commits a dirty close; `forget` and the current-version check decide
//! when an object is collected.

mod checkout;
mod content;
mod db;
mod layout;
mod locks;
mod noop;
mod ops;
mod recover;
mod upload;

pub mod remote;

#[cfg(all(test, feature = "mmap-tests"))]
mod tests;

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::mmap::MmError;
use crate::mmap::manifest::ManifestError;
use crate::mmap::types::Ino;

pub use db::{FuseRow, ShadowDb, ShadowDir, ShadowVersion, UploadPhase, VersionState};
pub use layout::{OwnerLock, ShadowLayout, hex16, namespace_component};
pub use locks::{LockTable, RangeLock, flock_exclusive, flock_shared};
pub use ops::{AttrChange, DirItem, NodeAttr};
pub use remote::{
    BatchState, BatchStatus, CheckoutBody, CheckoutEntry, CheckoutOutcome, CheckoutRequest,
    CheckoutSnapshot, FileData, FileReadRequest, GrantedLock, LockRequest, LockResponse, MmRemote,
    RemoteError, SignatureFile, SignatureFilePlan, SignaturesRequest, SignaturesResponse,
    UploadAbort, UploadBegin, UploadCommit, UploadFile, UploadPlan, UploadRequest, UploadResponse,
    UploadResult,
};

/// The one error every shadow operation returns.
#[derive(Debug, thiserror::Error)]
pub enum ShadowError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("database: {0}")]
    Db(#[from] MmError),
    #[error("manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("rsync: {0}")]
    Rsync(#[from] crate::mmap::rsync::RsyncError),
    #[error("remote: {0}")]
    Remote(#[from] RemoteError),
    #[error("not found")]
    NotFound,
    #[error("is a directory")]
    IsDir,
    #[error("not a directory")]
    NotDir,
    #[error("already exists")]
    Exists,
    #[error("directory is not empty")]
    NotEmpty,
    #[error("invalid: {0}")]
    Invalid(&'static str),
    #[error("busy")]
    Busy,
    #[error("conflict; retry on the next fsync")]
    Conflict,
    #[error("stale base")]
    Stale,
    #[error("too large")]
    TooLarge,
    #[error("read only")]
    ReadOnly,
    #[error("cross-directory rename is not supported")]
    CrossDevice,
    #[error("unsupported")]
    Unsupported,
}

impl ShadowError {
    /// The POSIX errno a FUSE callback should return.
    pub fn errno(&self) -> i32 {
        match self {
            Self::Io(_) => libc::EIO,
            Self::Db(_) | Self::Manifest(_) | Self::Rsync(_) => libc::EIO,
            Self::Remote(error) => match error {
                RemoteError::NotFound => libc::ENOENT,
                RemoteError::TooLarge(_) => libc::EFBIG,
                RemoteError::Unsupported(_) => libc::EOPNOTSUPP,
                RemoteError::BaseChanged { .. }
                | RemoteError::SignatureStale
                | RemoteError::ManifestIncomplete { .. }
                | RemoteError::HashMismatch { .. }
                | RemoteError::BatchConflict
                | RemoteError::LockHeld { .. }
                | RemoteError::LockLost { .. }
                | RemoteError::LockExpired => libc::EAGAIN,
                RemoteError::DirNotEmpty(_) => libc::ENOTEMPTY,
                RemoteError::Io(_) | RemoteError::Unauthenticated | RemoteError::Internal(_) => {
                    libc::EIO
                }
            },
            Self::NotFound => libc::ENOENT,
            Self::IsDir => libc::EISDIR,
            Self::NotDir => libc::ENOTDIR,
            Self::Exists => libc::EEXIST,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::Invalid(_) => libc::EINVAL,
            Self::Busy => libc::EBUSY,
            Self::Conflict => libc::EAGAIN,
            Self::Stale => libc::ESTALE,
            Self::TooLarge => libc::EFBIG,
            Self::ReadOnly => libc::EROFS,
            Self::CrossDevice => libc::EXDEV,
            Self::Unsupported => libc::EOPNOTSUPP,
        }
    }
}

/// How one mount finds its namespace and remote.
#[derive(Clone, Debug)]
pub struct ShadowConfig {
    pub state_root: PathBuf,
    pub namespace: String,
    pub revalidate_ttl: Duration,
}

impl ShadowConfig {
    /// A config with a one-second revalidation window.
    pub fn new(state_root: impl Into<PathBuf>, namespace: impl Into<String>) -> Self {
        Self {
            state_root: state_root.into(),
            namespace: namespace.into(),
            revalidate_ttl: Duration::from_secs(1),
        }
    }
}

/// One open file descriptor.
pub struct OpenFile {
    pub id: u64,
    pub fuse_ino: u64,
    pub ino: Ino,
    pub version: u64,
    pub dir_ino: Ino,
    pub name: String,
    pub file: File,
    pub writable: bool,
}

impl std::fmt::Debug for OpenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFile")
            .field("id", &self.id)
            .field("fuse_ino", &self.fuse_ino)
            .field("ino", &hex16(&self.ino))
            .field("version", &self.version)
            .field("dir_ino", &hex16(&self.dir_ino))
            .field("name", &self.name)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

/// Per-(inode, version) mutexes shared by writes and upload snapshots.
type VersionLocks = Mutex<HashMap<(Ino, u64), Arc<Mutex<()>>>>;

/// One directory's single-flight checkout and serialized upload.
#[derive(Debug, Default)]
pub(super) struct DirSlot {
    pub state: Mutex<SlotState>,
    pub changed: Condvar,
    pub upload: Mutex<()>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum SlotState {
    #[default]
    Idle,
    CheckingOut,
    /// The last checkout finished successfully; waiters may adopt it.
    Ready,
    Failed {
        retry_at: Option<Instant>,
    },
}

/// The mounted shadow filesystem state.
pub struct Shadow {
    pub(super) layout: ShadowLayout,
    pub(super) db: ShadowDb,
    pub(super) remote: Arc<dyn MmRemote>,
    pub(super) namespace: String,
    pub(super) ttl: Duration,
    pub(super) slots: Mutex<HashMap<Ino, Arc<DirSlot>>>,
    pub(super) handles: Mutex<HashMap<u64, Arc<OpenFile>>>,
    pub(super) next_handle: AtomicU64,
    pub(super) version_locks: VersionLocks,
    pub(super) locks: LockTable,
    pub(super) _owner: OwnerLock,
}

impl std::fmt::Debug for Shadow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shadow")
            .field("namespace", &self.namespace)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl Shadow {
    /// Open one namespace: take the owner lock, create the layout, open the
    /// metadata database and repair state left by a crash.
    pub fn open(config: ShadowConfig, remote: Arc<dyn MmRemote>) -> Result<Self, ShadowError> {
        let layout = ShadowLayout::new(&config.state_root, &config.namespace);
        layout.prepare()?;
        let owner = OwnerLock::acquire(&layout.owner_lock_path())?;
        layout.cleanup_startup()?;
        let db = ShadowDb::open(&layout, &config.namespace)?;
        db.reset_after_crash()?;
        let ttl_ms = u64::try_from(config.revalidate_ttl.as_millis()).unwrap_or(u64::MAX);
        if ttl_ms > 0 {
            db.set_revalidate_ttl_ms(ttl_ms)?;
        }
        let shadow = Self {
            layout,
            db,
            remote,
            namespace: config.namespace,
            ttl: config.revalidate_ttl,
            slots: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            version_locks: Mutex::new(HashMap::new()),
            locks: LockTable::new(),
            _owner: owner,
        };
        shadow.recover_batches()?;
        shadow.collect_orphan_objects()?;
        Ok(shadow)
    }

    /// The namespace served by this mount.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The shadow layout.
    pub fn layout(&self) -> &ShadowLayout {
        &self.layout
    }

    /// The metadata database.
    pub fn db(&self) -> &ShadowDb {
        &self.db
    }

    /// The configured revalidation TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The root kernel inode.
    pub const fn root_ino() -> u64 {
        1
    }

    pub(super) fn slot(&self, dir_ino: Ino) -> Arc<DirSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots
            .entry(dir_ino)
            .or_insert_with(|| Arc::new(DirSlot::default()))
            .clone()
    }

    pub(super) fn version_lock(&self, ino: Ino, version: u64) -> Arc<Mutex<()>> {
        let mut locks = self
            .version_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        locks
            .entry((ino, version))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub(super) fn handle(&self, id: u64) -> Option<Arc<OpenFile>> {
        self.handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    pub(super) fn insert_handle(&self, handle: OpenFile) -> Arc<OpenFile> {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let handle = Arc::new(OpenFile { id, ..handle });
        self.handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::clone(&handle));
        handle
    }

    pub(super) fn remove_handle(&self, id: u64) -> Option<Arc<OpenFile>> {
        self.handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
    }

    /// The number of currently open file descriptors.
    pub fn open_handle_count(&self) -> usize {
        self.handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Drop unpublished object versions that no metadata row references.
    fn collect_orphan_objects(&self) -> Result<(), ShadowError> {
        let objects = match std::fs::read_dir(self.layout.objects_root()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in objects {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(bytes) = hex::decode(name) else {
                continue;
            };
            let Ok(ino) = <Ino>::try_from(bytes.as_slice()) else {
                continue;
            };
            let versions = match std::fs::read_dir(entry.path()) {
                Ok(versions) => versions,
                Err(_) => continue,
            };
            for version in versions {
                let version = version?;
                let Some(file_name) = version.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(number) = file_name.strip_prefix('v') else {
                    continue;
                };
                let Ok(number) = number.parse::<u64>() else {
                    continue;
                };
                if !self.db.has_version_row(ino, number)? {
                    let _ = std::fs::remove_file(version.path());
                }
            }
            let _ = std::fs::remove_dir(entry.path());
        }
        Ok(())
    }

    /// Remove collectable versions and their object files.
    ///
    /// Call this after `release`/`forget`; it is safe to call at any time.
    pub fn collect_garbage(&self) -> Result<(), ShadowError> {
        for (ino, version, fuse_ino) in self.db.collectable_versions()? {
            if self.db.drop_version(ino, version, fuse_ino)? {
                let _ = self.layout.remove_object(&ino, version);
            }
        }
        Ok(())
    }
}

/// Current Unix time in milliseconds.
pub(super) fn now_ms() -> i64 {
    crate::mmap::now_ms()
}

/// Current Unix time in nanoseconds.
pub(super) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Build the canonical child path of one directory entry.
pub(super) fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Borrow a mutex without propagating poisoning.
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Parent path of one canonical directory path.
pub(super) fn parent_path(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}
