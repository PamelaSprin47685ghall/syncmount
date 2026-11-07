//! The backing-tree door: [`RootFd`], its `*at` helpers, and the
//! [`BackingStore`] facade.
//!
//! `RootFd` is opened before `mount(2)` and is the only handle that can reach
//! the underlying tree. Every path is resolved with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`, so `..`, absolute paths
//! and symlinks that leave the tree are rejected by the kernel with `EXDEV`.
//! No function in this module accepts an absolute backing path.

use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{
    AtFlags, Mode, OFlags, RawDir, RenameFlags as RxRenameFlags, ResolveFlags,
    Timespec as RxTimespec, Timestamps, XattrFlags,
};
use rustix::io::Errno as RxErrno;

use crate::store::node_table::{InodeId, NodeTable, validate_name};
use crate::store::{Attr, AttrDelta, Errno, Kind, RenameFlags, Result, Timespec, is_reserved_name};

/// One directory entry produced by [`BackingStore::readdir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Backing inode number (`d_ino`).
    pub ino: u64,
    /// Cursor to pass to the next `readdir` call.
    pub offset: u64,
    /// File type from `d_type`, or `Unknown` when the filesystem omits it.
    pub kind: Kind,
    /// Entry name, never `.` or `..` and never a reserved name.
    pub name: OsString,
}

/// Sink for [`BackingStore::readdir`].
pub trait DirSink {
    /// Consume one entry.
    fn push(&mut self, entry: DirEntry) -> Result<()>;
}

/// One replayed side effect, applied to the backing tree during a rebase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Write `data` at `off`.
    Write { off: u64, data: Vec<u8> },
    /// Truncate to `size`.
    Truncate { size: u64 },
    /// Apply attribute changes.
    SetAttr(AttrDelta),
    /// Set (`Some`) or remove (`None`) an extended attribute.
    Xattr {
        name: Vec<u8>,
        value: Option<Vec<u8>>,
    },
}

/// The backing-tree facade used by the FUSE, replay and sync layers.
///
/// Paths are never accepted here: callers speak [`InodeId`], and `PosixBacking`
/// resolves ids through [`NodeTable`] to a path relative to the root fd.
pub trait BackingStore: Send + Sync {
    /// Stat one directory entry without following a final symlink.
    fn lookup(&self, parent: InodeId, name: &OsStr) -> Result<Attr>;
    /// Stat an inode.
    fn getattr(&self, ino: InodeId) -> Result<Attr>;
    /// Read at an offset; returns a short count only at EOF.
    fn read_at(&self, ino: InodeId, off: u64, buf: &mut [u8]) -> Result<usize>;
    /// Write at an offset, completing the whole buffer.
    fn write_at(&self, ino: InodeId, off: u64, data: &[u8]) -> Result<usize>;
    /// Truncate to `size`.
    fn truncate(&self, ino: InodeId, size: u64) -> Result<()>;
    /// Apply attribute changes.
    fn set_attr(&self, ino: InodeId, delta: &AttrDelta) -> Result<()>;
    /// Flush one inode to the backing disk.
    fn fsync(&self, ino: InodeId, datasync: bool) -> Result<()>;
    /// Enumerate a directory from `cursor` (0 to start).
    fn readdir(&self, ino: InodeId, cursor: u64, sink: &mut dyn DirSink) -> Result<()>;

    /// Create a directory and return its fresh identity.
    fn mkdir(&self, parent: InodeId, name: &OsStr, mode: u32) -> Result<InodeId>;
    /// Create a file with a caller-supplied identity (`O_CREAT | O_EXCL`).
    fn create(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<()>;
    /// Remove a non-directory entry.
    fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<()>;
    /// Rename one entry, optionally with `RENAME_NOREPLACE`/`EXCHANGE`.
    fn rename(
        &self,
        old: (InodeId, &OsStr),
        new: (InodeId, &OsStr),
        flags: RenameFlags,
    ) -> Result<()>;
    /// Add a hard link to an existing inode.
    fn link(&self, ino: InodeId, newparent: InodeId, newname: &OsStr) -> Result<()>;
    /// Create a symlink.
    fn symlink(&self, parent: InodeId, name: &OsStr, target: &Path) -> Result<()>;

    /// Apply one replayed side effect.
    fn apply_effect(&self, ino: InodeId, eff: &Effect) -> Result<()>;
    /// Flush the whole backing filesystem (unmount fallback).
    fn syncfs(&self) -> Result<()>;
}

/// The backing root, opened before the FUSE mount covers the mountpoint.
///
/// The descriptor keeps pointing at the pre-mount directory even after
/// `mount(2)`; that property is the entire reason this design works.
pub struct RootFd {
    fd: OwnedFd,
    sync_fd: OwnedFd,
    mountpoint: PathBuf,
}

impl fmt::Debug for RootFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootFd")
            .field("mountpoint", &self.mountpoint)
            .finish_non_exhaustive()
    }
}

impl RootFd {
    /// Open the backing root *before* mounting.
    ///
    /// `O_PATH` is enough for every `*at` operation; a second `O_RDONLY`
    /// descriptor is kept because `syncfs(2)` does not accept `O_PATH`.
    pub fn open_before_mount(mountpoint: &Path) -> std::io::Result<Self> {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            mountpoint,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let sync_fd = rustix::fs::openat(
            rustix::fs::CWD,
            mountpoint,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            fd,
            sync_fd,
            mountpoint: mountpoint.to_path_buf(),
        })
    }

    /// Resolve a relative path to an `O_PATH` descriptor beneath the root.
    pub fn resolve(&self, rel: &Path) -> Result<OwnedFd> {
        self.open_at(rel, OFlags::PATH, Mode::empty())
    }

    /// Open a relative path beneath the root.
    ///
    /// Uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`. Kernels
    /// older than 5.6 fall back to `openat`; the `..` check in [`normalize`]
    /// still applies, but symlink escapes cannot be verified there.
    pub fn open_at(&self, rel: &Path, flags: OFlags, mode: Mode) -> Result<OwnedFd> {
        let rel = normalize(rel)?;
        let flags = flags | OFlags::CLOEXEC;
        let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        match rustix::fs::openat2(self.fd.as_fd(), &rel, flags, mode, resolve) {
            Ok(fd) => Ok(fd),
            Err(RxErrno::NOSYS) => {
                rustix::fs::openat(self.fd.as_fd(), &rel, flags, mode).map_err(Errno::from)
            }
            Err(err) => Err(Errno::from(err)),
        }
    }

    /// The `O_PATH` root descriptor, for `*at` calls.
    pub fn at(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The `O_RDONLY` root descriptor, for `syncfs`/`fstatfs`.
    pub fn sync_fd(&self) -> BorrowedFd<'_> {
        self.sync_fd.as_fd()
    }

    /// The path the root was opened from. Diagnostics only: it must never be
    /// used to reopen the backing tree after mounting.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Flush the backing filesystem.
    pub fn syncfs(&self) -> Result<()> {
        rustix::fs::syncfs(self.sync_fd.as_fd()).map_err(Errno::from)
    }

    /// Filesystem statistics from the `O_RDONLY` descriptor.
    ///
    /// `sync_fd` is the descriptor that can answer `fstatfs`/`syncfs`; the
    /// `O_PATH` root descriptor cannot.
    pub fn statfs(&self) -> Result<rustix::fs::StatFs> {
        rustix::fs::fstatfs(self.sync_fd.as_fd()).map_err(Errno::from)
    }

    /// Stat a relative path, optionally following a final symlink.
    pub fn stat_at(&self, rel: &Path, follow: bool) -> Result<Attr> {
        let rel = normalize(rel)?;
        let flags = if follow {
            AtFlags::empty()
        } else {
            AtFlags::SYMLINK_NOFOLLOW
        };
        rustix::fs::statat(self.fd.as_fd(), &rel, flags)
            .map(|stat| Attr::from_stat(&stat))
            .map_err(Errno::from)
    }

    /// List one directory, filtering `.`, `..` and reserved names.
    pub fn list_at(&self, rel: &Path) -> Result<Vec<DirEntry>> {
        let rel = normalize(rel)?;
        let fd = self.open_at(&rel, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?;
        let mut buffer = vec![std::mem::MaybeUninit::<u8>::uninit(); 64 * 1024];
        let mut raw = RawDir::new(fd.as_fd(), &mut buffer);
        let mut entries = Vec::new();
        let mut offset = 0u64;
        while let Some(entry) = raw.next() {
            let entry = entry.map_err(Errno::from)?;
            let name_bytes = entry.file_name().to_bytes();
            let name = OsString::from_vec(name_bytes.to_vec());
            if name_bytes == b".".as_slice()
                || name_bytes == b"..".as_slice()
                || is_reserved_name(&name)
            {
                continue;
            }
            offset += 1;
            entries.push(DirEntry {
                ino: entry.ino(),
                offset,
                kind: Kind::from_file_type(entry.file_type()),
                name,
            });
        }
        Ok(entries)
    }

    /// Walk a subtree without following symlinks.
    ///
    /// Returns `(relative path, attr)` in parent-before-child order. The depth
    /// cap matches the namespace limit (128) and turns a pathological tree into
    /// `ELOOP` instead of an unbounded loop.
    pub fn walk_at(&self, rel: &Path) -> Result<Vec<(PathBuf, Attr)>> {
        let root = normalize(rel)?;
        let root_attr = self.stat_at(&root, false)?;
        let mut out = vec![(root.clone(), root_attr)];
        let mut stack = if root_attr.kind().is_dir() {
            vec![root]
        } else {
            Vec::new()
        };
        while let Some(dir) = stack.pop() {
            let depth = dir
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count();
            if depth > 128 {
                return Err(Errno::ELOOP);
            }
            for entry in self.list_at(&dir)? {
                let child = if dir.as_os_str() == "." {
                    PathBuf::from(&entry.name)
                } else {
                    dir.join(&entry.name)
                };
                let attr = self.stat_at(&child, false)?;
                if attr.kind().is_dir() {
                    stack.push(child.clone());
                }
                out.push((child, attr));
            }
        }
        Ok(out)
    }

    /// `mkdirat`.
    pub fn mkdir_at(&self, rel: &Path, mode: u32) -> Result<()> {
        let rel = normalize(rel)?;
        rustix::fs::mkdirat(self.fd.as_fd(), &rel, Mode::from_raw_mode(mode)).map_err(Errno::from)
    }

    /// `unlinkat(..., 0)`.
    pub fn unlink_at(&self, rel: &Path) -> Result<()> {
        let rel = normalize(rel)?;
        rustix::fs::unlinkat(self.fd.as_fd(), &rel, AtFlags::empty()).map_err(Errno::from)
    }

    /// `unlinkat(..., AT_REMOVEDIR)`.
    pub fn rmdir_at(&self, rel: &Path) -> Result<()> {
        let rel = normalize(rel)?;
        rustix::fs::unlinkat(self.fd.as_fd(), &rel, AtFlags::REMOVEDIR).map_err(Errno::from)
    }

    /// `renameat` / `renameat2`.
    pub fn rename_at(&self, old: &Path, new: &Path, flags: RenameFlags) -> Result<()> {
        let old = normalize(old)?;
        let new = normalize(new)?;
        if flags.0 == 0 {
            rustix::fs::renameat(self.fd.as_fd(), &old, self.fd.as_fd(), &new).map_err(Errno::from)
        } else {
            let flags = RxRenameFlags::from_bits_truncate(flags.0);
            rustix::fs::renameat_with(self.fd.as_fd(), &old, self.fd.as_fd(), &new, flags)
                .map_err(Errno::from)
        }
    }

    /// `linkat(..., 0)`.
    pub fn link_at(&self, old: &Path, new: &Path) -> Result<()> {
        let old = normalize(old)?;
        let new = normalize(new)?;
        rustix::fs::linkat(
            self.fd.as_fd(),
            &old,
            self.fd.as_fd(),
            &new,
            AtFlags::empty(),
        )
        .map_err(Errno::from)
    }

    /// `symlinkat`. The target is user data and may point outside the root.
    pub fn symlink_at(&self, target: &Path, rel: &Path) -> Result<()> {
        let rel = normalize(rel)?;
        rustix::fs::symlinkat(target, self.fd.as_fd(), &rel).map_err(Errno::from)
    }

    /// `readlinkat`.
    pub fn readlink_at(&self, rel: &Path) -> Result<PathBuf> {
        let rel = normalize(rel)?;
        let target =
            rustix::fs::readlinkat(self.fd.as_fd(), &rel, Vec::new()).map_err(Errno::from)?;
        Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
    }

    /// `chmodat`.
    pub fn chmod_at(&self, rel: &Path, mode: u32) -> Result<()> {
        let rel = normalize(rel)?;
        rustix::fs::chmodat(
            self.fd.as_fd(),
            &rel,
            Mode::from_raw_mode(mode),
            AtFlags::empty(),
        )
        .map_err(Errno::from)
    }

    /// `chownat`; `None` leaves the field unchanged.
    pub fn chown_at(&self, rel: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        let rel = normalize(rel)?;
        let owner = uid.map(rustix::fs::Uid::from_raw_unchecked);
        let group = gid.map(rustix::fs::Gid::from_raw_unchecked);
        rustix::fs::chownat(self.fd.as_fd(), &rel, owner, group, AtFlags::empty())
            .map_err(Errno::from)
    }

    /// `utimensat`; `None` omits the corresponding timestamp.
    pub fn utimens_at(
        &self,
        rel: &Path,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
    ) -> Result<()> {
        let rel = normalize(rel)?;
        let to_rustix = |time: Option<Timespec>| match time {
            Some(time) => RxTimespec {
                tv_sec: time.sec,
                tv_nsec: time.nsec,
            },
            None => RxTimespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_OMIT,
            },
        };
        let times = Timestamps {
            last_access: to_rustix(atime),
            last_modification: to_rustix(mtime),
        };
        rustix::fs::utimensat(self.fd.as_fd(), &rel, &times, AtFlags::empty()).map_err(Errno::from)
    }

    /// Flush one file or directory.
    pub fn fsync_at(&self, rel: &Path, datasync: bool) -> Result<()> {
        let fd = self.open_at(rel, OFlags::RDONLY, Mode::empty())?;
        if datasync {
            rustix::fs::fdatasync(&fd).map_err(Errno::from)
        } else {
            rustix::fs::fsync(&fd).map_err(Errno::from)
        }
    }
}

/// Normalize a relative backing path.
///
/// Empty means the root (`.`). Absolute paths and any `..` component are
/// rejected with `EXDEV`: no internal operation needs them, and the pre-5.6
/// fallback cannot otherwise enforce the boundary.
fn normalize(rel: &Path) -> Result<PathBuf> {
    if rel.as_os_str().is_empty() {
        return Ok(PathBuf::from("."));
    }
    if rel.is_absolute() {
        return Err(Errno::EXDEV);
    }
    for component in rel.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Errno::EXDEV);
            }
            Component::Normal(part) => {
                if part.as_bytes().contains(&0) {
                    return Err(Errno::EINVAL);
                }
            }
            Component::CurDir => {}
        }
    }
    Ok(rel.to_path_buf())
}

/// The production [`BackingStore`] over a POSIX directory.
#[derive(Debug)]
pub struct PosixBacking {
    root: Arc<RootFd>,
    nodes: Arc<NodeTable>,
}

impl PosixBacking {
    /// Build a backing store with a fresh node table.
    pub fn new(root: RootFd) -> Self {
        Self {
            root: Arc::new(root),
            nodes: Arc::new(NodeTable::new()),
        }
    }

    /// Build a backing store over a shared root and node table.
    pub fn with_nodes(root: Arc<RootFd>, nodes: Arc<NodeTable>) -> Self {
        Self { root, nodes }
    }

    /// The root descriptor.
    pub fn root(&self) -> &RootFd {
        &self.root
    }

    /// The node table.
    pub fn nodes(&self) -> &NodeTable {
        &self.nodes
    }

    /// Stat a path relative to the root (bootstrap / JOIN paths).
    pub fn stat_path(&self, rel: &Path) -> Result<Attr> {
        self.root.stat_at(rel, false)
    }

    /// List a path relative to the root.
    pub fn list_path(&self, rel: &Path) -> Result<Vec<DirEntry>> {
        self.root.list_at(rel)
    }

    /// Walk a path relative to the root without following symlinks.
    pub fn walk_path(&self, rel: &Path) -> Result<Vec<(PathBuf, Attr)>> {
        self.root.walk_at(rel)
    }

    /// Create a symlink with a caller-supplied identity.
    pub fn symlink_with_id(
        &self,
        parent: InodeId,
        name: &OsStr,
        target: &Path,
        id: InodeId,
    ) -> Result<InodeId> {
        if is_reserved_name(name) {
            return Err(Errno::EEXIST);
        }
        validate_name(name)?;
        let parent_fd = self.dirfd(parent)?;
        rustix::fs::symlinkat(target, parent_fd.as_fd(), name).map_err(Errno::from)?;
        if let Err(err) = self.nodes.insert_link(id, parent, name, Kind::Symlink) {
            let _ = rustix::fs::unlinkat(parent_fd.as_fd(), name, AtFlags::empty());
            return Err(err);
        }
        Ok(id)
    }

    /// The directory entry that names `id`: `(parent dirfd, name)`.
    ///
    /// The root is addressed as `.` under the root descriptor. Every inode
    /// operation goes through a parent directory descriptor, so a hot path
    /// never rebuilds a root-relative path.
    fn entry(&self, id: InodeId) -> Result<(Arc<OwnedFd>, OsString)> {
        if id.is_root() {
            return Ok((self.dirfd(id)?, OsString::from(".")));
        }
        let (parent, name) = self.nodes.first_name(id).ok_or(Errno::ENOENT)?;
        Ok((self.dirfd(parent)?, name))
    }

    /// The cached `O_PATH` descriptor for a directory.
    ///
    /// A miss walks one level up through the parent's cached descriptor, so
    /// the first lookup of a deep directory opens each ancestor once and
    /// later operations reuse the descriptors.
    fn dirfd(&self, id: InodeId) -> Result<Arc<OwnedFd>> {
        if let Some(fd) = self.nodes.dirfd(id) {
            return Ok(fd);
        }
        let fd = if id.is_root() {
            self.root.open_at(
                Path::new("."),
                OFlags::PATH | OFlags::DIRECTORY,
                Mode::empty(),
            )?
        } else {
            let (parent_fd, name) = self.entry(id)?;
            rustix::fs::openat(
                parent_fd.as_fd(),
                name.as_os_str(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(Errno::from)?
        };
        let fd = Arc::new(fd);
        self.nodes.set_dirfd(id, Some(Arc::clone(&fd)));
        Ok(fd)
    }

    /// Open an inode through its parent directory descriptor.
    fn open_inode(&self, id: InodeId, flags: OFlags) -> Result<OwnedFd> {
        let (parent_fd, name) = self.entry(id)?;
        rustix::fs::openat(
            parent_fd.as_fd(),
            name.as_os_str(),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(Errno::from)
    }

    /// Stat an inode without following a final symlink.
    fn stat_inode(&self, id: InodeId) -> Result<Attr> {
        let (parent_fd, name) = self.entry(id)?;
        rustix::fs::statat(
            parent_fd.as_fd(),
            name.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map(|stat| Attr::from_stat(&stat))
        .map_err(Errno::from)
    }

    fn set_xattr(&self, ino: InodeId, name: &[u8], value: Option<&[u8]>) -> Result<()> {
        let fd = self.open_inode(ino, OFlags::RDONLY)?;
        let name = CString::new(name).map_err(|_| Errno::EINVAL)?;
        match value {
            Some(value) => rustix::fs::fsetxattr(&fd, name.as_c_str(), value, XattrFlags::empty())
                .map_err(Errno::from),
            None => rustix::fs::fremovexattr(&fd, name.as_c_str()).map_err(Errno::from),
        }
    }
}

impl BackingStore for PosixBacking {
    fn lookup(&self, parent: InodeId, name: &OsStr) -> Result<Attr> {
        if is_reserved_name(name) {
            return Err(Errno::ENOENT);
        }
        validate_name(name)?;
        let parent_fd = self.dirfd(parent)?;
        rustix::fs::statat(parent_fd.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map(|stat| Attr::from_stat(&stat))
            .map_err(Errno::from)
    }

    fn getattr(&self, ino: InodeId) -> Result<Attr> {
        self.stat_inode(ino)
    }

    fn read_at(&self, ino: InodeId, off: u64, buf: &mut [u8]) -> Result<usize> {
        let fd = self.open_inode(ino, OFlags::RDONLY)?;
        rustix::io::pread(&fd, buf, off).map_err(Errno::from)
    }

    fn write_at(&self, ino: InodeId, off: u64, data: &[u8]) -> Result<usize> {
        let fd = self.open_inode(ino, OFlags::WRONLY)?;
        let mut written = 0usize;
        while written < data.len() {
            let count = rustix::io::pwrite(&fd, &data[written..], off + written as u64)
                .map_err(Errno::from)?;
            if count == 0 {
                return Err(Errno::EIO);
            }
            written += count;
        }
        Ok(written)
    }

    fn truncate(&self, ino: InodeId, size: u64) -> Result<()> {
        let fd = self.open_inode(ino, OFlags::WRONLY)?;
        rustix::fs::ftruncate(&fd, size).map_err(Errno::from)
    }

    fn set_attr(&self, ino: InodeId, delta: &AttrDelta) -> Result<()> {
        let (parent_fd, name) = self.entry(ino)?;
        if let Some(size) = delta.size {
            let fd = self.open_inode(ino, OFlags::WRONLY)?;
            rustix::fs::ftruncate(&fd, size).map_err(Errno::from)?;
        }
        if delta.uid.is_some() || delta.gid.is_some() {
            let owner = delta.uid.map(rustix::fs::Uid::from_raw_unchecked);
            let group = delta.gid.map(rustix::fs::Gid::from_raw_unchecked);
            rustix::fs::chownat(
                parent_fd.as_fd(),
                name.as_os_str(),
                owner,
                group,
                AtFlags::empty(),
            )
            .map_err(Errno::from)?;
        }
        if let Some(mode) = delta.mode {
            rustix::fs::chmodat(
                parent_fd.as_fd(),
                name.as_os_str(),
                Mode::from_raw_mode(mode),
                AtFlags::empty(),
            )
            .map_err(Errno::from)?;
        }
        if delta.atime.is_some() || delta.mtime.is_some() {
            let to_rustix = |time: Option<Timespec>| match time {
                Some(time) => RxTimespec {
                    tv_sec: time.sec,
                    tv_nsec: time.nsec,
                },
                None => RxTimespec {
                    tv_sec: 0,
                    tv_nsec: rustix::fs::UTIME_OMIT,
                },
            };
            let times = Timestamps {
                last_access: to_rustix(delta.atime),
                last_modification: to_rustix(delta.mtime),
            };
            rustix::fs::utimensat(
                parent_fd.as_fd(),
                name.as_os_str(),
                &times,
                AtFlags::empty(),
            )
            .map_err(Errno::from)?;
        }
        Ok(())
    }

    fn fsync(&self, ino: InodeId, datasync: bool) -> Result<()> {
        // `fsync` needs any open descriptor. A write-only file cannot be
        // opened for reading, so fall back to the write side before failing.
        let fd = match self.open_inode(ino, OFlags::RDONLY) {
            Ok(fd) => fd,
            Err(Errno::EACCES) => self.open_inode(ino, OFlags::WRONLY)?,
            Err(err) => return Err(err),
        };
        if datasync {
            rustix::fs::fdatasync(&fd).map_err(Errno::from)
        } else {
            rustix::fs::fsync(&fd).map_err(Errno::from)
        }
    }

    fn readdir(&self, ino: InodeId, cursor: u64, sink: &mut dyn DirSink) -> Result<()> {
        let fd = self.open_inode(ino, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let mut buffer = vec![std::mem::MaybeUninit::<u8>::uninit(); 64 * 1024];
        let mut raw = RawDir::new(fd.as_fd(), &mut buffer);
        let mut index = 0u64;
        while let Some(entry) = raw.next() {
            let entry = entry.map_err(Errno::from)?;
            let name_bytes = entry.file_name().to_bytes();
            let name = OsString::from_vec(name_bytes.to_vec());
            if name_bytes == b".".as_slice()
                || name_bytes == b"..".as_slice()
                || is_reserved_name(&name)
            {
                continue;
            }
            index += 1;
            if index <= cursor {
                continue;
            }
            sink.push(DirEntry {
                ino: entry.ino(),
                offset: index,
                kind: Kind::from_file_type(entry.file_type()),
                name,
            })?;
        }
        Ok(())
    }

    fn mkdir(&self, parent: InodeId, name: &OsStr, mode: u32) -> Result<InodeId> {
        if is_reserved_name(name) {
            return Err(Errno::EEXIST);
        }
        validate_name(name)?;
        let parent_fd = self.dirfd(parent)?;
        rustix::fs::mkdirat(parent_fd.as_fd(), name, Mode::from_raw_mode(mode))
            .map_err(Errno::from)?;
        let id = InodeId::new_v4();
        if let Err(err) = self.nodes.insert_link(id, parent, name, Kind::Dir) {
            let _ = rustix::fs::unlinkat(parent_fd.as_fd(), name, AtFlags::REMOVEDIR);
            return Err(err);
        }
        Ok(id)
    }

    fn create(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<()> {
        if is_reserved_name(name) {
            return Err(Errno::EEXIST);
        }
        validate_name(name)?;
        let parent_fd = self.dirfd(parent)?;
        let fd = rustix::fs::openat(
            parent_fd.as_fd(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        )?;
        drop(fd);
        if let Err(err) = self.nodes.insert_link(id, parent, name, Kind::File) {
            let _ = rustix::fs::unlinkat(parent_fd.as_fd(), name, AtFlags::empty());
            return Err(err);
        }
        Ok(())
    }

    fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        if is_reserved_name(name) {
            return Err(Errno::EPERM);
        }
        validate_name(name)?;
        let parent_fd = self.dirfd(parent)?;
        rustix::fs::unlinkat(parent_fd.as_fd(), name, AtFlags::empty()).map_err(Errno::from)?;
        let _ = self.nodes.remove_name(parent, name);
        Ok(())
    }

    fn rename(
        &self,
        old: (InodeId, &OsStr),
        new: (InodeId, &OsStr),
        flags: RenameFlags,
    ) -> Result<()> {
        let (old_parent, old_name) = old;
        let (new_parent, new_name) = new;
        if is_reserved_name(old_name) {
            return Err(Errno::EPERM);
        }
        if is_reserved_name(new_name) {
            return Err(Errno::EEXIST);
        }
        validate_name(old_name)?;
        validate_name(new_name)?;
        let old_parent_fd = self.dirfd(old_parent)?;
        let new_parent_fd = self.dirfd(new_parent)?;
        if flags.0 == 0 {
            rustix::fs::renameat(
                old_parent_fd.as_fd(),
                old_name,
                new_parent_fd.as_fd(),
                new_name,
            )
            .map_err(Errno::from)?;
        } else {
            let flags = RxRenameFlags::from_bits_truncate(flags.0);
            rustix::fs::renameat_with(
                old_parent_fd.as_fd(),
                old_name,
                new_parent_fd.as_fd(),
                new_name,
                flags,
            )
            .map_err(Errno::from)?;
        }
        // The index follows the disk; a table miss (bootstrap view) is not an
        // error because the syscall already committed.
        if flags.0 & RenameFlags::EXCHANGE.0 != 0 {
            let _ = self
                .nodes
                .swap_names((old_parent, old_name), (new_parent, new_name));
        } else {
            let _ = self
                .nodes
                .rename_name(old_parent, old_name, new_parent, new_name);
        }
        Ok(())
    }

    fn link(&self, ino: InodeId, newparent: InodeId, newname: &OsStr) -> Result<()> {
        if is_reserved_name(newname) {
            return Err(Errno::EEXIST);
        }
        validate_name(newname)?;
        let (old_parent_fd, old_name) = self.entry(ino)?;
        let new_parent_fd = self.dirfd(newparent)?;
        rustix::fs::linkat(
            old_parent_fd.as_fd(),
            old_name.as_os_str(),
            new_parent_fd.as_fd(),
            newname,
            AtFlags::empty(),
        )
        .map_err(Errno::from)?;
        let kind = self
            .stat_inode(ino)
            .map(|attr| attr.kind())
            .unwrap_or(Kind::Unknown);
        if let Err(err) = self.nodes.insert_link(ino, newparent, newname, kind) {
            let _ = rustix::fs::unlinkat(new_parent_fd.as_fd(), newname, AtFlags::empty());
            return Err(err);
        }
        Ok(())
    }

    fn symlink(&self, parent: InodeId, name: &OsStr, target: &Path) -> Result<()> {
        self.symlink_with_id(parent, name, target, InodeId::new_v4())
            .map(|_| ())
    }

    fn apply_effect(&self, ino: InodeId, eff: &Effect) -> Result<()> {
        match eff {
            Effect::Write { off, data } => self.write_at(ino, *off, data).map(|_| ()),
            Effect::Truncate { size } => self.truncate(ino, *size),
            Effect::SetAttr(delta) => self.set_attr(ino, delta),
            Effect::Xattr { name, value } => self.set_xattr(ino, name, value.as_deref()),
        }
    }

    fn syncfs(&self) -> Result<()> {
        self.root.syncfs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use tempfile::TempDir;

    fn setup(_tag: &str) -> (TempDir, RootFd) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let mountpoint = tmp.path().join("mnt");
        std::fs::create_dir(&mountpoint).unwrap_or_else(|err| panic!("mkdir: {err}"));
        let root =
            RootFd::open_before_mount(&mountpoint).unwrap_or_else(|err| panic!("open root: {err}"));
        (tmp, root)
    }

    fn err<T: std::fmt::Debug>(result: Result<T>) -> Errno {
        match result {
            Ok(value) => panic!("expected an error, got {value:?}"),
            Err(err) => err,
        }
    }

    fn write_file(root: &RootFd, rel: &str, data: &[u8]) {
        let fd = root
            .open_at(
                Path::new(rel),
                OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
                Mode::from_raw_mode(0o644),
            )
            .unwrap_or_else(|err| panic!("open {rel}: {err:?}"));
        let mut written = 0usize;
        while written < data.len() {
            let count = rustix::io::pwrite(&fd, &data[written..], written as u64)
                .unwrap_or_else(|err| panic!("pwrite: {err}"));
            written += count;
        }
    }

    /// 31:M1-2
    #[test]
    fn u_store_rootfd_resolve_relative() {
        let (_tmp, root) = setup("resolve");
        root.mkdir_at(Path::new("a"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        write_file(&root, "a/f", b"hello");
        let fd = root
            .resolve(Path::new("a/f"))
            .unwrap_or_else(|err| panic!("resolve: {err:?}"));
        let stat = rustix::fs::fstat(&fd).unwrap_or_else(|err| panic!("fstat: {err}"));
        assert_eq!(stat.st_size, 5);
        assert_eq!(
            root.stat_at(Path::new("a/f"), false)
                .unwrap_or_else(|err| panic!("stat: {err:?}"))
                .size,
            5
        );
        assert_eq!(
            root.stat_at(Path::new("a/f"), false)
                .unwrap_or_else(|err| panic!("stat: {err:?}"))
                .kind(),
            Kind::File
        );
    }

    /// C-10
    #[test]
    fn u_store_rootfd_rejects_path_escape() {
        let (tmp, root) = setup("escape");
        std::fs::write(tmp.path().join("outside"), b"secret")
            .unwrap_or_else(|err| panic!("write outside: {err}"));

        assert_eq!(err(root.resolve(Path::new("../outside"))), Errno::EXDEV);
        assert_eq!(err(root.resolve(Path::new("/etc/passwd"))), Errno::EXDEV);
        assert_eq!(
            err(root.open_at(Path::new("a/../b"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );

        root.symlink_at(Path::new("../outside"), Path::new("link"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            err(root.open_at(Path::new("link"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );
        root.symlink_at(Path::new("/etc/passwd"), Path::new("abs-link"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            err(root.open_at(Path::new("abs-link"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );
    }

    /// C-10 / 41 §2.3: resolution goes through `openat2(RESOLVE_BENEATH)`.
    #[test]
    fn u_store_rootfd_openat2_resolve_beneath() {
        let (tmp, root) = setup("openat2");
        root.mkdir_at(Path::new("inner"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        write_file(&root, "inner/ok", b"x");
        let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        let fd = rustix::fs::openat2(
            root.at(),
            "inner/ok",
            OFlags::RDONLY,
            Mode::empty(),
            resolve,
        )
        .unwrap_or_else(|err| panic!("openat2: {err}"));
        let mut buf = [0u8; 1];
        assert_eq!(
            rustix::io::pread(&fd, &mut buf, 0).unwrap_or_else(|err| panic!("pread: {err}")),
            1
        );

        std::fs::write(tmp.path().join("outside"), b"secret")
            .unwrap_or_else(|err| panic!("write outside: {err}"));
        root.symlink_at(Path::new("../../outside"), Path::new("inner/up"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        let escaped = rustix::fs::openat2(
            root.at(),
            "inner/up",
            OFlags::RDONLY,
            Mode::empty(),
            resolve,
        )
        .map_err(Errno::from);
        assert_eq!(err(escaped), Errno::EXDEV);
        assert_eq!(
            err(root.open_at(Path::new("inner/up"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );
    }

    /// C-10: a symlink may resolve inside the tree but never outside it.
    #[test]
    fn u_store_rootfd_rejects_symlink_escape() {
        let (tmp, root) = setup("symlink-escape");
        root.mkdir_at(Path::new("inner"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        write_file(&root, "target", b"inside");
        std::fs::write(tmp.path().join("outside"), b"secret")
            .unwrap_or_else(|err| panic!("write outside: {err}"));

        root.symlink_at(Path::new("../../outside"), Path::new("inner/up"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            err(root.open_at(Path::new("inner/up"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );

        root.symlink_at(Path::new("/etc/passwd"), Path::new("inner/abs"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            err(root.open_at(Path::new("inner/abs"), OFlags::RDONLY, Mode::empty())),
            Errno::EXDEV
        );

        root.symlink_at(Path::new("loop"), Path::new("loop"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            err(root.open_at(Path::new("loop"), OFlags::RDONLY, Mode::empty())),
            Errno::ELOOP
        );

        root.symlink_at(Path::new("../target"), Path::new("inner/inside"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        let fd = root
            .open_at(Path::new("inner/inside"), OFlags::RDONLY, Mode::empty())
            .unwrap_or_else(|err| panic!("open inside: {err:?}"));
        let mut buf = [0u8; 6];
        assert_eq!(
            rustix::io::pread(&fd, &mut buf, 0).unwrap_or_else(|err| panic!("pread: {err}")),
            6
        );
        assert_eq!(&buf, b"inside");
    }

    /// 41 §2.3: `sync_fd` answers `fstatfs` and `syncfs`.
    #[test]
    fn u_store_rootfd_statfs_and_sync_fd() {
        let (_tmp, root) = setup("statfs");
        let stat = root
            .statfs()
            .unwrap_or_else(|err| panic!("statfs: {err:?}"));
        assert_ne!(stat.f_type, 0);
        let direct =
            rustix::fs::fstatfs(root.sync_fd()).unwrap_or_else(|err| panic!("fstatfs: {err}"));
        assert_eq!(direct.f_type, stat.f_type);
        root.syncfs()
            .unwrap_or_else(|err| panic!("syncfs: {err:?}"));
    }

    /// 31:M1-2
    #[test]
    fn u_store_rootfd_allows_internal_symlink() {
        let (_tmp, root) = setup("symlink");
        write_file(&root, "target", b"data");
        root.symlink_at(Path::new("target"), Path::new("link"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            root.readlink_at(Path::new("link"))
                .unwrap_or_else(|err| panic!("readlink: {err:?}")),
            PathBuf::from("target")
        );
        let fd = root
            .open_at(Path::new("link"), OFlags::RDONLY, Mode::empty())
            .unwrap_or_else(|err| panic!("open link: {err:?}"));
        let mut buf = [0u8; 4];
        let count =
            rustix::io::pread(&fd, &mut buf, 0).unwrap_or_else(|err| panic!("pread: {err}"));
        assert_eq!(count, 4);
        assert_eq!(&buf, b"data");
    }

    /// 31:M1-2
    #[test]
    fn u_store_rootfd_rename() {
        let (_tmp, root) = setup("rename");
        write_file(&root, "old", b"x");
        root.rename_at(Path::new("old"), Path::new("new"), RenameFlags::NONE)
            .unwrap_or_else(|err| panic!("rename: {err:?}"));
        assert_eq!(err(root.stat_at(Path::new("old"), false)), Errno::ENOENT);
        assert_eq!(
            root.stat_at(Path::new("new"), false)
                .unwrap_or_else(|err| panic!("stat: {err:?}"))
                .size,
            1
        );

        write_file(&root, "other", b"y");
        assert_eq!(
            err(root.rename_at(Path::new("new"), Path::new("other"), RenameFlags::NOREPLACE)),
            Errno::EEXIST
        );
    }

    /// 31:M1-2
    #[test]
    fn u_store_rootfd_unlink() {
        let (_tmp, root) = setup("unlink");
        write_file(&root, "file", b"data");
        root.unlink_at(Path::new("file"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        assert_eq!(err(root.stat_at(Path::new("file"), false)), Errno::ENOENT);

        root.mkdir_at(Path::new("dir"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        assert!(root.unlink_at(Path::new("dir")).is_err());
        root.rmdir_at(Path::new("dir"))
            .unwrap_or_else(|err| panic!("rmdir: {err:?}"));
    }

    /// C-10
    #[test]
    fn u_store_rootfd_survives_path_replacement() {
        // The mount(2) invariant: once the fd exists, the path may name a
        // different tree and the fd still sees the original one.
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let mountpoint = tmp.path().join("mnt");
        std::fs::create_dir(&mountpoint).unwrap_or_else(|err| panic!("mkdir: {err}"));
        std::fs::write(mountpoint.join("before"), b"1")
            .unwrap_or_else(|err| panic!("write: {err}"));
        let root =
            RootFd::open_before_mount(&mountpoint).unwrap_or_else(|err| panic!("open root: {err}"));

        let moved = tmp.path().join("moved");
        std::fs::rename(&mountpoint, &moved).unwrap_or_else(|err| panic!("rename: {err}"));
        std::fs::create_dir(&mountpoint).unwrap_or_else(|err| panic!("mkdir: {err}"));
        std::fs::write(mountpoint.join("after"), b"2").unwrap_or_else(|err| panic!("write: {err}"));

        assert_eq!(
            root.stat_at(Path::new("before"), false)
                .unwrap_or_else(|err| panic!("stat: {err:?}"))
                .size,
            1
        );
        assert_eq!(err(root.stat_at(Path::new("after"), false)), Errno::ENOENT);
        root.mkdir_at(Path::new("created"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        assert!(moved.join("created").is_dir());
        assert!(!mountpoint.join("created").exists());
    }

    /// 31:M1-2
    #[test]
    fn u_store_open_fd_survives_unlink() {
        let (_tmp, root) = setup("fd-life");
        write_file(&root, "file", b"hello");
        let fd = root
            .open_at(Path::new("file"), OFlags::RDONLY, Mode::empty())
            .unwrap_or_else(|err| panic!("open: {err:?}"));
        root.unlink_at(Path::new("file"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        let mut buf = [0u8; 5];
        let count =
            rustix::io::pread(&fd, &mut buf, 0).unwrap_or_else(|err| panic!("pread: {err}"));
        assert_eq!(count, 5);
        assert_eq!(&buf, b"hello");
        let _ = fd.as_raw_fd();
    }

    /// 31:M1-3
    #[test]
    fn u_store_rootfd_stat_list_walk() {
        let (_tmp, root) = setup("walk");
        root.mkdir_at(Path::new("a"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        root.mkdir_at(Path::new("a/b"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        write_file(&root, "a/b/c", b"x");
        root.symlink_at(Path::new("a"), Path::new("link-dir"))
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));

        let mut names: Vec<_> = root
            .list_at(Path::new("."))
            .unwrap_or_else(|err| panic!("list: {err:?}"))
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort();
        assert_eq!(names, vec![OsString::from("a"), OsString::from("link-dir")]);

        let walked = root
            .walk_at(Path::new("."))
            .unwrap_or_else(|err| panic!("walk: {err:?}"));
        let paths: Vec<_> = walked.iter().map(|(path, _)| path.clone()).collect();
        assert!(paths.contains(&PathBuf::from(".")));
        assert!(paths.contains(&PathBuf::from("a")));
        assert!(paths.contains(&PathBuf::from("a/b")));
        assert!(paths.contains(&PathBuf::from("a/b/c")));
        assert!(paths.contains(&PathBuf::from("link-dir")));
        assert!(!paths.contains(&PathBuf::from("link-dir/b")));
        let link_attr = walked
            .iter()
            .find(|(path, _)| path == Path::new("link-dir"))
            .map(|(_, attr)| *attr)
            .unwrap_or_else(|| panic!("link-dir missing"));
        assert_eq!(link_attr.kind(), Kind::Symlink);
    }

    fn backing(_tag: &str) -> (TempDir, PosixBacking) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let mountpoint = tmp.path().join("mnt");
        std::fs::create_dir(&mountpoint).unwrap_or_else(|err| panic!("mkdir: {err}"));
        let root =
            RootFd::open_before_mount(&mountpoint).unwrap_or_else(|err| panic!("open root: {err}"));
        (tmp, PosixBacking::new(root))
    }

    fn make_file(backing: &PosixBacking, parent: InodeId, name: &str) -> InodeId {
        let id = InodeId::new_v4();
        backing
            .create(parent, OsStr::new(name), id, 0o644)
            .unwrap_or_else(|err| panic!("create: {err:?}"));
        id
    }

    #[derive(Default)]
    struct VecSink {
        entries: Vec<DirEntry>,
    }

    impl DirSink for VecSink {
        fn push(&mut self, entry: DirEntry) -> Result<()> {
            self.entries.push(entry);
            Ok(())
        }
    }

    /// 31:M1-2
    #[test]
    fn u_store_backing_write_read_truncate() {
        let (_tmp, backing) = backing("rw");
        let dir = backing
            .mkdir(InodeId::ROOT, OsStr::new("d"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        let file = make_file(&backing, dir, "f");
        assert_eq!(
            backing
                .write_at(file, 0, b"hello world")
                .unwrap_or_else(|err| panic!("write: {err:?}")),
            11
        );
        let mut buf = [0u8; 5];
        assert_eq!(
            backing
                .read_at(file, 6, &mut buf)
                .unwrap_or_else(|err| panic!("read: {err:?}")),
            5
        );
        assert_eq!(&buf, b"world");
        backing
            .truncate(file, 5)
            .unwrap_or_else(|err| panic!("truncate: {err:?}"));
        assert_eq!(
            backing
                .getattr(file)
                .unwrap_or_else(|err| panic!("getattr: {err:?}"))
                .size,
            5
        );
        assert_eq!(
            backing
                .read_at(file, 5, &mut buf)
                .unwrap_or_else(|err| panic!("read: {err:?}")),
            0
        );
        assert_eq!(
            backing
                .write_at(file, 0, b"x")
                .unwrap_or_else(|err| panic!("write: {err:?}")),
            1
        );
        assert_eq!(
            backing
                .getattr(file)
                .unwrap_or_else(|err| panic!("getattr: {err:?}"))
                .size,
            5
        );
    }

    /// 31:M1-2
    #[test]
    fn u_store_backing_rename_and_unlink() {
        let (_tmp, backing) = backing("rename");
        let dir = backing
            .mkdir(InodeId::ROOT, OsStr::new("d"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        let file = make_file(&backing, dir, "f");
        backing
            .write_at(file, 0, b"data")
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        backing
            .rename(
                (dir, OsStr::new("f")),
                (InodeId::ROOT, OsStr::new("g")),
                RenameFlags::NONE,
            )
            .unwrap_or_else(|err| panic!("rename: {err:?}"));
        assert_eq!(
            backing
                .lookup(InodeId::ROOT, OsStr::new("g"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .size,
            4
        );
        assert_eq!(err(backing.lookup(dir, OsStr::new("f"))), Errno::ENOENT);
        assert_eq!(backing.nodes().path_of(file), Some(PathBuf::from("g")));

        let other = make_file(&backing, InodeId::ROOT, "h");
        backing
            .write_at(other, 0, b"zz")
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        backing
            .rename(
                (InodeId::ROOT, OsStr::new("g")),
                (InodeId::ROOT, OsStr::new("h")),
                RenameFlags::EXCHANGE,
            )
            .unwrap_or_else(|err| panic!("exchange: {err:?}"));
        assert_eq!(
            backing
                .lookup(InodeId::ROOT, OsStr::new("g"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .size,
            2
        );
        assert_eq!(
            backing
                .lookup(InodeId::ROOT, OsStr::new("h"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .size,
            4
        );
        assert_eq!(backing.nodes().path_of(file), Some(PathBuf::from("h")));

        backing
            .unlink(InodeId::ROOT, OsStr::new("h"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        assert_eq!(err(backing.getattr(file)), Errno::ENOENT);
    }

    /// C-10
    #[test]
    fn u_store_backing_reserved_names_are_invisible_and_immutable() {
        let (_tmp, backing) = backing("reserved");
        make_file(&backing, InodeId::ROOT, "f");
        assert_eq!(
            err(backing.mkdir(InodeId::ROOT, OsStr::new(".syncmount-staging"), 0o700)),
            Errno::EEXIST
        );
        assert_eq!(
            err(backing.lookup(InodeId::ROOT, OsStr::new(".audit.log"))),
            Errno::ENOENT
        );
        backing
            .root()
            .mkdir_at(Path::new(".syncmount-staging"), 0o700)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        let mut sink = VecSink::default();
        backing
            .readdir(InodeId::ROOT, 0, &mut sink)
            .unwrap_or_else(|err| panic!("readdir: {err:?}"));
        assert!(
            sink.entries
                .iter()
                .all(|entry| entry.name != OsStr::new(".syncmount-staging"))
        );
        assert_eq!(
            err(backing.rename(
                (InodeId::ROOT, OsStr::new("f")),
                (InodeId::ROOT, OsStr::new(".syncmount-staging")),
                RenameFlags::NONE,
            )),
            Errno::EEXIST
        );
        assert_eq!(
            err(backing.rename(
                (InodeId::ROOT, OsStr::new(".audit.log")),
                (InodeId::ROOT, OsStr::new("g")),
                RenameFlags::NONE,
            )),
            Errno::EPERM
        );
        assert_eq!(
            err(backing.unlink(InodeId::ROOT, OsStr::new(".audit.log"))),
            Errno::EPERM
        );
        assert_eq!(
            backing
                .lookup(InodeId::ROOT, OsStr::new("f"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .kind(),
            Kind::File
        );
    }

    /// 41 §2.3: metadata operations reuse the parent directory descriptor.
    #[test]
    fn u_store_backing_dirfd_cache_is_used_and_invalidated() {
        let (_tmp, backing) = backing("dirfd");
        let dir = backing
            .mkdir(InodeId::ROOT, OsStr::new("d"), 0o755)
            .unwrap_or_else(|err| panic!("mkdir: {err:?}"));
        assert!(backing.nodes().dirfd(InodeId::ROOT).is_some());
        let file = make_file(&backing, dir, "f");
        assert!(backing.nodes().dirfd(dir).is_some());
        assert_eq!(
            backing
                .lookup(dir, OsStr::new("f"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .size,
            0
        );

        // A rename keeps the descriptor valid: it names the same inode.
        backing
            .rename(
                (InodeId::ROOT, OsStr::new("d")),
                (InodeId::ROOT, OsStr::new("e")),
                RenameFlags::NONE,
            )
            .unwrap_or_else(|err| panic!("rename: {err:?}"));
        assert!(backing.nodes().dirfd(dir).is_some());
        assert_eq!(
            backing
                .lookup(dir, OsStr::new("f"))
                .unwrap_or_else(|err| panic!("lookup: {err:?}"))
                .kind(),
            Kind::File
        );

        // Dropping the last link drops the node and its cached descriptor.
        backing
            .unlink(dir, OsStr::new("f"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        backing
            .root()
            .rmdir_at(Path::new("e"))
            .unwrap_or_else(|err| panic!("rmdir: {err:?}"));
        let _ = backing.nodes().remove_name(InodeId::ROOT, OsStr::new("e"));
        assert!(backing.nodes().dirfd(dir).is_none());
        assert!(backing.nodes().path_of(file).is_none());
    }

    /// 31:M1-3
    #[test]
    fn u_store_backing_readdir_and_cursor() {
        let (_tmp, backing) = backing("readdir");
        for name in ["a", "b", "c"] {
            make_file(&backing, InodeId::ROOT, name);
        }
        let mut sink = VecSink::default();
        backing
            .readdir(InodeId::ROOT, 0, &mut sink)
            .unwrap_or_else(|err| panic!("readdir: {err:?}"));
        assert_eq!(sink.entries.len(), 3);
        assert_eq!(
            sink.entries
                .iter()
                .map(|entry| entry.offset)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let mut sink = VecSink::default();
        backing
            .readdir(InodeId::ROOT, 2, &mut sink)
            .unwrap_or_else(|err| panic!("readdir: {err:?}"));
        assert_eq!(sink.entries.len(), 1);
        assert_eq!(sink.entries[0].offset, 3);
        let mut sink = VecSink::default();
        backing
            .readdir(InodeId::ROOT, 99, &mut sink)
            .unwrap_or_else(|err| panic!("readdir: {err:?}"));
        assert!(sink.entries.is_empty());
    }

    /// 31:M1-2
    #[test]
    fn u_store_backing_hardlink() {
        let (_tmp, backing) = backing("link");
        let file = make_file(&backing, InodeId::ROOT, "a");
        backing
            .write_at(file, 0, b"payload")
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        backing
            .link(file, InodeId::ROOT, OsStr::new("b"))
            .unwrap_or_else(|err| panic!("link: {err:?}"));
        assert_eq!(
            backing
                .getattr(file)
                .unwrap_or_else(|err| panic!("getattr: {err:?}"))
                .nlink,
            2
        );
        assert_eq!(backing.nodes().nlink(file), 2);
        backing
            .unlink(InodeId::ROOT, OsStr::new("a"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        assert_eq!(
            backing
                .getattr(file)
                .unwrap_or_else(|err| panic!("getattr: {err:?}"))
                .nlink,
            1
        );
        backing
            .unlink(InodeId::ROOT, OsStr::new("b"))
            .unwrap_or_else(|err| panic!("unlink: {err:?}"));
        assert_eq!(err(backing.getattr(file)), Errno::ENOENT);
    }

    /// 31:M1-3
    #[test]
    fn u_store_backing_setattr_and_fsync() {
        let (_tmp, backing) = backing("setattr");
        let file = make_file(&backing, InodeId::ROOT, "f");
        backing
            .write_at(file, 0, b"abcdef")
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        let delta = AttrDelta {
            mode: Some(0o600),
            size: Some(3),
            atime: Some(Timespec::new(1_700_000_000, 1)),
            mtime: Some(Timespec::new(1_700_000_001, 2)),
            ..AttrDelta::default()
        };
        backing
            .set_attr(file, &delta)
            .unwrap_or_else(|err| panic!("set_attr: {err:?}"));
        let attr = backing
            .getattr(file)
            .unwrap_or_else(|err| panic!("getattr: {err:?}"));
        assert_eq!(attr.size, 3);
        assert_eq!(attr.perm(), 0o600);
        assert_eq!(attr.atime, Timespec::new(1_700_000_000, 1));
        assert_eq!(attr.mtime, Timespec::new(1_700_000_001, 2));
        backing
            .fsync(file, false)
            .unwrap_or_else(|err| panic!("fsync: {err:?}"));
        backing
            .fsync(file, true)
            .unwrap_or_else(|err| panic!("fdatasync: {err:?}"));

        // A write-only file cannot be reopened for reading; `fsync` must use
        // the write side instead of failing with EACCES.
        let write_only = make_file(&backing, InodeId::ROOT, "wo");
        backing
            .write_at(write_only, 0, b"x")
            .unwrap_or_else(|err| panic!("write: {err:?}"));
        backing
            .set_attr(
                write_only,
                &AttrDelta {
                    mode: Some(0o200),
                    ..AttrDelta::default()
                },
            )
            .unwrap_or_else(|err| panic!("chmod: {err:?}"));
        backing
            .fsync(write_only, false)
            .unwrap_or_else(|err| panic!("fsync write-only: {err:?}"));
    }

    /// 31:M1-2
    #[test]
    fn u_store_backing_symlink_and_effect() {
        let (_tmp, backing) = backing("effect");
        let file = make_file(&backing, InodeId::ROOT, "f");
        backing
            .apply_effect(
                file,
                &Effect::Write {
                    off: 0,
                    data: b"0123456789".to_vec(),
                },
            )
            .unwrap_or_else(|err| panic!("effect write: {err:?}"));
        backing
            .apply_effect(file, &Effect::Truncate { size: 4 })
            .unwrap_or_else(|err| panic!("effect truncate: {err:?}"));
        let mut buf = [0u8; 4];
        backing
            .read_at(file, 0, &mut buf)
            .unwrap_or_else(|err| panic!("read: {err:?}"));
        assert_eq!(&buf, b"0123");

        let link = backing
            .symlink_with_id(
                InodeId::ROOT,
                OsStr::new("link"),
                Path::new("f"),
                InodeId::new_v4(),
            )
            .unwrap_or_else(|err| panic!("symlink: {err:?}"));
        assert_eq!(
            backing
                .getattr(link)
                .unwrap_or_else(|err| panic!("getattr: {err:?}"))
                .kind(),
            Kind::Symlink
        );
    }
}
