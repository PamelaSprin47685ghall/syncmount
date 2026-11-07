//! The `fuser::Filesystem` adapter.
//!
//! Every callback translates one kernel request into one [`BackingStore`]
//! call and one reply. W13a is the local callback surface; W13b attaches the
//! write path: mutating callbacks first check [`WriteGate`], then apply the
//! change to the local tree, then enqueue a [`LocalOp`] in the [`Outbox`].
//! Reads never leave the local tree and never touch the network (41 §4).
//!
//! There is no per-open state and no replay state here. The replayer owns
//! `S(seq)` and materialises remote operations through [`super::ReplayView`],
//! which invalidates the kernel view after the disk has changed.
//!
//! [`BackingStore`] covers the nine F-a callbacks plus the namespace
//! operations. A few POSIX callbacks (`readlink`, xattr, `statfs`, `access`,
//! `fallocate`, `copy_file_range`, `lseek`, `rmdir`, `mknod`) are not on the
//! frozen trait; [`FuseBacking`] adds them so the adapter can still answer
//! them without inventing a second path-based backing API. `PosixBacking`
//! implements the extension over its root descriptor and node table.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, FileAttr, FileHandle, Filesystem, FopenFlags,
    INodeNo, InitFlags, IoctlFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl,
    ReplyLock, ReplyLseek, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    WriteFlags,
};
use rustix::fs::{Access, AtFlags, FallocateFlags, Mode, OFlags, SeekFrom, XattrFlags};
use rustix::io::Errno as RxErrno;

use crate::client::ReplayBacking;
use crate::client::replayer::{
    LOCK_ACTION_SET, LOCK_ACTION_UNLOCK, Lock, LockKey, LockType, derive_inode_id,
};
use crate::fuse::ino::{
    ATTR_TTL, ENTRY_TTL, GENERATION, file_attr, file_type, id_of, ino_of, timespec,
};
use crate::fuse::notify::Notify;
use crate::fuse::write_path::{MetaArgs, MetaOwner, WritePath, absolute_path, child_path};
use crate::protocol::messages::OpClass;
use crate::store::node_table::{InodeId, validate_name};
use crate::store::{
    AttrDelta, BackingStore, DirEntry, DirSink, Errno, Kind, NodeTable, PosixBacking,
    RenameFlags as StoreRenameFlags, Result, RootFd, is_reserved_name,
};

/// Capabilities requested from the kernel.
///
/// `DO_READDIRPLUS` and `PARALLEL_DIROPS` are always negotiated. POSIX record
/// locks are added by [`FuseFs::capabilities`] for a cluster mount, whose
/// write path carries a [`crate::client::SyncHandle`]: then `getlk`/`setlk`
/// reach the deterministic lock table. BSD `flock` stays local (49 A10), and
/// writeback cache, direct I/O and passthrough are never negotiated.
pub const INIT_CAPABILITIES: InitFlags =
    InitFlags::FUSE_DO_READDIRPLUS.union(InitFlags::FUSE_PARALLEL_DIROPS);

/// Maximum write size requested from the kernel (1 MiB).
const MAX_WRITE: u32 = 1024 * 1024;

/// Chunk used by the `fallocate`/`copy_file_range` fallbacks.
const IO_CHUNK: usize = 64 * 1024;

/// Sentinel returned by a directory sink when the reply buffer is full.
///
/// `Errno(0)` can never come from a syscall, so the adapter can distinguish
/// "stop enumerating" from a real error without adding a second sink trait.
const SINK_FULL: Errno = Errno(0);

/// `ERANGE` is not on [`Errno`]'s named list; xattr replies need it.
const ERANGE: Errno = Errno(libc::ERANGE);
/// The callbacks `fuser` exposes but the frozen [`BackingStore`] does not.
///
/// The FUSE adapter is the only caller that needs them today. Keeping them
/// in this crate-local trait avoids changing the frozen store contract while
/// still giving the adapter a single, inode-based door to the backing tree.
pub trait FuseBacking: BackingStore + ReplayBacking {
    /// The node table used for `INodeNo` ↔ [`InodeId`].
    fn nodes(&self) -> &NodeTable;

    /// Read a symbolic-link target.
    fn readlink(&self, ino: InodeId) -> Result<PathBuf>;

    /// Read one extended attribute.
    fn getxattr(&self, ino: InodeId, name: &OsStr) -> Result<Vec<u8>>;

    /// List extended-attribute names as a NUL-separated buffer.
    fn listxattr(&self, ino: InodeId) -> Result<Vec<u8>>;

    /// Set or replace one extended attribute.
    fn setxattr(&self, ino: InodeId, name: &OsStr, value: &[u8], flags: i32) -> Result<()>;

    /// Remove one extended attribute.
    fn removexattr(&self, ino: InodeId, name: &OsStr) -> Result<()>;

    /// Statistics of the backing filesystem.
    fn statfs(&self) -> Result<rustix::fs::StatFs>;

    /// Check access permissions against the backing file.
    fn access(&self, ino: InodeId, mask: i32) -> Result<()>;

    /// Preallocate, punch, or zero a range.
    fn fallocate(&self, ino: InodeId, offset: u64, length: u64, mode: i32) -> Result<()>;

    /// Copy a byte range between two backing inodes.
    fn copy_range(
        &self,
        ino_in: InodeId,
        off_in: u64,
        ino_out: InodeId,
        off_out: u64,
        len: u64,
    ) -> Result<u64>;

    /// Reposition or query a file offset.
    fn lseek(&self, ino: InodeId, offset: i64, whence: i32) -> Result<i64>;

    /// Remove an empty directory.
    fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<()>;

    /// Create a FIFO (or a regular file through `create`).
    fn mknod(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32, rdev: u32)
    -> Result<()>;
}

/// The local FUSE filesystem.
///
/// `B` is normally [`PosixBacking`]; tests may substitute another backing as
/// long as it provides the identity-preserving replay operations too.
pub struct FuseFs<B: FuseBacking + ?Sized> {
    store: Arc<B>,
    notify: Notify,
    path: Option<WritePath>,
}

impl<B: FuseBacking + ?Sized> fmt::Debug for FuseFs<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuseFs")
            .field("store", &std::any::type_name::<B>())
            .field("notify", &self.notify)
            .field("write_path", &self.path.is_some())
            .finish()
    }
}

impl<B: FuseBacking + ?Sized> FuseFs<B> {
    /// Build an adapter over a shared backing store.
    ///
    /// Without a [`WritePath`] every callback is W13a's local surface: it
    /// changes the backing tree and nothing else. The mount driver uses
    /// [`FuseFs::with_write_path`] instead.
    pub fn new(store: Arc<B>) -> Self {
        Self {
            store,
            notify: Notify::new(),
            path: None,
        }
    }

    /// Build an adapter whose mutations also enter the client outbox.
    pub fn with_write_path(store: Arc<B>, path: WritePath) -> Self {
        Self {
            store,
            notify: Notify::new(),
            path: Some(path),
        }
    }

    /// The backing store.
    pub fn store(&self) -> &Arc<B> {
        &self.store
    }

    /// The write path, when this mount is attached to a client.
    pub fn write_path(&self) -> Option<&WritePath> {
        self.path.as_ref()
    }

    /// The invalidation handle. The mount driver attaches the session
    /// notifier to it before the first request is served.
    pub fn notify(&self) -> &Notify {
        &self.notify
    }

    /// A clone of the invalidation handle, safe to keep after the adapter is
    /// moved into the mount session.
    pub fn notify_handle(&self) -> Notify {
        self.notify.clone()
    }

    /// Whether a replay engine arbitrates metadata and record locks.
    pub fn arbitrated(&self) -> bool {
        self.path.as_ref().is_some_and(WritePath::arbitrated)
    }

    /// The capabilities this mount negotiates.
    ///
    /// The kernel fixes these at INIT, which runs before the JOIN; the
    /// presence of the client handle is therefore the deciding fact, not
    /// whether the replayer is live yet.
    pub fn capabilities(&self) -> InitFlags {
        if self.path.as_ref().is_some_and(WritePath::has_sync) {
            INIT_CAPABILITIES | InitFlags::FUSE_POSIX_LOCKS
        } else {
            INIT_CAPABILITIES
        }
    }

    fn id(&self, ino: INodeNo) -> Result<InodeId> {
        id_of(self.store.nodes(), ino)
    }

    fn attr_of(&self, id: InodeId) -> Result<FileAttr> {
        let attr = self.store.getattr(id)?;
        file_attr(self.store.nodes(), id, &attr)
    }

    /// Fetch attributes and account for the kernel reference an entry reply
    /// creates.
    fn entry_of(&self, id: InodeId) -> Result<FileAttr> {
        let attr = self.attr_of(id)?;
        self.store.nodes().touch_lookup(id);
        Ok(attr)
    }

    fn lookup_inner(&self, parent: INodeNo, name: &OsStr) -> Result<(FileAttr, InodeId)> {
        lookup_name(name)?;
        let parent = self.id(parent)?;
        if let Some(id) = self.store.nodes().lookup(parent, name) {
            let attr = self.attr_of(id)?;
            self.store.nodes().touch_lookup(id);
            return Ok((attr, id));
        }

        let attr = self.store.lookup(parent, name)?;
        let candidate = InodeId::new_v4();
        let id = match self
            .store
            .nodes()
            .insert_link(candidate, parent, name, attr.kind())
        {
            Ok(()) => candidate,
            Err(err) if err == Errno::EEXIST => {
                self.store.nodes().lookup(parent, name).ok_or(Errno::EIO)?
            }
            Err(err) => return Err(err),
        };
        let attr = if id == candidate {
            attr
        } else {
            self.store.getattr(id)?
        };
        let attr = file_attr(self.store.nodes(), id, &attr)?;
        self.store.nodes().touch_lookup(id);
        Ok((attr, id))
    }

    fn getattr_inner(&self, ino: INodeNo) -> Result<FileAttr> {
        self.attr_of(self.id(ino)?)
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr_inner(
        &self,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr> {
        let id = self.id(ino)?;
        let mut delta = AttrDelta {
            mode,
            uid,
            gid,
            size,
            ..AttrDelta::default()
        };
        if let Some(time) = atime {
            delta.atime = Some(time_or_now(time));
        }
        if let Some(time) = mtime {
            delta.mtime = Some(time_or_now(time));
        }
        match &self.path {
            Some(path) => path.set_attr(self.store.as_ref(), id, &delta)?,
            None => BackingStore::set_attr(self.store.as_ref(), id, &delta)?,
        }
        self.attr_of(id)
    }

    fn readlink_inner(&self, ino: INodeNo) -> Result<PathBuf> {
        self.store.readlink(self.id(ino)?)
    }

    fn mknod_inner(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
    ) -> Result<FileAttr> {
        create_name(name)?;
        if let Some(path) = &self.path {
            // Special files have no v1 op class (39 §4 allows them as
            // best-effort), but the gate still applies to the local change.
            path.gate().check_write()?;
        }
        let parent = self.id(parent)?;
        let mode = mode & !umask;
        let kind = Kind::from_mode(mode);
        match kind {
            Kind::File => {
                let id = InodeId::new_v4();
                BackingStore::create(self.store.as_ref(), parent, name, id, mode)?;
                self.entry_of(id)
            }
            Kind::Fifo => {
                let id = InodeId::new_v4();
                self.store.mknod(parent, name, id, mode, rdev)?;
                self.entry_of(id)
            }
            // Device nodes and sockets are outside the accepted v1 surface;
            // the error is deterministic rather than a silent partial create.
            Kind::Char | Kind::Block | Kind::Socket => Err(Errno::EPERM),
            Kind::Dir | Kind::Symlink | Kind::Unknown => Err(Errno::EPERM),
        }
    }

    fn mkdir_inner(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let mode = mode & !umask;
        let Some(path) = &self.path else {
            let id = BackingStore::mkdir(self.store.as_ref(), parent, name, mode)?;
            return self.entry_of(id);
        };
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        // The replay engine derives the same identity from the op id (41 R6).
        let id = derive_inode_id(admission.op_id);
        if let Err(err) = ReplayBacking::mkdir(self.store.as_ref(), parent, name, id, mode) {
            admission.abort();
            return Err(err);
        }
        let attr = self.store.getattr(id)?;
        let fuse_attr = file_attr(self.store.nodes(), id, &attr)?;
        self.store.nodes().touch_lookup(id);
        path.commit_meta(
            admission,
            OpClass::MKDIR,
            Some(id),
            target,
            MetaArgs::Mode(mode),
            MetaOwner::from_attr(&attr),
        )?;
        Ok(fuse_attr)
    }

    fn unlink_inner(&self, parent: INodeNo, name: &OsStr) -> Result<()> {
        lookup_name(name)?;
        let parent = self.id(parent)?;
        let Some(path) = &self.path else {
            return BackingStore::unlink(self.store.as_ref(), parent, name);
        };
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let attr = self.store.lookup(parent, name)?;
        let id = self.store.nodes().lookup(parent, name);
        if let Err(err) = BackingStore::unlink(self.store.as_ref(), parent, name) {
            admission.abort();
            return Err(err);
        }
        path.commit_meta(
            admission,
            OpClass::UNLINK,
            id,
            target,
            MetaArgs::None,
            MetaOwner::from_attr(&attr),
        )
    }

    fn rmdir_inner(&self, parent: INodeNo, name: &OsStr) -> Result<()> {
        lookup_name(name)?;
        let parent = self.id(parent)?;
        let Some(path) = &self.path else {
            return FuseBacking::rmdir(self.store.as_ref(), parent, name);
        };
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let attr = self.store.lookup(parent, name)?;
        let id = self.store.nodes().lookup(parent, name);
        if let Err(err) = FuseBacking::rmdir(self.store.as_ref(), parent, name) {
            admission.abort();
            return Err(err);
        }
        path.commit_meta(
            admission,
            OpClass::RMDIR,
            id,
            target,
            MetaArgs::None,
            MetaOwner::from_attr(&attr),
        )
    }

    fn symlink_inner(&self, parent: INodeNo, name: &OsStr, target: &Path) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let Some(path) = &self.path else {
            BackingStore::symlink(self.store.as_ref(), parent, name, target)?;
            let id = ensure_child(self.store.as_ref(), parent, name, Kind::Symlink)?;
            return self.entry_of(id);
        };
        let admission = path.admit(0)?;
        let link = child_path(self.store.nodes(), parent, name)?;
        let contents = target.to_str().ok_or(Errno::EINVAL)?;
        let id = derive_inode_id(admission.op_id);
        if let Err(err) = ReplayBacking::symlink(self.store.as_ref(), parent, name, id, target) {
            admission.abort();
            return Err(err);
        }
        let attr = self.store.getattr(id)?;
        let fuse_attr = file_attr(self.store.nodes(), id, &attr)?;
        self.store.nodes().touch_lookup(id);
        path.commit_meta(
            admission,
            OpClass::SYMLINK,
            Some(id),
            link,
            MetaArgs::Symlink { target: contents },
            MetaOwner::from_attr(&attr),
        )?;
        Ok(fuse_attr)
    }

    fn rename_inner(
        &self,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
    ) -> Result<()> {
        rename_names(name, newname)?;
        let old_parent = self.id(parent)?;
        let new_parent = self.id(newparent)?;
        if let Some(path) = &self.path {
            path.gate().check_write()?;
            // A two-way exchange is not a single RENAME op; fail closed
            // instead of broadcasting half of it.
            if flags.contains(RenameFlags::RENAME_EXCHANGE) {
                return Err(Errno::EOPNOTSUPP);
            }
            let admission = path.admit(0)?;
            let old_path = child_path(self.store.nodes(), old_parent, name)?;
            let new_path = child_path(self.store.nodes(), new_parent, newname)?;
            let attr = self.store.lookup(old_parent, name)?;
            let id = self.store.nodes().lookup(old_parent, name);
            if let Err(err) = BackingStore::rename(
                self.store.as_ref(),
                (old_parent, name),
                (new_parent, newname),
                StoreRenameFlags(flags.bits()),
            ) {
                admission.abort();
                return Err(err);
            }
            return path.commit_meta(
                admission,
                OpClass::RENAME,
                id,
                old_path,
                MetaArgs::Rename { path2: &new_path },
                MetaOwner::from_attr(&attr),
            );
        }
        BackingStore::rename(
            self.store.as_ref(),
            (old_parent, name),
            (new_parent, newname),
            StoreRenameFlags(flags.bits()),
        )
    }

    fn link_inner(&self, ino: INodeNo, newparent: INodeNo, newname: &OsStr) -> Result<FileAttr> {
        create_name(newname)?;
        let id = self.id(ino)?;
        let newparent = self.id(newparent)?;
        let Some(path) = &self.path else {
            BackingStore::link(self.store.as_ref(), id, newparent, newname)?;
            return self.entry_of(id);
        };
        let admission = path.admit(0)?;
        let target = absolute_path(self.store.nodes(), id)?;
        let link = child_path(self.store.nodes(), newparent, newname)?;
        let attr = self.store.getattr(id)?;
        if let Err(err) = BackingStore::link(self.store.as_ref(), id, newparent, newname) {
            admission.abort();
            return Err(err);
        }
        let fuse_attr = self.entry_of(id)?;
        path.commit_meta(
            admission,
            OpClass::LINK,
            Some(id),
            link,
            MetaArgs::Link { target: &target },
            MetaOwner::from_attr(&attr),
        )?;
        Ok(fuse_attr)
    }

    fn create_inner(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let mode = mode & !umask;
        let Some(path) = &self.path else {
            let candidate = InodeId::new_v4();
            return match BackingStore::create(self.store.as_ref(), parent, name, candidate, mode) {
                Ok(()) => self.entry_of(candidate),
                Err(err) if err == Errno::EEXIST && flags & libc::O_EXCL == 0 => {
                    let id = ensure_child(self.store.as_ref(), parent, name, Kind::File)?;
                    let attr = self.store.getattr(id)?;
                    if attr.kind().is_dir() {
                        return Err(Errno::EISDIR);
                    }
                    if flags & libc::O_TRUNC != 0 {
                        BackingStore::truncate(self.store.as_ref(), id, 0)?;
                    }
                    self.entry_of(id)
                }
                Err(err) => Err(err),
            };
        };
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let candidate = derive_inode_id(admission.op_id);
        match ReplayBacking::create(self.store.as_ref(), parent, name, candidate, mode) {
            Ok(()) => {
                let attr = self.store.getattr(candidate)?;
                let fuse_attr = file_attr(self.store.nodes(), candidate, &attr)?;
                self.store.nodes().touch_lookup(candidate);
                path.commit_meta(
                    admission,
                    OpClass::CREATE_EXCL,
                    Some(candidate),
                    target,
                    MetaArgs::ModeFlags {
                        mode,
                        flags: flags as u32,
                    },
                    MetaOwner::from_attr(&attr),
                )?;
                Ok(fuse_attr)
            }
            Err(err) if err == Errno::EEXIST && flags & libc::O_EXCL == 0 => {
                admission.abort();
                let id = ensure_child(self.store.as_ref(), parent, name, Kind::File)?;
                let attr = self.store.getattr(id)?;
                if attr.kind().is_dir() {
                    return Err(Errno::EISDIR);
                }
                if flags & libc::O_TRUNC != 0 {
                    path.truncate(self.store.as_ref(), id, 0)?;
                }
                self.entry_of(id)
            }
            Err(err) => {
                admission.abort();
                Err(err)
            }
        }
    }

    // -----------------------------------------------------------------
    // L2 synchronous metadata (39 §2.1)
    //
    // With a replay engine attached, a namespace mutation is sent first and
    // applied by the replay engine in sequence order. The callback blocks
    // until that exact operation has been applied, so the caller observes
    // the total order's verdict instead of its own optimistic guess. The
    // disk is never touched here: a rejected operation (`EEXIST`, `ENOENT`,
    // …) leaves the local tree unchanged.
    // -----------------------------------------------------------------

    /// `mkdir` through the sequencer.
    fn mkdir_sync(
        &self,
        owner: MetaOwner,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let mode = mode & !umask;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let id = derive_inode_id(admission.op_id);
        path.commit_meta_sync(
            admission,
            OpClass::MKDIR,
            Some(id),
            target,
            MetaArgs::Mode(mode),
            owner,
        )?;
        self.entry_of(id)
    }

    /// `create` through the sequencer; `O_CREAT` without `O_EXCL` falls back
    /// to the existing inode after an `EEXIST` verdict.
    fn create_sync(
        &self,
        owner: MetaOwner,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let mode = mode & !umask;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let candidate = derive_inode_id(admission.op_id);
        match path.commit_meta_sync(
            admission,
            OpClass::CREATE_EXCL,
            Some(candidate),
            target,
            MetaArgs::ModeFlags {
                mode,
                flags: flags as u32,
            },
            owner,
        ) {
            Ok(()) => self.entry_of(candidate),
            Err(err) if err == Errno::EEXIST && flags & libc::O_EXCL == 0 => {
                let id = ensure_child(self.store.as_ref(), parent, name, Kind::File)?;
                let attr = self.store.getattr(id)?;
                if attr.kind().is_dir() {
                    return Err(Errno::EISDIR);
                }
                if flags & libc::O_TRUNC != 0 {
                    path.truncate(self.store.as_ref(), id, 0)?;
                }
                self.entry_of(id)
            }
            Err(err) => Err(err),
        }
    }

    /// `symlink` through the sequencer.
    fn symlink_sync(
        &self,
        owner: MetaOwner,
        parent: INodeNo,
        name: &OsStr,
        target: &Path,
    ) -> Result<FileAttr> {
        create_name(name)?;
        let parent = self.id(parent)?;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let link = child_path(self.store.nodes(), parent, name)?;
        let contents = target.to_str().ok_or(Errno::EINVAL)?;
        let id = derive_inode_id(admission.op_id);
        path.commit_meta_sync(
            admission,
            OpClass::SYMLINK,
            Some(id),
            link,
            MetaArgs::Symlink { target: contents },
            owner,
        )?;
        self.entry_of(id)
    }

    /// `link` through the sequencer.
    fn link_sync(
        &self,
        owner: MetaOwner,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
    ) -> Result<FileAttr> {
        create_name(newname)?;
        let id = self.id(ino)?;
        let newparent = self.id(newparent)?;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let target = absolute_path(self.store.nodes(), id)?;
        let link = child_path(self.store.nodes(), newparent, newname)?;
        path.commit_meta_sync(
            admission,
            OpClass::LINK,
            Some(id),
            link,
            MetaArgs::Link { target: &target },
            owner,
        )?;
        self.entry_of(id)
    }

    /// `rename` through the sequencer.
    fn rename_sync(
        &self,
        owner: MetaOwner,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
    ) -> Result<()> {
        rename_names(name, newname)?;
        let old_parent = self.id(parent)?;
        let new_parent = self.id(newparent)?;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        path.gate().check_write()?;
        // A two-way exchange is not a single RENAME op; fail closed instead
        // of broadcasting half of it.
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            return Err(Errno::EOPNOTSUPP);
        }
        // The wire `RENAME` body carries no flags, so `NOREPLACE` is checked
        // against the local tree before the operation enters the order. The
        // total order still decides a race with a concurrent creation; the
        // common case (target absent) keeps its POSIX guarantee.
        if flags.contains(RenameFlags::RENAME_NOREPLACE) {
            match self.store.lookup(new_parent, newname) {
                Ok(_) => return Err(Errno::EEXIST),
                Err(err) if err == Errno::ENOENT => {}
                Err(err) => return Err(err),
            }
        }
        let admission = path.admit(0)?;
        let old_path = child_path(self.store.nodes(), old_parent, name)?;
        let new_path = child_path(self.store.nodes(), new_parent, newname)?;
        let id = self.store.nodes().lookup(old_parent, name);
        path.commit_meta_sync(
            admission,
            OpClass::RENAME,
            id,
            old_path,
            MetaArgs::Rename { path2: &new_path },
            owner,
        )
    }

    /// `unlink` through the sequencer.
    fn unlink_sync(&self, owner: MetaOwner, parent: INodeNo, name: &OsStr) -> Result<()> {
        lookup_name(name)?;
        let parent = self.id(parent)?;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let id = self.store.nodes().lookup(parent, name);
        path.commit_meta_sync(
            admission,
            OpClass::UNLINK,
            id,
            target,
            MetaArgs::None,
            owner,
        )
    }

    /// `rmdir` through the sequencer.
    fn rmdir_sync(&self, owner: MetaOwner, parent: INodeNo, name: &OsStr) -> Result<()> {
        lookup_name(name)?;
        let parent = self.id(parent)?;
        let path = self.path.as_ref().ok_or(Errno::EIO)?;
        let admission = path.admit(0)?;
        let target = child_path(self.store.nodes(), parent, name)?;
        let id = self.store.nodes().lookup(parent, name);
        path.commit_meta_sync(admission, OpClass::RMDIR, id, target, MetaArgs::None, owner)
    }

    /// `F_GETLK` against the deterministic lock table.
    fn getlk_inner(
        &self,
        ino: INodeNo,
        start: u64,
        end: u64,
        typ: i32,
    ) -> Result<Option<(LockKey, Lock)>> {
        let path = self
            .path
            .as_ref()
            .filter(|path| path.arbitrated())
            .ok_or(Errno::ENOSYS)?;
        let id = self.id(ino)?;
        let typ = match typ {
            libc::F_RDLCK => LockType::Read,
            libc::F_WRLCK => LockType::Write,
            libc::F_UNLCK => return Ok(None),
            _ => return Err(Errno::EINVAL),
        };
        let end = if end == i64::MAX as u64 {
            u64::MAX
        } else {
            end
        };
        if end < start {
            return Ok(None);
        }
        Ok(path.lock_conflict(id, start, end, typ))
    }

    /// `F_SETLK`/`F_SETLKW` through the sequencer.
    fn setlk_inner(
        &self,
        owner: MetaOwner,
        ino: INodeNo,
        start: u64,
        end: u64,
        typ: i32,
        sleep: bool,
    ) -> Result<()> {
        // A blocking request needs a wakeup path on lock release; v1 answers
        // non-blocking requests only and says so instead of spinning.
        if sleep {
            return Err(Errno::EOPNOTSUPP);
        }
        let path = self
            .path
            .as_ref()
            .filter(|path| path.arbitrated())
            .ok_or(Errno::ENOSYS)?;
        let id = self.id(ino)?;
        let (lock_type, action) = match typ {
            libc::F_RDLCK => (0, LOCK_ACTION_SET),
            libc::F_WRLCK => (1, LOCK_ACTION_SET),
            libc::F_UNLCK => (0, LOCK_ACTION_UNLOCK),
            _ => return Err(Errno::EINVAL),
        };
        let len = lock_len(start, end);
        let admission = path.admit(0)?;
        let target = absolute_path(self.store.nodes(), id)?;
        path.commit_meta_sync(
            admission,
            OpClass::FCNTL_LOCK,
            Some(id),
            target,
            MetaArgs::FcntlLock {
                lock_type,
                action,
                start,
                len,
            },
            owner,
        )
    }

    fn open_inner(&self, ino: INodeNo) -> Result<()> {
        let id = self.id(ino)?;
        let attr = self.store.getattr(id)?;
        if attr.kind().is_dir() {
            return Err(Errno::EISDIR);
        }
        Ok(())
    }

    fn read_inner(&self, ino: INodeNo, offset: u64, size: u32) -> Result<Vec<u8>> {
        let id = self.id(ino)?;
        let mut buffer = vec![0u8; size as usize];
        let count = self.store.read_at(id, offset, &mut buffer)?;
        buffer.truncate(count);
        Ok(buffer)
    }

    fn write_inner(
        &self,
        ino: INodeNo,
        offset: u64,
        data: &[u8],
        flags: OpenFlags,
    ) -> Result<usize> {
        let id = self.id(ino)?;
        // Write-through page cache sends the offset the kernel computed. For
        // O_APPEND the daemon still anchors at EOF, matching the local
        // semantics promised by 39 §2.1.
        let offset = if flags.0 & libc::O_APPEND != 0 {
            self.store.getattr(id)?.size
        } else {
            offset
        };
        match &self.path {
            Some(path) => path.write(self.store.as_ref(), id, offset, data),
            None => BackingStore::write_at(self.store.as_ref(), id, offset, data),
        }
    }

    fn fsync_inner(&self, ino: INodeNo, datasync: bool) -> Result<()> {
        let id = self.id(ino)?;
        match &self.path {
            Some(path) => path.fsync(self.store.as_ref(), id, datasync),
            None => BackingStore::fsync(self.store.as_ref(), id, datasync),
        }
    }

    fn readdir_inner(&self, ino: INodeNo, offset: u64, reply: &mut ReplyDirectory) -> Result<()> {
        let id = self.id(ino)?;
        let attr = self.store.getattr(id)?;
        if !attr.kind().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let plan = readdir_plan(offset);
        let nodes = self.store.nodes();
        if plan.dot {
            let dot = ino_of(nodes, id)?;
            if reply.add(dot, 1, fuser::FileType::Directory, OsStr::new(".")) {
                return Ok(());
            }
        }
        if plan.dotdot {
            let parent = parent_of(nodes, id);
            let parent_ino = ino_of(nodes, parent)?;
            if reply.add(parent_ino, 2, fuser::FileType::Directory, OsStr::new("..")) {
                return Ok(());
            }
        }

        let mut sink = ReplySink {
            store: self.store.as_ref(),
            parent: id,
            reply,
            base: 2,
            full: false,
        };
        match self.store.readdir(id, plan.cursor, &mut sink) {
            Ok(()) => Ok(()),
            Err(err) if err == SINK_FULL && sink.full => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn readdirplus_inner(
        &self,
        ino: INodeNo,
        offset: u64,
        reply: &mut ReplyDirectoryPlus,
    ) -> Result<()> {
        let id = self.id(ino)?;
        let attr = self.store.getattr(id)?;
        if !attr.kind().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let plan = readdir_plan(offset);
        let nodes = self.store.nodes();

        if plan.dot {
            let dot = file_attr(nodes, id, &attr)?;
            if reply.add(dot.ino, 1, OsStr::new("."), &ENTRY_TTL, &dot, GENERATION) {
                return Ok(());
            }
            nodes.touch_lookup(id);
        }
        if plan.dotdot {
            let parent = parent_of(nodes, id);
            let parent_attr = if parent == id {
                attr
            } else {
                self.store.getattr(parent)?
            };
            let dotdot = file_attr(nodes, parent, &parent_attr)?;
            if reply.add(
                dotdot.ino,
                2,
                OsStr::new(".."),
                &ENTRY_TTL,
                &dotdot,
                GENERATION,
            ) {
                return Ok(());
            }
            nodes.touch_lookup(parent);
        }

        let mut sink = ReplySinkPlus {
            store: self.store.as_ref(),
            parent: id,
            reply,
            base: 2,
            full: false,
        };
        match self.store.readdir(id, plan.cursor, &mut sink) {
            Ok(()) => Ok(()),
            Err(err) if err == SINK_FULL && sink.full => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn statfs_inner(&self) -> Result<rustix::fs::StatFs> {
        self.store.statfs()
    }

    fn getxattr_inner(&self, ino: INodeNo, name: &OsStr, size: u32) -> Result<XattrReply> {
        let value = self.store.getxattr(self.id(ino)?, name)?;
        xattr_reply(value, size)
    }

    fn listxattr_inner(&self, ino: INodeNo, size: u32) -> Result<XattrReply> {
        let value = self.store.listxattr(self.id(ino)?)?;
        xattr_reply(value, size)
    }

    fn setxattr_inner(&self, ino: INodeNo, name: &OsStr, value: &[u8], flags: i32) -> Result<()> {
        let id = self.id(ino)?;
        match &self.path {
            Some(path) => path.set_xattr(self.store.as_ref(), id, name, Some(value), flags),
            None => self.store.setxattr(id, name, value, flags),
        }
    }

    fn removexattr_inner(&self, ino: INodeNo, name: &OsStr) -> Result<()> {
        let id = self.id(ino)?;
        match &self.path {
            Some(path) => path.set_xattr(self.store.as_ref(), id, name, None, 0),
            None => self.store.removexattr(id, name),
        }
    }

    fn access_inner(&self, ino: INodeNo, mask: i32) -> Result<()> {
        self.store.access(self.id(ino)?, mask)
    }

    fn fallocate_inner(&self, ino: INodeNo, offset: u64, length: u64, mode: i32) -> Result<()> {
        let id = self.id(ino)?;
        let Some(path) = &self.path else {
            return self.store.fallocate(id, offset, length, mode);
        };
        path.gate().check_write()?;
        let flags = FallocateFlags::from_bits_truncate(mode as u32);
        if flags.intersects(
            FallocateFlags::COLLAPSE_RANGE
                | FallocateFlags::INSERT_RANGE
                | FallocateFlags::UNSHARE_RANGE,
        ) {
            return Err(Errno::EOPNOTSUPP);
        }
        if length == 0 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(FallocateFlags::PUNCH_HOLE) && !flags.contains(FallocateFlags::KEEP_SIZE)
        {
            return Err(Errno::EINVAL);
        }
        // PUNCH_HOLE and ZERO_RANGE change content. 39 §4 degrades both to
        // writing zeros, and every chunk goes through the write path so the
        // change is broadcast like any other write.
        if flags.intersects(FallocateFlags::PUNCH_HOLE | FallocateFlags::ZERO_RANGE) {
            let end = offset.checked_add(length).ok_or(Errno::EOVERFLOW)?;
            let end = if flags.contains(FallocateFlags::PUNCH_HOLE) {
                end.min(self.store.getattr(id)?.size)
            } else {
                end
            };
            return self.write_zeros(path, id, offset, end);
        }
        // Plain allocation is local space management; it changes no bytes.
        self.store.fallocate(id, offset, length, mode)
    }

    fn copy_file_range_inner(
        &self,
        ino_in: INodeNo,
        offset_in: u64,
        ino_out: INodeNo,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
    ) -> Result<u32> {
        if !flags.is_empty() {
            return Err(Errno::EOPNOTSUPP);
        }
        let id_in = self.id(ino_in)?;
        let id_out = self.id(ino_out)?;
        let Some(path) = &self.path else {
            let copied = self
                .store
                .copy_range(id_in, offset_in, id_out, offset_out, len)?;
            return u32::try_from(copied).map_err(|_| Errno::EOVERFLOW);
        };
        path.gate().check_write()?;
        if len == 0 {
            return Ok(0);
        }
        let mut buffer = vec![0u8; IO_CHUNK];
        let mut copied = 0u64;
        while copied < len {
            let want = (len - copied).min(IO_CHUNK as u64) as usize;
            let read_offset = offset_in.checked_add(copied).ok_or(Errno::EOVERFLOW)?;
            let count = self
                .store
                .read_at(id_in, read_offset, &mut buffer[..want])?;
            if count == 0 {
                break;
            }
            let write_offset = offset_out.checked_add(copied).ok_or(Errno::EOVERFLOW)?;
            let written =
                path.write(self.store.as_ref(), id_out, write_offset, &buffer[..count])?;
            if written != count {
                return Err(Errno::EIO);
            }
            copied += count as u64;
        }
        u32::try_from(copied).map_err(|_| Errno::EOVERFLOW)
    }

    /// Write zeros through the write path (fallocate degradation).
    fn write_zeros(&self, path: &WritePath, id: InodeId, start: u64, end: u64) -> Result<()> {
        let zeros = [0u8; IO_CHUNK];
        let mut cursor = start;
        while cursor < end {
            let want = (end - cursor).min(IO_CHUNK as u64) as usize;
            let written = path.write(self.store.as_ref(), id, cursor, &zeros[..want])?;
            if written == 0 {
                return Err(Errno::EIO);
            }
            cursor += written as u64;
        }
        Ok(())
    }

    fn lseek_inner(&self, ino: INodeNo, offset: i64, whence: i32) -> Result<i64> {
        self.store.lseek(self.id(ino)?, offset, whence)
    }
}

/// One xattr reply shape.
#[derive(Debug)]
enum XattrReply {
    Size(u32),
    Data(Vec<u8>),
}

fn xattr_reply(value: Vec<u8>, size: u32) -> Result<XattrReply> {
    if size == 0 {
        let len = u32::try_from(value.len()).map_err(|_| Errno::EOVERFLOW)?;
        Ok(XattrReply::Size(len))
    } else if value.len() > size as usize {
        Err(ERANGE)
    } else {
        Ok(XattrReply::Data(value))
    }
}

impl<B: FuseBacking + ?Sized + 'static> Filesystem for FuseFs<B> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        let capabilities = self.capabilities();
        if let Err(unsupported) = config.add_capabilities(capabilities) {
            tracing::warn!(
                ?unsupported,
                "fuse: kernel does not support every requested capability"
            );
        }
        let _ = config.set_max_write(MAX_WRITE);
        Ok(())
    }

    fn destroy(&mut self) {
        if let Err(err) = self.store.syncfs() {
            tracing::warn!(%err, "fuse destroy: syncfs failed");
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_inner(parent, name) {
            Ok((attr, _id)) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        if let Some(id) = self.store.nodes().id_of(ino.0) {
            self.store.nodes().forget(id, nlookup);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.getattr_inner(ino) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        match self.setattr_inner(ino, mode, uid, gid, size, atime, mtime) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.readlink_inner(ino) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        match self.mknod_inner(parent, name, mode, umask, rdev) {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let result = if self.arbitrated() {
            self.mkdir_sync(
                MetaOwner::request(req.uid(), req.gid()),
                parent,
                name,
                mode,
                umask,
            )
        } else {
            self.mkdir_inner(parent, name, mode, umask)
        };
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = if self.arbitrated() {
            self.unlink_sync(MetaOwner::request(req.uid(), req.gid()), parent, name)
        } else {
            self.unlink_inner(parent, name)
        };
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = if self.arbitrated() {
            self.rmdir_sync(MetaOwner::request(req.uid(), req.gid()), parent, name)
        } else {
            self.rmdir_inner(parent, name)
        };
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let result = if self.arbitrated() {
            self.symlink_sync(
                MetaOwner::request(req.uid(), req.gid()),
                parent,
                link_name,
                target,
            )
        } else {
            self.symlink_inner(parent, link_name, target)
        };
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let result = if self.arbitrated() {
            self.rename_sync(
                MetaOwner::request(req.uid(), req.gid()),
                parent,
                name,
                newparent,
                newname,
                flags,
            )
        } else {
            self.rename_inner(parent, name, newparent, newname, flags)
        };
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let result = if self.arbitrated() {
            self.link_sync(
                MetaOwner::request(req.uid(), req.gid()),
                ino,
                newparent,
                newname,
            )
        } else {
            self.link_inner(ino, newparent, newname)
        };
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.open_inner(ino) {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.read_inner(ino, offset, size) {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.write_inner(ino, offset, data, flags) {
            Ok(count) => reply.written(count as u32),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // No writeback buffer exists, and W13a owns no locks.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.fsync_inner(ino, datasync) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.getattr_inner(ino) {
            Ok(attr) if attr.kind == fuser::FileType::Directory => {
                reply.opened(FileHandle(0), FopenFlags::empty());
            }
            Ok(_) => reply.error(fuser::Errno::ENOTDIR),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.readdir_inner(ino, offset, &mut reply) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        match self.readdirplus_inner(ino, offset, &mut reply) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.fsync_inner(ino, datasync) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.statfs_inner() {
            Ok(stat) => {
                let bsize = u32::try_from(stat.f_bsize).unwrap_or(u32::MAX);
                let namelen = u32::try_from(stat.f_namelen).unwrap_or(u32::MAX);
                let frsize = if stat.f_frsize == 0 {
                    bsize
                } else {
                    u32::try_from(stat.f_frsize).unwrap_or(u32::MAX)
                };
                reply.statfs(
                    stat.f_blocks,
                    stat.f_bfree,
                    stat.f_bavail,
                    stat.f_files,
                    stat.f_ffree,
                    bsize,
                    namelen,
                    frsize,
                );
            }
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        match self.setxattr_inner(ino, name, value, flags) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        match self.getxattr_inner(ino, name, size) {
            Ok(XattrReply::Size(size)) => reply.size(size),
            Ok(XattrReply::Data(data)) => reply.data(&data),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        match self.listxattr_inner(ino, size) {
            Ok(XattrReply::Size(size)) => reply.size(size),
            Ok(XattrReply::Data(data)) => reply.data(&data),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.removexattr_inner(ino, name) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        match self.access_inner(ino, mask.bits()) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let result = if self.arbitrated() {
            self.create_sync(
                MetaOwner::request(req.uid(), req.gid()),
                parent,
                name,
                mode,
                umask,
                flags,
            )
        } else {
            self.create_inner(parent, name, mode, umask, flags)
        };
        match result {
            Ok(attr) => reply.created(
                &ENTRY_TTL,
                &attr,
                GENERATION,
                FileHandle(0),
                FopenFlags::empty(),
            ),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn getlk(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        match self.getlk_inner(ino, start, end, typ) {
            Ok(Some((key, lock))) => reply.locked(key.start, key.end, lock_typ(lock.typ), 0),
            // No conflicting lock: `F_UNLCK` with the queried range.
            Ok(None) => reply.locked(start, end, libc::F_UNLCK, 0),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn setlk(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        match self.setlk_inner(
            MetaOwner::request(req.uid(), req.gid()),
            ino,
            start,
            end,
            typ,
            sleep,
        ) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn ioctl(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: IoctlFlags,
        _cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: ReplyIoctl,
    ) {
        // Only the FS_IOC_GETFLAGS/SETFLAGS subset is meaningful; everything
        // else is deterministically unsupported.
        reply.error(fuser::Errno::ENOTTY);
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        match self.fallocate_inner(ino, offset, length, mode) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn lseek(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        match self.lseek_inner(ino, offset, whence) {
            Ok(offset) => reply.offset(offset),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        ino_in: INodeNo,
        _fh_in: FileHandle,
        offset_in: u64,
        ino_out: INodeNo,
        _fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        match self.copy_file_range_inner(ino_in, offset_in, ino_out, offset_out, len, flags) {
            Ok(count) => reply.written(count),
            Err(err) => reply.error(to_fuser_errno(err)),
        }
    }
}

impl FuseBacking for PosixBacking {
    fn nodes(&self) -> &NodeTable {
        PosixBacking::nodes(self)
    }

    fn readlink(&self, ino: InodeId) -> Result<PathBuf> {
        let rel = rel_of(self.nodes(), ino)?;
        self.root().readlink_at(&rel)
    }

    fn getxattr(&self, ino: InodeId, name: &OsStr) -> Result<Vec<u8>> {
        let (_fd, path) = xattr_path(self.root(), self.nodes(), ino)?;
        let size = rustix::fs::lgetxattr_query(&path, name).map_err(Errno::from)?;
        let mut buffer = vec![0u8; size];
        let count = rustix::fs::lgetxattr(&path, name, &mut buffer).map_err(Errno::from)?;
        buffer.truncate(count);
        Ok(buffer)
    }

    fn listxattr(&self, ino: InodeId) -> Result<Vec<u8>> {
        let (_fd, path) = xattr_path(self.root(), self.nodes(), ino)?;
        let size = rustix::fs::llistxattr_query(&path).map_err(Errno::from)?;
        let mut buffer = vec![0u8; size];
        let count = rustix::fs::llistxattr(&path, &mut buffer).map_err(Errno::from)?;
        buffer.truncate(count);
        Ok(buffer)
    }

    fn setxattr(&self, ino: InodeId, name: &OsStr, value: &[u8], flags: i32) -> Result<()> {
        let (_fd, path) = xattr_path(self.root(), self.nodes(), ino)?;
        let flags = XattrFlags::from_bits_truncate(flags as u32);
        rustix::fs::lsetxattr(&path, name, value, flags).map_err(Errno::from)
    }

    fn removexattr(&self, ino: InodeId, name: &OsStr) -> Result<()> {
        let (_fd, path) = xattr_path(self.root(), self.nodes(), ino)?;
        rustix::fs::lremovexattr(&path, name).map_err(Errno::from)
    }

    fn statfs(&self) -> Result<rustix::fs::StatFs> {
        rustix::fs::fstatfs(self.root().sync_fd()).map_err(Errno::from)
    }

    fn access(&self, ino: InodeId, mask: i32) -> Result<()> {
        let rel = rel_or_dot(self.nodes(), ino)?;
        let access = Access::from_bits_truncate(mask as u32);
        rustix::fs::accessat(self.root().at(), &rel, access, AtFlags::EACCESS).map_err(Errno::from)
    }

    fn fallocate(&self, ino: InodeId, offset: u64, length: u64, mode: i32) -> Result<()> {
        let flags = FallocateFlags::from_bits_truncate(mode as u32);
        if flags.intersects(
            FallocateFlags::COLLAPSE_RANGE
                | FallocateFlags::INSERT_RANGE
                | FallocateFlags::UNSHARE_RANGE,
        ) {
            return Err(Errno::EOPNOTSUPP);
        }
        if length == 0 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(FallocateFlags::PUNCH_HOLE) && !flags.contains(FallocateFlags::KEEP_SIZE)
        {
            return Err(Errno::EINVAL);
        }

        let rel = rel_of(self.nodes(), ino)?;
        let fd = self.root().open_at(&rel, OFlags::WRONLY, Mode::empty())?;
        match rustix::fs::fallocate(&fd, flags, offset, length) {
            Ok(()) => Ok(()),
            Err(RxErrno::NOTSUP)
                if flags.intersects(FallocateFlags::PUNCH_HOLE | FallocateFlags::ZERO_RANGE) =>
            {
                let end = offset.checked_add(length).ok_or(Errno::EOVERFLOW)?;
                let end = if flags.contains(FallocateFlags::PUNCH_HOLE) {
                    end.min(self.getattr(ino)?.size)
                } else {
                    end
                };
                write_zeros(self, ino, offset, end)
            }
            Err(err) => Err(Errno::from(err)),
        }
    }

    fn copy_range(
        &self,
        ino_in: InodeId,
        off_in: u64,
        ino_out: InodeId,
        off_out: u64,
        len: u64,
    ) -> Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        let mut buffer = vec![0u8; IO_CHUNK];
        let mut copied = 0u64;
        while copied < len {
            let want = (len - copied).min(buffer.len() as u64) as usize;
            let read_offset = off_in.checked_add(copied).ok_or(Errno::EOVERFLOW)?;
            let count = self.read_at(ino_in, read_offset, &mut buffer[..want])?;
            if count == 0 {
                break;
            }
            let mut done = 0usize;
            while done < count {
                let write_offset = off_out
                    .checked_add(copied)
                    .and_then(|base| base.checked_add(done as u64))
                    .ok_or(Errno::EOVERFLOW)?;
                let written =
                    BackingStore::write_at(self, ino_out, write_offset, &buffer[done..count])?;
                if written == 0 {
                    return Err(Errno::EIO);
                }
                done += written;
            }
            copied += count as u64;
        }
        Ok(copied)
    }

    fn lseek(&self, ino: InodeId, offset: i64, whence: i32) -> Result<i64> {
        let rel = rel_of(self.nodes(), ino)?;
        let fd = self.root().open_at(&rel, OFlags::RDONLY, Mode::empty())?;
        let position = match whence {
            libc::SEEK_SET if offset >= 0 => SeekFrom::Start(offset as u64),
            libc::SEEK_END => SeekFrom::End(offset),
            libc::SEEK_DATA if offset >= 0 => SeekFrom::Data(offset as u64),
            libc::SEEK_HOLE if offset >= 0 => SeekFrom::Hole(offset as u64),
            _ => return Err(Errno::EINVAL),
        };
        let offset = rustix::fs::seek(&fd, position).map_err(Errno::from)?;
        i64::try_from(offset).map_err(|_| Errno::EOVERFLOW)
    }

    fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<()> {
        if is_reserved_name(name) {
            return Err(Errno::ENOENT);
        }
        let rel = child_rel(self.nodes(), parent, name)?;
        self.root().rmdir_at(&rel)?;
        let _ = self.nodes().remove_name(parent, name);
        Ok(())
    }

    fn mknod(
        &self,
        parent: InodeId,
        name: &OsStr,
        id: InodeId,
        mode: u32,
        rdev: u32,
    ) -> Result<()> {
        let kind = Kind::from_mode(mode);
        match kind {
            Kind::File => BackingStore::create(self, parent, name, id, mode),
            Kind::Fifo => {
                let rel = child_rel(self.nodes(), parent, name)?;
                rustix::fs::mknodat(
                    self.root().at(),
                    &rel,
                    rustix::fs::FileType::Fifo,
                    Mode::from_raw_mode(mode),
                    rdev as u64,
                )
                .map_err(Errno::from)?;
                if let Err(err) = self.nodes().insert_link(id, parent, name, kind) {
                    let _ = self.root().unlink_at(&rel);
                    return Err(err);
                }
                Ok(())
            }
            _ => Err(Errno::EPERM),
        }
    }
}

/// A sink that fills a `readdir` reply.
struct ReplySink<'a, B: FuseBacking + ?Sized> {
    store: &'a B,
    parent: InodeId,
    reply: &'a mut ReplyDirectory,
    base: u64,
    full: bool,
}

impl<B: FuseBacking + ?Sized> DirSink for ReplySink<'_, B> {
    fn push(&mut self, entry: DirEntry) -> Result<()> {
        if self.full || is_reserved_name(&entry.name) {
            return Ok(());
        }
        let id = match ensure_child(self.store, self.parent, &entry.name, entry.kind) {
            Ok(id) => id,
            Err(Errno::ENOENT) => return Ok(()),
            Err(err) => return Err(err),
        };
        let ino = ino_of(self.store.nodes(), id)?;
        let kind = self.store.nodes().kind_of(id).unwrap_or(entry.kind);
        if self.reply.add(
            ino,
            entry.offset.saturating_add(self.base),
            file_type(kind),
            entry.name.as_os_str(),
        ) {
            self.full = true;
            return Err(SINK_FULL);
        }
        Ok(())
    }
}

/// A sink that fills a `readdirplus` reply.
struct ReplySinkPlus<'a, B: FuseBacking + ?Sized> {
    store: &'a B,
    parent: InodeId,
    reply: &'a mut ReplyDirectoryPlus,
    base: u64,
    full: bool,
}

impl<B: FuseBacking + ?Sized> DirSink for ReplySinkPlus<'_, B> {
    fn push(&mut self, entry: DirEntry) -> Result<()> {
        if self.full || is_reserved_name(&entry.name) {
            return Ok(());
        }
        let id = match ensure_child(self.store, self.parent, &entry.name, entry.kind) {
            Ok(id) => id,
            Err(Errno::ENOENT) => return Ok(()),
            Err(err) => return Err(err),
        };
        let attr = match self.store.getattr(id) {
            Ok(attr) => attr,
            Err(Errno::ENOENT) => return Ok(()),
            Err(err) => return Err(err),
        };
        let attr = match file_attr(self.store.nodes(), id, &attr) {
            Ok(attr) => attr,
            Err(Errno::ENOENT) => return Ok(()),
            Err(err) => return Err(err),
        };
        if self.reply.add(
            attr.ino,
            entry.offset.saturating_add(self.base),
            entry.name.as_os_str(),
            &ENTRY_TTL,
            &attr,
            GENERATION,
        ) {
            self.full = true;
            return Err(SINK_FULL);
        }
        self.store.nodes().touch_lookup(id);
        Ok(())
    }
}

/// Cursor mapping for the synthesized `.`/`..` entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReaddirPlan {
    dot: bool,
    dotdot: bool,
    cursor: u64,
}

fn readdir_plan(offset: u64) -> ReaddirPlan {
    ReaddirPlan {
        dot: offset < 1,
        dotdot: offset < 2,
        cursor: offset.saturating_sub(2),
    }
}

/// Reserved-name policy: lookup must behave as if the entry does not exist.
fn lookup_name(name: &OsStr) -> Result<()> {
    if is_reserved_name(name) {
        Err(Errno::ENOENT)
    } else {
        Ok(())
    }
}

/// Reserved-name policy: a write target must report the name as occupied.
fn create_name(name: &OsStr) -> Result<()> {
    if is_reserved_name(name) {
        Err(Errno::EEXIST)
    } else {
        Ok(())
    }
}

/// Rename source is invisible; rename target is occupied.
fn rename_names(old: &OsStr, new: &OsStr) -> Result<()> {
    lookup_name(old)?;
    create_name(new)
}

/// Wire length of a `fcntl` range: `0` means "to end of file".
fn lock_len(start: u64, end: u64) -> u64 {
    if end == u64::MAX || end == i64::MAX as u64 || end < start {
        0
    } else {
        end - start + 1
    }
}

/// FUSE reply lock type.
const fn lock_typ(typ: LockType) -> i32 {
    match typ {
        LockType::Read => libc::F_RDLCK,
        LockType::Write => libc::F_WRLCK,
    }
}

/// Map a store error to a FUSE reply error.
fn to_fuser_errno(err: Errno) -> fuser::Errno {
    fuser::Errno::from_i32(err.raw())
}

fn time_or_now(time: TimeOrNow) -> crate::store::Timespec {
    match time {
        TimeOrNow::SpecificTime(time) => timespec(time),
        TimeOrNow::Now => timespec(SystemTime::now()),
    }
}

fn rel_of(nodes: &NodeTable, id: InodeId) -> Result<PathBuf> {
    nodes.path_of(id).ok_or(Errno::ENOENT)
}

fn rel_or_dot(nodes: &NodeTable, id: InodeId) -> Result<PathBuf> {
    let rel = rel_of(nodes, id)?;
    Ok(if rel.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rel
    })
}

fn child_rel(nodes: &NodeTable, parent: InodeId, name: &OsStr) -> Result<PathBuf> {
    validate_name(name)?;
    let parent = rel_of(nodes, parent)?;
    Ok(if parent.as_os_str().is_empty() {
        PathBuf::from(name)
    } else {
        parent.join(name)
    })
}

fn parent_of(nodes: &NodeTable, id: InodeId) -> InodeId {
    nodes.first_name(id).map(|(parent, _)| parent).unwrap_or(id)
}

/// Find or create the table entry for a backing name.
///
/// `readdir` learns names, not identities, so the table is populated lazily.
/// A concurrent lookup may win the race; `EEXIST` then means "use its id".
fn ensure_child<B: FuseBacking + ?Sized>(
    store: &B,
    parent: InodeId,
    name: &OsStr,
    kind: Kind,
) -> Result<InodeId> {
    if let Some(id) = store.nodes().lookup(parent, name) {
        return Ok(id);
    }
    let attr = store.lookup(parent, name)?;
    let kind = if kind == Kind::Unknown {
        attr.kind()
    } else {
        kind
    };
    if kind == Kind::Unknown {
        return Err(Errno::EIO);
    }
    let candidate = InodeId::new_v4();
    match store.nodes().insert_link(candidate, parent, name, kind) {
        Ok(()) => Ok(candidate),
        Err(err) if err == Errno::EEXIST => store.nodes().lookup(parent, name).ok_or(Errno::EIO),
        Err(err) => Err(err),
    }
}

fn proc_fd_path(fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

/// Resolve the parent directory through the root descriptor, then append one
/// validated name. The `/proc/self/fd/<parent>` prefix is a kernel-owned magic
/// link to the already-open directory, not a path through the mountpoint, so
/// it cannot recurse back into this FUSE session. `l*xattr` then operates on
/// the final component without following a symlink.
fn xattr_path(root: &RootFd, nodes: &NodeTable, id: InodeId) -> Result<(OwnedFd, PathBuf)> {
    if id.is_root() {
        let fd = root.open_at(
            Path::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        let path = proc_fd_path(fd.as_raw_fd());
        return Ok((fd, path));
    }
    let (parent, name) = nodes.first_name(id).ok_or(Errno::ENOENT)?;
    let parent_rel = rel_of(nodes, parent)?;
    let fd = root.open_at(
        &parent_rel,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    let mut path = proc_fd_path(fd.as_raw_fd());
    path.push(name);
    Ok((fd, path))
}

fn write_zeros<B: BackingStore + ?Sized>(
    store: &B,
    ino: InodeId,
    mut offset: u64,
    end: u64,
) -> Result<()> {
    let zeros = vec![0u8; IO_CHUNK];
    while offset < end {
        let len = (end - offset).min(IO_CHUNK as u64) as usize;
        store.write_at(ino, offset, &zeros[..len])?;
        offset += len as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::ffi::OsStr;
    use std::sync::Arc;

    use tempfile::TempDir;

    use crate::store::node_table::{InodeId, ROOT_INO};
    use crate::store::{Kind, PosixBacking, RootFd};

    struct Fixture {
        tmp: TempDir,
        backing: Arc<PosixBacking>,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let root =
            RootFd::open_before_mount(tmp.path()).unwrap_or_else(|err| panic!("open root: {err}"));
        Fixture {
            tmp,
            backing: Arc::new(PosixBacking::new(root)),
        }
    }

    fn fs(fixture: &Fixture) -> FuseFs<PosixBacking> {
        FuseFs::new(fixture.backing.clone())
    }

    fn ok<T, E: std::fmt::Debug>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|err| panic!("unexpected error: {err:?}"))
    }

    fn err<T: std::fmt::Debug>(result: Result<T>) -> Errno {
        match result {
            Ok(value) => panic!("expected an error, got {value:?}"),
            Err(err) => err,
        }
    }

    fn id_of_attr(fs: &FuseFs<PosixBacking>, attr: &FileAttr) -> InodeId {
        fs.store()
            .nodes()
            .id_of(attr.ino.0)
            .unwrap_or_else(|| panic!("no id for ino {}", attr.ino.0))
    }

    /// E6 / 45 C9: lookup hides every reserved name; writes report EEXIST.
    #[test]
    fn u_fuse_reserved_names_are_masked() {
        for name in [
            ".syncmount",
            ".syncmount-staging",
            ".syncmount-manifest",
            ".audit.log",
        ] {
            assert_eq!(err(lookup_name(OsStr::new(name))), Errno::ENOENT);
            assert_eq!(err(create_name(OsStr::new(name))), Errno::EEXIST);
        }
        assert!(lookup_name(OsStr::new(".syncmount-staging2")).is_ok());
        assert!(create_name(OsStr::new("staging")).is_ok());
        assert_eq!(
            err(rename_names(OsStr::new("x"), OsStr::new(".syncmount"))),
            Errno::EEXIST
        );
        assert_eq!(
            err(rename_names(OsStr::new(".syncmount"), OsStr::new("x"))),
            Errno::ENOENT
        );
    }

    /// E6 / 45 §4.3: errno values are preserved across the adapter.
    #[test]
    fn u_fuse_errno_mapping() {
        for errno in [
            Errno::ENOENT,
            Errno::EEXIST,
            Errno::ENOTEMPTY,
            Errno::EINVAL,
            Errno::EISDIR,
            Errno::ENOTDIR,
            Errno::EACCES,
            Errno::ENOSPC,
            Errno::EIO,
            Errno::EOPNOTSUPP,
            Errno::EROFS,
            Errno::ENAMETOOLONG,
        ] {
            assert_eq!(to_fuser_errno(errno).code(), errno.raw());
        }
    }

    /// E6 / 41 §2.2: the base set promises only the two directory
    /// capabilities; `FuseFs::capabilities` adds record locks when a replay
    /// engine is attached.
    #[test]
    fn u_fuse_init_capabilities() {
        assert!(INIT_CAPABILITIES.contains(InitFlags::FUSE_DO_READDIRPLUS));
        assert!(INIT_CAPABILITIES.contains(InitFlags::FUSE_PARALLEL_DIROPS));
        assert!(!INIT_CAPABILITIES.contains(InitFlags::FUSE_POSIX_LOCKS));
        assert!(!INIT_CAPABILITIES.contains(InitFlags::FUSE_FLOCK_LOCKS));
        assert!(!INIT_CAPABILITIES.contains(InitFlags::FUSE_WRITEBACK_CACHE));
        assert!(!INIT_CAPABILITIES.contains(InitFlags::FUSE_PASSTHROUGH));
    }

    /// E6 / 41 §4: lookup populates the table and is stable across calls.
    #[test]
    fn u_fuse_lookup_and_ino_are_stable() {
        let fixture = fixture();
        let fs = fs(&fixture);
        std::fs::write(fixture.tmp.path().join("f"), b"abc")
            .unwrap_or_else(|err| panic!("write: {err}"));

        let (first, id) = ok(fs.lookup_inner(INodeNo::ROOT, OsStr::new("f")));
        assert_eq!(first.size, 3);
        assert_eq!(first.kind, fuser::FileType::RegularFile);
        assert_eq!(
            fs.store().nodes().lookup(InodeId::ROOT, OsStr::new("f")),
            Some(id)
        );
        assert_eq!(fs.store().nodes().ino_of(id), Some(first.ino.0));

        let (second, second_id) = ok(fs.lookup_inner(INodeNo::ROOT, OsStr::new("f")));
        assert_eq!(second_id, id);
        assert_eq!(second.ino, first.ino);
        assert_eq!(ok(fs.getattr_inner(first.ino)).size, 3);
    }

    /// E6 / 45 C9: a reserved directory on disk stays invisible.
    #[test]
    fn u_fuse_reserved_lookup_is_enoent() {
        let fixture = fixture();
        let fs = fs(&fixture);
        std::fs::create_dir(fixture.tmp.path().join(".syncmount-staging"))
            .unwrap_or_else(|err| panic!("mkdir: {err}"));
        assert_eq!(
            err(fs.lookup_inner(INodeNo::ROOT, OsStr::new(".syncmount-staging"))),
            Errno::ENOENT
        );
        assert_eq!(
            err(fs.lookup_inner(INodeNo::ROOT, OsStr::new(".audit.log"))),
            Errno::ENOENT
        );
    }

    /// E6 / 45 C9: writes to reserved names are rejected before touching disk.
    #[test]
    fn u_fuse_reserved_write_targets_are_eexist() {
        let fixture = fixture();
        let fs = fs(&fixture);
        assert_eq!(
            err(fs.mkdir_inner(INodeNo::ROOT, OsStr::new(".syncmount-staging"), 0o755, 0)),
            Errno::EEXIST
        );
        assert_eq!(
            err(fs.create_inner(
                INodeNo::ROOT,
                OsStr::new(".syncmount-manifest"),
                0o644,
                0,
                libc::O_CREAT,
            )),
            Errno::EEXIST
        );
        assert_eq!(
            err(fs.mknod_inner(
                INodeNo::ROOT,
                OsStr::new(".audit.log"),
                libc::S_IFREG | 0o644,
                0,
                0,
            )),
            Errno::EEXIST
        );
    }

    /// E6 / 41 §3.3: create and open share the same inode identity.
    #[test]
    fn u_fuse_create_open_and_truncate() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let attr = ok(fs.create_inner(
            INodeNo::ROOT,
            OsStr::new("f"),
            0o644,
            0o022,
            libc::O_CREAT | libc::O_EXCL,
        ));
        assert_eq!(attr.perm, 0o644);
        let id = id_of_attr(&fs, &attr);
        assert_eq!(
            err(fs.create_inner(
                INodeNo::ROOT,
                OsStr::new("f"),
                0o644,
                0,
                libc::O_CREAT | libc::O_EXCL,
            )),
            Errno::EEXIST
        );
        ok(fs.write_inner(attr.ino, 0, b"payload", OpenFlags(0)));
        let truncated = ok(fs.create_inner(
            INodeNo::ROOT,
            OsStr::new("f"),
            0o644,
            0,
            libc::O_CREAT | libc::O_TRUNC,
        ));
        assert_eq!(truncated.size, 0);
        assert_eq!(truncated.ino, attr.ino);
        assert_eq!(ok(fs.getattr_inner(attr.ino)).size, 0);
        assert_eq!(fs.store().nodes().ino_of(id), Some(attr.ino.0));

        let dir = ok(fs.mkdir_inner(INodeNo::ROOT, OsStr::new("d"), 0o755, 0));
        assert_eq!(err(fs.open_inner(dir.ino)), Errno::EISDIR);
    }

    /// E6 / 39 §2.1: O_APPEND anchors at EOF even if the caller sends 0.
    #[test]
    fn u_fuse_write_read_and_append() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let attr = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        assert_eq!(ok(fs.write_inner(attr.ino, 0, b"abc", OpenFlags(0))), 3);
        assert_eq!(ok(fs.read_inner(attr.ino, 0, 16)).as_slice(), &b"abc"[..]);
        assert_eq!(
            ok(fs.write_inner(attr.ino, 0, b"d", OpenFlags(libc::O_APPEND),)),
            1
        );
        assert_eq!(ok(fs.read_inner(attr.ino, 0, 16)).as_slice(), &b"abcd"[..]);
        assert_eq!(ok(fs.read_inner(attr.ino, 1, 2)).as_slice(), &b"bc"[..]);
        ok(fs.fsync_inner(attr.ino, false));
        ok(fs.fsync_inner(attr.ino, true));
    }

    /// E6 / 45 C9 + 41 §5.4: rename semantics and reserved targets.
    #[test]
    fn u_fuse_rename_semantics() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let dir = ok(fs.mkdir_inner(INodeNo::ROOT, OsStr::new("d"), 0o755, 0));
        let dir_id = id_of_attr(&fs, &dir);
        let file = ok(fs.create_inner(dir.ino, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        let file_id = id_of_attr(&fs, &file);
        ok(fs.write_inner(file.ino, 0, b"hello", OpenFlags(0)));

        ok(fs.rename_inner(
            INodeNo::ROOT,
            OsStr::new("d"),
            INodeNo::ROOT,
            OsStr::new("e"),
            RenameFlags::empty(),
        ));
        assert_eq!(
            fs.store().nodes().path_of(file_id),
            Some(PathBuf::from("e/f"))
        );
        assert_eq!(fs.store().nodes().ino_of(file_id), Some(file.ino.0));
        assert_eq!(
            err(fs.lookup_inner(INodeNo::ROOT, OsStr::new("d"))),
            Errno::ENOENT
        );
        assert_eq!(ok(fs.read_inner(file.ino, 0, 16)).as_slice(), &b"hello"[..]);

        let a = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("a"), 0o644, 0, libc::O_CREAT));
        let b = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("b"), 0o644, 0, libc::O_CREAT));
        assert_eq!(
            err(fs.rename_inner(
                INodeNo::ROOT,
                OsStr::new("a"),
                INodeNo::ROOT,
                OsStr::new("b"),
                RenameFlags::RENAME_NOREPLACE,
            )),
            Errno::EEXIST
        );
        assert_eq!(ok(fs.getattr_inner(a.ino)).nlink, 1);
        assert_eq!(ok(fs.getattr_inner(b.ino)).nlink, 1);

        ok(fs.write_inner(a.ino, 0, b"1", OpenFlags(0)));
        ok(fs.write_inner(b.ino, 0, b"22", OpenFlags(0)));
        ok(fs.rename_inner(
            INodeNo::ROOT,
            OsStr::new("a"),
            INodeNo::ROOT,
            OsStr::new("b"),
            RenameFlags::RENAME_EXCHANGE,
        ));
        let a_id = id_of_attr(&fs, &a);
        let b_id = id_of_attr(&fs, &b);
        // EXCHANGE swaps directory entries, not inodes: the inode created as
        // "a" is now reachable as "b" and still holds its own bytes.
        assert_eq!(fs.store().nodes().path_of(a_id), Some(PathBuf::from("b")));
        assert_eq!(fs.store().nodes().path_of(b_id), Some(PathBuf::from("a")));
        assert_eq!(ok(fs.read_inner(a.ino, 0, 8)).as_slice(), &b"1"[..]);
        assert_eq!(ok(fs.read_inner(b.ino, 0, 8)).as_slice(), &b"22"[..]);
        assert_eq!(ok(fs.lookup_inner(INodeNo::ROOT, OsStr::new("a"))).1, b_id);
        assert_eq!(ok(fs.lookup_inner(INodeNo::ROOT, OsStr::new("b"))).1, a_id);

        let sub = ok(fs.mkdir_inner(dir.ino, OsStr::new("sub"), 0o755, 0));
        let sub_id = id_of_attr(&fs, &sub);
        assert_eq!(
            err(fs.rename_inner(
                INodeNo::ROOT,
                OsStr::new("e"),
                sub.ino,
                OsStr::new("e"),
                RenameFlags::empty(),
            )),
            Errno::EINVAL
        );
        assert_eq!(
            fs.store().nodes().path_of(sub_id),
            Some(PathBuf::from("e/sub"))
        );

        assert_eq!(
            err(fs.rename_inner(
                INodeNo::ROOT,
                OsStr::new("a"),
                INodeNo::ROOT,
                OsStr::new(".syncmount"),
                RenameFlags::empty(),
            )),
            Errno::EEXIST
        );
        assert_eq!(fs.store().nodes().path_of(dir_id), Some(PathBuf::from("e")));
    }

    /// E6 / 45 C9: rmdir reports ENOTEMPTY and unlink hides reserved names.
    #[test]
    fn u_fuse_rmdir_and_unlink() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let dir = ok(fs.mkdir_inner(INodeNo::ROOT, OsStr::new("d"), 0o755, 0));
        let file = ok(fs.create_inner(dir.ino, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        assert_eq!(
            err(fs.rmdir_inner(INodeNo::ROOT, OsStr::new("d"))),
            Errno::ENOTEMPTY
        );
        ok(fs.unlink_inner(dir.ino, OsStr::new("f")));
        assert_eq!(err(fs.getattr_inner(file.ino)), Errno::ENOENT);
        ok(fs.rmdir_inner(INodeNo::ROOT, OsStr::new("d")));
        assert_eq!(
            err(fs.lookup_inner(INodeNo::ROOT, OsStr::new("d"))),
            Errno::ENOENT
        );
        assert_eq!(
            err(fs.unlink_inner(INodeNo::ROOT, OsStr::new(".audit.log"))),
            Errno::ENOENT
        );
    }

    /// E6 / 45 §4.3: mknod accepts regular files and FIFOs only.
    #[test]
    fn u_fuse_mknod_surface() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let fifo = ok(fs.mknod_inner(
            INodeNo::ROOT,
            OsStr::new("fifo"),
            libc::S_IFIFO | 0o600,
            0,
            0,
        ));
        assert_eq!(fifo.kind, fuser::FileType::NamedPipe);
        let regular = ok(fs.mknod_inner(
            INodeNo::ROOT,
            OsStr::new("reg"),
            libc::S_IFREG | 0o644,
            0,
            0,
        ));
        assert_eq!(regular.kind, fuser::FileType::RegularFile);
        assert_eq!(
            err(fs.mknod_inner(
                INodeNo::ROOT,
                OsStr::new("chr"),
                libc::S_IFCHR | 0o600,
                0,
                0,
            )),
            Errno::EPERM
        );
        assert_eq!(
            err(fs.mknod_inner(
                INodeNo::ROOT,
                OsStr::new("sock"),
                libc::S_IFSOCK | 0o600,
                0,
                0,
            )),
            Errno::EPERM
        );
    }

    /// E6 / 41 §2.3: symlink creates a symlink inode and readlink returns it.
    #[test]
    fn u_fuse_symlink_and_readlink() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let attr = ok(fs.symlink_inner(INodeNo::ROOT, OsStr::new("link"), Path::new("target")));
        assert_eq!(attr.kind, fuser::FileType::Symlink);
        assert_eq!(ok(fs.readlink_inner(attr.ino)), PathBuf::from("target"));
        assert_eq!(
            err(fs.symlink_inner(INodeNo::ROOT, OsStr::new(".syncmount"), Path::new("x"),)),
            Errno::EEXIST
        );
    }

    /// E6 / 31:M1-3: xattr CRUD and the size-probe protocol.
    #[test]
    fn u_fuse_xattr_roundtrip() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let attr = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        let name = OsStr::new("user.syncmount-test");
        match fs.setxattr_inner(attr.ino, name, b"value", 0) {
            Ok(()) => {}
            Err(err) if err == Errno::EOPNOTSUPP => {
                eprintln!("SKIP[xattr] backing filesystem does not support user xattrs");
                return;
            }
            Err(err) => panic!("setxattr: {err:?}"),
        }
        match ok(fs.getxattr_inner(attr.ino, name, 0)) {
            XattrReply::Size(size) => assert_eq!(size, 5),
            XattrReply::Data(data) => panic!("expected size, got {data:?}"),
        }
        match ok(fs.getxattr_inner(attr.ino, name, 16)) {
            XattrReply::Data(data) => assert_eq!(data.as_slice(), &b"value"[..]),
            XattrReply::Size(size) => panic!("expected data, got size {size}"),
        }
        assert_eq!(err(fs.getxattr_inner(attr.ino, name, 1)), ERANGE);
        let listed = match ok(fs.listxattr_inner(attr.ino, 4096)) {
            XattrReply::Data(data) => data,
            XattrReply::Size(size) => panic!("expected data, got size {size}"),
        };
        assert!(
            listed
                .split(|byte| *byte == 0)
                .any(|item| item == name.as_bytes())
        );
        ok(fs.removexattr_inner(attr.ino, name));
        assert_eq!(
            err(fs.getxattr_inner(attr.ino, name, 0)).raw(),
            libc::ENODATA
        );
    }

    /// E6 / 45 §4.3: statfs and access reach the backing tree.
    #[test]
    fn u_fuse_statfs_and_access() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let stat = ok(fs.statfs_inner());
        assert!(stat.f_blocks > 0);
        assert!(stat.f_bsize > 0);
        let attr = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        ok(fs.access_inner(attr.ino, 0));
        ok(fs.access_inner(attr.ino, fuser::AccessFlags::R_OK.bits()));
    }

    /// E6 / 39 §4: fallocate degrades holes to zero writes; lseek is defined.
    #[test]
    fn u_fuse_fallocate_lseek_and_copy() {
        let fixture = fixture();
        let fs = fs(&fixture);
        let attr = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("f"), 0o644, 0, libc::O_CREAT));
        ok(fs.write_inner(attr.ino, 0, b"hello world", OpenFlags(0)));
        assert_eq!(ok(fs.lseek_inner(attr.ino, 6, libc::SEEK_SET)), 6);
        assert_eq!(ok(fs.lseek_inner(attr.ino, 0, libc::SEEK_END)), 11);
        assert_eq!(ok(fs.lseek_inner(attr.ino, -5, libc::SEEK_END)), 6);
        assert_eq!(ok(fs.lseek_inner(attr.ino, 0, libc::SEEK_DATA)), 0);
        assert_eq!(ok(fs.lseek_inner(attr.ino, 0, libc::SEEK_HOLE)), 11);
        assert_eq!(
            err(fs.lseek_inner(attr.ino, 11, libc::SEEK_DATA)),
            Errno(libc::ENXIO)
        );

        let punch = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
        ok(fs.fallocate_inner(attr.ino, 0, 4, punch));
        assert_eq!(ok(fs.read_inner(attr.ino, 0, 4)).as_slice(), &[0u8; 4][..]);
        assert_eq!(
            err(fs.fallocate_inner(attr.ino, 0, 4, libc::FALLOC_FL_COLLAPSE_RANGE)),
            Errno::EOPNOTSUPP
        );

        let dst = ok(fs.create_inner(INodeNo::ROOT, OsStr::new("dst"), 0o644, 0, libc::O_CREAT));
        assert_eq!(
            ok(fs.copy_file_range_inner(attr.ino, 6, dst.ino, 0, 5, CopyFileRangeFlags::empty(),)),
            5
        );
        assert_eq!(ok(fs.read_inner(dst.ino, 0, 16)).as_slice(), &b"world"[..]);
    }

    /// E6 / 41 §3.6: dot entries occupy offsets 1 and 2; backing entries
    /// start at 3 and map back to cursor 1.
    #[test]
    fn u_fuse_readdir_cursor_plan() {
        assert_eq!(
            readdir_plan(0),
            ReaddirPlan {
                dot: true,
                dotdot: true,
                cursor: 0
            }
        );
        assert_eq!(
            readdir_plan(1),
            ReaddirPlan {
                dot: false,
                dotdot: true,
                cursor: 0
            }
        );
        assert_eq!(
            readdir_plan(2),
            ReaddirPlan {
                dot: false,
                dotdot: false,
                cursor: 0
            }
        );
        assert_eq!(
            readdir_plan(3),
            ReaddirPlan {
                dot: false,
                dotdot: false,
                cursor: 1
            }
        );
        assert_eq!(readdir_plan(10).cursor, 8);
    }

    /// E6 / 41 §4: readdir lazily learns identities without duplicating them.
    #[test]
    fn u_fuse_ensure_child_is_idempotent() {
        let fixture = fixture();
        std::fs::write(fixture.tmp.path().join("f"), b"abc")
            .unwrap_or_else(|err| panic!("write: {err}"));
        let first = ok(ensure_child(
            fixture.backing.as_ref(),
            InodeId::ROOT,
            OsStr::new("f"),
            Kind::Unknown,
        ));
        let second = ok(ensure_child(
            fixture.backing.as_ref(),
            InodeId::ROOT,
            OsStr::new("f"),
            Kind::File,
        ));
        assert_eq!(first, second);
        assert_eq!(fixture.backing.nodes().ino_of(first), Some(ROOT_INO + 1));
        assert_eq!(
            err(ensure_child(
                fixture.backing.as_ref(),
                InodeId::ROOT,
                OsStr::new(".syncmount"),
                Kind::File,
            )),
            Errno::ENOENT
        );
    }

    // -----------------------------------------------------------------
    // W13b: the write path
    // -----------------------------------------------------------------

    use std::time::Duration;

    use crate::client::{
        IncomingOp, InstanceId, LocalOp, Op, OpBody, OpData, Outbox, PendingOverlay, Replayer,
        State, SyncHandle, Tuning, WriteGate,
    };
    use crate::fuse::ReplayView;
    use crate::fuse::notify::Invalidation;
    use crate::fuse::write_path::WritePath;
    use crate::protocol::frame::{ClientId, OpId, Seq, SessionId};
    use crate::protocol::messages::{DataRef, OpClass};
    use crate::store::NodeTable;

    struct PathFixture {
        tmp: TempDir,
        backing: Arc<PosixBacking>,
        nodes: Arc<NodeTable>,
        gate: Arc<WriteGate>,
        outbox: Arc<Outbox>,
        pending: Arc<PendingOverlay>,
        fs: FuseFs<PosixBacking>,
    }

    fn path_fixture() -> PathFixture {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let root =
            RootFd::open_before_mount(tmp.path()).unwrap_or_else(|err| panic!("open root: {err}"));
        let nodes = Arc::new(NodeTable::new());
        let backing = Arc::new(PosixBacking::with_nodes(Arc::new(root), Arc::clone(&nodes)));
        let gate = Arc::new(WriteGate::new(State::Steady));
        let outbox = Arc::new(Outbox::with_tuning(&Tuning::default()));
        let pending = Arc::new(PendingOverlay::new());
        let path = WritePath::new(
            Arc::clone(&gate),
            Arc::clone(&outbox),
            Arc::clone(&pending),
            InstanceId(7),
            ClientId::from_bytes([9; 16]),
        );
        let fs = FuseFs::with_write_path(Arc::clone(&backing), path);
        PathFixture {
            tmp,
            backing,
            nodes,
            gate,
            outbox,
            pending,
            fs,
        }
    }

    fn take_classes(outbox: &Outbox) -> Vec<OpClass> {
        let mut classes = Vec::new();
        while let Some(queued) = outbox.take_ready() {
            classes.push(match queued.op {
                LocalOp::Write { .. } => OpClass::WRITE,
                LocalOp::Truncate { .. } => OpClass::TRUNCATE,
                LocalOp::SetAttr { .. } => OpClass::SETATTR,
                LocalOp::Xattr { .. } => OpClass::SETATTR,
                LocalOp::Meta { class, .. } => class,
            });
        }
        classes
    }

    /// W13b / C-09: the gate refuses before the disk and the outbox move.
    #[test]
    fn u_fuse_write_path_gate_and_local_read() {
        let fixture = path_fixture();
        std::fs::write(fixture.tmp.path().join("f"), b"old")
            .unwrap_or_else(|err| panic!("write: {err}"));
        let (attr, _) = ok(fixture.fs.lookup_inner(INodeNo::ROOT, OsStr::new("f")));

        for (state, expected) in [
            (State::Joining, Errno::EROFS),
            (State::DegradedReadOnly, Errno::EROFS),
            (State::Unmounting, Errno(libc::ENOTCONN)),
        ] {
            fixture.gate.set(state);
            assert_eq!(
                err(fixture.fs.write_inner(attr.ino, 0, b"new", OpenFlags(0))),
                expected,
                "state {state:?}"
            );
            assert!(fixture.outbox.is_empty());
            assert_eq!(
                std::fs::read(fixture.tmp.path().join("f"))
                    .unwrap_or_else(|err| panic!("read: {err}")),
                b"old"
            );
        }

        fixture.gate.set(State::Steady);
        assert_eq!(
            ok(fixture.fs.write_inner(attr.ino, 0, b"new", OpenFlags(0))),
            3
        );
        assert_eq!(fixture.outbox.depth().ops, 1);
        assert_eq!(ok(fixture.fs.read_inner(attr.ino, 0, 3)), b"new".to_vec());
        assert_eq!(fixture.pending.len(), 1);
    }

    /// W13b: every namespace mutation queues exactly one operation, in order.
    #[test]
    fn u_fuse_write_path_metadata_ops() {
        let fixture = path_fixture();
        let root = INodeNo::ROOT;

        // Reserved names stay masked before the gate or the outbox is used.
        assert_eq!(
            err(fixture
                .fs
                .mkdir_inner(root, OsStr::new(".syncmount-staging"), 0o755, 0)),
            Errno::EEXIST
        );

        let dir = ok(fixture.fs.mkdir_inner(root, OsStr::new("d"), 0o755, 0));
        let file = ok(fixture.fs.create_inner(
            dir.ino,
            OsStr::new("f"),
            0o644,
            0,
            libc::O_CREAT | libc::O_EXCL,
        ));
        assert_eq!(
            ok(fixture.fs.write_inner(file.ino, 0, b"hi", OpenFlags(0))),
            2
        );
        ok(fixture
            .fs
            .setattr_inner(file.ino, Some(0o600), None, None, None, None, None));
        ok(fixture
            .fs
            .setattr_inner(file.ino, None, None, None, Some(1), None, None));
        ok(fixture.fs.link_inner(file.ino, dir.ino, OsStr::new("h")));
        ok(fixture.fs.rename_inner(
            dir.ino,
            OsStr::new("h"),
            dir.ino,
            OsStr::new("g"),
            RenameFlags::empty(),
        ));
        ok(fixture
            .fs
            .symlink_inner(dir.ino, OsStr::new("s"), Path::new("f")));
        ok(fixture.fs.unlink_inner(dir.ino, OsStr::new("g")));
        ok(fixture.fs.unlink_inner(dir.ino, OsStr::new("s")));
        ok(fixture.fs.unlink_inner(dir.ino, OsStr::new("f")));
        ok(fixture.fs.rmdir_inner(root, OsStr::new("d")));

        assert_eq!(
            take_classes(&fixture.outbox),
            vec![
                OpClass::MKDIR,
                OpClass::CREATE_EXCL,
                OpClass::WRITE,
                OpClass::SETATTR,
                OpClass::TRUNCATE,
                OpClass::LINK,
                OpClass::RENAME,
                OpClass::SYMLINK,
                OpClass::UNLINK,
                OpClass::UNLINK,
                OpClass::UNLINK,
                OpClass::RMDIR,
            ]
        );
        // The data operations (write, setattr, truncate) carry optimistic
        // effects; metadata operations rely on ReplayView idempotence.
        assert_eq!(fixture.pending.len(), 3);
    }

    /// W13b: a failed mutation must not stall every later operation.
    #[test]
    fn u_fuse_failed_mutation_does_not_stall_outbox() {
        let fixture = path_fixture();
        std::fs::create_dir(fixture.tmp.path().join("d"))
            .unwrap_or_else(|err| panic!("mkdir: {err}"));
        // The directory exists on disk but not in the node table, so the
        // local create hits EEXIST after admission.
        assert_eq!(
            err(fixture
                .fs
                .mkdir_inner(INodeNo::ROOT, OsStr::new("d"), 0o755, 0)),
            Errno::EEXIST
        );
        assert!(fixture.outbox.is_empty());

        std::fs::write(fixture.tmp.path().join("f"), b"x")
            .unwrap_or_else(|err| panic!("write: {err}"));
        let (attr, _) = ok(fixture.fs.lookup_inner(INodeNo::ROOT, OsStr::new("f")));
        ok(fixture.fs.write_inner(attr.ino, 0, b"y", OpenFlags(0)));
        assert_eq!(take_classes(&fixture.outbox), vec![OpClass::WRITE]);
    }

    /// W13b: a remote ORDERED is materialised and the FUSE view follows it.
    #[test]
    fn i_fuse_remote_ordered_updates_view() {
        let fixture = path_fixture();
        let mut replayer = Replayer::new(
            ClientId::from_bytes([9; 16]),
            Seq::UNSEQUENCED,
            1,
            &Tuning::default(),
            Arc::clone(&fixture.pending),
        );
        let view = ReplayView::new(
            Arc::clone(&fixture.backing),
            Arc::clone(&fixture.nodes),
            fixture.fs.notify_handle(),
        );
        let remote = ClientId::from_bytes([8; 16]);

        let mkdir = Op::new(OpId::from_bytes([2; 16]), remote, OpClass::MKDIR, "/d")
            .with_body(OpBody::Mkdir { mode: 0o755 });
        ok(replayer.on_ordered(
            IncomingOp::new(Seq(1), 1, mkdir),
            Duration::ZERO,
            &view,
            &NoData,
        ));
        let (dir, _) = ok(fixture.fs.lookup_inner(INodeNo::ROOT, OsStr::new("d")));
        assert_eq!(dir.kind, fuser::FileType::Directory);
        assert!(fixture.tmp.path().join("d").is_dir());

        let create = Op::new(
            OpId::from_bytes([3; 16]),
            remote,
            OpClass::CREATE_EXCL,
            "/d/f",
        )
        .with_body(OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        });
        ok(replayer.on_ordered(
            IncomingOp::new(Seq(2), 1, create),
            Duration::ZERO,
            &view,
            &NoData,
        ));
        let (file, _) = ok(fixture.fs.lookup_inner(dir.ino, OsStr::new("f")));

        let data = DataRef {
            session: SessionId::from_le_bytes([0; 16]),
            total_len: 5,
            data_hash: *blake3::hash(b"hello").as_bytes(),
        };
        let write = Op::new(OpId::from_bytes([4; 16]), remote, OpClass::WRITE, "/d/f")
            .with_body(OpBody::Write(data));
        ok(replayer.on_ordered(
            IncomingOp::new(Seq(3), 1, write),
            Duration::ZERO,
            &view,
            &OwnedData(b"hello".to_vec()),
        ));
        assert_eq!(ok(fixture.fs.read_inner(file.ino, 0, 5)), b"hello".to_vec());

        let recorded = fixture.fs.notify().recorded();
        assert!(recorded.iter().any(|event| matches!(
            event,
            Invalidation::Entry { parent, name }
                if *parent == INodeNo::ROOT && name == OsStr::new("d")
        )));
        assert!(recorded.iter().any(|event| matches!(
            event,
            Invalidation::Entry { parent, name }
                if *parent == dir.ino && name == OsStr::new("f")
        )));
        assert!(recorded.iter().any(|event| matches!(
            event,
            Invalidation::Inode { ino, offset: 0, len: 5 } if *ino == file.ino
        )));
    }

    struct NoData;

    impl OpData for NoData {
        fn read(&self, _data: &DataRef) -> Result<Vec<u8>> {
            Err(Errno::EIO)
        }
    }

    struct OwnedData(Vec<u8>);

    impl OpData for OwnedData {
        fn read(&self, _data: &DataRef) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    struct MaybeData(Option<Vec<u8>>);

    impl OpData for MaybeData {
        fn read(&self, _data: &DataRef) -> Result<Vec<u8>> {
            self.0.clone().ok_or(Errno::EIO)
        }
    }

    /// Rebuild the wire operation from one queued local operation.
    ///
    /// This is the test-side counterpart of the uplink encoder: it proves the
    /// write path leaves enough information in `LocalOp` for a remote client
    /// to replay the change.
    fn op_from_local(
        op: LocalOp,
        op_id: OpId,
        client_id: ClientId,
        nodes: &NodeTable,
    ) -> (Op, Option<Vec<u8>>) {
        use crate::protocol::frame::Limits;
        use crate::protocol::messages::{FieldMap, fid};
        match op {
            LocalOp::Write { ino, off, data } => {
                let path = absolute_path(nodes, ino).unwrap_or_else(|err| panic!("{err:?}"));
                let reference = DataRef {
                    session: SessionId::from_le_bytes([0; 16]),
                    total_len: data.len() as u64,
                    data_hash: *blake3::hash(&data).as_bytes(),
                };
                let (class, body) = if off == 0 {
                    (OpClass::WRITE, OpBody::Write(reference))
                } else {
                    (
                        OpClass::PWRITE,
                        OpBody::Pwrite {
                            offset: off,
                            data: reference,
                        },
                    )
                };
                (
                    Op::new(op_id, client_id, class, path).with_body(body),
                    Some(data),
                )
            }
            LocalOp::Truncate { ino, size } => {
                let path = absolute_path(nodes, ino).unwrap_or_else(|err| panic!("{err:?}"));
                (
                    Op::new(op_id, client_id, OpClass::TRUNCATE, path)
                        .with_body(OpBody::Truncate { length: size }),
                    None,
                )
            }
            LocalOp::SetAttr { ino, delta } => {
                let path = absolute_path(nodes, ino).unwrap_or_else(|err| panic!("{err:?}"));
                (
                    Op::new(op_id, client_id, OpClass::SETATTR, path)
                        .with_body(OpBody::Setattr { mode: delta.mode }),
                    None,
                )
            }
            LocalOp::Xattr { .. } => panic!("xattr has no v1 op class"),
            LocalOp::Meta { class, body, .. } => {
                let fields = FieldMap::parse(&body, &Limits::default())
                    .unwrap_or_else(|err| panic!("body: {err}"));
                let path = fields
                    .str(fid::F_PATH)
                    .unwrap_or_else(|err| panic!("path: {err}"))
                    .unwrap_or_else(|| panic!("missing path"))
                    .to_string();
                let attrs = crate::client::OpAttrs {
                    mode: fields.u32(fid::F_MODE).unwrap_or(None),
                    uid: fields.u32(fid::F_UID).unwrap_or(None).unwrap_or(0),
                    gid: fields.u32(fid::F_GID).unwrap_or(None).unwrap_or(0),
                    mtime_ns: fields.u64(fid::F_MTIME_NS).unwrap_or(None).unwrap_or(0),
                };
                let body = match class {
                    OpClass::MKDIR => OpBody::Mkdir {
                        mode: fields.u32(fid::F_MODE).unwrap_or(None).unwrap_or(0),
                    },
                    OpClass::CREATE_EXCL => OpBody::CreateExcl {
                        mode: fields.u32(fid::F_MODE).unwrap_or(None).unwrap_or(0),
                        flags: fields.u32(fid::F_OP_FLAGS).unwrap_or(None).unwrap_or(0),
                    },
                    OpClass::RENAME => OpBody::Rename {
                        path2: fields
                            .str(fid::F_PATH2)
                            .unwrap_or(None)
                            .unwrap_or_default()
                            .to_string(),
                    },
                    OpClass::LINK => OpBody::Link {
                        target: fields
                            .str(fid::F_TARGET)
                            .unwrap_or(None)
                            .unwrap_or_default()
                            .to_string(),
                    },
                    OpClass::SYMLINK => OpBody::Symlink {
                        target: fields
                            .str(fid::F_TARGET)
                            .unwrap_or(None)
                            .unwrap_or_default()
                            .to_string(),
                    },
                    OpClass::FCNTL_LOCK => OpBody::Lock {
                        lock_type: fields.u8(fid::F_LOCK_TYPE).unwrap_or(None).unwrap_or(0),
                        action: fields.u8(fid::F_LOCK_ACTION).unwrap_or(None).unwrap_or(0),
                        start: fields.u64(fid::F_LOCK_START).unwrap_or(None).unwrap_or(0),
                        len: fields.u64(fid::F_LOCK_LEN).unwrap_or(None).unwrap_or(0),
                        flock: false,
                    },
                    OpClass::UNLINK | OpClass::RMDIR => OpBody::None,
                    other => panic!("unexpected metadata class {other:?}"),
                };
                (
                    Op::new(op_id, client_id, class, path)
                        .with_attrs(attrs)
                        .with_body(body),
                    None,
                )
            }
        }
    }

    /// W13b / 31:M3: client A writes through FUSE, client B replays the
    /// broadcast and reads the same bytes through its own FUSE adapter.
    #[test]
    fn i_fuse_two_client_write_read_smoke() {
        let a = path_fixture();
        let b = path_fixture();
        let mut replayer = Replayer::new(
            ClientId::from_bytes([10; 16]),
            Seq::UNSEQUENCED,
            1,
            &Tuning::default(),
            Arc::clone(&b.pending),
        );
        let view = ReplayView::new(
            Arc::clone(&b.backing),
            Arc::clone(&b.nodes),
            b.fs.notify_handle(),
        );

        let dir = ok(a.fs.mkdir_inner(INodeNo::ROOT, OsStr::new("d"), 0o755, 0));
        let file = ok(a.fs.create_inner(
            dir.ino,
            OsStr::new("f"),
            0o644,
            0,
            libc::O_CREAT | libc::O_EXCL,
        ));
        assert_eq!(ok(a.fs.write_inner(file.ino, 0, b"hello", OpenFlags(0))), 5);

        let mut seq = 1;
        while let Some(queued) = a.outbox.take_ready() {
            let (op, data) = op_from_local(
                queued.op,
                queued.op_id,
                ClientId::from_bytes([9; 16]),
                a.fs.store().nodes(),
            );
            ok(replayer.on_ordered(
                IncomingOp::new(Seq(seq), 1, op),
                Duration::ZERO,
                &view,
                &MaybeData(data),
            ));
            seq += 1;
        }

        let (dir_b, _) = ok(b.fs.lookup_inner(INodeNo::ROOT, OsStr::new("d")));
        let (file_b, _) = ok(b.fs.lookup_inner(dir_b.ino, OsStr::new("f")));
        assert_eq!(ok(b.fs.read_inner(file_b.ino, 0, 5)), b"hello".to_vec());
        assert_eq!(file_b.nlink, 1);
    }

    // -----------------------------------------------------------------
    // W22: L2 synchronous metadata and record locks
    // -----------------------------------------------------------------

    struct SyncFixture {
        tmp: TempDir,
        backing: Arc<PosixBacking>,
        nodes: Arc<NodeTable>,
        outbox: Arc<Outbox>,
        fs: Arc<FuseFs<PosixBacking>>,
        replayer: Replayer,
        client: ClientId,
    }

    /// One mount whose write path and replayer share a [`SyncHandle`].
    fn sync_fixture(client: u8) -> SyncFixture {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let root =
            RootFd::open_before_mount(tmp.path()).unwrap_or_else(|err| panic!("open root: {err}"));
        let nodes = Arc::new(NodeTable::new());
        let backing = Arc::new(PosixBacking::with_nodes(Arc::new(root), Arc::clone(&nodes)));
        let gate = Arc::new(WriteGate::new(State::Steady));
        let outbox = Arc::new(Outbox::with_tuning(&Tuning::default()));
        let pending = Arc::new(PendingOverlay::new());
        let client_id = ClientId::from_bytes([client; 16]);
        let sync = SyncHandle::new();
        let replayer = Replayer::new(
            client_id,
            Seq::UNSEQUENCED,
            1,
            &Tuning::default(),
            Arc::clone(&pending),
        )
        .with_sync(sync.clone());
        let path = WritePath::new(
            Arc::clone(&gate),
            Arc::clone(&outbox),
            Arc::clone(&pending),
            InstanceId(u64::from(client)),
            client_id,
        )
        .with_sync(sync);
        let fs = Arc::new(FuseFs::with_write_path(Arc::clone(&backing), path));
        SyncFixture {
            tmp,
            backing,
            nodes,
            outbox,
            fs,
            replayer,
            client: client_id,
        }
    }

    /// Take the operation the blocked callback queued.
    fn next_meta(fixture: &SyncFixture) -> Op {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(queued) = fixture.outbox.take_ready() {
                let (op, _) = op_from_local(
                    queued.op,
                    queued.op_id,
                    fixture.client,
                    fixture.fs.store().nodes(),
                );
                return op;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the callback did not queue an operation"
            );
            std::thread::yield_now();
        }
    }

    /// Apply one ordered operation to a fixture, as the replay pump would.
    fn apply(fixture: &mut SyncFixture, op: Op, seq: u64) -> Result<(), Errno> {
        let view = ReplayView::new(
            Arc::clone(&fixture.backing),
            Arc::clone(&fixture.nodes),
            fixture.fs.notify_handle(),
        );
        let progress = fixture
            .replayer
            .on_ordered(
                IncomingOp::new(Seq(seq), 1, op),
                Duration::ZERO,
                &view,
                &NoData,
            )
            .unwrap_or_else(|fatal| panic!("replay failed: {fatal}"));
        progress.verdict
    }

    /// 39 §2.1: the adapter negotiates record locks only with a replayer.
    #[test]
    fn u_fuse_sync_capabilities_include_posix_locks() {
        let fixture = sync_fixture(9);
        let capabilities = fixture.fs.capabilities();
        assert!(capabilities.contains(InitFlags::FUSE_POSIX_LOCKS));
        assert!(!capabilities.contains(InitFlags::FUSE_FLOCK_LOCKS));

        let local = path_fixture();
        assert!(
            !local
                .fs
                .capabilities()
                .contains(InitFlags::FUSE_POSIX_LOCKS)
        );
    }

    /// L2: `rename` returns only after its own sequence was applied.
    #[test]
    fn u_fuse_sync_rename_waits_for_echo() {
        let mut a = sync_fixture(9);
        let create = Op::new(
            OpId::from_bytes([1; 16]),
            ClientId::from_bytes([8; 16]),
            OpClass::CREATE_EXCL,
            "/f",
        )
        .with_body(OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        });
        assert_eq!(apply(&mut a, create, 1), Ok(()));
        assert!(a.tmp.path().join("f").is_file());

        let fs = Arc::clone(&a.fs);
        let call = std::thread::spawn(move || {
            fs.rename_sync(
                MetaOwner::default(),
                INodeNo::ROOT,
                OsStr::new("f"),
                INodeNo::ROOT,
                OsStr::new("g"),
                RenameFlags::empty(),
            )
        });
        let op = next_meta(&a);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!call.is_finished(), "rename returned before its echo");
        // The callback did not touch the disk: the rename is the echo's job.
        assert!(a.tmp.path().join("f").is_file());
        assert!(!a.tmp.path().join("g").exists());

        assert_eq!(apply(&mut a, op, 2), Ok(()));
        call.join().unwrap().unwrap();
        assert!(!a.tmp.path().join("f").exists());
        assert!(a.tmp.path().join("g").is_file());
    }

    /// L2: two `O_EXCL` creates, one sequence order, exactly one success.
    #[test]
    fn u_fuse_sync_o_excl_has_one_winner() {
        let mut a = sync_fixture(9);
        let mut b = sync_fixture(10);
        let fs_a = Arc::clone(&a.fs);
        let fs_b = Arc::clone(&b.fs);
        let call_a = std::thread::spawn(move || {
            fs_a.create_sync(
                MetaOwner::default(),
                INodeNo::ROOT,
                OsStr::new("f"),
                0o644,
                0,
                libc::O_CREAT | libc::O_EXCL,
            )
        });
        let call_b = std::thread::spawn(move || {
            fs_b.create_sync(
                MetaOwner::default(),
                INodeNo::ROOT,
                OsStr::new("f"),
                0o644,
                0,
                libc::O_CREAT | libc::O_EXCL,
            )
        });
        let op_a = next_meta(&a);
        let op_b = next_meta(&b);
        let id_a = derive_inode_id(op_a.op_id);
        let id_b = derive_inode_id(op_b.op_id);
        assert_ne!(id_a, id_b);

        // The sequencer orders A first; both clients apply both operations.
        assert_eq!(apply(&mut a, op_a.clone(), 1), Ok(()));
        assert_eq!(apply(&mut b, op_a, 1), Ok(()));
        assert_eq!(apply(&mut a, op_b.clone(), 2), Err(Errno::EEXIST));
        assert_eq!(apply(&mut b, op_b, 2), Err(Errno::EEXIST));

        assert!(call_a.join().unwrap().is_ok(), "A must win");
        assert_eq!(call_b.join().unwrap().unwrap_err(), Errno::EEXIST);

        // Exactly one file, with A's identity, on both trees.
        assert_eq!(a.nodes.lookup(InodeId::ROOT, OsStr::new("f")), Some(id_a));
        assert_eq!(b.nodes.lookup(InodeId::ROOT, OsStr::new("f")), Some(id_a));
        assert!(a.tmp.path().join("f").is_file());
        assert!(b.tmp.path().join("f").is_file());
    }

    /// L2: A's `fcntl` write lock makes B's `F_SETLK` answer `EAGAIN`, and
    /// B's `F_GETLK` names A's lock.
    #[test]
    fn u_fuse_sync_fcntl_mutex() {
        let mut a = sync_fixture(9);
        let mut b = sync_fixture(10);
        let create = Op::new(
            OpId::from_bytes([2; 16]),
            ClientId::from_bytes([8; 16]),
            OpClass::CREATE_EXCL,
            "/f",
        )
        .with_body(OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        });
        assert_eq!(apply(&mut a, create.clone(), 1), Ok(()));
        assert_eq!(apply(&mut b, create, 1), Ok(()));
        let id = derive_inode_id(OpId::from_bytes([2; 16]));
        let ino_a = INodeNo(a.nodes.ino_of(id).expect("A ino"));
        let ino_b = INodeNo(b.nodes.ino_of(id).expect("B ino"));

        // A takes a write lock over the whole file.
        let fs_a = Arc::clone(&a.fs);
        let lock_a = std::thread::spawn(move || {
            fs_a.setlk_inner(
                MetaOwner::default(),
                ino_a,
                0,
                u64::MAX,
                libc::F_WRLCK,
                false,
            )
        });
        let lock_op = next_meta(&a);
        assert_eq!(apply(&mut a, lock_op.clone(), 2), Ok(()));
        lock_a.join().unwrap().unwrap();

        // The same ordered lock reaches B.
        assert_eq!(apply(&mut b, lock_op, 2), Ok(()));
        let conflict =
            b.fs.getlk_inner(ino_b, 0, u64::MAX, libc::F_WRLCK)
                .unwrap()
                .expect("A's lock must be visible to B");
        assert_eq!(conflict.1.typ, LockType::Write);
        assert_eq!(conflict.1.holder.client, a.client);

        // A lock held by the asking client is not a conflict.
        assert!(
            a.fs.getlk_inner(ino_a, 0, u64::MAX, libc::F_WRLCK)
                .unwrap()
                .is_none()
        );

        // B's conflicting request is refused by the total order.
        let fs_b = Arc::clone(&b.fs);
        let lock_b = std::thread::spawn(move || {
            fs_b.setlk_inner(
                MetaOwner::default(),
                ino_b,
                0,
                u64::MAX,
                libc::F_WRLCK,
                false,
            )
        });
        let op_b = next_meta(&b);
        assert_eq!(apply(&mut b, op_b, 3), Err(Errno::EAGAIN));
        assert_eq!(lock_b.join().unwrap().unwrap_err(), Errno::EAGAIN);

        // Releasing A's lock lets B through.
        let fs_a = Arc::clone(&a.fs);
        let unlock_a = std::thread::spawn(move || {
            fs_a.setlk_inner(
                MetaOwner::default(),
                ino_a,
                0,
                u64::MAX,
                libc::F_UNLCK,
                false,
            )
        });
        let unlock_op = next_meta(&a);
        assert_eq!(apply(&mut a, unlock_op.clone(), 3), Ok(()));
        unlock_a.join().unwrap().unwrap();
        assert_eq!(apply(&mut b, unlock_op, 4), Ok(()));

        let fs_b = Arc::clone(&b.fs);
        let retry = std::thread::spawn(move || {
            fs_b.setlk_inner(
                MetaOwner::default(),
                ino_b,
                0,
                u64::MAX,
                libc::F_WRLCK,
                false,
            )
        });
        let retry_op = next_meta(&b);
        assert_eq!(apply(&mut b, retry_op, 5), Ok(()));
        retry.join().unwrap().unwrap();
    }
}
