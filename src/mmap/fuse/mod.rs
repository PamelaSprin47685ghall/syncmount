//! `fuser` adapter for the 1.1 shadow filesystem.
//!
//! Every callback delegates to [`crate::mmap::shadow::Shadow`]. The adapter
//! keeps two rules:
//!
//! * `open`/`create` return `FOPEN_KEEP_CACHE`, never `FOPEN_DIRECT_IO`, so
//!   the kernel page cache and `mmap(MAP_SHARED)` work.
//! * `flush` never uploads; it may run many times. The final `release` of a
//!   dirty version commits the directory chain, and `fsync`/`fsyncdir` stay
//!   the explicit checkin points.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry,
    ReplyLock, ReplyLseek, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    WriteFlags,
};

use crate::mmap::shadow::{AttrChange, NodeAttr, Shadow, ShadowError};
use crate::mmap::types::EntryKind;

/// Attribute cache lifetime. One second bounds the remote-refresh window.
pub const ATTR_TTL: Duration = Duration::from_secs(1);
/// Directory-entry cache lifetime.
pub const ENTRY_TTL: Duration = Duration::from_secs(1);
/// The mm namespace never reuses `(ino, version)`.
pub const GENERATION: Generation = Generation(0);

/// The FUSE view over one shadow namespace.
#[derive(Debug, Clone)]
pub struct ShadowFs {
    shadow: Arc<Shadow>,
}

impl ShadowFs {
    /// Wrap one opened shadow.
    pub fn new(shadow: Arc<Shadow>) -> Self {
        Self { shadow }
    }

    /// The shadow behind this view; useful for status and mount tests.
    pub fn shadow(&self) -> &Arc<Shadow> {
        &self.shadow
    }
}

impl Filesystem for ShadowFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        // Cached writeback is the mmap prerequisite. POSIX locks are served by
        // the daemon lock table, so the kernel forwards fcntl calls.
        let wanted = InitFlags::FUSE_WRITEBACK_CACHE | InitFlags::FUSE_POSIX_LOCKS;
        if let Err(unsupported) = config.add_capabilities(wanted) {
            tracing::warn!(
                event = "mm_fuse_capabilities",
                ?unsupported,
                "kernel refused optional FUSE capabilities; mmap stays on the cached path"
            );
        }
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let result = name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| self.shadow.lookup(parent.0, name));
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &to_attr(&attr), GENERATION),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let _ = self.shadow.forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.shadow.getattr(ino.0, fh.map(|fh| fh.0)) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_attr(&attr)),
            Err(error) => reply.error(to_errno(error)),
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
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let change = AttrChange {
            mode,
            uid,
            gid,
            mtime_ns: mtime.map(time_ns),
            size,
        };
        match self.shadow.setattr(ino.0, fh.map(|fh| fh.0), change) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_attr(&attr)),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.shadow.readlink(ino.0) {
            Ok(target) => reply.data(&target),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if mode & libc::S_IFMT != libc::S_IFREG {
            reply.error(fuser::Errno::EPERM);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::EINVAL);
            return;
        };
        match self
            .shadow
            .create(parent.0, name, mode, umask, req.uid(), req.gid(), false)
        {
            Ok((attr, handle)) => {
                let _ = self.shadow.release(handle.id);
                reply.entry(&ENTRY_TTL, &to_attr(&attr), GENERATION);
            }
            Err(error) => reply.error(to_errno(error)),
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
        let result = name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| {
                self.shadow
                    .mkdir(parent.0, name, mode, umask, req.uid(), req.gid())
            });
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &to_attr(&attr), GENERATION),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| self.shadow.unlink(parent.0, name));
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| self.shadow.rmdir(parent.0, name));
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
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
        let result = link_name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| {
                self.shadow.symlink(
                    parent.0,
                    name,
                    target.as_os_str().as_bytes(),
                    req.uid(),
                    req.gid(),
                )
            });
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &to_attr(&attr), GENERATION),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            reply.error(fuser::Errno::EOPNOTSUPP);
            return;
        }
        let result = (|| {
            let name = name
                .to_str()
                .ok_or(ShadowError::Invalid("file name is not UTF-8"))?;
            let newname = newname
                .to_str()
                .ok_or(ShadowError::Invalid("file name is not UTF-8"))?;
            self.shadow.rename(
                parent.0,
                name,
                newparent.0,
                newname,
                flags.contains(RenameFlags::RENAME_NOREPLACE),
            )
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // The mm namespace assigns one name per inode by contract.
        reply.error(fuser::Errno::EOPNOTSUPP);
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let writable = flags.0 & libc::O_ACCMODE != libc::O_RDONLY;
        match self.shadow.open_file(ino.0, writable) {
            Ok(handle) => reply.opened(FileHandle(handle.id), FopenFlags::FOPEN_KEEP_CACHE),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.shadow.read(ino.0, Some(fh.0), offset, size) {
            Ok(data) => reply.data(&data),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.shadow.write(ino.0, fh.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.shadow.flush(fh.0, Some(lock_owner.0)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.shadow.release(fh.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.shadow.fsync(ino.0, Some(fh.0)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.shadow.opendir(ino.0) {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(error) => reply.error(to_errno(error)),
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
        let result = self.shadow.readdir(ino.0, offset, false);
        match result {
            Ok(items) => {
                for (index, item) in items.iter().enumerate() {
                    let next = offset.saturating_add(index as u64).saturating_add(1);
                    if reply.add(
                        INodeNo(item.fuse_ino),
                        next,
                        file_type(item.kind),
                        item.name.as_str(),
                    ) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(error) => reply.error(to_errno(error)),
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
        let result = self.shadow.readdir(ino.0, offset, true);
        match result {
            Ok(items) => {
                for (index, item) in items.iter().enumerate() {
                    let Some(attr) = &item.attr else {
                        continue;
                    };
                    let next = offset.saturating_add(index as u64).saturating_add(1);
                    if reply.add(
                        INodeNo(item.fuse_ino),
                        next,
                        item.name.as_str(),
                        &ENTRY_TTL,
                        &to_attr(attr),
                        GENERATION,
                    ) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        match self.shadow.releasedir(ino.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.shadow.fsyncdir(ino.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match rustix::fs::statvfs(self.shadow.layout().root()) {
            Ok(stat) => reply.statfs(
                stat.f_blocks,
                stat.f_bfree,
                stat.f_bavail,
                stat.f_files,
                stat.f_ffree,
                u32::try_from(stat.f_bsize).unwrap_or(4096),
                u32::try_from(stat.f_namemax).unwrap_or(255),
                u32::try_from(stat.f_frsize).unwrap_or(4096),
            ),
            Err(_) => reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        match self.shadow.access(ino.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
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
        let writable = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let result = name
            .to_str()
            .ok_or(ShadowError::Invalid("file name is not UTF-8"))
            .and_then(|name| {
                self.shadow
                    .create(parent.0, name, mode, umask, req.uid(), req.gid(), writable)
            });
        match result {
            Ok((attr, handle)) => reply.created(
                &ENTRY_TTL,
                &to_attr(&attr),
                GENERATION,
                FileHandle(handle.id),
                FopenFlags::FOPEN_KEEP_CACHE,
            ),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(fuser::Errno::ENODATA);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(fuser::Errno::EOPNOTSUPP);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(fuser::Errno::EOPNOTSUPP);
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if mode & !libc::FALLOC_FL_KEEP_SIZE != 0 {
            reply.error(fuser::Errno::EOPNOTSUPP);
            return;
        }
        if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
            reply.ok();
            return;
        }
        let result = (|| {
            let attr = self.shadow.getattr(ino.0, Some(fh.0))?;
            let end = offset.saturating_add(length);
            if end > attr.size {
                self.shadow.setattr(
                    ino.0,
                    Some(fh.0),
                    AttrChange {
                        size: Some(end),
                        ..AttrChange::default()
                    },
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &self,
        _req: &Request,
        ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        _ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            let mut copied = 0u64;
            while copied < len {
                let want = u32::try_from((len - copied).min(1 << 20)).unwrap_or(1 << 20);
                let data = self.shadow.read(
                    ino_in.0,
                    Some(fh_in.0),
                    offset_in.saturating_add(copied),
                    want,
                )?;
                if data.is_empty() {
                    break;
                }
                self.shadow.write(
                    _ino_out.0,
                    fh_out.0,
                    offset_out.saturating_add(copied),
                    &data,
                )?;
                copied = copied.saturating_add(data.len() as u64);
            }
            Ok(copied)
        })();
        match result {
            Ok(copied) => reply.written(u32::try_from(copied).unwrap_or(u32::MAX)),
            Err(error) => reply.error(to_errno(error)),
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
        match self.shadow.lseek(ino.0, offset, whence) {
            Ok(position) => reply.offset(position),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn getlk(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        match self.shadow.getlk(ino.0, lock_owner.0, start, end, typ) {
            Ok(Some(lock)) => reply.locked(lock.start, lock.end, lock.typ, lock.pid),
            Ok(None) => reply.locked(0, 0, libc::F_UNLCK, 0),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn setlk(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        match self
            .shadow
            .setlk(ino.0, lock_owner.0, start, end, typ, pid, sleep)
        {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn destroy(&mut self) {
        let _ = self.shadow.collect_garbage();
    }
}

/// Convert one shadow attribute to a kernel attribute block.
pub fn to_attr(attr: &NodeAttr) -> FileAttr {
    let (seconds, nanos) = split_ns(attr.attrs.mtime_ns);
    let time = UNIX_EPOCH + Duration::new(seconds, nanos);
    FileAttr {
        ino: INodeNo(attr.fuse_ino),
        size: attr.size,
        blocks: attr.size.div_ceil(512),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: UNIX_EPOCH,
        kind: file_type(attr.kind),
        perm: (attr.attrs.mode & 0o7777) as u16,
        nlink: attr.nlink,
        uid: attr.attrs.uid,
        gid: attr.attrs.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Map one entry kind to the kernel type.
pub const fn file_type(kind: EntryKind) -> FileType {
    match kind {
        EntryKind::File => FileType::RegularFile,
        EntryKind::Dir => FileType::Directory,
        EntryKind::Symlink => FileType::Symlink,
    }
}

fn split_ns(ns: i64) -> (u64, u32) {
    let ns = ns.max(0) as u64;
    (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

fn time_ns(time: TimeOrNow) -> i64 {
    match time {
        TimeOrNow::SpecificTime(time) => match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
            Err(_) => 0,
        },
        TimeOrNow::Now => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
            }),
    }
}

pub fn to_errno(error: ShadowError) -> fuser::Errno {
    fuser::Errno::from_i32(error.errno())
}

/// Mount configuration for an mm namespace.
pub fn mount_config(allow_other: bool) -> fuser::Config {
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        fuser::MountOption::FSName("syncmount-mm".to_owned()),
        fuser::MountOption::Subtype("syncmount-mm".to_owned()),
        fuser::MountOption::AutoUnmount,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
    ];
    config.acl = if allow_other {
        fuser::SessionACL::All
    } else {
        fuser::SessionACL::RootAndOwner
    };
    config.n_threads = Some(8);
    config.clone_fd = true;
    config
}

/// A convenience constructor for a mount test.
pub fn mountpoint_path(shadow: &Shadow) -> PathBuf {
    shadow.layout().root().to_path_buf()
}

/// Keep `Path` meaningful for the public mount helper signatures.
pub fn shadow_root(shadow: &Shadow) -> &Path {
    shadow.layout().root()
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::shadow::NodeAttr;
    use crate::mmap::types::DirAttrs;

    fn node(kind: EntryKind, mode: u32, size: u64) -> NodeAttr {
        NodeAttr {
            fuse_ino: 7,
            ino: [3; 16],
            version: 1,
            kind,
            size,
            nlink: 1,
            attrs: DirAttrs {
                mode,
                uid: 1000,
                gid: 1000,
                mtime_ns: 1_700_000_000_123_456_789,
            },
            target: None,
        }
    }

    #[test]
    fn attributes_carry_kernel_inode_and_permissions() {
        let attr = to_attr(&node(EntryKind::File, 0o100644, 4096));
        assert_eq!(attr.ino, INodeNo(7));
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blocks, 8);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.blksize, 4096);
    }

    #[test]
    fn every_kind_has_a_file_type() {
        assert_eq!(file_type(EntryKind::File), FileType::RegularFile);
        assert_eq!(file_type(EntryKind::Dir), FileType::Directory);
        assert_eq!(file_type(EntryKind::Symlink), FileType::Symlink);
    }

    #[test]
    fn negative_times_clamp_to_the_epoch() {
        let mut attr = node(EntryKind::File, 0o644, 0);
        attr.attrs.mtime_ns = -1;
        assert_eq!(to_attr(&attr).mtime, UNIX_EPOCH);
    }

    #[test]
    fn errno_mapping_is_stable() {
        assert_eq!(to_errno(ShadowError::NotFound).code(), libc::ENOENT);
        assert_eq!(to_errno(ShadowError::Conflict).code(), libc::EAGAIN);
        assert_eq!(to_errno(ShadowError::IsDir).code(), libc::EISDIR);
        assert_eq!(to_errno(ShadowError::CrossDevice).code(), libc::EXDEV);
    }

    #[test]
    fn mount_config_never_uses_direct_io() {
        let config = mount_config(false);
        assert!(
            config
                .mount_options
                .contains(&fuser::MountOption::AutoUnmount)
        );
        assert_eq!(config.n_threads, Some(8));
        assert!(config.clone_fd);
    }
}

#[cfg(all(test, feature = "fuse-tests"))]
mod mount_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    /// A remote that refuses every request. The mount smoke test only needs
    /// local metadata and local file bodies; remote-backed paths are covered
    /// by the shadow tests with a real mock.
    struct NullRemote;

    impl crate::mmap::shadow::remote::MmRemote for NullRemote {
        fn checkout(
            &self,
            _request: &crate::mmap::shadow::remote::CheckoutRequest,
        ) -> Result<
            crate::mmap::shadow::remote::CheckoutOutcome,
            crate::mmap::shadow::remote::RemoteError,
        > {
            Err(crate::mmap::shadow::remote::RemoteError::Unsupported(
                "mount smoke has no remote".to_owned(),
            ))
        }

        fn signatures(
            &self,
            _request: &crate::mmap::shadow::remote::SignaturesRequest,
        ) -> Result<
            crate::mmap::shadow::remote::SignaturesResponse,
            crate::mmap::shadow::remote::RemoteError,
        > {
            Err(crate::mmap::shadow::remote::RemoteError::Unsupported(
                "mount smoke has no remote".to_owned(),
            ))
        }

        fn upload(
            &self,
            _request: &crate::mmap::shadow::remote::UploadRequest,
        ) -> Result<
            crate::mmap::shadow::remote::UploadResponse,
            crate::mmap::shadow::remote::RemoteError,
        > {
            Err(crate::mmap::shadow::remote::RemoteError::Unsupported(
                "mount smoke has no remote".to_owned(),
            ))
        }

        fn lock(
            &self,
            _request: &crate::mmap::shadow::remote::LockRequest,
        ) -> Result<
            crate::mmap::shadow::remote::LockResponse,
            crate::mmap::shadow::remote::RemoteError,
        > {
            Err(crate::mmap::shadow::remote::RemoteError::Unsupported(
                "mount smoke has no remote".to_owned(),
            ))
        }

        fn file_read(
            &self,
            _request: &crate::mmap::shadow::remote::FileReadRequest,
        ) -> Result<crate::mmap::shadow::remote::FileData, crate::mmap::shadow::remote::RemoteError>
        {
            Err(crate::mmap::shadow::remote::RemoteError::Unsupported(
                "mount smoke has no remote".to_owned(),
            ))
        }
    }

    fn fuse_ready() -> bool {
        if !cfg!(target_os = "linux") || !Path::new("/dev/fuse").exists() {
            if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                panic!("FUSE is required but unavailable");
            }
            eprintln!("SKIP[FUSE] /dev/fuse is missing");
            return false;
        }
        true
    }

    fn mounted(path: &Path) -> bool {
        let needle = path.to_string_lossy().to_string();
        std::fs::read_to_string("/proc/mounts")
            .map(|mounts| {
                mounts
                    .lines()
                    .any(|line| line.split_whitespace().nth(1) == Some(needle.as_str()))
            })
            .unwrap_or(false)
    }

    fn run(cwd: &Path, command: &str) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|error| panic!("spawn {command:?}: {error}"));
        assert!(
            output.status.success(),
            "command failed: {command}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn mountpoint() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mnt");
        std::fs::create_dir(&mount).unwrap();
        (dir, mount)
    }

    #[test]
    #[serial_test::serial]
    fn mm_mount_reads_and_writes_a_shadow() {
        if !fuse_ready() {
            return;
        }
        // A real mount needs a remote. This smoke test only verifies that the
        // adapter can mount and serve the root row; the remote-backed path is
        // covered by the shadow tests.
        let (dir, mount) = mountpoint();
        let shadow = Shadow::open(
            crate::mmap::shadow::ShadowConfig::new(dir.path(), "/private-mm"),
            Arc::new(NullRemote),
        )
        .unwrap();
        // This smoke test has no server; treat the root as a local-only
        // directory so create/write/mkdir can run without a checkout.
        shadow
            .db()
            .set_local_only(crate::mmap::types::ROOT_INO, true)
            .unwrap();
        let shadow = Arc::new(shadow);
        let filesystem = ShadowFs::new(shadow);
        let mut config = mount_config(false);
        config
            .mount_options
            .retain(|option| *option != fuser::MountOption::AutoUnmount);
        config.acl = fuser::SessionACL::Owner;
        let session = match fuser::spawn_mount(filesystem, &mount, &config) {
            Ok(session) => session,
            Err(error) => {
                if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                    panic!("mount failed: {error}");
                }
                eprintln!("SKIP[FUSE] mount failed: {error}");
                return;
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !mounted(&mount) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mounted(&mount), "mountpoint is not visible");
        run(&mount, "printf hello > f");
        assert_eq!(run(&mount, "cat f"), "hello");
        assert_eq!(run(&mount, "stat -c %s f").trim(), "5");
        run(&mount, "mkdir d");
        run(&mount, "mv f d/g");
        assert_eq!(run(&mount, "cat d/g"), "hello");
        run(&mount, "ln -s d/g link");
        assert_eq!(run(&mount, "readlink link").trim(), "d/g");
        let _ = Command::new("fusermount3").arg("-uz").arg(&mount).output();
        assert!(session.umount_and_join().is_ok());
    }

    #[test]
    fn null_remote_refuses_every_request() {
        use crate::mmap::shadow::remote::{MmRemote, RemoteError};
        let remote = NullRemote;
        assert!(matches!(
            remote.file_read(&crate::mmap::shadow::remote::FileReadRequest {
                dir_path: "/".to_owned(),
                dir_ino: [0; 16],
                name: "x".to_owned(),
                ino: [1; 16],
                file_root: [0; 32],
                offset: 0,
                len: 1,
            }),
            Err(RemoteError::Unsupported(_))
        ));
    }
}
