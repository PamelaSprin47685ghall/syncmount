//! FUSE callbacks over the client SQLite database.
//!
//! There is no backing directory: every callback reads a snapshot
//! ([`ClientDb::read`]) or runs one local-first transaction. The kernel inode
//! is the persisted `fuse_inos.fuse_ino`; the 128-bit `objects.ino` remains
//! the sync identity.
//!
//! Reads open the file with `FOPEN_DIRECT_IO`, so a remote event never leaves
//! a stale page in the kernel cache. Attribute TTLs are one second for the
//! same reason.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen,
    ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};

use crate::client::db::{ClientDb, DbError, Ino};
use crate::client::lifecycle::{State, WriteGate};
use crate::client::ops::{AttrChange, CreateAttrs, RenameFlags as StoreRenameFlags};
use crate::store::Errno;
use crate::store::sqlite::{Object, ObjectKind};

/// Attribute cache lifetime.
pub const ATTR_TTL: Duration = Duration::from_secs(1);
/// Directory-entry cache lifetime.
pub const ENTRY_TTL: Duration = Duration::from_secs(1);
/// Generation for every inode; the database never reuses an ino.
pub const GENERATION: Generation = Generation(0);

/// The FUSE view over one client database.
pub struct SqliteFs {
    store: Arc<ClientDb>,
    gate: Arc<WriteGate>,
}

impl std::fmt::Debug for SqliteFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteFs")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl SqliteFs {
    /// Build the view.
    pub fn new(store: Arc<ClientDb>, gate: Arc<WriteGate>) -> Self {
        Self { store, gate }
    }

    fn ino(&self, fuse_ino: INodeNo) -> Result<Ino, fuser::Errno> {
        self.store
            .ino_by_fuse(fuse_ino.0)
            .map_err(to_errno)?
            .ok_or(fuser::Errno::ENOENT)
    }

    fn attr(&self, ino: Ino, object: &Object) -> Result<FileAttr, fuser::Errno> {
        let fuse_ino = self.store.fuse_ino(ino).map_err(to_errno)?;
        Ok(to_attr(fuse_ino, object))
    }

    fn gate(&self) -> Result<(), fuser::Errno> {
        self.gate.check_write().map_err(|errno| fuser::Errno::from_i32(errno.raw()))
    }
}

impl Filesystem for SqliteFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let result = (|| {
            let parent = self.ino(parent)?;
            let object = self.store.lookup(parent, name).map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(error) => reply.error(error),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            self.attr(ino, &object)
        })();
        match result {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(error) => reply.error(error),
        }
    }

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
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = (|| {
            self.gate()?;
            let ino = self.ino(ino)?;
            let change = AttrChange {
                mode,
                uid,
                gid,
                mtime_ns: mtime.map(time_ns),
                size,
            };
            let object = self.store.setattr(ino, change).map_err(to_errno)?;
            self.attr(ino, &object)
        })();
        match result {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(error) => reply.error(error),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let result = (|| {
            let ino = self.ino(ino)?;
            self.store.readlink(ino).map_err(to_errno)
        })();
        match result {
            Ok(target) => reply.data(&target),
            Err(error) => reply.error(error),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            self.gate()?;
            if mode & libc::S_IFMT != libc::S_IFREG {
                return Err(fuser::Errno::EPERM);
            }
            let parent = self.ino(parent)?;
            let attrs = CreateAttrs::new(mode & !umask & 0o7777, 0, 0);
            let object = self.store.create_file(parent, name, attrs).map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(error) => reply.error(error),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            self.gate()?;
            let parent = self.ino(parent)?;
            let attrs = CreateAttrs::new(mode & !umask & 0o7777, 0, 0);
            let object = self.store.create_dir(parent, name, attrs).map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(error) => reply.error(error),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            self.gate()?;
            let parent = self.ino(parent)?;
            self.store.unlink(parent, name).map_err(to_errno)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            self.gate()?;
            let parent = self.ino(parent)?;
            self.store.rmdir(parent, name).map_err(to_errno)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            self.gate()?;
            let parent = self.ino(parent)?;
            let attrs = CreateAttrs::new(0o777, 0, 0);
            let object = self
                .store
                .create_symlink(parent, link_name, target.as_os_str(), attrs)
                .map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(error) => reply.error(error),
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
        let result = (|| {
            self.gate()?;
            let old_parent = self.ino(parent)?;
            let new_parent = self.ino(newparent)?;
            let flags = StoreRenameFlags {
                noreplace: flags.contains(RenameFlags::RENAME_NOREPLACE),
                exchange: flags.contains(RenameFlags::RENAME_EXCHANGE),
            };
            self.store
                .rename(old_parent, name, new_parent, newname, flags)
                .map_err(to_errno)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            self.gate()?;
            let ino = self.ino(ino)?;
            let newparent = self.ino(newparent)?;
            let object = self.store.link(ino, newparent, newname).map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr, GENERATION),
            Err(error) => reply.error(error),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            if object.kind.is_dir() {
                return Err(fuser::Errno::EISDIR);
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(error),
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
        let result = (|| {
            let ino = self.ino(ino)?;
            self.store.read_at(ino, offset, size).map_err(to_errno)
        })();
        match result {
            Ok(data) => reply.data(&data),
            Err(error) => reply.error(error),
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
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            self.gate()?;
            let ino = self.ino(ino)?;
            self.store.write_at(ino, offset, data).map_err(to_errno)
        })();
        match result {
            Ok(written) => reply.written(u32::try_from(written).unwrap_or(u32::MAX)),
            Err(error) => reply.error(error),
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

    fn fsync(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.store.fsync() {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(to_errno(error)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            if !object.kind.is_dir() {
                return Err(fuser::Errno::ENOTDIR);
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(error) => reply.error(error),
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
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            if !object.kind.is_dir() {
                return Err(fuser::Errno::ENOTDIR);
            }
            let parent = self.store.parent_of(ino).unwrap_or(ino);
            let mut entries: Vec<(String, Ino, FileType)> = Vec::new();
            entries.push((
                ".".to_owned(),
                ino,
                FileType::Directory,
            ));
            entries.push((
                "..".to_owned(),
                parent,
                FileType::Directory,
            ));
            for (name, child, kind) in self.store.children(ino).map_err(to_errno)? {
                entries.push((name, child, file_type(kind)));
            }
            let start = usize::try_from(offset).unwrap_or(0);
            for (index, (name, child, kind)) in entries.iter().enumerate().skip(start) {
                let fuse_ino = self.store.fuse_ino(*child).map_err(to_errno)?;
                if reply.add(INodeNo(fuse_ino), (index + 1) as u64, *kind, name) {
                    break;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
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
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            if !object.kind.is_dir() {
                return Err(fuser::Errno::ENOTDIR);
            }
            let parent = self.store.parent_of(ino).unwrap_or(ino);
            let mut entries: Vec<(String, Ino)> = vec![(".".to_owned(), ino), ("..".to_owned(), parent)];
            for (name, child, _) in self.store.children(ino).map_err(to_errno)? {
                entries.push((name, child));
            }
            let start = usize::try_from(offset).unwrap_or(0);
            for (index, (name, child)) in entries.iter().enumerate().skip(start) {
                let child_object = self.store.getattr(*child).map_err(to_errno)?;
                let attr = self.attr(*child, &child_object)?;
                if reply.add(
                    attr.ino,
                    (index + 1) as u64,
                    name,
                    &ENTRY_TTL,
                    &attr,
                    GENERATION,
                ) {
                    break;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match rustix::fs::statvfs(self.store.path()) {
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
        match self.ino(ino).and_then(|ino| self.store.getattr(ino).map_err(to_errno)) {
            Ok(_) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            self.gate()?;
            let parent = self.ino(parent)?;
            let attrs = CreateAttrs::new(mode & !umask & 0o7777, 0, 0);
            let object = self.store.create_file(parent, name, attrs).map_err(to_errno)?;
            self.attr(object.ino, &object)
        })();
        match result {
            Ok(attr) => reply.created(
                &ENTRY_TTL,
                &attr,
                GENERATION,
                FileHandle(0),
                FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(error) => reply.error(error),
        }
    }

    fn getxattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, _size: u32, reply: ReplyXattr) {
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
        reply.error(fuser::Errno::ENOTSUP);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(fuser::Errno::ENOTSUP);
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
        let result = (|| {
            self.gate()?;
            if mode & !libc::FALLOC_FL_KEEP_SIZE != 0 {
                return Err(fuser::Errno::ENOTSUP);
            }
            if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
                return Ok(());
            }
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            let end = offset.saturating_add(length);
            if end > object.size {
                self.store.truncate(ino, end).map_err(to_errno)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
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
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            self.gate()?;
            let source = self.ino(ino_in)?;
            let target = self.ino(ino_out)?;
            let mut copied = 0u64;
            while copied < len {
                let want = (len - copied).min(1 << 20) as u32;
                let data = self
                    .store
                    .read_at(source, offset_in + copied, want)
                    .map_err(to_errno)?;
                if data.is_empty() {
                    break;
                }
                self.store
                    .write_at(target, offset_out + copied, &data)
                    .map_err(to_errno)?;
                copied += data.len() as u64;
            }
            Ok(copied)
        })();
        match result {
            Ok(copied) => reply.written(u32::try_from(copied).unwrap_or(u32::MAX)),
            Err(error) => reply.error(error),
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
        let result = (|| {
            let ino = self.ino(ino)?;
            let object = self.store.getattr(ino).map_err(to_errno)?;
            let size = object.size as i64;
            let position = match whence {
                libc::SEEK_DATA => {
                    if offset >= size {
                        return Err(fuser::Errno::ENXIO);
                    }
                    offset
                }
                libc::SEEK_HOLE => size,
                _ => offset,
            };
            Ok(position.max(0) as u64)
        })();
        match result {
            Ok(position) => reply.offset(position as i64),
            Err(error) => reply.error(error),
        }
    }

    fn getlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: fuser::ReplyLock,
    ) {
        reply.error(fuser::Errno::ENOSYS);
    }

    fn setlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(fuser::Errno::ENOSYS);
    }
}

/// Convert a stored object to a kernel attribute block.
pub fn to_attr(fuse_ino: u64, object: &Object) -> FileAttr {
    let (sec, nsec) = split_ns(object.mtime_ns);
    let time = UNIX_EPOCH + Duration::new(sec, nsec);
    FileAttr {
        ino: INodeNo(fuse_ino),
        size: object.size,
        blocks: object.size.div_ceil(512),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: UNIX_EPOCH,
        kind: file_type(object.kind),
        perm: (object.mode & 0o7777) as u16,
        nlink: object.nlink,
        uid: object.uid,
        gid: object.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn split_ns(ns: i64) -> (u64, u32) {
    let ns = ns.max(0) as u64;
    (ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

/// Map a stored kind to the kernel file type.
pub const fn file_type(kind: ObjectKind) -> FileType {
    match kind {
        ObjectKind::File => FileType::RegularFile,
        ObjectKind::Dir => FileType::Directory,
        ObjectKind::Symlink => FileType::Symlink,
        ObjectKind::Char => FileType::CharDevice,
        ObjectKind::Block => FileType::BlockDevice,
        ObjectKind::Fifo => FileType::NamedPipe,
        ObjectKind::Socket => FileType::Socket,
    }
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

fn to_errno(error: DbError) -> fuser::Errno {
    fuser::Errno::from_i32(error.errno().raw())
}

/// The write gate's state name, for logs.
pub fn gate_state(gate: &WriteGate) -> &'static str {
    match gate.state() {
        State::Boot => "BOOT",
        State::Locked => "LOCKED",
        State::Cleanup => "CLEANUP",
        State::Mounting => "MOUNTING",
        State::Joining => "JOINING",
        State::Steady => "STEADY",
        State::Unmounting => "UNMOUNTING",
        State::DegradedReadOnly => "DEGRADED_RO",
        State::Exited => "EXITED",
    }
}

/// Unused parameter type guard for `Errno` (keeps the import meaningful when
/// a future callback reports a raw errno).
const _: fn(Errno) -> i32 = |errno| errno.raw();

/// FUSE file-name bytes, used by tests.
pub fn name_bytes(name: &OsStr) -> &[u8] {
    name.as_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::store::sqlite::ObjectKind;

    fn object(kind: ObjectKind, size: u64, mode: u32) -> Object {
        Object {
            ino: [1u8; 16],
            kind,
            mode,
            uid: 1000,
            gid: 1000,
            mtime_ns: 1_700_000_000_123_456_789,
            size,
            file_root: [0u8; 32],
            block_count: 0,
            target: None,
            nlink: 1,
            deleted: false,
            created_seq: 0,
            updated_seq: 0,
        }
    }

    #[test]
    fn attributes_carry_the_kernel_inode_and_stored_mode() {
        let attr = to_attr(42, &object(ObjectKind::File, 4096, 0o100644));
        assert_eq!(attr.ino, INodeNo(42));
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blocks, 8);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.mtime.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1_700_000_000);
    }

    #[test]
    fn every_object_kind_has_a_fuse_type() {
        assert_eq!(file_type(ObjectKind::Dir), FileType::Directory);
        assert_eq!(file_type(ObjectKind::Symlink), FileType::Symlink);
        assert_eq!(file_type(ObjectKind::Fifo), FileType::NamedPipe);
        assert_eq!(file_type(ObjectKind::Socket), FileType::Socket);
        assert_eq!(file_type(ObjectKind::Char), FileType::CharDevice);
        assert_eq!(file_type(ObjectKind::Block), FileType::BlockDevice);
    }

    #[test]
    fn a_negative_timestamp_clamps_to_the_epoch() {
        let mut file = object(ObjectKind::File, 0, 0o644);
        file.mtime_ns = -5;
        let attr = to_attr(2, &file);
        assert_eq!(attr.mtime, UNIX_EPOCH);
    }
}

#[cfg(all(test, feature = "fuse-tests"))]
mod mount_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::client::db::ClientDb;
    use crate::client::lifecycle::{State, WriteGate};
    use crate::client::ops::CreateAttrs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

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
    fn fuse_reads_and_writes_the_sqlite_tree() {
        if !fuse_ready() {
            return;
        }
        let (dir, mount) = mountpoint();
        let store = Arc::new(
            ClientDb::open(dir.path().join("client.db"), [5u8; 16]).unwrap(),
        );
        let gate = Arc::new(WriteGate::new(State::Steady));
        let filesystem = SqliteFs::new(Arc::clone(&store), gate);
        let mut config = crate::fuse::mount_config();
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

        run(&mount, "echo hello > f");
        assert_eq!(run(&mount, "cat f"), "hello\n");
        assert_eq!(run(&mount, "stat -c %s f").trim(), "6");
        run(&mount, "mkdir d");
        run(&mount, "mv f d/g");
        assert_eq!(run(&mount, "cat d/g"), "hello\n");
        run(&mount, "ln -s d/g link");
        assert_eq!(run(&mount, "readlink link").trim(), "d/g");
        run(&mount, "rm d/g");
        run(&mount, "rmdir d");
        run(&mount, "rm link");

        // The data lives in SQLite, not in the mountpoint.
        let file = store.lookup_by_path("/f");
        assert!(file.is_err(), "the file was renamed away");
        let gate = store.lookup_by_path("/link");
        assert!(gate.is_err(), "the link was removed");

        let _ = Command::new("fusermount3").arg("-uz").arg(&mount).output();
        assert!(session.umount_and_join().is_ok());
        assert!(!mounted(&mount));
        assert!(store.outbox_count(crate::client::db::OutboxState::Pending).unwrap() > 0);
    }

    #[test]
    #[serial_test::serial]
    fn fuse_refuses_writes_when_the_gate_is_closed() {
        if !fuse_ready() {
            return;
        }
        let (dir, mount) = mountpoint();
        let store = Arc::new(
            ClientDb::open(dir.path().join("client.db"), [6u8; 16]).unwrap(),
        );
        let gate = Arc::new(WriteGate::new(State::Joining));
        let filesystem = SqliteFs::new(Arc::clone(&store), Arc::clone(&gate));
        let mut config = crate::fuse::mount_config();
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
        let output = Command::new("sh")
            .arg("-c")
            .arg("echo blocked > g")
            .current_dir(&mount)
            .output()
            .unwrap();
        assert!(!output.status.success(), "a closed gate must refuse the write");
        assert!(store.lookup_by_path("/g").is_err());
        gate.set(State::Steady);
        run(&mount, "echo open > g");
        assert_eq!(run(&mount, "cat g"), "open\n");
        let _ = Command::new("fusermount3").arg("-uz").arg(&mount).output();
        assert!(session.umount_and_join().is_ok());
    }

    #[test]
    fn local_write_returns_without_a_network() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClientDb::open(dir.path().join("client.db"), [7u8; 16]).unwrap();
        let file = store
            .create_file(crate::store::sqlite::ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        assert_eq!(store.write_at(file.ino, 0, b"local").unwrap(), 5);
        assert_eq!(store.read_at(file.ino, 0, 5).unwrap(), b"local");
        assert_eq!(
            store.outbox_count(crate::client::db::OutboxState::Pending).unwrap(),
            2
        );
    }
}
