//! `INodeNo` ↔ [`InodeId`] translation and attribute conversion.
//!
//! The kernel inode number is owned by [`NodeTable`]: it is stable for the
//! lifetime of one mount and survives `rename`/`link`. The backing `st_ino`
//! is never exposed to the kernel; it is only a directory-entry cursor value.
//!
//! All FUSE replies use the same generation (`0`) and short TTLs. A short TTL
//! keeps the kernel from caching a stale view for longer than the local
//! write-through path can justify; remote invalidation arrives through
//! [`super::notify`] as soon as the replayer has materialised the change.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{FileAttr, FileType, Generation, INodeNo};

use crate::store::node_table::{InodeId, NodeTable};
use crate::store::{Attr, Errno, Kind, Timespec};

/// Generation used for every inode. `NodeTable` never reuses an inode number
/// while it is known, so a single generation is enough for one mount.
pub const GENERATION: Generation = Generation(0);

/// Attribute TTL used by `getattr`/`lookup`/`readdirplus`.
pub const ATTR_TTL: Duration = Duration::from_secs(1);

/// Directory-entry TTL used by `lookup`/`readdirplus`.
pub const ENTRY_TTL: Duration = Duration::from_secs(1);

/// Translate a kernel inode number to the global identity.
pub fn id_of(nodes: &NodeTable, ino: INodeNo) -> Result<InodeId, Errno> {
    nodes.id_of(ino.0).ok_or(Errno::ENOENT)
}

/// Translate a global identity to the kernel inode number.
pub fn ino_of(nodes: &NodeTable, id: InodeId) -> Result<INodeNo, Errno> {
    nodes.ino_of(id).map(INodeNo).ok_or(Errno::ENOENT)
}

/// Map the store's file type to the FUSE one.
///
/// `Unknown` only appears when the backing filesystem omits `d_type`; callers
/// that care stat the entry first, so this fallback is for display only.
pub fn file_type(kind: Kind) -> FileType {
    match kind {
        Kind::File => FileType::RegularFile,
        Kind::Dir => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
        Kind::Char => FileType::CharDevice,
        Kind::Block => FileType::BlockDevice,
        Kind::Fifo => FileType::NamedPipe,
        Kind::Socket => FileType::Socket,
        Kind::Unknown => FileType::RegularFile,
    }
}

/// Convert store attributes to a FUSE attribute block.
///
/// The inode number comes from `NodeTable`, not from `attr.ino`: the backing
/// inode is an implementation detail and may be reused after unlink.
pub fn file_attr(nodes: &NodeTable, id: InodeId, attr: &Attr) -> Result<FileAttr, Errno> {
    Ok(FileAttr {
        ino: ino_of(nodes, id)?,
        size: attr.size,
        blocks: attr.blocks,
        atime: system_time(attr.atime),
        mtime: system_time(attr.mtime),
        ctime: system_time(attr.ctime),
        crtime: UNIX_EPOCH,
        kind: file_type(attr.kind()),
        perm: (attr.perm() & 0o7777) as u16,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev as u32,
        blksize: if attr.blksize == 0 {
            4096
        } else {
            attr.blksize
        },
        flags: 0,
    })
}

/// Convert a store timestamp to `SystemTime`.
pub fn system_time(time: Timespec) -> SystemTime {
    let nsec = time.nsec.clamp(0, 999_999_999) as u32;
    if time.sec >= 0 {
        UNIX_EPOCH + Duration::new(time.sec as u64, nsec)
    } else {
        // A negative timestamp with a positive nanosecond part is
        // `-abs(sec) + nsec/1e9`, e.g. (-1, 500_000_000) is -0.5s.
        UNIX_EPOCH - Duration::new(time.sec.unsigned_abs(), 0) + Duration::new(0, nsec)
    }
}

/// Convert a `SystemTime` to a store timestamp.
pub fn timespec(time: SystemTime) -> Timespec {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Timespec::new(duration.as_secs() as i64, duration.subsec_nanos() as i64),
        Err(err) => {
            let duration = err.duration();
            let mut sec = -(duration.as_secs() as i64);
            let mut nsec = -(duration.subsec_nanos() as i64);
            if nsec < 0 {
                nsec += 1_000_000_000;
                sec -= 1;
            }
            Timespec::new(sec, nsec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::time::Duration;

    fn err<T: std::fmt::Debug>(result: Result<T, Errno>) -> Errno {
        match result {
            Ok(value) => panic!("expected an error, got {value:?}"),
            Err(err) => err,
        }
    }

    /// E6 / 41 §2.3, §8.8: the root maps both ways and stays stable.
    #[test]
    fn u_fuse_ino_root_roundtrip() {
        let nodes = NodeTable::new();
        assert_eq!(
            id_of(&nodes, INodeNo::ROOT).unwrap_or_else(|err| panic!("root id: {err:?}")),
            InodeId::ROOT
        );
        assert_eq!(
            ino_of(&nodes, InodeId::ROOT).unwrap_or_else(|err| panic!("root ino: {err:?}")),
            INodeNo::ROOT
        );
        assert_eq!(err(id_of(&nodes, INodeNo(999))), Errno::ENOENT);
        assert_eq!(err(ino_of(&nodes, InodeId::new_v4())), Errno::ENOENT);
    }

    /// E6 / 41 §8.8: rename keeps the inode number.
    #[test]
    fn u_fuse_ino_is_stable_across_rename() {
        let nodes = NodeTable::new();
        let id = InodeId::new_v4();
        nodes
            .insert_link(id, InodeId::ROOT, OsStr::new("a"), Kind::File)
            .unwrap_or_else(|err| panic!("insert: {err:?}"));
        let ino = ino_of(&nodes, id).unwrap_or_else(|err| panic!("ino: {err:?}"));
        nodes
            .rename_name(
                InodeId::ROOT,
                OsStr::new("a"),
                InodeId::ROOT,
                OsStr::new("b"),
            )
            .unwrap_or_else(|err| panic!("rename: {err:?}"));
        assert_eq!(ino_of(&nodes, id), Ok(ino));
        assert_eq!(id_of(&nodes, ino), Ok(id));
    }

    /// E6 / 41 §4: attributes carry the kernel inode, not the backing one.
    #[test]
    fn u_fuse_attr_translation() {
        let nodes = NodeTable::new();
        let id = InodeId::new_v4();
        nodes
            .insert_link(id, InodeId::ROOT, OsStr::new("f"), Kind::File)
            .unwrap_or_else(|err| panic!("insert: {err:?}"));
        let ino = ino_of(&nodes, id).unwrap_or_else(|err| panic!("ino: {err:?}"));
        let attr = Attr {
            ino: 42,
            size: 7,
            blocks: 8,
            blksize: 4096,
            mode: 0o100640,
            nlink: 2,
            uid: 1000,
            gid: 1001,
            rdev: 0,
            atime: Timespec::new(1_700_000_000, 1),
            mtime: Timespec::new(1_700_000_001, 2),
            ctime: Timespec::new(1_700_000_002, 3),
        };
        let file_attr = file_attr(&nodes, id, &attr).unwrap_or_else(|err| panic!("attr: {err:?}"));
        assert_eq!(file_attr.ino, ino);
        assert_eq!(file_attr.size, 7);
        assert_eq!(file_attr.perm, 0o640);
        assert_eq!(file_attr.nlink, 2);
        assert_eq!(file_attr.kind, FileType::RegularFile);
        assert_eq!(file_attr.blksize, 4096);
        assert_eq!(
            file_attr.mtime,
            UNIX_EPOCH + Duration::new(1_700_000_001, 2)
        );
    }

    /// E6 / 41 §4: timestamps round-trip, including pre-epoch values.
    #[test]
    fn u_fuse_time_conversion_roundtrip() {
        for ts in [
            Timespec::new(0, 0),
            Timespec::new(1_700_000_000, 123),
            Timespec::new(-1, 500_000_000),
            Timespec::new(-2, 0),
        ] {
            assert_eq!(timespec(system_time(ts)), ts);
        }
        let before_epoch = UNIX_EPOCH - Duration::new(0, 500_000_000);
        assert_eq!(timespec(before_epoch), Timespec::new(-1, 500_000_000));
    }

    /// E6 / 41 §2.3: every store kind maps to a FUSE kind.
    #[test]
    fn u_fuse_file_type_mapping() {
        assert_eq!(file_type(Kind::File), FileType::RegularFile);
        assert_eq!(file_type(Kind::Dir), FileType::Directory);
        assert_eq!(file_type(Kind::Symlink), FileType::Symlink);
        assert_eq!(file_type(Kind::Char), FileType::CharDevice);
        assert_eq!(file_type(Kind::Block), FileType::BlockDevice);
        assert_eq!(file_type(Kind::Fifo), FileType::NamedPipe);
        assert_eq!(file_type(Kind::Socket), FileType::Socket);
        assert_eq!(file_type(Kind::Unknown), FileType::RegularFile);
    }
}
