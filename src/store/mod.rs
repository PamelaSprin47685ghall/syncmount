//! Local POSIX backing store.
//!
//! # The one rule
//!
//! The backing tree is reachable **only** through [`backing::RootFd`], opened
//! *before* the FUSE mount covers the mountpoint. Every operation is a `*at`
//! syscall relative to that descriptor. Never build an absolute path under the
//! mountpoint, and never open the backing tree by path after mounting: the path
//! would resolve through our own FUSE filesystem back into this process and
//! deadlock (self-recursion). `RootFd` exposes no path-based constructor, so the
//! mistake cannot be expressed through the safe API.
//!
//! `u_store_no_bare_path_open` scans this directory for the forbidden pattern.
//!
//! # Layout
//!
//! | module | responsibility |
//! |---|---|
//! | [`backing`] | [`BackingStore`] trait, [`PosixBacking`], [`RootFd`], `*at` helpers |
//! | [`chunk_store`] | content-addressed chunk cache (`chunk_id` + `blob_id`) |
//! | [`node_table`] | [`InodeId`] and the inode/path/name index |
//! | [`runtime_dir`] | `/run/syncmount/<mount_id>`: status file and instance lock |
//! | [`sqlite`] | shared SQLite state store for the SQLite-backed architecture |

pub mod backing;
pub mod chunk_store;
pub mod node_table;
pub mod runtime_dir;
pub mod sqlite;

pub use backing::{BackingStore, DirEntry, DirSink, Effect, PosixBacking, RootFd};
pub use node_table::{InodeId, Node, NodeTable};
pub use runtime_dir::RuntimeDir;

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;

/// Internal names that belong to the daemon, never to the user tree.
///
/// They are hidden by the FUSE layer, excluded from the manifest, and never
/// removed by `LocalOnly` cleanup. Writes that target these names are rejected
/// with `EEXIST`; reads resolve them to `ENOENT`.
pub const RESERVED_NAMES: [&str; 4] = [
    ".syncmount",
    ".syncmount-staging",
    ".syncmount-manifest",
    ".audit.log",
];

/// Staging root below the backing root.
pub const STAGING_DIR: &str = ".syncmount-staging";
/// Content-addressed chunk cache below the staging root.
pub const CHUNK_DIR: &str = ".syncmount-staging/chunks";
/// Flat staging tree for files that are about to be renamed into place.
pub const STAGING_TREE: &str = ".syncmount-staging/tree";
/// Local manifest cache (accelerator, never authoritative).
pub const MANIFEST_FILE: &str = ".syncmount-manifest";
/// Append-only audit journal.
pub const AUDIT_FILE: &str = ".audit.log";

/// True if `name` is an internal name that must not enter the user namespace.
pub fn is_reserved_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    RESERVED_NAMES
        .iter()
        .any(|reserved| bytes == reserved.as_bytes())
}

/// Result alias used across the store boundary.
///
/// The error parameter is defaulted so call sites stay short while a caller
/// that needs a precise error type can still name it.
pub type Result<T, E = Errno> = std::result::Result<T, E>;

/// A POSIX error number.
///
/// `Errno` is deliberately a thin newtype over the platform error number: the
/// FUSE and sync layers translate it to `reply.error`/`io::Error` at their
/// edge, and nothing in between invents error semantics.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Errno(pub i32);

impl Errno {
    pub const EPERM: Self = Self(rustix::io::Errno::PERM.raw_os_error());
    pub const ENOENT: Self = Self(rustix::io::Errno::NOENT.raw_os_error());
    pub const EINTR: Self = Self(rustix::io::Errno::INTR.raw_os_error());
    pub const EIO: Self = Self(rustix::io::Errno::IO.raw_os_error());
    pub const EAGAIN: Self = Self(rustix::io::Errno::AGAIN.raw_os_error());
    pub const EACCES: Self = Self(rustix::io::Errno::ACCESS.raw_os_error());
    pub const EEXIST: Self = Self(rustix::io::Errno::EXIST.raw_os_error());
    pub const EXDEV: Self = Self(rustix::io::Errno::XDEV.raw_os_error());
    pub const ENOTDIR: Self = Self(rustix::io::Errno::NOTDIR.raw_os_error());
    pub const EISDIR: Self = Self(rustix::io::Errno::ISDIR.raw_os_error());
    pub const EINVAL: Self = Self(rustix::io::Errno::INVAL.raw_os_error());
    pub const EMFILE: Self = Self(rustix::io::Errno::MFILE.raw_os_error());
    pub const ENOSPC: Self = Self(rustix::io::Errno::NOSPC.raw_os_error());
    pub const ENOTEMPTY: Self = Self(rustix::io::Errno::NOTEMPTY.raw_os_error());
    pub const ELOOP: Self = Self(rustix::io::Errno::LOOP.raw_os_error());
    pub const ENAMETOOLONG: Self = Self(rustix::io::Errno::NAMETOOLONG.raw_os_error());
    pub const ENOSYS: Self = Self(rustix::io::Errno::NOSYS.raw_os_error());
    pub const EOPNOTSUPP: Self = Self(rustix::io::Errno::NOTSUP.raw_os_error());
    pub const EROFS: Self = Self(rustix::io::Errno::ROFS.raw_os_error());
    pub const EDQUOT: Self = Self(rustix::io::Errno::DQUOT.raw_os_error());
    pub const EBUSY: Self = Self(rustix::io::Errno::BUSY.raw_os_error());
    pub const EMLINK: Self = Self(rustix::io::Errno::MLINK.raw_os_error());
    pub const EOVERFLOW: Self = Self(rustix::io::Errno::OVERFLOW.raw_os_error());

    /// Map an [`io::Error`] to an errno, defaulting to `EIO`.
    pub fn from_io(err: &io::Error) -> Self {
        Self(err.raw_os_error().unwrap_or(Self::EIO.0))
    }

    /// Map a rustix error to an errno.
    pub fn from_rustix(err: rustix::io::Errno) -> Self {
        Self(err.raw_os_error())
    }

    /// The raw platform error number.
    pub fn raw(self) -> i32 {
        self.0
    }

    fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            value if value == Self::EPERM.0 => "EPERM",
            value if value == Self::ENOENT.0 => "ENOENT",
            value if value == Self::EINTR.0 => "EINTR",
            value if value == Self::EIO.0 => "EIO",
            value if value == Self::EAGAIN.0 => "EAGAIN",
            value if value == Self::EACCES.0 => "EACCES",
            value if value == Self::EEXIST.0 => "EEXIST",
            value if value == Self::EXDEV.0 => "EXDEV",
            value if value == Self::ENOTDIR.0 => "ENOTDIR",
            value if value == Self::EISDIR.0 => "EISDIR",
            value if value == Self::EINVAL.0 => "EINVAL",
            value if value == Self::ENOSPC.0 => "ENOSPC",
            value if value == Self::ENOTEMPTY.0 => "ENOTEMPTY",
            value if value == Self::ELOOP.0 => "ELOOP",
            value if value == Self::ENAMETOOLONG.0 => "ENAMETOOLONG",
            value if value == Self::ENOSYS.0 => "ENOSYS",
            value if value == Self::EOPNOTSUPP.0 => "EOPNOTSUPP",
            value if value == Self::EROFS.0 => "EROFS",
            value if value == Self::EDQUOT.0 => "EDQUOT",
            value if value == Self::EBUSY.0 => "EBUSY",
            value if value == Self::EMLINK.0 => "EMLINK",
            _ => return None,
        })
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "Errno({name}={})", self.0),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (os error {})", self.0),
            None => write!(f, "os error {}", self.0),
        }
    }
}

impl std::error::Error for Errno {}

impl From<io::Error> for Errno {
    fn from(err: io::Error) -> Self {
        Self::from_io(&err)
    }
}

impl From<rustix::io::Errno> for Errno {
    fn from(err: rustix::io::Errno) -> Self {
        Self::from_rustix(err)
    }
}

impl From<Errno> for io::Error {
    fn from(err: Errno) -> Self {
        io::Error::from_raw_os_error(err.0)
    }
}

/// A file type, derived from `st_mode` or `d_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Char,
    Block,
    Fifo,
    Socket,
    Unknown,
}

impl Kind {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    /// Classify a `st_mode`.
    pub fn from_mode(mode: u32) -> Self {
        match mode & Self::S_IFMT {
            Self::S_IFREG => Self::File,
            Self::S_IFDIR => Self::Dir,
            Self::S_IFLNK => Self::Symlink,
            Self::S_IFCHR => Self::Char,
            Self::S_IFBLK => Self::Block,
            Self::S_IFIFO => Self::Fifo,
            Self::S_IFSOCK => Self::Socket,
            _ => Self::Unknown,
        }
    }

    /// Classify a `rustix` file type from `getdents64`.
    pub fn from_file_type(file_type: rustix::fs::FileType) -> Self {
        use rustix::fs::FileType;
        match file_type {
            FileType::RegularFile => Self::File,
            FileType::Directory => Self::Dir,
            FileType::Symlink => Self::Symlink,
            FileType::CharacterDevice => Self::Char,
            FileType::BlockDevice => Self::Block,
            FileType::Fifo => Self::Fifo,
            FileType::Socket => Self::Socket,
            FileType::Unknown => Self::Unknown,
        }
    }

    /// True for directories.
    pub fn is_dir(self) -> bool {
        self == Self::Dir
    }
}

/// A timestamp with nanosecond precision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    /// The Unix epoch.
    pub const EPOCH: Self = Self { sec: 0, nsec: 0 };

    /// Construct from seconds and nanoseconds.
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }
}

/// Metadata returned by the backing store.
///
/// This mirrors the subset of `struct stat` the FUSE layer needs; `ctime` is
/// carried for local display only and never participates in replay or in
/// cross-node manifest comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub blksize: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

impl Attr {
    /// Convert a `rustix` stat result.
    pub fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            ino: stat.st_ino,
            size: stat.st_size.max(0) as u64,
            blocks: stat.st_blocks.max(0) as u64,
            blksize: stat.st_blksize.max(0) as u32,
            mode: stat.st_mode,
            nlink: stat.st_nlink as u32,
            uid: stat.st_uid,
            gid: stat.st_gid,
            rdev: stat.st_rdev,
            atime: Timespec::new(stat.st_atime, stat.st_atime_nsec as i64),
            mtime: Timespec::new(stat.st_mtime, stat.st_mtime_nsec as i64),
            ctime: Timespec::new(stat.st_ctime, stat.st_ctime_nsec as i64),
        }
    }

    /// The file type encoded in `mode`.
    pub fn kind(&self) -> Kind {
        Kind::from_mode(self.mode)
    }

    /// Permission bits, including setuid/setgid/sticky.
    pub fn perm(&self) -> u32 {
        self.mode & 0o7777
    }
}

/// Attribute changes carried by `setattr` / `SETATTR` replay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrDelta {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<Timespec>,
    pub mtime: Option<Timespec>,
}

/// Flags for [`BackingStore::rename`].
///
/// Store defines its own type so it never depends on the FUSE adapter; the
/// numeric values match `renameat2(2)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenameFlags(pub u32);

impl RenameFlags {
    pub const NONE: Self = Self(0);
    pub const NOREPLACE: Self = Self(rustix::fs::RenameFlags::NOREPLACE.bits());
    pub const EXCHANGE: Self = Self(rustix::fs::RenameFlags::EXCHANGE.bits());
    pub const WHITEOUT: Self = Self(rustix::fs::RenameFlags::WHITEOUT.bits());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 31:M1-2
    #[test]
    fn u_store_reserved_names_are_matched_exactly() {
        assert!(is_reserved_name(OsStr::new(".syncmount-staging")));
        assert!(is_reserved_name(OsStr::new(".syncmount-manifest")));
        assert!(is_reserved_name(OsStr::new(".audit.log")));
        assert!(is_reserved_name(OsStr::new(".syncmount")));
        assert!(!is_reserved_name(OsStr::new(".syncmount-staging2")));
        assert!(!is_reserved_name(OsStr::new("staging")));
        assert!(!is_reserved_name(OsStr::new("")));
    }

    /// 31:M1-2
    #[test]
    fn u_store_errno_roundtrip() {
        let errno = Errno::from_io(&io::Error::from_raw_os_error(Errno::ENOENT.raw()));
        assert_eq!(errno, Errno::ENOENT);
        assert_eq!(
            io::Error::from(errno).raw_os_error(),
            Some(Errno::ENOENT.raw())
        );
        assert_eq!(format!("{errno:?}"), "Errno(ENOENT=2)");
    }

    /// 31:M1-2
    #[test]
    fn u_store_attr_kind_mapping() {
        use rustix::fs::FileType;
        for (raw_mode, kind) in [
            (FileType::RegularFile.as_raw_mode() | 0o644, Kind::File),
            (FileType::Directory.as_raw_mode() | 0o755, Kind::Dir),
            (FileType::Symlink.as_raw_mode() | 0o777, Kind::Symlink),
            (FileType::Fifo.as_raw_mode() | 0o600, Kind::Fifo),
        ] {
            assert_eq!(Kind::from_mode(raw_mode), kind);
        }
    }

    /// C-10
    #[test]
    fn u_store_no_bare_path_open() {
        // W6 / C-10 / P1-2: the backing tree must never be opened by path.
        // The needles are assembled with `concat!` so this test's own source
        // does not contain the literal it forbids.
        const SOURCES: [(&str, &str); 5] = [
            ("mod.rs", include_str!("mod.rs")),
            ("backing.rs", include_str!("backing.rs")),
            ("chunk_store.rs", include_str!("chunk_store.rs")),
            ("node_table.rs", include_str!("node_table.rs")),
            ("runtime_dir.rs", include_str!("runtime_dir.rs")),
        ];
        let needles = [
            concat!("File", "::open("),
            concat!("File", "::create("),
            concat!("std::fs", "::read("),
        ];
        for (file, source) in SOURCES {
            for (line_no, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    continue;
                }
                for needle in needles {
                    assert!(
                        !line.contains(needle),
                        "{file}:{} uses path-based file access: {line}",
                        line_no + 1
                    );
                }
            }
        }
    }
}
