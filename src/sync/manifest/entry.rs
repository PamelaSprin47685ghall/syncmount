//! Manifest entries and the file-level root.
//!
//! Owner: W14 (E7). See 43 §3.1–§3.2 and 45 §8.3.
//!
//! # `file_root` is a Merkle root, not a whole-file hash
//!
//! ```text
//! file_root = BLAKE3("sm/v1/fileroot" ‖ block_count_le64
//!                    ‖ concat(block_index_le32 ‖ chunk_id))
//! ```
//!
//! A write to one 256 KiB block changes one leaf, so a client can maintain the
//! root incrementally; a 1 TiB file costs `O(blocks)` to verify, not
//! `O(bytes)`. The root still changes whenever any block changes, which is the
//! only property the diff needs.
//!
//! Directories and symlinks get their own domain-separated roots so an empty
//! file, an empty directory and a symlink to `""` can never compare equal.

use std::ffi::OsStr;

use crate::store::Kind;
use crate::store::node_table::InodeId;
use crate::sync::config;
use crate::sync::{ChunkId, SyncError};

/// Domain prefix for a regular file's Merkle root.
pub const FILEROOT_DOMAIN: &[u8] = b"sm/v1/fileroot";
/// Domain prefix for a symlink's root (the target bytes).
pub const SYMLINK_DOMAIN: &[u8] = b"sm/v1/symlink";
/// Domain prefix for a directory's root.
pub const DIR_DOMAIN: &[u8] = b"sm/v1/dir";

/// One file-level manifest record.
///
/// `path` is a relative, slash-separated, NFC string with no trailing slash
/// (45 §8.3). `target` is non-empty exactly for symlinks; it is part of the
/// entry because the applier needs the bytes to recreate the link, and the
/// diff needs it to tell `AttrsOnly` from `TypeReplace`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Relative path, `/` separated.
    pub path: String,
    /// File type.
    pub kind: Kind,
    /// Stable inode identity (`UUIDv4`, never reused).
    pub inode: InodeId,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Size in bytes; `0` for directories.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
    /// File-level root (43 §3.2).
    pub file_root: [u8; 32],
    /// Number of 256 KiB blocks; `0` for directories and symlinks.
    pub block_count: u32,
    /// Symlink target; empty otherwise.
    pub target: String,
}

impl Entry {
    /// A regular file whose content is `blocks`, in order.
    ///
    // The argument list mirrors the record fields; a builder would add a
    // second place to forget `file_root` and no extra safety.
    #[allow(clippy::too_many_arguments)]
    pub fn file(
        path: impl Into<String>,
        inode: InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        mtime_ns: u64,
        blocks: &[ChunkId],
    ) -> Self {
        Self {
            path: path.into(),
            kind: Kind::File,
            inode,
            mode,
            uid,
            gid,
            size,
            mtime_ns,
            file_root: file_root(blocks),
            block_count: u32::try_from(blocks.len()).unwrap_or(u32::MAX),
            target: String::new(),
        }
    }

    /// A directory.
    pub fn dir(
        path: impl Into<String>,
        inode: InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_ns: u64,
    ) -> Self {
        Self {
            path: path.into(),
            kind: Kind::Dir,
            inode,
            mode,
            uid,
            gid,
            size: 0,
            mtime_ns,
            file_root: *blake3::hash(DIR_DOMAIN).as_bytes(),
            block_count: 0,
            target: String::new(),
        }
    }

    /// A symlink.
    pub fn symlink(
        path: impl Into<String>,
        inode: InodeId,
        uid: u32,
        gid: u32,
        mtime_ns: u64,
        target: impl Into<String>,
    ) -> Self {
        let target = target.into();
        let mut hasher = blake3::Hasher::new();
        hasher.update(SYMLINK_DOMAIN);
        hasher.update(target.as_bytes());
        Self {
            path: path.into(),
            kind: Kind::Symlink,
            inode,
            mode: 0o777,
            uid,
            gid,
            size: 0,
            mtime_ns,
            file_root: *hasher.finalize().as_bytes(),
            block_count: 0,
            target,
        }
    }

    /// A device node, fifo or socket. Metadata only; v1 does not transfer the
    /// endpoint (39 §4).
    #[allow(clippy::too_many_arguments)]
    pub fn special(
        path: impl Into<String>,
        kind: Kind,
        inode: InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        mtime_ns: u64,
    ) -> Self {
        Self {
            path: path.into(),
            kind,
            inode,
            mode,
            uid,
            gid,
            size,
            mtime_ns,
            file_root: *blake3::hash(DIR_DOMAIN).as_bytes(),
            block_count: 0,
            target: String::new(),
        }
    }

    /// `BLAKE3(path)` — log correlation and `MANIFEST_ENTRY_REQ` (43 §3.3).
    pub fn path_hash(&self) -> [u8; 32] {
        *blake3::hash(self.path.as_bytes()).as_bytes()
    }

    /// Number of path components.
    pub fn depth(&self) -> usize {
        self.path.bytes().filter(|byte| *byte == b'/').count() + 1
    }

    /// Structural validation.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for an absolute path, a `.`/`..` component, a
    /// reserved name, a control byte, an over-long path, or a kind/content
    /// disagreement.
    pub fn validate(&self) -> Result<(), SyncError> {
        let path = self.path.as_str();
        if path.is_empty() {
            return Err(SyncError::Format("empty manifest path"));
        }
        if path.len() > config::MAX_PATH_BYTES {
            return Err(SyncError::Format("manifest path too long"));
        }
        if path.starts_with('/') || path.ends_with('/') || path.contains("//") {
            return Err(SyncError::Format(
                "manifest path is not relative and normal",
            ));
        }
        for byte in path.bytes() {
            if byte < 0x20 || byte == 0x7f {
                return Err(SyncError::Format("manifest path has a control byte"));
            }
        }
        for component in path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(SyncError::Format("manifest path has a dot component"));
            }
            if crate::store::is_reserved_name(OsStr::new(component)) {
                return Err(SyncError::Format("manifest path is a reserved name"));
            }
        }
        match self.kind {
            Kind::File => {
                if !self.target.is_empty() {
                    return Err(SyncError::Format("file carries a symlink target"));
                }
                if self.block_count == 0 && self.size != 0 {
                    return Err(SyncError::Format("file size without blocks"));
                }
            }
            Kind::Dir => {
                if self.size != 0 || self.block_count != 0 || !self.target.is_empty() {
                    return Err(SyncError::Format("directory carries content"));
                }
            }
            Kind::Symlink => {
                if self.target.is_empty() || self.block_count != 0 {
                    return Err(SyncError::Format("symlink without a target"));
                }
            }
            Kind::Char | Kind::Block | Kind::Fifo | Kind::Socket => {
                if self.block_count != 0 || !self.target.is_empty() {
                    return Err(SyncError::Format("special file carries content"));
                }
            }
            Kind::Unknown => return Err(SyncError::Format("unknown file kind")),
        }
        Ok(())
    }
}

/// The file-level root of a block sequence (43 §3.2).
pub fn file_root(blocks: &[ChunkId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILEROOT_DOMAIN);
    hasher.update(&(blocks.len() as u64).to_le_bytes());
    for (index, id) in blocks.iter().enumerate() {
        hasher.update(&(index as u32).to_le_bytes());
        hasher.update(id.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The root of an empty block list; the fixed value for empty files.
pub fn empty_file_root() -> [u8; 32] {
    file_root(&[])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn id(seed: u8) -> ChunkId {
        ChunkId::from_bytes([seed; 32])
    }

    fn inode(seed: u8) -> InodeId {
        InodeId(u128::from(seed))
    }

    /// 43 §3.2: the root is order-sensitive and includes the block index.
    #[test]
    fn u_entry_file_root_is_ordered() {
        let a = file_root(&[id(1), id(2)]);
        let b = file_root(&[id(2), id(1)]);
        assert_ne!(a, b);
        assert_eq!(a, file_root(&[id(1), id(2)]));
        assert_ne!(a, empty_file_root());
        assert_eq!(empty_file_root(), file_root(&[]));
    }

    /// A one-block change changes the root; the block count is bound too.
    #[test]
    fn u_entry_file_root_changes_with_content() {
        let before = file_root(&[id(1), id(2), id(3)]);
        let after = file_root(&[id(1), id(9), id(3)]);
        assert_ne!(before, after);
        assert_ne!(file_root(&[id(1)]), file_root(&[id(1), id(1)]));
    }

    /// 43 §3.5: an empty file, an empty directory and a symlink differ.
    #[test]
    fn u_entry_kinds_have_distinct_roots() {
        let file = Entry::file("f", inode(1), 0o644, 0, 0, 0, 1, &[]);
        let dir = Entry::dir("d", inode(2), 0o755, 0, 0, 1);
        let link = Entry::symlink("l", inode(3), 0, 0, 1, "");
        assert_ne!(file.file_root, dir.file_root);
        assert_ne!(dir.file_root, link.file_root);
        assert!(link.validate().is_err(), "an empty target is not a symlink");
    }

    /// Path validation rejects everything the applier cannot represent.
    #[test]
    fn u_entry_validate_rejects_bad_paths() {
        for path in [
            "",
            "/abs",
            "a/",
            "a//b",
            "a/./b",
            "a/../b",
            ".syncmount-manifest",
        ] {
            let entry = Entry::file(path, inode(1), 0o644, 0, 0, 0, 1, &[]);
            assert!(entry.validate().is_err(), "accepted {path:?}");
        }
        let long = "x".repeat(config::MAX_PATH_BYTES + 1);
        assert!(
            Entry::file(long, inode(1), 0o644, 0, 0, 0, 1, &[])
                .validate()
                .is_err()
        );
        let ok = Entry::file("a/b", inode(1), 0o644, 0, 0, 0, 1, &[]);
        assert_eq!(ok.validate(), Ok(()));
        assert_eq!(ok.depth(), 2);
        assert_eq!(ok.path_hash(), *blake3::hash(b"a/b").as_bytes());
    }

    /// Kind/content disagreements are rejected instead of applied.
    #[test]
    fn u_entry_validate_rejects_kind_mismatch() {
        let mut file = Entry::file("f", inode(1), 0o644, 0, 0, 10, 1, &[]);
        assert!(file.validate().is_err());
        file.size = 0;
        assert_eq!(file.validate(), Ok(()));
        let mut dir = Entry::dir("d", inode(2), 0o755, 0, 0, 1);
        dir.size = 5;
        assert!(dir.validate().is_err());
        let mut link = Entry::symlink("l", inode(3), 0, 0, 1, "target");
        assert_eq!(link.validate(), Ok(()));
        link.block_count = 1;
        assert!(link.validate().is_err());
    }
}
