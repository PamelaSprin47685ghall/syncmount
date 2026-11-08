//! Base versions and canonical directory-version hashing.
//!
//! # Contracts
//!
//! * `file_root` is exactly the 1.0 [`crate::store::sqlite::file_root`]:
//!   a file is a 64 KiB chunk-list Merkle root, a symlink is the domain-separated
//!   target root, and a directory is the fixed directory root.
//! * `dir_version` commits to the directory's namespace, inode, attributes and
//!   direct entries, sorted by name bytes. It deliberately excludes the
//!   manifest operation, `from_name`, symlink target text and `content_hash`:
//!   a symlink target change already changes `file_root`, and `content_hash`
//!   is only the transport-level whole-file check.
//!
//! ```text
//! dir_version = BLAKE3 derive_key("sm/1.1/mm/dir-version")
//!     namespace_len_le32 || namespace
//!     || dir_ino
//!     || mode_le32 || uid_le32 || gid_le32 || mtime_ns_le64
//!     || entry_count_le32
//!     || for each entry sorted by name:
//!          name_len_le32 || name || kind_u8 || ino
//!          || mode_le32 || uid_le32 || gid_le32 || mtime_ns_le64
//!          || size_le64 || file_root
//! ```

use crate::store::sqlite::{ChunkRef, ObjectKind, file_root as store_file_root};

use super::types::{DirAttrs, EntryKind, Hash, Ino, ManifestEntry};

/// BLAKE3 derive-key context for `dir_version`.
pub const DIR_VERSION_DOMAIN: &str = "sm/1.1/mm/dir-version";

/// The 1.0-compatible `file_root` of one entry.
///
/// `chunks` must be the ordered chunk list for a regular file and empty for a
/// symlink or directory. The symlink `target` is required for
/// [`EntryKind::Symlink`] and ignored otherwise.
pub fn file_root(kind: EntryKind, target: Option<&[u8]>, chunks: &[ChunkRef]) -> Hash {
    let kind = match kind {
        EntryKind::File => ObjectKind::File,
        EntryKind::Symlink => ObjectKind::Symlink,
        EntryKind::Dir => ObjectKind::Dir,
    };
    store_file_root(kind, target, chunks)
}

/// The fixed `file_root` of an empty regular file.
pub fn empty_file_root() -> Hash {
    file_root(EntryKind::File, None, &[])
}

/// The fixed `file_root` of a directory.
pub fn dir_root() -> Hash {
    file_root(EntryKind::Dir, None, &[])
}

/// The `file_root` of a symlink target.
pub fn symlink_root(target: &[u8]) -> Hash {
    file_root(EntryKind::Symlink, Some(target), &[])
}

/// Compute the canonical `dir_version` of one directory.
///
/// Entries are sorted by name bytes inside this function, so the caller may
/// pass rows in any order. Only the fields listed in the module contract are
/// fed to the hash; `op`, `from_name`, `target` and `content_hash` are ignored.
pub fn dir_version(
    namespace: &str,
    dir_ino: Ino,
    attrs: &DirAttrs,
    entries: &[ManifestEntry],
) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(DIR_VERSION_DOMAIN);
    feed_bytes(&mut hasher, namespace.as_bytes());
    hasher.update(&dir_ino);
    feed_attrs(&mut hasher, attrs);

    let mut sorted: Vec<&ManifestEntry> = entries.iter().collect();
    sorted.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    assert!(
        sorted.len() <= u32::MAX as usize,
        "directory entry count does not fit u32"
    );
    hasher.update(&(sorted.len() as u32).to_le_bytes());

    for entry in sorted {
        feed_bytes(&mut hasher, entry.name.as_bytes());
        hasher.update(&[entry.kind.tag()]);
        hasher.update(&entry.ino);
        hasher.update(&entry.mode.to_le_bytes());
        hasher.update(&entry.uid.to_le_bytes());
        hasher.update(&entry.gid.to_le_bytes());
        hasher.update(&(entry.mtime_ns as u64).to_le_bytes());
        hasher.update(&entry.size.to_le_bytes());
        hasher.update(&entry.file_root);
    }

    *hasher.finalize().as_bytes()
}

fn feed_attrs(hasher: &mut blake3::Hasher, attrs: &DirAttrs) {
    hasher.update(&attrs.mode.to_le_bytes());
    hasher.update(&attrs.uid.to_le_bytes());
    hasher.update(&attrs.gid.to_le_bytes());
    hasher.update(&(attrs.mtime_ns as u64).to_le_bytes());
}

fn feed_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    assert!(
        bytes.len() <= u32::MAX as usize,
        "field length does not fit u32"
    );
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}
