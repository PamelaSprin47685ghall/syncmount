//! Content-addressed chunk cache with a **dual index**.
//!
//! The identity of a chunk is its plaintext hash:
//!
//! ```text
//! chunk_id = BLAKE3(plaintext, at most 256 KiB)
//! blob_id  = BLAKE3(blob)                  // blob = nonce(12) || ciphertext||tag
//! ```
//!
//! Both hashes are indexed. `chunk_id` is the logical key used by manifests,
//! `BLOCK_REQ`, dedup and resume; `blob_id` is the physical key used to verify
//! bytes before they are decrypted. A single `chunk_id` may legitimately map
//! to several blobs (a random nonce per encryption), but the cache keeps the
//! first blob and reports every later one as a duplicate (49 A3/D-5).
//!
//! # Layout
//!
//! ```text
//! .syncmount-staging/chunks/<kind>/<chunk_id-hex>   # nonce || ciphertext || tag
//! .syncmount-staging/chunks/tmp/<pid>.<n>.sm-tmp   # staging for atomic rename
//! ```
//!
//! `<kind>` is one of `file`, `snapshot`, `manifest`, `blockmap`, `delta`.
//! Writes go through a temporary file, `fsync`, and `renameat(2)`, so a reader
//! never observes a partial blob. The cache is pure cache: eviction is always
//! safe because every chunk can be re-derived from some member's plaintext
//! (43 I9).
//!
//! This module stores ciphertext only. It verifies the **physical** hash
//! (`blob_id`) but cannot verify `chunk_id` without the key; the content
//! layer performs that second check.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::fs::{Mode, OFlags};
use thiserror::Error;

use crate::store::backing::RootFd;
use crate::store::{Errno, Kind, RenameFlags, STAGING_DIR};

/// Plaintext bytes in one chunk (43 §0, 49 A4).
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Random nonce width in a blob.
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag width in a blob.
pub const TAG_LEN: usize = 16;
/// Bytes a blob adds to its plaintext.
pub const BLOB_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Largest blob accepted by the cache.
pub const MAX_BLOB_BYTES: usize = CHUNK_BYTES + BLOB_OVERHEAD;

/// Directory name of the chunk cache below the staging root.
pub const CHUNKS_DIR: &str = "chunks";
/// Directory name for in-flight blob writes.
pub const TMP_DIR: &str = "tmp";

const HEX: &[u8; 16] = b"0123456789abcdef";

macro_rules! hash_id {
    ($name:ident) => {
        #[doc = concat!("A 32-byte ", stringify!($name), ".")]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Width in bytes.
            pub const LEN: usize = 32;

            /// Wrap raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hex, 64 characters.
            pub fn to_hex(self) -> String {
                let mut out = String::with_capacity(64);
                for byte in self.0 {
                    out.push(HEX[(byte >> 4) as usize] as char);
                    out.push(HEX[(byte & 0x0f) as usize] as char);
                }
                out
            }

            /// Parse the exact lowercase-or-uppercase hex form.
            pub fn parse_hex(text: &str) -> Option<Self> {
                let bytes = text.as_bytes();
                if bytes.len() != 64 {
                    return None;
                }
                let mut out = [0u8; 32];
                for (index, pair) in bytes.chunks_exact(2).enumerate() {
                    let hi = hex_nibble(pair[0])?;
                    let lo = hex_nibble(pair[1])?;
                    out[index] = (hi << 4) | lo;
                }
                Some(Self(out))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }
    };
}

hash_id!(ChunkId);
hash_id!(BlobId);

impl ChunkId {
    /// The "absent" sentinel used by part descriptors.
    ///
    /// A real BLAKE3 output is never all zero, so container formats can use
    /// zero to mean "this slot has no chunk".
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hash plaintext (alias of [`Self::of_plaintext`]).
    pub fn of(plaintext: &[u8]) -> Self {
        Self::of_plaintext(plaintext)
    }

    /// The logical identity of a plaintext chunk.
    pub fn of_plaintext(plaintext: &[u8]) -> Self {
        Self(*blake3::hash(plaintext).as_bytes())
    }

    /// True for [`Self::ZERO`].
    pub const fn is_zero(self) -> bool {
        let mut at = 0;
        while at < Self::LEN {
            if self.0[at] != 0 {
                return false;
            }
            at += 1;
        }
        true
    }
}

impl BlobId {
    /// The physical identity of a stored/transmitted blob.
    pub fn of_blob(blob: &[u8]) -> Self {
        Self(*blake3::hash(blob).as_bytes())
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The five content domains (43 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ChunkKind {
    /// User file block (`1`).
    File = 1,
    /// Snapshot part (`2`).
    Snapshot = 2,
    /// Manifest part (`3`).
    Manifest = 3,
    /// Blockmap part (`4`).
    Blockmap = 4,
    /// rsync delta fragment (`5`).
    Delta = 5,
}

impl ChunkKind {
    /// Every kind, in wire order.
    pub const ALL: [Self; 5] = [
        Self::File,
        Self::Snapshot,
        Self::Manifest,
        Self::Blockmap,
        Self::Delta,
    ];

    /// The wire value used in the chunk AAD.
    pub const fn wire(self) -> u8 {
        self as u8
    }

    /// The cache subdirectory name.
    pub const fn dir(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Snapshot => "snapshot",
            Self::Manifest => "manifest",
            Self::Blockmap => "blockmap",
            Self::Delta => "delta",
        }
    }

    /// Decode a wire value.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::File),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Manifest),
            4 => Some(Self::Blockmap),
            5 => Some(Self::Delta),
            _ => None,
        }
    }

    // Descriptive aliases used by some sync call sites. They denote the same
    // wire values as the canonical variants above.
    /// Alias of [`Self::File`].
    #[allow(non_upper_case_globals)]
    pub const FileBlock: Self = Self::File;
    /// Alias of [`Self::Snapshot`].
    #[allow(non_upper_case_globals)]
    pub const SnapshotPart: Self = Self::Snapshot;
    /// Alias of [`Self::Manifest`].
    #[allow(non_upper_case_globals)]
    pub const ManifestPart: Self = Self::Manifest;
    /// Alias of [`Self::Blockmap`].
    #[allow(non_upper_case_globals)]
    pub const BlockmapPart: Self = Self::Blockmap;
    /// Alias of [`Self::Delta`].
    #[allow(non_upper_case_globals)]
    pub const RsyncDelta: Self = Self::Delta;
}

/// What happened to a `put`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    /// A new blob was written.
    Stored,
    /// The `chunk_id` already had a blob; the first one wins (43 I2).
    Duplicate {
        /// The blob already stored under this `chunk_id`.
        existing: BlobId,
    },
}

/// Chunk-cache failures.
#[derive(Debug, Error)]
pub enum ChunkError {
    /// A backing `*at` call failed.
    #[error("chunk store I/O: {0}")]
    Io(#[from] Errno),
    /// The bytes do not hash to the advertised `blob_id`.
    #[error("blob id mismatch: expected {expected}, got {actual}")]
    BlobIdMismatch {
        /// The advertised id.
        expected: BlobId,
        /// The computed id.
        actual: BlobId,
    },
    /// A blob larger than [`MAX_BLOB_BYTES`] was offered.
    #[error("blob too large: {len} bytes > {max}")]
    BlobTooLarge {
        /// Offered length.
        len: usize,
        /// Upper bound.
        max: usize,
    },
    /// A blob shorter than a nonce plus a tag.
    #[error("blob too short: {len} bytes < {min}")]
    BlobTooShort {
        /// Offered length.
        len: usize,
        /// Minimum length.
        min: usize,
    },
    /// A path that must be a directory is not one.
    #[error("not a directory: {0}")]
    NotADirectory(String),
    /// The in-memory index and the disk disagree in a way we cannot repair.
    #[error("chunk index is inconsistent")]
    IndexInconsistent,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    blob_id: Option<BlobId>,
    len: u64,
    tick: u64,
    pinned: bool,
}

#[derive(Debug, Default)]
struct Index {
    by_chunk: BTreeMap<(ChunkKind, ChunkId), Entry>,
    by_blob: BTreeMap<BlobId, (ChunkKind, ChunkId)>,
    bytes: u64,
    tick: u64,
}

impl Index {
    fn next_tick(&mut self) -> u64 {
        let tick = self.tick;
        self.tick = self.tick.wrapping_add(1);
        tick
    }

    fn insert(&mut self, kind: ChunkKind, id: ChunkId, entry: Entry) {
        if let Some(old) = self.by_chunk.insert((kind, id), entry) {
            self.bytes = self.bytes.saturating_sub(old.len);
            if let Some(blob) = old.blob_id {
                self.by_blob.remove(&blob);
            }
        }
        self.bytes = self.bytes.saturating_add(entry.len);
        if let Some(blob) = entry.blob_id {
            self.by_blob.insert(blob, (kind, id));
        }
    }

    fn remove(&mut self, kind: ChunkKind, id: ChunkId) -> Option<Entry> {
        let entry = self.by_chunk.remove(&(kind, id))?;
        self.bytes = self.bytes.saturating_sub(entry.len);
        if let Some(blob) = entry.blob_id {
            self.by_blob.remove(&blob);
        }
        Some(entry)
    }
}

/// The on-disk chunk cache plus its two in-memory indexes.
#[derive(Debug)]
pub struct ChunkStore {
    root: Arc<RootFd>,
    index: Mutex<Index>,
    tmp_seq: AtomicU64,
}

impl ChunkStore {
    /// Open (and create) the cache below `root`.
    ///
    /// The kind directories are created with mode `0700`. Stale temporary
    /// files are removed; the index is rebuilt from directory names and file
    /// sizes. `blob_id` entries stay unknown until a blob is read or written,
    /// so opening a multi-gigabyte cache does not hash it.
    pub fn open(root: Arc<RootFd>) -> Result<Self, ChunkError> {
        let store = Self {
            root,
            index: Mutex::new(Index::default()),
            tmp_seq: AtomicU64::new(0),
        };
        store.ensure_layout()?;
        store.cleanup_tmp()?;
        store.rebuild_index()?;
        Ok(store)
    }

    /// The backing root this cache belongs to.
    pub fn root(&self) -> &RootFd {
        &self.root
    }

    /// Cache directory, relative to the backing root.
    pub fn chunk_root() -> PathBuf {
        Path::new(STAGING_DIR).join(CHUNKS_DIR)
    }

    /// Relative path of one blob.
    pub fn blob_path(kind: ChunkKind, id: &ChunkId) -> PathBuf {
        Path::new(STAGING_DIR)
            .join(CHUNKS_DIR)
            .join(kind.dir())
            .join(id.to_hex())
    }

    /// True when the index knows `id` for `kind`.
    ///
    /// This is the resume predicate (43 §5.5): presence in the cache is
    /// "received". A file removed behind our back is repaired by [`Self::get`].
    pub fn has(&self, kind: ChunkKind, id: &ChunkId) -> bool {
        self.lock().by_chunk.contains_key(&(kind, *id))
    }

    /// Number of cached chunks.
    pub fn len(&self) -> usize {
        self.lock().by_chunk.len()
    }

    /// True when the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes of cached blobs.
    pub fn bytes(&self) -> u64 {
        self.lock().bytes
    }

    /// The stored blob id for a `chunk_id`, when known.
    pub fn blob_id_of(&self, kind: ChunkKind, id: &ChunkId) -> Option<BlobId> {
        self.lock()
            .by_chunk
            .get(&(kind, *id))
            .and_then(|entry| entry.blob_id)
    }

    /// The `chunk_id` stored under a `blob_id`, when known.
    pub fn chunk_id_of_blob(&self, blob: &BlobId) -> Option<ChunkId> {
        self.lock().by_blob.get(blob).map(|(_, id)| *id)
    }

    /// Read a blob, verifying its physical hash.
    ///
    /// The first read fills the `blob_id` side of the dual index. A stored
    /// file whose bytes no longer match the remembered `blob_id` is reported,
    /// never silently accepted.
    pub fn get(&self, kind: ChunkKind, id: &ChunkId) -> Result<Option<Vec<u8>>, ChunkError> {
        let mut index = self.lock();
        let tick = index.next_tick();
        if !index.by_chunk.contains_key(&(kind, *id))
            && !self.index_existing(&mut index, kind, id, tick)?
        {
            return Ok(None);
        }

        let path = Self::blob_path(kind, id);
        let blob = match read_all(&self.root, &path) {
            Ok(blob) => blob,
            Err(ChunkError::Io(err)) if err == Errno::ENOENT => {
                index.remove(kind, *id);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        if blob.len() > MAX_BLOB_BYTES {
            index.remove(kind, *id);
            return Err(ChunkError::BlobTooLarge {
                len: blob.len(),
                max: MAX_BLOB_BYTES,
            });
        }
        let actual = BlobId::of_blob(&blob);
        let known = index
            .by_chunk
            .get(&(kind, *id))
            .ok_or(ChunkError::IndexInconsistent)?
            .blob_id;
        if let Some(known) = known {
            if known != actual {
                return Err(ChunkError::BlobIdMismatch {
                    expected: known,
                    actual,
                });
            }
        } else {
            index.by_blob.insert(actual, (kind, *id));
        }
        let entry = index
            .by_chunk
            .get_mut(&(kind, *id))
            .ok_or(ChunkError::IndexInconsistent)?;
        entry.blob_id = Some(actual);
        entry.tick = tick;
        Ok(Some(blob))
    }

    /// Store a blob after checking `expected_blob_id`.
    ///
    /// The first blob for a `chunk_id` wins. A later blob with the same
    /// `chunk_id` is a legal re-encryption of the same plaintext, so it is
    /// reported as [`PutOutcome::Duplicate`] and dropped (49 A3.4).
    ///
    /// # Errors
    ///
    /// [`ChunkError::BlobIdMismatch`] when `blob` does not hash to
    /// `expected_blob_id`, and [`ChunkError::BlobTooLarge`] above
    /// [`MAX_BLOB_BYTES`].
    pub fn put(
        &self,
        kind: ChunkKind,
        id: &ChunkId,
        blob: &[u8],
        expected_blob_id: BlobId,
    ) -> Result<PutOutcome, ChunkError> {
        if blob.len() < BLOB_OVERHEAD {
            return Err(ChunkError::BlobTooShort {
                len: blob.len(),
                min: BLOB_OVERHEAD,
            });
        }
        if blob.len() > MAX_BLOB_BYTES {
            return Err(ChunkError::BlobTooLarge {
                len: blob.len(),
                max: MAX_BLOB_BYTES,
            });
        }
        let actual = BlobId::of_blob(blob);
        if actual != expected_blob_id {
            return Err(ChunkError::BlobIdMismatch {
                expected: expected_blob_id,
                actual,
            });
        }

        let mut index = self.lock();
        let path = Self::blob_path(kind, id);
        if let Some(known) = index.by_chunk.get(&(kind, *id)).map(|entry| entry.blob_id) {
            match self.root.stat_at(&path, false) {
                Ok(attr) if attr.kind() == Kind::File && attr.size == blob.len() as u64 => {
                    let existing = match known {
                        Some(existing) => existing,
                        None => {
                            // The index was rebuilt from names; hash the stored
                            // blob once so the duplicate report is truthful.
                            let stored = read_all(&self.root, &path)?;
                            let existing = BlobId::of_blob(&stored);
                            let entry = index
                                .by_chunk
                                .get_mut(&(kind, *id))
                                .ok_or(ChunkError::IndexInconsistent)?;
                            entry.blob_id = Some(existing);
                            index.by_blob.insert(existing, (kind, *id));
                            existing
                        }
                    };
                    return Ok(PutOutcome::Duplicate { existing });
                }
                Ok(_) => {
                    index.remove(kind, *id);
                }
                Err(err) if err == Errno::ENOENT => {
                    index.remove(kind, *id);
                }
                Err(err) => return Err(err.into()),
            }
        }

        self.write_atomic(&path, blob)?;
        let tick = index.next_tick();
        index.insert(
            kind,
            *id,
            Entry {
                blob_id: Some(actual),
                len: blob.len() as u64,
                tick,
                pinned: false,
            },
        );
        Ok(PutOutcome::Stored)
    }

    /// Remove one blob from disk and both indexes.
    ///
    /// Returns `true` when something was removed. A missing file is treated
    /// as already evicted.
    pub fn evict(&self, kind: ChunkKind, id: &ChunkId) -> Result<bool, ChunkError> {
        let path = Self::blob_path(kind, id);
        match self.root.unlink_at(&path) {
            Ok(()) => {}
            Err(err) if err == Errno::ENOENT => {}
            Err(err) => return Err(err.into()),
        }
        Ok(self.lock().remove(kind, *id).is_some())
    }

    /// Evict least-recently-used, unpinned chunks until the cache fits.
    ///
    /// Returns the number of bytes freed. Eviction is always safe (43 I9).
    pub fn evict_to_fit(&self, max_bytes: u64) -> Result<u64, ChunkError> {
        let mut freed = 0u64;
        loop {
            let victim = {
                let index = self.lock();
                if index.bytes <= max_bytes {
                    break;
                }
                index
                    .by_chunk
                    .iter()
                    .filter(|(_, entry)| !entry.pinned)
                    .min_by_key(|(_, entry)| entry.tick)
                    .map(|((kind, id), _)| (*kind, *id))
            };
            let Some((kind, id)) = victim else {
                break;
            };
            let len = self
                .lock()
                .by_chunk
                .get(&(kind, id))
                .map_or(0, |entry| entry.len);
            if self.evict(kind, &id)? {
                freed = freed.saturating_add(len);
            } else {
                break;
            }
        }
        Ok(freed)
    }

    /// Pin a chunk so LRU eviction skips it.
    pub fn pin(&self, kind: ChunkKind, id: &ChunkId) {
        if let Some(entry) = self.lock().by_chunk.get_mut(&(kind, *id)) {
            entry.pinned = true;
        }
    }

    /// Release a pin.
    pub fn unpin(&self, kind: ChunkKind, id: &ChunkId) {
        if let Some(entry) = self.lock().by_chunk.get_mut(&(kind, *id)) {
            entry.pinned = false;
        }
    }

    fn lock(&self) -> MutexGuard<'_, Index> {
        self.index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_layout(&self) -> Result<(), ChunkError> {
        ensure_dir(&self.root, Path::new(STAGING_DIR))?;
        ensure_dir(&self.root, &Self::chunk_root())?;
        for kind in ChunkKind::ALL {
            ensure_dir(&self.root, &Self::chunk_root().join(kind.dir()))?;
        }
        ensure_dir(&self.root, &Self::chunk_root().join(TMP_DIR))?;
        Ok(())
    }

    fn cleanup_tmp(&self) -> Result<(), ChunkError> {
        let dir = Self::chunk_root().join(TMP_DIR);
        for entry in self.root.list_at(&dir)? {
            let path = dir.join(entry.name);
            match self.root.unlink_at(&path) {
                Ok(()) => {}
                Err(err) if err == Errno::ENOENT => {}
                Err(err) if err == Errno::EISDIR => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn rebuild_index(&self) -> Result<(), ChunkError> {
        let mut index = self.lock();
        for kind in ChunkKind::ALL {
            let dir = Self::chunk_root().join(kind.dir());
            let entries = match self.root.list_at(&dir) {
                Ok(entries) => entries,
                Err(err) if err == Errno::ENOENT => continue,
                Err(err) => return Err(err.into()),
            };
            for entry in entries {
                let Some(name) = entry.name.to_str() else {
                    continue;
                };
                let Some(id) = ChunkId::parse_hex(name) else {
                    continue;
                };
                let path = dir.join(name);
                let attr = match self.root.stat_at(&path, false) {
                    Ok(attr) => attr,
                    Err(err) if err == Errno::ENOENT => continue,
                    Err(err) => return Err(err.into()),
                };
                if attr.kind() != Kind::File {
                    continue;
                }
                let tick = index.next_tick();
                index.insert(
                    kind,
                    id,
                    Entry {
                        blob_id: None,
                        len: attr.size,
                        tick,
                        pinned: false,
                    },
                );
            }
        }
        Ok(())
    }

    fn index_existing(
        &self,
        index: &mut Index,
        kind: ChunkKind,
        id: &ChunkId,
        tick: u64,
    ) -> Result<bool, ChunkError> {
        let path = Self::blob_path(kind, id);
        match self.root.stat_at(&path, false) {
            Ok(attr) if attr.kind() == Kind::File => {
                index.insert(
                    kind,
                    *id,
                    Entry {
                        blob_id: None,
                        len: attr.size,
                        tick,
                        pinned: false,
                    },
                );
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(err) if err == Errno::ENOENT => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn write_atomic(&self, path: &Path, blob: &[u8]) -> Result<(), ChunkError> {
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = Self::chunk_root()
            .join(TMP_DIR)
            .join(format!("{}.{seq}.sm-tmp", std::process::id()));
        let fd = self.root.open_at(
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        )?;
        let result = (|| -> Result<(), ChunkError> {
            write_all(&fd, blob)?;
            rustix::fs::fsync(&fd).map_err(Errno::from)?;
            Ok(())
        })();
        drop(fd);
        if let Err(err) = result {
            let _ = self.root.unlink_at(&tmp);
            return Err(err);
        }
        if let Err(err) = self.root.rename_at(&tmp, path, RenameFlags::NONE) {
            let _ = self.root.unlink_at(&tmp);
            return Err(err.into());
        }
        if let Some(parent) = path.parent() {
            self.root.fsync_at(parent, false)?;
        }
        Ok(())
    }
}

/// Create one directory, accepting an existing directory.
fn ensure_dir(root: &RootFd, rel: &Path) -> Result<(), ChunkError> {
    match root.mkdir_at(rel, 0o700) {
        Ok(()) => Ok(()),
        Err(err) if err == Errno::EEXIST => {
            let attr = root.stat_at(rel, false)?;
            if attr.kind() == Kind::Dir {
                Ok(())
            } else {
                Err(ChunkError::NotADirectory(rel.display().to_string()))
            }
        }
        Err(err) => Err(err.into()),
    }
}

fn write_all(fd: &std::os::fd::OwnedFd, mut data: &[u8]) -> Result<(), ChunkError> {
    while !data.is_empty() {
        let written = rustix::io::write(fd, data).map_err(Errno::from)?;
        if written == 0 {
            return Err(Errno::EIO.into());
        }
        data = &data[written..];
    }
    Ok(())
}

fn read_all(root: &RootFd, rel: &Path) -> Result<Vec<u8>, ChunkError> {
    let attr = root.stat_at(rel, false)?;
    if attr.kind() != Kind::File {
        return Err(Errno::EINVAL.into());
    }
    let len = usize::try_from(attr.size).map_err(|_| ChunkError::BlobTooLarge {
        len: usize::MAX,
        max: MAX_BLOB_BYTES,
    })?;
    if len > MAX_BLOB_BYTES {
        return Err(ChunkError::BlobTooLarge {
            len,
            max: MAX_BLOB_BYTES,
        });
    }
    let fd = root.open_at(rel, OFlags::RDONLY, Mode::empty())?;
    let mut out = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        let count = rustix::io::pread(&fd, &mut out[read..], read as u64).map_err(Errno::from)?;
        if count == 0 {
            break;
        }
        read += count;
    }
    out.truncate(read);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::store::RootFd;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup(tag: &str) -> (TempDir, Arc<RootFd>) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir {tag}: {err}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|err| panic!("mkdir {tag}: {err}"));
        let root =
            RootFd::open_before_mount(&mount).unwrap_or_else(|err| panic!("root {tag}: {err}"));
        (tmp, Arc::new(root))
    }

    fn blob(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(index as u8))
            .collect()
    }

    /// 45:I-JOIN / C-29
    #[test]
    fn u_store_chunk_store_put_get_dual_index() {
        let (_tmp, root) = setup("dual");
        let store = ChunkStore::open(root).unwrap_or_else(|err| panic!("open: {err}"));
        let id = ChunkId::of_plaintext(b"plaintext");
        let bytes = blob(0x11, 128);
        let blob_id = BlobId::of_blob(&bytes);

        assert_eq!(
            store
                .put(ChunkKind::File, &id, &bytes, blob_id)
                .unwrap_or_else(|err| panic!("put: {err}")),
            PutOutcome::Stored
        );
        assert!(store.has(ChunkKind::File, &id));
        assert_eq!(store.blob_id_of(ChunkKind::File, &id), Some(blob_id));
        assert_eq!(store.chunk_id_of_blob(&blob_id), Some(id));
        assert_eq!(store.bytes(), bytes.len() as u64);
        assert_eq!(store.len(), 1);

        let got = store
            .get(ChunkKind::File, &id)
            .unwrap_or_else(|err| panic!("get: {err}"))
            .unwrap_or_else(|| panic!("missing blob"));
        assert_eq!(got, bytes);
        assert_eq!(
            ChunkStore::blob_path(ChunkKind::File, &id),
            Path::new(".syncmount-staging/chunks/file").join(id.to_hex())
        );
    }

    /// 45:I-JOIN / C-29
    #[test]
    fn u_store_chunk_store_rejects_blob_id_mismatch() {
        let (_tmp, root) = setup("mismatch");
        let store = ChunkStore::open(root).unwrap_or_else(|err| panic!("open: {err}"));
        let id = ChunkId::of_plaintext(b"x");
        let bytes = blob(0x22, 64);
        let wrong = BlobId::of_blob(b"other");

        let err = store
            .put(ChunkKind::File, &id, &bytes, wrong)
            .expect_err("mismatch must fail");
        assert!(matches!(err, ChunkError::BlobIdMismatch { .. }));
        assert!(!store.has(ChunkKind::File, &id));
        assert_eq!(store.bytes(), 0);
    }

    /// 45:I-JOIN / C-29
    #[test]
    fn u_store_chunk_store_rejects_short_blob() {
        let (_tmp, root) = setup("short");
        let store = ChunkStore::open(root).unwrap_or_else(|err| panic!("open: {err}"));
        let id = ChunkId::of_plaintext(b"x");
        let short = b"not-a-blob".to_vec();
        let err = store
            .put(ChunkKind::File, &id, &short, BlobId::of_blob(&short))
            .expect_err("a blob shorter than nonce+tag must fail");
        assert!(matches!(err, ChunkError::BlobTooShort { .. }));
        assert!(!store.has(ChunkKind::File, &id));
    }

    /// 45:I-JOIN
    #[test]
    fn u_store_chunk_store_first_blob_wins() {
        let (_tmp, root) = setup("dedup");
        let store = ChunkStore::open(root).unwrap_or_else(|err| panic!("open: {err}"));
        let id = ChunkId::of_plaintext(b"same plaintext");
        let first = blob(0x33, 96);
        let second = blob(0x44, 96);
        let first_id = BlobId::of_blob(&first);
        let second_id = BlobId::of_blob(&second);

        assert_eq!(
            store.put(ChunkKind::File, &id, &first, first_id).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            store.put(ChunkKind::File, &id, &second, second_id).unwrap(),
            PutOutcome::Duplicate { existing: first_id }
        );
        assert_eq!(
            store.get(ChunkKind::File, &id).unwrap().unwrap(),
            first,
            "the first blob must be kept"
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.bytes(), first.len() as u64);
        assert_eq!(store.chunk_id_of_blob(&second_id), None);
    }

    /// 45:I-JOIN
    #[test]
    fn u_store_chunk_store_evicts_one() {
        let (_tmp, root) = setup("evict");
        let store = ChunkStore::open(root).unwrap_or_else(|err| panic!("open: {err}"));
        let a = ChunkId::of_plaintext(b"a");
        let b = ChunkId::of_plaintext(b"b");
        let blob_a = blob(0x55, 32);
        let blob_b = blob(0x66, 48);
        store
            .put(ChunkKind::File, &a, &blob_a, BlobId::of_blob(&blob_a))
            .unwrap();
        store
            .put(ChunkKind::Snapshot, &b, &blob_b, BlobId::of_blob(&blob_b))
            .unwrap();

        assert!(store.evict(ChunkKind::File, &a).unwrap());
        assert!(!store.has(ChunkKind::File, &a));
        assert!(store.has(ChunkKind::Snapshot, &b));
        assert!(!store.evict(ChunkKind::File, &a).unwrap());
        assert_eq!(store.len(), 1);
    }

    /// 45:I-JOIN
    #[test]
    fn u_store_chunk_store_reopens_and_rebuilds_index() {
        let (_tmp, root) = setup("reopen");
        let id = ChunkId::of_plaintext(b"persist");
        let bytes = blob(0x77, 80);
        let blob_id = BlobId::of_blob(&bytes);
        {
            let store = ChunkStore::open(root.clone()).unwrap();
            store
                .put(ChunkKind::Manifest, &id, &bytes, blob_id)
                .unwrap();
        }
        let store = ChunkStore::open(root).unwrap();
        assert!(store.has(ChunkKind::Manifest, &id));
        assert_eq!(store.bytes(), bytes.len() as u64);
        assert_eq!(
            store.blob_id_of(ChunkKind::Manifest, &id),
            None,
            "lazy until read"
        );
        assert_eq!(store.get(ChunkKind::Manifest, &id).unwrap().unwrap(), bytes);
        assert_eq!(store.blob_id_of(ChunkKind::Manifest, &id), Some(blob_id));
        assert_eq!(store.chunk_id_of_blob(&blob_id), Some(id));
    }

    /// 45:§6.3 R9
    #[test]
    fn u_store_chunk_store_cleans_stale_tmp_on_open() {
        let (tmp, root) = setup("tmp");
        let stale = tmp
            .path()
            .join("mnt/.syncmount-staging/chunks/tmp/leftover.sm-tmp");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, b"partial").unwrap();

        let store = ChunkStore::open(root).unwrap();
        assert!(!stale.exists(), "stale temporary blob must be removed");
        assert!(store.is_empty());
    }
}
