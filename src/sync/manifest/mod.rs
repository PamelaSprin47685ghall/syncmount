//! The remote file view, its local cache, and the service that moves both.
//!
//! Owner: W14 (E7). See 43 §3.
//!
//! # Two products, one capture
//!
//! The holder captures one state image and derives two containers from it:
//! [`Manifest`] (file level, pulled in full) and [`Blockmap`]
//! (block level, pulled sparsely). Both name the same `at_seq`, so a joiner
//! can never mix a manifest from one moment with a blockmap from another.
//!
//! # The cache is an accelerator
//!
//! [`LocalManifest`] lives in `<mountpoint>/.syncmount-manifest`. It is
//! written once at the end of apply, by `tmp` + `rename`, and it is never
//! required for correctness: a missing, truncated, corrupt, or foreign-cluster
//! cache only turns `Identical` into `ContentDiff` (43 §3.4). That is why
//! [`LocalManifest::load`] returns `Option` and swallows every error: a cache
//! that cannot be trusted is the same as no cache.
//!
//! The bootstrap JOIN is the one exception: when a non-empty disk becomes the
//! cluster's initial view, the cache is the only evidence that the tree is a
//! previously mounted one rather than a directory that happens to hold files.
//! [`LocalManifest::inspect`] therefore distinguishes a missing cache from a
//! corrupt one so the client can refuse both by default.

pub mod blockmap;
pub mod codec;
pub mod diff;
pub mod entry;

pub use blockmap::{Blockmap, BlockmapIndex};
pub use codec::{
    BlockmapBuild, BlockmapIndexRef, ManifestBuilder, ManifestRef, PartHeader, PartReader,
    PartWriter,
};
pub use diff::{DiffCounts, DiffKind, DiffPlan, PlanItem};
pub use entry::{Entry, empty_file_root, file_root};

use std::path::Path;

use rustix::fs::{Mode, OFlags};

use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::Seq;
use crate::store::MANIFEST_FILE;
use crate::store::backing::RootFd;
use crate::sync::config;
use crate::sync::wire;
use crate::sync::{ChunkId, ChunkKind, ChunkSource, StateImage, SyncError, SyncPorts};

/// The local manifest cache's temporary sibling.
pub const MANIFEST_TMP: &str = ".syncmount-manifest.tmp";

/// The file-level view of one state image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Sequence the view was generated at.
    pub at_seq: Seq,
    entries: Vec<Entry>,
}

impl Manifest {
    /// Sort `entries` by path bytes.
    ///
    /// No validation: use [`Manifest::try_new`] at every trust boundary. This
    /// constructor exists for values that were just built from [`Entry`]
    /// constructors, which already enforce the invariants.
    pub fn new(at_seq: Seq, mut entries: Vec<Entry>) -> Self {
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        Self { at_seq, entries }
    }

    /// Validate, then sort.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for an invalid entry or a duplicate path.
    pub fn try_new(at_seq: Seq, mut entries: Vec<Entry>) -> Result<Self, SyncError> {
        for entry in &entries {
            entry.validate()?;
        }
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        for pair in entries.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(SyncError::Format("duplicate manifest path"));
            }
        }
        Ok(Self { at_seq, entries })
    }

    /// Build from a captured image.
    ///
    /// # Errors
    ///
    /// Same as [`Manifest::try_new`].
    pub fn from_image(image: &dyn StateImage) -> Result<Self, SyncError> {
        Self::try_new(image.covered_seq(), image.entries())
    }

    /// Entries, sorted by path bytes.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry at a plan index.
    pub fn entry(&self, index: u32) -> Option<&Entry> {
        self.entries.get(index as usize)
    }

    /// Index of `path`, or `None`.
    pub fn find_index(&self, path: &str) -> Option<u32> {
        self.entries
            .binary_search_by(|entry| entry.path.as_bytes().cmp(path.as_bytes()))
            .ok()
            .map(|index| index as u32)
    }

    /// Entry for `path`, or `None`.
    pub fn find(&self, path: &str) -> Option<&Entry> {
        self.find_index(path).and_then(|index| self.entry(index))
    }

    /// Total file bytes.
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|entry| entry.size).sum()
    }
}

/// The last successfully applied manifest, with the identity that vouches for
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalManifest {
    /// Cluster the cache belongs to.
    pub cluster_id: ClusterId,
    /// Sequence that was applied.
    pub at_seq: Seq,
    /// Epoch that was applied under.
    pub epoch: u64,
    /// The applied manifest.
    pub manifest: Manifest,
}

/// What [`LocalManifest::inspect`] found in the mount root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalManifestState {
    /// No cache file exists.
    Missing,
    /// A cache file exists but does not decode or does not belong to this
    /// cluster.
    Corrupt,
    /// A usable cache.
    Valid(LocalManifest),
}

impl LocalManifest {
    /// Fixed prefix: magic, version, cluster, epoch, sequence, entry count,
    /// payload length.
    const HEADER_LEN: usize = 4 + 1 + ClusterId::LEN + 8 + 8 + 4 + 8;

    /// Encode the cache file.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for entry in self.manifest.entries() {
            codec::encode_entry(entry, &mut payload);
        }
        let mut out = Vec::with_capacity(Self::HEADER_LEN + payload.len() + 32);
        wire::put_magic(&mut out, config::LOCAL_MANIFEST_MAGIC);
        wire::put_u8(&mut out, config::FORMAT_VER);
        out.extend_from_slice(self.cluster_id.as_bytes());
        wire::put_u64(&mut out, self.epoch);
        wire::put_u64(&mut out, self.at_seq.get());
        wire::put_u32(&mut out, self.manifest.len() as u32);
        wire::put_u64(&mut out, payload.len() as u64);
        out.extend_from_slice(&payload);
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        out
    }

    /// Decode and verify a cache file.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a bad magic, version, digest, length, entry
    /// count, or a cache that belongs to another cluster.
    pub fn decode(bytes: &[u8], cluster: ClusterId) -> Result<Self, SyncError> {
        if bytes.len() < Self::HEADER_LEN + 32 {
            return Err(SyncError::Format("manifest cache too short"));
        }
        let split = bytes.len() - 32;
        let (body, digest) = bytes.split_at(split);
        if blake3::hash(body).as_bytes() != digest {
            return Err(SyncError::Format("manifest cache digest mismatch"));
        }
        let mut reader = wire::Reader::new(body);
        reader.magic(config::LOCAL_MANIFEST_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported manifest cache version"));
        }
        let cluster_id = ClusterId::from_bytes(reader.array16()?);
        if cluster_id != cluster {
            return Err(SyncError::Format(
                "manifest cache belongs to another cluster",
            ));
        }
        let epoch = reader.u64()?;
        let at_seq = Seq(reader.u64()?);
        let entry_count = reader.u32()?;
        let payload_len = reader.u64()?;
        let payload = reader.bytes(usize::try_from(payload_len).unwrap_or(usize::MAX))?;
        reader.finish()?;
        let entries = codec::decode_entries(payload)?;
        if entries.len() != entry_count as usize {
            return Err(SyncError::Format("manifest cache entry count mismatch"));
        }
        Ok(Self {
            cluster_id,
            at_seq,
            epoch,
            manifest: Manifest::try_new(at_seq, entries)?,
        })
    }

    /// Load the cache; any error means "no usable cache".
    pub fn load(root: &RootFd, cluster: ClusterId) -> Option<Self> {
        let bytes = read_all(root, MANIFEST_FILE).ok()?;
        Self::decode(&bytes, cluster).ok()
    }

    /// Classify the cache file without hiding why it is unusable.
    ///
    /// [`Self::load`] collapses every failure into `None`. A bootstrap JOIN
    /// must tell a new mount (no cache) from a damaged one (cache present but
    /// undecodable), because the second case asks the operator to inspect or
    /// remove the file instead of silently adopting the disk.
    pub fn inspect(root: &RootFd, cluster: ClusterId) -> LocalManifestState {
        match read_all(root, MANIFEST_FILE) {
            Err(_) => LocalManifestState::Missing,
            Ok(bytes) => match Self::decode(&bytes, cluster) {
                Ok(manifest) => LocalManifestState::Valid(manifest),
                Err(_) => LocalManifestState::Corrupt,
            },
        }
    }

    /// Replace the cache atomically.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the temporary file cannot be written or renamed.
    pub fn store(&self, root: &RootFd) -> Result<(), SyncError> {
        write_all(root, MANIFEST_TMP, &self.encode())?;
        root.rename_at(
            Path::new(MANIFEST_TMP),
            Path::new(MANIFEST_FILE),
            crate::store::RenameFlags::NONE,
        )?;
        Ok(())
    }
}

/// Reads and writes the joiner side of the manifest and blockmap.
#[derive(Debug)]
pub struct ManifestService<'a> {
    ports: &'a SyncPorts,
}

impl<'a> ManifestService<'a> {
    /// Bind the ports.
    pub const fn new(ports: &'a SyncPorts) -> Self {
        Self { ports }
    }

    /// Pull and decode the full manifest.
    ///
    /// # Errors
    ///
    /// Whatever [`ManifestService::read_manifest`] returns.
    pub async fn fetch(&self, reference: &ManifestRef) -> Result<Manifest, SyncError> {
        Self::read_manifest(self.ports.chunks.as_ref(), reference).await
    }

    /// Pull and decode a manifest with an explicit chunk source.
    ///
    /// # Errors
    ///
    /// [`SyncError::PartLengthMismatch`] when the parts do not assemble to
    /// `total_len`, [`SyncError::Format`] on a bad record stream, and chunk
    /// errors from the source.
    pub async fn read_manifest(
        chunks: &dyn ChunkSource,
        reference: &ManifestRef,
    ) -> Result<Manifest, SyncError> {
        let reader = PartReader::new(chunks, ChunkKind::Manifest, config::MANIFEST_PART_MAGIC);
        let mut stream = Vec::with_capacity(reference.total_len as usize);
        for desc in &reference.parts {
            stream.extend_from_slice(&reader.read(reference.at_seq, desc).await?);
        }
        if stream.len() as u64 != reference.total_len {
            return Err(SyncError::PartLengthMismatch {
                part: 0,
                expected: u32::try_from(reference.total_len).unwrap_or(u32::MAX),
                found: u32::try_from(stream.len()).unwrap_or(u32::MAX),
            });
        }
        let entries = codec::decode_entries(&stream)?;
        if entries.len() != reference.entry_count as usize {
            return Err(SyncError::Format("manifest entry count mismatch"));
        }
        Manifest::try_new(reference.at_seq, entries)
    }

    /// Pull and decode the blockmap index.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the decoded index disagrees with the
    /// reference, and chunk errors from the source.
    pub async fn fetch_blockmap_index(
        &self,
        reference: &BlockmapIndexRef,
    ) -> Result<BlockmapIndex, SyncError> {
        let reader = PartReader::new(
            self.ports.chunks.as_ref(),
            ChunkKind::Blockmap,
            config::BLOCKMAP_INDEX_MAGIC,
        );
        let mut stream = Vec::new();
        for desc in &reference.parts {
            stream.extend_from_slice(&reader.read(reference.at_seq, desc).await?);
        }
        let index = BlockmapIndex::decode(&stream)?;
        if index.at_seq != reference.at_seq
            || index.file_count() != reference.file_count
            || index.block_total != reference.block_total
        {
            return Err(SyncError::Format("blockmap index disagrees with reference"));
        }
        Ok(index)
    }

    /// Pull a sparse set of blockmap data parts.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a part index outside the index, and chunk
    /// errors from the source.
    pub async fn fetch_blockmap(
        &self,
        index: &BlockmapIndex,
        parts: &[u32],
    ) -> Result<Blockmap, SyncError> {
        let mut map = Blockmap::sparse(
            index.at_seq,
            index.block_total,
            index.file_first_block.clone(),
            index.data_parts.clone(),
        )?;
        let reader = PartReader::new(
            self.ports.chunks.as_ref(),
            ChunkKind::Blockmap,
            config::BLOCKMAP_PART_MAGIC,
        );
        for part in parts {
            let desc = index
                .data_parts
                .get(*part as usize)
                .ok_or(SyncError::Format("blockmap part out of range"))?;
            let payload = reader.read(index.at_seq, desc).await?;
            map.insert_part(*part, decode_block_ids(&payload)?)?;
        }
        Ok(map)
    }
}

/// Decode a blockmap data part payload into identifiers.
fn decode_block_ids(payload: &[u8]) -> Result<Vec<ChunkId>, SyncError> {
    if payload.len() % ChunkId::LEN != 0 {
        return Err(SyncError::Format(
            "blockmap payload is not a whole number of ids",
        ));
    }
    Ok(payload
        .chunks_exact(ChunkId::LEN)
        .map(|chunk| {
            let mut raw = [0u8; ChunkId::LEN];
            raw.copy_from_slice(chunk);
            ChunkId::from_bytes(raw)
        })
        .collect())
}

fn write_all(root: &RootFd, rel: &str, bytes: &[u8]) -> Result<(), SyncError> {
    let fd = root.open_at(
        Path::new(rel),
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut at = 0usize;
    while at < bytes.len() {
        let written =
            rustix::io::write(&fd, &bytes[at..]).map_err(|err| SyncError::Io(err.to_string()))?;
        if written == 0 {
            return Err(SyncError::Io("short write".to_owned()));
        }
        at += written;
    }
    Ok(())
}

fn read_all(root: &RootFd, rel: &str) -> Result<Vec<u8>, SyncError> {
    use std::io::Read;

    let fd = root.open_at(
        Path::new(rel),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file = std::fs::File::from(fd);
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::store::node_table::InodeId;

    fn manifest() -> Manifest {
        Manifest::new(
            Seq(42),
            vec![
                Entry::file("b", InodeId(2), 0o644, 1000, 1000, 0, 2, &[]),
                Entry::file("a", InodeId(1), 0o644, 1000, 1000, 0, 1, &[]),
                Entry::dir("d", InodeId(3), 0o755, 1000, 1000, 3),
            ],
        )
    }

    /// Entries are sorted by path bytes and binary search finds them.
    #[test]
    fn u_manifest_sorted_and_found() {
        let manifest = manifest();
        let paths: Vec<&str> = manifest.entries().iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["a", "b", "d"]);
        assert_eq!(manifest.find_index("b"), Some(1));
        assert_eq!(manifest.find("d").unwrap().kind, crate::store::Kind::Dir);
        assert!(manifest.find("z").is_none());
        assert_eq!(manifest.total_bytes(), 0);
    }

    /// Duplicate paths are a format error, not a silent overwrite.
    #[test]
    fn u_manifest_rejects_duplicates() {
        let entries = vec![
            Entry::file("a", InodeId(1), 0o644, 0, 0, 0, 1, &[]),
            Entry::file("a", InodeId(2), 0o644, 0, 0, 0, 2, &[]),
        ];
        assert_eq!(
            Manifest::try_new(Seq(1), entries),
            Err(SyncError::Format("duplicate manifest path"))
        );
    }

    /// The cache round-trips and is bound to its cluster.
    #[test]
    fn u_local_manifest_round_trip() {
        let cluster = ClusterId::from_bytes([5; 16]);
        let cache = LocalManifest {
            cluster_id: cluster,
            at_seq: Seq(42),
            epoch: 9,
            manifest: manifest(),
        };
        let bytes = cache.encode();
        assert_eq!(LocalManifest::decode(&bytes, cluster).unwrap(), cache);
        assert_eq!(
            LocalManifest::decode(&bytes, ClusterId::from_bytes([6; 16])),
            Err(SyncError::Format(
                "manifest cache belongs to another cluster"
            ))
        );
        let mut broken = bytes.clone();
        let at = broken.len() - 1;
        broken[at] ^= 1;
        assert_eq!(
            LocalManifest::decode(&broken, cluster),
            Err(SyncError::Format("manifest cache digest mismatch"))
        );
    }

    /// A truncated cache is rejected, never partially applied.
    #[test]
    fn u_local_manifest_truncated() {
        let cluster = ClusterId::from_bytes([5; 16]);
        let cache = LocalManifest {
            cluster_id: cluster,
            at_seq: Seq(1),
            epoch: 1,
            manifest: manifest(),
        };
        let mut bytes = cache.encode();
        bytes.truncate(bytes.len() / 2);
        assert!(LocalManifest::decode(&bytes, cluster).is_err());
    }
}
