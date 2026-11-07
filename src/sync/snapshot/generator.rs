//! Snapshot generation: serialize, split into parts, seal, publish.
//!
//! Owner: W14 (E7). See 43 §2.2–§2.3.
//!
//! # Order
//!
//! Data parts first, then the digest, then the index, then the reference. The
//! digest cannot exist before the last data part, and the reference cannot
//! exist before the index, so this order is forced. A generation that loses
//! its grant mid-way simply drops the chunks; they are content-addressed and
//! GC collects them (43 §2.3).
//!
//! # The index circularity, resolved
//!
//! The index part is itself up to four chunks. Chunk 0's id is the reference's
//! `root_chunk_id`, so chunk 0 cannot contain it. Chunk 0 *does* contain the
//! ids of chunks 1..k, which are hashes of later plaintext and therefore not
//! circular. [`Generator::generate`] builds the plaintext once to learn its
//! length, hashes the tail chunks, rewrites the header with their ids, and
//! only then seals chunk 0. Because chunk 0's own bytes never change after
//! that rewrite, its id is stable.

use std::time::{Duration, Instant};

use crate::protocol::frame::{ClientId, Seq};
use crate::protocol::messages::SnapshotRef;
use crate::sync::config;
use crate::sync::snapshot::format::{DataPartHeader, SnapshotIndex};
use crate::sync::{ChunkId, ChunkKind, ChunkSource, PartDesc, StateImage, SyncError, ZERO_CHUNK};

/// The two halves of a generated snapshot.
#[derive(Clone, Debug)]
pub struct Bundle {
    /// What the server broadcasts and a joiner fetches by.
    pub reference: SnapshotRef,
    /// The decoded index, for the generator's own bookkeeping.
    pub index: SnapshotIndex,
}

/// Turns a captured state image into a publishable snapshot.
#[derive(Debug)]
pub struct Generator<'a> {
    chunks: &'a dyn ChunkSource,
    holder: ClientId,
}

impl<'a> Generator<'a> {
    /// Bind a chunk sink and the identity that will hold the snapshot.
    pub const fn new(chunks: &'a dyn ChunkSource, holder: ClientId) -> Self {
        Self { chunks, holder }
    }

    /// The next sequence that should be offered, if any.
    ///
    /// A client offers when `applied_seq` first reaches a multiple of
    /// [`config::SNAPSHOT_INTERVAL`], and never offers the same sequence twice
    /// (43 §2.3). Pure, so the actor's decision is testable without a clock.
    pub fn should_offer(applied: Seq, last_offered: Option<Seq>) -> Option<Seq> {
        let seq = applied.get();
        if seq == 0 || seq % config::SNAPSHOT_INTERVAL != 0 {
            return None;
        }
        if last_offered == Some(applied) {
            return None;
        }
        Some(applied)
    }

    /// Whether a granted generator still has time.
    ///
    /// The deadline exists to break a deadlock, not to bound normal work
    /// (43 §2.1); a caller that misses it discards the chunks.
    pub fn within_deadline(granted_at: Instant, now: Instant, budget: Duration) -> bool {
        now.saturating_duration_since(granted_at) <= budget
    }

    /// Generate and store every chunk, returning the reference to broadcast.
    ///
    /// # Errors
    ///
    /// * [`SyncError::Format`] when the image is too large for one index part.
    /// * [`SyncError::TooLarge`] when the index would exceed four chunks.
    /// * Whatever [`ChunkSource::put`] returns.
    pub fn generate(&self, image: &dyn StateImage) -> Result<Bundle, SyncError> {
        let covered_seq = image.covered_seq();
        let payload = image.encode();
        let total_len = payload.len() as u64;

        let mut hasher = blake3::Hasher::new();
        let mut parts = Vec::new();
        for (offset, slice) in payload.chunks(config::PART_PAYLOAD).enumerate() {
            let part_index = u32::try_from(offset + 1)
                .map_err(|_| SyncError::Format("snapshot has too many parts"))?;
            let mut plain = Vec::with_capacity(DataPartHeader::LEN + slice.len());
            DataPartHeader::new(covered_seq, part_index, slice.len() as u32)
                .encode_into(&mut plain);
            plain.extend_from_slice(slice);
            hasher.update(&plain);
            let ids = self.put_chunks(&plain)?;
            parts.push(PartDesc::new(part_index, plain.len() as u32, &ids));
        }
        let state_digest = *hasher.finalize().as_bytes();
        let part_count = u32::try_from(parts.len() + 1)
            .map_err(|_| SyncError::Format("snapshot has too many parts"))?;

        let mut index = SnapshotIndex {
            covered_seq,
            state_digest,
            part_count,
            index_chunks: vec![ZERO_CHUNK],
            parts,
        };

        // First pass: length only. Ids are fixed-width, so the length does not
        // depend on their values.
        let probe = index.encode()?;
        let chunk_count = probe.len().div_ceil(config::CHUNK_BYTES);
        if chunk_count == 0 || chunk_count > config::CHUNKS_PER_PART {
            return Err(SyncError::TooLarge {
                what: "snapshot index",
                parts: u32::try_from(chunk_count).unwrap_or(u32::MAX),
            });
        }

        let mut index_ids = vec![ZERO_CHUNK; chunk_count];
        for (slot, slice) in probe.chunks(config::CHUNK_BYTES).enumerate().skip(1) {
            index_ids[slot] = ChunkId::of_plaintext(slice);
        }
        index.index_chunks = index_ids;

        // Second pass: the header now names chunks 1..k. Chunk 0 changes, the
        // tail chunks do not, so their ids stay valid.
        let plain = index.encode()?;
        let mut slices: Vec<&[u8]> = plain.chunks(config::CHUNK_BYTES).collect();
        if slices.len() != index.index_chunks.len() {
            return Err(SyncError::Format("index chunk count moved"));
        }
        let root = self.chunks.put(ChunkKind::Snapshot, slices[0])?;
        for slice in slices.drain(1..) {
            let id = self.chunks.put(ChunkKind::Snapshot, slice)?;
            if id != ChunkId::of_plaintext(slice) {
                return Err(SyncError::ChunkCorrupt { id });
            }
        }
        index.index_chunks[0] = root;

        Ok(Bundle {
            reference: SnapshotRef {
                covered_seq: covered_seq.get(),
                part_count,
                total_len,
                root_chunk_id: *root.as_bytes(),
                holder: self.holder,
            },
            index,
        })
    }

    fn put_chunks(&self, plain: &[u8]) -> Result<Vec<ChunkId>, SyncError> {
        let mut ids = Vec::with_capacity(plain.len().div_ceil(config::CHUNK_BYTES));
        for slice in plain.chunks(config::CHUNK_BYTES) {
            ids.push(self.chunks.put(ChunkKind::Snapshot, slice)?);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::StateImage;
    use crate::sync::test_support::{MemChunks, make_image};

    fn holder() -> ClientId {
        ClientId::from_bytes([0x11; 16])
    }

    /// 43 §2.3: a client offers once per 4096-sequence boundary.
    #[test]
    fn u_gen_offer_boundaries() {
        assert_eq!(Generator::should_offer(Seq(0), None), None);
        assert_eq!(Generator::should_offer(Seq(4095), None), None);
        assert_eq!(Generator::should_offer(Seq(4096), None), Some(Seq(4096)));
        assert_eq!(Generator::should_offer(Seq(4096), Some(Seq(4096))), None);
        assert_eq!(
            Generator::should_offer(Seq(8192), Some(Seq(4096))),
            Some(Seq(8192))
        );
    }

    /// 43 §2.1: the deadline only guards against a stuck generator.
    #[test]
    fn u_gen_deadline() {
        let start = Instant::now();
        assert!(Generator::within_deadline(
            start,
            start + Duration::from_secs(29),
            config::GRANT_DEADLINE
        ));
        assert!(!Generator::within_deadline(
            start,
            start + Duration::from_secs(31),
            config::GRANT_DEADLINE
        ));
    }

    /// 43 §2.2: a 2.5 MiB image becomes three data parts plus the index.
    #[test]
    fn u_gen_part_split() {
        let chunks = MemChunks::new();
        let image = make_image(4096, &[("a", 1)], 5 * 1024 * 1024 / 2);
        let bundle = Generator::new(chunks.as_ref(), holder())
            .generate(&image)
            .unwrap();
        assert_eq!(bundle.reference.covered_seq, 4096);
        assert_eq!(bundle.reference.total_len, image.encode().len() as u64);
        assert_eq!(bundle.index.parts.len(), 3);
        assert_eq!(bundle.reference.part_count, 4);
        assert_eq!(
            bundle.index.parts[0].plain_len as usize,
            config::SNAPSHOT_PART
        );
        assert_eq!(
            bundle.index.parts[1].plain_len as usize,
            config::SNAPSHOT_PART
        );
        assert_eq!(
            bundle.index.parts[2].plain_len as usize,
            image.encode().len() - 2 * config::PART_PAYLOAD + DataPartHeader::LEN
        );
        assert_eq!(bundle.index.parts[0].chunk_count(), 4);
        assert_eq!(bundle.index.parts[2].chunk_count(), 3);
        assert_eq!(bundle.index.index_chunks.len(), 1);
        assert_eq!(
            bundle.reference.root_chunk_id,
            *bundle.index.index_chunks[0].as_bytes()
        );
        assert_eq!(bundle.reference.holder, holder());
        assert!(chunks.has(ChunkKind::Snapshot, bundle.index.index_chunks[0]));
    }

    /// The digest covers the data part plaintexts, headers included.
    #[test]
    fn u_gen_digest_covers_part_headers() {
        let chunks = MemChunks::new();
        let image = make_image(7, &[("a", 1)], 4096);
        let bundle = Generator::new(chunks.as_ref(), holder())
            .generate(&image)
            .unwrap();
        let mut hasher = blake3::Hasher::new();
        for part in &bundle.index.parts {
            let mut plain = Vec::new();
            for id in part.chunks() {
                plain.extend_from_slice(
                    &crate::sync::test_support::futures_block_on(
                        chunks.fetch(ChunkKind::Snapshot, id),
                    )
                    .unwrap(),
                );
            }
            hasher.update(&plain);
        }
        assert_eq!(*hasher.finalize().as_bytes(), bundle.index.state_digest);
    }

    /// An empty image still produces a valid index-only container.
    #[test]
    fn u_gen_empty_image() {
        let chunks = MemChunks::new();
        let image = make_image(1, &[], 0);
        let bundle = Generator::new(chunks.as_ref(), holder())
            .generate(&image)
            .unwrap();
        assert_eq!(bundle.reference.part_count, 1);
        assert_eq!(bundle.reference.total_len, 0);
        assert!(bundle.index.parts.is_empty());
        assert_eq!(bundle.index.state_digest, *blake3::hash(b"").as_bytes());
    }

    /// Determinism: the same image produces the same chunk ids.
    #[test]
    fn u_gen_is_deterministic() {
        let first = MemChunks::new();
        let second = MemChunks::new();
        let image = make_image(4096, &[("a", 1), ("b", 2)], 3 * 1024 * 1024);
        let a = Generator::new(first.as_ref(), holder())
            .generate(&image)
            .unwrap();
        let b = Generator::new(second.as_ref(), holder())
            .generate(&image)
            .unwrap();
        assert_eq!(a.reference, b.reference);
        assert_eq!(a.index, b.index);
    }
}
