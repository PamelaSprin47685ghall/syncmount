//! Snapshot container formats: the index part and the data parts.
//!
//! Owner: W14 (E7). Layout is `43-sync-skeleton.md` §2.2.
//!
//! # Determinism
//!
//! Every field is fixed-width little endian and the index lists parts in
//! ascending order, so the plaintext of a snapshot is a pure function of the
//! state image and `covered_seq`. Two generators that captured the same
//! sequence produce byte-identical parts, and therefore the same chunk ids.
//!
//! # Two containers
//!
//! * **Index part** (`part 0`): names the data parts. It is itself split into
//!   at most four chunks. Chunk 0 is identified by
//!   [`crate::protocol::messages::SnapshotRef::root_chunk_id`]; chunks 1..k are
//!   named *inside* chunk 0, which is why the header carries up to three extra
//!   ids. Nothing is self-referential: chunk 0's id never appears in chunk 0.
//! * **Data part** (`part i > 0`): a 21-byte header plus payload bytes. A
//!   record may be cut across two parts (43 §2.2); the installer concatenates
//!   payloads before decoding the state image.

use crate::protocol::frame::Seq;
use crate::sync::config;
use crate::sync::{ChunkId, PartDesc, SyncError, ZERO_CHUNK, chunk_is_zero, wire};

/// Fixed prefix of the index part.
pub const INDEX_FIXED_LEN: usize =
    4 + 1 + 8 + ChunkId::LEN + 4 + 1 + (config::CHUNKS_PER_PART - 1) * ChunkId::LEN + 4;

/// Header of a snapshot data part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataPartHeader {
    /// Sequence the snapshot covers.
    pub covered_seq: Seq,
    /// Zero-based part index; never zero, because part 0 is the index.
    pub part_index: u32,
    /// Payload bytes following this header.
    pub payload_len: u32,
}

impl DataPartHeader {
    /// Encoded width.
    pub const LEN: usize = config::PART_HEADER_LEN;

    /// Build a header.
    pub const fn new(covered_seq: Seq, part_index: u32, payload_len: u32) -> Self {
        Self {
            covered_seq,
            part_index,
            payload_len,
        }
    }

    /// Append the encoding.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        wire::put_magic(out, config::SNAPSHOT_DATA_MAGIC);
        wire::put_u8(out, config::FORMAT_VER);
        wire::put_u64(out, self.covered_seq.get());
        wire::put_u32(out, self.part_index);
        wire::put_u32(out, self.payload_len);
    }

    /// Decode a data part header from the front of `plain`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on a bad magic, version, index, or length.
    pub fn decode(plain: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(plain);
        reader.magic(config::SNAPSHOT_DATA_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported snapshot version"));
        }
        let covered_seq = Seq(reader.u64()?);
        let part_index = reader.u32()?;
        let payload_len = reader.u32()?;
        if part_index == 0 {
            return Err(SyncError::Format("data part claims index index"));
        }
        if payload_len as usize > config::PART_PAYLOAD {
            return Err(SyncError::Format("data part payload too long"));
        }
        if plain.len() != Self::LEN + payload_len as usize {
            return Err(SyncError::Format("data part length disagrees with header"));
        }
        Ok(Self {
            covered_seq,
            part_index,
            payload_len,
        })
    }
}

/// The decoded index part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotIndex {
    /// Sequence the snapshot covers.
    pub covered_seq: Seq,
    /// `BLAKE3` over the data part plaintexts, concatenated in order.
    pub state_digest: [u8; 32],
    /// Total parts, index included.
    pub part_count: u32,
    /// Chunk ids of the index part itself; `[0]` equals the reference's root.
    pub index_chunks: Vec<ChunkId>,
    /// Descriptors for parts `1..part_count`, in order.
    pub parts: Vec<PartDesc>,
}

impl SnapshotIndex {
    /// Number of bytes the index occupies when encoded.
    pub fn plain_len(&self) -> usize {
        INDEX_FIXED_LEN + self.parts.len() * PartDesc::LEN
    }

    /// Length of the state image: payload bytes across all data parts.
    ///
    /// Each part's `plain_len` includes its 21-byte header; the image does
    /// not, and `SnapshotRef.total_len` counts image bytes (43 §2.2).
    pub fn payload_len(&self) -> u64 {
        self.parts
            .iter()
            .map(|part| u64::from(part.plain_len.saturating_sub(DataPartHeader::LEN as u32)))
            .sum()
    }

    /// Encode the index.
    ///
    /// `index_chunks` may be shorter than the true chunk count only while the
    /// generator is sizing the container; the final encoding must carry every
    /// id. Missing ids are written as [`ZERO_CHUNK`] and rejected by
    /// [`SnapshotIndex::decode`].
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the descriptor count disagrees with
    /// `part_count`.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        if self.parts.len() + 1 != self.part_count as usize {
            return Err(SyncError::Format("index descriptor count mismatch"));
        }
        if self.index_chunks.len() > config::CHUNKS_PER_PART || self.index_chunks.is_empty() {
            return Err(SyncError::Format("index chunk count out of range"));
        }
        let mut out = Vec::with_capacity(self.plain_len());
        wire::put_magic(&mut out, config::SNAPSHOT_INDEX_MAGIC);
        wire::put_u8(&mut out, config::FORMAT_VER);
        wire::put_u64(&mut out, self.covered_seq.get());
        out.extend_from_slice(&self.state_digest);
        wire::put_u32(&mut out, self.part_count);
        wire::put_u8(&mut out, self.index_chunks.len() as u8);
        for slot in 0..config::CHUNKS_PER_PART - 1 {
            let id = self
                .index_chunks
                .get(slot + 1)
                .copied()
                .unwrap_or(ZERO_CHUNK);
            out.extend_from_slice(id.as_bytes());
        }
        wire::put_u32(&mut out, self.parts.len() as u32);
        for part in &self.parts {
            part.encode_into(&mut out);
        }
        Ok(out)
    }

    /// Decode an index part.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on any structural inconsistency. The sequence
    /// check against a reference belongs to the installer, not here.
    ///
    /// `index_chunks[0]` is left as [`ZERO_CHUNK`]: a chunk cannot name
    /// itself, so the caller fills it from the reference's `root_chunk_id`.
    pub fn decode(plain: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(plain);
        reader.magic(config::SNAPSHOT_INDEX_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported snapshot version"));
        }
        let covered_seq = Seq(reader.u64()?);
        let state_digest = reader.array32()?;
        let part_count = reader.u32()?;
        if part_count == 0 {
            return Err(SyncError::Format("snapshot has no index part"));
        }
        let index_chunk_count = reader.u8()?;
        if index_chunk_count == 0 || index_chunk_count as usize > config::CHUNKS_PER_PART {
            return Err(SyncError::Format("index chunk count out of range"));
        }
        let mut extra = [ZERO_CHUNK; config::CHUNKS_PER_PART - 1];
        for slot in &mut extra {
            *slot = ChunkId::from_bytes(reader.array32()?);
        }
        for (slot, id) in extra.iter().enumerate() {
            if slot + 1 >= index_chunk_count as usize {
                if !chunk_is_zero(*id) {
                    return Err(SyncError::Format("index chunk beyond the count"));
                }
            } else if chunk_is_zero(*id) {
                return Err(SyncError::Format("index chunk id missing"));
            }
        }
        let mut index_chunks = vec![ZERO_CHUNK; index_chunk_count as usize];
        index_chunks[1..].copy_from_slice(&extra[..index_chunk_count as usize - 1]);
        let desc_count = reader.u32()?;
        if desc_count + 1 != part_count {
            return Err(SyncError::Format("index descriptor count mismatch"));
        }
        let mut parts = Vec::with_capacity(desc_count as usize);
        for expected in 1..part_count {
            let part = PartDesc::decode(&mut reader)?;
            if part.part_index != expected {
                return Err(SyncError::Format("data part indices are not dense"));
            }
            parts.push(part);
        }
        reader.finish()?;
        if plain.len() != INDEX_FIXED_LEN + parts.len() * PartDesc::LEN {
            return Err(SyncError::Format("index length mismatch"));
        }
        Ok(Self {
            covered_seq,
            state_digest,
            part_count,
            index_chunks,
            parts,
        })
    }

    /// Read just the fixed header, enough to learn the extra index chunk ids.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the first chunk is too short to hold a
    /// header.
    pub fn peek_index_chunks(chunk0: &[u8]) -> Result<(u8, [ChunkId; 3]), SyncError> {
        if chunk0.len() < INDEX_FIXED_LEN {
            return Err(SyncError::Format("index chunk 0 shorter than its header"));
        }
        let mut reader = wire::Reader::new(chunk0);
        reader.magic(config::SNAPSHOT_INDEX_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported snapshot version"));
        }
        let _covered = reader.u64()?;
        let _digest = reader.array32()?;
        let _part_count = reader.u32()?;
        let index_chunks = reader.u8()?;
        if index_chunks == 0 || index_chunks as usize > config::CHUNKS_PER_PART {
            return Err(SyncError::Format("index chunk count out of range"));
        }
        let mut extra = [ZERO_CHUNK; 3];
        for slot in &mut extra {
            *slot = ChunkId::from_bytes(reader.array32()?);
        }
        Ok((index_chunks, extra))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn desc(index: u32, plain_len: u32, seed: u8) -> PartDesc {
        PartDesc::new(
            index,
            plain_len,
            &[
                ChunkId::from_bytes([seed; 32]),
                ChunkId::from_bytes([seed.wrapping_add(1); 32]),
            ],
        )
    }

    fn sample() -> SnapshotIndex {
        SnapshotIndex {
            covered_seq: Seq(4096),
            state_digest: [0x33; 32],
            part_count: 3,
            index_chunks: vec![ChunkId::from_bytes([1; 32]), ChunkId::from_bytes([2; 32])],
            parts: vec![desc(1, 1000, 9), desc(2, 500, 11)],
        }
    }

    /// 43 §2.2: the index round-trips and stays deterministic.
    #[test]
    fn u_snapshot_format_index_round_trip() {
        let index = sample();
        let bytes = index.encode().unwrap();
        assert_eq!(bytes.len(), index.plain_len());
        assert_eq!(bytes.len(), INDEX_FIXED_LEN + 2 * PartDesc::LEN);
        let decoded = SnapshotIndex::decode(&bytes).unwrap();
        // A chunk cannot name itself: slot 0 is the reference's
        // `root_chunk_id`, which the installer fills in.
        let mut expected = index.clone();
        expected.index_chunks[0] = ZERO_CHUNK;
        assert_eq!(decoded, expected);
        assert_eq!(decoded.payload_len(), 1458);
        assert_eq!(index.encode().unwrap(), bytes);
    }

    /// The peek used before fetching the rest of the index sees the same ids.
    #[test]
    fn u_snapshot_format_peek_index_chunks() {
        let index = sample();
        let bytes = index.encode().unwrap();
        let (count, extra) = SnapshotIndex::peek_index_chunks(&bytes).unwrap();
        assert_eq!(count, 2);
        assert_eq!(extra[0], ChunkId::from_bytes([2; 32]));
        assert!(chunk_is_zero(extra[1]));
        assert!(chunk_is_zero(extra[2]));
    }

    /// A descriptor hole is rejected: chunk ids are a prefix, not a bitmap.
    #[test]
    fn u_snapshot_format_rejects_hole() {
        let mut index = sample();
        index.parts[0].chunk_ids[0] = ZERO_CHUNK;
        index.parts[0].chunk_ids[1] = ChunkId::from_bytes([3; 32]);
        let bytes = index.encode().unwrap();
        assert_eq!(
            SnapshotIndex::decode(&bytes),
            Err(SyncError::Format("part descriptor hole before chunk"))
        );
    }

    /// Part indices must be dense and start at one.
    #[test]
    fn u_snapshot_format_rejects_gap() {
        let mut index = sample();
        index.parts[1].part_index = 7;
        let bytes = index.encode().unwrap();
        assert_eq!(
            SnapshotIndex::decode(&bytes),
            Err(SyncError::Format("data part indices are not dense"))
        );
    }

    /// The data part header is 21 bytes and length-checked.
    #[test]
    fn u_snapshot_format_data_header() {
        let header = DataPartHeader::new(Seq(42), 3, 100);
        let mut plain = Vec::new();
        header.encode_into(&mut plain);
        assert_eq!(plain.len(), DataPartHeader::LEN);
        plain.extend_from_slice(&[0u8; 100]);
        assert_eq!(DataPartHeader::decode(&plain), Ok(header));
        plain.pop();
        assert!(DataPartHeader::decode(&plain).is_err());
    }

    /// Trailing bytes are a format error, not something to ignore.
    #[test]
    fn u_snapshot_format_rejects_trailing() {
        let mut bytes = sample().encode().unwrap();
        bytes.push(0);
        assert_eq!(
            SnapshotIndex::decode(&bytes),
            Err(SyncError::Format("trailing bytes"))
        );
    }
}
