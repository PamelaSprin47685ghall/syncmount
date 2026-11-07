//! The block-level baseline: one `ChunkId` per 256 KiB block, pulled sparsely.
//!
//! Owner: W14 (E7). See 43 §3.1.
//!
//! # Why it is sparse
//!
//! A million files with eight blocks each is eight million identifiers, 256 MiB
//! of blockmap. A joiner with a local baseline needs the identifiers only for
//! the files it will transfer, so the index is pulled in full (a few MiB) and
//! the data parts are pulled by range. The index carries
//! `file_first_block[file_index]`, monotonic, which turns "which parts does
//! this file need" into a division instead of a search.
//!
//! # Two states, one type
//!
//! The holder holds every identifier; the joiner holds some parts. Both are
//! [`Blockmap`]. [`Blockmap::block`] answers from either, and returns `None`
//! for a part that has not arrived, which is the signal to pull it.

use std::collections::BTreeMap;

use crate::protocol::frame::Seq;
use crate::sync::config;
use crate::sync::wire;
use crate::sync::{ChunkId, PartDesc, StateImage, SyncError};

/// The sparse index: where each file's blocks live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockmapIndex {
    /// Sequence the blockmap describes.
    pub at_seq: Seq,
    /// Total identifiers across all files.
    pub block_total: u64,
    /// `file_first_block[i]`; non-decreasing, one entry per file.
    pub file_first_block: Vec<u32>,
    /// Descriptors of the blockmap data parts.
    pub data_parts: Vec<PartDesc>,
}

impl BlockmapIndex {
    /// Identifiers in one full part.
    pub const IDS_PER_PART: usize = config::BLOCKMAP_IDS_PER_PART;

    /// Encode the index container.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the descriptor count does not match
    /// `block_total`, or a file offset is not monotonic.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        let expected = Self::expected_data_parts(self.block_total);
        if self.data_parts.len() as u32 != expected {
            return Err(SyncError::Format("blockmap part count mismatch"));
        }
        let mut previous = 0u32;
        for first in &self.file_first_block {
            if *first < previous || u64::from(*first) > self.block_total {
                return Err(SyncError::Format("blockmap file offsets are not monotonic"));
            }
            previous = *first;
        }
        let mut out = Vec::with_capacity(
            4 + 1
                + 8
                + 8
                + 4
                + 4
                + self.file_first_block.len() * 4
                + self.data_parts.len() * PartDesc::LEN,
        );
        wire::put_magic(&mut out, config::BLOCKMAP_INDEX_MAGIC);
        wire::put_u8(&mut out, config::FORMAT_VER);
        wire::put_u64(&mut out, self.at_seq.get());
        wire::put_u64(&mut out, self.block_total);
        wire::put_u32(&mut out, self.data_parts.len() as u32);
        wire::put_u32(&mut out, self.file_first_block.len() as u32);
        for first in &self.file_first_block {
            wire::put_u32(&mut out, *first);
        }
        for part in &self.data_parts {
            part.encode_into(&mut out);
        }
        Ok(out)
    }

    /// Decode the index container.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on a bad magic or version, an over-long field,
    /// a non-monotonic offset list, or a part count that disagrees with
    /// `block_total`.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(bytes);
        reader.magic(config::BLOCKMAP_INDEX_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported blockmap version"));
        }
        let at_seq = Seq(reader.u64()?);
        let block_total = reader.u64()?;
        let part_count = reader.u32()?;
        let file_count = reader.u32()?;
        let needed = file_count as usize * 4 + part_count as usize * PartDesc::LEN;
        if needed > reader.remaining() {
            return Err(SyncError::Format(
                "blockmap index length disagrees with counts",
            ));
        }
        let mut file_first_block = Vec::with_capacity(file_count as usize);
        let mut previous = 0u32;
        for _ in 0..file_count {
            let first = reader.u32()?;
            if first < previous || u64::from(first) > block_total {
                return Err(SyncError::Format("blockmap file offsets are not monotonic"));
            }
            previous = first;
            file_first_block.push(first);
        }
        let mut data_parts = Vec::with_capacity(part_count as usize);
        for expected in 0..part_count {
            let part = PartDesc::decode(&mut reader)?;
            if part.part_index != expected {
                return Err(SyncError::Format("blockmap parts are not dense"));
            }
            data_parts.push(part);
        }
        reader.finish()?;
        if part_count != Self::expected_data_parts(block_total) {
            return Err(SyncError::Format("blockmap part count mismatch"));
        }
        Ok(Self {
            at_seq,
            block_total,
            file_first_block,
            data_parts,
        })
    }

    /// Parts a blockmap of `block_total` identifiers needs.
    pub const fn expected_data_parts(block_total: u64) -> u32 {
        if block_total == 0 {
            return 1;
        }
        let per = Self::IDS_PER_PART as u64;
        let parts = block_total.div_ceil(per);
        if parts > u32::MAX as u64 {
            u32::MAX
        } else {
            parts as u32
        }
    }

    /// Number of files described.
    pub fn file_count(&self) -> u32 {
        u32::try_from(self.file_first_block.len()).unwrap_or(u32::MAX)
    }

    /// First block and block count of one file.
    pub fn block_range(&self, file_index: u32) -> Option<(u32, u32)> {
        let first = *self.file_first_block.get(file_index as usize)?;
        let next = self
            .file_first_block
            .get(file_index as usize + 1)
            .copied()
            .unwrap_or(u32::try_from(self.block_total).ok()?);
        Some((first, next.saturating_sub(first)))
    }

    /// Data parts covering `[first, first + count)`.
    pub fn parts_for_range(&self, first: u32, count: u32) -> Vec<u32> {
        if count == 0 {
            return Vec::new();
        }
        let per = Self::IDS_PER_PART as u32;
        let start = first / per;
        let end = (first.saturating_add(count) - 1) / per;
        (start..=end).collect()
    }
}

/// A blockmap, complete on the holder and sparse on the joiner.
#[derive(Clone, Debug)]
pub struct Blockmap {
    at_seq: Seq,
    block_total: u64,
    file_first_block: Vec<u32>,
    parts: Vec<PartDesc>,
    ids: Vec<ChunkId>,
    loaded: BTreeMap<u32, Vec<ChunkId>>,
    complete: bool,
}

impl Blockmap {
    /// A complete blockmap from the holder's state image.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the entries' block counts do not sum to the
    /// identifier list length, or the offsets are not monotonic.
    pub fn from_image(image: &dyn StateImage) -> Result<Self, SyncError> {
        let entries = image.entries();
        let blocks = image.blocks();
        let mut file_first_block = Vec::with_capacity(entries.len());
        let mut total: u64 = 0;
        for entry in &entries {
            if total > u64::from(u32::MAX) {
                return Err(SyncError::Format("blockmap offset overflows u32"));
            }
            file_first_block.push(total as u32);
            total += u64::from(entry.block_count);
        }
        if total != blocks.len() as u64 {
            return Err(SyncError::Format("block count disagrees with state image"));
        }
        Self::new(image.covered_seq(), file_first_block, blocks)
    }

    /// A complete blockmap from explicit offsets and identifiers.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on a non-monotonic offset list or a last offset
    /// beyond `ids`.
    pub fn new(
        at_seq: Seq,
        file_first_block: Vec<u32>,
        ids: Vec<ChunkId>,
    ) -> Result<Self, SyncError> {
        let block_total = ids.len() as u64;
        let mut previous = 0u32;
        for first in &file_first_block {
            if *first < previous || u64::from(*first) > block_total {
                return Err(SyncError::Format("blockmap file offsets are not monotonic"));
            }
            previous = *first;
        }
        Ok(Self {
            at_seq,
            block_total,
            file_first_block,
            parts: Vec::new(),
            ids,
            loaded: BTreeMap::new(),
            complete: true,
        })
    }

    /// A sparse blockmap that knows where the parts are but not their content.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on a non-monotonic offset list.
    pub fn sparse(
        at_seq: Seq,
        block_total: u64,
        file_first_block: Vec<u32>,
        parts: Vec<PartDesc>,
    ) -> Result<Self, SyncError> {
        let mut previous = 0u32;
        for first in &file_first_block {
            if *first < previous || u64::from(*first) > block_total {
                return Err(SyncError::Format("blockmap file offsets are not monotonic"));
            }
            previous = *first;
        }
        Ok(Self {
            at_seq,
            block_total,
            file_first_block,
            parts,
            ids: Vec::new(),
            loaded: BTreeMap::new(),
            complete: false,
        })
    }

    /// Sequence the blockmap describes.
    pub const fn at_seq(&self) -> Seq {
        self.at_seq
    }

    /// Total identifiers.
    pub const fn block_total(&self) -> u64 {
        self.block_total
    }

    /// Files described.
    pub fn file_count(&self) -> u32 {
        u32::try_from(self.file_first_block.len()).unwrap_or(u32::MAX)
    }

    /// `file_first_block` for the index builder.
    pub fn file_first_block(&self) -> &[u32] {
        &self.file_first_block
    }

    /// Data part descriptors, empty on a freshly built holder blockmap.
    pub fn parts(&self) -> &[PartDesc] {
        &self.parts
    }

    /// Every identifier, in manifest order. Empty for a sparse map.
    pub fn ids(&self) -> &[ChunkId] {
        &self.ids
    }

    /// True when every part is present.
    pub fn is_complete(&self) -> bool {
        self.complete
            || self.loaded.len() as u32 == BlockmapIndex::expected_data_parts(self.block_total)
    }

    /// Install one data part.
    ///
    /// # Errors
    ///
    /// [`SyncError::PartLengthMismatch`] when the part has the wrong number of
    /// identifiers, [`SyncError::Format`] for an unknown part index.
    pub fn insert_part(&mut self, index: u32, ids: Vec<ChunkId>) -> Result<(), SyncError> {
        let per = BlockmapIndex::IDS_PER_PART as u64;
        if u64::from(index) * per >= self.block_total {
            return Err(SyncError::Format("blockmap part beyond the end"));
        }
        let expected = self
            .block_total
            .saturating_sub(u64::from(index) * per)
            .min(per) as u32;
        if ids.len() as u32 != expected {
            return Err(SyncError::PartLengthMismatch {
                part: index,
                expected,
                found: u32::try_from(ids.len()).unwrap_or(u32::MAX),
            });
        }
        self.loaded.insert(index, ids);
        Ok(())
    }

    /// Identifier of one block, or `None` when its part has not arrived.
    pub fn block(&self, file_index: u32, block_index: u32) -> Option<ChunkId> {
        let (first, count) = self.range(file_index)?;
        if block_index >= count {
            return None;
        }
        let global = u64::from(first) + u64::from(block_index);
        if self.complete {
            return self.ids.get(usize::try_from(global).ok()?).copied();
        }
        let part = global / BlockmapIndex::IDS_PER_PART as u64;
        let offset = global % BlockmapIndex::IDS_PER_PART as u64;
        self.loaded
            .get(&u32::try_from(part).ok()?)?
            .get(usize::try_from(offset).ok()?)
            .copied()
    }

    /// Every block of one file, or `None` when a covering part is absent.
    pub fn file_blocks(&self, file_index: u32) -> Option<Vec<ChunkId>> {
        let (_, count) = self.range(file_index)?;
        (0..count)
            .map(|offset| self.block(file_index, offset))
            .collect()
    }

    /// Data parts needed for a set of files.
    pub fn parts_for_files(&self, files: &[u32]) -> Vec<u32> {
        let mut parts = Vec::new();
        for file in files {
            let Some((first, count)) = self.range(*file) else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let per = BlockmapIndex::IDS_PER_PART as u32;
            let start = first / per;
            let end = (first + count - 1) / per;
            for part in start..=end {
                parts.push(part);
            }
        }
        parts.sort_unstable();
        parts.dedup();
        parts
    }

    fn range(&self, file_index: u32) -> Option<(u32, u32)> {
        let first = *self.file_first_block.get(file_index as usize)?;
        let next = self
            .file_first_block
            .get(file_index as usize + 1)
            .copied()
            .unwrap_or(u32::try_from(self.block_total).ok()?);
        Some((first, next.saturating_sub(first)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::manifest::ManifestBuilder;
    use crate::sync::test_support::{MemChunks, make_image};

    fn ids(count: usize) -> Vec<ChunkId> {
        (0..count)
            .map(|index| {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(index as u64).to_le_bytes());
                ChunkId::from_bytes(raw)
            })
            .collect()
    }

    /// The index round-trips and keeps the file→block mapping.
    #[test]
    fn u_blockmap_index_round_trip() {
        let blockmap = Blockmap::new(Seq(7), vec![0, 3, 3, 10], ids(12)).unwrap();
        let chunks = MemChunks::new();
        let builder = ManifestBuilder::new(chunks.as_ref(), Seq(7));
        let build = builder.build_blockmap(&blockmap).unwrap();
        let encoded = build.index.encode().unwrap();
        assert_eq!(BlockmapIndex::decode(&encoded), Ok(build.index.clone()));
        let index = build.index;
        assert_eq!(index.file_count(), 4);
        assert_eq!(index.block_range(0), Some((0, 3)));
        assert_eq!(index.block_range(1), Some((3, 0)));
        assert_eq!(index.block_range(3), Some((10, 2)));
        assert_eq!(index.block_range(4), None);
    }

    /// Sparse lookup answers only for parts that arrived.
    #[test]
    fn u_blockmap_sparse_lookup() {
        let full = Blockmap::new(Seq(1), vec![0, 2], ids(4)).unwrap();
        assert_eq!(full.block(0, 1), Some(ids(4)[1]));
        assert!(full.is_complete());
        let mut sparse = Blockmap::sparse(Seq(1), 4, vec![0, 2], Vec::new()).unwrap();
        assert!(!sparse.is_complete());
        assert_eq!(sparse.block(0, 1), None);
        sparse.insert_part(0, ids(4)).unwrap();
        assert!(sparse.is_complete());
        assert_eq!(sparse.block(0, 1), Some(ids(4)[1]));
        assert_eq!(sparse.file_blocks(1), Some(ids(4)[2..].to_vec()));
    }

    /// A part with the wrong identifier count is refused.
    #[test]
    fn u_blockmap_part_length() {
        let mut sparse = Blockmap::sparse(Seq(1), 4, vec![0, 2], Vec::new()).unwrap();
        assert_eq!(
            sparse.insert_part(0, ids(3)),
            Err(SyncError::PartLengthMismatch {
                part: 0,
                expected: 4,
                found: 3,
            })
        );
        assert!(sparse.insert_part(1, ids(1)).is_err());
    }

    /// 43 §3.1: a file's blocks can span several parts, and the index says so.
    #[test]
    fn u_blockmap_parts_for_files() {
        let per = BlockmapIndex::IDS_PER_PART;
        let total = per * 2 + 5;
        let full =
            Blockmap::new(Seq(1), vec![0, per as u32, (per * 2) as u32], ids(total)).unwrap();
        assert_eq!(full.parts_for_files(&[0]), vec![0]);
        assert_eq!(full.parts_for_files(&[1]), vec![1]);
        assert_eq!(full.parts_for_files(&[2]), vec![2]);
        assert_eq!(full.parts_for_files(&[0, 2]), vec![0, 2]);
    }

    /// A blockmap built from an image validates the block counts.
    #[test]
    fn u_blockmap_from_image() {
        let image = make_image(9, &[("a", 2), ("b", 3)], 16);
        let blockmap = Blockmap::from_image(&image).unwrap();
        assert_eq!(blockmap.block_total(), 5);
        assert_eq!(blockmap.file_count(), 2);
        assert_eq!(blockmap.file_first_block(), &[0, 2]);
        assert_eq!(blockmap.block(1, 2), Some(image.blocks()[4]));
        let mut broken = image;
        broken.blocks.pop();
        assert!(Blockmap::from_image(&broken).is_err());
    }

    /// The part count is derived, and a mismatched index is rejected.
    #[test]
    fn u_blockmap_index_part_count() {
        assert_eq!(BlockmapIndex::expected_data_parts(0), 1);
        assert_eq!(
            BlockmapIndex::expected_data_parts(BlockmapIndex::IDS_PER_PART as u64),
            1
        );
        assert_eq!(
            BlockmapIndex::expected_data_parts(BlockmapIndex::IDS_PER_PART as u64 + 1),
            2
        );
        let index = BlockmapIndex {
            at_seq: Seq(1),
            block_total: 4,
            file_first_block: vec![0, 2],
            data_parts: Vec::new(),
        };
        assert_eq!(
            index.encode(),
            Err(SyncError::Format("blockmap part count mismatch"))
        );
    }
}
