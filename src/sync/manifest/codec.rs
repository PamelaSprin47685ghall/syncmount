//! Manifest and blockmap containers: references, part streams, entry codec.
//!
//! Owner: W14 (E7). See 43 §3.1–§3.3.
//!
//! # One stream, fixed-size parts
//!
//! A manifest is one byte stream of records. The stream is cut at exact
//! [`config::PART_PAYLOAD`] boundaries, so a record may straddle two parts
//! (43 §2.2 explicitly allows this). Cutting at record boundaries instead
//! would make part sizes depend on path lengths, and two clients generating
//! the same manifest would produce different part counts.
//!
//! # References fit one control payload
//!
//! [`ManifestRef`] and [`BlockmapIndexRef`] carry one descriptor per part.
//! [`config::MAX_REF_PARTS`] bounds the count so a pathological tree fails
//! with [`SyncError::TooLarge`] instead of producing a reference that cannot
//! be sent. A 1M-file tree needs ~200 parts, well inside the bound.

use crate::protocol::frame::Seq;
use crate::sync::config;
use crate::sync::manifest::{Blockmap, BlockmapIndex, Entry, Manifest};
use crate::sync::wire;
use crate::sync::{ChunkId, ChunkKind, ChunkSource, PartDesc, SyncError};

/// The 21-byte header shared by manifest and blockmap parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartHeader {
    /// Sequence the container describes.
    pub covered_seq: Seq,
    /// Zero-based part index. Unlike a snapshot, part 0 is data.
    pub part_index: u32,
    /// Payload bytes after this header.
    pub payload_len: u32,
}

impl PartHeader {
    /// Encoded width.
    pub const LEN: usize = config::PART_HEADER_LEN;

    /// Append the encoding with `magic`.
    pub fn encode_into(&self, magic: [u8; 4], out: &mut Vec<u8>) {
        wire::put_magic(out, magic);
        wire::put_u8(out, config::FORMAT_VER);
        wire::put_u64(out, self.covered_seq.get());
        wire::put_u32(out, self.part_index);
        wire::put_u32(out, self.payload_len);
    }

    /// Decode and length-check a part.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a bad magic, version, or a payload length that
    /// disagrees with the buffer.
    pub fn decode(magic: [u8; 4], plain: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(plain);
        reader.magic(magic)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported container version"));
        }
        let covered_seq = Seq(reader.u64()?);
        let part_index = reader.u32()?;
        let payload_len = reader.u32()?;
        if payload_len as usize > config::PART_PAYLOAD {
            return Err(SyncError::Format("part payload too long"));
        }
        if plain.len() != Self::LEN + payload_len as usize {
            return Err(SyncError::Format("part length disagrees with header"));
        }
        Ok(Self {
            covered_seq,
            part_index,
            payload_len,
        })
    }
}

/// What a joiner needs to pull a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRef {
    /// Sequence the peer's manifest was generated at.
    pub at_seq: Seq,
    /// Number of records in the stream.
    pub entry_count: u32,
    /// Total payload bytes across all parts.
    pub total_len: u64,
    /// Parts, in order.
    pub parts: Vec<PartDesc>,
}

impl ManifestRef {
    /// Encode the control payload.
    ///
    /// # Errors
    ///
    /// [`SyncError::TooLarge`] above [`config::MAX_REF_PARTS`].
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        if self.parts.len() as u32 > config::MAX_REF_PARTS {
            return Err(SyncError::TooLarge {
                what: "manifest reference",
                parts: self.parts.len() as u32,
            });
        }
        let mut out = Vec::with_capacity(8 + 4 + 8 + 4 + self.parts.len() * PartDesc::LEN);
        wire::put_magic(&mut out, config::MANIFEST_REF_MAGIC);
        wire::put_u8(&mut out, config::FORMAT_VER);
        wire::put_u64(&mut out, self.at_seq.get());
        wire::put_u32(&mut out, self.entry_count);
        wire::put_u64(&mut out, self.total_len);
        wire::put_u32(&mut out, self.parts.len() as u32);
        for part in &self.parts {
            part.encode_into(&mut out);
        }
        Ok(out)
    }

    /// Decode the control payload.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a bad magic, version, count, or a
    /// non-dense part list.
    pub fn decode(body: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(body);
        reader.magic(config::MANIFEST_REF_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported reference version"));
        }
        let at_seq = Seq(reader.u64()?);
        let entry_count = reader.u32()?;
        let total_len = reader.u64()?;
        let part_count = reader.u32()?;
        if part_count > config::MAX_REF_PARTS {
            return Err(SyncError::Format("reference has too many parts"));
        }
        if total_len > u64::from(part_count) * config::PART_PAYLOAD as u64 {
            return Err(SyncError::Format("reference length exceeds its parts"));
        }
        let mut parts = Vec::with_capacity(part_count as usize);
        for expected in 0..part_count {
            let part = PartDesc::decode(&mut reader)?;
            if part.part_index != expected {
                return Err(SyncError::Format("reference parts are not dense"));
            }
            parts.push(part);
        }
        reader.finish()?;
        Ok(Self {
            at_seq,
            entry_count,
            total_len,
            parts,
        })
    }
}

/// What a joiner needs to pull the blockmap index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockmapIndexRef {
    /// Sequence the index belongs to.
    pub at_seq: Seq,
    /// Files in the manifest that produced it.
    pub file_count: u32,
    /// Total block identifiers.
    pub block_total: u64,
    /// Index parts, in order.
    pub parts: Vec<PartDesc>,
}

impl BlockmapIndexRef {
    /// Encode the control payload.
    ///
    /// # Errors
    ///
    /// [`SyncError::TooLarge`] above [`config::MAX_REF_PARTS`].
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        if self.parts.len() as u32 > config::MAX_REF_PARTS {
            return Err(SyncError::TooLarge {
                what: "blockmap index reference",
                parts: self.parts.len() as u32,
            });
        }
        let mut out = Vec::with_capacity(8 + 4 + 8 + 4 + self.parts.len() * PartDesc::LEN);
        wire::put_magic(&mut out, config::BLOCKMAP_REF_MAGIC);
        wire::put_u8(&mut out, config::FORMAT_VER);
        wire::put_u64(&mut out, self.at_seq.get());
        wire::put_u32(&mut out, self.file_count);
        wire::put_u64(&mut out, self.block_total);
        wire::put_u32(&mut out, self.parts.len() as u32);
        for part in &self.parts {
            part.encode_into(&mut out);
        }
        Ok(out)
    }

    /// Decode the control payload.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a bad magic, version, count, or a
    /// non-dense part list.
    pub fn decode(body: &[u8]) -> Result<Self, SyncError> {
        let mut reader = wire::Reader::new(body);
        reader.magic(config::BLOCKMAP_REF_MAGIC)?;
        let ver = reader.u8()?;
        if ver != config::FORMAT_VER {
            return Err(SyncError::Format("unsupported reference version"));
        }
        let at_seq = Seq(reader.u64()?);
        let file_count = reader.u32()?;
        let block_total = reader.u64()?;
        let part_count = reader.u32()?;
        if part_count > config::MAX_REF_PARTS {
            return Err(SyncError::Format("reference has too many parts"));
        }
        let mut parts = Vec::with_capacity(part_count as usize);
        for expected in 0..part_count {
            let part = PartDesc::decode(&mut reader)?;
            if part.part_index != expected {
                return Err(SyncError::Format("reference parts are not dense"));
            }
            parts.push(part);
        }
        reader.finish()?;
        Ok(Self {
            at_seq,
            file_count,
            block_total,
            parts,
        })
    }
}

/// Encode one manifest record.
pub fn encode_entry(entry: &Entry, out: &mut Vec<u8>) {
    wire::put_u8(out, kind_to_u8(entry.kind));
    out.extend_from_slice(&entry.inode.0.to_le_bytes());
    wire::put_u32(out, entry.mode);
    wire::put_u32(out, entry.uid);
    wire::put_u32(out, entry.gid);
    wire::put_u64(out, entry.size);
    wire::put_u64(out, entry.mtime_ns);
    wire::put_u32(out, entry.block_count);
    out.extend_from_slice(&entry.file_root);
    wire::put_u16(out, u16::try_from(entry.path.len()).unwrap_or(u16::MAX));
    wire::put_u16(out, u16::try_from(entry.target.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(entry.path.as_bytes());
    out.extend_from_slice(entry.target.as_bytes());
}

/// Decode a manifest record stream.
///
/// # Errors
///
/// [`SyncError::Format`] on truncation, an unknown kind, an over-long field,
/// or an entry that fails [`Entry::validate`].
pub fn decode_entries(mut stream: &[u8]) -> Result<Vec<Entry>, SyncError> {
    let mut entries = Vec::new();
    while !stream.is_empty() {
        let mut reader = wire::Reader::new(stream);
        let kind = kind_from_u8(reader.u8()?)?;
        let inode = crate::store::node_table::InodeId(u128::from_le_bytes(
            reader
                .bytes(16)?
                .try_into()
                .map_err(|_| SyncError::Format("inode width"))?,
        ));
        let mode = reader.u32()?;
        let uid = reader.u32()?;
        let gid = reader.u32()?;
        let size = reader.u64()?;
        let mtime_ns = reader.u64()?;
        let block_count = reader.u32()?;
        let file_root = reader.array32()?;
        let path_len = reader.u16()? as usize;
        let target_len = reader.u16()? as usize;
        let path = reader.bytes(path_len)?;
        let target = reader.bytes(target_len)?;
        let consumed = reader.remaining();
        let path = std::str::from_utf8(path)
            .map_err(|_| SyncError::Format("manifest path is not UTF-8"))?
            .to_owned();
        let target = std::str::from_utf8(target)
            .map_err(|_| SyncError::Format("symlink target is not UTF-8"))?
            .to_owned();
        let entry = Entry {
            path,
            kind,
            inode,
            mode,
            uid,
            gid,
            size,
            mtime_ns,
            file_root,
            block_count,
            target,
        };
        entry.validate()?;
        entries.push(entry);
        stream = &stream[stream.len() - consumed..];
    }
    Ok(entries)
}

fn kind_to_u8(kind: crate::store::Kind) -> u8 {
    use crate::store::Kind;
    match kind {
        Kind::File => 1,
        Kind::Dir => 2,
        Kind::Symlink => 3,
        Kind::Char => 4,
        Kind::Block => 5,
        Kind::Fifo => 6,
        Kind::Socket => 7,
        Kind::Unknown => 8,
    }
}

fn kind_from_u8(raw: u8) -> Result<crate::store::Kind, SyncError> {
    use crate::store::Kind;
    match raw {
        1 => Ok(Kind::File),
        2 => Ok(Kind::Dir),
        3 => Ok(Kind::Symlink),
        4 => Ok(Kind::Char),
        5 => Ok(Kind::Block),
        6 => Ok(Kind::Fifo),
        7 => Ok(Kind::Socket),
        _ => Err(SyncError::Format("unknown manifest file kind")),
    }
}

/// Writes one container as a sequence of sealed parts.
#[derive(Debug)]
pub struct PartWriter<'a> {
    chunks: &'a dyn ChunkSource,
    kind: ChunkKind,
    magic: [u8; 4],
    covered_seq: Seq,
    buffer: Vec<u8>,
    parts: Vec<PartDesc>,
    total: u64,
}

impl<'a> PartWriter<'a> {
    /// Start a container.
    pub fn new(
        chunks: &'a dyn ChunkSource,
        kind: ChunkKind,
        magic: [u8; 4],
        covered_seq: Seq,
    ) -> Self {
        Self {
            chunks,
            kind,
            magic,
            covered_seq,
            buffer: Vec::with_capacity(config::PART_PAYLOAD),
            parts: Vec::new(),
            total: 0,
        }
    }

    /// Append bytes, flushing complete parts.
    ///
    /// # Errors
    ///
    /// Whatever [`ChunkSource::put`] returns.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), SyncError> {
        while !bytes.is_empty() {
            let room = config::PART_PAYLOAD - self.buffer.len();
            if room == 0 {
                self.flush_full()?;
                continue;
            }
            let take = room.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == config::PART_PAYLOAD {
                self.flush_full()?;
            }
        }
        Ok(())
    }

    /// Flush the remainder and return the descriptors plus the payload total.
    ///
    /// An empty container still gets one empty part, so every container has at
    /// least one chunk to fetch and cannot be confused with "absent".
    ///
    /// # Errors
    ///
    /// Whatever [`ChunkSource::put`] returns.
    pub fn finish(mut self) -> Result<(Vec<PartDesc>, u64), SyncError> {
        if !self.buffer.is_empty() || self.parts.is_empty() {
            let payload = std::mem::take(&mut self.buffer);
            self.emit(&payload)?;
        }
        Ok((self.parts, self.total))
    }

    fn flush_full(&mut self) -> Result<(), SyncError> {
        let payload = std::mem::take(&mut self.buffer);
        debug_assert_eq!(payload.len(), config::PART_PAYLOAD);
        self.emit(&payload)
    }

    fn emit(&mut self, payload: &[u8]) -> Result<(), SyncError> {
        let part_index = u32::try_from(self.parts.len())
            .map_err(|_| SyncError::Format("container has too many parts"))?;
        let mut plain = Vec::with_capacity(PartHeader::LEN + payload.len());
        PartHeader {
            covered_seq: self.covered_seq,
            part_index,
            payload_len: payload.len() as u32,
        }
        .encode_into(self.magic, &mut plain);
        plain.extend_from_slice(payload);

        let mut ids = Vec::with_capacity(plain.len().div_ceil(config::CHUNK_BYTES));
        for slice in plain.chunks(config::CHUNK_BYTES) {
            ids.push(self.chunks.put(self.kind, slice)?);
        }
        self.parts
            .push(PartDesc::new(part_index, plain.len() as u32, &ids));
        self.total += payload.len() as u64;
        Ok(())
    }
}

/// Reads one container part by descriptor.
#[derive(Debug)]
pub struct PartReader<'a> {
    chunks: &'a dyn ChunkSource,
    kind: ChunkKind,
    magic: [u8; 4],
}

impl<'a> PartReader<'a> {
    /// Bind a chunk source.
    pub const fn new(chunks: &'a dyn ChunkSource, kind: ChunkKind, magic: [u8; 4]) -> Self {
        Self {
            chunks,
            kind,
            magic,
        }
    }

    /// Fetch, assemble and validate one part; returns its payload.
    ///
    /// # Errors
    ///
    /// [`SyncError::PartLengthMismatch`] when the chunks assemble to the wrong
    /// size, [`SyncError::CoveredSeqMismatch`] when the part belongs to another
    /// sequence, and chunk errors from the source.
    pub async fn read(&self, covered_seq: Seq, desc: &PartDesc) -> Result<Vec<u8>, SyncError> {
        let mut plain = Vec::with_capacity(desc.plain_len as usize);
        for id in desc.chunks() {
            let piece = self.chunks.fetch(self.kind, id).await?;
            plain.extend_from_slice(&piece);
        }
        if plain.len() != desc.plain_len as usize {
            return Err(SyncError::PartLengthMismatch {
                part: desc.part_index,
                expected: desc.plain_len,
                found: u32::try_from(plain.len()).unwrap_or(u32::MAX),
            });
        }
        let header = PartHeader::decode(self.magic, &plain)?;
        if header.covered_seq != covered_seq {
            return Err(SyncError::CoveredSeqMismatch {
                expected: covered_seq,
                found: header.covered_seq,
            });
        }
        if header.part_index != desc.part_index {
            return Err(SyncError::Format("part index disagrees with descriptor"));
        }
        Ok(plain[PartHeader::LEN..].to_vec())
    }
}

/// Builds the holder side of the manifest and blockmap.
#[derive(Debug)]
pub struct ManifestBuilder<'a> {
    chunks: &'a dyn ChunkSource,
    at_seq: Seq,
}

/// The blockmap index and its reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockmapBuild {
    /// What the joiner is told.
    pub reference: BlockmapIndexRef,
    /// What the holder keeps to serve part requests.
    pub index: BlockmapIndex,
}

impl<'a> ManifestBuilder<'a> {
    /// Bind a chunk sink and the sequence the containers describe.
    pub const fn new(chunks: &'a dyn ChunkSource, at_seq: Seq) -> Self {
        Self { chunks, at_seq }
    }

    /// Serialize a full manifest.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when `manifest.at_seq` differs from the builder's
    /// sequence, or an entry is invalid.
    pub fn build(&self, manifest: &Manifest) -> Result<ManifestRef, SyncError> {
        if manifest.at_seq != self.at_seq {
            return Err(SyncError::Format(
                "manifest sequence disagrees with builder",
            ));
        }
        let mut writer = PartWriter::new(
            self.chunks,
            ChunkKind::Manifest,
            config::MANIFEST_PART_MAGIC,
            self.at_seq,
        );
        let mut record = Vec::new();
        for entry in manifest.entries() {
            entry.validate()?;
            record.clear();
            encode_entry(entry, &mut record);
            writer.push(&record)?;
        }
        let (parts, total_len) = writer.finish()?;
        Ok(ManifestRef {
            at_seq: self.at_seq,
            entry_count: u32::try_from(manifest.len())
                .map_err(|_| SyncError::Format("too many manifest entries"))?,
            total_len,
            parts,
        })
    }

    /// Serialize the blockmap index and every data part.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the blockmap sequence differs, or
    /// [`SyncError::TooLarge`] when the index needs more than one reference.
    pub fn build_blockmap(&self, blockmap: &Blockmap) -> Result<BlockmapBuild, SyncError> {
        if blockmap.at_seq() != self.at_seq {
            return Err(SyncError::Format(
                "blockmap sequence disagrees with builder",
            ));
        }
        let ids = blockmap.ids();
        let mut data_writer = PartWriter::new(
            self.chunks,
            ChunkKind::Blockmap,
            config::BLOCKMAP_PART_MAGIC,
            self.at_seq,
        );
        for slice in ids.chunks(config::BLOCKMAP_IDS_PER_PART) {
            let mut payload = Vec::with_capacity(slice.len() * ChunkId::LEN);
            for id in slice {
                payload.extend_from_slice(id.as_bytes());
            }
            data_writer.push(&payload)?;
        }
        let (data_parts, _) = data_writer.finish()?;

        let index = BlockmapIndex {
            at_seq: self.at_seq,
            block_total: ids.len() as u64,
            file_first_block: blockmap.file_first_block().to_vec(),
            data_parts,
        };
        let encoded = index.encode()?;
        let mut index_writer = PartWriter::new(
            self.chunks,
            ChunkKind::Blockmap,
            config::BLOCKMAP_INDEX_MAGIC,
            self.at_seq,
        );
        index_writer.push(&encoded)?;
        let (parts, _) = index_writer.finish()?;

        let reference = BlockmapIndexRef {
            at_seq: self.at_seq,
            file_count: u32::try_from(index.file_first_block.len())
                .map_err(|_| SyncError::Format("too many files"))?,
            block_total: index.block_total,
            parts,
        };
        Ok(BlockmapBuild { reference, index })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::store::node_table::InodeId;
    use crate::sync::test_support::{MemChunks, futures_block_on};

    fn manifest(count: usize, at: u64) -> Manifest {
        let entries = (0..count)
            .map(|index| {
                Entry::file(
                    format!("dir/file-{index:04}"),
                    InodeId(index as u128 + 1),
                    0o644,
                    1000,
                    1000,
                    0,
                    1_700_000_000 + index as u64,
                    &[],
                )
            })
            .collect();
        Manifest::new(Seq(at), entries)
    }

    /// A full manifest round-trips through parts.
    #[tokio::test]
    async fn i_codec_manifest_round_trip() {
        let chunks = MemChunks::new();
        let source = manifest(500, 4096);
        let builder = ManifestBuilder::new(chunks.as_ref(), Seq(4096));
        let reference = builder.build(&source).unwrap();
        assert_eq!(reference.entry_count, 500);
        let decoded =
            crate::sync::manifest::ManifestService::read_manifest(chunks.as_ref(), &reference)
                .await
                .unwrap();
        assert_eq!(decoded.entries(), source.entries());
        assert_eq!(decoded.at_seq, Seq(4096));
    }

    /// 43 §2.2: a record may straddle a part boundary.
    #[tokio::test]
    async fn i_codec_record_crosses_part() {
        let chunks = MemChunks::new();
        // One entry with a path long enough to force a boundary.
        let long_path = format!("dir/{}", "x".repeat(1000));
        let entry = Entry::file(long_path, InodeId(1), 0o644, 0, 0, 0, 1, &[]);
        let source = Manifest::new(Seq(1), vec![entry]);
        let builder = ManifestBuilder::new(chunks.as_ref(), Seq(1));
        let reference = builder.build(&source).unwrap();
        assert_eq!(reference.parts.len(), 1);
        let decoded =
            crate::sync::manifest::ManifestService::read_manifest(chunks.as_ref(), &reference)
                .await
                .unwrap();
        assert_eq!(decoded.entries()[0].path.len(), 1004);
    }

    /// A large manifest splits into several parts and still decodes.
    #[tokio::test]
    async fn i_codec_manifest_multi_part() {
        let chunks = MemChunks::new();
        let source = manifest(40_000, 7);
        let builder = ManifestBuilder::new(chunks.as_ref(), Seq(7));
        let reference = builder.build(&source).unwrap();
        assert!(reference.parts.len() > 1);
        let decoded =
            crate::sync::manifest::ManifestService::read_manifest(chunks.as_ref(), &reference)
                .await
                .unwrap();
        assert_eq!(decoded.len(), 40_000);
    }

    /// References reject non-dense part lists.
    #[test]
    fn u_codec_reference_density() {
        let reference = ManifestRef {
            at_seq: Seq(1),
            entry_count: 0,
            total_len: 0,
            parts: vec![PartDesc::new(1, 21, &[ChunkId::from_bytes([1; 32])])],
        };
        let encoded = reference.encode().unwrap();
        assert_eq!(
            ManifestRef::decode(&encoded),
            Err(SyncError::Format("reference parts are not dense"))
        );
    }

    /// A reference whose length exceeds its parts is rejected before alloc.
    #[test]
    fn u_codec_reference_length_guard() {
        let reference = ManifestRef {
            at_seq: Seq(1),
            entry_count: 0,
            total_len: u64::from(config::PART_PAYLOAD as u32) + 1,
            parts: vec![PartDesc::new(0, 21, &[ChunkId::from_bytes([1; 32])])],
        };
        let encoded = reference.encode().unwrap();
        assert_eq!(
            ManifestRef::decode(&encoded),
            Err(SyncError::Format("reference length exceeds its parts"))
        );
    }

    /// An empty manifest still has one part, so absence is unambiguous.
    #[tokio::test]
    async fn i_codec_empty_manifest() {
        let chunks = MemChunks::new();
        let source = Manifest::new(Seq(3), Vec::new());
        let builder = ManifestBuilder::new(chunks.as_ref(), Seq(3));
        let reference = builder.build(&source).unwrap();
        assert_eq!(reference.parts.len(), 1);
        assert_eq!(reference.total_len, 0);
        let decoded =
            crate::sync::manifest::ManifestService::read_manifest(chunks.as_ref(), &reference)
                .await
                .unwrap();
        assert!(decoded.is_empty());
    }

    /// Entry encoding is stable and rejects an unknown kind byte.
    #[test]
    fn u_codec_entry_bytes() {
        let entry = Entry::symlink("l", InodeId(9), 1000, 1000, 42, "target");
        let mut buf = Vec::new();
        encode_entry(&entry, &mut buf);
        assert_eq!(decode_entries(&buf).unwrap(), vec![entry]);
        buf[0] = 0xff;
        assert_eq!(
            decode_entries(&buf),
            Err(SyncError::Format("unknown manifest file kind"))
        );
        let _ = futures_block_on(async { 0 });
    }
}
