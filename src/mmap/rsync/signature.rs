//! Signature format and streaming signer.
//!
//! A signature is one header plus one entry per block:
//!
//! ```text
//! magic [4] = "SMR1" | version u8 | flags u8 | strong_len u16
//! block_size u32 | basis_len u64 | block_count u32
//! entry: weak u32 | block_len u32 | strong[strong_len]
//! ```
//!
//! All integers are big-endian. The parser validates every field before the
//! signature can reach the delta path. A zero block size, a short block in the
//! middle, a count that disagrees with `basis_len`, and trailing bytes are all
//! rejected.
//!
//! This is the engine's internal serialization. The SMM1 wire format is a
//! field stream; the server and client map it through
//! [`BlockSignature::new`] and [`Signature::new`].

use std::io::{self, Read, Write};

use super::engine::{
    DEFAULT_STRONG_LEN, MAX_BLOCK_BYTES, MAX_BLOCKS, MIN_BLOCK_BYTES, RsyncError, block_count_for,
};
use super::strong::{STRONG_LEN, StrongHash, strong128};
use super::weak::WeakState;

/// Signature magic.
pub const SIGNATURE_MAGIC: [u8; 4] = *b"SMR1";
/// Signature format version.
pub const SIGNATURE_VERSION: u8 = 1;
/// Header size.
pub const SIGNATURE_HEADER_BYTES: usize = 24;
/// Entry size with BLAKE3-128.
pub const SIGNATURE_ENTRY_BYTES: usize = 4 + 4 + STRONG_LEN;

/// One block entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSignature {
    weak: u32,
    strong: StrongHash,
    len: u32,
}

impl BlockSignature {
    /// Build one block entry from a weak checksum, a BLAKE3-128 strong
    /// checksum, and the block length.
    ///
    /// The server and client use this to rebuild a [`Signature`] from the
    /// protocol block list. The final length and placement rules are checked
    /// by [`Signature::new`].
    pub fn new(weak: u32, strong: StrongHash, len: u32) -> Result<Self, RsyncError> {
        if len == 0 {
            return Err(RsyncError::BadSignature("zero-length block"));
        }
        if len > MAX_BLOCK_BYTES {
            return Err(RsyncError::BadSignature(
                "block longer than the block size ceiling",
            ));
        }
        Ok(Self { weak, strong, len })
    }

    /// Weak checksum of the block.
    #[must_use]
    pub fn weak(&self) -> u32 {
        self.weak
    }

    /// BLAKE3-128 of the block.
    #[must_use]
    pub fn strong(&self) -> &StrongHash {
        &self.strong
    }

    /// Actual block length. Only the final block may be shorter than the
    /// policy block size.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// True for a zero-length entry, which a valid signature never contains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A whole-file or whole-segment signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    block_size: u32,
    basis_len: u64,
    strong_len: u16,
    blocks: Vec<BlockSignature>,
}

impl Signature {
    /// Build and validate a signature from parts.
    pub fn new(
        block_size: u32,
        basis_len: u64,
        blocks: Vec<BlockSignature>,
    ) -> Result<Self, RsyncError> {
        let signature = Self {
            block_size,
            basis_len,
            strong_len: DEFAULT_STRONG_LEN as u16,
            blocks,
        };
        signature.check()?;
        Ok(signature)
    }

    /// Block size used by the signer.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Number of bytes the signature covers.
    #[must_use]
    pub fn basis_len(&self) -> u64 {
        self.basis_len
    }

    /// Strong-checksum width in bytes.
    #[must_use]
    pub fn strong_len(&self) -> u32 {
        u32::from(self.strong_len)
    }

    /// Block entries in file order.
    #[must_use]
    pub fn blocks(&self) -> &[BlockSignature] {
        &self.blocks
    }

    /// One block by index.
    #[must_use]
    pub fn block(&self, index: u32) -> Option<&BlockSignature> {
        self.blocks.get(index as usize)
    }

    /// True when the basis was empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Number of block entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Serialized size.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        SIGNATURE_HEADER_BYTES + self.blocks.len() * SIGNATURE_ENTRY_BYTES
    }

    /// Check the internal invariants again.
    pub fn validate(&self) -> Result<(), RsyncError> {
        self.check()
    }

    /// Check that this signature belongs to `policy`.
    pub fn check_policy(&self, policy: &super::engine::SegmentPolicy) -> Result<(), RsyncError> {
        policy.validate()?;
        if self.block_size != policy.block_size {
            return Err(RsyncError::BlockSizeMismatch {
                expected: policy.block_size,
                actual: self.block_size,
            });
        }
        if u32::from(self.strong_len) != policy.strong_len {
            return Err(RsyncError::BadSignature(
                "strong length does not match the policy",
            ));
        }
        if self.basis_len > policy.segment_bytes as u64 {
            return Err(RsyncError::SegmentTooLarge {
                len: self.basis_len,
                max: policy.segment_bytes as u64,
            });
        }
        let max_blocks = policy.segment_bytes.div_ceil(policy.block_size as usize) as u64;
        if self.blocks.len() as u64 > max_blocks {
            return Err(RsyncError::BadSignature(
                "signature covers more blocks than one segment holds",
            ));
        }
        Ok(())
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        let result = self.encode_into(&mut out);
        debug_assert!(result.is_ok());
        out
    }

    /// Serialize into a writer.
    pub fn write_to<W: Write>(&self, out: &mut W) -> Result<(), RsyncError> {
        self.encode_into(out)
    }

    /// Parse exactly one signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RsyncError> {
        if bytes.len() < SIGNATURE_HEADER_BYTES {
            return Err(RsyncError::BadSignature(
                "shorter than the 24-byte signature header",
            ));
        }
        if bytes[..4] != SIGNATURE_MAGIC {
            return Err(RsyncError::BadSignature("not a signature"));
        }
        if bytes[4] != SIGNATURE_VERSION {
            return Err(RsyncError::BadSignature("unsupported signature version"));
        }
        if bytes[5] != 0 {
            return Err(RsyncError::BadSignature("unsupported signature flags"));
        }
        let strong_len = u16::from_be_bytes([bytes[6], bytes[7]]);
        if u32::from(strong_len) != DEFAULT_STRONG_LEN {
            return Err(RsyncError::BadSignature("strong length must be 16 bytes"));
        }
        let block_size = be_u32(&bytes[8..12]);
        let basis_len = be_u64(&bytes[12..20]);
        let count = be_u32(&bytes[20..24]);
        if u64::from(count) > MAX_BLOCKS {
            return Err(RsyncError::BadSignature("block count exceeds the 1M limit"));
        }
        let expected_len = SIGNATURE_HEADER_BYTES + count as usize * SIGNATURE_ENTRY_BYTES;
        if bytes.len() != expected_len {
            return Err(RsyncError::BadSignature(
                "signature length does not match the block count",
            ));
        }
        let mut blocks = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let at = SIGNATURE_HEADER_BYTES + index * SIGNATURE_ENTRY_BYTES;
            let weak = be_u32(&bytes[at..at + 4]);
            let len = be_u32(&bytes[at + 4..at + 8]);
            let mut strong = [0u8; STRONG_LEN];
            strong.copy_from_slice(&bytes[at + 8..at + 8 + STRONG_LEN]);
            blocks.push(BlockSignature { weak, strong, len });
        }
        Self::new(block_size, basis_len, blocks)
    }

    /// Read one signature from a reader.
    pub fn read_from<R: Read>(mut reader: R) -> Result<Self, RsyncError> {
        let max = SIGNATURE_HEADER_BYTES + MAX_BLOCKS as usize * SIGNATURE_ENTRY_BYTES;
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(RsyncError::BadSignature(
                "signature exceeds the 1M-block bound",
            ));
        }
        Self::from_bytes(&bytes)
    }

    fn encode_into<W: Write>(&self, out: &mut W) -> Result<(), RsyncError> {
        out.write_all(&SIGNATURE_MAGIC)?;
        out.write_all(&[SIGNATURE_VERSION, 0])?;
        out.write_all(&self.strong_len.to_be_bytes())?;
        out.write_all(&self.block_size.to_be_bytes())?;
        out.write_all(&self.basis_len.to_be_bytes())?;
        out.write_all(&(self.blocks.len() as u32).to_be_bytes())?;
        for block in &self.blocks {
            out.write_all(&block.weak.to_be_bytes())?;
            out.write_all(&block.len.to_be_bytes())?;
            out.write_all(&block.strong)?;
        }
        Ok(())
    }

    fn check(&self) -> Result<(), RsyncError> {
        check_block_size(self.block_size).map_err(RsyncError::BadSignature)?;
        if self.strong_len != DEFAULT_STRONG_LEN as u16 {
            return Err(RsyncError::BadSignature("strong length must be 16 bytes"));
        }
        if self.blocks.len() as u64 > MAX_BLOCKS {
            return Err(RsyncError::TooManyBlocks {
                count: self.blocks.len() as u64,
                max: MAX_BLOCKS,
            });
        }
        let expected = block_count_for(self.basis_len, self.block_size);
        if expected != self.blocks.len() as u64 {
            return Err(RsyncError::BadSignature(
                "block count does not match basis length",
            ));
        }
        if self.blocks.is_empty() {
            return Ok(());
        }
        let full_blocks = self.blocks.len() - 1;
        for (index, block) in self.blocks.iter().enumerate() {
            if block.len == 0 {
                return Err(RsyncError::BadSignature("zero-length block"));
            }
            if block.len > self.block_size {
                return Err(RsyncError::BadSignature("block longer than the block size"));
            }
            if index < full_blocks && block.len != self.block_size {
                return Err(RsyncError::BadSignature(
                    "short block before the final block",
                ));
            }
        }
        let last = self
            .blocks
            .last()
            .ok_or(RsyncError::BadSignature("missing final block"))?;
        let expected_last = self.basis_len - full_blocks as u64 * u64::from(self.block_size);
        if u64::from(last.len) != expected_last {
            return Err(RsyncError::BadSignature(
                "final block length does not match basis length",
            ));
        }
        Ok(())
    }
}

fn check_block_size(block_size: u32) -> Result<(), &'static str> {
    if !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&block_size) {
        return Err("block size outside 1 KiB..=1 MiB");
    }
    if !block_size.is_power_of_two() {
        return Err("block size is not a power of two");
    }
    Ok(())
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Compute the signature of a reader.
pub fn sign<R: Read>(reader: R, block_size: u32) -> Result<Signature, RsyncError> {
    sign_limited(reader, block_size, u64::MAX)
}

/// Compute a signature and reject a basis larger than `max_bytes`.
pub fn sign_limited<R: Read>(
    mut reader: R,
    block_size: u32,
    max_bytes: u64,
) -> Result<Signature, RsyncError> {
    check_block_size(block_size).map_err(RsyncError::Policy)?;
    let block_len = block_size as usize;
    let mut block = vec![0u8; block_len];
    let mut blocks = Vec::new();
    let mut basis_len = 0u64;
    loop {
        let read = read_full(&mut reader, &mut block)?;
        if read == 0 {
            break;
        }
        basis_len = basis_len
            .checked_add(read as u64)
            .ok_or(RsyncError::SegmentTooLarge {
                len: u64::MAX,
                max: max_bytes,
            })?;
        if basis_len > max_bytes {
            return Err(RsyncError::SegmentTooLarge {
                len: basis_len,
                max: max_bytes,
            });
        }
        if blocks.len() as u64 >= MAX_BLOCKS {
            return Err(RsyncError::TooManyBlocks {
                count: blocks.len() as u64 + 1,
                max: MAX_BLOCKS,
            });
        }
        let weak = WeakState::new(&block[..read]).weak();
        let strong = strong128(&block[..read]);
        blocks.push(BlockSignature {
            weak,
            strong,
            len: read as u32,
        });
        if read < block_len {
            break;
        }
    }
    Signature::new(block_size, basis_len, blocks)
}

/// Sign one segment under `policy`.
pub fn sign_segment<R: Read>(
    reader: R,
    policy: &super::engine::SegmentPolicy,
) -> Result<Signature, RsyncError> {
    policy.validate()?;
    sign_limited(reader, policy.block_size, policy.segment_bytes as u64)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::rsync::engine::SegmentPolicy;
    use std::io::Cursor;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(state as u8);
        }
        out
    }

    #[test]
    fn u_rsync_sign_empty() {
        let signature = sign(Cursor::new(Vec::<u8>::new()), 1024).unwrap();
        assert_eq!(signature.basis_len(), 0);
        assert_eq!(signature.block_size(), 1024);
        assert_eq!(signature.strong_len(), 16);
        assert!(signature.is_empty());
        assert_eq!(signature.len(), 0);
        assert_eq!(signature.to_bytes().len(), SIGNATURE_HEADER_BYTES);
        assert_eq!(
            Signature::from_bytes(&signature.to_bytes()).unwrap(),
            signature
        );
    }

    #[test]
    fn u_rsync_sign_block_lengths() {
        let data = noise(10_000, 0x11);
        let signature = sign(Cursor::new(&data), 4096).unwrap();
        assert_eq!(signature.basis_len(), 10_000);
        assert_eq!(signature.len(), 3);
        assert_eq!(signature.block(0).unwrap().len(), 4096);
        assert_eq!(signature.block(1).unwrap().len(), 4096);
        assert_eq!(signature.block(2).unwrap().len(), 1808);
        assert_eq!(
            signature.block(0).unwrap().strong(),
            &strong128(&data[..4096])
        );
        assert_eq!(
            signature.block(0).unwrap().weak(),
            WeakState::new(&data[..4096]).weak()
        );
    }

    #[test]
    fn u_rsync_signature_roundtrip_preserves_bytes() {
        let data = noise(65_536, 0x12);
        let signature = sign(Cursor::new(&data), 2048).unwrap();
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), signature.encoded_len());
        assert_eq!(Signature::from_bytes(&bytes).unwrap(), signature);

        let mut written = Vec::new();
        signature.write_to(&mut written).unwrap();
        assert_eq!(written, bytes);

        let mut reader = Cursor::new(&bytes);
        assert_eq!(Signature::read_from(&mut reader).unwrap(), signature);
    }

    #[test]
    fn u_rsync_block_signature_public_constructor() {
        let block = BlockSignature::new(7, [0x11; 16], 1024).unwrap();
        assert_eq!(block.weak(), 7);
        assert_eq!(block.strong(), &[0x11; 16]);
        assert_eq!(block.len(), 1024);
        assert!(BlockSignature::new(0, [0u8; 16], 0).is_err());
        assert!(BlockSignature::new(0, [0u8; 16], MAX_BLOCK_BYTES + 1).is_err());

        let signature = Signature::new(1024, 1024, vec![block]).unwrap();
        assert_eq!(signature.len(), 1);
    }

    #[test]
    fn u_rsync_signature_from_protocol_parts() {
        use crate::mmap::rsync::{apply, delta};

        let basis = noise(4096, 0x71);
        let signed = sign(Cursor::new(&basis), 1024).unwrap();
        let blocks: Vec<BlockSignature> = signed
            .blocks()
            .iter()
            .map(|block| BlockSignature::new(block.weak(), *block.strong(), block.len()).unwrap())
            .collect();
        let rebuilt = Signature::new(signed.block_size(), signed.basis_len(), blocks).unwrap();
        assert_eq!(rebuilt, signed);

        let instructions = delta(&basis, &rebuilt).unwrap();
        assert_eq!(apply(&basis, &instructions).unwrap(), basis);
    }

    #[test]
    fn u_rsync_sign_handles_short_reads() {
        struct ShortRead {
            data: Vec<u8>,
            at: usize,
        }
        impl Read for ShortRead {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let take = buffer.len().min(7).min(self.data.len() - self.at);
                buffer[..take].copy_from_slice(&self.data[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }
        let data = noise(5000, 0x13);
        let signature = sign(
            ShortRead {
                data: data.clone(),
                at: 0,
            },
            1024,
        )
        .unwrap();
        let expected = sign(Cursor::new(&data), 1024).unwrap();
        assert_eq!(signature, expected);
    }

    #[test]
    fn u_rsync_sign_reads_in_block_chunks() {
        struct Bounded {
            remaining: usize,
            block: usize,
        }
        impl Read for Bounded {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert!(buffer.len() <= self.block, "request={}", buffer.len());
                let take = buffer.len().min(self.remaining).min(97);
                buffer[..take].fill(0x5a);
                self.remaining -= take;
                Ok(take)
            }
        }
        let signature = sign(
            Bounded {
                remaining: 100_000,
                block: 1024,
            },
            1024,
        )
        .unwrap();
        assert_eq!(signature.basis_len(), 100_000);
        assert_eq!(signature.len(), 98);
    }

    #[test]
    fn u_rsync_signature_rejects_malformed() {
        let data = noise(4096, 0x14);
        let signature = sign(Cursor::new(&data), 1024).unwrap();
        let good = signature.to_bytes();

        assert!(matches!(
            Signature::from_bytes(&[]),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[4] = 2;
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[5] = 1;
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[6..8].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&3000u32.to_be_bytes());
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad.pop();
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad.push(0);
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));

        let mut bad = good.clone();
        bad[20..24].copy_from_slice(&(MAX_BLOCKS as u32 + 1).to_be_bytes());
        assert!(matches!(
            Signature::from_bytes(&bad),
            Err(RsyncError::BadSignature(_))
        ));
    }

    #[test]
    fn u_rsync_signature_rejects_inconsistent_lengths() {
        let block = |len: u32| BlockSignature {
            weak: 0,
            strong: [0u8; 16],
            len,
        };

        assert!(Signature::new(1024, 0, vec![block(1)]).is_err());
        assert!(Signature::new(1024, 1024, vec![]).is_err());
        assert!(Signature::new(1024, 2048, vec![block(1024)]).is_err());
        assert!(Signature::new(1024, 2048, vec![block(512), block(1536)]).is_err());
        assert!(Signature::new(1024, 2048, vec![block(1024), block(1024)]).is_ok());
        assert!(Signature::new(1024, 1025, vec![block(1024), block(1)]).is_ok());
        assert!(Signature::new(1024, 1025, vec![block(1024), block(2)]).is_err());
    }

    #[test]
    fn u_rsync_signature_check_policy() {
        let data = noise(8192, 0x15);
        let signature = sign(Cursor::new(&data), 2048).unwrap();
        let policy = SegmentPolicy {
            block_size: 2048,
            ..SegmentPolicy::DEFAULT
        };
        assert!(signature.check_policy(&policy).is_ok());

        let policy = SegmentPolicy {
            block_size: 4096,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            signature.check_policy(&policy),
            Err(RsyncError::BlockSizeMismatch { .. })
        ));

        let policy = SegmentPolicy {
            segment_bytes: 4096,
            chunk_bytes: 1024,
            block_size: 2048,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            signature.check_policy(&policy),
            Err(RsyncError::SegmentTooLarge { .. })
        ));
    }

    #[test]
    fn u_rsync_sign_limited_rejects_oversized_basis() {
        let data = noise(8192, 0x16);
        assert!(matches!(
            sign_limited(Cursor::new(&data), 1024, 4096),
            Err(RsyncError::SegmentTooLarge { .. })
        ));
        let signature = sign_limited(Cursor::new(&data), 1024, 8192).unwrap();
        assert_eq!(signature.basis_len(), 8192);
    }

    #[test]
    fn u_rsync_sign_segment_uses_policy() {
        let data = noise(4096, 0x17);
        let policy = SegmentPolicy {
            block_size: 1024,
            ..SegmentPolicy::DEFAULT
        };
        let signature = sign_segment(Cursor::new(&data), &policy).unwrap();
        assert_eq!(signature.block_size(), 1024);
        assert_eq!(signature.len(), 4);
    }

    #[test]
    fn u_rsync_sign_rejects_bad_block_size() {
        assert!(matches!(
            sign(Cursor::new(Vec::<u8>::new()), 0),
            Err(RsyncError::Policy(_))
        ));
        assert!(matches!(
            sign(Cursor::new(Vec::<u8>::new()), 3000),
            Err(RsyncError::Policy(_))
        ));
        assert!(matches!(
            sign(Cursor::new(Vec::<u8>::new()), MAX_BLOCK_BYTES * 2),
            Err(RsyncError::Policy(_))
        ));
    }
}
