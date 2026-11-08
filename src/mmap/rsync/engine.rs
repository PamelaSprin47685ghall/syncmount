//! Backend-neutral rsync policy, block sizing, and the shared error type.
//!
//! The engine works on byte slices or readers. It never touches a manifest, a
//! file, or a socket. A file is split into [`SEGMENT_BYTES`] windows whose
//! offsets are multiples of [`CHUNK_BYTES`].
//!
//! The block size follows the 1.1 rule:
//!
//! ```text
//! B = clamp(2^ceil(log2(sqrt(file_len))), 1 KiB, 1 MiB)
//! ```
//!
//! A file whose block count exceeds [`MAX_BLOCKS`] must fall back to FULL.

use std::io;

/// Content chunk size. The storage grid is a hard 64 KiB.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Default segment size: 4 MiB, or 64 content chunks.
pub const SEGMENT_BYTES: usize = 4 * 1024 * 1024;

/// Number of chunks in one full segment.
pub const SEGMENT_CHUNKS: usize = SEGMENT_BYTES / CHUNK_BYTES;

/// Resident bytes per rsync worker: basis + new + delta.
pub const PEAK_PER_WORKER: usize = 3 * SEGMENT_BYTES;

/// Smallest block size.
pub const MIN_BLOCK_BYTES: u32 = 1024;

/// Largest block size. Production files (<= 4 GiB) use at most 64 KiB.
pub const MAX_BLOCK_BYTES: u32 = 1024 * 1024;

/// Strong checksum width. BLAKE3-128 is the only supported width.
pub const DEFAULT_STRONG_LEN: u32 = 16;

/// Strong checksum width ceiling.
pub const MAX_STRONG_LEN: u32 = 16;

/// Hard block-count ceiling. Above this, the caller must send FULL.
pub const MAX_BLOCKS: u64 = 1024 * 1024;

/// Hard segment-count ceiling. Production files are at most 4 GiB, or 1024
/// segments at 4 MiB.
pub const MAX_SEGMENTS: u64 = 1024 * 1024;

/// Maximum literal payload in one instruction record.
pub const LITERAL_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum output of the convenience [`super::apply`] path. Production
/// callers use [`super::apply_exact`] with the manifest size.
pub const MAX_APPLY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

const _: () = {
    assert!(SEGMENT_BYTES == SEGMENT_CHUNKS * CHUNK_BYTES);
    assert!(SEGMENT_CHUNKS == 64);
    assert!(PEAK_PER_WORKER == 3 * SEGMENT_BYTES);
    assert!(MIN_BLOCK_BYTES.is_power_of_two());
    assert!(MAX_BLOCK_BYTES.is_power_of_two());
    assert!(MIN_BLOCK_BYTES <= MAX_BLOCK_BYTES);
    assert!(MAX_BLOCK_BYTES as usize <= SEGMENT_BYTES);
    assert!(LITERAL_CHUNK_BYTES <= CHUNK_BYTES);
};

/// Per-file rsync parameters.
///
/// The same policy must be used by both ends for one file. The signature
/// carries `block_size` and `strong_len`, so the peer can verify agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentPolicy {
    /// Maximum bytes per signature/delta/apply call.
    pub segment_bytes: usize,
    /// Content chunk size; segment offsets must be a multiple of it.
    pub chunk_bytes: usize,
    /// Rolling-window and signature entry size.
    pub block_size: u32,
    /// Bytes of BLAKE3 used per block.
    pub strong_len: u32,
}

impl SegmentPolicy {
    /// Production defaults: 4 MiB segments, 64 KiB chunks, 1 KiB blocks,
    /// 128-bit strong sums.
    pub const DEFAULT: Self = Self {
        segment_bytes: SEGMENT_BYTES,
        chunk_bytes: CHUNK_BYTES,
        block_size: MIN_BLOCK_BYTES,
        strong_len: DEFAULT_STRONG_LEN,
    };

    /// Build a policy for one whole file.
    #[must_use]
    pub fn for_file_size(file_len: u64) -> Self {
        Self {
            block_size: block_size_for(file_len),
            ..Self::DEFAULT
        }
    }

    /// Reject a policy that cannot produce a chunk-aligned segment plan.
    pub fn validate(&self) -> Result<(), RsyncError> {
        if self.segment_bytes == 0 {
            return Err(RsyncError::Policy("segment_bytes must be non-zero"));
        }
        if self.chunk_bytes == 0 {
            return Err(RsyncError::Policy("chunk_bytes must be non-zero"));
        }
        if self.segment_bytes % self.chunk_bytes != 0 {
            return Err(RsyncError::Policy(
                "segment_bytes must be a multiple of chunk_bytes",
            ));
        }
        if !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&self.block_size) {
            return Err(RsyncError::Policy(
                "block_size must be within 1 KiB..=1 MiB",
            ));
        }
        if !self.block_size.is_power_of_two() {
            return Err(RsyncError::Policy("block_size must be a power of two"));
        }
        if self.block_size as usize > self.segment_bytes {
            return Err(RsyncError::Policy("block_size exceeds segment_bytes"));
        }
        if self.strong_len != DEFAULT_STRONG_LEN {
            return Err(RsyncError::Policy(
                "strong_len must be 16 bytes (BLAKE3-128)",
            ));
        }
        Ok(())
    }

    /// True when every block lies inside one 64 KiB storage chunk.
    ///
    /// The production formula satisfies this for files up to 4 GiB. Larger
    /// files may use blocks above 64 KiB; those blocks span several chunks
    /// and remain valid for the delta engine, but not for per-chunk signing.
    #[must_use]
    pub fn is_storage_aligned(&self) -> bool {
        let block = self.block_size as usize;
        block <= self.chunk_bytes && self.chunk_bytes % block == 0
    }

    /// Upper bound on a signature for one segment under this policy.
    #[must_use]
    pub fn max_signature_bytes(&self) -> usize {
        signature_bound(self.segment_bytes, self.block_size, self.strong_len)
    }

    /// Upper bound on an encoded delta for one segment.
    ///
    /// One full literal segment plus command overhead fits inside one
    /// segment plus one chunk.
    #[must_use]
    pub fn max_delta_bytes(&self) -> usize {
        self.segment_bytes.saturating_add(self.chunk_bytes)
    }
}

impl Default for SegmentPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Pick the rsync block size for a whole file.
///
/// `B = clamp(2^ceil(log2(sqrt(size))), 1 KiB, 1 MiB)`. The loop is exact:
/// it finds the smallest `k` with `4^k >= size`, so `k = ceil(log2(sqrt))`.
#[must_use]
pub fn block_size_for(file_len: u64) -> u32 {
    let size = u128::from(file_len.max(1));
    let mut k = 0u32;
    while (1u128 << (2 * k)) < size {
        k += 1;
    }
    let bytes = 1u64 << k;
    bytes.clamp(u64::from(MIN_BLOCK_BYTES), u64::from(MAX_BLOCK_BYTES)) as u32
}

/// Number of blocks a file produces under `block_size`.
#[must_use]
pub fn block_count_for(file_len: u64, block_size: u32) -> u64 {
    if block_size == 0 {
        return 0;
    }
    file_len.div_ceil(u64::from(block_size))
}

/// Serialized signature size bound for a segment.
#[must_use]
pub fn signature_bound(segment_bytes: usize, block_size: u32, strong_len: u32) -> usize {
    let block = (block_size as usize).max(1);
    let entries = segment_bytes.div_ceil(block) as u64;
    let entry_bytes = 4u64 + 4 + u64::from(strong_len);
    let total = entries.saturating_mul(entry_bytes).saturating_add(24);
    total.min(usize::MAX as u64) as usize
}

/// Whole-file plan: the block size and whether DELTA is allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilePlan {
    /// Block size for every segment of this file.
    pub block_size: u32,
    /// Number of blocks over the whole file.
    pub block_count: u64,
    /// DELTA or FULL.
    pub kind: FilePlanKind,
}

impl FilePlan {
    /// Plan a file. Above [`MAX_BLOCKS`], the result is FULL.
    #[must_use]
    pub fn for_len(file_len: u64) -> Self {
        let block_size = block_size_for(file_len);
        let block_count = block_count_for(file_len, block_size);
        let kind = if block_count > MAX_BLOCKS {
            FilePlanKind::Full(FullReason::TooManyBlocks)
        } else {
            FilePlanKind::Delta
        };
        Self {
            block_size,
            block_count,
            kind,
        }
    }

    /// True when the caller must send the whole file.
    #[must_use]
    pub fn is_full(&self) -> bool {
        matches!(self.kind, FilePlanKind::Full(_))
    }
}

/// DELTA or a specific FULL reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilePlanKind {
    /// Signature/delta are allowed.
    Delta,
    /// The file must be sent whole.
    Full(FullReason),
}

/// Why a file cannot use DELTA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FullReason {
    /// The signature would hold more than [`MAX_BLOCKS`] entries.
    TooManyBlocks,
}

/// Failure of any rsync step.
#[derive(Debug, thiserror::Error)]
pub enum RsyncError {
    /// The policy is internally inconsistent.
    #[error("invalid policy: {0}")]
    Policy(&'static str),
    /// An input buffer is larger than the allowed segment.
    #[error("segment length {len} exceeds the {max}-byte limit")]
    SegmentTooLarge { len: u64, max: u64 },
    /// A signature would hold too many blocks; the caller must send FULL.
    #[error("block count {count} exceeds the {max}-block limit; fall back to FULL")]
    TooManyBlocks { count: u64, max: u64 },
    /// Reading or writing failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A signature is malformed or internally inconsistent.
    #[error("invalid signature: {0}")]
    BadSignature(&'static str),
    /// The signature was made for another block size.
    #[error("signature block size {actual} does not match the expected {expected}")]
    BlockSizeMismatch { expected: u32, actual: u32 },
    /// An instruction is malformed or out of order.
    #[error("invalid instruction: {0}")]
    BadInstruction(&'static str),
    /// A COPY points outside the base file.
    #[error("copy range offset={offset} len={len} exceeds base length {base_len}")]
    CopyOutOfBounds {
        offset: u64,
        len: u32,
        base_len: u64,
    },
    /// The base bytes no longer match the signature that produced the COPY.
    #[error("copy strong hash mismatch at block {block}")]
    StrongMismatch { block: u32 },
    /// The rebuilt output does not have the expected length.
    #[error("output length {actual} does not match the expected {expected}")]
    LengthMismatch { expected: u64, actual: u64 },
    /// The rebuilt output would exceed the safety limit.
    #[error("output exceeds the {max}-byte limit")]
    OutputTooLarge { max: u64 },
    /// UNCHANGED does not match the base bytes.
    #[error("whole-file hash mismatch")]
    HashMismatch,
    /// An encoded delta exceeds the policy bound.
    #[error("delta length {len} exceeds the {max}-byte limit")]
    DeltaTooLarge { len: usize, max: usize },
    /// The blocking worker was cancelled or panicked.
    #[error("blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn u_rsync_policy_constants_match_1_1() {
        assert_eq!(SEGMENT_BYTES, 4 * 1024 * 1024);
        assert_eq!(CHUNK_BYTES, 64 * 1024);
        assert_eq!(SEGMENT_CHUNKS, 64);
        assert_eq!(PEAK_PER_WORKER, 12 * 1024 * 1024);
        assert_eq!(SegmentPolicy::DEFAULT.segment_bytes, SEGMENT_BYTES);
        assert_eq!(SegmentPolicy::DEFAULT.chunk_bytes, CHUNK_BYTES);
        assert!(SegmentPolicy::DEFAULT.validate().is_ok());
    }

    #[test]
    fn u_rsync_policy_block_size_follows_ceil_sqrt_formula() {
        let cases = [
            (0, 1024),
            (1, 1024),
            (1024, 1024),
            (1024 * 1024, 1024),
            (2 * 1024 * 1024, 2048),
            (4 * 1024 * 1024, 2048),
            (16 * 1024 * 1024, 4096),
            (64 * 1024 * 1024, 8192),
            (256 * 1024 * 1024, 16384),
            (1024 * 1024 * 1024, 32768),
            (4 * 1024 * 1024 * 1024, 65536),
            (16 * 1024 * 1024 * 1024, 131072),
            (64 * 1024 * 1024 * 1024, 262144),
            (256 * 1024 * 1024 * 1024, 524288),
            (1024 * 1024 * 1024 * 1024, 1048576),
            (2 * 1024 * 1024 * 1024 * 1024, 1048576),
            (u64::MAX, 1048576),
        ];
        for (size, expected) in cases {
            assert_eq!(block_size_for(size), expected, "size={size}");
            assert_eq!(SegmentPolicy::for_file_size(size).block_size, expected);
        }
    }

    #[test]
    fn u_rsync_policy_block_size_is_power_of_two() {
        for exponent in 0..64 {
            let size = 1u64 << exponent;
            let block = block_size_for(size);
            assert!(block.is_power_of_two(), "size={size} block={block}");
            assert!((MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&block));
        }
    }

    #[test]
    fn u_rsync_policy_rejects_misalignment() {
        let policy = SegmentPolicy {
            segment_bytes: SEGMENT_BYTES - 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(RsyncError::Policy(_))));

        let policy = SegmentPolicy {
            block_size: 3 * 1024,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(RsyncError::Policy(_))));

        let policy = SegmentPolicy {
            block_size: 2048,
            ..SegmentPolicy::DEFAULT
        };
        assert!(policy.validate().is_ok());
        assert!(policy.is_storage_aligned());

        let policy = SegmentPolicy {
            block_size: 128 * 1024,
            ..SegmentPolicy::DEFAULT
        };
        assert!(policy.validate().is_ok());
        assert!(!policy.is_storage_aligned());

        let policy = SegmentPolicy {
            strong_len: 0,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(RsyncError::Policy(_))));

        let policy = SegmentPolicy {
            strong_len: MAX_STRONG_LEN + 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(RsyncError::Policy(_))));
    }

    #[test]
    fn u_rsync_file_plan_full_above_one_million_blocks() {
        let plan = FilePlan::for_len(1024 * 1024 * 1024 * 1024);
        assert_eq!(plan.block_count, MAX_BLOCKS);
        assert!(!plan.is_full());

        let plan = FilePlan::for_len(1024 * 1024 * 1024 * 1024 + 1);
        assert_eq!(plan.block_count, MAX_BLOCKS + 1);
        assert_eq!(plan.kind, FilePlanKind::Full(FullReason::TooManyBlocks));

        let plan = FilePlan::for_len(0);
        assert_eq!(plan.block_count, 0);
        assert!(!plan.is_full());
    }

    #[test]
    fn u_rsync_signature_and_delta_bounds() {
        let policy = SegmentPolicy::DEFAULT;
        assert!(policy.max_signature_bytes() > 24);
        assert_eq!(policy.max_delta_bytes(), SEGMENT_BYTES + CHUNK_BYTES);
        assert!(signature_bound(SEGMENT_BYTES, 1024, 16) > 0);
    }
}
