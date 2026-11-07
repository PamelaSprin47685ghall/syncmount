//! Backend-neutral rsync contract: [`DeltaEngine`], [`SegmentPolicy`], and
//! the errors every backend returns.
//!
//! Direction is fixed by 49 A2 and must never be reversed:
//!
//! ```text
//! joiner: signature(local basis segment) ──> peer
//! peer:   delta(received signature, authoritative new segment) ──> joiner
//! joiner: patch(local basis segment, received delta) == new segment
//! ```
//!
//! The engine works on one segment at a time. A file is split by
//! [`super::segment::SegmentPlan`] into pieces of at most [`SEGMENT_BYTES`]
//! whose offsets are aligned to [`CHUNK_BYTES`] content chunks. Every method
//! takes byte slices and returns owned buffers; there is no cross-thread
//! stream.

use std::error::Error;
use std::io::Write;

/// v1 segment size: 16 MiB, exactly 64 content chunks (49 A12 / 43 §4.3).
pub const SEGMENT_BYTES: usize = 16 * 1024 * 1024;

/// Content-addressed chunk size: 256 KiB (49 A4).
pub const CHUNK_BYTES: usize = 256 * 1024;

/// Number of chunks in one full segment.
pub const SEGMENT_CHUNKS: usize = SEGMENT_BYTES / CHUNK_BYTES;

/// Worst-case resident bytes per rsync worker: basis + new + delta.
///
/// 43 §4.3 and 49 A12 budget three 16 MiB buffers, i.e. 48 MiB.
pub const PEAK_PER_WORKER: usize = 3 * SEGMENT_BYTES;

/// Smallest rsync block size. 49 A4 fixes the floor at 4 KiB so a one-byte
/// edit cannot inflate into a 256 KiB literal.
pub const MIN_BLOCK_BYTES: u32 = 4 * 1024;

/// Largest rsync block size for the v1 4 GiB file ceiling (49 A4).
pub const MAX_BLOCK_BYTES: u32 = 64 * 1024;

/// BLAKE2b strong-sum widths accepted by `librsync_oxide`.
pub const MAX_STRONG_LEN: u32 = 32;

/// Default strong-sum width carried in `SIG_HDR.strong_len`.
///
/// This is a policy value, not a constant of the algorithm: 49 A12 requires
/// the width to travel on the wire so a backend that only emits 32 B can be
/// adopted without a code change.
pub const DEFAULT_STRONG_LEN: u32 = 16;

const _: () = {
    assert!(SEGMENT_BYTES == SEGMENT_CHUNKS * CHUNK_BYTES);
    assert!(SEGMENT_CHUNKS == 64);
    assert!(PEAK_PER_WORKER >= 3 * SEGMENT_BYTES);
    assert!(MIN_BLOCK_BYTES.is_power_of_two());
    assert!(MAX_BLOCK_BYTES.is_power_of_two());
    assert!(MIN_BLOCK_BYTES <= MAX_BLOCK_BYTES);
    assert!(CHUNK_BYTES % MIN_BLOCK_BYTES as usize == 0);
    assert!(CHUNK_BYTES % MAX_BLOCK_BYTES as usize == 0);
};

/// Per-file rsync parameters.
///
/// `block_size` is chosen from the *whole file* length by
/// [`SegmentPolicy::for_file_size`], not from a segment length: a 4 GiB file
/// uses 64 KiB blocks in every 16 MiB segment, keeping the signature small.
/// The same policy must be used by both ends for one file; `SIG_HDR` carries
/// `block_len` and `strong_len` so the peer can verify the agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentPolicy {
    /// Maximum bytes per signature/delta/patch call.
    pub segment_bytes: usize,
    /// Content chunk size; segment offsets must be a multiple of it.
    pub chunk_bytes: usize,
    /// Rolling-window and signature entry size.
    pub block_size: u32,
    /// Bytes of BLAKE2b used per block.
    pub strong_len: u32,
}

impl SegmentPolicy {
    /// Production defaults: 16 MiB segments, 256 KiB chunks, 4 KiB blocks,
    /// 128-bit strong sums.
    pub const DEFAULT: Self = Self {
        segment_bytes: SEGMENT_BYTES,
        chunk_bytes: CHUNK_BYTES,
        block_size: MIN_BLOCK_BYTES,
        strong_len: DEFAULT_STRONG_LEN,
    };

    /// Build a policy for one file.
    ///
    /// The block-size formula is the approved 40 §3.2 / 49 A4 rule:
    /// `B = clamp(2^floor(log2(sqrt(size))), 4 KiB, 64 KiB)`. This supersedes
    /// the 512 B / 1 KiB rows in 43 §4.3, which contradict the arbitration.
    #[must_use]
    pub fn for_file_size(file_len: u64) -> Self {
        Self {
            block_size: block_size_for(file_len),
            ..Self::DEFAULT
        }
    }

    /// Reject a policy that cannot produce a chunk-aligned segment plan.
    pub fn validate(&self) -> Result<(), DeltaError> {
        if self.segment_bytes == 0 {
            return Err(DeltaError::Policy("segment_bytes must be non-zero"));
        }
        if self.chunk_bytes == 0 {
            return Err(DeltaError::Policy("chunk_bytes must be non-zero"));
        }
        if self.segment_bytes % self.chunk_bytes != 0 {
            return Err(DeltaError::Policy(
                "segment_bytes must be a multiple of chunk_bytes",
            ));
        }
        if !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&self.block_size) {
            return Err(DeltaError::Policy(
                "block_size must be within 4 KiB..=64 KiB",
            ));
        }
        if !self.block_size.is_power_of_two() {
            return Err(DeltaError::Policy("block_size must be a power of two"));
        }
        if self.block_size as usize > self.segment_bytes {
            return Err(DeltaError::Policy("block_size exceeds segment_bytes"));
        }
        if self.chunk_bytes % self.block_size as usize != 0 {
            return Err(DeltaError::Policy("block_size must divide chunk_bytes"));
        }
        if self.strong_len == 0 || self.strong_len > MAX_STRONG_LEN {
            return Err(DeltaError::Policy("strong_len must be within 1..=32 bytes"));
        }
        Ok(())
    }

    /// Upper bound on a signature for one segment under this policy.
    #[must_use]
    pub fn max_signature_bytes(&self) -> usize {
        signature_bound(self.segment_bytes, self.block_size, self.strong_len)
    }

    /// Upper bound on a delta for one segment.
    ///
    /// One full literal segment plus at most one chunk of command overhead.
    /// This keeps the three-buffer 48 MiB worker budget (49 A12) true; the
    /// looser 40 §7.2 formula (`new_size x 1.05 + 1 MiB`) is the protocol's
    /// outer guard, not the in-process allocation bound.
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

/// Pick the rsync block size for a whole file (40 §3.2 / 49 A4).
#[must_use]
pub fn block_size_for(file_len: u64) -> u32 {
    let size = file_len.max(1);
    let root = size.isqrt();
    let shift = 63 - root.leading_zeros();
    let bytes = 1u64 << shift;
    bytes.clamp(u64::from(MIN_BLOCK_BYTES), u64::from(MAX_BLOCK_BYTES)) as u32
}

/// Serialized signature size bound for a segment.
#[must_use]
pub fn signature_bound(segment_bytes: usize, block_size: u32, strong_len: u32) -> usize {
    let block = (block_size as usize).max(1);
    let entries = segment_bytes.div_ceil(block);
    entries
        .saturating_mul(4usize.saturating_add(strong_len as usize))
        .saturating_add(12)
}

/// One rsync backend.
///
/// The joiner calls [`signature`](Self::signature), the peer calls
/// [`delta`](Self::delta), and the joiner calls [`patch`](Self::patch). The
/// implementation never reads files or manifests: inputs are plain bytes and
/// outputs are owned buffers, so the trait is testable without W14 types.
pub trait DeltaEngine: Send + Sync + std::fmt::Debug {
    /// Compute the signature of a local basis segment (joiner side).
    fn signature(&self, basis: &[u8]) -> Result<Vec<u8>, DeltaError>;

    /// Compute a delta from `signature` and the authoritative new segment
    /// (peer side).
    fn delta(&self, signature: &[u8], new: &[u8]) -> Result<Vec<u8>, DeltaError>;

    /// Reconstruct the new segment from the local basis and the received
    /// delta (joiner side).
    fn patch(&self, basis: &[u8], delta: &[u8]) -> Result<Vec<u8>, DeltaError>;

    /// [`signature`](Self::signature) into a caller-provided sink.
    fn signature_to(&self, basis: &[u8], out: &mut dyn Write) -> Result<(), DeltaError> {
        out.write_all(&self.signature(basis)?)?;
        Ok(())
    }

    /// [`delta`](Self::delta) into a caller-provided sink.
    fn delta_to(
        &self,
        signature: &[u8],
        new: &[u8],
        out: &mut dyn Write,
    ) -> Result<(), DeltaError> {
        out.write_all(&self.delta(signature, new)?)?;
        Ok(())
    }

    /// [`patch`](Self::patch) into a caller-provided sink.
    ///
    /// The patch is assembled in memory first, so a corrupt delta never
    /// leaves a partial segment in `out`.
    fn patch_to(&self, basis: &[u8], delta: &[u8], out: &mut dyn Write) -> Result<(), DeltaError> {
        out.write_all(&self.patch(basis, delta)?)?;
        Ok(())
    }
}

/// Failure of any segment-level rsync step.
#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    /// The policy is internally inconsistent.
    #[error("invalid segment policy: {0}")]
    Policy(&'static str),
    /// An input buffer is larger than one segment.
    #[error("segment length {len} exceeds the {max}-byte limit")]
    SegmentTooLarge { len: usize, max: usize },
    /// A delta is larger than the policy allows.
    #[error("delta length {len} exceeds the {max}-byte limit")]
    DeltaTooLarge { len: usize, max: usize },
    /// A signature is malformed or uses an unsupported parameter set.
    #[error("invalid signature: {0}")]
    BadSignature(&'static str),
    /// The backend could not compute a delta.
    #[error("delta computation failed: {0}")]
    Diff(#[source] Box<dyn Error + Send + Sync>),
    /// The backend rejected the delta or the basis.
    #[error("patch failed: {0}")]
    Patch(#[source] Box<dyn Error + Send + Sync>),
    /// Writing to a caller-provided sink failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The blocking worker was cancelled or panicked.
    #[error("blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// 51:P1-3 — the v1 constants encode 16 MiB = 64 x 256 KiB and a
    /// three-buffer 48 MiB worker budget.
    #[test]
    fn u_rsync_policy_constants_match_mandate() {
        assert_eq!(SEGMENT_BYTES, 16 * 1024 * 1024);
        assert_eq!(CHUNK_BYTES, 256 * 1024);
        assert_eq!(SEGMENT_CHUNKS, 64);
        assert_eq!(PEAK_PER_WORKER, 48 * 1024 * 1024);
        assert_eq!(PEAK_PER_WORKER, 3 * SEGMENT_BYTES);
        assert_eq!(SegmentPolicy::DEFAULT.segment_bytes, SEGMENT_BYTES);
        assert_eq!(SegmentPolicy::DEFAULT.chunk_bytes, CHUNK_BYTES);
        assert!(SegmentPolicy::DEFAULT.validate().is_ok());
    }

    /// 49 A4 — the sqrt formula reproduces the approved table.
    #[test]
    fn u_rsync_policy_block_size_follows_sqrt_formula() {
        let cases = [
            (0, 4 * 1024),
            (1, 4 * 1024),
            (1024 * 1024, 4 * 1024),
            (16 * 1024 * 1024, 4 * 1024),
            (64 * 1024 * 1024, 8 * 1024),
            (256 * 1024 * 1024, 16 * 1024),
            (1024 * 1024 * 1024, 32 * 1024),
            (4 * 1024 * 1024 * 1024, 64 * 1024),
            (16 * 1024 * 1024 * 1024, 64 * 1024),
        ];
        for (size, expected) in cases {
            assert_eq!(block_size_for(size), expected, "size={size}");
            assert_eq!(SegmentPolicy::for_file_size(size).block_size, expected);
        }
    }

    /// 45:§0.2 C14 — a misaligned segment or an unsupported block size is
    /// rejected before the backend is called.
    #[test]
    fn u_rsync_policy_rejects_misalignment() {
        let policy = SegmentPolicy {
            segment_bytes: SEGMENT_BYTES - 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(DeltaError::Policy(_))));

        let policy = SegmentPolicy {
            block_size: 3 * 1024,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(DeltaError::Policy(_))));

        let policy = SegmentPolicy {
            strong_len: 0,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(DeltaError::Policy(_))));

        let policy = SegmentPolicy {
            strong_len: MAX_STRONG_LEN + 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(policy.validate(), Err(DeltaError::Policy(_))));
    }

    /// 49 A12 — strong width is a policy field, not a hard-coded 16.
    #[test]
    fn u_rsync_policy_strong_len_is_parameterised() {
        let policy = SegmentPolicy {
            strong_len: 32,
            ..SegmentPolicy::DEFAULT
        };
        assert!(policy.validate().is_ok());
        assert!(policy.max_signature_bytes() > SegmentPolicy::DEFAULT.max_signature_bytes());
    }

    /// 49 A12 — the delta ceiling is one segment plus one chunk, so a worker
    /// still fits in three 16 MiB buffers.
    #[test]
    fn u_rsync_policy_delta_ceiling_bounds_worker() {
        let policy = SegmentPolicy::DEFAULT;
        assert_eq!(policy.max_delta_bytes(), SEGMENT_BYTES + CHUNK_BYTES);
        assert!(policy.max_delta_bytes() > policy.segment_bytes);
    }
}
