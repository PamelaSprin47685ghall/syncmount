//! `librsync_oxide` 0.3.0 backend.
//!
//! This is the only backend in v1 (49 A12). The crate is pure Rust,
//! Apache-2.0, and speaks librsync 2.2.1's signature/delta formats. It has no
//! streaming input API, so the segment policy bounds every call to 16 MiB.
//!
//! The wire format is deliberately not hidden: [`SignatureType::Blake2`] plus
//! the BLAKE2 signature magic is validated before `deserialize`, because the
//! crate does not reject a zero `block_size` and `diff` would spin forever on
//! one.

use librsync_oxide::{Signature, SignatureOptions, SignatureType, apply_limited, diff};

use super::engine::{
    DeltaEngine, DeltaError, MAX_BLOCK_BYTES, MAX_STRONG_LEN, MIN_BLOCK_BYTES, SegmentPolicy,
    signature_bound,
};

/// librsync's BLAKE2 signature magic (`RS_BLAKE2_SIG_MAGIC`).
///
/// This is the value `SIG_HDR.sig_magic` carries (49 A12).
pub const BLAKE2_SIGNATURE_MAGIC: u32 = 0x7273_0137;

/// librsync's delta magic (`RS_DELTA_MAGIC`).
pub const DELTA_MAGIC: u32 = 0x7273_0236;

/// `magic u32 | block_size u32 | strong_len u32`.
const SIGNATURE_HEADER_BYTES: usize = 12;

/// The v1 delta engine.
///
/// The engine is stateless apart from its [`SegmentPolicy`]; cloning it is
/// cheap. Construct one per file with [`OxideEngine::for_file_size`] so the
/// block size matches the whole-file formula, then reuse it for every segment
/// of that file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OxideEngine {
    policy: SegmentPolicy,
}

impl OxideEngine {
    /// Build an engine with an explicit policy.
    #[must_use]
    pub const fn new(policy: SegmentPolicy) -> Self {
        Self { policy }
    }

    /// Build an engine whose block size follows the whole-file formula.
    #[must_use]
    pub fn for_file_size(file_len: u64) -> Self {
        Self::new(SegmentPolicy::for_file_size(file_len))
    }

    /// The policy used by this engine.
    #[must_use]
    pub fn policy(&self) -> &SegmentPolicy {
        &self.policy
    }

    fn check_segment(&self, len: usize) -> Result<(), DeltaError> {
        self.policy.validate()?;
        if len > self.policy.segment_bytes {
            return Err(DeltaError::SegmentTooLarge {
                len,
                max: self.policy.segment_bytes,
            });
        }
        Ok(())
    }
}

impl Default for OxideEngine {
    fn default() -> Self {
        Self::new(SegmentPolicy::DEFAULT)
    }
}

impl DeltaEngine for OxideEngine {
    /// joiner: signature over the local basis segment.
    fn signature(&self, basis: &[u8]) -> Result<Vec<u8>, DeltaError> {
        self.check_segment(basis.len())?;
        let options = SignatureOptions {
            block_size: self.policy.block_size,
            crypto_hash_size: self.policy.strong_len,
            signature_type: SignatureType::Blake2,
        };
        let signature = Signature::calculate(basis, options);
        let bytes = signature.into_serialized();
        debug_assert!(bytes.len() <= self.policy.max_signature_bytes());
        Ok(bytes)
    }

    /// peer: delta from the joiner's signature and the authoritative new
    /// segment.
    fn delta(&self, signature: &[u8], new: &[u8]) -> Result<Vec<u8>, DeltaError> {
        self.check_segment(new.len())?;
        let header = SignatureHeader::parse(signature, &self.policy)?;
        let bound = signature_bound(
            self.policy.segment_bytes,
            header.block_size,
            header.strong_len,
        );
        if signature.len() > bound {
            return Err(DeltaError::BadSignature(
                "signature exceeds the segment block bound",
            ));
        }
        let parsed = Signature::deserialize(signature.to_vec())
            .map_err(|_| DeltaError::BadSignature("signature does not parse"))?;
        let indexed = parsed.index();
        // Most deltas are far smaller than the new segment; grow on demand
        // instead of reserving 16 MiB for a one-byte edit.
        let mut out = Vec::with_capacity(new.len().min(64 * 1024));
        diff(&indexed, new, &mut out).map_err(|error| DeltaError::Diff(Box::new(error)))?;
        let max = self.policy.max_delta_bytes();
        if out.len() > max {
            return Err(DeltaError::DeltaTooLarge {
                len: out.len(),
                max,
            });
        }
        Ok(out)
    }

    /// joiner: patch the local basis with the received delta.
    ///
    /// Output is bounded by `segment_bytes` and assembled in memory first, so
    /// a malformed delta cannot leave a partially patched segment behind.
    fn patch(&self, basis: &[u8], delta: &[u8]) -> Result<Vec<u8>, DeltaError> {
        self.check_segment(basis.len())?;
        let max_delta = self.policy.max_delta_bytes();
        if delta.len() > max_delta {
            return Err(DeltaError::DeltaTooLarge {
                len: delta.len(),
                max: max_delta,
            });
        }
        let mut out = Vec::with_capacity(basis.len().min(self.policy.segment_bytes));
        apply_limited(basis, delta, &mut out, self.policy.segment_bytes)
            .map_err(|error| DeltaError::Patch(Box::new(error)))?;
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignatureHeader {
    block_size: u32,
    strong_len: u32,
}

impl SignatureHeader {
    /// Validate the parts of the signature that `librsync_oxide` leaves
    /// unchecked. A zero `block_size` must never reach `diff`: the rolling
    /// loop would never advance.
    fn parse(bytes: &[u8], policy: &SegmentPolicy) -> Result<Self, DeltaError> {
        if bytes.len() < SIGNATURE_HEADER_BYTES {
            return Err(DeltaError::BadSignature(
                "shorter than the 12-byte signature header",
            ));
        }
        let magic = read_u32(bytes, 0);
        if magic != BLAKE2_SIGNATURE_MAGIC {
            return Err(DeltaError::BadSignature("not a BLAKE2 signature"));
        }
        let block_size = read_u32(bytes, 4);
        let strong_len = read_u32(bytes, 8);
        if !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&block_size) {
            return Err(DeltaError::BadSignature(
                "block size outside 4 KiB..=64 KiB",
            ));
        }
        if !block_size.is_power_of_two() {
            return Err(DeltaError::BadSignature("block size is not a power of two"));
        }
        if policy.chunk_bytes % block_size as usize != 0 {
            return Err(DeltaError::BadSignature(
                "block size does not divide a chunk",
            ));
        }
        if strong_len == 0 || strong_len > MAX_STRONG_LEN {
            return Err(DeltaError::BadSignature(
                "strong length outside 1..=32 bytes",
            ));
        }
        let entry = 4usize.saturating_add(strong_len as usize);
        let payload = bytes.len() - SIGNATURE_HEADER_BYTES;
        if payload % entry != 0 {
            return Err(DeltaError::BadSignature(
                "signature payload is not a whole number of blocks",
            ));
        }
        let blocks = payload / entry;
        let max_blocks = policy.segment_bytes.div_ceil(block_size as usize);
        if blocks > max_blocks {
            return Err(DeltaError::BadSignature(
                "signature covers more blocks than a segment holds",
            ));
        }
        Ok(Self {
            block_size,
            strong_len,
        })
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Craft a delta that copies `len` bytes from `offset` in the basis.
#[cfg(test)]
fn copy_command(offset: u8, len: u16) -> [u8; 4] {
    // RS_OP_COPY_N1_N2: one-byte offset, two-byte length.
    let [hi, lo] = len.to_be_bytes();
    [0x46, offset, hi, lo]
}

/// Delta bytes for a copy-bomb test: 4097 copies of a 4 KiB basis.
#[cfg(test)]
fn copy_bomb_delta(basis_len: usize) -> Vec<u8> {
    assert_eq!(basis_len, 4096);
    let mut delta = Vec::new();
    delta.extend_from_slice(&DELTA_MAGIC.to_be_bytes());
    for _ in 0..=4096 {
        delta.extend_from_slice(&copy_command(0, 4096));
    }
    delta.push(0);
    delta
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::rsync::engine::{DEFAULT_STRONG_LEN, SEGMENT_BYTES};

    /// Deterministic non-repeating bytes; xorshift64.
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

    fn roundtrip(basis: &[u8], new: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let engine = OxideEngine::default();
        let signature = engine.signature(basis).unwrap();
        let delta = engine.delta(&signature, new).unwrap();
        let patched = engine.patch(basis, &delta).unwrap();
        (patched, delta)
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    /// 49 A12 — a fixed golden vector pins `librsync_oxide` 0.3.0's signature
    /// and delta bytes. A crate update that changes the wire format must fail
    /// here before it reaches a peer.
    #[test]
    fn u_rsync_oxide_golden_vector() {
        let basis: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let mut new = basis.clone();
        new.push(0xaa);
        let engine = OxideEngine::default();

        let signature = engine.signature(&basis).unwrap();
        assert_eq!(
            hex(&signature),
            "72730137000010000000001047e0a54811c294a11dc67e3ddb25f8c06cca2721"
        );

        let delta = engine.delta(&signature, &new).unwrap();
        assert_eq!(hex(&delta), "727302364600100001aa00");
        assert_eq!(engine.patch(&basis, &delta).unwrap(), new);
    }

    /// 31:M3-4 — a small edit round-trips and produces a delta far smaller
    /// than the file.
    #[test]
    fn u_rsync_roundtrip_and_incremental_delta() {
        let basis = noise(100_000, 0x51);
        let mut new = basis.clone();
        new[50_000..50_010].copy_from_slice(b"0123456789");
        let (patched, delta) = roundtrip(&basis, &new);
        assert_eq!(patched, new);
        assert!(
            delta.len() < 16 * 1024,
            "delta={} should stay near one block",
            delta.len()
        );
    }

    /// 31:M3-4 — one byte changed in a 1 MiB file moves one block only.
    #[test]
    fn u_rsync_single_byte_edit_is_incremental() {
        let basis = noise(1024 * 1024, 0x52);
        let mut new = basis.clone();
        new[700_000] ^= 0xff;
        let (patched, delta) = roundtrip(&basis, &new);
        assert_eq!(patched, new);
        assert!(delta.len() < 16 * 1024, "delta={}", delta.len());
        assert!(delta.len() * 100 < new.len());
    }

    /// 40 §4.3 — a missing or empty basis is a full-literal delta, not a
    /// separate code path.
    #[test]
    fn u_rsync_empty_basis_full_literal() {
        let new = noise(8192, 0x58);
        let (patched, delta) = roundtrip(&[], &new);
        assert_eq!(patched, new);
        assert!(delta.len() >= new.len());
    }

    /// 40 §4.3 — truncating a file to zero produces an empty patch target.
    #[test]
    fn u_rsync_truncate_to_empty() {
        let basis = noise(8192, 0x59);
        let (patched, delta) = roundtrip(&basis, &[]);
        assert!(patched.is_empty());
        assert_eq!(delta.len(), 5);
    }

    /// 40 §2.3 / 49 A2 — a one-byte insertion at the head must realign by
    /// rolling, not invalidate every fixed boundary.
    #[test]
    fn u_rsync_head_insertion_realigns() {
        let basis = noise(1024 * 1024, 0x53);
        let mut new = Vec::with_capacity(basis.len() + 1);
        new.push(0xab);
        new.extend_from_slice(&basis);
        let (patched, delta) = roundtrip(&basis, &new);
        assert_eq!(patched, new);
        assert!(
            delta.len() < 32 * 1024,
            "delta={} should mostly copy shifted blocks",
            delta.len()
        );
        assert!(delta.len() * 10 < new.len());
    }

    /// 45:§0.2 C14 — empty inputs are legal: zero blocks, five-byte delta.
    #[test]
    fn u_rsync_empty_file_roundtrip() {
        let engine = OxideEngine::default();
        let signature = engine.signature(&[]).unwrap();
        assert_eq!(signature.len(), 12);
        let delta = engine.delta(&signature, &[]).unwrap();
        assert_eq!(delta.len(), 5);
        assert_eq!(delta[0..4], DELTA_MAGIC.to_be_bytes());
        assert!(engine.patch(&[], &delta).unwrap().is_empty());
    }

    /// 43 §4.2 — the `Write` convenience methods match the `Vec` API, and a
    /// failed patch writes nothing to the sink.
    #[test]
    fn u_rsync_write_sinks_roundtrip() {
        let basis = noise(4096, 0x5a);
        let mut new = basis.clone();
        new[10] ^= 1;
        let engine = OxideEngine::default();

        let mut signature = Vec::new();
        engine.signature_to(&basis, &mut signature).unwrap();
        assert_eq!(signature, engine.signature(&basis).unwrap());

        let mut delta = Vec::new();
        engine.delta_to(&signature, &new, &mut delta).unwrap();
        assert_eq!(delta, engine.delta(&signature, &new).unwrap());

        let mut patched = Vec::new();
        engine.patch_to(&basis, &delta, &mut patched).unwrap();
        assert_eq!(patched, new);

        let mut sink = Vec::new();
        assert!(engine.patch_to(&basis, &[0, 0, 0, 0], &mut sink).is_err());
        assert!(sink.is_empty());
    }

    /// 49 A12 — the signature header is BLAKE2 with the policy widths.
    #[test]
    fn u_rsync_signature_header_is_blake2() {
        let engine = OxideEngine::default();
        let signature = engine.signature(&noise(8192, 0x54)).unwrap();
        assert_eq!(signature.len(), 12 + 2 * (4 + DEFAULT_STRONG_LEN as usize));
        assert_eq!(read_u32(&signature, 0), BLAKE2_SIGNATURE_MAGIC);
        assert_eq!(read_u32(&signature, 4), SegmentPolicy::DEFAULT.block_size);
        assert_eq!(read_u32(&signature, 8), DEFAULT_STRONG_LEN);
    }

    /// 49 A12 — a 32-byte strong sum is accepted without code changes.
    #[test]
    fn u_rsync_strong_len_32_roundtrip() {
        let policy = SegmentPolicy {
            strong_len: 32,
            ..SegmentPolicy::DEFAULT
        };
        let engine = OxideEngine::new(policy);
        let basis = noise(64 * 1024, 0x55);
        let mut new = basis.clone();
        new[1234] ^= 1;
        let signature = engine.signature(&basis).unwrap();
        assert_eq!(
            read_u32(&signature, 8),
            32,
            "SIG_HDR.strong_len must travel"
        );
        let delta = engine.delta(&signature, &new).unwrap();
        assert_eq!(engine.patch(&basis, &delta).unwrap(), new);
    }

    /// 31:M3-7 / 45:§0.2 C14 — corrupt deltas are rejected, never partially
    /// applied.
    #[test]
    fn u_rsync_patch_rejects_corrupt_delta() {
        let basis = noise(16 * 1024, 0x56);
        let mut new = basis.clone();
        new[100] ^= 0xff;
        let engine = OxideEngine::default();
        let signature = engine.signature(&basis).unwrap();
        let delta = engine.delta(&signature, &new).unwrap();

        let mut bad_magic = delta.clone();
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            engine.patch(&basis, &bad_magic),
            Err(DeltaError::Patch(_))
        ));

        let mut truncated = delta.clone();
        truncated.pop();
        assert!(matches!(
            engine.patch(&basis, &truncated),
            Err(DeltaError::Patch(_))
        ));

        let mut trailing = delta.clone();
        trailing.push(0);
        assert!(matches!(
            engine.patch(&basis, &trailing),
            Err(DeltaError::Patch(_))
        ));

        let mut out_of_bounds = DELTA_MAGIC.to_be_bytes().to_vec();
        out_of_bounds.extend_from_slice(&[0x45, 0x00, 0x01, 0x00]);
        assert!(matches!(
            engine.patch(&[], &out_of_bounds),
            Err(DeltaError::Patch(_))
        ));
    }

    /// 45:§0.2 C14 — a delta that expands beyond one segment is refused by
    /// `apply_limited`, so a malicious peer cannot exhaust memory.
    #[test]
    fn u_rsync_patch_rejects_oversized_output() {
        let basis = vec![7u8; 4096];
        let engine = OxideEngine::default();
        let delta = copy_bomb_delta(basis.len());
        assert!(delta.len() < engine.policy().max_delta_bytes());
        assert!(matches!(
            engine.patch(&basis, &delta),
            Err(DeltaError::Patch(_))
        ));
    }

    /// 45:§0.2 C14 — malformed signatures are rejected before `diff`; in
    /// particular a zero block size must not spin forever.
    #[test]
    fn u_rsync_delta_rejects_malformed_signature() {
        let engine = OxideEngine::default();
        let new = noise(4096, 0x57);

        assert!(matches!(
            engine.delta(&[], &new),
            Err(DeltaError::BadSignature(_))
        ));

        let mut zero_block = Vec::new();
        zero_block.extend_from_slice(&BLAKE2_SIGNATURE_MAGIC.to_be_bytes());
        zero_block.extend_from_slice(&0u32.to_be_bytes());
        zero_block.extend_from_slice(&DEFAULT_STRONG_LEN.to_be_bytes());
        assert!(matches!(
            engine.delta(&zero_block, &new),
            Err(DeltaError::BadSignature(_))
        ));

        let mut zero_strong = Vec::new();
        zero_strong.extend_from_slice(&BLAKE2_SIGNATURE_MAGIC.to_be_bytes());
        zero_strong.extend_from_slice(&SegmentPolicy::DEFAULT.block_size.to_be_bytes());
        zero_strong.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            engine.delta(&zero_strong, &new),
            Err(DeltaError::BadSignature(_))
        ));

        let mut md4 = Vec::new();
        md4.extend_from_slice(&0x7273_0136u32.to_be_bytes());
        md4.extend_from_slice(&SegmentPolicy::DEFAULT.block_size.to_be_bytes());
        md4.extend_from_slice(&DEFAULT_STRONG_LEN.to_be_bytes());
        assert!(matches!(
            engine.delta(&md4, &new),
            Err(DeltaError::BadSignature(_))
        ));

        let mut too_many_blocks = Vec::new();
        too_many_blocks.extend_from_slice(&BLAKE2_SIGNATURE_MAGIC.to_be_bytes());
        too_many_blocks.extend_from_slice(&MIN_BLOCK_BYTES.to_be_bytes());
        too_many_blocks.extend_from_slice(&DEFAULT_STRONG_LEN.to_be_bytes());
        let entries = SEGMENT_BYTES / MIN_BLOCK_BYTES as usize + 1;
        too_many_blocks.resize(12 + entries * (4 + DEFAULT_STRONG_LEN as usize), 0);
        assert!(matches!(
            engine.delta(&too_many_blocks, &new),
            Err(DeltaError::BadSignature(_))
        ));
    }

    /// 51:P1-3 — the engine refuses whole files; callers must segment.
    #[test]
    fn u_rsync_engine_rejects_oversized_segments() {
        let engine = OxideEngine::default();
        let oversized = vec![0u8; SEGMENT_BYTES + 1];
        assert!(matches!(
            engine.signature(&oversized),
            Err(DeltaError::SegmentTooLarge { .. })
        ));
        let signature = engine.signature(&[]).unwrap();
        assert!(matches!(
            engine.delta(&signature, &oversized),
            Err(DeltaError::SegmentTooLarge { .. })
        ));
        assert!(matches!(
            engine.patch(&oversized, &[]),
            Err(DeltaError::SegmentTooLarge { .. })
        ));
    }

    /// 40 §7.2 — an oversized delta is refused before it reaches `apply`.
    #[test]
    fn u_rsync_patch_rejects_oversized_delta() {
        let engine = OxideEngine::default();
        let delta = vec![0u8; engine.policy().max_delta_bytes() + 1];
        assert!(matches!(
            engine.patch(&[], &delta),
            Err(DeltaError::DeltaTooLarge { .. })
        ));
    }
}
