//! Standard rsync block engine with BLAKE3-128 block confirmation.
//!
//! The engine is backend-neutral. It never touches a manifest, a socket, or a
//! database. Inputs are readers or byte slices; outputs are instructions or
//! bytes.
//!
//! # Pieces
//!
//! * [`engine`] — policy, block-size formula, segment bounds, errors.
//! * [`weak`] — standard rsync rolling 16+16-bit checksum (`CHAR_OFFSET = 0`).
//! * [`strong`] — BLAKE3-128 block hashes and BLAKE3-256 file hashes.
//! * [`signature`] — streaming signer and the validated signature format.
//! * [`instruction`] — COPY / LITERAL / UNCHANGED / END_FILE / END_BATCH.
//! * [`delta`] — rolling search over a slice or a reader.
//! * [`apply`] — bounded reconstruction with per-COPY strong verification.
//! * [`segment`] — 4 MiB segment plan and per-segment retry.
//! * [`skip`] — file-level skip rules; only `size + file_root` can skip.
//! * [`verify`] — whole-file BLAKE3-256 check.
//! * [`bridge`] — `spawn_blocking` wrapper for async callers.
//!
//! # Invariants
//!
//! 1. A weak hit never becomes a COPY until BLAKE3-128 matches.
//! 2. A COPY is checked against the base bytes again during [`apply`], so a
//!    stale signature fails closed.
//! 3. The file-level skip authority is `size + file_root`. A weak checksum can
//!    only reject a file; it can never prove that a file is unchanged.
//! 4. `sign` and `delta_to` read in bounded buffers. `delta` and `apply` are
//!    convenience paths for one segment.

pub mod apply;
pub mod bridge;
pub mod delta;
pub mod engine;
pub mod instruction;
pub mod segment;
pub mod signature;
pub mod skip;
pub mod strong;
pub mod verify;
pub mod weak;

pub use apply::{apply, apply_exact, apply_file, apply_file_exact, apply_file_to, apply_to};
pub use bridge::EngineBridge;
pub use delta::{DeltaStats, delta, delta_to, delta_with_policy};
pub use engine::{
    CHUNK_BYTES, DEFAULT_STRONG_LEN, FilePlan, FilePlanKind, FullReason, LITERAL_CHUNK_BYTES,
    MAX_APPLY_BYTES, MAX_BLOCK_BYTES, MAX_BLOCKS, MAX_SEGMENTS, MAX_STRONG_LEN, MIN_BLOCK_BYTES,
    PEAK_PER_WORKER, RsyncError, SEGMENT_BYTES, SEGMENT_CHUNKS, SegmentPolicy, block_count_for,
    block_size_for, signature_bound,
};
pub use instruction::{
    INSTRUCTION_HEADER_BYTES, INSTRUCTION_MAGIC, INSTRUCTION_VERSION, Instruction, decode_from,
    encode_to,
};
pub use segment::{
    Segment, SegmentFailure, SegmentPlan, SegmentRetry, SegmentRun, run_segments, slice_segment,
};
pub use signature::{
    BlockSignature, SIGNATURE_ENTRY_BYTES, SIGNATURE_HEADER_BYTES, SIGNATURE_MAGIC,
    SIGNATURE_VERSION, Signature, sign, sign_limited, sign_segment,
};
pub use skip::{FileIdentity, SkipDecision, WeakVerdict, skip_decision, weak_verdict};
pub use strong::{Hash256, STRONG_LEN, StrongHash, file_hash, file_hash_reader, strong128};
pub use verify::{hash_reader, verify, verify_reader};
pub use weak::{WeakState, weak};
