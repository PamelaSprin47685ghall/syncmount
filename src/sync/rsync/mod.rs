//! rsync delta engine (W15).
//!
//! The only path is the one fixed by 49 A2:
//!
//! 1. the joiner computes a [`DeltaEngine::signature`] over each local basis
//!    segment;
//! 2. the peer computes a [`DeltaEngine::delta`] against the authoritative new
//!    segment;
//! 3. the joiner [`DeltaEngine::patch`]es its basis and verifies the result
//!    with `file_root`.
//!
//! Files are split by [`SegmentPlan`] into 16 MiB windows aligned to 256 KiB
//! content chunks ([`SEGMENT_BYTES`], [`CHUNK_BYTES`]). Each window is an
//! independent retry unit; [`run_segments`] records skipped segments instead
//! of hiding them. The engine never touches a manifest, a file, or a socket:
//! inputs are `&[u8]` and outputs are owned buffers or [`std::io::Write`]
//! sinks, so the whole module is unit-testable on its own.
//!
//! [`OxideEngine`] is the sole backend (`librsync_oxide` 0.3.0, pure Rust,
//! Apache-2.0). The trait exists for test doubles and for the boundary W14 and
//! W16 consume; it is not a backend-selection knob.

pub mod bridge;
pub mod engine;
pub mod oxide;
pub mod segment;

pub use bridge::EngineBridge;
pub use engine::{
    CHUNK_BYTES, DEFAULT_STRONG_LEN, DeltaEngine, DeltaError, MAX_BLOCK_BYTES, MAX_STRONG_LEN,
    MIN_BLOCK_BYTES, PEAK_PER_WORKER, SEGMENT_BYTES, SEGMENT_CHUNKS, SegmentPolicy, block_size_for,
    signature_bound,
};
pub use oxide::{BLAKE2_SIGNATURE_MAGIC, DELTA_MAGIC, OxideEngine};
pub use segment::{
    Segment, SegmentFailure, SegmentPlan, SegmentRetry, SegmentRun, run_segments, slice_segment,
};
