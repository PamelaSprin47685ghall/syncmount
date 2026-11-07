//! Segment planning and per-segment retry/skip.
//!
//! `librsync_oxide` takes whole in-memory slices, so a file is processed as
//! independent [`SEGMENT_BYTES`] windows. Segment offsets are multiples of
//! [`CHUNK_BYTES`] because [`super::engine::SegmentPolicy`] requires
//! `segment_bytes % chunk_bytes == 0`; a chunk therefore never straddles two
//! segments. The last segment may be shorter.
//!
//! Segments are the retry unit (43 §4.6): a failed segment is retried up to
//! [`SegmentRetry::max_attempts`] and then recorded as skipped while the rest
//! of the file continues. Skipping is explicit data, never a silent success.

use std::ops::Range;

use super::engine::{DeltaError, SEGMENT_BYTES, SegmentPolicy};

/// One segment of a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    /// Zero-based segment index.
    pub index: u32,
    /// Byte offset in the file.
    pub offset: u64,
    /// Segment length; the final segment may be shorter than the policy.
    pub len: usize,
}

impl Segment {
    /// One-past-the-end offset.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len as u64)
    }

    /// Half-open byte range.
    #[must_use]
    pub fn range(&self) -> Range<u64> {
        self.offset..self.end()
    }

    /// True when this segment starts on a content-chunk boundary.
    #[must_use]
    pub fn starts_on_chunk(&self, chunk_bytes: usize) -> bool {
        chunk_bytes > 0 && self.offset % chunk_bytes as u64 == 0
    }

    /// Slice `data` at this segment.
    ///
    /// Returns an empty slice when the segment starts beyond `data` and a
    /// truncated slice when `data` ends inside the segment. That is exactly
    /// what a shorter basis needs when the peer's file grew.
    #[must_use]
    pub fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let start = usize::try_from(self.offset).unwrap_or(usize::MAX);
        if start >= data.len() {
            return &[];
        }
        let end = start.saturating_add(self.len).min(data.len());
        &data[start..end]
    }
}

/// The segment layout of one file.
///
/// The v1 4 GiB file ceiling gives at most 256 segments at the default 16 MiB
/// size, so the `u32` index is never a practical limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentPlan {
    total_len: u64,
    segment_bytes: usize,
    segments: Vec<Segment>,
}

impl SegmentPlan {
    /// Plan with the production segment size.
    #[must_use]
    pub fn for_len(total_len: u64) -> Self {
        Self::with_segment_bytes(total_len, SEGMENT_BYTES)
    }

    /// Plan under a validated policy.
    ///
    /// Rejecting an invalid policy here keeps the invariant "every segment
    /// offset is chunk-aligned" true by construction.
    pub fn with_policy(total_len: u64, policy: &SegmentPolicy) -> Result<Self, DeltaError> {
        policy.validate()?;
        Ok(Self::with_segment_bytes(total_len, policy.segment_bytes))
    }

    /// Plan with an explicit segment size.
    ///
    /// Private on purpose: every plan must come from [`SegmentPlan::for_len`]
    /// or [`SegmentPlan::with_policy`], so a chunk-misaligned layout cannot be
    /// constructed by accident.
    fn with_segment_bytes(total_len: u64, segment_bytes: usize) -> Self {
        let segment_bytes = segment_bytes.max(1);
        let count = total_len.div_ceil(segment_bytes as u64);
        // 4 GiB / 16 MiB is 256; the cap only avoids a huge reservation for a
        // deliberately tiny segment size.
        let mut segments = Vec::with_capacity(count.min(1024) as usize);
        let mut offset = 0u64;
        for index in 0..count {
            let remaining = total_len - offset;
            let len = remaining.min(segment_bytes as u64) as usize;
            segments.push(Segment {
                index: index as u32,
                offset,
                len,
            });
            offset += len as u64;
        }
        Self {
            total_len,
            segment_bytes,
            segments,
        }
    }

    /// Segments in file order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Number of segments; zero for an empty file.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// True for an empty file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// One segment by index.
    #[must_use]
    pub fn segment(&self, index: u32) -> Option<&Segment> {
        self.segments.get(index as usize)
    }

    /// Total file length this plan covers.
    #[must_use]
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Segment size used by this plan.
    #[must_use]
    pub fn segment_bytes(&self) -> usize {
        self.segment_bytes
    }

    /// True when every segment starts on a content-chunk boundary.
    #[must_use]
    pub fn is_chunk_aligned(&self, chunk_bytes: usize) -> bool {
        chunk_bytes > 0
            && self
                .segments
                .iter()
                .all(|segment| segment.starts_on_chunk(chunk_bytes))
    }
}

/// How many attempts one segment gets before it is skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentRetry {
    max_attempts: u32,
}

impl SegmentRetry {
    /// Three attempts per segment (43 §4.6 allows three source changes).
    pub const DEFAULT: Self = Self { max_attempts: 3 };

    /// Build a budget; zero is normalised to one attempt.
    #[must_use]
    pub const fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts: if max_attempts == 0 { 1 } else { max_attempts },
        }
    }

    /// Attempts granted to each segment.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

impl Default for SegmentRetry {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One segment that exhausted its retry budget.
#[derive(Debug)]
pub struct SegmentFailure {
    /// Segment index.
    pub index: u32,
    /// Attempts consumed.
    pub attempts: u32,
    /// Last error.
    pub error: DeltaError,
}

/// Result of one [`run_segments`] pass.
#[derive(Debug, Default)]
pub struct SegmentRun {
    /// Segments completed, in file order.
    pub completed: Vec<u32>,
    /// Segments skipped after retries, in file order.
    pub skipped: Vec<SegmentFailure>,
    /// Total attempts across all segments.
    pub attempts: u32,
}

impl SegmentRun {
    /// True when every segment completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty()
    }

    /// Number of completed segments.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Number of skipped segments.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }
}

/// Run `work` for each segment with per-segment retries.
///
/// A segment that still fails is recorded in [`SegmentRun::skipped`] and the
/// next segment is attempted. The caller decides whether a skipped segment
/// triggers a whole-file fallback; this function never hides it.
#[must_use]
pub fn run_segments<F>(plan: &SegmentPlan, retry: SegmentRetry, mut work: F) -> SegmentRun
where
    F: FnMut(&Segment) -> Result<(), DeltaError>,
{
    let mut run = SegmentRun::default();
    for segment in plan.segments() {
        let mut failure = None;
        for attempt in 1..=retry.max_attempts() {
            run.attempts = run.attempts.saturating_add(1);
            match work(segment) {
                Ok(()) => {
                    run.completed.push(segment.index);
                    failure = None;
                    break;
                }
                Err(error) => failure = Some((attempt, error)),
            }
        }
        if let Some((attempts, error)) = failure {
            run.skipped.push(SegmentFailure {
                index: segment.index,
                attempts,
                error,
            });
        }
    }
    run
}

/// Slice `data` at `segment` without panicking on short input.
#[must_use]
pub fn slice_segment<'a>(data: &'a [u8], segment: &Segment) -> &'a [u8] {
    segment.bytes(data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::rsync::OxideEngine;
    use crate::sync::rsync::engine::{CHUNK_BYTES, DeltaEngine};

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

    /// 45:§0.2 C14 — 16 MiB - 1, exactly 16 MiB, 16 MiB + 1, and a short tail
    /// produce the expected segment layout.
    #[test]
    fn u_rsync_segment_plan_boundaries() {
        let empty = SegmentPlan::for_len(0);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.segments().is_empty());

        let under = SegmentPlan::for_len(SEGMENT_BYTES as u64 - 1);
        assert_eq!(under.len(), 1);
        assert_eq!(under.segments()[0].offset, 0);
        assert_eq!(under.segments()[0].len, SEGMENT_BYTES - 1);

        let exact = SegmentPlan::for_len(SEGMENT_BYTES as u64);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact.segments()[0].len, SEGMENT_BYTES);

        let over = SegmentPlan::for_len(SEGMENT_BYTES as u64 + 1);
        assert_eq!(over.len(), 2);
        assert_eq!(over.segments()[0].offset, 0);
        assert_eq!(over.segments()[0].len, SEGMENT_BYTES);
        assert_eq!(over.segments()[1].index, 1);
        assert_eq!(over.segments()[1].offset, SEGMENT_BYTES as u64);
        assert_eq!(over.segments()[1].len, 1);
        assert_eq!(over.segments()[1].end(), SEGMENT_BYTES as u64 + 1);

        let tail = SegmentPlan::for_len(2 * SEGMENT_BYTES as u64 + 123);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail.segments()[2].offset, 2 * SEGMENT_BYTES as u64);
        assert_eq!(tail.segments()[2].len, 123);
        assert_eq!(
            tail.segments()[2].range(),
            2 * SEGMENT_BYTES as u64..2 * SEGMENT_BYTES as u64 + 123
        );
    }

    /// 45:§0.2 C14 — every segment starts on a 256 KiB chunk boundary, so a
    /// content chunk never straddles two segments.
    #[test]
    fn u_rsync_segment_plan_is_chunk_aligned() {
        let plan = SegmentPlan::for_len(5 * SEGMENT_BYTES as u64 + 7);
        assert!(plan.is_chunk_aligned(CHUNK_BYTES));
        assert!(plan.is_chunk_aligned(SEGMENT_BYTES));
        for segment in plan.segments() {
            assert_eq!(segment.offset % CHUNK_BYTES as u64, 0);
            assert!(segment.len <= SEGMENT_BYTES);
        }
        assert!(!plan.is_chunk_aligned(0));
    }

    /// 45:§0.2 C14 — a policy that does not divide into chunks is rejected by
    /// the planner, not silently rounded.
    #[test]
    fn u_rsync_segment_plan_rejects_bad_policy() {
        let policy = SegmentPolicy {
            segment_bytes: SEGMENT_BYTES - 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            SegmentPlan::with_policy(1024, &policy),
            Err(DeltaError::Policy(_))
        ));
    }

    /// 45:§0.2 C14 — a shorter basis yields empty or truncated slices.
    #[test]
    fn u_rsync_segment_slice_handles_short_basis() {
        let plan = SegmentPlan::for_len(2 * SEGMENT_BYTES as u64);
        let basis = vec![1u8; SEGMENT_BYTES + 10];
        assert_eq!(plan.segments()[0].bytes(&basis).len(), SEGMENT_BYTES);
        assert_eq!(plan.segments()[1].bytes(&basis).len(), 10);
        let empty: &[u8] = &[];
        assert!(plan.segments()[0].bytes(empty).is_empty());
    }

    /// 43 §4.6 — retries are per segment; exhaustion skips only that segment.
    #[test]
    fn u_rsync_segment_retry_retries_then_skips() {
        let plan = SegmentPlan::for_len(3 * SEGMENT_BYTES as u64);
        let mut seen = [0u32; 3];
        let run = run_segments(&plan, SegmentRetry::new(3), |segment| {
            let attempt = &mut seen[segment.index as usize];
            *attempt += 1;
            match segment.index {
                0 => Err(DeltaError::Policy("permanent")),
                1 if *attempt < 2 => Err(DeltaError::Policy("transient")),
                _ => Ok(()),
            }
        });
        assert_eq!(seen, [3, 2, 1]);
        assert_eq!(run.attempts, 6);
        assert_eq!(run.completed, vec![1, 2]);
        assert_eq!(run.skipped.len(), 1);
        assert_eq!(run.skipped[0].index, 0);
        assert_eq!(run.skipped[0].attempts, 3);
        assert!(!run.is_complete());
    }

    /// 43 §4.6 — an empty file has nothing to retry.
    #[test]
    fn u_rsync_segment_run_empty_plan() {
        let plan = SegmentPlan::for_len(0);
        let run = run_segments(&plan, SegmentRetry::DEFAULT, |_| Ok(()));
        assert!(run.is_complete());
        assert_eq!(run.attempts, 0);
        assert_eq!(run.completed_count(), 0);
        assert_eq!(SegmentRetry::DEFAULT.max_attempts(), 3);
        assert_eq!(SegmentRetry::new(0).max_attempts(), 1);
        assert_eq!(SegmentRetry::new(7).max_attempts(), 7);
    }

    /// 31:M3-7, 45:§0.2 C14 — full segmented sig->delta->patch round-trip at
    /// 16 MiB - 1, 16 MiB, and 16 MiB + 1, including the one-byte tail.
    #[test]
    fn u_rsync_segmented_roundtrip_at_boundaries() {
        for len in [0usize, SEGMENT_BYTES - 1, SEGMENT_BYTES, SEGMENT_BYTES + 1] {
            let basis = noise(len, 0x61 + len as u64);
            let mut new = basis.clone();
            if let Some(last) = new.last_mut() {
                *last ^= 0xff;
            }
            let policy = SegmentPolicy::for_file_size(new.len() as u64);
            let engine = OxideEngine::new(policy);
            let plan = SegmentPlan::with_policy(new.len() as u64, &policy).unwrap();
            let mut assembled = Vec::with_capacity(new.len());
            let mut delta_bytes = 0usize;
            for segment in plan.segments() {
                let basis_segment = segment.bytes(&basis);
                let new_segment = segment.bytes(&new);
                let signature = engine.signature(basis_segment).unwrap();
                let delta = engine.delta(&signature, new_segment).unwrap();
                delta_bytes += delta.len();
                let patched = engine.patch(basis_segment, &delta).unwrap();
                assert_eq!(patched, new_segment, "len={len} segment={}", segment.index);
                assembled.extend_from_slice(&patched);
            }
            assert_eq!(assembled, new, "len={len}");
            if len > 0 {
                assert!(delta_bytes < 128 * 1024, "len={len} delta={delta_bytes}");
                assert!(
                    delta_bytes * 100 < new.len(),
                    "len={len} delta={delta_bytes}"
                );
            } else {
                assert_eq!(delta_bytes, 0);
            }
        }
    }
}
