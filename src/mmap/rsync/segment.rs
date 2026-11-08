//! Segment planning and per-segment retry.
//!
//! A file is split into [`SEGMENT_BYTES`] windows. Every window starts on a
//! [`CHUNK_BYTES`] boundary, so a content chunk never straddles two windows.
//! The final window may be shorter.
//!
//! A segment is the retry unit. When a segment exhausts its retry budget,
//! [`run_segments`] stops. The caller must fall back to FULL for the whole
//! file; it must not treat the remaining segments as complete.

use std::ops::Range;

use super::engine::{MAX_SEGMENTS, RsyncError, SEGMENT_BYTES, SegmentPolicy};

/// One segment of a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    /// Zero-based segment index.
    pub index: u32,
    /// Byte offset in the file.
    pub offset: u64,
    /// Segment length. The final segment may be shorter.
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
    /// A segment beyond `data` yields an empty slice. A segment that extends
    /// past `data` yields the available prefix. That is what a shorter basis
    /// needs when the peer's file grew.
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
        debug_assert!(
            total_len.div_ceil(SEGMENT_BYTES as u64) <= MAX_SEGMENTS,
            "use try_for_len for untrusted sizes"
        );
        Self::with_segment_bytes(total_len, SEGMENT_BYTES)
    }

    /// Plan with the production segment size, rejecting absurd lengths.
    pub fn try_for_len(total_len: u64) -> Result<Self, RsyncError> {
        let count = total_len.div_ceil(SEGMENT_BYTES as u64);
        if count > MAX_SEGMENTS {
            return Err(RsyncError::SegmentTooLarge {
                len: total_len,
                max: MAX_SEGMENTS.saturating_mul(SEGMENT_BYTES as u64),
            });
        }
        Ok(Self::with_segment_bytes(total_len, SEGMENT_BYTES))
    }

    /// Plan under a validated policy.
    pub fn with_policy(total_len: u64, policy: &SegmentPolicy) -> Result<Self, RsyncError> {
        policy.validate()?;
        let count = total_len.div_ceil(policy.segment_bytes as u64);
        if count > MAX_SEGMENTS {
            return Err(RsyncError::SegmentTooLarge {
                len: total_len,
                max: MAX_SEGMENTS.saturating_mul(policy.segment_bytes as u64),
            });
        }
        Ok(Self::with_segment_bytes(total_len, policy.segment_bytes))
    }

    fn with_segment_bytes(total_len: u64, segment_bytes: usize) -> Self {
        let segment_bytes = segment_bytes.max(1);
        let count = total_len.div_ceil(segment_bytes as u64);
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

    /// Number of segments. Zero for an empty file.
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

/// How many attempts one segment gets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentRetry {
    max_attempts: u32,
}

impl SegmentRetry {
    /// Three attempts per segment.
    pub const DEFAULT: Self = Self { max_attempts: 3 };

    /// Build a budget. Zero is normalised to one attempt.
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
    pub error: RsyncError,
}

/// Result of one [`run_segments`] pass.
#[derive(Debug, Default)]
pub struct SegmentRun {
    /// Segments completed, in file order.
    pub completed: Vec<u32>,
    /// First segment that exhausted its budget, if any.
    pub failed: Option<SegmentFailure>,
    /// Total attempts across all segments.
    pub attempts: u32,
}

impl SegmentRun {
    /// True when every segment completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failed.is_none()
    }

    /// Number of completed segments.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}

/// Run `work` for each segment with per-segment retries.
///
/// The first segment that exhausts its budget stops the pass. The caller must
/// fall back to FULL; later segments were not attempted.
#[must_use]
pub fn run_segments<F>(plan: &SegmentPlan, retry: SegmentRetry, mut work: F) -> SegmentRun
where
    F: FnMut(&Segment) -> Result<(), RsyncError>,
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
            run.failed = Some(SegmentFailure {
                index: segment.index,
                attempts,
                error,
            });
            break;
        }
    }
    run
}

/// Slice `data` at `segment` without panicking on short input.
#[must_use]
pub fn slice_segment<'a>(data: &'a [u8], segment: &Segment) -> &'a [u8] {
    segment.bytes(data)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::rsync::engine::{CHUNK_BYTES, SEGMENT_BYTES};

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
    fn u_rsync_segment_plan_boundaries() {
        let plan = SegmentPlan::for_len(0);
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);

        let plan = SegmentPlan::for_len(SEGMENT_BYTES as u64);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.segment(0).unwrap().offset, 0);
        assert_eq!(plan.segment(0).unwrap().len, SEGMENT_BYTES);

        let plan = SegmentPlan::for_len(SEGMENT_BYTES as u64 + 1);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.segment(1).unwrap().offset, SEGMENT_BYTES as u64);
        assert_eq!(plan.segment(1).unwrap().len, 1);

        let plan = SegmentPlan::for_len(4 * 1024 * 1024 * 1024);
        assert_eq!(plan.len(), 1024);
        assert_eq!(plan.segment(1023).unwrap().end(), 4 * 1024 * 1024 * 1024);
        assert!(plan.is_chunk_aligned(CHUNK_BYTES));
        assert!(
            plan.segments()
                .iter()
                .all(|segment| segment.starts_on_chunk(CHUNK_BYTES))
        );
    }

    #[test]
    fn u_rsync_segment_plan_rejects_bad_policy() {
        let policy = SegmentPolicy {
            segment_bytes: SEGMENT_BYTES - 1,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            SegmentPlan::with_policy(10, &policy),
            Err(RsyncError::Policy(_))
        ));
    }

    #[test]
    fn u_rsync_segment_plan_rejects_absurd_length() {
        assert!(matches!(
            SegmentPlan::try_for_len(u64::MAX),
            Err(RsyncError::SegmentTooLarge { .. })
        ));
        assert!(SegmentPlan::try_for_len(4 * 1024 * 1024 * 1024).is_ok());
    }

    #[test]
    fn u_rsync_segment_bytes_short_input() {
        let segment = Segment {
            index: 0,
            offset: 10,
            len: 100,
        };
        assert_eq!(segment.bytes(&[0u8; 50]).len(), 40);
        assert_eq!(segment.bytes(&[0u8; 5]).len(), 0);
        assert_eq!(segment.range(), 10..110);
        assert_eq!(slice_segment(&[0u8; 200], &segment).len(), 100);
    }

    #[test]
    fn u_rsync_segment_retry_normalises_zero() {
        assert_eq!(SegmentRetry::new(0).max_attempts(), 1);
        assert_eq!(SegmentRetry::new(3).max_attempts(), 3);
        assert_eq!(SegmentRetry::DEFAULT.max_attempts(), 3);
    }

    #[test]
    fn u_rsync_run_segments_retries_transient_failure() {
        let plan = SegmentPlan::for_len(3 * SEGMENT_BYTES as u64);
        let mut calls = 0;
        let run = run_segments(&plan, SegmentRetry::new(3), |segment| {
            calls += 1;
            if segment.index == 0 && calls == 1 {
                return Err(RsyncError::Policy("transient"));
            }
            Ok(())
        });
        assert!(run.is_complete());
        assert_eq!(run.completed, vec![0, 1, 2]);
        assert_eq!(run.attempts, 4);
    }

    #[test]
    fn u_rsync_run_segments_stops_on_permanent_failure() {
        let plan = SegmentPlan::for_len(3 * SEGMENT_BYTES as u64);
        let mut attempted = Vec::new();
        let run = run_segments(&plan, SegmentRetry::new(2), |segment| {
            attempted.push(segment.index);
            if segment.index == 1 {
                return Err(RsyncError::Policy("permanent"));
            }
            Ok(())
        });
        assert!(!run.is_complete());
        assert_eq!(run.completed, vec![0]);
        assert_eq!(run.failed.as_ref().unwrap().index, 1);
        assert_eq!(run.failed.as_ref().unwrap().attempts, 2);
        assert_eq!(attempted, vec![0, 1, 1]);
    }

    #[test]
    fn u_rsync_multi_segment_roundtrip() {
        use crate::mmap::rsync::{apply, delta, sign};
        use std::io::Cursor;

        let basis = noise(2 * SEGMENT_BYTES + 12_345, 0x61);
        let mut new = basis.clone();
        new[SEGMENT_BYTES + 100] ^= 0x5a;
        let plan = SegmentPlan::for_len(new.len() as u64);
        assert_eq!(plan.len(), 3);

        let mut rebuilt = Vec::with_capacity(new.len());
        for segment in plan.segments() {
            let base_slice = segment.bytes(&basis);
            let new_slice = segment.bytes(&new);
            let signature = sign(Cursor::new(base_slice), 2048).unwrap();
            let instructions = delta(new_slice, &signature).unwrap();
            let patched = apply(base_slice, &instructions).unwrap();
            assert_eq!(patched, new_slice, "segment={}", segment.index);
            rebuilt.extend_from_slice(&patched);
        }
        assert_eq!(rebuilt, new);
    }

    #[test]
    fn u_rsync_multi_segment_insert_roundtrip() {
        use crate::mmap::rsync::{apply, delta, sign};
        use std::io::Cursor;

        let basis = noise(2 * SEGMENT_BYTES, 0x62);
        let mut new = Vec::with_capacity(basis.len() + 1);
        new.push(0xab);
        new.extend_from_slice(&basis);
        let plan = SegmentPlan::for_len(new.len() as u64);

        let mut rebuilt = Vec::with_capacity(new.len());
        for segment in plan.segments() {
            let base_slice = segment.bytes(&basis);
            let new_slice = segment.bytes(&new);
            let signature = sign(Cursor::new(base_slice), 2048).unwrap();
            let instructions = delta(new_slice, &signature).unwrap();
            let patched = apply(base_slice, &instructions).unwrap();
            assert_eq!(patched, new_slice, "segment={}", segment.index);
            rebuilt.extend_from_slice(&patched);
        }
        assert_eq!(rebuilt, new);
    }
}
