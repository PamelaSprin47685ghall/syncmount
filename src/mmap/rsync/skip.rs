//! File-level skip rules.
//!
//! `size` and `file_root` are the only authority for "unchanged". A weak
//! checksum can reject a file (different checksum means changed), but a weak
//! hit proves nothing and must never skip a file.

use super::strong::Hash256;

/// The two authoritative file-level values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    /// File size in bytes.
    pub size: u64,
    /// 1.0-compatible `file_root` (BLAKE3-256 Merkle root).
    pub file_root: Hash256,
}

impl FileIdentity {
    /// True when size and file_root both match.
    #[must_use]
    pub fn unchanged(&self, other: &Self) -> bool {
        self.size == other.size && self.file_root == other.file_root
    }
}

/// Result of the authoritative file-level comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipDecision {
    /// Size and file_root match. The file can be skipped.
    Unchanged,
    /// At least one authoritative value differs.
    Changed,
}

/// Decide whether a file can be skipped.
#[must_use]
pub fn skip_decision(base: &FileIdentity, local: &FileIdentity) -> SkipDecision {
    if base.unchanged(local) {
        SkipDecision::Unchanged
    } else {
        SkipDecision::Changed
    }
}

/// What a weak checksum comparison proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeakVerdict {
    /// The checksums differ, so the file is definitely changed.
    Changed,
    /// The checksums match, but this proves nothing. Use `size + file_root`.
    Inconclusive,
}

/// Negative filter for a weak file-level checksum.
#[must_use]
pub fn weak_verdict(base_weak: u32, local_weak: u32) -> WeakVerdict {
    if base_weak == local_weak {
        WeakVerdict::Inconclusive
    } else {
        WeakVerdict::Changed
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn identity(size: u64, root: u8) -> FileIdentity {
        FileIdentity {
            size,
            file_root: [root; 32],
        }
    }

    #[test]
    fn u_rsync_skip_requires_size_and_file_root() {
        let base = identity(100, 1);
        assert_eq!(
            skip_decision(&base, &identity(100, 1)),
            SkipDecision::Unchanged
        );
        assert_eq!(
            skip_decision(&base, &identity(100, 2)),
            SkipDecision::Changed
        );
        assert_eq!(
            skip_decision(&base, &identity(101, 1)),
            SkipDecision::Changed
        );
    }

    #[test]
    fn u_rsync_weak_is_only_negative() {
        assert_eq!(weak_verdict(7, 8), WeakVerdict::Changed);
        assert_eq!(weak_verdict(7, 7), WeakVerdict::Inconclusive);
        assert_eq!(weak_verdict(0, 0), WeakVerdict::Inconclusive);
    }
}
