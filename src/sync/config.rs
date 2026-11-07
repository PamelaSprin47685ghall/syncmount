//! Every synchronisation constant and threshold (43 appendix B).
//!
//! Owner: W14 (E7). This file is the single source for the numbers the rest of
//! `sync` uses; a magic number anywhere else is a bug. The values come from
//! `39-s1-spec.md` and `43-sync-skeleton.md` appendix B, except where a later
//! decision replaced them (43 appendix A).
//!
//! Sizes are plain bytes, not "KiB" strings, so a unit mistake fails the
//! compile-time assertions at the bottom of the file instead of the network.

use std::time::Duration;

/// Sequence interval between snapshot generations (`SNAPSHOT_INTERVAL`).
pub const SNAPSHOT_INTERVAL: u64 = 4096;

/// Snapshot part plaintext size, including the part header.
pub const SNAPSHOT_PART: usize = 1024 * 1024;

/// Content chunk plaintext size: storage, addressing and resume unit.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// Chunks in one full part. The last chunk of the last part may be shorter.
pub const CHUNKS_PER_PART: usize = SNAPSHOT_PART / CHUNK_BYTES;

/// Version byte written into every snapshot and manifest container.
pub const FORMAT_VER: u8 = 1;

/// Magic for the snapshot index part (`part 0`).
pub const SNAPSHOT_INDEX_MAGIC: [u8; 4] = *b"SMSP";
/// Magic for a snapshot data part.
pub const SNAPSHOT_DATA_MAGIC: [u8; 4] = *b"SMSD";
/// Magic for a manifest data part.
pub const MANIFEST_PART_MAGIC: [u8; 4] = *b"SMMF";
/// Magic for a blockmap data part.
pub const BLOCKMAP_PART_MAGIC: [u8; 4] = *b"SMBM";
/// Magic for the local manifest cache file.
pub const LOCAL_MANIFEST_MAGIC: [u8; 4] = *b"SMMC";
/// Magic for the manifest reference control payload.
pub const MANIFEST_REF_MAGIC: [u8; 4] = *b"SMMR";
/// Magic for the blockmap index reference control payload.
pub const BLOCKMAP_REF_MAGIC: [u8; 4] = *b"SMIR";
/// Magic for the blockmap index container.
pub const BLOCKMAP_INDEX_MAGIC: [u8; 4] = *b"SMBI";

/// Common part header: magic, version, covered sequence, part index, payload
/// length.
pub const PART_HEADER_LEN: usize = 4 + 1 + 8 + 4 + 4;

/// Payload bytes available in a full part after its header.
pub const PART_PAYLOAD: usize = SNAPSHOT_PART - PART_HEADER_LEN;

/// `ChunkId` width.
pub const CHUNK_ID_LEN: usize = 32;

/// Blockmap identifiers per full part.
pub const BLOCKMAP_IDS_PER_PART: usize = PART_PAYLOAD / CHUNK_ID_LEN;

/// Snapshot generation grant deadline (`GRANT_DEADLINE`).
pub const GRANT_DEADLINE: Duration = Duration::from_secs(30);

/// Cluster-wide `SNAPSHOT_NOW` rate limit (`SNAPSHOT_NOW_RATE`).
pub const SNAPSHOT_NOW_RATE: Duration = Duration::from_secs(60);

/// Snapshots kept per client (`SNAPSHOT_KEEP`).
pub const SNAPSHOT_KEEP: usize = 2;

/// Snapshot parts in flight (`PART_WINDOW`).
pub const PART_WINDOW: usize = 4;

/// Content chunks in flight (`CHUNK_WINDOW`).
pub const CHUNK_WINDOW: usize = 16;

/// Peer switches before a file becomes `unavailable` (`PEER_RETRY`).
pub const PEER_RETRY: u32 = 3;

/// Cooldown after a peer keeps missing (`PEER_COOLDOWN`).
pub const PEER_COOLDOWN: Duration = Duration::from_secs(60);

/// Manifest refetch rounds for one path (`MANIFEST_RETRY`).
pub const MANIFEST_RETRY: u32 = 3;

/// Baseline samples compared against the cached manifest (`§7.1`).
pub const BASELINE_SAMPLE: usize = 1024;

/// Rsync segment size: 16 MiB, a multiple of [`CHUNK_BYTES`] (43 §4.3).
pub const RSYNC_SEGMENT: u64 = 16 * 1024 * 1024;

/// Files smaller than this skip rsync and use whole-chunk transfer.
pub const RSYNC_SKIP_BELOW: u64 = 64 * 1024;

/// Upper bound on the part descriptors carried by one control payload.
///
/// The reference must fit a single frame after encryption; 4096 descriptors
/// are 544 KiB, well past any v1 frame, so the real limit is the frame size.
/// This constant is the *container* guard that turns an oversized tree into a
/// clear error instead of a silently truncated manifest.
pub const MAX_REF_PARTS: u32 = 512;

/// Largest path, in bytes, that a manifest entry may carry.
pub const MAX_PATH_BYTES: usize = 4096;

/// Tuning knobs that tests may shrink.
///
/// Windows are clamped to at least one where they are used, so a zero value is
/// total rather than a panic. Everything here is a *policy* number; protocol
/// sizes above are not tunable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    /// Snapshot parts fetched concurrently.
    pub part_window: usize,
    /// Content chunks fetched concurrently.
    pub chunk_window: usize,
    /// Peer switches before a chunk is declared unavailable.
    pub peer_retry: u32,
    /// Manifest refetch rounds for one path.
    pub manifest_retry: u32,
    /// How long a granted generator may take.
    pub grant_deadline: Duration,
    /// Snapshots retained locally.
    pub keep_snapshots: usize,
    /// Entries compared when classifying a cached manifest.
    pub baseline_sample: usize,
}

impl SyncConfig {
    /// The production configuration.
    pub const fn new() -> Self {
        Self {
            part_window: PART_WINDOW,
            chunk_window: CHUNK_WINDOW,
            peer_retry: PEER_RETRY,
            manifest_retry: MANIFEST_RETRY,
            grant_deadline: GRANT_DEADLINE,
            keep_snapshots: SNAPSHOT_KEEP,
            baseline_sample: BASELINE_SAMPLE,
        }
    }

    /// Effective part window; never zero.
    pub const fn part_window(&self) -> usize {
        if self.part_window == 0 {
            1
        } else {
            self.part_window
        }
    }

    /// Effective chunk window; never zero.
    pub const fn chunk_window(&self) -> usize {
        if self.chunk_window == 0 {
            1
        } else {
            self.chunk_window
        }
    }

    /// Effective baseline sample count; never zero.
    pub const fn baseline_sample(&self) -> usize {
        if self.baseline_sample == 0 {
            1
        } else {
            self.baseline_sample
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time checks: a unit slip in any size breaks the build, not a test.
const _: () = assert!(SNAPSHOT_PART == 4 * CHUNK_BYTES);
const _: () = assert!(CHUNKS_PER_PART == 4);
const _: () = assert!(PART_PAYLOAD > 0);
const _: () = assert!(BLOCKMAP_IDS_PER_PART > 0);
const _: () = assert!(RSYNC_SEGMENT % CHUNK_BYTES as u64 == 0);
const _: () = assert!(RSYNC_SEGMENT / CHUNK_BYTES as u64 == 64);

#[cfg(test)]
mod tests {
    use super::*;

    /// 43 appendix B: the chunk/part relationship is exact.
    #[test]
    fn u_config_part_is_four_chunks() {
        assert_eq!(CHUNK_BYTES * CHUNKS_PER_PART, SNAPSHOT_PART);
        assert_eq!(PART_HEADER_LEN, 21);
        assert_eq!(PART_PAYLOAD, SNAPSHOT_PART - 21);
    }

    /// 43 §4.3: a 16 MiB segment holds exactly 64 chunks.
    #[test]
    fn u_config_segment_aligns_to_chunk() {
        assert_eq!(RSYNC_SEGMENT / CHUNK_BYTES as u64, 64);
        assert_eq!(RSYNC_SEGMENT % CHUNK_BYTES as u64, 0);
    }

    /// A zero window is total, not a panic.
    #[test]
    fn u_config_zero_windows_clamp() {
        let config = SyncConfig {
            part_window: 0,
            chunk_window: 0,
            baseline_sample: 0,
            ..SyncConfig::new()
        };
        assert_eq!(config.part_window(), 1);
        assert_eq!(config.chunk_window(), 1);
        assert_eq!(config.baseline_sample(), 1);
    }
}
