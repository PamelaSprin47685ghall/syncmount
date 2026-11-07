//! Status file, counters and the connection trace ring.
//!
//! Owner: W11 (E5). See 41 §2.8, 27 §4 and 53 W11.
//!
//! The client publishes one JSON document every five seconds through
//! [`RuntimeDir::write_status`], which replaces it atomically (write, `fsync`,
//! `rename`, `fsync` the directory). A reader therefore sees either the
//! previous complete document or the new one.
//!
//! Two rules shape the document:
//!
//! * paths never appear in clear text — only an eight-hex prefix of their
//!   BLAKE3 hash, matching the log convention (27 §3);
//! * keys, ciphertext and session secrets never appear at all.
//!
//! The module is passive: it neither spawns a task nor opens a socket. W12
//! drives [`StatusWriter::write`] on the status interval.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Serialize;

use crate::client::writer::OutboxDepth;
use crate::protocol::frame::Seq;
use crate::store::Errno;
use crate::store::runtime_dir::RuntimeDir;

/// Schema version of the status document.
pub const STATUS_SCHEMA: u32 = 1;
/// Entries kept by the connection trace ring.
pub const CONNTRACE_CAPACITY: usize = 256;
/// Prefix length of a hashed path, in hex characters.
pub const PATH_HASH_PREFIX: usize = 8;

/// Eight-hex prefix of `BLAKE3(path)`.
///
/// The status file and the logs correlate events through this value; the
/// plaintext path never leaves the process.
pub fn path_hash_prefix(path: &str) -> String {
    let hash = blake3::hash(path.as_bytes());
    let hex = hash.to_hex();
    hex.as_str()[..PATH_HASH_PREFIX].to_owned()
}

/// One counter set, shared by every task.
#[derive(Debug, Default)]
pub struct Counters {
    /// Operations applied to `S`.
    pub ops_applied: AtomicU64,
    /// Operations the total order refused.
    pub ops_rejected: AtomicU64,
    /// Duplicate frames dropped.
    pub ops_duplicate: AtomicU64,
    /// Payload bytes written to the backing tree.
    pub bytes_written: AtomicU64,
    /// Frames read from the downlink.
    pub frames_in: AtomicU64,
    /// Frames written to the uplink.
    pub frames_out: AtomicU64,
    /// Resyncs started.
    pub resyncs: AtomicU64,
    /// Uplink losses detected.
    pub uplink_lost: AtomicU64,
    /// Materialize failures.
    pub materialize_errors: AtomicU64,
    /// Block misses served from a peer.
    pub block_misses: AtomicU64,
    /// Waiters released by an unmount.
    pub waiters_dropped: AtomicU64,
}

impl Counters {
    /// Snapshot every counter.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            ops_applied: self.ops_applied.load(Ordering::Relaxed),
            ops_rejected: self.ops_rejected.load(Ordering::Relaxed),
            ops_duplicate: self.ops_duplicate.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            frames_in: self.frames_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            resyncs: self.resyncs.load(Ordering::Relaxed),
            uplink_lost: self.uplink_lost.load(Ordering::Relaxed),
            materialize_errors: self.materialize_errors.load(Ordering::Relaxed),
            block_misses: self.block_misses.load(Ordering::Relaxed),
            waiters_dropped: self.waiters_dropped.load(Ordering::Relaxed),
        }
    }

    /// Increment one counter by one.
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to one counter.
    pub fn add(counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

/// A plain snapshot of [`Counters`], ready for serialization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CounterSnapshot {
    /// Operations applied.
    pub ops_applied: u64,
    /// Operations rejected by the total order.
    pub ops_rejected: u64,
    /// Duplicate frames.
    pub ops_duplicate: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Frames received.
    pub frames_in: u64,
    /// Frames sent.
    pub frames_out: u64,
    /// Resyncs.
    pub resyncs: u64,
    /// Uplink losses.
    pub uplink_lost: u64,
    /// Materialize failures.
    pub materialize_errors: u64,
    /// Block misses.
    pub block_misses: u64,
    /// Waiters dropped at unmount.
    pub waiters_dropped: u64,
}

/// One connection-trace entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceEntry {
    /// Wall-clock time, microseconds since the Unix epoch.
    pub at_us: i64,
    /// `"in"` or `"out"`.
    pub dir: String,
    /// Frame type name.
    pub kind: String,
    /// Frame body length.
    pub bytes: u32,
    /// Sequence number, zero when unsequenced.
    pub seq: u64,
}

impl TraceEntry {
    /// Build an entry.
    pub fn new(
        at_us: i64,
        dir: impl Into<String>,
        kind: impl Into<String>,
        bytes: u32,
        seq: Seq,
    ) -> Self {
        Self {
            at_us,
            dir: dir.into(),
            kind: kind.into(),
            bytes,
            seq: seq.get(),
        }
    }
}

/// Bounded ring of the most recent frames.
#[derive(Debug)]
pub struct Conntrace {
    entries: Mutex<VecDeque<TraceEntry>>,
    capacity: usize,
}

impl Default for Conntrace {
    fn default() -> Self {
        Self::new(CONNTRACE_CAPACITY)
    }
}

impl Conntrace {
    /// Build a ring holding at most `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
        }
    }

    /// Record one entry, dropping the oldest when full.
    pub fn record(&self, entry: TraceEntry) {
        let mut entries = self.lock();
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Copy the ring in arrival order.
    pub fn snapshot(&self) -> Vec<TraceEntry> {
        self.lock().iter().cloned().collect()
    }

    /// Number of retained entries.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Configured capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drop every entry.
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<TraceEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Occupancy of the outbox, as rendered in the status document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OutboxStatus {
    /// Reserved operations.
    pub ops: u64,
    /// Reserved bytes.
    pub bytes: u64,
}

impl From<OutboxDepth> for OutboxStatus {
    fn from(depth: OutboxDepth) -> Self {
        Self {
            ops: depth.ops as u64,
            bytes: depth.bytes as u64,
        }
    }
}

/// Replay-side occupancy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReplayStatus {
    /// Pending optimistic effects.
    pub pending: u64,
    /// Frames waiting behind a hole.
    pub reorder: u64,
    /// Dedup entries.
    pub dedup: u64,
    /// Resyncs in the current run.
    pub resyncs: u32,
    /// Whether an unknown operation class was seen.
    pub diverged: bool,
}

/// One complete status document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatusSnapshot {
    /// Schema version.
    pub schema: u32,
    /// Stable mount identifier.
    pub mount_id: String,
    /// Lifecycle state name (`STEADY`, `JOINING`, …).
    pub state: String,
    /// Honest watermark.
    pub applied_seq: u64,
    /// Session epoch.
    pub epoch: u64,
    /// Outbox occupancy.
    pub outbox: OutboxStatus,
    /// Replay occupancy.
    pub replay: ReplayStatus,
    /// Counters.
    pub counters: CounterSnapshot,
    /// Recent frames.
    pub conntrace: Vec<TraceEntry>,
}

impl StatusSnapshot {
    /// Build the fixed part of a document.
    pub fn new(
        mount_id: impl Into<String>,
        state: impl Into<String>,
        applied: Seq,
        epoch: u64,
    ) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            mount_id: mount_id.into(),
            state: state.into(),
            applied_seq: applied.get(),
            epoch,
            outbox: OutboxStatus::default(),
            replay: ReplayStatus::default(),
            counters: CounterSnapshot::default(),
            conntrace: Vec::new(),
        }
    }

    /// Attach outbox occupancy.
    pub fn with_outbox(mut self, outbox: OutboxStatus) -> Self {
        self.outbox = outbox;
        self
    }

    /// Attach replay occupancy.
    pub fn with_replay(mut self, replay: ReplayStatus) -> Self {
        self.replay = replay;
        self
    }

    /// Attach counters.
    pub fn with_counters(mut self, counters: CounterSnapshot) -> Self {
        self.counters = counters;
        self
    }

    /// Attach the connection trace.
    pub fn with_conntrace(mut self, conntrace: Vec<TraceEntry>) -> Self {
        self.conntrace = conntrace;
        self
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<Vec<u8>, StatusError> {
        serde_json::to_vec(self).map_err(StatusError::Encode)
    }

    /// Serialize to a compact JSON string.
    pub fn to_json_string(&self) -> Result<String, StatusError> {
        serde_json::to_string(self).map_err(StatusError::Encode)
    }
}

/// Publishes the document through the runtime directory.
#[derive(Debug)]
pub struct StatusWriter {
    dir: RuntimeDir,
    interval: Duration,
}

impl StatusWriter {
    /// Build a writer for `dir`.
    pub fn new(dir: RuntimeDir, interval: Duration) -> Self {
        Self { dir, interval }
    }

    /// Refresh interval this writer was configured with.
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Path of the document.
    pub fn path(&self) -> std::path::PathBuf {
        self.dir.status_path()
    }

    /// Write one snapshot atomically.
    pub fn write(&self, snapshot: &StatusSnapshot) -> Result<(), StatusError> {
        let json = snapshot.to_json()?;
        self.dir.write_status(&json).map_err(StatusError::Io)
    }
}

/// A status failure.
#[derive(Debug)]
pub enum StatusError {
    /// The document could not be encoded.
    Encode(serde_json::Error),
    /// The runtime directory refused the write.
    Io(Errno),
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(err) => write!(f, "cannot encode status document: {err}"),
            Self::Io(err) => write!(f, "cannot write status document: {err}"),
        }
    }
}

impl std::error::Error for StatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::time::Duration;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot::new("0123456789abcdef", "STEADY", Seq(42), 7)
            .with_outbox(OutboxStatus {
                ops: 3,
                bytes: 4096,
            })
            .with_replay(ReplayStatus {
                pending: 2,
                reorder: 1,
                dedup: 10,
                resyncs: 0,
                diverged: false,
            })
            .with_counters(CounterSnapshot {
                ops_applied: 42,
                bytes_written: 8192,
                ..CounterSnapshot::default()
            })
            .with_conntrace(vec![TraceEntry::new(
                1_700_000_000_000_000,
                "in",
                "ORDERED",
                128,
                Seq(42),
            )])
    }

    /// 27 §4, 45 status/log: the document has every documented field.
    #[test]
    fn u_status_json_schema() {
        let json = snapshot().to_json_string().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema"], STATUS_SCHEMA);
        assert_eq!(value["mount_id"], "0123456789abcdef");
        assert_eq!(value["state"], "STEADY");
        assert_eq!(value["applied_seq"], 42);
        assert_eq!(value["epoch"], 7);
        assert_eq!(value["outbox"]["ops"], 3);
        assert_eq!(value["outbox"]["bytes"], 4096);
        assert_eq!(value["replay"]["pending"], 2);
        assert_eq!(value["replay"]["diverged"], false);
        assert_eq!(value["counters"]["ops_applied"], 42);
        assert_eq!(value["counters"]["bytes_written"], 8192);
        assert_eq!(value["conntrace"][0]["kind"], "ORDERED");
        assert_eq!(value["conntrace"][0]["seq"], 42);
    }

    /// 27 §3: a path appears only as an eight-hex hash prefix.
    #[test]
    fn u_status_paths_are_hashed() {
        let prefix = path_hash_prefix("/home/user/secret.txt");
        assert_eq!(prefix.len(), 8);
        assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!prefix.contains("secret"));
        assert_eq!(prefix, path_hash_prefix("/home/user/secret.txt"));
        assert_ne!(prefix, path_hash_prefix("/home/user/other.txt"));
    }

    /// 41 §2.8: the ring keeps the newest entries.
    #[test]
    fn u_status_conntrace_ring_is_bounded() {
        let trace = Conntrace::new(3);
        for seq in 1..=5 {
            trace.record(TraceEntry::new(seq as i64, "out", "ORDERED", 10, Seq(seq)));
        }
        assert_eq!(trace.len(), 3);
        let entries = trace.snapshot();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 3);
        assert_eq!(entries[2].seq, 5);
        trace.clear();
        assert!(trace.is_empty());
    }

    /// 41 §2.8: counters are monotonic and snapshot atomically enough.
    #[test]
    fn u_status_counters() {
        let counters = Counters::default();
        Counters::bump(&counters.ops_applied);
        Counters::add(&counters.bytes_written, 4096);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.ops_applied, 1);
        assert_eq!(snapshot.bytes_written, 4096);
        assert_eq!(snapshot.frames_in, 0);
    }

    /// 41 §2.8: the writer replaces the file atomically and the JSON parses.
    #[test]
    fn u_status_writer_roundtrip() {
        let base = tempdir();
        let dir = RuntimeDir::create_in(base.path(), "mounttest").unwrap();
        let writer = StatusWriter::new(dir, Duration::from_secs(5));
        assert_eq!(writer.interval(), Duration::from_secs(5));
        assert!(writer.path().ends_with("status.json"));

        writer.write(&snapshot()).unwrap();
        let data = std::fs::read(writer.path()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(value["applied_seq"], 42);

        // A second write replaces the document, never appends to it.
        let mut second = snapshot();
        second.applied_seq = 43;
        writer.write(&second).unwrap();
        let data = std::fs::read(writer.path()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(value["applied_seq"], 43);
        // A single top-level object; nested objects are counted separately.
        assert!(data.starts_with(b"{"));
    }

    /// 39 §2.1: the document is mode 0600.
    #[test]
    fn u_status_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempdir();
        let dir = RuntimeDir::create_in(base.path(), "mountperm").unwrap();
        let writer = StatusWriter::new(dir, Duration::from_secs(5));
        writer.write(&snapshot()).unwrap();
        let mode = std::fs::metadata(writer.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
