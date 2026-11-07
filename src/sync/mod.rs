//! Sync engine actor: snapshot, manifest, diff, and the client ↔ sync port.
//!
//! Owner: W14 (E7). See `43-sync-skeleton.md` and `53-work-breakdown.md` W14.
//!
//! # Shape
//!
//! [`SyncEngine`] is the only public entry point. It spawns one actor that
//! owns a [`state::Machine`] and never blocks on I/O: every port call is a
//! future, and a join runs concurrently with the command channel so `Abort`
//! is always heard. W15–W17 add submodules behind the same facade; they must
//! not add a second engine.
//!
//! # Ports, not dependencies
//!
//! `sync` never names `client`, `fuse` or the transport. It sees five ports
//! ([`StateProvider`], [`ChunkSource`], [`SyncLink`], [`LocalTree`]) that the
//! client implements, which keeps the dependency direction one-way
//! (`client → sync`) and lets every test run without a socket.
//!
//! # Content identity
//!
//! [`ChunkId`] is `BLAKE3(plaintext)`. It is the only identity the wire, the
//! blockmap and the resume ledger use (43 §5.1). Ciphertext is never an
//! identity: [`ChunkSource`] seals and opens, and the caller only ever sees
//! plaintext that has already been verified against the id.

pub mod baseline;
pub mod chunk;
pub mod config;
pub mod manifest;
pub mod resume;
pub mod rsync;
pub mod snapshot;
pub mod staging;
pub mod state;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::Seq;
use crate::protocol::messages::SnapshotRef;
use crate::store::Kind;

pub use baseline::Baseline;
pub use config::SyncConfig;
pub use manifest::codec::{BlockmapIndexRef, ManifestRef};
pub use manifest::diff::{DiffCounts, DiffKind, DiffPlan, PlanItem};
pub use manifest::{Blockmap, LocalManifest, Manifest};
pub use resume::{
    ApplyOutcome, ChunkPresence, ChunkReader, ClusterWins, DeltaPeer, DiskTree, FileResume,
    JoinView, Ledger, RemoteView, Resume, SyncState,
};
pub use snapshot::format::SnapshotIndex;
pub use state::{Machine, RetryClass, SyncError, SyncEvent, SyncPhase};

/// A boxed, sendable future, the shape every port returns.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// Content identity
// ---------------------------------------------------------------------------

/// `BLAKE3(plaintext)` — the identity of a content chunk.
///
/// The type is the store's canonical one (W16): the wire, the blockmap, the
/// chunk cache and the resume ledger must agree on a single identity, so
/// `sync` re-exports rather than defines it. Computed on plaintext, never on
/// ciphertext (43 appendix A-7).
pub use crate::store::chunk_store::{ChunkId, ChunkKind};

/// The "absent" sentinel used by part descriptors.
///
/// A real BLAKE3 output is never all zero, so the container formats can use
/// zero to mean "this slot has no chunk".
pub const ZERO_CHUNK: ChunkId = ChunkId::from_bytes([0u8; 32]);

/// True for [`ZERO_CHUNK`].
pub fn chunk_is_zero(id: ChunkId) -> bool {
    id.as_bytes().iter().all(|byte| *byte == 0)
}

// ---------------------------------------------------------------------------
// Part descriptors
// ---------------------------------------------------------------------------

/// One 1 MiB part described by content, not by location.
///
/// A part holds at most [`config::CHUNKS_PER_PART`] chunks. The final chunk may
/// be shorter than [`config::CHUNK_BYTES`]; unused slots are [`ZERO_CHUNK`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PartDesc {
    /// Zero-based part index within its container.
    pub part_index: u32,
    /// Plaintext length of the whole part, header included.
    pub plain_len: u32,
    /// Up to four chunk identities, in order.
    pub chunk_ids: [ChunkId; config::CHUNKS_PER_PART],
}

impl PartDesc {
    /// Encoded width.
    pub const LEN: usize = 4 + 4 + config::CHUNKS_PER_PART * ChunkId::LEN;

    /// Build a descriptor from the chunks that actually exist.
    pub fn new(part_index: u32, plain_len: u32, ids: &[ChunkId]) -> Self {
        let mut chunk_ids = [ZERO_CHUNK; config::CHUNKS_PER_PART];
        for (slot, id) in chunk_ids.iter_mut().zip(ids) {
            *slot = *id;
        }
        Self {
            part_index,
            plain_len,
            chunk_ids,
        }
    }

    /// The chunks present in this part, in order.
    pub fn chunks(&self) -> impl Iterator<Item = ChunkId> + '_ {
        self.chunk_ids
            .iter()
            .copied()
            .filter(|id| !chunk_is_zero(*id))
    }

    /// Number of chunks actually present.
    pub fn chunk_count(&self) -> usize {
        self.chunks().count()
    }

    /// Append the little-endian encoding.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        wire::put_u32(out, self.part_index);
        wire::put_u32(out, self.plain_len);
        for id in &self.chunk_ids {
            out.extend_from_slice(id.as_bytes());
        }
    }

    /// Decode exactly [`PartDesc::LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] on a short buffer or a hole before a live chunk.
    pub(crate) fn decode(reader: &mut wire::Reader<'_>) -> Result<Self, SyncError> {
        let part_index = reader.u32()?;
        let plain_len = reader.u32()?;
        let mut chunk_ids = [ZERO_CHUNK; config::CHUNKS_PER_PART];
        for slot in &mut chunk_ids {
            *slot = ChunkId::from_bytes(reader.array32()?);
        }
        let mut seen_zero = false;
        for id in chunk_ids {
            if chunk_is_zero(id) {
                seen_zero = true;
            } else if seen_zero {
                return Err(SyncError::Format("part descriptor hole before chunk"));
            }
        }
        if usize::try_from(plain_len).unwrap_or(usize::MAX) > config::SNAPSHOT_PART {
            return Err(SyncError::Format("part longer than the part size"));
        }
        Ok(Self {
            part_index,
            plain_len,
            chunk_ids,
        })
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// An immutable state image captured at one sequence number.
///
/// Capture is `O(1)` because the replay state is copy-on-write (43 §2.1); the
/// image owns the root it captured. `encode` is a pure function of the image,
/// so two generators produce identical bytes for the same `covered_seq`.
pub trait StateImage: Send + Sync + fmt::Debug {
    /// The sequence this image describes.
    fn covered_seq(&self) -> Seq;

    /// Deterministic serialization of the whole state machine.
    fn encode(&self) -> Vec<u8>;

    /// File-level manifest entries, sorted by path.
    fn entries(&self) -> Vec<manifest::Entry>;

    /// Block-level baseline, concatenated in entry order.
    fn blocks(&self) -> Vec<ChunkId>;
}

/// The replay engine as `sync` sees it.
pub trait StateProvider: Send + Sync + fmt::Debug {
    /// Highest applied sequence.
    fn applied_seq(&self) -> Seq;

    /// Capture the current state without stopping apply.
    fn capture(&self) -> Arc<dyn StateImage>;

    /// Install a verified state image as the new baseline.
    ///
    /// The implementation must be all-or-nothing: a failed install leaves the
    /// previous state and `applied_seq` untouched. `sync` only calls this after
    /// the container digest has passed (C-28).
    fn install(&self, covered_seq: Seq, image: &[u8]) -> Result<(), SyncError>;
}

/// Content-addressed chunk storage plus transfer.
///
/// `put` seals and stores; `fetch` returns *verified* plaintext, decrypting
/// and re-hashing before it returns. The production implementation is W16's
/// chunk store (43 §5.1); the test implementation in this crate's test module
/// seals with the W3 [`crate::protocol::crypto::Sealer`], which is the same
/// envelope the production path uses.
pub trait ChunkSource: Send + Sync + fmt::Debug {
    /// Seal `plain` under `kind` and store it. Returns its content id.
    fn put(&self, kind: ChunkKind, plain: &[u8]) -> Result<ChunkId, SyncError>;

    /// Return the verified plaintext for `(kind, id)`.
    fn fetch(&self, kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>>;
}

/// Why a sync session ended (43 §0.2 `SYNC_END`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncEndReason {
    /// The join finished.
    Done,
    /// One side cancelled.
    Cancel,
    /// No peer can serve the request.
    NoPeer,
    /// The data is unavailable after the retry budget.
    Unavailable,
}

impl SyncEndReason {
    /// Wire value.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Done => 1,
            Self::Cancel => 2,
            Self::NoPeer => 3,
            Self::Unavailable => 4,
        }
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Cancel => "CANCEL",
            Self::NoPeer => "NO_PEER",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// Control-plane operations: everything the server routes but never parses.
///
/// Content never crosses this port; it travels through [`ChunkSource`]. That
/// split is what keeps a manifest request small and a block request
/// content-addressed (43 §5.3).
pub trait SyncLink: Send + Sync + fmt::Debug {
    /// Ask for the snapshot covering `covered_seq`.
    fn request_snapshot(&self, covered_seq: Seq) -> BoxFut<'_, Result<SnapshotRef, SyncError>>;

    /// Publish a snapshot this client generated (43 §2.3).
    fn publish_snapshot(&self, reference: SnapshotRef) -> BoxFut<'_, Result<(), SyncError>>;

    /// Ask the peer for its manifest at `at_seq` (its current applied seq when
    /// `None`).
    fn request_manifest(&self, at_seq: Option<Seq>) -> BoxFut<'_, Result<ManifestRef, SyncError>>;

    /// Ask for the blockmap index that belongs to `at_seq`.
    fn request_blockmap_index(
        &self,
        at_seq: Seq,
    ) -> BoxFut<'_, Result<BlockmapIndexRef, SyncError>>;

    /// End the session.
    fn sync_end(&self, reason: SyncEndReason) -> BoxFut<'_, Result<(), SyncError>>;
}

/// One local directory entry as the diff sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskStat {
    /// File type on disk.
    pub kind: Kind,
    /// Size in bytes (`0` for directories).
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Symlink target, when `kind` is [`Kind::Symlink`].
    pub target: Option<String>,
    /// True when the symlink's target does not resolve.
    pub dangling: bool,
}

impl DiskStat {
    /// Attributes of a regular file.
    pub fn file(size: u64, mtime_ns: u64, mode: u32) -> Self {
        Self {
            kind: Kind::File,
            size,
            mtime_ns,
            mode,
            uid: 1000,
            gid: 1000,
            target: None,
            dangling: false,
        }
    }

    /// Attributes of a directory.
    pub fn dir(mtime_ns: u64, mode: u32) -> Self {
        Self {
            kind: Kind::Dir,
            size: 0,
            mtime_ns,
            mode,
            uid: 1000,
            gid: 1000,
            target: None,
            dangling: false,
        }
    }
}

/// The local side: the disk tree and the last applied manifest.
///
/// Reading is the only operation. Writing the cache is the apply step's job
/// (W16), and keeping it out of this trait is what prevents a diff from
/// accidentally "fixing" the trust anchor.
pub trait LocalTree: Send + Sync + fmt::Debug {
    /// Every entry below the root, sorted by path bytes, reserved names
    /// excluded.
    fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError>;

    /// Stat one relative path.
    fn stat(&self, path: &str) -> Result<Option<DiskStat>, SyncError>;

    /// The last successfully applied manifest, if it is usable.
    fn cached_manifest(&self) -> Option<LocalManifest>;
}

/// Everything the engine needs, assembled once.
#[derive(Clone, Debug)]
pub struct SyncPorts {
    /// Replay state.
    pub state: Arc<dyn StateProvider>,
    /// Content chunks (transfer side).
    pub chunks: Arc<dyn ChunkSource>,
    /// Control plane.
    pub link: Arc<dyn SyncLink>,
    /// Local disk view.
    pub tree: Arc<dyn LocalTree>,
    /// Verified local content cache, read by the apply stage (W17).
    pub cache: Option<Arc<dyn resume::ChunkReader>>,
    /// Peer delta source, used by `ContentDiff` (W15/W17).
    pub delta: Option<Arc<dyn resume::DeltaPeer>>,
    /// Cluster identity; a cached manifest from another cluster is ignored.
    pub cluster: ClusterId,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// What the client knows when a join starts.
#[derive(Clone, Copy, Debug)]
pub struct JoinStart {
    /// `current_seq` from `WELCOME`.
    pub current_seq: Seq,
    /// Server epoch from `WELCOME`.
    pub epoch: u64,
    /// `latest_snapshot` from `WELCOME`, when the server has one.
    pub reference: Option<SnapshotRef>,
}

/// Progress the engine reports to its owner.
#[derive(Clone, Debug)]
pub enum SyncNotice {
    /// A phase was entered.
    Phase(SyncPhase),
    /// The local baseline was classified (43 §7).
    Baseline(Baseline),
    /// A snapshot is installed; `applied_seq == covered_seq`.
    SnapshotInstalled {
        /// Covered sequence.
        covered_seq: Seq,
        /// Parts in the container, index included.
        parts: u32,
        /// State image length.
        plain_len: u64,
    },
    /// The remote manifest decoded.
    ManifestFetched {
        /// Sequence the manifest was generated at.
        at_seq: Seq,
        /// Entry count.
        entries: usize,
    },
    /// The diff plan is ready. `blockmap_parts` is the sparse pull set.
    Planned {
        /// The plan.
        plan: DiffPlan,
        /// Blockmap data parts that must be fetched, ascending.
        blockmap_parts: Vec<u32>,
    },
    /// No snapshot exists; the server must designate a generator.
    NeedSnapshotNow,
    /// The join was aborted by a command.
    Aborted {
        /// Why.
        reason: String,
    },
    /// The join failed.
    Failed(SyncError),
}

/// A handle to the running engine.
#[derive(Debug)]
pub struct SyncHandle {
    commands: mpsc::Sender<SyncCommand>,
    notices: mpsc::UnboundedReceiver<SyncNotice>,
    task: JoinHandle<()>,
}

impl SyncHandle {
    /// Start a join. The engine reports through [`SyncHandle::next_notice`].
    ///
    /// # Errors
    ///
    /// [`SyncError::EngineStopped`] when the actor is gone.
    pub async fn begin(&self, start: JoinStart) -> Result<(), SyncError> {
        self.commands
            .send(SyncCommand::Begin(start))
            .await
            .map_err(|_| SyncError::EngineStopped)
    }

    /// Next notice, or `None` when the actor exited.
    pub async fn next_notice(&mut self) -> Option<SyncNotice> {
        self.notices.recv().await
    }

    /// Non-blocking notice.
    pub fn try_next_notice(&mut self) -> Option<SyncNotice> {
        self.notices.try_recv().ok()
    }

    /// Abort the running join and stay alive.
    ///
    /// # Errors
    ///
    /// [`SyncError::EngineStopped`] when the actor is gone.
    pub async fn abort(&self, reason: impl Into<String>) -> Result<(), SyncError> {
        self.commands
            .send(SyncCommand::Abort {
                reason: reason.into(),
            })
            .await
            .map_err(|_| SyncError::EngineStopped)
    }

    /// Stop the actor and wait for it.
    pub async fn shutdown(self) {
        let _ = self.commands.send(SyncCommand::Shutdown).await;
        let _ = self.task.await;
    }

    /// True once the actor task has finished.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Commands the actor accepts.
#[derive(Debug)]
enum SyncCommand {
    Begin(JoinStart),
    Abort { reason: String },
    Shutdown,
}

/// The sync engine facade.
#[derive(Debug)]
pub struct SyncEngine;

impl SyncEngine {
    /// Spawn the actor.
    ///
    /// Must be called from a Tokio runtime; the returned handle owns the task.
    pub fn spawn(ports: SyncPorts, config: SyncConfig) -> SyncHandle {
        let (command_tx, command_rx) = mpsc::channel(8);
        let (notice_tx, notice_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_engine(command_rx, notice_tx, ports, config));
        SyncHandle {
            commands: command_tx,
            notices: notice_rx,
            task,
        }
    }
}

async fn run_engine(
    mut commands: mpsc::Receiver<SyncCommand>,
    notices: mpsc::UnboundedSender<SyncNotice>,
    ports: SyncPorts,
    config: SyncConfig,
) {
    type JoinFuture = Pin<Box<dyn Future<Output = Result<(), SyncError>> + Send>>;
    let mut join: Option<JoinFuture> = None;

    loop {
        let Some(mut running) = join.take() else {
            match commands.recv().await {
                None | Some(SyncCommand::Shutdown) => break,
                Some(SyncCommand::Abort { reason }) => {
                    let _ = notices.send(SyncNotice::Aborted { reason });
                }
                Some(SyncCommand::Begin(start)) => {
                    join = Some(Box::pin(drive_join(
                        ports.clone(),
                        config.clone(),
                        start,
                        notices.clone(),
                    )));
                }
            }
            continue;
        };

        let mut keep = true;
        tokio::select! {
            command = commands.recv() => match command {
                None | Some(SyncCommand::Shutdown) => {
                    keep = false;
                }
                Some(SyncCommand::Abort { reason }) => {
                    keep = false;
                    let _ = notices.send(SyncNotice::Aborted { reason });
                }
                Some(SyncCommand::Begin(_)) => {
                    let _ = notices.send(SyncNotice::Failed(SyncError::Busy));
                }
            },
            result = &mut running => {
                keep = false;
                if let Err(err) = result {
                    let _ = notices.send(SyncNotice::Failed(err));
                }
            }
        }
        if keep {
            join = Some(running);
        }
    }
}

/// Drive one join from `WELCOME` to the end of W14's pipeline.
///
/// The pipeline stops after the diff plan: rsync (W15) and chunk/staging (W16)
/// continue from `DiffPlan`, and resume/journal (W17) owns the rest of the
/// phase machine.
async fn drive_join(
    ports: SyncPorts,
    config: SyncConfig,
    start: JoinStart,
    notices: mpsc::UnboundedSender<SyncNotice>,
) -> Result<(), SyncError> {
    let mut tracker = Tracker::new(notices.clone());

    tracker.step(SyncEvent::Welcome)?;
    if start.reference.is_some() {
        tracker.step(SyncEvent::SnapshotRef)?;
    } else {
        tracker.step(SyncEvent::SnapshotAbsent)?;
    }

    // The scan and the diff are blocking (directory walk, then comparison).
    // Run them off the actor thread so `Abort` is heard while they work
    // (43 §1: the actor never blocks on I/O).
    let scan = Arc::clone(&ports.tree);
    let cluster = ports.cluster;
    let scan_config = config.clone();
    let baseline = tokio::task::spawn_blocking(move || {
        baseline::classify(scan.as_ref(), cluster, &scan_config)
    })
    .await
    .map_err(|_| SyncError::Io("baseline scan task failed".to_owned()))?;
    let _ = notices.send(SyncNotice::Baseline(baseline));

    let Some(reference) = start.reference else {
        let _ = notices.send(SyncNotice::NeedSnapshotNow);
        let _ = ports.link.sync_end(SyncEndReason::NoPeer).await;
        return Ok(());
    };

    tracker.step(SyncEvent::SnapshotSelected)?;
    let installer = snapshot::Installer::new(&ports, &config);
    let pulled = installer.pull(&reference).await?;
    tracker.step(SyncEvent::PartsComplete)?;
    let installed = installer.install(pulled)?;
    tracker.step(SyncEvent::Installed)?;
    let _ = notices.send(SyncNotice::SnapshotInstalled {
        covered_seq: installed.covered_seq,
        parts: installed.parts,
        plain_len: installed.plain_len,
    });

    let manifest_ref = ports.link.request_manifest(None).await?;
    let service = manifest::ManifestService::new(&ports);
    let remote = service.fetch(&manifest_ref).await?;
    tracker.step(SyncEvent::ManifestDone)?;
    let _ = notices.send(SyncNotice::ManifestFetched {
        at_seq: remote.at_seq,
        entries: remote.len(),
    });

    let scan = Arc::clone(&ports.tree);
    let cluster = ports.cluster;
    let (plan, remote) = tokio::task::spawn_blocking(move || {
        let local = scan.cached_manifest();
        manifest::diff::plan(local.as_ref(), &remote, scan.as_ref(), cluster)
            .map(|plan| (plan, remote))
    })
    .await
    .map_err(|_| SyncError::Io("diff plan task failed".to_owned()))??;
    let blockmap_parts = if plan.needs_blockmap(&remote) {
        let index_ref = ports.link.request_blockmap_index(remote.at_seq).await?;
        let index = service.fetch_blockmap_index(&index_ref).await?;
        plan.blockmap_parts(&index, &remote)
    } else {
        Vec::new()
    };
    tracker.step(SyncEvent::Planned)?;
    let _ = notices.send(SyncNotice::Planned {
        plan,
        blockmap_parts,
    });
    Ok(())
}

/// Phase tracking plus notice fan-out.
struct Tracker {
    machine: Machine,
    notices: mpsc::UnboundedSender<SyncNotice>,
}

impl Tracker {
    fn new(notices: mpsc::UnboundedSender<SyncNotice>) -> Self {
        Self {
            machine: Machine::new(),
            notices,
        }
    }

    fn step(&mut self, event: SyncEvent) -> Result<SyncPhase, SyncError> {
        let phase = self.machine.apply(event)?;
        let _ = self.notices.send(SyncNotice::Phase(phase));
        Ok(phase)
    }
}

// ---------------------------------------------------------------------------
// Little-endian container helpers
// ---------------------------------------------------------------------------

/// Bounds-checked readers and writers shared by every container codec.
pub(crate) mod wire {
    use super::SyncError;

    /// Append one byte.
    pub(crate) fn put_u8(out: &mut Vec<u8>, value: u8) {
        out.push(value);
    }

    /// Append a little-endian `u16`.
    pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a 4-byte magic.
    pub(crate) fn put_magic(out: &mut Vec<u8>, magic: [u8; 4]) {
        out.extend_from_slice(&magic);
    }

    /// A cursor over one container.
    #[derive(Debug)]
    pub(crate) struct Reader<'a> {
        buf: &'a [u8],
        at: usize,
    }

    impl<'a> Reader<'a> {
        /// Start at byte zero.
        pub(crate) const fn new(buf: &'a [u8]) -> Self {
            Self { buf, at: 0 }
        }

        /// Bytes not yet consumed.
        pub(crate) fn remaining(&self) -> usize {
            self.buf.len().saturating_sub(self.at)
        }

        /// Consume one byte.
        pub(crate) fn u8(&mut self) -> Result<u8, SyncError> {
            Ok(self.bytes(1)?[0])
        }

        /// Consume a little-endian `u16`.
        pub(crate) fn u16(&mut self) -> Result<u16, SyncError> {
            let raw = self.bytes(2)?;
            Ok(u16::from_le_bytes([raw[0], raw[1]]))
        }

        /// Consume a little-endian `u32`.
        pub(crate) fn u32(&mut self) -> Result<u32, SyncError> {
            let raw = self.bytes(4)?;
            Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
        }

        /// Consume a little-endian `u64`.
        pub(crate) fn u64(&mut self) -> Result<u64, SyncError> {
            let raw = self.bytes(8)?;
            Ok(u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]))
        }

        /// Consume exactly four bytes and compare them with a magic.
        pub(crate) fn magic(&mut self, expected: [u8; 4]) -> Result<(), SyncError> {
            if self.bytes(4)? == expected {
                Ok(())
            } else {
                Err(SyncError::Format("bad container magic"))
            }
        }

        /// Consume exactly 32 bytes.
        pub(crate) fn array32(&mut self) -> Result<[u8; 32], SyncError> {
            let raw = self.bytes(32)?;
            let mut out = [0u8; 32];
            out.copy_from_slice(raw);
            Ok(out)
        }

        /// Consume exactly 16 bytes.
        pub(crate) fn array16(&mut self) -> Result<[u8; 16], SyncError> {
            let raw = self.bytes(16)?;
            let mut out = [0u8; 16];
            out.copy_from_slice(raw);
            Ok(out)
        }

        /// Consume `len` bytes.
        pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], SyncError> {
            let end = self
                .at
                .checked_add(len)
                .ok_or(SyncError::Format("container length overflow"))?;
            if end > self.buf.len() {
                return Err(SyncError::Format("container truncated"));
            }
            let slice = &self.buf[self.at..end];
            self.at = end;
            Ok(slice)
        }

        /// Reject trailing bytes.
        pub(crate) fn finish(&self) -> Result<(), SyncError> {
            if self.at == self.buf.len() {
                Ok(())
            } else {
                Err(SyncError::Format("trailing bytes"))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    //! Deterministic in-process ports for the sync tests.
    //!
    //! The chunk sink seals with the content cipher (W16's [`ChunkCipher`]),
    //! which is the same `enc_key` and AEAD that W3 derives, under the
    //! content-domain AAD. The message [`crate::protocol::crypto::Sealer`]
    //! cannot be used here: it caps plaintext at 64 KiB, while a chunk is
    //! 256 KiB. Sealing, opening and the `BLAKE3(plaintext) == id` check are
    //! all exercised, so the tests see the real envelope, not a byte map.

    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::protocol::crypto::ClusterId;
    use crate::protocol::frame::Seq;
    use crate::protocol::messages::SnapshotRef;
    use crate::store::Kind;
    use crate::sync::chunk::id::ChunkCipher;

    use super::{
        BoxFut, ChunkId, ChunkKind, ChunkSource, DiskStat, JoinStart, LocalManifest, LocalTree,
        Manifest, StateImage, StateProvider, SyncEndReason, SyncError, SyncLink, SyncPorts, config,
        manifest, snapshot,
    };
    use crate::sync::manifest::Blockmap;
    use crate::sync::manifest::codec::{BlockmapIndexRef, ManifestRef};
    use crate::sync::manifest::diff::DiffPlan;

    /// Cluster used by every test.
    pub(crate) const CLUSTER: ClusterId = ClusterId::from_bytes([0x2a; 16]);

    /// Content key for the test cipher. Any 32 bytes work: the cipher is
    /// content-addressed, so the key changes nothing observable but the blob.
    const TEST_CONTENT_KEY: [u8; 32] = [0x42; 32];

    /// In-memory chunk store that seals with the content cipher.
    #[derive(Debug)]
    pub(crate) struct MemChunks {
        cipher: ChunkCipher,
        blobs: Mutex<HashMap<[u8; 33], Vec<u8>>>,
        corrupt_plain: Mutex<Option<ChunkId>>,
        corrupt_blob: Mutex<Option<ChunkId>>,
        missing: Mutex<Option<ChunkId>>,
        fetches: AtomicU64,
    }

    impl MemChunks {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                cipher: ChunkCipher::new(TEST_CONTENT_KEY),
                blobs: Mutex::new(HashMap::new()),
                corrupt_plain: Mutex::new(None),
                corrupt_blob: Mutex::new(None),
                missing: Mutex::new(None),
                fetches: AtomicU64::new(0),
            })
        }

        fn key(kind: ChunkKind, id: ChunkId) -> [u8; 33] {
            let mut key = [0u8; 33];
            key[0] = kind.wire();
            key[1..].copy_from_slice(id.as_bytes());
            key
        }

        pub(crate) fn fetches(&self) -> u64 {
            self.fetches.load(Ordering::Relaxed)
        }

        pub(crate) fn corrupt_plaintext(&self, id: ChunkId) {
            *self.corrupt_plain.lock().unwrap() = Some(id);
        }

        pub(crate) fn corrupt_blob(&self, id: ChunkId) {
            *self.corrupt_blob.lock().unwrap() = Some(id);
        }

        pub(crate) fn drop_chunk(&self, id: ChunkId) {
            *self.missing.lock().unwrap() = Some(id);
        }

        pub(crate) fn has(&self, kind: ChunkKind, id: ChunkId) -> bool {
            self.blobs
                .lock()
                .unwrap()
                .contains_key(&Self::key(kind, id))
        }
    }

    impl crate::sync::resume::ChunkReader for MemChunks {
        fn read(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
            let blob = self
                .blobs
                .lock()
                .unwrap()
                .get(&Self::key(kind, id))
                .cloned();
            let Some(blob) = blob else {
                return Ok(None);
            };
            let plain = self
                .cipher
                .open(kind, &id, &blob)
                .map_err(|_| SyncError::ChunkCorrupt { id })?;
            if ChunkId::of_plaintext(&plain) != id {
                return Err(SyncError::ChunkCorrupt { id });
            }
            Ok(Some(plain.to_vec()))
        }
    }

    impl ChunkSource for MemChunks {
        fn put(&self, kind: ChunkKind, plain: &[u8]) -> Result<ChunkId, SyncError> {
            let id = ChunkId::of_plaintext(plain);
            let sealed = self
                .cipher
                .seal(kind, plain)
                .map_err(|_| SyncError::ChunkCorrupt { id })?;
            self.blobs
                .lock()
                .unwrap()
                .insert(Self::key(kind, id), sealed.blob);
            Ok(id)
        }

        fn fetch(&self, kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>> {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            if *self.missing.lock().unwrap() == Some(id) {
                return Box::pin(async move { Err(SyncError::ChunkUnavailable { id }) });
            }
            let blob = self
                .blobs
                .lock()
                .unwrap()
                .get(&Self::key(kind, id))
                .cloned()
                .ok_or(SyncError::ChunkUnavailable { id });
            let blob = match blob {
                Ok(blob) => blob,
                Err(err) => return Box::pin(async move { Err(err) }),
            };
            let opened = self.cipher.open(kind, &id, &blob);
            let mut plain = match opened {
                Ok(plain) => plain.to_vec(),
                Err(_) => return Box::pin(async move { Err(SyncError::ChunkCorrupt { id }) }),
            };
            if *self.corrupt_blob.lock().unwrap() == Some(id) {
                return Box::pin(async move { Err(SyncError::ChunkCorrupt { id }) });
            }
            if ChunkId::of_plaintext(&plain) != id {
                return Box::pin(async move { Err(SyncError::ChunkCorrupt { id }) });
            }
            if *self.corrupt_plain.lock().unwrap() == Some(id) {
                // Flip a payload byte, not the header: the container must
                // parse and then fail the state digest (C-28).
                if let Some(last) = plain.last_mut() {
                    *last ^= 0xff;
                }
            }
            Box::pin(async move { Ok(plain) })
        }
    }

    /// A deterministic state image.
    #[derive(Clone, Debug)]
    pub(crate) struct FakeImage {
        pub(crate) covered_seq: Seq,
        pub(crate) bytes: Vec<u8>,
        pub(crate) entries: Vec<manifest::Entry>,
        pub(crate) blocks: Vec<ChunkId>,
    }

    impl StateImage for FakeImage {
        fn covered_seq(&self) -> Seq {
            self.covered_seq
        }

        fn encode(&self) -> Vec<u8> {
            self.bytes.clone()
        }

        fn entries(&self) -> Vec<manifest::Entry> {
            self.entries.clone()
        }

        fn blocks(&self) -> Vec<ChunkId> {
            self.blocks.clone()
        }
    }

    /// A replay-state stand-in that records installs.
    #[derive(Debug)]
    pub(crate) struct FakeState {
        applied: AtomicU64,
        image: Mutex<Option<Arc<FakeImage>>>,
        pub(crate) installs: AtomicU64,
    }

    impl FakeState {
        pub(crate) fn new(applied: u64, image: FakeImage) -> Arc<Self> {
            Arc::new(Self {
                applied: AtomicU64::new(applied),
                image: Mutex::new(Some(Arc::new(image))),
                installs: AtomicU64::new(0),
            })
        }

        pub(crate) fn installed(&self) -> u64 {
            self.installs.load(Ordering::Relaxed)
        }
    }

    impl StateProvider for FakeState {
        fn applied_seq(&self) -> Seq {
            Seq(self.applied.load(Ordering::Relaxed))
        }

        fn capture(&self) -> Arc<dyn StateImage> {
            let image = self.image.lock().unwrap();
            match image.as_ref() {
                Some(image) => Arc::clone(image) as Arc<dyn StateImage>,
                None => Arc::new(FakeImage {
                    covered_seq: Seq(self.applied.load(Ordering::Relaxed)),
                    bytes: Vec::new(),
                    entries: Vec::new(),
                    blocks: Vec::new(),
                }),
            }
        }

        fn install(&self, covered_seq: Seq, image: &[u8]) -> Result<(), SyncError> {
            let stored = self.image.lock().unwrap().clone();
            let entries = stored
                .as_ref()
                .map(|image| image.entries.clone())
                .unwrap_or_default();
            let blocks = stored
                .as_ref()
                .map(|image| image.blocks.clone())
                .unwrap_or_default();
            *self.image.lock().unwrap() = Some(Arc::new(FakeImage {
                covered_seq,
                bytes: image.to_vec(),
                entries,
                blocks,
            }));
            self.applied.store(covered_seq.get(), Ordering::Relaxed);
            self.installs.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// A control-plane stand-in that serves what the test stored.
    #[derive(Debug)]
    pub(crate) struct FakeLink {
        pub(crate) chunks: Arc<MemChunks>,
        pub(crate) snapshot: Mutex<Option<SnapshotRef>>,
        pub(crate) manifest: Mutex<Option<Manifest>>,
        pub(crate) blockmap: Mutex<Option<Blockmap>>,
        pub(crate) ended: Mutex<Option<SyncEndReason>>,
        pub(crate) requests: AtomicU64,
    }

    impl FakeLink {
        pub(crate) fn new(chunks: Arc<MemChunks>) -> Arc<Self> {
            Arc::new(Self {
                chunks,
                snapshot: Mutex::new(None),
                manifest: Mutex::new(None),
                blockmap: Mutex::new(None),
                ended: Mutex::new(None),
                requests: AtomicU64::new(0),
            })
        }
    }

    impl SyncLink for FakeLink {
        fn request_snapshot(
            &self,
            _covered_seq: Seq,
        ) -> BoxFut<'_, Result<SnapshotRef, SyncError>> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            let snapshot = *self.snapshot.lock().unwrap();
            Box::pin(async move { snapshot.ok_or(SyncError::SnapshotMissing) })
        }

        fn publish_snapshot(&self, reference: SnapshotRef) -> BoxFut<'_, Result<(), SyncError>> {
            *self.snapshot.lock().unwrap() = Some(reference);
            Box::pin(async { Ok(()) })
        }

        fn request_manifest(
            &self,
            _at_seq: Option<Seq>,
        ) -> BoxFut<'_, Result<ManifestRef, SyncError>> {
            self.requests.fetch_add(1, Ordering::Relaxed);
            let manifest = self.manifest.lock().unwrap().clone();
            let chunks = Arc::clone(&self.chunks);
            Box::pin(async move {
                let manifest = manifest.ok_or(SyncError::SnapshotMissing)?;
                let builder = manifest::ManifestBuilder::new(chunks.as_ref(), manifest.at_seq);
                builder.build(&manifest)
            })
        }

        fn request_blockmap_index(
            &self,
            at_seq: Seq,
        ) -> BoxFut<'_, Result<BlockmapIndexRef, SyncError>> {
            let blockmap = self.blockmap.lock().unwrap().clone();
            let chunks = Arc::clone(&self.chunks);
            Box::pin(async move {
                let blockmap = blockmap.ok_or(SyncError::SnapshotMissing)?;
                let builder = manifest::ManifestBuilder::new(chunks.as_ref(), at_seq);
                builder
                    .build_blockmap(&blockmap)
                    .map(|build| build.reference)
            })
        }

        fn sync_end(&self, reason: SyncEndReason) -> BoxFut<'_, Result<(), SyncError>> {
            *self.ended.lock().unwrap() = Some(reason);
            Box::pin(async { Ok(()) })
        }
    }

    /// A mutable local tree that simulates apply.
    #[derive(Debug, Default)]
    pub(crate) struct MemTree {
        pub(crate) entries: Mutex<BTreeMap<String, DiskStat>>,
        pub(crate) cached: Mutex<Option<LocalManifest>>,
    }

    impl MemTree {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub(crate) fn insert(&self, path: &str, stat: DiskStat) {
            self.entries.lock().unwrap().insert(path.to_owned(), stat);
        }
    }

    impl LocalTree for MemTree {
        fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .iter()
                .map(|(path, stat)| (path.clone(), stat.clone()))
                .collect())
        }

        fn stat(&self, path: &str) -> Result<Option<DiskStat>, SyncError> {
            Ok(self.entries.lock().unwrap().get(path).cloned())
        }

        fn cached_manifest(&self) -> Option<LocalManifest> {
            self.cached.lock().unwrap().clone()
        }
    }

    /// Build a deterministic image from `(path, blocks, bytes)` triples.
    pub(crate) fn make_image(
        covered_seq: u64,
        files: &[(&str, u32)],
        image_len: usize,
    ) -> FakeImage {
        let mut entries = Vec::new();
        let mut blocks = Vec::new();
        let mut payload = vec![0u8; image_len];
        for (index, (path, block_count)) in files.iter().enumerate() {
            let mut ids = Vec::new();
            for block in 0..*block_count {
                let mut seed = Vec::new();
                seed.extend_from_slice(path.as_bytes());
                seed.extend_from_slice(&block.to_le_bytes());
                let id = ChunkId::of_plaintext(&seed);
                if let Some(slot) = payload.get_mut((index * 7 + block as usize) % image_len.max(1))
                {
                    *slot = (index as u8) ^ (block as u8);
                }
                ids.push(id);
                blocks.push(id);
            }
            let mut inode = [0u8; 16];
            inode[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            entries.push(manifest::Entry::file(
                *path,
                crate::store::node_table::InodeId(u128::from_le_bytes(inode)),
                0o644,
                1000,
                1000,
                u64::from(*block_count) * config::CHUNK_BYTES as u64,
                1_700_000_000_000_000_000 + index as u64,
                &ids,
            ));
        }
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        FakeImage {
            covered_seq: Seq(covered_seq),
            bytes: payload,
            entries,
            blocks,
        }
    }

    /// Generate and publish a snapshot for `image`.
    pub(crate) async fn publish_snapshot(
        image: &dyn StateImage,
        chunks: &dyn ChunkSource,
        link: &dyn SyncLink,
    ) -> SnapshotRef {
        let bundle = snapshot::Generator::new(chunks, holder())
            .generate(image)
            .unwrap();
        let reference = bundle.reference;
        link.publish_snapshot(reference).await.unwrap();
        reference
    }

    /// The holder id used by generated test snapshots.
    pub(crate) const fn holder() -> crate::protocol::frame::ClientId {
        crate::protocol::frame::ClientId::from_bytes([0x11; 16])
    }

    /// Run a ready future on a scratch runtime.
    pub(crate) fn futures_block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Apply a plan to the fake tree and commit the manifest cache.
    ///
    /// This is the W16 apply step, reduced to its observable result: every
    /// path ends at the remote version, deletions are gone, and the cache
    /// names the manifest that was applied. A test may call it halfway to
    /// simulate a crash (C-31).
    pub(crate) fn apply_plan(tree: &MemTree, plan: &DiffPlan, remote: &Manifest) {
        for item in plan.items() {
            match item.kind {
                crate::sync::DiffKind::LocalOnly => {
                    tree.entries.lock().unwrap().remove(&item.path);
                }
                crate::sync::DiffKind::Identical | crate::sync::DiffKind::AttrsOnly => {
                    if let Some(entry) = item.remote.and_then(|index| remote.entry(index)) {
                        tree.insert(&item.path, stat_of(entry));
                    }
                }
                crate::sync::DiffKind::DirSync
                | crate::sync::DiffKind::RemoteOnly
                | crate::sync::DiffKind::ContentDiff
                | crate::sync::DiffKind::TypeReplace => {
                    if let Some(entry) = item.remote.and_then(|index| remote.entry(index)) {
                        tree.insert(&item.path, stat_of(entry));
                    }
                }
            }
        }
        *tree.cached.lock().unwrap() = Some(LocalManifest {
            cluster_id: CLUSTER,
            at_seq: remote.at_seq,
            epoch: 7,
            manifest: remote.clone(),
        });
    }

    /// The disk view a fully applied entry produces.
    pub(crate) fn stat_of(entry: &manifest::Entry) -> DiskStat {
        DiskStat {
            kind: entry.kind,
            size: entry.size,
            mtime_ns: entry.mtime_ns,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            target: if entry.kind == Kind::Symlink {
                Some(entry.target.clone())
            } else {
                None
            },
            dangling: false,
        }
    }

    /// Assemble ports for an engine test.
    pub(crate) fn ports(
        state: Arc<FakeState>,
        chunks: Arc<MemChunks>,
        link: Arc<FakeLink>,
        tree: Arc<MemTree>,
    ) -> SyncPorts {
        SyncPorts {
            state,
            chunks,
            link,
            tree,
            cache: None,
            delta: None,
            cluster: CLUSTER,
        }
    }

    /// A join start that names `reference`.
    pub(crate) fn join_start(reference: Option<SnapshotRef>) -> JoinStart {
        JoinStart {
            current_seq: Seq(9000),
            epoch: 7,
            reference,
        }
    }

    /// Manifest and blockmap for an image, as the holder would build them.
    pub(crate) fn holder_views(
        image: &dyn StateImage,
        chunks: &dyn ChunkSource,
    ) -> (Manifest, Blockmap) {
        let manifest = Manifest::new(image.covered_seq(), image.entries());
        let blockmap = Blockmap::from_image(image).unwrap();
        let builder = manifest::ManifestBuilder::new(chunks, image.covered_seq());
        let _ = builder.build(&manifest).unwrap();
        let _ = builder.build_blockmap(&blockmap).unwrap();
        (manifest, blockmap)
    }
}

#[cfg(test)]
mod engine_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    //! End-to-end join tests at the sync-core boundary.
    //!
    //! The transfer stages (W15/W16) are not here: the join stops after
    //! [`super::SyncNotice::Planned`]. That is the whole of W14's contract, and
    //! the tests assert it at the plan level: every remote path appears, the
    //! blockmap pull set is sparse, and an applied plan re-plans as
    //! `Identical` (the `diff -r` analogue of M3-1/M3-3).

    use std::sync::Arc;

    use crate::protocol::frame::Seq;
    use crate::protocol::messages::SnapshotRef;
    use crate::sync::manifest::{self, DiffPlan, Manifest};
    use crate::sync::test_support::{
        CLUSTER, FakeLink, FakeState, MemChunks, MemTree, apply_plan, holder_views, join_start,
        make_image, ports, publish_snapshot, stat_of,
    };
    use crate::sync::{
        Baseline, ChunkId, LocalManifest, LocalTree, StateProvider, SyncConfig, SyncEndReason,
        SyncEngine, SyncNotice, SyncPhase, SyncPorts,
    };

    fn phases(notices: &[SyncNotice]) -> Vec<SyncPhase> {
        notices
            .iter()
            .filter_map(|notice| match notice {
                SyncNotice::Phase(phase) => Some(*phase),
                _ => None,
            })
            .collect()
    }

    fn planned(notices: &[SyncNotice]) -> (&DiffPlan, &[u32]) {
        notices
            .iter()
            .find_map(|notice| match notice {
                SyncNotice::Planned {
                    plan,
                    blockmap_parts,
                } => Some((plan, blockmap_parts.as_slice())),
                _ => None,
            })
            .expect("join must produce a plan")
    }

    fn assert_clean(notices: &[SyncNotice]) {
        if let Some(notice) = notices
            .iter()
            .find(|notice| matches!(notice, SyncNotice::Failed(_)))
        {
            panic!("join failed: {notice:?}");
        }
    }

    /// Drive one join and collect notices until the pipeline rests.
    async fn drive(ports: SyncPorts, reference: Option<SnapshotRef>) -> Vec<SyncNotice> {
        let mut engine = SyncEngine::spawn(ports, SyncConfig::new());
        engine.begin(join_start(reference)).await.unwrap();
        let mut notices = Vec::new();
        while let Some(notice) = engine.next_notice().await {
            let terminal = matches!(
                notice,
                SyncNotice::Planned { .. } | SyncNotice::Failed(_) | SyncNotice::NeedSnapshotNow
            );
            notices.push(notice);
            if terminal {
                break;
            }
        }
        engine.shutdown().await;
        notices
    }

    /// A holder with one published snapshot and a matching manifest.
    struct Holder {
        chunks: Arc<MemChunks>,
        link: Arc<FakeLink>,
        reference: SnapshotRef,
        manifest: Manifest,
    }

    async fn holder(image: &crate::sync::test_support::FakeImage) -> Holder {
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let reference = publish_snapshot(image, chunks.as_ref(), link.as_ref()).await;
        let (manifest, blockmap) = holder_views(image, chunks.as_ref());
        *link.manifest.lock().unwrap() = Some(manifest.clone());
        *link.blockmap.lock().unwrap() = Some(blockmap.clone());
        Holder {
            chunks,
            link,
            reference,
            manifest,
        }
    }

    /// I-JOIN: snapshot → manifest → plan, with every phase in order.
    #[tokio::test]
    async fn i_join_snapshot_manifest_plan() {
        let image = make_image(4096, &[("a", 1), ("b", 2), ("c", 3)], 3 * 1024 * 1024);
        let holder = holder(&image).await;
        let state = FakeState::new(0, image);
        let tree = MemTree::new();
        let notices = drive(
            ports(
                state.clone(),
                holder.chunks.clone(),
                holder.link.clone(),
                tree.clone(),
            ),
            Some(holder.reference),
        )
        .await;
        assert_clean(&notices);
        assert_eq!(
            phases(&notices),
            vec![
                SyncPhase::Handshake,
                SyncPhase::SnapshotSelect,
                SyncPhase::SnapshotPull,
                SyncPhase::SnapshotInstall,
                SyncPhase::ManifestFetch,
                SyncPhase::DiffPlan,
                SyncPhase::RsyncRun,
            ]
        );
        assert!(
            notices
                .iter()
                .any(|notice| matches!(notice, SyncNotice::Baseline(Baseline::Empty)))
        );
        assert_eq!(state.applied_seq(), Seq(4096));
        assert_eq!(state.installed(), 1);
        let (plan, parts) = planned(&notices);
        assert_eq!(plan.counts().remote_only, 3);
        assert_eq!(plan.stats().planned_bytes, 6 * 256 * 1024);
        assert_eq!(parts, &[0]);
        assert_eq!(*holder.link.ended.lock().unwrap(), None);
        assert_eq!(holder.manifest.len(), 3);
    }

    /// M3-1: an empty joiner receives every path, and applying the plan makes
    /// the next diff converge with zero transfers.
    #[tokio::test]
    async fn i_join_m3_1_empty_joiner_converges() {
        let image = make_image(4096, &[("a", 1), ("b", 2), ("c", 3)], 4096);
        let holder = holder(&image).await;
        let state = FakeState::new(0, image);
        let tree = MemTree::new();
        let notices = drive(
            ports(
                state.clone(),
                holder.chunks.clone(),
                holder.link.clone(),
                tree.clone(),
            ),
            Some(holder.reference),
        )
        .await;
        assert_clean(&notices);
        let (plan, _) = planned(&notices);
        assert_eq!(plan.counts().remote_only, 3);

        apply_plan(&tree, plan, &holder.manifest);
        let done = manifest::diff::plan(
            tree.cached_manifest().as_ref(),
            &holder.manifest,
            tree.as_ref(),
            CLUSTER,
        )
        .unwrap();
        assert!(done.is_converged());
        assert_eq!(done.counts().identical, 3);
        assert_eq!(done.counts().transfers(), 0);
    }

    /// M3-2: the manifest is newer than the snapshot, so a write during the
    /// pull is still in the plan.
    #[tokio::test]
    async fn i_join_m3_2_writes_during_pull_reach_the_plan() {
        let snapshot_image = make_image(4096, &[("a", 1)], 512);
        let newer = make_image(4100, &[("a", 1), ("late", 1)], 1024);
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let reference = publish_snapshot(&snapshot_image, chunks.as_ref(), link.as_ref()).await;
        let (remote, blockmap) = holder_views(&newer, chunks.as_ref());
        *link.manifest.lock().unwrap() = Some(remote.clone());
        *link.blockmap.lock().unwrap() = Some(blockmap);

        let state = FakeState::new(0, snapshot_image);
        let tree = MemTree::new();
        let notices = drive(ports(state.clone(), chunks, link, tree), Some(reference)).await;
        assert_clean(&notices);
        assert!(notices.iter().any(|notice| matches!(
            notice,
            SyncNotice::ManifestFetched {
                at_seq: Seq(4100),
                entries: 2
            }
        )));
        let (plan, _) = planned(&notices);
        let late = plan
            .items()
            .iter()
            .find(|item| item.path == "late")
            .expect("the file written during the pull must be planned");
        assert_eq!(late.kind, crate::sync::DiffKind::RemoteOnly);
        assert_eq!(state.applied_seq(), Seq(4096));
    }

    /// M3-3: a 1 GiB tree is fully covered by the plan without moving a byte.
    #[tokio::test]
    async fn i_join_m3_3_one_gib_tree_plan_covers_everything() {
        let names: Vec<String> = (0..4096).map(|index| format!("f{index:04}")).collect();
        let files: Vec<(&str, u32)> = names.iter().map(|name| (name.as_str(), 1)).collect();
        let image = make_image(1, &files, 0);
        assert_eq!(image.entries.len(), 4096);
        let holder = holder(&image).await;
        let state = FakeState::new(0, image);
        let tree = MemTree::new();
        let notices = drive(
            ports(
                state.clone(),
                holder.chunks.clone(),
                holder.link.clone(),
                tree.clone(),
            ),
            Some(holder.reference),
        )
        .await;
        assert_clean(&notices);
        let (plan, _) = planned(&notices);
        assert_eq!(plan.counts().remote_only, 4096);
        assert_eq!(plan.stats().planned_files, 4096);
        assert_eq!(plan.stats().planned_bytes, 1024 * 1024 * 1024);

        apply_plan(&tree, plan, &holder.manifest);
        let done = manifest::diff::plan(
            tree.cached_manifest().as_ref(),
            &holder.manifest,
            tree.as_ref(),
            CLUSTER,
        )
        .unwrap();
        assert!(done.is_converged());
    }

    /// M3-4: one changed block pulls one blockmap part, not the whole map.
    #[tokio::test]
    async fn i_join_m3_4_blockmap_pull_is_sparse() {
        let chunks = MemChunks::new();
        let names: Vec<String> = (0..1000).map(|index| format!("f{index:04}")).collect();
        let files: Vec<(&str, u32)> = names.iter().map(|name| (name.as_str(), 100)).collect();
        let old = make_image(100, &files, 0);
        let mut remote = old.clone();
        remote.covered_seq = Seq(200);
        let per_file = 100usize;
        let changed = 500usize;
        let at = changed * per_file + 3;
        remote.blocks[at] = ChunkId::of_plaintext(b"changed");
        let start = changed * per_file;
        remote.entries[changed].file_root =
            manifest::file_root(&remote.blocks[start..start + per_file]);
        remote.entries[changed].mtime_ns += 1;

        let (remote_manifest, blockmap) = holder_views(&remote, chunks.as_ref());
        let index = manifest::ManifestBuilder::new(chunks.as_ref(), remote.covered_seq)
            .build_blockmap(&blockmap)
            .unwrap()
            .index;
        assert_eq!(index.data_parts.len(), 4);

        let tree = MemTree::new();
        for entry in &old.entries {
            tree.insert(&entry.path, stat_of(entry));
        }
        let cache = LocalManifest {
            cluster_id: CLUSTER,
            at_seq: Seq(100),
            epoch: 1,
            manifest: Manifest::new(Seq(100), old.entries.clone()),
        };
        let plan =
            manifest::diff::plan(Some(&cache), &remote_manifest, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(plan.counts().content_diff, 1);
        assert_eq!(plan.counts().identical, 999);
        assert_eq!(plan.stats().planned_files, 1);
        assert_eq!(plan.transfers().count(), 1);

        let parts = plan.blockmap_parts(&index, &remote_manifest);
        assert_eq!(parts, vec![1]);
        assert!(parts.len() < index.data_parts.len());
    }

    /// 43 §2.3: no snapshot means the server must designate a generator.
    #[tokio::test]
    async fn i_join_without_snapshot_requests_generation() {
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let state = FakeState::new(0, make_image(0, &[], 0));
        let tree = MemTree::new();
        let notices = drive(ports(state, chunks, link.clone(), tree), None).await;
        assert!(
            notices
                .iter()
                .any(|notice| matches!(notice, SyncNotice::NeedSnapshotNow))
        );
        assert_eq!(
            phases(&notices),
            vec![SyncPhase::Handshake, SyncPhase::SnapshotSelect]
        );
        assert_eq!(*link.ended.lock().unwrap(), Some(SyncEndReason::NoPeer));
    }

    /// C-29/I2: a missing chunk and a tampered blob fail closed, and the
    /// installer never reaches the state provider.
    #[tokio::test]
    async fn i_snapshot_chunk_failures_are_typed() {
        use crate::sync::SyncError;
        use crate::sync::snapshot::Installer;

        let image = make_image(4096, &[("a", 1)], 1024);
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let reference = publish_snapshot(&image, chunks.as_ref(), link.as_ref()).await;
        let state = FakeState::new(0, make_image(0, &[], 0));
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);

        chunks.drop_chunk(ChunkId::from_bytes(reference.root_chunk_id));
        assert_eq!(
            installer.pull(&reference).await.unwrap_err(),
            SyncError::ChunkUnavailable {
                id: ChunkId::from_bytes(reference.root_chunk_id)
            }
        );
        assert_eq!(state.applied_seq(), Seq(0));
    }

    /// A tampered data blob fails the tag check and never reaches the state
    /// provider (43 I2).
    #[tokio::test]
    async fn i_snapshot_corrupt_blob_is_typed() {
        use crate::sync::SyncError;
        use crate::sync::snapshot::Installer;

        let image = make_image(4096, &[("a", 1)], 1024);
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let bundle = crate::sync::snapshot::Generator::new(
            chunks.as_ref(),
            crate::sync::test_support::holder(),
        )
        .generate(&image)
        .unwrap();
        let data_id = bundle.index.parts[0].chunks().next().unwrap();
        chunks.corrupt_blob(data_id);
        let state = FakeState::new(0, make_image(0, &[], 0));
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);

        assert_eq!(
            installer.pull(&bundle.reference).await.unwrap_err(),
            SyncError::ChunkCorrupt { id: data_id }
        );
        assert_eq!(state.applied_seq(), Seq(0));
    }
}
