//! Holder side of the manifest-only relay: answer `ManifestReq`, `DiffReq`,
//! `BlockReq`, `BlockMiss` and `Cancel`.
//!
//! Owner: client transport. See `43-sync-skeleton.md` §5.3.
//!
//! # View source
//!
//! The holder describes its own mounted tree. It prefers the
//! `<mountpoint>/.syncmount-manifest` cache (written by the JOIN), and
//! rebuilds the entry list from [`DiskTree`] when the cache is missing or no
//! longer agrees with the disk. In both cases it reads every regular file in
//! 256 KiB blocks, hashes the plaintext and ensures the sealed blob is in the
//! [`VerifiedChunkStore`], so a later `BlockReq` can serve it.
//!
//! The container sequence is the one the joiner asked for
//! (`F_SNAPSHOT_COVERED`); a holder is selected because it applied exactly
//! that sequence. The cache's own `at_seq` is therefore only a hint.
//!
//! # Wire contract
//!
//! Exactly the convention defined by [`RelaySyncLink`](crate::client::sync_link):
//!
//! ```text
//! ManifestReq  F_EXTRA = id u64 LE, F_SNAPSHOT_COVERED = at_seq (optional)
//! DiffReq      F_EXTRA = id u64 LE, F_SNAPSHOT_COVERED = at_seq
//! BlockReq     F_EXTRA = id u64 LE || kind u8, F_CHUNK_ID = chunk id
//! answer       ManifestSig, F_EXTRA = id u64 LE || payload
//!              (ManifestRef for ManifestReq, BlockmapIndexRef for DiffReq)
//! miss         BlockMiss, F_EXTRA = id u64 LE
//! block        STREAM_DATA{BLOCK}, fragments of the sealed blob
//! ```
//!
//! # Single writer
//!
//! Every answer leaves through a [`FrameSink`]: the steady-state
//! `UplinkTask` control queue, or a JOINING scoped writer. The holder never
//! opens a transport of its own.

use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use rustix::fs::{Mode, OFlags};

use crate::protocol::crypto::{KeyRing, NonceMinter, Opener, Sealer};
use crate::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
use crate::protocol::messages::{MessageError, RelaySub, WcpError, WcpWriter, fid};
use crate::protocol::{
    Flags, FrameBuf, FrameHeader, Limits, Message, MsgType, Prefix, RoutePrefix, Seq, SessionId,
    StreamId, decode_sealed,
};
use crate::store::{InodeId, Kind, RootFd};
use crate::sync::chunk::{CHUNK_BYTES, ChunkId, ChunkKind, VerifiedChunkStore};
use crate::sync::manifest::{
    Blockmap, BlockmapIndexRef, Entry, LocalManifest, Manifest, ManifestBuilder, ManifestRef,
    file_root,
};
use crate::sync::{BoxFut, ChunkSource, DiskTree, LocalTree, SyncError};

use crate::client::sync_link::{FrameSink, RelayError, flow_frame, seal_relay, split_extra};

/// Holder failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HolderError {
    /// The answer could not be sealed or written.
    #[error("relay: {0}")]
    Relay(#[from] RelayError),
    /// The local tree or container build failed.
    #[error("sync: {0}")]
    Sync(#[from] SyncError),
    /// A request body was malformed.
    #[error("message: {0}")]
    Message(#[from] MessageError),
    /// A WCP field was malformed.
    #[error("wcp: {0}")]
    Wcp(#[from] WcpError),
    /// A fragment plan failed.
    #[error("fragment: {0}")]
    Fragment(#[from] crate::protocol::FragmentError),
    /// A request lacked a required field.
    #[error("malformed relay request: {0}")]
    Malformed(&'static str),
    /// No sequenced view can be described (the holder is at seq 0).
    #[error("holder has no sequenced view to serve")]
    NoViewSeq,
    /// The request names a sequence this holder has not applied.
    #[error("requested seq {requested} is ahead of applied seq {applied}")]
    SeqAhead {
        /// Sequence the joiner asked for.
        requested: Seq,
        /// Highest sequence this holder applied.
        applied: Seq,
    },
    /// The blocking view build could not run.
    #[error("view build task failed: {0}")]
    Task(String),
}

/// The manifest and blockmap one sequence exposes.
pub struct HolderView {
    at_seq: Seq,
    manifest: Manifest,
    blockmap: Blockmap,
    manifest_ref: ManifestRef,
    blockmap_ref: BlockmapIndexRef,
}

impl fmt::Debug for HolderView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderView")
            .field("at_seq", &self.at_seq)
            .field("entries", &self.manifest.len())
            .field("blocks", &self.blockmap.block_total())
            .finish()
    }
}

impl HolderView {
    /// Sequence the containers describe.
    pub const fn at_seq(&self) -> Seq {
        self.at_seq
    }

    /// The manifest this view serves.
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The blockmap this view serves.
    pub const fn blockmap(&self) -> &Blockmap {
        &self.blockmap
    }

    /// Reference to pull the manifest.
    pub const fn manifest_ref(&self) -> &ManifestRef {
        &self.manifest_ref
    }

    /// Reference to pull the blockmap index.
    pub const fn blockmap_ref(&self) -> &BlockmapIndexRef {
        &self.blockmap_ref
    }
}

/// Answers relay requests from a mounted tree.
pub struct Holder {
    root: Arc<RootFd>,
    store: Arc<VerifiedChunkStore>,
    ring: Arc<KeyRing>,
    nonces: NonceMinter,
    cluster: crate::protocol::crypto::ClusterId,
    default_at_seq: AtomicU64,
    applied_seq: OnceLock<Arc<AtomicU64>>,
    sink: Mutex<Arc<dyn FrameSink>>,
    view: Mutex<Option<Arc<HolderView>>>,
    build_gate: tokio::sync::Mutex<()>,
    cancelled: Mutex<HashSet<u64>>,
    own_session: Option<SessionId>,
    limits: Limits,
}

impl fmt::Debug for Holder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Holder")
            .field("at_seq", &self.latest_seq())
            .field(
                "view",
                &self
                    .view
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some(),
            )
            .field(
                "cancelled",
                &self
                    .cancelled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

impl Holder {
    /// Bind the holder to a mounted tree and a frame sink.
    pub fn new(
        root: Arc<RootFd>,
        store: Arc<VerifiedChunkStore>,
        ring: Arc<KeyRing>,
        cluster: crate::protocol::crypto::ClusterId,
        at_seq: Seq,
        sink: Arc<dyn FrameSink>,
    ) -> Self {
        Self {
            root,
            store,
            ring,
            nonces: NonceMinter::with_instance(rand::random::<u64>()),
            cluster,
            default_at_seq: AtomicU64::new(at_seq.get()),
            applied_seq: OnceLock::new(),
            sink: Mutex::new(sink),
            view: Mutex::new(None),
            build_gate: tokio::sync::Mutex::new(()),
            cancelled: Mutex::new(HashSet::new()),
            own_session: None,
            limits: Limits::default(),
        }
    }

    /// Ignore frames on this client's own relay session.
    ///
    /// The server already refuses to select the requester as its own source;
    /// this guard keeps a single-process remount test from answering itself.
    pub fn with_own_session(mut self, session: SessionId) -> Self {
        self.own_session = Some(session);
        self
    }

    /// Route later answers to another writer.
    pub fn rebind(&self, sink: Arc<dyn FrameSink>) {
        *self.sink.lock().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// Track the replay pump's applied watermark.
    ///
    /// Once bound, a request without a sequence is answered at the latest
    /// applied sequence. A request that names a sequence is honoured when the
    /// holder has applied at least that far, and refused when it is ahead;
    /// the holder never labels an older tree with a future sequence.
    ///
    /// The caller passes the same atomic the status document and the
    /// watermark reader use, so no extra task is needed.
    pub fn with_applied_seq(self, applied: Arc<AtomicU64>) -> Self {
        let _ = self.applied_seq.set(applied);
        self
    }

    /// Attach the live watermark after construction.
    ///
    /// The steady-state run loop calls this once with the same atomic the
    /// status document publishes; a second call is ignored.
    pub fn track_applied_seq(&self, applied: Arc<AtomicU64>) {
        let _ = self.applied_seq.set(applied);
    }

    /// Replace the fallback sequence used when no watermark is tracked.
    pub fn set_default_at_seq(&self, at_seq: Seq) {
        self.default_at_seq.store(at_seq.get(), Ordering::Relaxed);
    }

    /// The sequence this holder would label a view with right now.
    ///
    /// May be [`Seq::UNSEQUENCED`] when nothing is tracked. Zero is a valid
    /// label for a bootstrap view: the joiner's disk is the cluster's initial
    /// state and there is no operation history behind it.
    pub fn latest_seq(&self) -> Seq {
        if let Some(applied) = self.applied_seq.get() {
            let seq = Seq(applied.load(Ordering::Relaxed));
            if seq.is_sequenced() {
                return seq;
            }
        }
        Seq(self.default_at_seq.load(Ordering::Relaxed))
    }

    /// Number of request ids marked cancelled (diagnostics and tests).
    pub fn cancelled_len(&self) -> usize {
        self.lock_cancelled().len()
    }

    fn lock_cancelled(&self) -> MutexGuard<'_, HashSet<u64>> {
        self.cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn sink(&self) -> Arc<dyn FrameSink> {
        Arc::clone(&self.sink.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Build or reuse the view for `at_seq`.
    ///
    /// # Errors
    ///
    /// [`HolderError::Sync`] when the disk cannot be described, and
    /// [`HolderError::Task`] when the blocking build panics.
    pub async fn view_for(&self, at_seq: Seq) -> Result<Arc<HolderView>, HolderError> {
        if let Some(view) = self.cached_view(at_seq) {
            return Ok(view);
        }
        let _gate = self.build_gate.lock().await;
        if let Some(view) = self.cached_view(at_seq) {
            return Ok(view);
        }
        let root = Arc::clone(&self.root);
        let store = Arc::clone(&self.store);
        let cluster = self.cluster;
        let view = tokio::task::spawn_blocking(move || {
            build_view(root.as_ref(), store.as_ref(), cluster, at_seq)
        })
        .await
        .map_err(|error| HolderError::Task(error.to_string()))??;
        let view = Arc::new(view);
        *self.view.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&view));
        Ok(view)
    }

    fn cached_view(&self, at_seq: Seq) -> Option<Arc<HolderView>> {
        self.view
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|view| view.at_seq == at_seq)
            .cloned()
    }

    /// Consume one downlink `RELAY` frame.
    ///
    /// Returns `false` for frames that are not a request this holder serves
    /// (another session, another stream, or an unopenable body).
    pub async fn deliver(&self, frame: &FrameBuf) -> Result<bool, HolderError> {
        let Some(route) = frame.prefix.as_route() else {
            return Ok(false);
        };
        if route.stream != StreamId::CTRL {
            return Ok(false);
        }
        if self.own_session == Some(route.session_id) {
            return Ok(false);
        }
        let Ok(plaintext) =
            Opener::new(self.ring.as_ref()).open(&frame.header, &frame.prefix, &frame.body)
        else {
            return Ok(false);
        };
        let Ok(Message::Relay(relay)) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &self.limits)
        else {
            return Ok(false);
        };
        // The JOIN proof exchange is not a manifest/block request. Leave it
        // to the pump's JOIN proof handler.
        if matches!(
            relay.sub,
            RelaySub::JoinProof | RelaySub::JoinAccept | RelaySub::JoinFail
        ) {
            return Ok(false);
        }
        let Some(extra) = relay.fields.get(fid::F_EXTRA) else {
            return Ok(false);
        };
        let Some((request_id, tail)) = split_extra(extra) else {
            return Ok(false);
        };

        match relay.sub {
            RelaySub::ManifestReq => {
                let at_seq = self.requested_seq(&relay.fields)?;
                let view = self.view_for(at_seq).await?;
                let payload = view.manifest_ref.encode()?;
                self.send_control(
                    route.session_id,
                    RelaySub::ManifestSig,
                    request_id,
                    &payload,
                )
                .await?;
                Ok(true)
            }
            RelaySub::DiffReq => {
                let at_seq = self.requested_seq(&relay.fields)?;
                let view = self.view_for(at_seq).await?;
                let payload = view.blockmap_ref.encode()?;
                self.send_control(
                    route.session_id,
                    RelaySub::ManifestSig,
                    request_id,
                    &payload,
                )
                .await?;
                Ok(true)
            }
            RelaySub::BlockReq => {
                let kind = tail
                    .first()
                    .copied()
                    .and_then(ChunkKind::from_wire)
                    .ok_or(HolderError::Malformed("BlockReq has no chunk kind"))?;
                let raw = relay
                    .fields
                    .get(fid::F_CHUNK_ID)
                    .ok_or(HolderError::Malformed("BlockReq has no chunk id"))?;
                let bytes: [u8; 32] = raw
                    .try_into()
                    .map_err(|_| HolderError::Malformed("BlockReq chunk id is not 32 bytes"))?;
                self.serve_block(
                    route.session_id,
                    request_id,
                    kind,
                    ChunkId::from_bytes(bytes),
                )
                .await?;
                Ok(true)
            }
            RelaySub::Cancel => {
                self.lock_cancelled().insert(request_id);
                Ok(true)
            }
            RelaySub::BlockMiss => {
                // A peer-side miss is not a request; clear any stale marker.
                self.lock_cancelled().remove(&request_id);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn requested_seq(
        &self,
        fields: &crate::protocol::messages::FieldMap<'_>,
    ) -> Result<Seq, HolderError> {
        let requested = fields.u64(fid::F_SNAPSHOT_COVERED)?.map(Seq);
        let applied = self
            .applied_seq
            .get()
            .map(|applied| Seq(applied.load(Ordering::Relaxed)))
            .filter(|seq| seq.is_sequenced());
        match (requested, applied) {
            // The holder applied past the requested view: serve the label the
            // joiner asked for. The extra applied state is invisible to the
            // container; a later op is replayed from the requested watermark.
            (Some(requested), Some(applied)) if requested <= applied => Ok(requested),
            // The holder has not reached the requested sequence; describing
            // its older tree with that label would lie.
            (Some(requested), Some(applied)) => Err(HolderError::SeqAhead { requested, applied }),
            // No live tracker: the explicit request is the only authority.
            (Some(requested), None) => Ok(requested),
            // No request: label the current tree with the live watermark.
            (None, Some(applied)) => Ok(applied),
            // Nothing is sequenced; do not fall back to zero.
            (None, None) => {
                let default = Seq(self.default_at_seq.load(Ordering::Relaxed));
                if default.is_sequenced() {
                    Ok(default)
                } else {
                    Err(HolderError::NoViewSeq)
                }
            }
        }
    }

    async fn send_control(
        &self,
        session: SessionId,
        sub: RelaySub,
        request_id: u64,
        payload: &[u8],
    ) -> Result<(), HolderError> {
        let mut extra = request_id.to_le_bytes().to_vec();
        extra.extend_from_slice(payload);
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, sub.as_u8());
        writer.bytes(fid::F_EXTRA, &extra);
        let body = writer.finish()?;
        let frame = seal_relay(self.ring.as_ref(), &self.nonces, session, &body)?;
        self.sink().send_frame(frame).await?;
        Ok(())
    }

    async fn serve_block(
        &self,
        session: SessionId,
        request_id: u64,
        kind: ChunkKind,
        id: ChunkId,
    ) -> Result<(), HolderError> {
        // A Cancel for a reused id must not poison this request.
        self.lock_cancelled().remove(&request_id);
        let blob = match self.store.get_blob(kind, &id) {
            Ok(Some(blob)) => blob,
            _ => {
                self.send_control(session, RelaySub::BlockMiss, request_id, &[])
                    .await?;
                return Ok(());
            }
        };
        let sink = self.sink();
        let fragmenter = Fragmenter::new(session, StreamId::BLOCK, blob.len() as u64)?;
        let total = fragmenter.total_chunks();
        for index in 0..total {
            if self.take_cancelled(request_id) {
                break;
            }
            let length = fragmenter.chunk_len(index)?;
            let start = index as usize * CHUNK_PLAIN;
            let end = start + length;
            let frame = seal_stream(
                self.ring.as_ref(),
                &self.nonces,
                session,
                index,
                total,
                &blob[start..end],
            )?;
            let wire_len = frame.header.len;
            sink.send_frame(frame).await?;
            if let Some(flow) = flow_frame(session, wire_len)? {
                sink.send_frame(flow).await?;
            }
        }
        Ok(())
    }

    fn take_cancelled(&self, request_id: u64) -> bool {
        self.lock_cancelled().remove(&request_id)
    }
}

/// Seal one `STREAM_DATA{BLOCK}` fragment.
fn seal_stream(
    ring: &KeyRing,
    nonces: &NonceMinter,
    session: SessionId,
    index: u32,
    total: u32,
    data: &[u8],
) -> Result<FrameBuf, RelayError> {
    let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::BLOCK, index, total));
    let mut header = FrameHeader::new(
        MsgType::STREAM_DATA,
        Flags::ENC.with(Flags::ROUTED),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = Sealer::new(ring, nonces).seal(&mut header, &prefix, data)?;
    Ok(FrameBuf::new(header, prefix, sealed.into_vec()))
}

/// Adapter used only by [`ManifestBuilder`]; the holder's store is local.
struct StoreChunks<'a> {
    store: &'a VerifiedChunkStore,
}

impl fmt::Debug for StoreChunks<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreChunks")
            .finish_non_exhaustive()
    }
}

impl ChunkSource for StoreChunks<'_> {
    fn put(&self, kind: ChunkKind, plain: &[u8]) -> Result<ChunkId, SyncError> {
        let (id, _) = self
            .store
            .put_plaintext(kind, plain)
            .map_err(|error| SyncError::Io(format!("chunk store put: {error}")))?;
        Ok(id)
    }

    fn fetch(&self, kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>> {
        Box::pin(async move {
            match self.store.get(kind, &id) {
                Ok(Some(plaintext)) => Ok(plaintext.to_vec()),
                Ok(None) => Err(SyncError::ChunkUnavailable { id }),
                Err(_) => Err(SyncError::ChunkCorrupt { id }),
            }
        })
    }
}

/// Build the manifest and blockmap for `at_seq`.
fn build_view(
    root: &RootFd,
    store: &VerifiedChunkStore,
    cluster: crate::protocol::crypto::ClusterId,
    at_seq: Seq,
) -> Result<HolderView, SyncError> {
    let rows = match LocalManifest::load(root, cluster) {
        Some(cache) if cache_matches_disk(root, cluster, cache.manifest.entries()) => {
            match blocks_from_entries(root, store, cache.manifest.entries()) {
                Ok(rows) => rows,
                Err(_) => scan_tree(root, store, cluster)?,
            }
        }
        _ => scan_tree(root, store, cluster)?,
    };

    let mut entries = Vec::with_capacity(rows.len());
    let mut blocks = Vec::new();
    let mut first = Vec::with_capacity(rows.len());
    let mut total = 0u32;
    for (entry, ids) in rows {
        first.push(total);
        total = total
            .checked_add(entry.block_count)
            .ok_or(SyncError::Format("block count overflows u32"))?;
        blocks.extend_from_slice(&ids);
        entries.push(entry);
    }
    if usize::try_from(total).ok() != Some(blocks.len()) {
        return Err(SyncError::Format("block map disagrees with entries"));
    }

    let manifest = Manifest::try_new(at_seq, entries)?;
    let blockmap = Blockmap::new(at_seq, first, blocks)?;
    let chunks = StoreChunks { store };
    let builder = ManifestBuilder::new(&chunks, at_seq);
    let manifest_ref = builder.build(&manifest)?;
    let build = builder.build_blockmap(&blockmap)?;
    Ok(HolderView {
        at_seq,
        manifest,
        blockmap,
        manifest_ref,
        blockmap_ref: build.reference,
    })
}

/// True when the cache still describes every path the disk has.
///
/// The cache is written at JOIN time, but the mounted tree keeps changing.
/// A new file would otherwise be missing from the served manifest, and a
/// changed metadata field would be stale. Any disagreement sends the holder
/// through the full rebuild.
fn cache_matches_disk(
    root: &RootFd,
    cluster: crate::protocol::crypto::ClusterId,
    entries: &[Entry],
) -> bool {
    let tree = DiskTree::new(root, Some(cluster));
    let Ok(walked) = tree.walk() else {
        return false;
    };
    if walked.len() != entries.len() {
        return false;
    }
    walked.iter().zip(entries).all(|((path, stat), entry)| {
        path == &entry.path
            && stat.kind == entry.kind
            && stat.size == entry.size
            && stat.mtime_ns == entry.mtime_ns
            && stat.mode == entry.mode
            && stat.uid == entry.uid
            && stat.gid == entry.gid
            && stat.target.as_deref().unwrap_or("") == entry.target
    })
}

/// Reuse the cached entry list, verifying it against the disk.
fn blocks_from_entries(
    root: &RootFd,
    store: &VerifiedChunkStore,
    entries: &[Entry],
) -> Result<Vec<(Entry, Vec<ChunkId>)>, SyncError> {
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.kind != Kind::File {
            rows.push((entry.clone(), Vec::new()));
            continue;
        }
        let (ids, size) = read_file_blocks(root, store, &entry.path)?;
        if size != entry.size || file_root(&ids) != entry.file_root {
            return Err(SyncError::Local(format!(
                "manifest cache disagrees with disk: {}",
                entry.path
            )));
        }
        rows.push((entry.clone(), ids));
    }
    Ok(rows)
}

/// Describe the whole tree from disk.
fn scan_tree(
    root: &RootFd,
    store: &VerifiedChunkStore,
    cluster: crate::protocol::crypto::ClusterId,
) -> Result<Vec<(Entry, Vec<ChunkId>)>, SyncError> {
    let tree = DiskTree::new(root, Some(cluster));
    let walked = tree.walk()?;
    let mut rows = Vec::with_capacity(walked.len());
    for (path, stat) in walked {
        let inode = inode_for(&path);
        let row = match stat.kind {
            Kind::Dir => (
                Entry::dir(path, inode, stat.mode, stat.uid, stat.gid, stat.mtime_ns),
                Vec::new(),
            ),
            Kind::Symlink => (
                Entry::symlink(
                    path,
                    inode,
                    stat.uid,
                    stat.gid,
                    stat.mtime_ns,
                    stat.target.unwrap_or_default(),
                ),
                Vec::new(),
            ),
            Kind::File => {
                let (ids, size) = read_file_blocks(root, store, &path)?;
                if size != stat.size {
                    return Err(SyncError::Local(format!(
                        "{path} changed while the manifest was rebuilt"
                    )));
                }
                (
                    Entry::file(
                        path,
                        inode,
                        stat.mode,
                        stat.uid,
                        stat.gid,
                        size,
                        stat.mtime_ns,
                        &ids,
                    ),
                    ids,
                )
            }
            other => (
                Entry::special(
                    path,
                    other,
                    inode,
                    stat.mode,
                    stat.uid,
                    stat.gid,
                    stat.size,
                    stat.mtime_ns,
                ),
                Vec::new(),
            ),
        };
        rows.push(row);
    }
    Ok(rows)
}

/// Stable pseudo-inode for a rebuilt view.
fn inode_for(path: &str) -> InodeId {
    let digest = blake3::hash(path.as_bytes());
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[..16]);
    InodeId::from_bytes(raw)
}

/// Read one regular file in 256 KiB blocks and ensure each blob is stored.
fn read_file_blocks(
    root: &RootFd,
    store: &VerifiedChunkStore,
    path: &str,
) -> Result<(Vec<ChunkId>, u64), SyncError> {
    let fd = root
        .open_at(
            Path::new(path),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(SyncError::from)?;
    let mut file = std::fs::File::from(fd);
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut ids = Vec::new();
    let mut size = 0u64;
    loop {
        let mut filled = 0usize;
        while filled < CHUNK_BYTES {
            let read = file
                .read(&mut buffer[filled..])
                .map_err(|error| SyncError::Io(error.to_string()))?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        let plain = &buffer[..filled];
        let id = ChunkId::of_plaintext(plain);
        if !store.has(ChunkKind::File, &id) {
            store
                .put_plaintext(ChunkKind::File, plain)
                .map_err(|error| SyncError::Io(format!("chunk store: {error}")))?;
        }
        ids.push(id);
        size = size.saturating_add(filled as u64);
        if filled < CHUNK_BYTES {
            break;
        }
    }
    Ok((ids, size))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use tempfile::TempDir;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::client::chunk_source::RelayChunkSource;
    use crate::client::sync_link::RelaySyncLink;
    use crate::protocol::crypto::{ClusterId, KeyRing};
    use crate::sync::SyncLink;
    use crate::sync::config;
    use crate::sync::manifest::{ManifestService, PartReader};

    const KEY: [u8; 32] = [0x42; 32];
    const CLUSTER: ClusterId = ClusterId::from_bytes([9u8; 16]);
    const SESSION: SessionId = SessionId::new(0x9001);

    fn ring() -> Arc<KeyRing> {
        Arc::new(KeyRing::derive(&[7u8; 32], &CLUSTER).expect("derive key ring"))
    }

    fn temp_root(tag: &str) -> (TempDir, Arc<RootFd>) {
        let tmp = TempDir::new().unwrap_or_else(|error| panic!("tempdir {tag}: {error}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|error| panic!("mkdir {tag}: {error}"));
        let root = Arc::new(
            RootFd::open_before_mount(&mount).unwrap_or_else(|error| panic!("root {tag}: {error}")),
        );
        (tmp, root)
    }

    fn store(root: &Arc<RootFd>) -> Arc<VerifiedChunkStore> {
        Arc::new(
            VerifiedChunkStore::open(Arc::clone(root), KEY)
                .unwrap_or_else(|error| panic!("store: {error}")),
        )
    }

    struct Harness {
        holder: Arc<Holder>,
        link: Arc<RelaySyncLink>,
        chunks: Arc<RelayChunkSource>,
        holder_store: Arc<VerifiedChunkStore>,
        _root: TempDir,
        _holder_root: Arc<RootFd>,
        _joiner: TempDir,
        _joiner_root: Arc<RootFd>,
        tasks: Mutex<Vec<JoinHandle<()>>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            for task in self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain(..)
            {
                task.abort();
            }
        }
    }

    impl Harness {
        async fn new(seed: &[u8]) -> Self {
            Self::with_applied(seed, None).await
        }

        async fn with_applied(seed: &[u8], applied: Option<Arc<AtomicU64>>) -> Self {
            let (root, root_fd) = temp_root("holder");
            let mount = root.path().join("mnt");
            std::fs::create_dir(mount.join("dir")).expect("mkdir dir");
            std::fs::write(mount.join("hello.txt"), seed).expect("write hello");
            std::fs::write(mount.join("dir/empty"), b"").expect("write empty");
            std::os::unix::fs::symlink("hello.txt", mount.join("link")).expect("symlink");
            let holder_store = store(&root_fd);

            let (joiner_tmp, joiner_root) = temp_root("joiner");
            let joiner_store = store(&joiner_root);

            let ring = ring();
            let (holder_tx, mut holder_rx) = mpsc::channel::<FrameBuf>(128);
            let (joiner_tx, mut joiner_rx) = mpsc::channel::<FrameBuf>(128);
            let mut holder = Holder::new(
                Arc::clone(&root_fd),
                Arc::clone(&holder_store),
                Arc::clone(&ring),
                CLUSTER,
                Seq(7),
                Arc::new(holder_tx),
            );
            if let Some(applied) = applied {
                holder = holder.with_applied_seq(applied);
            }
            let holder = Arc::new(holder);
            let link = Arc::new(RelaySyncLink::new(
                Arc::new(joiner_tx),
                Arc::clone(&ring),
                SESSION,
            ));

            let holder_for_requests = Arc::clone(&holder);
            let requests = tokio::spawn(async move {
                while let Some(frame) = joiner_rx.recv().await {
                    if let Err(error) = holder_for_requests.deliver(&frame).await {
                        panic!("holder: {error}");
                    }
                }
            });
            let link_for_answers = Arc::clone(&link);
            let answers = tokio::spawn(async move {
                while let Some(frame) = holder_rx.recv().await {
                    match frame.header.msg_type {
                        MsgType::RELAY => {
                            link_for_answers.deliver(&frame);
                        }
                        MsgType::STREAM_DATA => {
                            link_for_answers
                                .deliver_stream(&frame)
                                .await
                                .expect("deliver stream");
                        }
                        _ => {}
                    }
                }
            });

            let chunks = Arc::new(RelayChunkSource::new(Arc::clone(&link), joiner_store));
            Self {
                holder,
                link,
                chunks,
                holder_store,
                _root: root,
                _holder_root: root_fd,
                _joiner: joiner_tmp,
                _joiner_root: joiner_root,
                tasks: Mutex::new(vec![requests, answers]),
            }
        }
    }

    async fn read_index(
        chunks: &dyn ChunkSource,
        reference: &BlockmapIndexRef,
    ) -> crate::sync::manifest::BlockmapIndex {
        let reader = PartReader::new(chunks, ChunkKind::Blockmap, config::BLOCKMAP_INDEX_MAGIC);
        let mut stream = Vec::new();
        for desc in &reference.parts {
            stream.extend_from_slice(
                &reader
                    .read(reference.at_seq, desc)
                    .await
                    .expect("index part"),
            );
        }
        crate::sync::manifest::BlockmapIndex::decode(&stream).expect("index")
    }

    async fn read_ids(
        chunks: &dyn ChunkSource,
        at_seq: Seq,
        desc: &crate::sync::PartDesc,
    ) -> Vec<ChunkId> {
        let reader = PartReader::new(chunks, ChunkKind::Blockmap, config::BLOCKMAP_PART_MAGIC);
        let payload = reader.read(at_seq, desc).await.expect("blockmap part");
        payload
            .chunks_exact(32)
            .map(|raw| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(raw);
                ChunkId::from_bytes(bytes)
            })
            .collect()
    }

    #[tokio::test]
    async fn u_holder_manifest_blockmap_and_block_roundtrip() {
        let data = vec![0x5a; CHUNK_BYTES + 100];
        let harness = Harness::new(&data).await;
        assert!(
            LocalManifest::load(harness._holder_root.as_ref(), CLUSTER).is_none(),
            "the test must exercise the rebuild path"
        );

        let reference = harness
            .link
            .request_manifest(Some(Seq(7)))
            .await
            .expect("manifest ref");
        assert_eq!(reference.at_seq, Seq(7));
        let manifest = ManifestService::read_manifest(harness.chunks.as_ref(), &reference)
            .await
            .expect("manifest");
        let entry = manifest
            .entries()
            .iter()
            .find(|entry| entry.path == "hello.txt")
            .expect("hello.txt");
        assert_eq!(entry.block_count, 2);

        let index_ref = harness
            .link
            .request_blockmap_index(Seq(7))
            .await
            .expect("index ref");
        let index = read_index(harness.chunks.as_ref(), &index_ref).await;
        assert_eq!(index.at_seq, Seq(7));
        assert_eq!(index.block_total, 2);
        let ids = read_ids(harness.chunks.as_ref(), Seq(7), &index.data_parts[0]).await;
        assert_eq!(ids.len(), 2);

        let first = harness
            .chunks
            .fetch(ChunkKind::File, ids[0])
            .await
            .expect("first block");
        assert_eq!(first.as_slice(), &data[..CHUNK_BYTES]);
        let second = harness
            .chunks
            .fetch(ChunkKind::File, ids[1])
            .await
            .expect("second block");
        assert_eq!(second.as_slice(), &data[CHUNK_BYTES..]);
    }

    #[tokio::test]
    async fn u_holder_uses_cached_manifest_entries() {
        let data = vec![0x33; 4096];
        let harness = Harness::new(&data).await;
        // Build a cache that matches the disk exactly, so the holder takes
        // the cached path instead of the rebuild path.
        let rows = scan_tree(
            harness._holder_root.as_ref(),
            harness.holder_store.as_ref(),
            CLUSTER,
        )
        .expect("scan");
        let entries: Vec<Entry> = rows.into_iter().map(|(entry, _)| entry).collect();
        let manifest = Manifest::try_new(Seq(6), entries).expect("manifest");
        LocalManifest {
            cluster_id: CLUSTER,
            at_seq: Seq(6),
            epoch: 1,
            manifest,
        }
        .store(harness._holder_root.as_ref())
        .expect("store cache");
        assert!(LocalManifest::load(harness._holder_root.as_ref(), CLUSTER).is_some());

        let reference = harness
            .link
            .request_manifest(Some(Seq(7)))
            .await
            .expect("manifest ref");
        assert_eq!(reference.at_seq, Seq(7));
        let manifest = ManifestService::read_manifest(harness.chunks.as_ref(), &reference)
            .await
            .expect("manifest");
        let entry = manifest
            .entries()
            .iter()
            .find(|entry| entry.path == "hello.txt")
            .expect("hello.txt");
        assert_eq!(entry.block_count, 1);
        assert_eq!(entry.file_root, file_root(&[ChunkId::of_plaintext(&data)]));
    }

    #[tokio::test]
    async fn u_holder_block_miss_for_absent_chunk() {
        let harness = Harness::new(b"present").await;
        let absent = ChunkId::of_plaintext(b"absent");
        let error = harness
            .link
            .request_block_blob(ChunkKind::File, absent)
            .await
            .expect_err("missing chunk");
        assert!(matches!(error, RelayError::BlockMiss));
    }

    #[tokio::test]
    async fn u_holder_cancel_is_cleared_by_the_next_request() {
        let data = b"cancelled then served".to_vec();
        let harness = Harness::new(&data).await;
        // Populate the holder's store and learn the chunk id.
        let reference = harness
            .link
            .request_manifest(Some(Seq(7)))
            .await
            .expect("manifest ref");
        let _ = ManifestService::read_manifest(harness.chunks.as_ref(), &reference)
            .await
            .expect("manifest");
        let id = ChunkId::of_plaintext(&data);
        assert!(harness.holder_store.has(ChunkKind::File, &id));

        // Cancel id 5, then issue a BlockReq that reuses it.
        let ring = ring();
        let cancel = manual_request(&ring, RelaySub::Cancel, 5, &[]);
        assert!(harness.holder.deliver(&cancel).await.expect("cancel"));
        assert_eq!(harness.holder.cancelled_len(), 1);
        let mut block = WcpWriter::new();
        block.u8(fid::F_SUB_KIND, RelaySub::BlockReq.as_u8());
        let mut extra = 5u64.to_le_bytes().to_vec();
        extra.push(ChunkKind::File.wire());
        block.bytes(fid::F_EXTRA, &extra);
        block.bytes(fid::F_CHUNK_ID, id.as_bytes());
        let frame = sealed_body(&ring, SESSION, &block.finish().expect("body"));
        assert!(harness.holder.deliver(&frame).await.expect("block"));
        assert_eq!(harness.holder.cancelled_len(), 0);
    }

    #[tokio::test]
    async fn u_holder_tracks_the_applied_watermark() {
        let applied = Arc::new(AtomicU64::new(7));
        let harness = Harness::with_applied(b"watermark", Some(Arc::clone(&applied))).await;
        let first = harness
            .link
            .request_manifest(None)
            .await
            .expect("manifest at 7");
        assert_eq!(first.at_seq, Seq(7));

        applied.store(9, Ordering::Relaxed);
        let second = harness
            .link
            .request_manifest(None)
            .await
            .expect("manifest at 9");
        assert_eq!(second.at_seq, Seq(9));

        // An explicit older request is honoured: the joiner asked for the
        // view it knows, and this holder has applied past it.
        let third = harness
            .link
            .request_manifest(Some(Seq(5)))
            .await
            .expect("manifest at the requested seq");
        assert_eq!(third.at_seq, Seq(5));
    }

    #[tokio::test]
    async fn u_holder_sequence_rules() {
        // requested=15, applied=0 (unsequenced tracker): the request wins.
        let zero = Harness::with_applied(b"seq-zero", Some(Arc::new(AtomicU64::new(0)))).await;
        let reference = zero
            .link
            .request_manifest(Some(Seq(15)))
            .await
            .expect("requested seq with an unsequenced tracker");
        assert_eq!(reference.at_seq, Seq(15));

        // requested=15, applied=16: the holder has applied past the view.
        let applied = Arc::new(AtomicU64::new(16));
        let harness = Harness::with_applied(b"seq-sixteen", Some(Arc::clone(&applied))).await;
        let reference = harness
            .link
            .request_manifest(Some(Seq(15)))
            .await
            .expect("requested seq behind the applied watermark");
        assert_eq!(reference.at_seq, Seq(15));

        // requested=20, applied=16: the holder has not applied it.
        let ring = ring();
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::ManifestReq.as_u8());
        writer.bytes(fid::F_EXTRA, &1u64.to_le_bytes());
        writer.u64(fid::F_SNAPSHOT_COVERED, 20);
        let frame = sealed_body(&ring, SESSION, &writer.finish().expect("body"));
        let error = harness
            .holder
            .deliver(&frame)
            .await
            .expect_err("a future seq must be refused");
        assert!(matches!(
            error,
            HolderError::SeqAhead {
                requested: Seq(20),
                applied: Seq(16)
            }
        ));

        // default=0 and no tracker: zero is a valid bootstrap label, but an
        // unlabelled request still has no sequence to answer with.
        let sink: Arc<dyn FrameSink> = Arc::new(mpsc::channel::<FrameBuf>(4).0);
        let holder = Holder::new(
            Arc::clone(&harness._holder_root),
            Arc::clone(&harness.holder_store),
            ring,
            CLUSTER,
            Seq::UNSEQUENCED,
            sink,
        );
        let view = holder
            .view_for(Seq::UNSEQUENCED)
            .await
            .expect("zero is a bootstrap label");
        assert_eq!(view.at_seq(), Seq::UNSEQUENCED);
        let frame = manual_request(
            &KeyRing::derive(&[7u8; 32], &CLUSTER).expect("ring"),
            RelaySub::ManifestReq,
            2,
            &[],
        );
        let error = holder
            .deliver(&frame)
            .await
            .expect_err("no default seq to describe");
        assert!(matches!(error, HolderError::NoViewSeq));
    }

    /// A sequence-zero view describes the disk and can be served to a
    /// joiner. Nothing in the containers requires a positive sequence.
    #[tokio::test]
    async fn u_holder_serves_a_sequence_zero_bootstrap_view() {
        let harness = Harness::new(b"bootstrap").await;
        let view = harness
            .holder
            .view_for(Seq::UNSEQUENCED)
            .await
            .expect("a zero view");
        assert_eq!(view.at_seq(), Seq::UNSEQUENCED);
        assert_eq!(view.manifest().at_seq, Seq::UNSEQUENCED);
        assert!(view.manifest().find("hello.txt").is_some());
        assert!(view.manifest().len() >= 4);
        assert_eq!(view.blockmap().at_seq(), Seq::UNSEQUENCED);
    }

    #[tokio::test]
    async fn u_holder_passes_join_frames_to_the_pump() {
        let harness = Harness::new(b"join-frames").await;
        let ring = ring();
        for sub in [
            RelaySub::JoinProof,
            RelaySub::JoinAccept,
            RelaySub::JoinFail,
        ] {
            let mut writer = WcpWriter::new();
            writer.u8(fid::F_SUB_KIND, sub.as_u8());
            writer.bytes(fid::F_CLIENT_NONCE, &[1u8; 32]);
            writer.bytes(fid::F_SERVER_NONCE, &[2u8; 32]);
            writer.bytes(fid::F_PROOF, &[3u8; 16]);
            let frame = sealed_body(
                &ring,
                SessionId::new(0x7777),
                &writer.finish().expect("body"),
            );
            assert!(
                !harness.holder.deliver(&frame).await.expect("deliver"),
                "{sub:?} must reach the pump"
            );
        }
    }

    #[tokio::test]
    async fn u_holder_ignores_its_own_session() {
        let harness = Harness::new(b"own").await;
        let ring = ring();
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::ManifestReq.as_u8());
        writer.bytes(fid::F_EXTRA, &1u64.to_le_bytes());
        let frame = sealed_body(&ring, SESSION, &writer.finish().expect("body"));
        let holder = Holder::new(
            Arc::clone(&harness._holder_root),
            Arc::clone(&harness.holder_store),
            ring,
            CLUSTER,
            Seq(7),
            Arc::new(mpsc::channel::<FrameBuf>(4).0),
        )
        .with_own_session(SESSION);
        assert!(!holder.deliver(&frame).await.expect("ignored"));
    }

    #[test]
    fn u_holder_block_boundaries_do_not_add_empty_blocks() {
        let (tmp, root) = temp_root("boundary");
        let mount = tmp.path().join("mnt");
        std::fs::write(mount.join("exact"), vec![0u8; CHUNK_BYTES * 2]).expect("write");
        let store = store(&root);
        let (ids, size) = read_file_blocks(&root, &store, "exact").expect("read");
        assert_eq!(size, (CHUNK_BYTES * 2) as u64);
        assert_eq!(ids.len(), 2);
        assert!(read_file_blocks(&root, &store, "absent").is_err());
    }

    fn sealed_body(ring: &KeyRing, session: SessionId, body: &[u8]) -> FrameBuf {
        seal_relay(
            ring,
            &NonceMinter::with_instance(rand::random::<u64>()),
            session,
            body,
        )
        .expect("seal")
    }

    fn manual_request(ring: &KeyRing, sub: RelaySub, id: u64, payload: &[u8]) -> FrameBuf {
        let mut extra = id.to_le_bytes().to_vec();
        extra.extend_from_slice(payload);
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, sub.as_u8());
        writer.bytes(fid::F_EXTRA, &extra);
        sealed_body(ring, SESSION, &writer.finish().expect("body"))
    }
}
