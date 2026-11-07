//! Relay control link: `RELAY{CTRL}` requests, answers and block streams.
//!
//! Owner: client transport. See `43-sync-skeleton.md` §5.3 and the JOIN
//! manifest-only path in `.pi/goals`.
//!
//! # One session, many requests
//!
//! The server opens one relay slot per `session_id` and picks the peer once
//! (42 §5.5). Opening a second slot while the first is live is the client's
//! only way to say "this source is bad", and it spends the frozen retry
//! budget. This link therefore reuses a single [`SessionId`] for every
//! request of one JOIN and closes it once with `SYNC_END`.
//!
//! # Pairing
//!
//! A request and its answer share the session; a monotonically increasing
//! request id inside the sealed `RELAY` body disambiguates concurrent
//! requests and stale answers:
//!
//! ```text
//! request  F_SUB_KIND = ManifestReq | DiffReq | BlockReq | Cancel
//!          F_EXTRA    = request_id u64 LE [|| chunk kind u8, BlockReq only]
//!          ManifestReq  F_SNAPSHOT_COVERED = at_seq, omitted for "current"
//!          DiffReq      F_SNAPSHOT_COVERED = at_seq
//!          BlockReq     F_CHUNK_ID = BLAKE3(plaintext)
//! answer   F_SUB_KIND = ManifestSig
//!          F_EXTRA    = request_id u64 LE || payload
//!          payload    = ManifestRef::encode() for ManifestReq,
//!                       BlockmapIndexRef::encode() for DiffReq
//! miss     F_SUB_KIND = BlockMiss, F_EXTRA = request_id u64 LE
//! ```
//!
//! A `BlockReq` answer is a `STREAM_DATA{BLOCK}` stream on the same session.
//! The route prefix has no request id, so only one block stream may be in
//! flight at a time; [`RelaySyncLink::request_block_blob`] serializes them.
//! The reassembled bytes are the sealed **blob** (`nonce || ciphertext ||
//! tag`), which the chunk source verifies with `put_blob` before use.
//!
//! # Delivery
//!
//! The downlink owns the read side. Its consumer calls
//! [`RelaySyncLink::deliver`] for every [`DownlinkItem::Relay`] and
//! [`RelaySyncLink::deliver_stream`] for every [`DownlinkItem::StreamData`].
//! Both return `false` when the frame belongs to another session (the JOIN
//! proof uses its own), so a dispatcher can keep its existing handlers.
//!
//! # Timeouts
//!
//! A request has no absolute deadline. It fails only when no `RELAY` or
//! `STREAM_DATA` frame for this session arrives for
//! [`DEFAULT_PROGRESS_TIMEOUT`]; an answer that keeps delivering bytes never
//! times out, however slow it is.
//!
//! [`DownlinkItem::Relay`]: crate::client::net::downlink::DownlinkItem::Relay
//! [`DownlinkItem::StreamData`]: crate::client::net::downlink::DownlinkItem::StreamData

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use crate::protocol::crypto::{CryptoError, KeyRing, NonceMinter, Opener, Sealer};
use crate::protocol::fragment::CHUNK_PLAIN;
use crate::protocol::messages::{
    MessageError, RelaySub, SnapshotRef, SyncEnd, WcpError, WcpWriter, Welcome, fid,
};
use crate::protocol::{
    Flags, Flow, FrameBuf, FrameHeader, Limits, Message, MsgType, Prefix, RoutePrefix, Seq,
    SessionId, StreamId, decode_sealed,
};
use crate::sync::chunk::{ChunkId, ChunkKind, MAX_BLOB_BYTES};
use crate::sync::manifest::{BlockmapIndexRef, ManifestRef};
use crate::sync::{BoxFut, SyncEndReason, SyncError, SyncLink};

/// Default no-progress window: a request fails after this long without a
/// frame for its own relay session.
pub const DEFAULT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline for a best-effort `CANCEL`; a dead peer must not stall teardown.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(1);

/// Out-of-order fragments buffered per block stream.
const REORDER_CHUNKS: usize = 8;
/// Out-of-order bytes buffered per block stream.
const REORDER_BYTES: usize = 8 * CHUNK_PLAIN;

/// Length of the request id inside `F_EXTRA`.
const REQUEST_ID_LEN: usize = 8;

/// Where sealed relay frames are written.
///
/// The two implementations are the steady-state [`UplinkTask`] control queue
/// and the JOINING [`ScopedUplink`](crate::client::net::scoped::ScopedUplink) handle. The
/// link never owns a transport, so the single-writer rule stays intact.
///
/// [`UplinkTask`]: crate::client::net::uplink::UplinkTask
pub trait FrameSink: Send + Sync + fmt::Debug {
    /// Write one complete frame.
    fn send_frame(&self, frame: FrameBuf) -> BoxFut<'_, Result<(), RelayError>>;
}

impl FrameSink for mpsc::Sender<FrameBuf> {
    fn send_frame(&self, frame: FrameBuf) -> BoxFut<'_, Result<(), RelayError>> {
        Box::pin(async move { self.send(frame).await.map_err(|_| RelayError::Closed) })
    }
}

/// Relay request/answer failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The link or its writer is gone.
    #[error("relay link is closed")]
    Closed,
    /// No frame for the request's session arrived for the whole window.
    #[error("relay request {id} timed out after {after:?}")]
    Timeout {
        /// Request id.
        id: u64,
        /// Window that elapsed without a frame.
        after: Duration,
    },
    /// The peer answered `BLOCK_MISS`.
    #[error("peer reported BLOCK_MISS")]
    BlockMiss,
    /// A block stream was malformed or overflowed its bounds.
    #[error("block stream: {0}")]
    Block(String),
    /// A frame was not a legal relay frame.
    #[error("protocol: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    /// A sealed message body was invalid.
    #[error("message: {0}")]
    Message(#[from] MessageError),
    /// AEAD authentication failed.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// WCP encoding failed.
    #[error("wcp: {0}")]
    Wcp(#[from] WcpError),
    /// The underlying writer refused the frame.
    #[error("uplink: {0}")]
    Uplink(String),
}

impl RelayError {
    /// A transient condition: retrying the JOIN may succeed.
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }
}

impl From<RelayError> for SyncError {
    fn from(error: RelayError) -> Self {
        if error.is_transient() {
            Self::Link(format!("transient: {error}"))
        } else {
            Self::Link(error.to_string())
        }
    }
}

/// One pending control answer.
struct Pending {
    request: RelaySub,
    tx: oneshot::Sender<Vec<u8>>,
}

/// One in-flight block stream.
struct BlockRequest {
    id: u64,
    assembler: BlockAssembler,
    tx: oneshot::Sender<Result<Vec<u8>, RelayError>>,
}

#[derive(Default)]
struct BlockSlot {
    request: Option<BlockRequest>,
}

struct Inner {
    sink: Mutex<Arc<dyn FrameSink>>,
    ring: Arc<KeyRing>,
    nonces: NonceMinter,
    session: SessionId,
    limits: Limits,
    timeout: Duration,
    progress: watch::Sender<u64>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
    block: Mutex<BlockSlot>,
    block_gate: tokio::sync::Mutex<()>,
    closed: AtomicBool,
}

impl Inner {
    fn lock_pending(&self) -> MutexGuard<'_, HashMap<u64, Pending>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_block(&self) -> MutexGuard<'_, BlockSlot> {
        self.block.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sink(&self) -> Arc<dyn FrameSink> {
        Arc::clone(&self.sink.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn next_id(&self) -> u64 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

/// Removes a pending control entry even when the caller's future is dropped.
struct PendingGuard {
    inner: Arc<Inner>,
    id: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.inner.lock_pending().remove(&self.id);
    }
}

/// Clears the block slot when a request is cancelled or dropped.
struct BlockGuard {
    inner: Arc<Inner>,
    id: u64,
}

impl Drop for BlockGuard {
    fn drop(&mut self) {
        let mut slot = self.inner.lock_block();
        if slot
            .request
            .as_ref()
            .is_some_and(|request| request.id == self.id)
        {
            slot.request = None;
        }
    }
}

/// The `SyncLink` implementation for the relay path.
pub struct RelaySyncLink {
    inner: Arc<Inner>,
}

impl fmt::Debug for RelaySyncLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelaySyncLink")
            .field("session", &self.inner.session)
            .field("closed", &self.inner.closed.load(Ordering::Relaxed))
            .field("pending", &self.inner.lock_pending().len())
            .field("blocking", &self.inner.lock_block().request.is_some())
            .finish()
    }
}

impl RelaySyncLink {
    /// Bind the link to one relay session and one frame writer.
    pub fn new(sink: Arc<dyn FrameSink>, ring: Arc<KeyRing>, session: SessionId) -> Self {
        Self {
            inner: Arc::new(Inner {
                sink: Mutex::new(sink),
                ring,
                nonces: NonceMinter::with_instance(rand::random::<u64>()),
                session,
                limits: Limits::default(),
                timeout: DEFAULT_PROGRESS_TIMEOUT,
                progress: watch::channel(0).0,
                next_id: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                block: Mutex::new(BlockSlot::default()),
                block_gate: tokio::sync::Mutex::new(()),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Pick the session advertised by `WELCOME`.
    ///
    /// A holder-backed JOIN carries `view_session`; that token is the relay
    /// session the server routes to the holder. Without a view the link
    /// generates an id, which lets the server choose any online peer.
    pub fn from_welcome(welcome: &Welcome, sink: Arc<dyn FrameSink>, ring: Arc<KeyRing>) -> Self {
        let session = welcome
            .view_session
            .unwrap_or_else(|| SessionId::new(rand::random::<u128>()));
        Self::new(sink, ring, session)
    }

    /// Replace the no-progress window: a request fails after this long
    /// without a frame for its session.
    ///
    /// Must be called before the link is shared: the inner state is still
    /// uniquely owned at that point.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.timeout = timeout;
        }
        self
    }

    /// The relay session every frame uses.
    pub fn session(&self) -> SessionId {
        self.inner.session
    }

    /// Route later frames to another writer.
    ///
    /// The caller must stop the previous writer first: JOINING hands the RPC
    /// stream from [`ScopedUplink`](crate::client::net::scoped::ScopedUplink) to the
    /// steady-state `UplinkTask`, and only one may write at a time.
    pub fn rebind(&self, sink: Arc<dyn FrameSink>) {
        *self
            .inner
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// Whether [`RelaySyncLink::close`] already ran.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    /// Number of control requests awaiting an answer (diagnostics and tests).
    pub fn pending_len(&self) -> usize {
        self.inner.lock_pending().len()
    }

    /// Whether a block stream is in flight (diagnostics and tests).
    pub fn block_in_flight(&self) -> bool {
        self.inner.lock_block().request.is_some()
    }

    /// Consume one downlink `RELAY` frame.
    ///
    /// Returns `false` when the frame belongs to another relay session (the
    /// JOIN proof uses its own), so the caller can keep its other handlers.
    pub fn deliver(&self, frame: &FrameBuf) -> bool {
        let Some(route) = frame.prefix.as_route() else {
            return false;
        };
        if route.session_id != self.inner.session || route.stream != StreamId::CTRL {
            return false;
        }
        // Any frame for this session proves the link is alive, so it restarts
        // the no-progress clock before the body is even opened.
        self.inner
            .progress
            .send_modify(|version| *version = version.wrapping_add(1));
        let Ok(plaintext) =
            Opener::new(self.inner.ring.as_ref()).open(&frame.header, &frame.prefix, &frame.body)
        else {
            // Not ours to judge: the JOIN proof handler also opens frames and
            // must see them. Consuming an unopenable frame here would swallow
            // another client's proof and stall the joiner.
            return false;
        };
        let Ok(Message::Relay(relay)) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &self.inner.limits)
        else {
            return false;
        };
        // Join-exchange frames belong to the JOIN proof handler, even if a
        // future body carries an `F_EXTRA` field.
        if matches!(
            relay.sub,
            RelaySub::JoinProof | RelaySub::JoinAccept | RelaySub::JoinFail
        ) {
            return false;
        }
        let Some(extra) = relay.fields.get(fid::F_EXTRA) else {
            return false;
        };
        let Some((id, payload)) = split_extra(extra) else {
            return false;
        };

        match relay.sub {
            RelaySub::ManifestSig | RelaySub::ManifestReq | RelaySub::DiffReq => {
                let Some(pending) = self.inner.lock_pending().remove(&id) else {
                    return true;
                };
                // `ManifestSig` is the canonical answer; accepting the
                // request's own sub-kind lets a peer echo it instead.
                let echoed = relay.sub == pending.request;
                if relay.sub != RelaySub::ManifestSig && !echoed {
                    return true;
                }
                let _ = pending.tx.send(payload.to_vec());
                true
            }
            RelaySub::BlockMiss => {
                let mut slot = self.inner.lock_block();
                if slot
                    .request
                    .as_ref()
                    .is_some_and(|request| request.id == id)
                {
                    if let Some(request) = slot.request.take() {
                        let _ = request.tx.send(Err(RelayError::BlockMiss));
                    }
                }
                true
            }
            RelaySub::Cancel => {
                let _ = self.inner.lock_pending().remove(&id);
                let mut slot = self.inner.lock_block();
                if slot
                    .request
                    .as_ref()
                    .is_some_and(|request| request.id == id)
                {
                    if let Some(request) = slot.request.take() {
                        let _ = request.tx.send(Err(RelayError::Closed));
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Consume one downlink `STREAM_DATA` frame.
    ///
    /// Only `BLOCK` streams on this link's session are touched; write payload
    /// streams (`OP_DATA`) and other sessions return `false`.
    ///
    /// Every accepted fragment releases its wire bytes with `FLOW`, so the
    /// server's 8 MiB window never becomes a silent stall.
    pub async fn deliver_stream(&self, frame: &FrameBuf) -> Result<bool, RelayError> {
        let Some(route) = frame.prefix.as_route() else {
            return Ok(false);
        };
        if route.session_id != self.inner.session || route.stream != StreamId::BLOCK {
            return Ok(false);
        }
        // Progress is per session, not per request: even a fragment that is
        // rejected below shows the peer is still sending.
        self.inner
            .progress
            .send_modify(|version| *version = version.wrapping_add(1));
        let plaintext = Opener::new(self.inner.ring.as_ref()).open(
            &frame.header,
            &frame.prefix,
            &frame.body,
        )?;
        let wire_len = frame.header.len;
        let served = {
            let mut slot = self.inner.lock_block();
            let outcome = slot.request.as_mut().map(|request| {
                request
                    .assembler
                    .push(route.chunk_index, route.total_chunks, plaintext.as_slice())
            });
            match outcome {
                None => false,
                Some(Ok(None)) => true,
                Some(Ok(Some(blob))) => {
                    if let Some(request) = slot.request.take() {
                        let _ = request.tx.send(Ok(blob));
                    }
                    true
                }
                Some(Err(error)) => {
                    if let Some(request) = slot.request.take() {
                        let _ = request.tx.send(Err(error));
                    }
                    true
                }
            }
        };
        self.send_flow(wire_len).await?;
        Ok(served)
    }

    /// Request one chunk blob and wait for the complete `STREAM_DATA` stream.
    ///
    /// Only one block stream can be in flight on a session; concurrent calls
    /// queue on an async gate. The returned bytes are the sealed blob, not
    /// plaintext: the caller verifies them with `VerifiedChunkStore`.
    pub async fn request_block_blob(
        &self,
        kind: ChunkKind,
        id: ChunkId,
    ) -> Result<Vec<u8>, RelayError> {
        let _gate = self.inner.block_gate.lock().await;
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(RelayError::Closed);
        }
        let request_id = self.inner.next_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.inner.lock_block();
            if slot.request.is_some() {
                return Err(RelayError::Block(
                    "another block stream is active".to_owned(),
                ));
            }
            slot.request = Some(BlockRequest {
                id: request_id,
                assembler: BlockAssembler::default(),
                tx,
            });
        }
        let _guard = BlockGuard {
            inner: Arc::clone(&self.inner),
            id: request_id,
        };

        let mut extra = Vec::with_capacity(REQUEST_ID_LEN + 1);
        extra.extend_from_slice(&request_id.to_le_bytes());
        extra.push(kind.wire());
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::BlockReq.as_u8());
        writer.bytes(fid::F_EXTRA, &extra);
        writer.bytes(fid::F_CHUNK_ID, id.as_bytes());
        let body = writer.finish()?;
        let frame = seal_relay(
            self.inner.ring.as_ref(),
            &self.inner.nonces,
            self.inner.session,
            &body,
        )?;
        // Sending has no inbound progress to wait on, so it keeps an absolute
        // deadline of the same window.
        match tokio::time::timeout(self.inner.timeout, self.inner.sink().send_frame(frame)).await {
            Err(_) => {
                return Err(RelayError::Timeout {
                    id: request_id,
                    after: self.inner.timeout,
                });
            }
            Ok(Err(error)) => return Err(error),
            Ok(Ok(())) => {}
        }
        let outcome = self.await_answer(request_id, rx).await;
        match outcome {
            Err(error) => {
                if error.is_transient() {
                    self.send_cancel(request_id).await;
                }
                Err(error)
            }
            Ok(Ok(blob)) => Ok(blob),
            Ok(Err(error)) => Err(error),
        }
    }

    /// Wait for one answer, restarting the clock on every frame for this
    /// session.
    ///
    /// The progress watch is subscribed before the loop, so a bump between
    /// two iterations is still observed and cannot be lost.
    async fn await_answer<T>(
        &self,
        id: u64,
        mut rx: oneshot::Receiver<T>,
    ) -> Result<T, RelayError> {
        let timeout = self.inner.timeout;
        let mut progress = self.inner.progress.subscribe();
        let mut last = tokio::time::Instant::now();
        loop {
            let idle = last.elapsed();
            if idle >= timeout {
                return Err(RelayError::Timeout { id, after: timeout });
            }
            tokio::select! {
                biased;
                result = &mut rx => return result.map_err(|_| RelayError::Closed),
                changed = progress.changed() => {
                    if changed.is_err() {
                        return Err(RelayError::Closed);
                    }
                    last = tokio::time::Instant::now();
                }
                _ = tokio::time::sleep(timeout - idle) => {}
            }
        }
    }

    /// Write one already-sealed frame through the current sink.
    ///
    /// Used by the JOINING proof responder: the scoped writer is still the
    /// only RPC writer, and the frame leaves exactly like a request.
    pub async fn send_frame(&self, frame: FrameBuf) -> Result<(), RelayError> {
        self.inner.sink().send_frame(frame).await
    }

    /// Release relay credit for bytes the peer sent.
    pub async fn send_flow(&self, grant_bytes: u32) -> Result<(), RelayError> {
        if grant_bytes == 0 {
            return Ok(());
        }
        let body = Flow { grant_bytes }.encode()?;
        let prefix = Prefix::Route(RoutePrefix::new(self.inner.session, StreamId::CTRL, 0, 0));
        let mut header = FrameHeader::new(MsgType::FLOW, Flags::ROUTED, 0, Seq::UNSEQUENCED);
        header.len = (RoutePrefix::ENCODED_LEN + body.len()) as u32;
        self.inner
            .sink()
            .send_frame(FrameBuf::new(header, prefix, body))
            .await
    }

    /// Close the relay session and fail every pending request.
    ///
    /// Idempotent. The server removes the slot on `SYNC_END` and resets the
    /// origin's retry budget; leaving it open would make the next session
    /// look like a source change.
    pub async fn close(&self, reason: SyncEndReason) -> Result<(), RelayError> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.lock_pending().clear();
        {
            let mut slot = self.inner.lock_block();
            if let Some(request) = slot.request.take() {
                let _ = request.tx.send(Err(RelayError::Closed));
            }
        }

        let body = SyncEnd {
            reason: wire_reason(reason),
            detail: None,
        }
        .encode()?;
        let prefix = Prefix::Route(RoutePrefix::new(self.inner.session, StreamId::CTRL, 0, 0));
        let mut header = FrameHeader::new(MsgType::SYNC_END, Flags::ROUTED, 0, Seq::UNSEQUENCED);
        header.len = (RoutePrefix::ENCODED_LEN + body.len()) as u32;
        match tokio::time::timeout(
            CANCEL_TIMEOUT,
            self.inner
                .sink()
                .send_frame(FrameBuf::new(header, prefix, body)),
        )
        .await
        {
            Err(_) => Err(RelayError::Timeout {
                id: 0,
                after: CANCEL_TIMEOUT,
            }),
            Ok(result) => result,
        }
    }

    async fn request_control(
        &self,
        sub: RelaySub,
        at_seq: Option<Seq>,
    ) -> Result<Vec<u8>, RelayError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(RelayError::Closed);
        }
        let id = self.inner.next_id();
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock_pending()
            .insert(id, Pending { request: sub, tx });
        let _guard = PendingGuard {
            inner: Arc::clone(&self.inner),
            id,
        };

        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, sub.as_u8());
        writer.bytes(fid::F_EXTRA, &id.to_le_bytes());
        if let Some(seq) = at_seq {
            writer.u64(fid::F_SNAPSHOT_COVERED, seq.get());
        }
        let body = writer.finish()?;
        let frame = seal_relay(
            self.inner.ring.as_ref(),
            &self.inner.nonces,
            self.inner.session,
            &body,
        )?;
        // Sending has no inbound progress to wait on, so it keeps an absolute
        // deadline of the same window.
        match tokio::time::timeout(self.inner.timeout, self.inner.sink().send_frame(frame)).await {
            Err(_) => {
                return Err(RelayError::Timeout {
                    id,
                    after: self.inner.timeout,
                });
            }
            Ok(Err(error)) => return Err(error),
            Ok(Ok(())) => {}
        }
        let outcome = self.await_answer(id, rx).await;
        match outcome {
            Err(error) => {
                if error.is_transient() {
                    self.send_cancel(id).await;
                }
                Err(error)
            }
            Ok(payload) => Ok(payload),
        }
    }

    async fn send_cancel(&self, id: u64) {
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::Cancel.as_u8());
        writer.bytes(fid::F_EXTRA, &id.to_le_bytes());
        let Ok(body) = writer.finish() else {
            return;
        };
        let Ok(frame) = seal_relay(
            self.inner.ring.as_ref(),
            &self.inner.nonces,
            self.inner.session,
            &body,
        ) else {
            return;
        };
        let _ = tokio::time::timeout(CANCEL_TIMEOUT, self.inner.sink().send_frame(frame)).await;
    }
}

impl SyncLink for RelaySyncLink {
    fn request_snapshot(&self, _covered_seq: Seq) -> BoxFut<'_, Result<SnapshotRef, SyncError>> {
        Box::pin(async move {
            Err(SyncError::Link(
                "snapshot requests are not served by the manifest-only relay".to_owned(),
            ))
        })
    }

    fn publish_snapshot(&self, _reference: SnapshotRef) -> BoxFut<'_, Result<(), SyncError>> {
        Box::pin(async move {
            Err(SyncError::Link(
                "snapshot publishing is not served by the manifest-only relay".to_owned(),
            ))
        })
    }

    fn request_manifest(&self, at_seq: Option<Seq>) -> BoxFut<'_, Result<ManifestRef, SyncError>> {
        Box::pin(async move {
            let payload = self.request_control(RelaySub::ManifestReq, at_seq).await?;
            ManifestRef::decode(&payload)
        })
    }

    fn request_blockmap_index(
        &self,
        at_seq: Seq,
    ) -> BoxFut<'_, Result<BlockmapIndexRef, SyncError>> {
        Box::pin(async move {
            let payload = self
                .request_control(RelaySub::DiffReq, Some(at_seq))
                .await?;
            BlockmapIndexRef::decode(&payload)
        })
    }

    fn sync_end(&self, reason: SyncEndReason) -> BoxFut<'_, Result<(), SyncError>> {
        Box::pin(async move { self.close(reason).await.map_err(SyncError::from) })
    }
}

/// Map the sync-layer end reason onto its wire value.
fn wire_reason(reason: SyncEndReason) -> crate::protocol::errors::SyncEndReason {
    use crate::protocol::errors::SyncEndReason as Wire;
    match reason {
        SyncEndReason::Done => Wire::Done,
        SyncEndReason::Cancel => Wire::Cancel,
        SyncEndReason::NoPeer => Wire::NoPeer,
        SyncEndReason::Unavailable => Wire::Failed,
    }
}

/// Build a plaintext `FLOW` frame, or `None` for a zero grant.
pub(crate) fn flow_frame(
    session: SessionId,
    grant_bytes: u32,
) -> Result<Option<FrameBuf>, RelayError> {
    if grant_bytes == 0 {
        return Ok(None);
    }
    let body = Flow { grant_bytes }.encode()?;
    let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
    let mut header = FrameHeader::new(MsgType::FLOW, Flags::ROUTED, 0, Seq::UNSEQUENCED);
    header.len = (RoutePrefix::ENCODED_LEN + body.len()) as u32;
    Ok(Some(FrameBuf::new(header, prefix, body)))
}

/// Seal one `RELAY{CTRL}` body for `session`.
pub(crate) fn seal_relay(
    ring: &KeyRing,
    nonces: &NonceMinter,
    session: SessionId,
    body: &[u8],
) -> Result<FrameBuf, RelayError> {
    let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
    let mut header = FrameHeader::new(
        MsgType::RELAY,
        Flags::ENC.with(Flags::ROUTED),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = Sealer::new(ring, nonces).seal(&mut header, &prefix, body)?;
    Ok(FrameBuf::new(header, prefix, sealed.into_vec()))
}

/// Split `F_EXTRA` into `(request_id, tail)`.
pub(crate) fn split_extra(extra: &[u8]) -> Option<(u64, &[u8])> {
    if extra.len() < REQUEST_ID_LEN {
        return None;
    }
    let mut raw = [0u8; REQUEST_ID_LEN];
    raw.copy_from_slice(&extra[..REQUEST_ID_LEN]);
    Some((u64::from_le_bytes(raw), &extra[REQUEST_ID_LEN..]))
}

/// Reassembles one `STREAM_DATA{BLOCK}` stream.
///
/// Duplicate fragments are ignored; out-of-order fragments are buffered
/// within fixed bounds. After a timeout the assembler waits for a fresh
/// index 0, so a late fragment from the abandoned attempt cannot seed the
/// retry.
#[derive(Debug, Default)]
struct BlockAssembler {
    total: u32,
    next: u32,
    bytes: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    started: bool,
}

impl BlockAssembler {
    fn push(&mut self, index: u32, total: u32, data: &[u8]) -> Result<Option<Vec<u8>>, RelayError> {
        if !self.started {
            self.total = total;
            self.started = true;
        }
        if total != self.total {
            return Err(RelayError::Block(format!(
                "fragment total changed from {} to {total}",
                self.total
            )));
        }
        if index >= self.total {
            return Err(RelayError::Block(format!(
                "fragment index {index} outside total {}",
                self.total
            )));
        }
        if index + 1 < self.total {
            if data.len() != CHUNK_PLAIN {
                return Err(RelayError::Block(format!(
                    "fragment {index} has length {}, expected {CHUNK_PLAIN}",
                    data.len()
                )));
            }
        } else if data.len() > CHUNK_PLAIN {
            return Err(RelayError::Block(format!(
                "final fragment {index} has length {}",
                data.len()
            )));
        }
        if index < self.next || self.pending.contains_key(&index) {
            return Ok(None);
        }
        if index == self.next {
            self.bytes.extend_from_slice(data);
            self.next += 1;
            while let Some(buffered) = self.pending.remove(&self.next) {
                self.pending_bytes = self.pending_bytes.saturating_sub(buffered.len());
                self.bytes.extend_from_slice(&buffered);
                self.next += 1;
            }
        } else {
            if self.pending.len() >= REORDER_CHUNKS
                || self.pending_bytes.saturating_add(data.len()) > REORDER_BYTES
            {
                return Err(RelayError::Block(
                    "fragment reorder buffer overflow".to_owned(),
                ));
            }
            self.pending_bytes = self.pending_bytes.saturating_add(data.len());
            self.pending.insert(index, data.to_vec());
        }
        if self.bytes.len() > MAX_BLOB_BYTES {
            return Err(RelayError::Block(format!(
                "block blob is {} bytes, above {MAX_BLOB_BYTES}",
                self.bytes.len()
            )));
        }
        if self.next == self.total {
            return Ok(Some(std::mem::take(&mut self.bytes)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::crypto::ClusterId;
    use crate::protocol::decode_plain;
    use crate::sync::PartDesc;

    fn ring() -> Arc<KeyRing> {
        Arc::new(
            KeyRing::derive(&[7u8; 32], &ClusterId::from_bytes([9u8; 16]))
                .expect("derive key ring"),
        )
    }

    fn welcome(session: Option<SessionId>) -> Welcome {
        Welcome {
            proto: crate::protocol::ProtoVersion::CURRENT,
            caps: crate::protocol::Caps::REQUIRED,
            epoch: 1,
            current_seq: Seq(4),
            client_id: crate::protocol::ClientId::from_bytes([3u8; 16]),
            resync: crate::protocol::ResyncMode::ManifestDiff,
            limits: crate::protocol::WelcomeLimits {
                max_frame: 128 * 1024,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 8,
            },
            server_time: 0,
            server_nonce: [0u8; 32],
            join_state: crate::protocol::JoinState::Accepted,
            session_id: None,
            snapshot_ref: None,
            view_holder: session.map(|_| crate::protocol::ClientId::from_bytes([4u8; 16])),
            view_seq: session.map(|_| Seq(4)),
            view_session: session,
            view_self: false,
        }
    }

    struct ParsedRequest {
        sub: RelaySub,
        id: u64,
        at_seq: Option<u64>,
    }

    fn parse_request(frame: &FrameBuf, ring: &KeyRing) -> ParsedRequest {
        let plaintext = Opener::new(ring)
            .open(&frame.header, &frame.prefix, &frame.body)
            .expect("open relay");
        let Message::Relay(relay) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default())
                .expect("decode relay")
        else {
            panic!("not a relay");
        };
        let extra = relay.fields.get(fid::F_EXTRA).expect("F_EXTRA");
        ParsedRequest {
            sub: relay.sub,
            id: split_extra(extra).expect("request id").0,
            at_seq: relay.fields.u64(fid::F_SNAPSHOT_COVERED).expect("at seq"),
        }
    }

    fn answer(ring: &KeyRing, session: SessionId, id: u64, payload: &[u8]) -> FrameBuf {
        let mut extra = id.to_le_bytes().to_vec();
        extra.extend_from_slice(payload);
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::ManifestSig.as_u8());
        writer.bytes(fid::F_EXTRA, &extra);
        let body = writer.finish().expect("body");
        seal_relay(ring, &NonceMinter::with_instance(11), session, &body).expect("seal")
    }

    #[tokio::test]
    async fn u_relay_manifest_request_response_pairing() {
        let ring = ring();
        let session = SessionId::new(0xabc);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let responder = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let frame = control_rx.recv().await.expect("request");
            let request = parse_request(&frame, &responder_ring);
            assert_eq!(request.sub, RelaySub::ManifestReq);
            assert_eq!(request.at_seq, Some(5));
            let reference = ManifestRef {
                at_seq: Seq(5),
                entry_count: 0,
                total_len: 0,
                parts: Vec::new(),
            };
            let reply = answer(
                &responder_ring,
                session,
                request.id,
                &reference.encode().expect("encode ref"),
            );
            assert!(responder.deliver(&reply));
        });

        let reference = link.request_manifest(Some(Seq(5))).await.expect("manifest");
        assert_eq!(reference.at_seq, Seq(5));
        assert_eq!(link.pending_len(), 0);
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_relay_blockmap_index_request_response_pairing() {
        let ring = ring();
        let session = SessionId::new(0xabd);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let responder = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let frame = control_rx.recv().await.expect("request");
            let request = parse_request(&frame, &responder_ring);
            assert_eq!(request.sub, RelaySub::DiffReq);
            assert_eq!(request.at_seq, Some(9));
            let reference = BlockmapIndexRef {
                at_seq: Seq(9),
                file_count: 0,
                block_total: 0,
                parts: vec![PartDesc::new(0, 0, &[])],
            };
            let reply = answer(
                &responder_ring,
                session,
                request.id,
                &reference.encode().expect("encode ref"),
            );
            assert!(responder.deliver(&reply));
        });

        let reference = link
            .request_blockmap_index(Seq(9))
            .await
            .expect("blockmap index");
        assert_eq!(reference.at_seq, Seq(9));
        assert_eq!(reference.file_count, 0);
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_relay_request_times_out_and_clears_pending() {
        let ring = ring();
        let session = SessionId::new(0xabe);
        let (control_tx, control_rx) = mpsc::channel(8);
        // Hold the receiver so sends succeed but nobody answers.
        let _held = control_rx;
        let link = RelaySyncLink::new(Arc::new(control_tx), ring, session)
            .with_timeout(Duration::from_millis(40));
        let error = link
            .request_manifest(None)
            .await
            .expect_err("must time out");
        assert!(matches!(&error, SyncError::Link(text) if text.contains("timed out")));
        assert_eq!(link.pending_len(), 0);
    }

    #[tokio::test]
    async fn u_relay_request_survives_while_frames_keep_arriving() {
        let ring = ring();
        let session = SessionId::new(0xac0);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let link = Arc::new(
            RelaySyncLink::new(Arc::new(control_tx), Arc::clone(&ring), session)
                .with_timeout(Duration::from_millis(40)),
        );
        let requester = Arc::clone(&link);
        let task = tokio::spawn(async move { requester.request_manifest(None).await });

        let frame = control_rx.recv().await.expect("request");
        let request = parse_request(&frame, &ring);
        assert_eq!(request.sub, RelaySub::ManifestReq);

        // An unrelated sealed frame on the same session proves the peer is
        // alive; ten of them span 150 ms, well past the 40 ms window.
        let keepalive = answer(&ring, session, u64::MAX, &[]);
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            assert!(link.deliver(&keepalive), "keepalive must count as progress");
        }

        let reference = ManifestRef {
            at_seq: Seq(4),
            entry_count: 0,
            total_len: 0,
            parts: Vec::new(),
        };
        let reply = answer(
            &ring,
            session,
            request.id,
            &reference.encode().expect("encode ref"),
        );
        assert!(link.deliver(&reply));

        let reference = task.await.expect("request task").expect("manifest");
        assert_eq!(reference.at_seq, Seq(4));
        assert_eq!(link.pending_len(), 0);
    }

    #[test]
    fn u_relay_timeout_is_transient_and_marked_for_retry() {
        let error = RelayError::Timeout {
            id: 3,
            after: Duration::from_millis(10),
        };
        assert!(error.is_transient());
        assert!(!RelayError::Closed.is_transient());
        let mapped = SyncError::from(error);
        assert!(
            matches!(&mapped, SyncError::Link(text) if text.starts_with("transient: ")),
            "unexpected mapping: {mapped:?}"
        );
    }

    #[tokio::test]
    async fn u_relay_deliver_ignores_other_sessions() {
        let ring = ring();
        let session = SessionId::new(0xabf);
        let (control_tx, _control_rx) = mpsc::channel(8);
        let link = RelaySyncLink::new(Arc::new(control_tx), Arc::clone(&ring), session);
        let other = answer(&ring, SessionId::new(0x1), 1, &[]);
        assert!(!link.deliver(&other));
    }

    #[test]
    fn u_relay_session_comes_from_view_session() {
        let session = SessionId::new(0x1234);
        let (tx, _rx) = mpsc::channel(1);
        let sink: Arc<dyn FrameSink> = Arc::new(tx);
        let link = RelaySyncLink::from_welcome(&welcome(Some(session)), sink, ring());
        assert_eq!(link.session(), session);
    }

    #[tokio::test]
    async fn u_relay_close_sends_sync_end_and_releases_the_session() {
        let ring = ring();
        let session = SessionId::new(0xab2);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let link = RelaySyncLink::new(Arc::new(control_tx), Arc::clone(&ring), session);
        link.close(SyncEndReason::Done).await.expect("close");
        assert!(link.is_closed());
        let frame = control_rx.recv().await.expect("SYNC_END frame");
        assert_eq!(frame.header.msg_type, MsgType::SYNC_END);
        let route = frame.prefix.as_route().expect("route prefix");
        assert_eq!(route.session_id, session);
        let Message::SyncEnd(end) =
            decode_plain(MsgType::SYNC_END, &frame.body, &Limits::default()).expect("body")
        else {
            panic!("not a SYNC_END");
        };
        assert_eq!(end.reason, crate::protocol::SyncEndReason::Done);
        // Closing twice is harmless, and a closed link refuses new requests.
        link.close(SyncEndReason::Done).await.expect("idempotent");
        let error = link.request_manifest(None).await.expect_err("closed link");
        assert!(matches!(&error, SyncError::Link(text) if text.contains("closed")));
    }

    #[test]
    fn u_relay_deliver_leaves_join_frames_to_the_pump() {
        let ring = ring();
        let session = SessionId::new(0xab0);
        let (tx, _rx) = mpsc::channel(8);
        let link = RelaySyncLink::new(Arc::new(tx), Arc::clone(&ring), session);
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
            let body = writer.finish().expect("body");
            let frame = seal_relay(
                &ring,
                &NonceMinter::with_instance(rand::random::<u64>()),
                session,
                &body,
            )
            .expect("seal");
            assert!(!link.deliver(&frame), "{sub:?} must reach the pump");
        }
    }

    #[test]
    fn u_relay_deliver_does_not_consume_unopenable_frames() {
        let ring = ring();
        let session = SessionId::new(0xab1);
        let (tx, _rx) = mpsc::channel(8);
        let link = RelaySyncLink::new(Arc::new(tx), ring, session);
        let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
        let mut header = FrameHeader::new(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        header.len = (RoutePrefix::ENCODED_LEN + 8) as u32;
        let frame = FrameBuf::new(header, prefix, vec![0u8; 8]);
        assert!(!link.deliver(&frame));
    }

    #[test]
    fn u_relay_block_assembler_reorders_and_ignores_duplicates() {
        let mut assembler = BlockAssembler::default();
        let first = vec![1u8; 64 * 1024];
        let second = vec![2u8; 64 * 1024];
        let third = vec![3u8; 100];
        assert!(assembler.push(1, 3, &second).expect("buffer").is_none());
        assert!(assembler.push(1, 3, &second).expect("duplicate").is_none());
        assert!(assembler.push(0, 3, &first).expect("append").is_none());
        let blob = assembler
            .push(2, 3, &third)
            .expect("complete")
            .expect("blob");
        assert_eq!(blob.len(), first.len() + second.len() + third.len());
        assert_eq!(&blob[..64 * 1024], &first[..]);
    }
}
