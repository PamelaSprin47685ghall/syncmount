//! The single sequencer actor: one mutable total order backed by SQLite.
//!
//! # Invariants
//!
//! * The durable sequence lives in `meta.seq`; the actor mirrors it and every
//!   commit assigns exactly one new value inside the store transaction.
//! * The order is: decrypt, decode, plan, **commit**, broadcast. A crash
//!   between commit and broadcast is repaired by replay; the reverse order
//!   would let a client apply an event the server never persisted.
//! * Broadcast forwards the client's original AEAD ciphertext and rewrites
//!   only `header.seq` (the AAD excludes it).
//! * A semantic rejection consumes no sequence and is sent to the author
//!   alone as a plain `ERROR` whose detail carries `op_id | errno | reason`.
//! * A session is keyed by the server-assigned `SessionId`. `client_id` is
//!   decoded but never trusted or used for routing.
//! * `Replaying` sessions do not receive live broadcasts; replay and live
//!   frames therefore never interleave in one outbox. `ReplayDone` flips the
//!   state to `Online` only when the replay cursor has reached `current_seq`.
//! * Accepted operations wait in one batch for at most [`GroupCommit::window`]
//!   or until [`GroupCommit::max_ops`] is reached. The store commits the batch
//!   in one transaction and returns one sequence per accepted operation; the
//!   actor then broadcasts every applied event in strictly increasing
//!   sequence order. A rejection, duplicate or failed operation never joins
//!   the transaction and never consumes a sequence.
//!
//! # Handshake pairing
//!
//! The downlink and uplink of one connection are paired by `X-SM-Nonce`. The
//! actor parks an early downlink or a waiting uplink; the session task sends
//! `WELCOME` (carrying the sealed `ACCEPT`) through the paired sender and only
//! then calls `Attach`. An unauthenticated peer never enters the online table.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::protocol::crypto::{NonceMinter, PskKeyRing, Sealer};
use crate::protocol::messages::{Kick as KickMessage, WcpWriter, fid};
use crate::protocol::{
    BodyEncoding, Caps, ErrorMessage, Flags, FrameBuf, FrameHeader, FrameRef, KickReason, MsgType,
    Prefix, PrefixKind, ProtocolError, Seq, SessionId, TrnReason, encode_frame,
};
use crate::store::sqlite::{EventKind, EventPayload, EventRow};
use crate::transport::{MpscSender, PeerId};

use super::Epoch;
use super::config::ServeConfig;
use super::health::{HealthLimits, HealthMonitor};
use super::kick;
use super::metrics::Metrics;
use super::online::{
    DRAIN_GRACE, OnlineTable, Outbox, PushOutcome, QueueStats, Session, SessionInit, SessionState,
    WatermarkVerdict,
};
use super::relay::{RelayHub, RelayLimits, RouteAction};
use super::store::{CommitOutcome, CommitRequest, StoreHandle, StoreMeta};
use super::wire;

/// Actor handle. Cheap to clone; every clone feeds the same channel.
#[derive(Clone, Debug)]
pub struct Sequencer {
    cmd_tx: mpsc::Sender<SeqCmd>,
    seq_view: Arc<AtomicU64>,
    epoch: Epoch,
    metrics: Arc<Metrics>,
    store: StoreHandle,
    ring: Arc<PskKeyRing>,
    nonces: Arc<NonceMinter>,
}

/// Why a sequencer call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SequencerError {
    /// The actor task has stopped.
    #[error("sequencer stopped")]
    Stopped,
}

/// Bounds one group-commit batch.
///
/// The window starts when the first accepted operation enters an empty batch.
/// The batch commits as soon as either bound is reached, so a quiet server
/// waits at most one window and never for a fixed number of operations.
///
/// Both values are configurable without a rebuild:
///
/// * `SYNCMOUNT_GROUP_COMMIT_US` — window in microseconds (`0` commits the
///   batch on the next actor iteration).
/// * `SYNCMOUNT_GROUP_COMMIT_OPS` — maximum accepted operations per batch
///   (`0` and unparsable values fall back to the default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupCommit {
    /// Maximum wait for more operations after the first one.
    pub window: Duration,
    /// Maximum operations in one commit transaction.
    pub max_ops: usize,
}

impl GroupCommit {
    /// Default window: one millisecond.
    pub const DEFAULT_WINDOW: Duration = Duration::from_millis(1);
    /// Default operation cap: 64.
    pub const DEFAULT_MAX_OPS: usize = 64;

    /// Read the deployment overrides, falling back to the defaults.
    fn from_env() -> Self {
        let window = std::env::var("SYNCMOUNT_GROUP_COMMIT_US")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_micros)
            .unwrap_or(Self::DEFAULT_WINDOW);
        let max_ops = std::env::var("SYNCMOUNT_GROUP_COMMIT_OPS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(Self::DEFAULT_MAX_OPS);
        Self { window, max_ops }
    }
}

impl Default for GroupCommit {
    fn default() -> Self {
        Self {
            window: Self::DEFAULT_WINDOW,
            max_ops: Self::DEFAULT_MAX_OPS,
        }
    }
}

/// Why an `events` half could not be registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventsReject {
    /// Another downlink is already parked under this nonce.
    #[error("nonce is already parked")]
    DuplicateNonce,
    /// The nonce already belongs to a paired session.
    #[error("nonce already belongs to an online session")]
    AlreadyOnline,
    /// The sequencer stopped, or the waiting uplink disappeared.
    #[error("sequencer stopped")]
    Closed,
}

/// Result of parking a downlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventsOutcome {
    /// A waiting uplink claimed it immediately.
    Bound,
    /// Stored until the uplink arrives.
    Parked,
}

/// Why a session detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachCause {
    /// The client sent `LEAVE`; the notice was already broadcast.
    ClientLeft,
    /// The uplink ended without `LEAVE`.
    Disconnected,
    /// The downlink writer ended.
    WriterClosed,
    /// A frame violated the protocol.
    Protocol,
}

impl DetachCause {
    /// Whether this cause injects a `LEAVE` pseudo-operation.
    const fn injects_leave(self) -> bool {
        matches!(
            self,
            Self::Disconnected | Self::WriterClosed | Self::Protocol
        )
    }
}

/// One authenticated session waiting to be attached.
#[derive(Debug)]
pub struct AttachRequest {
    /// Server-assigned identity.
    pub session_id: SessionId,
    /// Pairing token of the two HTTP halves.
    pub nonce: u64,
    /// Diagnostic connection handle.
    pub peer: PeerId,
    /// Downlink queues (the actor keeps the senders).
    pub outbox: Outbox,
    /// Epoch reported by the client.
    pub epoch_seen: u64,
    /// Applied sequence reported by the client.
    pub applied_seq: Seq,
}

/// What the actor hands back after a successful `Attach`.
#[derive(Debug)]
pub struct AttachReply {
    /// Generation of the attached session.
    pub generation: u64,
    /// Sequence at attach time.
    pub current_seq: Seq,
    /// First sequence the replay task must send; `current_seq + 1` means the
    /// session is already caught up.
    pub replay_from: Seq,
    /// Data sender for the replay task.
    pub replay_tx: mpsc::Sender<Bytes>,
    /// Control sender, for protocol errors raised outside the actor.
    pub ctrl_tx: mpsc::Sender<Bytes>,
    /// Queue accounting shared with the writer.
    pub queued: Arc<QueueStats>,
}

/// Reply to a pairing request.
#[derive(Debug)]
pub struct PairReply {
    /// Downlink that arrived before the uplink.
    pub events: Option<MpscSender>,
    /// Downlink that has not arrived yet.
    pub wait: Option<oneshot::Receiver<MpscSender>>,
}

/// One watermark observation.
#[derive(Clone, Copy, Debug)]
pub struct WatermarkReport {
    /// Reporting session.
    pub session: SessionId,
    /// Highest applied sequence.
    pub applied_seq: Seq,
    /// Epoch the client last saw.
    pub epoch_seen: u64,
    /// Client-reported RTT sample.
    pub rtt_ms: Option<u16>,
    /// Observation instant (`Instant`, never wall clock).
    pub at: Instant,
}

/// Diagnostic snapshot of the actor state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqSnapshot {
    /// Server epoch.
    pub epoch: u64,
    /// Current sequence.
    pub current_seq: Seq,
    /// Attached sessions.
    pub clients: usize,
    /// Sessions receiving live broadcasts.
    pub online: usize,
    /// Sessions still replaying.
    pub replaying: usize,
    /// Sessions being kicked.
    pub kicking: usize,
}

/// What a replay task must do after reporting its cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStep {
    /// The session is caught up and now receives live broadcasts.
    Online,
    /// More events were committed; replay through `target`.
    Continue {
        /// New target sequence.
        target: Seq,
    },
}

/// Result of a drain request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReport {
    /// Sessions still attached when the wait ended.
    pub sessions: usize,
    /// Sequence at the start of the drain.
    pub current_seq: Seq,
    /// Lowest applied watermark observed.
    pub applied_min: Seq,
    /// True when the deadline fired first.
    pub timed_out: bool,
}

/// Commands accepted by the actor.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SeqCmd {
    /// Pair an uplink with its downlink.
    Pair {
        /// Pairing token.
        nonce: u64,
        /// Reply channel.
        reply: oneshot::Sender<Result<PairReply, TrnReason>>,
    },
    /// Drop a pairing waiter that timed out.
    CancelPair {
        /// Pairing token.
        nonce: u64,
    },
    /// Park or bind a downlink.
    Events {
        /// Pairing token.
        nonce: u64,
        /// Downlink writer.
        out: MpscSender,
        /// Reply channel.
        reply: oneshot::Sender<Result<EventsOutcome, EventsReject>>,
    },
    /// Attach an authenticated session.
    Attach {
        /// Parsed request.
        request: Box<AttachRequest>,
        /// Reply channel.
        reply: oneshot::Sender<Result<AttachReply, TrnReason>>,
    },
    /// Commit and broadcast one `ORDERED` operation.
    Ordered {
        /// Author.
        session: SessionId,
        /// Prepared commit.
        request: Box<CommitRequest>,
    },
    /// Route one `RELAY`/`FLOW`/`SYNC_END`/`STREAM_DATA` frame.
    Relay {
        /// Author.
        from: SessionId,
        /// Decoded frame; body and route prefix stay opaque.
        frame: Box<FrameBuf>,
    },
    /// Update a watermark.
    Watermark(WatermarkReport),
    /// Record that a valid uplink frame arrived.
    Seen {
        /// Author.
        session: SessionId,
    },
    /// Commit and broadcast a client `LEAVE`.
    Leave {
        /// Author.
        session: SessionId,
        /// Encoded frame with `seq = 0`.
        wire: Vec<u8>,
    },
    /// Remove a session.
    Detach {
        /// Session to remove.
        session: SessionId,
        /// Generation assigned at attach.
        generation: u64,
        /// Why.
        cause: DetachCause,
    },
    /// A replay task reached `upto`.
    ReplayDone {
        /// Session.
        session: SessionId,
        /// Generation assigned at attach.
        generation: u64,
        /// Last sequence sent.
        upto: Seq,
        /// Reply channel.
        reply: oneshot::Sender<ReplayStep>,
    },
    /// Periodic maintenance.
    Tick {
        /// Tick instant.
        now: Instant,
    },
    /// Diagnostic snapshot.
    Snapshot {
        /// Reply channel.
        reply: oneshot::Sender<SeqSnapshot>,
    },
    /// Wait until every session has applied `current_seq`, or the deadline.
    Drain {
        /// Absolute deadline.
        deadline: Instant,
        /// Reply channel.
        reply: oneshot::Sender<DrainReport>,
    },
    /// Kick every session and compact the event log.
    Compact {
        /// Reply channel.
        reply: oneshot::Sender<Result<super::store::CompactReport, String>>,
    },
    /// Stop the actor.
    Shutdown {
        /// Reply channel.
        reply: oneshot::Sender<()>,
    },
}

impl Sequencer {
    /// Start the actor task.
    pub fn start(
        config: Arc<ServeConfig>,
        meta: StoreMeta,
        store: StoreHandle,
        ring: Arc<PskKeyRing>,
        metrics: Arc<Metrics>,
    ) -> (Self, JoinHandle<()>) {
        Self::start_with_group_commit(config, meta, store, ring, metrics, GroupCommit::from_env())
    }

    /// Start the actor task with an explicit group-commit bound.
    ///
    /// Tests and embedders use this to make the window deterministic; the
    /// binary calls [`Sequencer::start`], which reads the environment.
    pub fn start_with_group_commit(
        config: Arc<ServeConfig>,
        meta: StoreMeta,
        store: StoreHandle,
        ring: Arc<PskKeyRing>,
        metrics: Arc<Metrics>,
        group: GroupCommit,
    ) -> (Self, JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(config.command_capacity.max(1));
        let epoch = Epoch::new(meta.epoch.max(1) as u64);
        let seq_view = Arc::new(AtomicU64::new(meta.seq.max(0) as u64));
        metrics.seq.store(meta.seq.max(0) as u64, Ordering::Release);
        let handle_store = store.clone();
        let handle_ring = Arc::clone(&ring);
        let nonces = Arc::new(NonceMinter::new(&mut rand::rng()));
        let handle_nonces = Arc::clone(&nonces);
        let core = SequencerCore {
            seq: meta.seq.max(0) as u64,
            last_op_seq: meta.seq.max(0) as u64,
            replay_floor: meta.replay_floor.max(1) as u64,
            epoch,
            online: OnlineTable::new(),
            generation: 0,
            relay: RelayHub::new(RelayLimits::default()),
            health: HealthMonitor::new(HealthLimits::default()),
            pending_events: HashMap::new(),
            awaiting_events: HashMap::new(),
            pending_kicks: Vec::new(),
            pending_detaches: Vec::new(),
            pending_leaves: Vec::new(),
            pending_leave_wires: Vec::new(),
            pending_commits: Vec::new(),
            group,
            config,
            metrics: Arc::clone(&metrics),
            seq_view: Arc::clone(&seq_view),
            store,
            ring,
            nonces,
            draining: None,
            fatal: false,
        };
        let task = tokio::spawn(core.run(cmd_rx));
        (
            Self {
                cmd_tx,
                seq_view,
                epoch,
                metrics,
                store: handle_store,
                ring: handle_ring,
                nonces: handle_nonces,
            },
            task,
        )
    }

    /// Server epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Current sequence without asking the actor.
    pub fn current_seq(&self) -> Seq {
        Seq(self.seq_view.load(Ordering::Acquire))
    }

    /// Shared counters.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// PSK ring, for per-connection handshake and replay tasks.
    pub fn ring(&self) -> Arc<PskKeyRing> {
        Arc::clone(&self.ring)
    }

    /// Store handle, for replay readers.
    pub fn store(&self) -> StoreHandle {
        self.store.clone()
    }

    /// Server nonce minter for synthesized frames.
    pub fn nonces(&self) -> Arc<NonceMinter> {
        Arc::clone(&self.nonces)
    }

    /// Pair an uplink with its downlink.
    pub async fn pair(&self, nonce: u64) -> Result<PairReply, TrnReason> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Pair { nonce, reply })
            .await
            .map_err(|_| TrnReason::Internal)?;
        rx.await.map_err(|_| TrnReason::Internal)?
    }

    /// Drop a pairing waiter that timed out.
    pub async fn cancel_pair(&self, nonce: u64) {
        let _ = self.cmd_tx.send(SeqCmd::CancelPair { nonce }).await;
    }

    /// Park or bind one downlink.
    pub async fn events(&self, nonce: u64, out: MpscSender) -> Result<EventsOutcome, EventsReject> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Events { nonce, out, reply })
            .await
            .map_err(|_| EventsReject::Closed)?;
        rx.await.map_err(|_| EventsReject::Closed)?
    }

    /// Attach an authenticated session.
    pub async fn attach(&self, request: AttachRequest) -> Result<AttachReply, TrnReason> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Attach {
                request: Box::new(request),
                reply,
            })
            .await
            .map_err(|_| TrnReason::Internal)?;
        rx.await.map_err(|_| TrnReason::Internal)?
    }

    /// Commit and broadcast one `ORDERED` operation.
    pub async fn ordered(
        &self,
        session: SessionId,
        request: CommitRequest,
    ) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Ordered {
                session,
                request: Box::new(request),
            })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Route one relay-path frame.
    pub async fn relay(&self, from: SessionId, frame: FrameBuf) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Relay {
                from,
                frame: Box::new(frame),
            })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Record a watermark observation.
    pub async fn watermark(&self, report: WatermarkReport) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Watermark(report))
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Record one valid uplink frame that carries no watermark (`ACK`,
    /// `RESPONSE`). The actor only moves `last_seen_at`.
    pub async fn seen(&self, session: SessionId) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Seen { session })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Commit and broadcast a client `LEAVE`.
    pub async fn leave(&self, session: SessionId, wire: Vec<u8>) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Leave { session, wire })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Remove a session.
    pub async fn detach(
        &self,
        session: SessionId,
        generation: u64,
        cause: DetachCause,
    ) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Detach {
                session,
                generation,
                cause,
            })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Report that a replay task reached `upto`.
    pub async fn replay_done(
        &self,
        session: SessionId,
        generation: u64,
        upto: Seq,
    ) -> Result<ReplayStep, SequencerError> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::ReplayDone {
                session,
                generation,
                upto,
                reply,
            })
            .await
            .map_err(|_| SequencerError::Stopped)?;
        rx.await.map_err(|_| SequencerError::Stopped)
    }

    /// Run one maintenance tick.
    pub async fn tick(&self, now: Instant) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Tick { now })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Read a diagnostic snapshot.
    pub async fn snapshot(&self) -> Result<SeqSnapshot, SequencerError> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Snapshot { reply })
            .await
            .map_err(|_| SequencerError::Stopped)?;
        rx.await.map_err(|_| SequencerError::Stopped)
    }

    /// Wait until every session has applied `current_seq`, or the deadline.
    pub async fn drain(&self, timeout: std::time::Duration) -> Result<DrainReport, SequencerError> {
        let (reply, rx) = oneshot::channel();
        let deadline = Instant::now() + timeout;
        // The actor only checks the drain condition when a command arrives.
        // Wake it at the deadline so a quiet server still reports the
        // timeout; the periodic ticker covers the production path.
        let wake = self.cmd_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            let _ = wake
                .send(SeqCmd::Tick {
                    now: Instant::now(),
                })
                .await;
        });
        self.cmd_tx
            .send(SeqCmd::Drain { deadline, reply })
            .await
            .map_err(|_| SequencerError::Stopped)?;
        rx.await.map_err(|_| SequencerError::Stopped)
    }

    /// Kick every session and compact the event log.
    pub async fn compact(&self) -> Result<super::store::CompactReport, String> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Compact { reply })
            .await
            .map_err(|_| "sequencer stopped".to_owned())?;
        rx.await.map_err(|_| "sequencer stopped".to_owned())?
    }

    /// Stop the actor. Idempotent: a second call observes a closed channel.
    pub async fn shutdown(&self) -> Result<(), SequencerError> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Shutdown { reply })
            .await
            .map_err(|_| SequencerError::Stopped)?;
        rx.await.map_err(|_| SequencerError::Stopped)
    }
}

struct PendingEvents {
    out: MpscSender,
    parked_at: Instant,
}

struct AwaitingEvents {
    reply: oneshot::Sender<MpscSender>,
    since: Instant,
}

/// One accepted operation waiting for the group commit.
struct PendingCommit {
    /// Author.
    session: SessionId,
    /// Prepared commit.
    request: CommitRequest,
}

struct SequencerCore {
    seq: u64,
    /// Highest committed sequence. `LEAVE` also consumes one, but assigns no
    /// file work, so the health gate must not count it as pending content.
    last_op_seq: u64,
    /// First sequence a fresh replica must replay.
    replay_floor: u64,
    epoch: Epoch,
    online: OnlineTable,
    generation: u64,
    relay: RelayHub,
    health: HealthMonitor,
    pending_events: HashMap<u64, PendingEvents>,
    awaiting_events: HashMap<u64, AwaitingEvents>,
    pending_kicks: Vec<(SessionId, KickReason)>,
    pending_detaches: Vec<SessionId>,
    pending_leaves: Vec<(SessionId, Seq)>,
    pending_leave_wires: Vec<Vec<u8>>,
    /// Accepted operations waiting for the next group commit.
    pending_commits: Vec<PendingCommit>,
    /// Batch window and operation cap.
    group: GroupCommit,
    config: Arc<ServeConfig>,
    metrics: Arc<Metrics>,
    seq_view: Arc<AtomicU64>,
    store: StoreHandle,
    ring: Arc<PskKeyRing>,
    nonces: Arc<NonceMinter>,
    draining: Option<(Instant, oneshot::Sender<DrainReport>)>,
    fatal: bool,
}

impl SequencerCore {
    async fn run(mut self, mut rx: mpsc::Receiver<SeqCmd>) {
        let mut deadline: Option<Instant> = None;
        loop {
            // While a batch is open, wait at most until its deadline. The
            // timeout is the only source of unbounded delay, and it is
            // bounded by `group.window`.
            let mut cmd = None;
            if self.pending_commits.is_empty() {
                match rx.recv().await {
                    Some(received) => cmd = Some(received),
                    None => break,
                }
            } else {
                let limit = deadline.unwrap_or_else(Instant::now);
                let now = Instant::now();
                // A batch that already holds more than one operation and has
                // no queued successor is the whole burst: commit it now
                // instead of burning the rest of the window. A lone
                // operation still waits, because another client may be
                // microseconds behind.
                let idle = self.pending_commits.len() > 1 && rx.is_empty();
                if now >= limit || idle {
                    self.flush_pending().await;
                    deadline = None;
                } else {
                    match tokio::time::timeout(limit - now, rx.recv()).await {
                        Ok(Some(received)) => cmd = Some(received),
                        Ok(None) => {
                            self.flush_pending().await;
                            break;
                        }
                        Err(_) => {
                            self.flush_pending().await;
                            deadline = None;
                        }
                    }
                }
            }

            let now = Instant::now();
            let now_us = wall_clock_us();
            let mut stop = false;

            if let Some(command) = cmd {
                // Commands that observe the sequence must see every earlier
                // accepted operation committed and broadcast first.
                let flush_first = matches!(
                    &command,
                    SeqCmd::Leave { .. }
                        | SeqCmd::Drain { .. }
                        | SeqCmd::Snapshot { .. }
                        | SeqCmd::Compact { .. }
                        | SeqCmd::Shutdown { .. }
                );
                if flush_first && !self.pending_commits.is_empty() {
                    self.flush_pending().await;
                    deadline = None;
                }
                match command {
                    SeqCmd::Pair { nonce, reply } => {
                        let _ = reply.send(self.on_pair(nonce, now));
                    }
                    SeqCmd::CancelPair { nonce } => {
                        self.awaiting_events.remove(&nonce);
                        self.pending_events.remove(&nonce);
                    }
                    SeqCmd::Events { nonce, out, reply } => {
                        let _ = reply.send(self.on_events(nonce, out, now));
                    }
                    SeqCmd::Attach { request, reply } => {
                        let _ = reply.send(self.on_attach(*request, now));
                    }
                    SeqCmd::Ordered { session, request } => {
                        self.queue_ordered(session, *request, now);
                        if self.pending_commits.len() == 1 {
                            deadline = Some(now + self.group.window);
                        }
                        if self.pending_commits.len() >= self.group.max_ops {
                            self.flush_pending().await;
                            deadline = None;
                        }
                    }
                    SeqCmd::Relay { from, frame } => self.on_relay(from, *frame, now),
                    SeqCmd::Watermark(report) => self.on_watermark(report),
                    SeqCmd::Seen { session } => self.on_seen(session, now),
                    SeqCmd::Leave { session, wire } => {
                        self.on_leave(session, wire, now_us).await;
                    }
                    SeqCmd::Detach {
                        session,
                        generation,
                        cause,
                    } => self.on_detach(session, generation, cause, now_us),
                    SeqCmd::ReplayDone {
                        session,
                        generation,
                        upto,
                        reply,
                    } => {
                        let _ = reply.send(self.on_replay_done(session, generation, upto));
                    }
                    SeqCmd::Tick { now } => self.on_tick(now),
                    SeqCmd::Snapshot { reply } => {
                        let _ = reply.send(self.snapshot());
                    }
                    SeqCmd::Drain { deadline, reply } => {
                        self.draining = Some((deadline, reply));
                        self.check_drain(now);
                    }
                    SeqCmd::Compact { reply } => {
                        let result = self.on_compact(now_us).await;
                        let _ = reply.send(result);
                    }
                    SeqCmd::Shutdown { reply } => {
                        self.on_shutdown(now_us);
                        let _ = reply.send(());
                        stop = true;
                    }
                }
            }

            // A synthesized `leave` must follow every accepted operation.
            if !self.pending_commits.is_empty() && !self.pending_leaves.is_empty() {
                self.flush_pending().await;
                deadline = None;
            }
            // A drain includes every accepted operation, as it did when each
            // operation committed on its own.
            if self.draining.is_some() && !self.pending_commits.is_empty() {
                self.flush_pending().await;
                deadline = None;
            }
            self.check_drain(now);
            self.flush_kicks(now_us);
            self.flush_detaches(now_us);
            self.flush_leaves(now_us).await;
            self.metrics.seq.store(self.seq, Ordering::Release);
            self.metrics
                .clients
                .store(self.online.len() as u64, Ordering::Release);
            self.metrics
                .sync_sessions
                .store(self.relay.session_count() as u64, Ordering::Release);
            if stop || self.fatal {
                break;
            }
        }
    }

    fn current_seq(&self) -> Seq {
        Seq(self.seq)
    }

    fn last_op(&self) -> Seq {
        Seq(self.last_op_seq)
    }

    /// Start the lag clock for every session that was caught up before this
    /// operation.
    fn note_work(&mut self, before: Seq, now: Instant) {
        for (_, session) in self.online.iter_mut() {
            if !session.state.receives_broadcast() {
                continue;
            }
            if session.watermark.applied_seq() >= before {
                session.watermark.note_work(now);
            }
        }
    }

    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn on_pair(&mut self, nonce: u64, now: Instant) -> Result<PairReply, TrnReason> {
        if self.online.contains_nonce(nonce) {
            return Err(TrnReason::Protocol);
        }
        if let Some(parked) = self.pending_events.remove(&nonce) {
            return Ok(PairReply {
                events: Some(parked.out),
                wait: None,
            });
        }
        if self.awaiting_events.contains_key(&nonce) {
            return Err(TrnReason::Protocol);
        }
        let (tx, rx) = oneshot::channel();
        self.awaiting_events.insert(
            nonce,
            AwaitingEvents {
                reply: tx,
                since: now,
            },
        );
        Ok(PairReply {
            events: None,
            wait: Some(rx),
        })
    }

    fn on_events(
        &mut self,
        nonce: u64,
        out: MpscSender,
        now: Instant,
    ) -> Result<EventsOutcome, EventsReject> {
        if let Some(waiting) = self.awaiting_events.remove(&nonce) {
            return match waiting.reply.send(out) {
                Ok(()) => Ok(EventsOutcome::Bound),
                Err(_) => Err(EventsReject::Closed),
            };
        }
        if self.online.contains_nonce(nonce) {
            return Err(EventsReject::AlreadyOnline);
        }
        if self.pending_events.contains_key(&nonce) {
            return Err(EventsReject::DuplicateNonce);
        }
        self.pending_events.insert(
            nonce,
            PendingEvents {
                out,
                parked_at: now,
            },
        );
        Ok(EventsOutcome::Parked)
    }

    fn on_attach(
        &mut self,
        request: AttachRequest,
        now: Instant,
    ) -> Result<AttachReply, TrnReason> {
        if self.online.contains(&request.session_id) {
            return Err(TrnReason::Protocol);
        }
        if self.online.contains_nonce(request.nonce) {
            return Err(TrnReason::Protocol);
        }
        let current = self.current_seq();
        let caught_up = request.epoch_seen == self.epoch.get()
            && request.applied_seq >= Seq(self.replay_floor.saturating_sub(1))
            && request.applied_seq <= current;
        let replay_from = if caught_up {
            Seq(request.applied_seq.get().saturating_add(1))
        } else {
            Seq(self.replay_floor)
        };
        let AttachRequest {
            session_id,
            nonce,
            peer,
            outbox,
            epoch_seen,
            applied_seq,
        } = request;
        let replay_tx = outbox.data.clone();
        let ctrl_tx = outbox.ctrl.clone();
        let queued = Arc::clone(&outbox.queued);
        let mut session = Session::new(SessionInit {
            session_id,
            nonce,
            peer,
            outbox,
            epoch: self.epoch.get(),
            epoch_seen,
            applied_seq,
            current_seq: current,
            now,
        });
        let generation = self.next_generation();
        session.generation = generation;
        session.state = if replay_from > current {
            SessionState::Online
        } else {
            SessionState::Replaying
        };
        self.online.insert(session);
        Ok(AttachReply {
            generation,
            current_seq: current,
            replay_from,
            replay_tx,
            ctrl_tx,
            queued,
        })
    }

    /// Accept one operation into the open batch.
    ///
    /// The session checks happen at arrival, not at flush time, so an
    /// operation that arrived before a kick or detach still commits. That is
    /// the same order the sequential actor gave it.
    fn queue_ordered(&mut self, session_id: SessionId, request: CommitRequest, now: Instant) {
        let Some(state) = self.online.get(&session_id).map(|s| s.state) else {
            return;
        };
        if matches!(state, SessionState::Kicking) {
            return;
        }
        if let Some(session) = self.online.get_mut(&session_id) {
            session.last_seen_at = now;
        }
        self.pending_commits.push(PendingCommit {
            session: session_id,
            request,
        });
    }

    /// Commit the open batch and broadcast every applied event in sequence.
    async fn flush_pending(&mut self) {
        if self.pending_commits.is_empty() {
            return;
        }
        let before = self.last_op();
        let now = Instant::now();
        let pending = std::mem::take(&mut self.pending_commits);
        let mut requests = Vec::with_capacity(pending.len());
        let mut authors = Vec::with_capacity(pending.len());
        for item in pending {
            authors.push((
                item.session,
                item.request.op.op_id,
                item.request.op.path.clone(),
            ));
            requests.push(item.request);
        }
        let outcomes = self.store.commit_batch(requests).await;
        if outcomes.len() != authors.len() {
            tracing::error!(
                expected = authors.len(),
                got = outcomes.len(),
                "store returned the wrong group-commit outcome count"
            );
            self.fatal = true;
            return;
        }
        let mut applied = false;
        for ((session_id, op_id, reject_path), outcome) in authors.into_iter().zip(outcomes) {
            applied |= self
                .apply_outcome(session_id, op_id, &reject_path, outcome)
                .await;
        }
        if applied {
            self.note_work(before, now);
        }
    }

    /// Handle one store outcome. Returns true when an event was broadcast.
    async fn apply_outcome(
        &mut self,
        session_id: SessionId,
        op_id: [u8; 16],
        reject_path: &str,
        outcome: CommitOutcome,
    ) -> bool {
        match outcome {
            CommitOutcome::Applied {
                seq,
                event,
                content,
            } => {
                let seq = Seq(seq.max(0) as u64);
                if seq.get() <= self.seq {
                    tracing::error!(seq = seq.get(), "store returned a non-monotonic sequence");
                    self.fatal = true;
                    return false;
                }
                self.seq = seq.get();
                self.seq_view.store(self.seq, Ordering::Release);
                // Broadcast the server's committed event, never the author's
                // original frame. The author's `F_EXTRA` is its local payload;
                // the server resolves paths and builds the complete file, so
                // live and replay receivers must see the same bytes.
                let frame = wire::replay_ordered_with_content(
                    &event,
                    &self.ring,
                    &self.nonces,
                    content.as_deref(),
                )
                .and_then(|bytes| wire::with_seq(&bytes, seq));
                match frame {
                    Ok(bytes) => {
                        match self.broadcast_ordered(
                            Bytes::from(bytes),
                            &event,
                            content.as_deref(),
                            seq,
                        ) {
                            Ok(()) => {
                                self.last_op_seq = seq.get();
                                true
                            }
                            Err(error) => {
                                tracing::error!(
                                    ?error,
                                    seq = seq.get(),
                                    "cannot build broadcast content"
                                );
                                self.fatal = true;
                                false
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(?error, seq = seq.get(), "cannot rebuild broadcast frame");
                        self.fatal = true;
                        false
                    }
                }
            }
            CommitOutcome::Rejected { reject } => {
                let state = self.store.path_state(reject_path).await.ok().flatten();
                self.send_reject(session_id, op_id, reject, state.as_ref());
                false
            }
            CommitOutcome::Duplicate { seq } => {
                let seq = Seq(seq.max(0) as u64);
                // A replaying session must receive sequence numbers in order.
                // The replay task will deliver this event; sending the stored
                // frame now would overtake the replay cursor and make the
                // receiver fail with a sequence gap. The replay frame also
                // acknowledges the resent outbox row.
                let online = self
                    .online
                    .get(&session_id)
                    .is_some_and(|session| session.state == SessionState::Online);
                if online {
                    match self.store.wire(seq.get() as i64).await {
                        Ok(Some(bytes)) => {
                            if let Ok(bytes) = wire::with_seq(&bytes, seq) {
                                self.send_to_author(session_id, Bytes::from(bytes));
                            }
                        }
                        Ok(None) => {
                            self.send_error_to(session_id, TrnReason::Internal, None);
                        }
                        Err(message) => {
                            tracing::error!(%message, "cannot read duplicate wire");
                            self.send_error_to(session_id, TrnReason::Internal, None);
                        }
                    }
                }
                false
            }
            CommitOutcome::Failed { message } => {
                tracing::error!(%message, op_id = ?op_id, "commit failed");
                self.send_error_detail(session_id, TrnReason::Internal, message.as_bytes());
                false
            }
        }
    }

    async fn on_leave(&mut self, session_id: SessionId, wire: Vec<u8>, now_us: u64) {
        // A client `LEAVE` frame carries no sequence. Replay must still
        // advance the receiver's `applied` cursor, so replace it with the
        // synthesized ORDERED class-LEAVE frame; the raw notice is advisory.
        let wire = if is_leave_frame(&wire) {
            let last_good = self
                .online
                .get(&session_id)
                .map_or(Seq::UNSEQUENCED, |session| session.last_good_seq);
            let synthesized = self.synthesize_leave(session_id, last_good, now_us);
            if synthesized.is_empty() {
                wire
            } else {
                synthesized
            }
        } else {
            wire
        };
        let before = self.last_op();
        let outcome = self
            .store
            .leave(session_id.to_le_bytes(), wire.clone())
            .await;
        if let CommitOutcome::Applied { seq, .. } = outcome {
            let seq = Seq(seq.max(0) as u64);
            self.seq = seq.get();
            self.seq_view.store(self.seq, Ordering::Release);
            if let Ok(bytes) = wire::with_seq(&wire, seq) {
                self.broadcast(Bytes::from(bytes), seq);
                self.last_op_seq = seq.get();
                self.note_work(before, Instant::now());
            }
        }
        self.detach_now(session_id, false, now_us);
    }

    fn on_replay_done(&mut self, session_id: SessionId, generation: u64, upto: Seq) -> ReplayStep {
        let current = self.current_seq();
        let Some(session) = self.online.get_mut(&session_id) else {
            return ReplayStep::Online;
        };
        if session.generation != generation {
            return ReplayStep::Online;
        }
        if upto >= current {
            session.state = SessionState::Online;
            ReplayStep::Online
        } else {
            ReplayStep::Continue { target: current }
        }
    }

    fn on_relay(&mut self, from: SessionId, frame: FrameBuf, now: Instant) {
        if !self.online.contains(&from) {
            return;
        }
        let kind = frame.header.msg_type;
        let Some(prefix) = frame.prefix.as_route().copied() else {
            self.send_error_to(from, TrnReason::Protocol, None);
            return;
        };
        if let Some(session) = self.online.get_mut(&from) {
            session.last_seen_at = now;
        }
        // OP_DATA is assembled by the session task and committed with the
        // ORDERED frame, but live readers still need the sealed fragments:
        // fan them out unchanged, never charging a relay slot.
        if kind == MsgType::STREAM_DATA && prefix.stream == crate::protocol::StreamId::OP_DATA {
            let Some(wire) = encode_relay(&frame) else {
                self.send_error_to(from, TrnReason::Internal, Some(prefix.session_id));
                return;
            };
            self.fanout(wire, Some(from), None);
            return;
        }
        let action = if kind == MsgType::FLOW {
            match crate::protocol::decode_plain(MsgType::FLOW, &frame.body, &self.config.limits) {
                Ok(crate::protocol::Message::Flow(flow)) => {
                    self.relay
                        .on_flow(from, &prefix, flow.grant_bytes, &self.online, now)
                }
                _ => RouteAction::Reject {
                    to: from,
                    reason: TrnReason::BadFrame,
                },
            }
        } else {
            self.relay.route(
                from,
                kind,
                frame.header.flags,
                &prefix,
                frame.encoded_len(),
                &self.online,
                now,
            )
        };
        match action {
            RouteAction::Forward { to } | RouteAction::Open { to, .. } => {
                let Some(wire) = encode_relay(&frame) else {
                    self.send_error_to(from, TrnReason::Internal, Some(prefix.session_id));
                    return;
                };
                self.forward_relay(from, to, wire, prefix.session_id);
            }
            RouteAction::Reject { to, reason } => {
                self.send_error_to(to, reason, Some(prefix.session_id));
            }
            RouteAction::Drop { reason } => {
                self.send_error_to(from, reason, Some(prefix.session_id));
            }
        }
    }

    fn forward_relay(&mut self, from: SessionId, to: SessionId, wire: Bytes, id: SessionId) {
        let outcome = match self.online.get(&to) {
            Some(session) if session.state.receives_broadcast() => {
                session.outbox.try_push_data(wire)
            }
            _ => {
                self.send_error_to(from, TrnReason::NoPeer, Some(id));
                return;
            }
        };
        match outcome {
            PushOutcome::Queued => {}
            PushOutcome::Overflow => {
                let stalled = self
                    .online
                    .get(&to)
                    .is_some_and(|session| session.outbox.queued.since_drain() > DRAIN_GRACE);
                if stalled {
                    self.pending_kicks.push((to, KickReason::QueueOverflow));
                } else {
                    self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                }
            }
            PushOutcome::Closed => {
                self.pending_detaches.push(to);
                self.send_error_to(from, TrnReason::NoPeer, Some(id));
            }
        }
    }

    fn send_error_to(&self, session_id: SessionId, reason: TrnReason, id: Option<SessionId>) {
        let Some(session) = self.online.get(&session_id) else {
            return;
        };
        if let Some(frame) = kick::encode_error(reason, id) {
            let _ = session.outbox.try_push_ctrl(frame);
        }
    }

    fn send_error_detail(&self, session_id: SessionId, reason: TrnReason, detail: &[u8]) {
        let Some(session) = self.online.get(&session_id) else {
            return;
        };
        let Ok(body) = (ErrorMessage {
            reason,
            detail,
            session_id: Some(session_id),
        })
        .encode() else {
            return;
        };
        if let Ok(frame) = encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED) {
            let _ = session.outbox.try_push_ctrl(frame);
        }
    }

    fn send_reject(
        &self,
        session_id: SessionId,
        op_id: [u8; 16],
        reject: crate::state::Reject,
        state: Option<&crate::store::sqlite::RejectState>,
    ) {
        let detail = wire::reject_body(
            op_id,
            reject,
            state,
            usize::from(self.config.limits.detail_max),
        );
        self.send_error_detail(session_id, TrnReason::Protocol, &detail);
    }

    fn send_to_author(&mut self, session_id: SessionId, frame: Bytes) {
        let Some(session) = self.online.get_mut(&session_id) else {
            return;
        };
        match session.outbox.try_push_data(frame) {
            PushOutcome::Queued => {}
            PushOutcome::Overflow => {
                // The author's echo carries a sequence number. Dropping it
                // would hide that sequence until the next reconnect.
                session.state = SessionState::Kicking;
                self.pending_kicks
                    .push((session_id, KickReason::QueueOverflow));
                self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    session = ?session_id,
                    "downlink full on an echo; kicking the session"
                );
            }
            PushOutcome::Closed => self.pending_detaches.push(session_id),
        }
    }

    fn release_relay(&mut self, session_id: SessionId, now: Instant) {
        let dropped = self.relay.drop_by_session(session_id, now);
        for session in dropped {
            if let Some(survivor) = session.survivor(session_id) {
                self.send_error_to(survivor, TrnReason::NoPeer, Some(session.id));
            }
        }
    }

    fn on_watermark(&mut self, report: WatermarkReport) {
        let current = self.current_seq();
        let epoch = self.epoch.get();
        let Some(session) = self.online.get_mut(&report.session) else {
            return;
        };
        match self.health.on_watermark(
            session,
            report.applied_seq,
            report.epoch_seen,
            epoch,
            current,
            report.at,
        ) {
            WatermarkVerdict::Kick(reason) => {
                self.pending_kicks.push((report.session, reason));
                return;
            }
            WatermarkVerdict::EpochMismatch => {
                // The client names a different history. Reconnecting is the
                // only way to replay it, so kick instead of guessing.
                self.pending_kicks
                    .push((report.session, KickReason::EpochMismatch));
                return;
            }
            WatermarkVerdict::Unchanged | WatermarkVerdict::Advanced => {}
        }
        if let Some(rtt) = report.rtt_ms {
            session.watermark.push_rtt(rtt);
        }
        session.last_seen_at = report.at;
    }

    fn on_seen(&mut self, session_id: SessionId, now: Instant) {
        if let Some(session) = self.online.get_mut(&session_id) {
            session.last_seen_at = now;
        }
    }

    fn on_detach(
        &mut self,
        session_id: SessionId,
        generation: u64,
        cause: DetachCause,
        now_us: u64,
    ) {
        match cause {
            DetachCause::ClientLeft | DetachCause::WriterClosed => {
                self.detach_generation_now(session_id, generation, false, now_us);
            }
            DetachCause::Disconnected | DetachCause::Protocol => {
                self.detach_generation_now(session_id, generation, cause.injects_leave(), now_us);
            }
        }
    }

    fn on_tick(&mut self, now: Instant) {
        let ttl = self.config.pair_timeout;
        self.pending_events
            .retain(|_, parked| now.saturating_duration_since(parked.parked_at) < ttl);
        self.awaiting_events
            .retain(|_, waiting| now.saturating_duration_since(waiting.since) < ttl);
        let work = self.last_op();
        let reaped = self.relay.reap(now);
        for session in reaped {
            self.send_error_to(session.origin, TrnReason::NoPeer, Some(session.id));
            self.send_error_to(session.peer, TrnReason::NoPeer, Some(session.id));
        }
        let mut max_lag_ms = 0_u64;
        let mut max_pending = 0_u64;
        for (session_id, session) in self.online.iter_mut() {
            let Some(diagnosis) = self.health.diagnose(session, work, now) else {
                continue;
            };
            max_lag_ms =
                max_lag_ms.max(u64::try_from(diagnosis.lag.as_millis()).unwrap_or(u64::MAX));
            max_pending = max_pending.max(diagnosis.pending_ops);
            if self.health.should_report(*session_id, now) {
                tracing::warn!(
                    session = ?session_id,
                    lag_ms = u64::try_from(diagnosis.lag.as_millis()).unwrap_or(u64::MAX),
                    threshold_ms = u64::try_from(diagnosis.threshold.as_millis()).unwrap_or(u64::MAX),
                    pending_ops = diagnosis.pending_ops,
                    backlog_bytes = diagnosis.backlog_bytes,
                    "session is behind its watermark threshold; keeping it attached"
                );
            }
        }
        self.metrics
            .watermark_lag_ms
            .store(max_lag_ms, Ordering::Relaxed);
        self.metrics
            .pending_ops
            .store(max_pending, Ordering::Relaxed);
    }

    fn snapshot(&self) -> SeqSnapshot {
        let mut online = 0;
        let mut replaying = 0;
        let mut kicking = 0;
        for (_, session) in self.online.iter() {
            match session.state {
                SessionState::Online => online += 1,
                SessionState::Replaying => replaying += 1,
                SessionState::Kicking => kicking += 1,
            }
        }
        SeqSnapshot {
            epoch: self.epoch.get(),
            current_seq: self.current_seq(),
            clients: self.online.len(),
            online,
            replaying,
            kicking,
        }
    }

    fn check_drain(&mut self, now: Instant) {
        let Some((deadline, _)) = self.draining.as_ref() else {
            return;
        };
        let current = self.current_seq();
        let sessions = self.online.len();
        let mut applied_min = current;
        let mut caught_up = true;
        for (_, session) in self.online.iter() {
            let applied = session.watermark.applied_seq();
            applied_min = applied_min.min(applied);
            if applied < current {
                caught_up = false;
            }
        }
        let expired = now >= *deadline;
        if !caught_up && !expired {
            return;
        }
        let Some((_, reply)) = self.draining.take() else {
            return;
        };
        let _ = reply.send(DrainReport {
            sessions,
            current_seq: current,
            applied_min,
            timed_out: !caught_up,
        });
    }

    async fn on_compact(&mut self, now_us: u64) -> Result<super::store::CompactReport, String> {
        let sessions: Vec<SessionId> = self.online.iter().map(|(id, _)| *id).collect();
        for session in sessions {
            self.kick_now(session, KickReason::EpochMismatch, now_us);
        }
        let report = self.store.compact().await?;
        self.epoch = Epoch::new(report.epoch.max(1) as u64);
        // Compaction resets `meta.seq` to zero and then emits one replayable
        // event per live object, so the final sequence equals `events`.
        self.seq = report.events;
        self.last_op_seq = report.events;
        self.replay_floor = 1;
        self.seq_view.store(report.events, Ordering::Release);
        self.metrics.publish_epoch(report.epoch.max(1) as u64);
        self.metrics.seq.store(report.events, Ordering::Release);
        Ok(report)
    }

    fn on_shutdown(&mut self, now_us: u64) {
        let sessions: Vec<SessionId> = self.online.iter().map(|(id, _)| *id).collect();
        for session in sessions {
            self.kick_now(session, KickReason::ServerShutdown, now_us);
        }
    }

    /// Broadcast one sequenced frame to every online session.
    fn broadcast(&mut self, wire: Bytes, seq: Seq) {
        self.fanout(wire, None, Some(seq));
    }

    /// Broadcast one rebuilt `ORDERED` plus the content stream it describes.
    ///
    /// The author's original stream is not reusable: it carries the author's
    /// random data session id and only the patched chunks. The rebuilt frame
    /// names the server's complete file, so the matching `STREAM_DATA`
    /// frames must precede it. A session that cannot take the content skips
    /// the `ORDERED`; the resulting sequence gap makes it reconnect and
    /// replay from the server's log.
    fn broadcast_ordered(
        &mut self,
        ordered: Bytes,
        event: &EventRow,
        content: Option<&[u8]>,
        seq: Seq,
    ) -> Result<(), wire::WireError> {
        let frames = match (event.kind, content) {
            (EventKind::Write, Some(data)) if !data.is_empty() => {
                wire::replay_content_frames(event, &self.ring, &self.nonces, data)?
            }
            _ => Vec::new(),
        };
        let mut kicked = Vec::new();
        for (session_id, session) in self.online.iter_mut() {
            if !session.state.receives_broadcast() {
                continue;
            }
            let mut delivered = true;
            for frame in &frames {
                match session.outbox.try_push_data(Bytes::from(frame.clone())) {
                    PushOutcome::Queued => {}
                    PushOutcome::Overflow => {
                        // A partially delivered event has no ORDERED, and a
                        // following ORDERED would leave a sequence hole that
                        // the client cannot repair. Stop the session instead:
                        // the queued prefix is contiguous, and the client
                        // replays the missing event on reconnect.
                        session.state = SessionState::Kicking;
                        kicked.push((*session_id, KickReason::QueueOverflow));
                        self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            session = ?session_id,
                            queued_bytes = session.outbox.queued.bytes(),
                            seq = seq.get(),
                            "downlink full; kicking the session instead of leaving a sequence hole"
                        );
                        delivered = false;
                        break;
                    }
                    PushOutcome::Closed => {
                        self.pending_detaches.push(*session_id);
                        delivered = false;
                        break;
                    }
                }
            }
            if !delivered {
                continue;
            }
            match session.outbox.try_push_data(ordered.clone()) {
                PushOutcome::Queued => session.last_good_seq = seq,
                PushOutcome::Overflow => {
                    session.state = SessionState::Kicking;
                    kicked.push((*session_id, KickReason::QueueOverflow));
                    self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        session = ?session_id,
                        queued_bytes = session.outbox.queued.bytes(),
                        seq = seq.get(),
                        "downlink full; kicking the session instead of leaving a sequence hole"
                    );
                }
                PushOutcome::Closed => self.pending_detaches.push(*session_id),
            }
        }
        self.pending_kicks.extend(kicked);
        Ok(())
    }

    fn fanout(&mut self, wire: Bytes, except: Option<SessionId>, seq: Option<Seq>) {
        let mut kicked = Vec::new();
        for (session_id, session) in self.online.iter_mut() {
            if !session.state.receives_broadcast() || except == Some(*session_id) {
                continue;
            }
            match session.outbox.try_push_data(wire.clone()) {
                PushOutcome::Queued => {
                    if let Some(seq) = seq {
                        session.last_good_seq = seq;
                    }
                }
                PushOutcome::Overflow => {
                    self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                    // A sequenced frame must never be skipped: the next
                    // ORDERED would expose a gap. Relay traffic has its own
                    // flow control, so only a stalled relay queue ends the
                    // session.
                    if seq.is_some()
                        || session.outbox.queued.since_drain() > DRAIN_GRACE
                    {
                        session.state = SessionState::Kicking;
                        kicked.push((*session_id, KickReason::QueueOverflow));
                        tracing::warn!(
                            session = ?session_id,
                            queued_bytes = session.outbox.queued.bytes(),
                            seq = seq.map(Seq::get),
                            "downlink full; kicking the session instead of leaving a sequence hole"
                        );
                    } else {
                        tracing::debug!(
                            session = ?session_id,
                            queued_bytes = session.outbox.queued.bytes(),
                            "relay frame dropped"
                        );
                    }
                }
                PushOutcome::Closed => self.pending_detaches.push(*session_id),
            }
        }
        self.pending_kicks.extend(kicked);
    }

    fn detach_now(&mut self, session_id: SessionId, inject_leave: bool, now_us: u64) {
        let Some(session) = self.online.remove(&session_id) else {
            return;
        };
        self.finish_detach(session, inject_leave, now_us);
    }

    fn detach_generation_now(
        &mut self,
        session_id: SessionId,
        generation: u64,
        inject_leave: bool,
        now_us: u64,
    ) {
        let Some(session) = self.online.remove_generation(&session_id, generation) else {
            return;
        };
        self.finish_detach(session, inject_leave, now_us);
    }

    fn finish_detach(&mut self, session: Session, inject_leave: bool, now_us: u64) {
        self.health.forget(session.session_id);
        self.awaiting_events.remove(&session.nonce);
        self.pending_events.remove(&session.nonce);
        self.release_relay(session.session_id, Instant::now());
        // `Kicking` is set on a live session before its queued kick runs, so
        // it still owns the locks that `LEAVE` must release.
        let inject_leave = inject_leave
            && matches!(
                session.state,
                SessionState::Online | SessionState::Replaying | SessionState::Kicking
            );
        if inject_leave {
            self.inject_leave(session.session_id, session.last_good_seq, now_us);
        }
    }

    fn kick_now(&mut self, session_id: SessionId, reason: KickReason, now_us: u64) {
        let Some(session) = self.online.remove(&session_id) else {
            return;
        };
        self.health.forget(session_id);
        self.awaiting_events.remove(&session.nonce);
        self.pending_events.remove(&session.nonce);
        if let Some(frame) = self.encode_kick(reason, session.last_good_seq) {
            let pushed = session.outbox.try_push_ctrl(frame);
            tracing::debug!(?session_id, ?reason, ?pushed, "kick queued");
        } else {
            tracing::warn!(?session_id, ?reason, "cannot encode the kick frame");
        }
        let dropped = self.relay.drop_by_session(session_id, Instant::now());
        for relay in dropped {
            if let Some(survivor) = relay.survivor(session_id) {
                self.send_error_to(survivor, TrnReason::NoPeer, Some(relay.id));
            }
        }
        let last_good = session.last_good_seq;
        // `Kicking` is set on a live session before its queued kick runs, so
        // it still owns the locks that `LEAVE` must release.
        let inject = kick::injects_leave(reason)
            && matches!(
                session.state,
                SessionState::Online | SessionState::Replaying | SessionState::Kicking
            );
        drop(session);
        if inject {
            self.inject_leave(session_id, last_good, now_us);
        }
    }

    fn inject_leave(&mut self, session_id: SessionId, last_good: Seq, now_us: u64) {
        let wire = self.synthesize_leave(session_id, last_good, now_us);
        if wire.is_empty() {
            return;
        }
        self.pending_leaves.push((session_id, last_good));
        self.pending_leave_wires.push(wire);
    }

    /// Commit queued `LEAVE` events and broadcast their frames.
    async fn flush_leaves(&mut self, now_us: u64) {
        while let Some(wire) = self.pending_leave_wires.pop() {
            let (session_id, _) = self
                .pending_leaves
                .pop()
                .unwrap_or((SessionId::ZERO, Seq::UNSEQUENCED));
            let before = self.last_op();
            match self
                .store
                .leave(session_id.to_le_bytes(), wire.clone())
                .await
            {
                CommitOutcome::Applied { seq, .. } => {
                    let seq = Seq(seq.max(0) as u64);
                    self.seq = seq.get();
                    self.seq_view.store(self.seq, Ordering::Release);
                    if let Ok(bytes) = wire::with_seq(&wire, seq) {
                        self.broadcast(Bytes::from(bytes), seq);
                        self.last_op_seq = seq.get();
                        self.note_work(before, Instant::now());
                    }
                }
                other => tracing::warn!(?other, "leave commit failed"),
            }
        }
        let _ = now_us;
    }

    fn synthesize_leave(&self, session_id: SessionId, last_good: Seq, now_us: u64) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sm/v2/leave\0");
        hasher.update(&session_id.to_le_bytes());
        hasher.update(&last_good.get().to_le_bytes());
        hasher.update(&now_us.to_le_bytes());
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        let payload = EventPayload::Leave.encode().unwrap_or_default();
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &[0u8; 16]);
        writer.u8(fid::F_OP_CLASS, 15);
        writer.bytes(fid::F_OP_ID, &op_id);
        writer.bytes(fid::F_EXTRA, &payload);
        let body = match writer.finish() {
            Ok(body) => body,
            Err(_) => return Vec::new(),
        };
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        let sealed = match Sealer::with_session_key(&self.ring.session_key(), &self.nonces).seal(
            &mut header,
            &Prefix::None,
            &body,
        ) {
            Ok(sealed) => sealed,
            Err(_) => return Vec::new(),
        };
        encode_frame(&FrameRef::new(&header, &Prefix::None, sealed.as_bytes())).unwrap_or_default()
    }

    fn encode_kick(&self, reason: KickReason, last_good: Seq) -> Option<Bytes> {
        let body = (KickMessage { reason }).encode().ok()?;
        let mut header = FrameHeader::new(MsgType::KICK, Flags::ENC, 0, last_good);
        let sealed = Sealer::with_session_key(&self.ring.session_key(), &self.nonces)
            .seal(&mut header, &Prefix::None, &body)
            .ok()?;
        let bytes = encode_frame(&FrameRef::new(&header, &Prefix::None, sealed.as_bytes())).ok()?;
        Some(Bytes::from(bytes))
    }

    fn flush_kicks(&mut self, now_us: u64) {
        while let Some((session, reason)) = self.pending_kicks.pop() {
            self.kick_now(session, reason, now_us);
        }
    }

    fn flush_detaches(&mut self, now_us: u64) {
        while let Some(session) = self.pending_detaches.pop() {
            self.detach_now(session, true, now_us);
        }
    }
}

fn encode_relay(frame: &FrameBuf) -> Option<Bytes> {
    encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
        .ok()
        .map(Bytes::from)
}

/// Whether an encoded frame is a plain client `LEAVE` notice.
fn is_leave_frame(frame: &[u8]) -> bool {
    frame.len() >= 3 && frame[0] == crate::protocol::MAGIC && frame[2] == MsgType::LEAVE.get()
}

/// Encode one server-authored plain control frame.
pub(crate) fn encode_control(
    msg_type: MsgType,
    prefix: Prefix,
    body: &[u8],
    seq: Seq,
) -> Result<Bytes, ProtocolError> {
    let mut flags = Flags::EMPTY;
    match prefix.kind() {
        PrefixKind::None => {}
        PrefixKind::Route => flags = flags.with(Flags::ROUTED),
        PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
    }
    if msg_type.body_encoding() == BodyEncoding::Sealed {
        flags = flags.with(Flags::ENC);
    }
    let mut header = FrameHeader::new(msg_type, flags, 0, seq);
    let len = prefix
        .encoded_len()
        .checked_add(body.len())
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(ProtocolError::BadLen {
            len: u32::MAX,
            prefix: prefix.encoded_len() as u8,
            cap: crate::protocol::FRAME_MAX,
        })?;
    header.len = len;
    let bytes = encode_frame(&FrameRef::new(&header, &prefix, body))?;
    Ok(Bytes::from(bytes))
}

/// Capabilities the server advertises.
pub(crate) fn server_caps() -> Caps {
    Caps::REQUIRED
}

/// Wall clock in microseconds, diagnostic only.
pub(crate) fn wall_clock_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Wall clock in seconds, for event timestamps.
pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::{FrameDecoder, Limits};

    fn decode(bytes: &Bytes) -> FrameBuf {
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(bytes).unwrap();
        decoder.next_frame_owned().unwrap().unwrap()
    }

    #[test]
    fn server_caps_require_only_the_psk_world() {
        let caps = server_caps();
        assert!(caps.contains(Caps::PSK_AUTH));
    }

    #[test]
    fn plain_error_encoding_keeps_the_header_contract() {
        let body = (ErrorMessage {
            reason: TrnReason::Internal,
            detail: b"x",
            session_id: None,
        })
        .encode()
        .unwrap();
        let frame = encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED).unwrap();
        let decoded = decode(&frame);
        assert_eq!(decoded.header.msg_type, MsgType::ERROR);
        assert_eq!(decoded.header.seq, Seq::UNSEQUENCED);
    }
}
