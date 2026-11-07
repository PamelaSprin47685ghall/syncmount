//! The single sequencer actor: one mutable total order.
//!
//! # Invariants
//!
//! * `seq` starts at 1 (0 means "unsequenced") and every sequenced event
//!   increments it by exactly one (42 I1). The only writer is [`SequencerCore`].
//! * The critical section between [`SequencerCore::stamp`] and
//!   [`SequencerCore::broadcast`] contains no `.await`, no lock and no I/O.
//!   The actor task is the only place session state mutates, so ordering,
//!   broadcast order and observation order coincide without synchronisation.
//! * Fan-out is one `Bytes` construction plus N reference-counted clones
//!   (42 §3.3). A consumer that stops draining is removed at its queue
//!   ceiling; a slow consumer that keeps draining stays attached, and the
//!   actor never blocks on either.
//! * Only `ORDERED`, `LEAVE` and the injected control frames are sequenced.
//!   `WELCOME`, `KICK` and `ERROR` carry `seq = 0` (or
//!   `last_good_seq` for `KICK`) and never advance the counter.
//!
//! # Handshake pairing
//!
//! The downlink and uplink of one session are paired by `X-SM-Nonce`, never
//! by address (42 §7.3). Both arrival orders are supported: an early
//! downlink parks in `pending_events`, an early uplink leaves a one-shot
//! sender in `awaiting_events`. The actor owns both maps, so pairing needs
//! no mutex and no cross-task shared state.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::protocol::{
    BodyEncoding, Caps, ClientId, ErrorMessage, Flags, FrameBuf, FrameEncoder, FrameHeader,
    FrameRef, JoinState, KickReason, Leave, Message, MsgType, Prefix, PrefixKind, ProtoVersion,
    ProtocolError, ResyncMode, Seq, SessionId, SnapshotRef, TrnReason, Welcome, WelcomeLimits,
    decode_plain,
};
use crate::transport::{MpscSender, PeerId};

use super::Epoch;
use super::config::ServeConfig;
use super::health::{HealthLimits, HealthMonitor};
use super::kick::{self, KickPlan};
use super::online::{
    DRAIN_GRACE, OnlineTable, Outbox, PushOutcome, QueueStats, Session, SessionInit, SessionState,
    WatermarkVerdict,
};
use super::relay::{RelayHub, RelayLimits, RouteAction};
use super::snapshot_registry::{SnapshotLimits, SnapshotRegistry};
use super::view_registry::ViewChoice;

pub use super::metrics::Metrics;

/// Actor handle. Cheap to clone; every clone feeds the same channel.
#[derive(Clone, Debug)]
pub struct Sequencer {
    cmd_tx: mpsc::Sender<SeqCmd>,
    seq_view: Arc<AtomicU64>,
    epoch: Epoch,
    metrics: Arc<Metrics>,
}

/// Why a sequencer call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SequencerError {
    /// The actor task has stopped.
    #[error("sequencer stopped")]
    Stopped,
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
    /// A waiting `HELLO` claimed it immediately.
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

/// One `HELLO` and the queues that belong to it.
#[derive(Debug)]
pub struct HelloRequest {
    /// Pairing token.
    pub nonce: u64,
    /// Identity claimed by the client.
    pub client_id: ClientId,
    /// Epoch the client last saw.
    pub epoch_seen: u64,
    /// Applied sequence reported by the client.
    pub applied_seq: Seq,
    /// Diagnostic connection handle.
    pub peer: PeerId,
    /// Downlink queues (the actor keeps the senders).
    pub outbox: Outbox,
    /// Data receiver for the session writer.
    pub data: mpsc::Receiver<Bytes>,
    /// Control receiver for the session writer.
    pub ctrl: mpsc::Receiver<Bytes>,
}

/// What the actor hands back after a successful `HELLO`.
#[derive(Debug)]
pub struct HelloReply {
    /// Assigned (echoed) identity.
    pub client_id: ClientId,
    /// Generation of the attached session.
    ///
    /// The uplink passes it back on detach so a late disconnect from a
    /// replaced connection cannot remove its successor.
    pub generation: u64,
    /// Server epoch.
    pub epoch: u64,
    /// Sequence at attach time.
    pub current_seq: Seq,
    /// Downlink, if it arrived before the uplink.
    pub events: Option<MpscSender>,
    /// Downlink, if it has not arrived yet.
    pub wait: Option<oneshot::Receiver<MpscSender>>,
    /// Data receiver for the writer.
    pub data: mpsc::Receiver<Bytes>,
    /// Control receiver for the writer.
    pub ctrl: mpsc::Receiver<Bytes>,
    /// Control sender, for protocol errors raised outside the actor.
    pub ctrl_tx: mpsc::Sender<Bytes>,
    /// Queue accounting shared with the writer.
    pub queued: Arc<QueueStats>,
}

/// One watermark observation.
#[derive(Clone, Copy, Debug)]
pub struct WatermarkReport {
    /// Reporting session.
    pub client: ClientId,
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
    /// Sessions that can receive broadcasts.
    pub online: usize,
    /// Sessions still waiting for a downlink.
    pub awaiting: usize,
    /// Sessions resynchronizing after an epoch mismatch.
    pub resyncing: usize,
}

/// Commands accepted by the actor.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SeqCmd {
    /// Attach an uplink.
    Hello {
        /// Parsed request.
        request: Box<HelloRequest>,
        /// Capability bits advertised by the client in `HELLO`.
        caps: Caps,
        /// Reply channel.
        reply: oneshot::Sender<Result<HelloReply, TrnReason>>,
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
    /// Sequence and broadcast one client frame.
    Ordered {
        /// Author.
        from: ClientId,
        /// Frame with an unsequenced header.
        frame: Box<FrameBuf>,
    },
    /// Route one `RELAY`/`FLOW`/`SYNC_END`/`STREAM_DATA` frame.
    Relay {
        /// Author.
        from: ClientId,
        /// Decoded frame; body and route prefix stay opaque.
        frame: Box<FrameBuf>,
    },
    /// Update a watermark.
    Watermark(WatermarkReport),
    /// Record that a valid uplink frame arrived.
    Seen {
        /// Author.
        client: ClientId,
    },
    /// Broadcast a `LEAVE` and detach.
    Leave {
        /// Author.
        client: ClientId,
        /// Client-provided frame, or `None` for a server-injected notice.
        frame: Option<Box<FrameBuf>>,
    },
    /// Remove a session.
    Detach {
        /// Session to remove.
        client: ClientId,
        /// Generation assigned at attach.
        generation: u64,
        /// Why.
        cause: DetachCause,
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
    /// Stop the actor.
    Shutdown,
}

impl Sequencer {
    /// Start the actor task.
    pub fn start(
        config: Arc<ServeConfig>,
        epoch: Epoch,
        metrics: Arc<Metrics>,
    ) -> (Self, JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(config.command_capacity.max(1));
        let seq_view = Arc::new(AtomicU64::new(0));
        let core = SequencerCore {
            seq: 0,
            last_op_seq: 0,
            last_ts_us: 0,
            epoch,
            online: OnlineTable::new(),
            generation: 0,
            relay: RelayHub::new(RelayLimits::default()),
            health: HealthMonitor::new(HealthLimits::default()),
            snapshots: SnapshotRegistry::new(SnapshotLimits::default()),
            pending_events: HashMap::new(),
            awaiting_events: HashMap::new(),
            pending_kicks: Vec::new(),
            pending_detaches: Vec::new(),
            encoder: FrameEncoder::with_capacity(4096),
            config,
            metrics: Arc::clone(&metrics),
            seq_view: Arc::clone(&seq_view),
            fatal: false,
        };
        let task = tokio::spawn(core.run(cmd_rx));
        (
            Self {
                cmd_tx,
                seq_view,
                epoch,
                metrics,
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

    /// Attach one uplink.
    pub async fn hello(&self, request: HelloRequest) -> Result<HelloReply, TrnReason> {
        self.hello_with_caps(request, Caps::EMPTY).await
    }

    /// Attach one uplink, carrying the client's negotiated `HELLO` caps.
    ///
    /// `VIEW_SOURCE` is the only bit the welcome path reads; callers that do
    /// not negotiate capabilities keep [`Sequencer::hello`] and receive a
    /// `WELCOME` without view-source fields.
    pub async fn hello_with_caps(
        &self,
        request: HelloRequest,
        caps: Caps,
    ) -> Result<HelloReply, TrnReason> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SeqCmd::Hello {
                request: Box::new(request),
                caps,
                reply,
            })
            .await
            .map_err(|_| TrnReason::Internal)?;
        rx.await.map_err(|_| TrnReason::Internal)?
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

    /// Sequence and broadcast one `ORDERED` frame.
    pub async fn ordered(&self, from: ClientId, frame: FrameBuf) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Ordered {
                from,
                frame: Box::new(frame),
            })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Route one relay-path frame.
    pub async fn relay(&self, from: ClientId, frame: FrameBuf) -> Result<(), SequencerError> {
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
    pub async fn seen(&self, client: ClientId) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Seen { client })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Broadcast a `LEAVE` and detach.
    pub async fn leave(
        &self,
        client: ClientId,
        frame: Option<FrameBuf>,
    ) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Leave {
                client,
                frame: frame.map(Box::new),
            })
            .await
            .map_err(|_| SequencerError::Stopped)
    }

    /// Remove a session.
    pub async fn detach(
        &self,
        client: ClientId,
        generation: u64,
        cause: DetachCause,
    ) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Detach {
                client,
                generation,
                cause,
            })
            .await
            .map_err(|_| SequencerError::Stopped)
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

    /// Stop the actor. Idempotent: a second call observes a closed channel.
    pub async fn shutdown(&self) -> Result<(), SequencerError> {
        self.cmd_tx
            .send(SeqCmd::Shutdown)
            .await
            .map_err(|_| SequencerError::Stopped)
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

struct SequencerCore {
    seq: u64,
    /// Highest `ORDERED` sequence. `LEAVE` also consumes a sequence, but it
    /// assigns no work, so the health gate must not count it.
    last_op_seq: u64,
    last_ts_us: u64,
    epoch: Epoch,
    online: OnlineTable,
    generation: u64,
    relay: RelayHub,
    health: HealthMonitor,
    snapshots: SnapshotRegistry,
    pending_events: HashMap<u64, PendingEvents>,
    awaiting_events: HashMap<u64, AwaitingEvents>,
    pending_kicks: Vec<(ClientId, KickReason)>,
    /// Sessions whose writer is gone. Processed iteratively after the current
    /// command, so a `LEAVE` broadcast can queue more without recursion.
    pending_detaches: Vec<ClientId>,
    encoder: FrameEncoder,
    config: Arc<ServeConfig>,
    metrics: Arc<Metrics>,
    seq_view: Arc<AtomicU64>,
    fatal: bool,
}

impl SequencerCore {
    async fn run(mut self, mut rx: mpsc::Receiver<SeqCmd>) {
        while let Some(cmd) = rx.recv().await {
            let now = Instant::now();
            let now_us = wall_clock_us();
            let mut stop = false;
            match cmd {
                SeqCmd::Hello {
                    request,
                    caps,
                    reply,
                } => {
                    let client = request.client_id;
                    let result = self.on_hello(*request, caps, now, now_us);
                    if reply.send(result).is_err() {
                        self.detach_now(client, false, now_us);
                    }
                }
                SeqCmd::Events { nonce, out, reply } => {
                    let _ = reply.send(self.on_events(nonce, out, now));
                }
                SeqCmd::Ordered { from, frame } => self.on_ordered(from, *frame, now, now_us),
                SeqCmd::Relay { from, frame } => self.on_relay(from, *frame, now),
                SeqCmd::Watermark(report) => self.on_watermark(report),
                SeqCmd::Seen { client } => self.on_seen(client, now),
                SeqCmd::Leave { client, frame } => {
                    self.on_leave(client, frame.map(|frame| *frame), now, now_us);
                }
                SeqCmd::Detach {
                    client,
                    generation,
                    cause,
                } => self.on_detach(client, generation, cause, now_us),
                SeqCmd::Tick { now } => self.on_tick(now),
                SeqCmd::Snapshot { reply } => {
                    let _ = reply.send(self.snapshot());
                }
                SeqCmd::Shutdown => {
                    self.on_shutdown(now_us);
                    stop = true;
                }
            }
            self.flush_kicks(now_us);
            self.flush_detaches(now_us);
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

    /// Highest `ORDERED` sequence; see [`SequencerCore::last_op_seq`].
    fn last_op(&self) -> Seq {
        Seq(self.last_op_seq)
    }

    /// Start the lag clock for every session that was caught up before this
    /// operation.
    ///
    /// A session that already has an outstanding operation keeps its clock:
    /// new work must not postpone the kick of a client that is not applying.
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

    /// Allocate the next connection generation.
    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    /// Advance the sequence once.
    ///
    /// Wall clock is diagnostic only (49 D-1): it never orders events and
    /// never appears in a frame header. It is clamped so `server_time` in
    /// `WELCOME`/`PONG` never goes backwards (23 §1.2).
    fn stamp(&mut self, now_us: u64) -> Option<Seq> {
        let ts = now_us.max(self.last_ts_us);
        self.last_ts_us = ts;
        let next = self.seq.checked_add(1)?;
        self.seq = next;
        self.seq_view.store(next, Ordering::Release);
        Some(Seq(next))
    }

    fn on_hello(
        &mut self,
        request: HelloRequest,
        caps: Caps,
        now: Instant,
        now_us: u64,
    ) -> Result<HelloReply, TrnReason> {
        let HelloRequest {
            nonce,
            client_id,
            epoch_seen,
            applied_seq,
            peer,
            outbox,
            data,
            ctrl,
        } = request;
        if self.online.contains_nonce(nonce) || self.awaiting_events.contains_key(&nonce) {
            return Err(TrnReason::Protocol);
        }
        // T4: kick the old session before the new one joins the broadcast set,
        // so the newcomer never observes the predecessor's LEAVE (42 D7).
        if self.online.contains(&client_id) {
            self.kick_now(client_id, KickReason::DuplicateClient, now_us);
        }
        // A new connection replaces every token minted for the old one,
        // whether this client was the joiner or the holder.
        self.relay.views_mut().invalidate(client_id);
        let current = self.current_seq();
        let welcome = self.build_welcome(client_id, caps, epoch_seen, applied_seq, now_us, now)?;
        let queued = Arc::clone(&outbox.queued);
        let ctrl_tx = outbox.ctrl.clone();
        let (state, events, wait) = match self.pending_events.remove(&nonce) {
            Some(parked) => (SessionState::Online, Some(parked.out), None),
            None => {
                let (tx, rx) = oneshot::channel();
                self.awaiting_events.insert(
                    nonce,
                    AwaitingEvents {
                        reply: tx,
                        since: now,
                    },
                );
                (SessionState::AwaitingDownstream, None, Some(rx))
            }
        };
        let mut session = Session::new(SessionInit {
            client_id,
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
        session.state = state;
        let _ = session.outbox.try_push_ctrl(welcome);
        // A joining client may pull a large view before its first write. No
        // timer watches it: the connection and the kernel keepalive decide
        // whether it is still alive.
        self.online.insert(session);
        if epoch_seen == self.epoch.get() && applied_seq > current {
            self.pending_kicks.push((client_id, KickReason::Overclaim));
        }
        Ok(HelloReply {
            client_id,
            generation,
            epoch: self.epoch.get(),
            current_seq: current,
            events,
            wait,
            data,
            ctrl,
            ctrl_tx,
            queued,
        })
    }

    fn build_welcome(
        &mut self,
        client_id: ClientId,
        client_caps: Caps,
        epoch_seen: u64,
        applied_seq: Seq,
        now_us: u64,
        now: Instant,
    ) -> Result<Bytes, TrnReason> {
        let current = self.current_seq();
        let ts = now_us.max(self.last_ts_us);
        self.last_ts_us = ts;
        let resync = if epoch_seen != self.epoch.get() || applied_seq > current {
            ResyncMode::Full
        } else {
            ResyncMode::ManifestDiff
        };
        let mut server_nonce = [0_u8; 32];
        for chunk in server_nonce.chunks_mut(8) {
            chunk.copy_from_slice(&rand::random::<u64>().to_le_bytes());
        }
        // Both endpoints must advertise `VIEW_SOURCE`; otherwise the view
        // fields stay absent and the joiner uses the snapshot path. A self
        // view additionally needs `VIEW_SELF` on both sides.
        // The one-sequence gap a self view tolerates must be a `LEAVE`
        // pseudo-operation, never an `ORDERED` the client failed to apply.
        // `last_op` is the highest sequenced operation; a content gap makes
        // `applied < last_op` and forbids the self view.
        let allow_self = server_caps().contains(Caps::VIEW_SELF)
            && client_caps.contains(Caps::VIEW_SELF)
            && applied_seq >= self.last_op();
        let view = if server_caps().contains(Caps::VIEW_SOURCE)
            && client_caps.contains(Caps::VIEW_SOURCE)
        {
            self.relay.views_mut().select_view_or_self(
                &self.online,
                client_id,
                current,
                applied_seq,
                epoch_seen,
                self.epoch.get(),
                allow_self,
                now,
            )
        } else {
            None
        };
        let (view_holder, view_seq, view_session, view_self) = match view {
            Some(ViewChoice::Holder(source)) => (
                Some(source.holder),
                Some(source.seq),
                Some(source.session),
                false,
            ),
            // Protocol B: a self view carries no holder, sequence or session
            // fields; the client uses `current_seq` and its local manifest.
            Some(ViewChoice::SelfView { .. }) => (None, None, None, true),
            None => (None, None, None, false),
        };
        let welcome = Welcome {
            proto: ProtoVersion::CURRENT,
            caps: server_caps(),
            epoch: self.epoch.get(),
            current_seq: current,
            client_id,
            resync,
            limits: WelcomeLimits {
                max_frame: self.config.limits.effective_cap(),
                credit_bytes: self.config.welcome.credit_bytes,
                session_ttl_s: self.config.welcome.session_ttl_s,
                max_sessions: self.config.welcome.max_sessions,
            },
            server_time: ts,
            server_nonce,
            join_state: JoinState::Accepted,
            session_id: None,
            // `part_count` and `total_len` are not part of the registry's
            // frozen three-field view; zero means "ask the holder".
            snapshot_ref: self.snapshots.view_fresh(now).map(|entry| SnapshotRef {
                covered_seq: entry.covered_seq.get(),
                part_count: 0,
                total_len: 0,
                root_chunk_id: entry.root_chunk_id,
                holder: entry.holder,
            }),
            view_holder,
            view_seq,
            view_session,
            view_self,
        };
        let body = welcome.encode().map_err(|_| TrnReason::Internal)?;
        encode_control(MsgType::WELCOME, Prefix::None, &body, Seq::UNSEQUENCED)
            .map_err(|_| TrnReason::Internal)
    }

    fn on_events(
        &mut self,
        nonce: u64,
        out: MpscSender,
        now: Instant,
    ) -> Result<EventsOutcome, EventsReject> {
        // An uplink that is still waiting for its downlink is the common
        // case and must be resolved before the `by_nonce` index is consulted:
        // the session is already attached, but not yet paired.
        if let Some(waiting) = self.awaiting_events.remove(&nonce) {
            let Some(client) = self.online.nonce_of(nonce) else {
                return Err(EventsReject::Closed);
            };
            if let Some(session) = self.online.get_mut(&client) {
                session.state = SessionState::Online;
            }
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

    fn on_ordered(&mut self, from: ClientId, frame: FrameBuf, now: Instant, now_us: u64) {
        if !self.online.contains(&from) {
            return;
        }
        if let Some(session) = self.online.get_mut(&from) {
            session.last_seen_at = now;
        }
        if frame.header.msg_type != MsgType::ORDERED
            || frame.header.seq != Seq::UNSEQUENCED
            || frame.prefix.kind() != PrefixKind::None
        {
            self.reject(from, TrnReason::Protocol, now_us);
            return;
        }
        let before = self.last_op();
        let Some(seq) = self.stamp(now_us) else {
            self.fatal = true;
            return;
        };
        let header = frame.header.with_seq(seq);
        match self
            .encoder
            .encode(&FrameRef::new(&header, &frame.prefix, &frame.body))
        {
            Ok(bytes) => {
                let wire = Bytes::copy_from_slice(bytes);
                self.broadcast(wire, seq);
                self.last_op_seq = seq.get();
                self.note_work(before, now);
            }
            Err(_) => self.reject(from, TrnReason::BadFrame, now_us),
        }
    }

    /// Route one relay-path frame without touching its bytes.
    fn on_relay(&mut self, from: ClientId, frame: FrameBuf, now: Instant) {
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
        let action = if kind == MsgType::FLOW {
            match decode_plain(MsgType::FLOW, &frame.body, &self.config.limits) {
                Ok(Message::Flow(flow)) => {
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
                let Some(wire) = self.encode_relay(&frame) else {
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

    fn encode_relay(&mut self, frame: &FrameBuf) -> Option<Bytes> {
        self.encoder
            .encode(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
            .ok()
            .map(Bytes::copy_from_slice)
    }

    fn forward_relay(&mut self, from: ClientId, to: ClientId, wire: Bytes, id: SessionId) {
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
                    tracing::debug!(
                        client = ?to,
                        session = id.get(),
                        "relay queue full but draining; frame dropped, requester retries"
                    );
                }
            }
            PushOutcome::Closed => {
                self.pending_detaches.push(to);
                self.send_error_to(from, TrnReason::NoPeer, Some(id));
            }
        }
    }

    fn send_error_to(&self, client: ClientId, reason: TrnReason, id: Option<SessionId>) {
        let Some(session) = self.online.get(&client) else {
            return;
        };
        if let Some(frame) = kick::encode_error(reason, id) {
            let _ = session.outbox.try_push_ctrl(frame);
        }
    }

    /// Release route slots held by `client` and tell each survivor.
    fn release_relay(&mut self, client: ClientId, now: Instant) {
        let dropped = self.relay.drop_by_client(client, now);
        for session in dropped {
            if let Some(survivor) = session.survivor(client) {
                self.send_error_to(survivor, TrnReason::NoPeer, Some(session.id));
            }
        }
    }

    fn on_watermark(&mut self, report: WatermarkReport) {
        let current = self.current_seq();
        let epoch = self.epoch.get();
        let Some(session) = self.online.get_mut(&report.client) else {
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
                self.pending_kicks.push((report.client, reason));
                return;
            }
            WatermarkVerdict::EpochMismatch => {
                session.state = SessionState::Resyncing;
            }
            WatermarkVerdict::Unchanged | WatermarkVerdict::Advanced => {}
        }
        if let Some(rtt) = report.rtt_ms {
            session.watermark.push_rtt(rtt);
        }
        session.last_seen_at = report.at;
    }

    /// Refresh the liveness timestamp of one valid frame that carries no
    /// watermark (`ACK`, `RESPONSE`). Nothing else changes.
    fn on_seen(&mut self, client: ClientId, now: Instant) {
        if let Some(session) = self.online.get_mut(&client) {
            session.last_seen_at = now;
        }
    }

    fn on_leave(&mut self, client: ClientId, frame: Option<FrameBuf>, now: Instant, now_us: u64) {
        if let Some(session) = self.online.get_mut(&client) {
            session.last_seen_at = now;
        }
        let Some(session) = self.online.get(&client) else {
            return;
        };
        let last_good = session.last_good_seq;
        let Some(seq) = self.stamp(now_us) else {
            self.fatal = true;
            return;
        };
        let wire = match frame {
            Some(frame) => {
                if frame.header.msg_type != MsgType::LEAVE
                    || frame.header.seq != Seq::UNSEQUENCED
                    || frame.prefix.kind() != PrefixKind::None
                {
                    self.reject(client, TrnReason::Protocol, now_us);
                    return;
                }
                let header = frame.header.with_seq(seq);
                self.encoder
                    .encode(&FrameRef::new(&header, &frame.prefix, &frame.body))
                    .map(Bytes::copy_from_slice)
                    .ok()
            }
            None => (Leave {
                client_id: client,
                reason: 0,
                last_signed_seq: last_good.get(),
            })
            .encode()
            .ok()
            .and_then(|body| encode_control(MsgType::LEAVE, Prefix::None, &body, seq).ok()),
        };
        if let Some(wire) = wire {
            // The author is still attached here, so it observes its own LEAVE
            // at the same sequence every other client does (42 §6.4).
            self.broadcast(wire, seq);
        }
        self.detach_now(client, false, now_us);
    }

    fn on_detach(&mut self, client: ClientId, generation: u64, cause: DetachCause, now_us: u64) {
        match cause {
            DetachCause::ClientLeft | DetachCause::WriterClosed => {
                self.detach_generation_now(client, generation, false, now_us);
            }
            DetachCause::Disconnected | DetachCause::Protocol => {
                self.detach_generation_now(client, generation, cause.injects_leave(), now_us);
            }
        }
    }

    fn on_tick(&mut self, now: Instant) {
        let ttl = self.config.pair_timeout;
        self.pending_events
            .retain(|_, parked| now.saturating_duration_since(parked.parked_at) < ttl);
        self.awaiting_events
            .retain(|_, waiting| now.saturating_duration_since(waiting.since) < ttl);
        let current = self.current_seq();
        let work = self.last_op();
        let _expired_views = self.relay.views_mut().on_tick(now);
        let reaped = self.relay.reap(now);
        for session in reaped {
            self.send_error_to(session.origin, TrnReason::NoPeer, Some(session.id));
            self.send_error_to(session.peer, TrnReason::NoPeer, Some(session.id));
        }
        // Health is diagnostic only: no tick ends a session. A session that
        // is behind its threshold is logged (throttled per client) and
        // published as a gauge; the connection decides whether it is alive.
        let mut max_lag_ms = 0_u64;
        let mut max_pending = 0_u64;
        for (client, session) in self.online.iter_mut() {
            let Some(diagnosis) = self.health.diagnose(session, work, now) else {
                continue;
            };
            max_lag_ms =
                max_lag_ms.max(u64::try_from(diagnosis.lag.as_millis()).unwrap_or(u64::MAX));
            max_pending = max_pending.max(diagnosis.pending_ops);
            if self.health.should_report(*client, now) {
                tracing::warn!(
                    client = ?client,
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
        // The frozen wire has no plaintext snapshot control frame (44); the
        // join coordinator owns delivery. The registry still expires grants
        // and advances `SNAPSHOT_NOW` rate limiting here.
        let _actions = self.snapshots.on_tick(&self.online, current, now);
    }

    fn snapshot(&self) -> SeqSnapshot {
        let mut online = 0;
        let mut awaiting = 0;
        let mut resyncing = 0;
        for (_, session) in self.online.iter() {
            match session.state {
                SessionState::Online => online += 1,
                SessionState::AwaitingDownstream => awaiting += 1,
                SessionState::Resyncing => resyncing += 1,
                SessionState::Kicking => {}
            }
        }
        SeqSnapshot {
            epoch: self.epoch.get(),
            current_seq: self.current_seq(),
            clients: self.online.len(),
            online,
            awaiting,
            resyncing,
        }
    }

    fn on_shutdown(&mut self, now_us: u64) {
        let clients: Vec<ClientId> = self.online.iter_mut().map(|(client, _)| *client).collect();
        for client in clients {
            self.kick_now(client, KickReason::ServerShutdown, now_us);
        }
    }

    /// Broadcast one encoded frame to every non-kicking session.
    ///
    /// `Bytes` clones are reference-count bumps; the actor performs one
    /// `try_send` per session and never awaits.
    ///
    /// An overflow ends a session only when the queue has not drained for
    /// [`DRAIN_GRACE`]: a slow consumer that keeps taking frames stays
    /// attached, and the one frame that did not fit is counted and dropped
    /// so the queue stays bounded. The client sees the sequence gap and
    /// resynchronizes; nothing is lost silently.
    fn broadcast(&mut self, wire: Bytes, seq: Seq) {
        let mut kicked = Vec::new();
        for (client, session) in self.online.iter_mut() {
            if !session.state.receives_broadcast() {
                continue;
            }
            match session.outbox.try_push_data(wire.clone()) {
                PushOutcome::Queued => session.last_good_seq = seq,
                PushOutcome::Overflow if session.outbox.queued.since_drain() > DRAIN_GRACE => {
                    kicked.push((*client, KickReason::QueueOverflow));
                }
                PushOutcome::Overflow => {
                    self.metrics.dropped_frames.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        client = ?client,
                        queued_bytes = session.outbox.queued.bytes(),
                        "downlink queue full but draining; frame dropped, client will resync"
                    );
                }
                // The writer half is gone: the connection is dead, not slow.
                PushOutcome::Closed => self.pending_detaches.push(*client),
            }
        }
        self.pending_kicks.extend(kicked);
    }

    fn reject(&mut self, client: ClientId, reason: TrnReason, now_us: u64) {
        if let Some(session) = self.online.get(&client) {
            if let Ok(body) = (ErrorMessage {
                reason,
                detail: &[],
                session_id: None,
            })
            .encode()
            {
                if let Ok(frame) =
                    encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED)
                {
                    let _ = session.outbox.try_push_ctrl(frame);
                }
            }
        }
        self.detach_now(client, true, now_us);
    }

    /// Remove a session, optionally broadcasting a `LEAVE` first.
    fn detach_now(&mut self, client: ClientId, inject_leave: bool, now_us: u64) {
        let Some(session) = self.online.remove(&client) else {
            return;
        };
        self.finish_detach(session, inject_leave, now_us);
    }

    /// Remove a session only if it still belongs to `generation`.
    ///
    /// The uplink names the generation it attached with, so a detach that
    /// races a replacement HELLO observes the successor and does nothing.
    fn detach_generation_now(
        &mut self,
        client: ClientId,
        generation: u64,
        inject_leave: bool,
        now_us: u64,
    ) {
        let Some(session) = self.online.remove_generation(&client, generation) else {
            return;
        };
        self.finish_detach(session, inject_leave, now_us);
    }

    fn finish_detach(&mut self, session: Session, inject_leave: bool, now_us: u64) {
        self.health.forget(session.client_id);
        self.awaiting_events.remove(&session.nonce);
        self.pending_events.remove(&session.nonce);
        self.relay.views_mut().invalidate(session.client_id);
        // A session that never became `Online` never paired its downlink, so
        // no peer observed it as joined. Injecting `LEAVE` for it would
        // advance `current`, so a retrying joiner whose watermark lags could
        // never satisfy the view-selection equality again (hp1 live lock).
        // `Kicking` is excluded as well: the kick already carries its notice.
        let inject_leave = inject_leave
            && session.state != SessionState::AwaitingDownstream
            && session.state.receives_broadcast();
        self.release_relay(session.client_id, Instant::now());
        if inject_leave {
            self.inject_leave(session.client_id, session.last_good_seq, now_us);
        }
    }

    /// Kick a session: leave the broadcast set, queue `KICK`, inject `LEAVE`.
    ///
    /// The sender halves are dropped when `session` goes out of scope; the
    /// writer drains what was already queued and then writes the deferred
    /// `KICK` (42 §6.4, I9).
    fn kick_now(&mut self, client: ClientId, reason: KickReason, now_us: u64) {
        self.relay.views_mut().invalidate(client);
        let Some(plan) = KickPlan::prepare(
            &mut self.online,
            &mut self.relay,
            client,
            reason,
            Instant::now(),
        ) else {
            return;
        };
        self.health.forget(client);
        self.awaiting_events.remove(&plan.session.nonce);
        self.pending_events.remove(&plan.session.nonce);
        let dropped = plan.dropped_relay().to_vec();
        let (session, inject_leave) = plan.deliver();
        let last_good = session.last_good_seq;
        for relay in dropped {
            if let Some(survivor) = relay.survivor(client) {
                self.send_error_to(survivor, TrnReason::NoPeer, Some(relay.id));
            }
        }
        // Dropping the session closes both writer channels after the queued
        // KICK has been drained.
        drop(session);
        if inject_leave {
            self.inject_leave(client, last_good, now_us);
        }
    }

    fn inject_leave(&mut self, client: ClientId, last_good: Seq, now_us: u64) {
        let Some(seq) = self.stamp(now_us) else {
            self.fatal = true;
            return;
        };
        let Ok(body) = (Leave {
            client_id: client,
            reason: 0,
            last_signed_seq: last_good.get(),
        })
        .encode() else {
            return;
        };
        if let Ok(frame) = encode_control(MsgType::LEAVE, Prefix::None, &body, seq) {
            self.broadcast(frame, seq);
        }
    }

    fn flush_kicks(&mut self, now_us: u64) {
        while let Some((client, reason)) = self.pending_kicks.pop() {
            self.kick_now(client, reason, now_us);
        }
    }

    /// Detach sessions whose writer half is gone.
    ///
    /// The queue is drained iteratively: `detach_now` broadcasts a `LEAVE`,
    /// which may discover more closed writers. Recursion would make the
    /// depth depend on how many sessions died at once.
    fn flush_detaches(&mut self, now_us: u64) {
        while let Some(client) = self.pending_detaches.pop() {
            self.detach_now(client, true, now_us);
        }
    }
}

/// Encode one server-authored control frame.
///
/// `len` is derived from the parts and checked by the encoder, so the only
/// mutable header field the server ever sets is `seq` (42 I4).
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
    let mut encoder = FrameEncoder::with_capacity(
        crate::protocol::HEADER_LEN + prefix.encoded_len() + body.len(),
    );
    let bytes = encoder.encode(&FrameRef::new(&header, &prefix, body))?;
    Ok(Bytes::copy_from_slice(bytes))
}

/// Capabilities the server advertises.
pub(crate) fn server_caps() -> Caps {
    Caps::REQUIRED
        .union(Caps::SNAPSHOT_RSYNC)
        .union(Caps::VIEW_SOURCE)
        .union(Caps::VIEW_SELF)
}

/// Wall clock in microseconds, diagnostic only.
fn wall_clock_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::{FrameDecoder, Message, Seq, decode_plain};
    use crate::server::config::OutboxConfig;
    use crate::server::online::Outbox;
    use std::time::Duration;

    fn client(byte: u8) -> ClientId {
        ClientId::from_bytes([byte; 16])
    }

    fn ordered_frame() -> FrameBuf {
        let body = vec![0x5a; 30];
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(body.len()).unwrap();
        FrameBuf::new(header, Prefix::None, body)
    }

    async fn start(config: ServeConfig, epoch: u64) -> (Sequencer, Arc<Metrics>, JoinHandle<()>) {
        let epoch = Epoch::new(epoch);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, task) = Sequencer::start(Arc::new(config), epoch, Arc::clone(&metrics));
        (sequencer, metrics, task)
    }

    async fn register(
        sequencer: &Sequencer,
        id: ClientId,
        nonce: u64,
        config: &OutboxConfig,
    ) -> HelloReply {
        register_with_caps(sequencer, id, nonce, config, Caps::EMPTY).await
    }

    async fn register_with_caps(
        sequencer: &Sequencer,
        id: ClientId,
        nonce: u64,
        config: &OutboxConfig,
        caps: Caps,
    ) -> HelloReply {
        register_full(sequencer, id, nonce, config, caps, Seq::UNSEQUENCED).await
    }

    async fn register_full(
        sequencer: &Sequencer,
        id: ClientId,
        nonce: u64,
        config: &OutboxConfig,
        caps: Caps,
        applied_seq: Seq,
    ) -> HelloReply {
        let (outbox, data, ctrl) = Outbox::new(config);
        let request = HelloRequest {
            nonce,
            client_id: id,
            epoch_seen: sequencer.epoch().get(),
            applied_seq,
            peer: PeerId::from_serial(nonce),
            outbox,
            data,
            ctrl,
        };
        sequencer.hello_with_caps(request, caps).await.unwrap()
    }

    fn relay_open_frame(id: SessionId) -> FrameBuf {
        relay_frame(id, crate::protocol::StreamId::CTRL, 32)
    }

    fn relay_data_frame(id: SessionId, body_len: usize) -> FrameBuf {
        relay_frame(id, crate::protocol::StreamId::BLOCK, body_len)
    }

    fn relay_frame(id: SessionId, stream: crate::protocol::StreamId, body_len: usize) -> FrameBuf {
        let prefix = Prefix::Route(crate::protocol::RoutePrefix::new(id, stream, 0, 0));
        let body = vec![0x5a; body_len];
        let mut header = FrameHeader::new(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
        FrameBuf::new(header, prefix, body)
    }

    fn take_kick(ctrl: &mut mpsc::Receiver<Bytes>) -> Option<KickReason> {
        while let Ok(bytes) = ctrl.try_recv() {
            let frame = decode(&bytes);
            if frame.header.msg_type == MsgType::KICK {
                return Some(kick_reason(&bytes));
            }
        }
        None
    }

    async fn welcome_of(ctrl: &mut mpsc::Receiver<Bytes>) -> crate::protocol::Welcome {
        let bytes = ctrl.recv().await.unwrap();
        let frame = decode(&bytes);
        assert_eq!(frame.header.msg_type, MsgType::WELCOME);
        match decode_plain(
            MsgType::WELCOME,
            &frame.body,
            &crate::protocol::Limits::default(),
        )
        .unwrap()
        {
            Message::Welcome(welcome) => welcome,
            other => panic!("expected WELCOME, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_welcome_names_a_caught_up_view_holder_when_both_sides_opt_in() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let holder = client(0x21);
        let joiner = client(0x22);

        let _holder_reply = register(&sequencer, holder, 21, &outbox).await;
        let (events, _body) = crate::transport::MpscBody::channel(4);
        sequencer.events(21, events).await.unwrap();

        let mut joiner_reply =
            register_with_caps(&sequencer, joiner, 22, &outbox, Caps::VIEW_SOURCE).await;
        let welcome = welcome_of(&mut joiner_reply.ctrl).await;
        assert_eq!(welcome.view_holder, Some(holder));
        assert_eq!(welcome.view_seq, Some(Seq::UNSEQUENCED));
        let session = welcome.view_session.unwrap();
        assert_ne!(session, SessionId::ZERO);

        // Without the client bit the three fields stay absent.
        let mut plain_reply = register(&sequencer, client(0x23), 23, &outbox).await;
        let plain = welcome_of(&mut plain_reply.ctrl).await;
        assert_eq!(plain.view_holder, None);
        assert_eq!(plain.view_seq, None);
        assert_eq!(plain.view_session, None);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    fn decode(bytes: &Bytes) -> FrameBuf {
        let mut decoder = FrameDecoder::new(crate::protocol::Limits::default());
        decoder.push(bytes).unwrap();
        decoder.next_frame_owned().unwrap().unwrap()
    }

    fn kick_reason(bytes: &Bytes) -> KickReason {
        let frame = decode(bytes);
        assert_eq!(frame.header.msg_type, MsgType::KICK);
        match decode_plain(
            MsgType::KICK,
            &frame.body,
            &crate::protocol::Limits::default(),
        )
        .unwrap()
        {
            Message::Kick(kick) => kick.reason,
            other => panic!("expected KICK, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_late_detach_keeps_the_replacement_session() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, metrics, task) = start(config, 5).await;
        let id = client(0x41);

        let first = register(&sequencer, id, 41, &outbox).await;
        let second = register(&sequencer, id, 42, &outbox).await;
        assert_ne!(first.generation, second.generation);
        assert_eq!(metrics.clients.load(Ordering::Acquire), 1);

        // The replaced connection detaches after the new HELLO. Its stale
        // generation must not remove the successor.
        sequencer
            .detach(id, first.generation, DetachCause::Disconnected)
            .await
            .unwrap();
        assert_eq!(
            sequencer.snapshot().await.unwrap().clients,
            1,
            "a stale detach must leave the replacement online"
        );

        // The current generation still detaches normally.
        sequencer
            .detach(id, second.generation, DetachCause::Disconnected)
            .await
            .unwrap();
        assert_eq!(sequencer.snapshot().await.unwrap().clients, 0);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// A solo client that already applied `current` gets the self-view mark:
    /// three view fields absent, `view_self` set, no relay session minted.
    #[tokio::test]
    async fn server_welcome_marks_a_solo_caught_up_client_as_self_view() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let id = client(0x71);

        let first = register(&sequencer, id, 71, &outbox).await;
        let (events, _body) = crate::transport::MpscBody::channel(4);
        sequencer.events(71, events).await.unwrap();
        sequencer.ordered(id, ordered_frame()).await.unwrap();
        // A clean LEAVE-free detach keeps `current` at one, exactly what a
        // restarted client reports as its applied watermark.
        sequencer
            .detach(id, first.generation, DetachCause::ClientLeft)
            .await
            .unwrap();
        sequencer.snapshot().await.unwrap();
        assert_eq!(sequencer.current_seq(), Seq(1));

        let mut reply = register_full(
            &sequencer,
            id,
            72,
            &outbox,
            Caps::VIEW_SOURCE.union(Caps::VIEW_SELF),
            Seq(1),
        )
        .await;
        let welcome = welcome_of(&mut reply.ctrl).await;
        assert!(welcome.view_self);
        assert_eq!(welcome.view_holder, None);
        assert_eq!(welcome.view_seq, None);
        assert_eq!(welcome.view_session, None);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// hp: a joiner pulling 1.37 MB over a slow link is never kicked. The
    /// lag threshold only produces diagnostics; nothing in the tick ends the
    /// session, whether it is joining or steady.
    #[tokio::test]
    async fn server_slow_joiner_pull_is_never_kicked() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let epoch = sequencer.epoch().get();
        let writer = client(0x61);
        let holder = client(0x62);
        let joiner = client(0x63);

        let writer_reply = register(&sequencer, writer, 61, &outbox).await;
        let (writer_events, _writer_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(61, writer_events).await.unwrap();
        let _holder_reply = register(&sequencer, holder, 62, &outbox).await;
        let (holder_events, _holder_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(62, holder_events).await.unwrap();
        let joiner_reply = register(&sequencer, joiner, 63, &outbox).await;
        let (joiner_events, _joiner_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(63, joiner_events).await.unwrap();
        let mut joiner_ctrl = joiner_reply.ctrl;
        let _joiner_data = joiner_reply.data;
        while joiner_ctrl.try_recv().is_ok() {}

        let base = Instant::now();
        // One unapplied ORDERED: the joiner is behind while it pulls.
        sequencer.ordered(writer, ordered_frame()).await.unwrap();
        // The holder is caught up; only the joiner should be judged.
        sequencer
            .watermark(WatermarkReport {
                client: holder,
                applied_seq: Seq(1),
                epoch_seen: epoch,
                rtt_ms: None,
                at: base,
            })
            .await
            .unwrap();
        // The writer leaves without a LEAVE; the holder can only pick the
        // joiner as the relay peer.
        sequencer
            .detach(writer, writer_reply.generation, DetachCause::ClientLeft)
            .await
            .unwrap();
        sequencer.snapshot().await.unwrap();

        let session = SessionId(0xabc);
        sequencer
            .relay(holder, relay_open_frame(session))
            .await
            .unwrap();

        let total = 1_371_795_usize;
        let chunk = 32 * 1024;
        let frames = total.div_ceil(chunk);
        for index in 0..frames {
            let len = chunk.min(total - index * chunk);
            sequencer
                .relay(holder, relay_data_frame(session, len))
                .await
                .unwrap();
            // Watermark reports and relayed frames keep arriving during the
            // pull; none of them is a liveness timer.
            let at = base + Duration::from_millis(700 * (index as u64 + 1));
            for client in [joiner, holder] {
                sequencer
                    .watermark(WatermarkReport {
                        client,
                        applied_seq: if client == joiner {
                            Seq::UNSEQUENCED
                        } else {
                            Seq(1)
                        },
                        epoch_seen: epoch,
                        rtt_ms: None,
                        at,
                    })
                    .await
                    .unwrap();
            }
            sequencer.tick(at).await.unwrap();
            assert_eq!(
                take_kick(&mut joiner_ctrl),
                None,
                "the slow joiner was kicked at {at:?}"
            );
        }

        // The view is installed; a watermark covering `last_op` ends the join.
        let done = base + Duration::from_secs(30);
        sequencer
            .watermark(WatermarkReport {
                client: joiner,
                applied_seq: Seq(1),
                epoch_seen: epoch,
                rtt_ms: None,
                at: done,
            })
            .await
            .unwrap();
        sequencer.tick(done + Duration::from_secs(1)).await.unwrap();
        assert_eq!(take_kick(&mut joiner_ctrl), None);

        // A new ORDERED the client has not applied yet is a diagnosis, not a
        // death sentence. The joiner stays attached however long it takes.
        sequencer.ordered(holder, ordered_frame()).await.unwrap();
        let late = done + Duration::from_secs(30);
        sequencer
            .watermark(WatermarkReport {
                client: joiner,
                applied_seq: Seq(1),
                epoch_seen: epoch,
                rtt_ms: None,
                at: late,
            })
            .await
            .unwrap();
        sequencer.tick(late).await.unwrap();
        sequencer.snapshot().await.unwrap();
        assert_eq!(take_kick(&mut joiner_ctrl), None);
        assert_eq!(sequencer.snapshot().await.unwrap().clients, 2);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// A one-sequence gap is only safe when it is a `LEAVE`. If the missing
    /// sequence was an `ORDERED` operation the client never applied, a self
    /// view would silently lose content, so it must be refused.
    #[tokio::test]
    async fn server_self_view_rejects_a_one_sequence_content_gap() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let epoch = sequencer.epoch().get();
        let b = client(0x41);
        let c = client(0x42);

        let b_reply = register(&sequencer, b, 41, &outbox).await;
        let (b_events, _b_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(41, b_events).await.unwrap();
        let c_reply = register(&sequencer, c, 42, &outbox).await;
        let (c_events, _c_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(42, c_events).await.unwrap();

        sequencer.ordered(c, ordered_frame()).await.unwrap();
        sequencer
            .watermark(WatermarkReport {
                client: b,
                applied_seq: Seq(1),
                epoch_seen: epoch,
                rtt_ms: None,
                at: Instant::now(),
            })
            .await
            .unwrap();
        // Sequence 2 is an ORDERED the joiner never applied.
        sequencer.ordered(c, ordered_frame()).await.unwrap();

        sequencer
            .detach(c, c_reply.generation, DetachCause::ClientLeft)
            .await
            .unwrap();
        sequencer
            .detach(b, b_reply.generation, DetachCause::ClientLeft)
            .await
            .unwrap();
        sequencer.snapshot().await.unwrap();
        assert_eq!(sequencer.current_seq(), Seq(2));

        let mut reply = register_full(
            &sequencer,
            b,
            43,
            &outbox,
            Caps::VIEW_SOURCE.union(Caps::VIEW_SELF),
            Seq(1),
        )
        .await;
        let welcome = welcome_of(&mut reply.ctrl).await;
        assert!(
            !welcome.view_self,
            "a content gap must never be mistaken for a LEAVE"
        );
        assert_eq!(welcome.view_holder, None);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// A duplicate `HELLO` invalidates the old connection's view routes. The
    /// old token must no longer target the departed holder; the relay falls
    /// back to the remaining peer instead.
    #[tokio::test]
    async fn server_duplicate_hello_drops_the_old_view_route() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let joiner = client(0x11);
        let low = client(0x21);
        let high = client(0x31);

        let _low_reply = register(&sequencer, low, 21, &outbox).await;
        let (low_events, _low_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(21, low_events).await.unwrap();
        let high_reply = register(&sequencer, high, 31, &outbox).await;
        let (high_events, _high_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(31, high_events).await.unwrap();
        let mut high_data = high_reply.data;

        let mut first =
            register_with_caps(&sequencer, joiner, 11, &outbox, Caps::VIEW_SOURCE).await;
        let first_welcome = welcome_of(&mut first.ctrl).await;
        let token = first_welcome.view_session.expect("holder token");
        assert_eq!(first_welcome.view_holder, Some(low));

        // Park the targeted holder in `Resyncing`: the relay token path still
        // accepts it (`receives_broadcast`), while the random fallback
        // requires `Online` and therefore can only pick `high`. That makes
        // "did the old token survive?" observable.
        sequencer
            .watermark(WatermarkReport {
                client: low,
                applied_seq: Seq::UNSEQUENCED,
                epoch_seen: sequencer.epoch().get().wrapping_sub(1),
                rtt_ms: None,
                at: Instant::now(),
            })
            .await
            .unwrap();
        sequencer.snapshot().await.unwrap();

        // Same identity reconnects. The duplicate kick invalidates its old
        // view route before the new WELCOME is built.
        let _second = register_with_caps(&sequencer, joiner, 12, &outbox, Caps::VIEW_SOURCE).await;

        sequencer
            .relay(joiner, relay_open_frame(token))
            .await
            .unwrap();
        // The duplicate kick broadcasts a LEAVE first; skip it and wait for
        // the relayed opening.
        let frame = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                let bytes = high_data.recv().await.unwrap();
                let frame = decode(&bytes);
                if frame.header.msg_type == MsgType::RELAY {
                    break frame;
                }
            }
        })
        .await
        .expect("the old token must not target the departed holder");
        assert_eq!(
            frame.prefix.as_route().unwrap().session_id,
            token,
            "fallback selection forwards the same client-chosen id"
        );

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// hp1: a `HELLO` whose downlink never paired is not a visible member of
    /// the broadcast set. Injecting `LEAVE` for it would advance `current` on
    /// every retry, so a joiner's applied sequence could never catch up with
    /// the view-selection equality.
    #[tokio::test]
    async fn server_detach_before_online_does_not_inject_leave() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;

        let id = client(0x61);
        let reply = register(&sequencer, id, 61, &outbox).await;
        assert_eq!(sequencer.current_seq(), Seq::UNSEQUENCED);

        sequencer
            .detach(id, reply.generation, DetachCause::Disconnected)
            .await
            .unwrap();
        // Barrier: the actor processed the detach before the read.
        sequencer.snapshot().await.unwrap();
        assert_eq!(
            sequencer.current_seq(),
            Seq::UNSEQUENCED,
            "a not-yet-online detach must not consume a sequence"
        );

        // Once the downlink pairs, the same disconnect is visible and injects.
        let paired = register(&sequencer, client(0x62), 62, &outbox).await;
        let (events, _body) = crate::transport::MpscBody::channel(4);
        sequencer.events(62, events).await.unwrap();
        sequencer
            .detach(client(0x62), paired.generation, DetachCause::Disconnected)
            .await
            .unwrap();
        sequencer.snapshot().await.unwrap();
        assert_eq!(sequencer.current_seq(), Seq(1));

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// A `LEAVE` consumes a sequence but is not an operation. A peer that has
    /// applied every `ORDERED` must not be judged stalled by that sequence.
    #[tokio::test]
    async fn server_leave_does_not_stall_an_idle_peer() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let epoch = sequencer.epoch().get();
        let author = client(0x41);
        let peer = client(0x42);
        let author_reply = register(&sequencer, author, 41, &outbox).await;
        let peer_reply = register(&sequencer, peer, 42, &outbox).await;
        // Both halves paired: the author is `Online`, so its disconnect is a
        // visible LEAVE and the test still exercises the sequence gap.
        let (author_events, _author_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(41, author_events).await.unwrap();
        let (peer_events, _peer_body) = crate::transport::MpscBody::channel(4);
        sequencer.events(42, peer_events).await.unwrap();
        let mut peer_ctrl = peer_reply.ctrl;
        let mut peer_data = peer_reply.data;
        let peer_queued = peer_reply.queued;

        let now = Instant::now();
        sequencer.ordered(author, ordered_frame()).await.unwrap();
        for (who, applied) in [(author, Seq(1)), (peer, Seq(1))] {
            sequencer
                .watermark(WatermarkReport {
                    client: who,
                    applied_seq: applied,
                    epoch_seen: epoch,
                    rtt_ms: None,
                    at: now,
                })
                .await
                .unwrap();
        }
        while peer_ctrl.try_recv().is_ok() {}

        // The author disconnects; the injected LEAVE takes sequence 2.
        sequencer
            .detach(author, author_reply.generation, DetachCause::Disconnected)
            .await
            .unwrap();
        // `detach` only enqueues; the snapshot reply proves the actor has
        // already broadcast the LEAVE.
        sequencer.snapshot().await.unwrap();
        // Drain like a real writer: the backlog term must not mask the gate.
        while let Ok(bytes) = peer_data.try_recv() {
            let len = bytes.len();
            peer_queued.sub(len);
        }
        sequencer.tick(now + Duration::from_secs(2)).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer_ctrl.recv())
                .await
                .is_err(),
            "an idle peer must not be kicked by the sequence a LEAVE consumed"
        );

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// W20 repro: the client applied the last `ORDERED`, a fresh `PONG` went
    /// out, and only the tail of a relay stream is still queued. 1.6 s later
    /// the tick must not call that stalled.
    #[tokio::test]
    async fn server_stream_tail_without_pending_ops_is_not_stalled() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, _metrics, task) = start(config, 5).await;
        let epoch = sequencer.epoch().get();
        let author = client(0x51);
        let peer = client(0x52);
        let author_reply = register(&sequencer, author, 51, &outbox).await;
        let peer_reply = register(&sequencer, peer, 52, &outbox).await;
        let mut peer_ctrl = peer_reply.ctrl;
        // Never drain the peer's data queue: the frames stay counted as
        // backlog exactly like the tail of a relay stream.
        let _peer_data = peer_reply.data;
        let _author_data = author_reply.data;

        let now = Instant::now();
        sequencer.ordered(author, ordered_frame()).await.unwrap();
        sequencer.snapshot().await.unwrap();
        for who in [author, peer] {
            sequencer
                .watermark(WatermarkReport {
                    client: who,
                    applied_seq: Seq(1),
                    epoch_seen: epoch,
                    rtt_ms: None,
                    at: now,
                })
                .await
                .unwrap();
        }
        // Barrier: the reports (and their `PONG`s) are processed.
        sequencer.snapshot().await.unwrap();
        while peer_ctrl.try_recv().is_ok() {}

        sequencer
            .tick(now + Duration::from_millis(1_600))
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer_ctrl.recv())
                .await
                .is_err(),
            "an applied watermark must be idle even with a stream tail queued"
        );

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_sequencer_ten_thousand_concurrent_ordered_has_no_gaps() {
        let config = ServeConfig::for_tests();
        let outbox_config = config.outbox;
        let (sequencer, metrics, task) = start(config, 42).await;
        let observer = client(0xee);
        let observer_reply = register(&sequencer, observer, 1, &outbox_config).await;
        let mut observer_data = observer_reply.data;

        // Every sender drains its own queue, exactly like a real writer.
        let mut senders = Vec::new();
        for index in 0..100_u8 {
            let reply = register(
                &sequencer,
                client(index.wrapping_add(1)),
                100 + u64::from(index),
                &outbox_config,
            )
            .await;
            let mut data = reply.data;
            let mut ctrl = reply.ctrl;
            senders.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        Some(_) = ctrl.recv() => {}
                        Some(_) = data.recv() => {}
                        else => break,
                    }
                }
            }));
        }

        let collected = tokio::spawn(async move {
            let mut seqs = Vec::with_capacity(10_000);
            while let Some(bytes) = observer_data.recv().await {
                let frame = decode(&bytes);
                if frame.header.msg_type == MsgType::ORDERED {
                    seqs.push(frame.header.seq.get());
                }
                if seqs.len() == 10_000 {
                    break;
                }
            }
            seqs
        });

        let mut writers = Vec::new();
        for index in 0..100_u8 {
            let sequencer = sequencer.clone();
            let author = client(index.wrapping_add(1));
            writers.push(tokio::spawn(async move {
                for _ in 0..100 {
                    sequencer.ordered(author, ordered_frame()).await.unwrap();
                }
            }));
        }
        for writer in writers {
            writer.await.unwrap();
        }

        let seqs = collected.await.unwrap();
        eprintln!(
            "W9 evidence: 100 concurrent writers x 100 frames = 10000 ORDERED; observer seq {:?}..={:?}, count={}, strictly_increasing={}",
            seqs.first(),
            seqs.last(),
            seqs.len(),
            seqs.windows(2).all(|pair| pair[0] + 1 == pair[1])
        );
        let expected: Vec<u64> = (1..=10_000).collect();
        assert_eq!(
            seqs, expected,
            "broadcast order is strictly increasing with no gap and no duplicate"
        );
        assert_eq!(metrics.seq.load(Ordering::Acquire), 10_000);
        assert_eq!(sequencer.current_seq(), Seq(10_000));

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
        for sender in senders {
            sender.abort();
        }
    }

    #[tokio::test]
    async fn server_slow_consumer_is_isolated_and_only_a_stalled_queue_is_kicked() {
        let small = OutboxConfig {
            cap_bytes: 4096,
            cap_frames: 8,
            data_frames: 8,
            ctrl_frames: 8,
        };
        let big = ServeConfig::for_tests().outbox;
        let mut config = ServeConfig::for_tests();
        config.outbox = small;
        let (sequencer, metrics, task) = start(config, 7).await;

        let slow = client(1);
        let slow_reply = register(&sequencer, slow, 11, &small).await;
        // The drain clock starts when the writer takes a frame, not when the
        // queue is built. Mark one drain so the first overflow is measured
        // from "now" even when the test machine is busy.
        slow_reply.queued.mark_drain();
        let _slow_data = slow_reply.data; // never read: the queue fills
        let mut slow_ctrl = slow_reply.ctrl;
        // Drain WELCOME; only a later KICK is interesting.
        while slow_ctrl.try_recv().is_ok() {}

        let fast = client(2);
        let fast_reply = register(&sequencer, fast, 12, &big).await;
        let mut fast_data = fast_reply.data;

        for _ in 0..100 {
            sequencer.ordered(fast, ordered_frame()).await.unwrap();
        }

        let mut seen = Vec::new();
        while seen.len() < 100 {
            let bytes = fast_data.recv().await.unwrap();
            let frame = decode(&bytes);
            seen.push(frame.header.seq.get());
            assert!(
                frame.header.msg_type == MsgType::ORDERED
                    || frame.header.msg_type == MsgType::LEAVE
            );
        }
        seen.sort_unstable();
        assert_eq!(
            seen,
            (1..=100).collect::<Vec<_>>(),
            "the fast session sees every sequence; the slow one cannot steal frames"
        );

        // The queue overflowed while it was still fresh: that is a slow
        // consumer, not a stuck one. It stays attached and the frame that did
        // not fit is counted.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), slow_ctrl.recv())
                .await
                .is_err(),
            "a draining queue must not be kicked"
        );
        assert_eq!(metrics.clients.load(Ordering::Acquire), 2);
        assert!(metrics.dropped_frames.load(Ordering::Acquire) > 0);

        // No drain for longer than the grace: now the queue is stuck and the
        // session is removed.
        tokio::time::sleep(DRAIN_GRACE + Duration::from_millis(200)).await;
        sequencer.ordered(fast, ordered_frame()).await.unwrap();
        let mut kicked = false;
        while let Ok(Some(bytes)) =
            tokio::time::timeout(Duration::from_millis(50), slow_ctrl.recv())
                .await
                .map_err(|_| ())
                .and_then(|value| value.ok_or(()).map(Some))
        {
            if decode(&bytes).header.msg_type == MsgType::KICK {
                assert_eq!(kick_reason(&bytes), KickReason::QueueOverflow);
                kicked = true;
                break;
            }
        }
        assert!(
            kicked,
            "a stalled queue must receive KICK{{QUEUE_OVERFLOW}}"
        );
        eprintln!(
            "W9 evidence: slow consumer stayed attached until the drain grace expired, then QueueOverflow; fast observed {} frames covering 1..=100; clients={}",
            seen.len(),
            metrics.clients.load(Ordering::Acquire)
        );
        assert_eq!(metrics.clients.load(Ordering::Acquire), 1);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    /// A writer half that is gone means the connection is dead. The session
    /// is detached, not kicked: a `KICK` could never be delivered, and the
    /// reason is not queue pressure.
    #[tokio::test]
    async fn server_closed_writer_detaches_instead_of_reporting_overflow() {
        let config = ServeConfig::for_tests();
        let outbox = config.outbox;
        let (sequencer, metrics, task) = start(config, 12).await;
        let dead = client(0x31);
        let alive = client(0x32);

        let dead_reply = register(&sequencer, dead, 301, &outbox).await;
        let mut dead_ctrl = dead_reply.ctrl;
        // Drain WELCOME: only a later KICK would be a failure.
        while dead_ctrl.try_recv().is_ok() {}
        // The downlink writer is gone: every `try_push_data` now says Closed.
        drop(dead_reply.data);

        let _alive_reply = register(&sequencer, alive, 302, &outbox).await;
        sequencer.ordered(alive, ordered_frame()).await.unwrap();

        let snapshot = sequencer.snapshot().await.unwrap();
        assert_eq!(snapshot.clients, 1, "the dead session is removed");
        assert!(
            dead_ctrl.try_recv().is_err(),
            "a closed writer must not receive KICK{{QUEUE_OVERFLOW}}"
        );
        assert_eq!(metrics.dropped_frames.load(Ordering::Acquire), 0);

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn server_watermark_t2_t3_kick_immediately() {
        let config = ServeConfig::for_tests();
        let outbox_config = config.outbox;
        let (sequencer, _metrics, task) = start(config, 9).await;
        let a = client(3);
        let mut a_reply = register(&sequencer, a, 21, &outbox_config).await;
        for _ in 0..10 {
            sequencer.ordered(a, ordered_frame()).await.unwrap();
        }
        // Drain ORDERED frames so the queue stays open for control frames.
        let drain = tokio::spawn(async move {
            while let Some(frame) = a_reply.data.recv().await {
                if decode(&frame).header.msg_type == MsgType::LEAVE {
                    break;
                }
            }
        });

        // T3: applied > current.
        sequencer
            .watermark(WatermarkReport {
                client: a,
                applied_seq: Seq(11),
                epoch_seen: 9,
                rtt_ms: None,
                at: Instant::now(),
            })
            .await
            .unwrap();
        let mut reason = None;
        while let Some(bytes) = a_reply.ctrl.recv().await {
            let frame = decode(&bytes);
            if frame.header.msg_type == MsgType::KICK {
                reason = Some(kick_reason(&bytes));
                break;
            }
        }
        assert_eq!(reason, Some(KickReason::Overclaim));
        eprintln!("W9 evidence: T3 applied=11 current=10 -> {reason:?}");
        drain.await.unwrap();

        // T2: applied moves backwards.
        let b = client(4);
        let mut b_reply = register(&sequencer, b, 22, &outbox_config).await;
        for applied in [5_u64, 4] {
            sequencer
                .watermark(WatermarkReport {
                    client: b,
                    applied_seq: Seq(applied),
                    epoch_seen: 9,
                    rtt_ms: None,
                    at: Instant::now(),
                })
                .await
                .unwrap();
        }
        let mut reason = None;
        while let Some(bytes) = b_reply.ctrl.recv().await {
            let frame = decode(&bytes);
            if frame.header.msg_type == MsgType::KICK {
                reason = Some(kick_reason(&bytes));
                break;
            }
        }
        assert_eq!(reason, Some(KickReason::Regression));
        eprintln!("W9 evidence: T2 applied 5 -> 4 -> {reason:?}");

        sequencer.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn server_restart_changes_epoch_and_restarts_seq() {
        let config = ServeConfig::for_tests();
        let outbox_config = config.outbox;
        let (first, _first_metrics, first_task) = start(config.clone(), 100).await;
        let a = client(5);
        let first_reply = register(&first, a, 31, &outbox_config).await;
        for _ in 0..3 {
            first.ordered(a, ordered_frame()).await.unwrap();
        }
        let first_snapshot = first.snapshot().await.unwrap();
        assert_eq!(first_snapshot.clients, 1);
        assert_eq!(first_snapshot.current_seq, Seq(3));
        first.shutdown().await.unwrap();
        first_task.await.unwrap();

        let (second, second_metrics, second_task) = start(config, 200).await;
        assert_eq!(second.current_seq(), Seq::UNSEQUENCED);
        let b = client(6);
        let mut second_reply = register(&second, b, 32, &outbox_config).await;
        let welcome = decode(&second_reply.ctrl.recv().await.unwrap());
        assert_eq!(welcome.header.msg_type, MsgType::WELCOME);
        match decode_plain(
            MsgType::WELCOME,
            &welcome.body,
            &crate::protocol::Limits::default(),
        )
        .unwrap()
        {
            Message::Welcome(welcome) => {
                assert_eq!(welcome.epoch, 200);
                assert_eq!(welcome.current_seq, Seq::UNSEQUENCED);
                eprintln!(
                    "W9 evidence: restart epoch 100/seq 3 -> epoch {}/seq {:?}",
                    welcome.epoch, welcome.current_seq
                );
            }
            other => panic!("expected WELCOME, got {other:?}"),
        }
        // A report from the dead epoch is not compared, so it cannot kick.
        second
            .watermark(WatermarkReport {
                client: b,
                applied_seq: Seq(3),
                epoch_seen: 100,
                rtt_ms: None,
                at: Instant::now(),
            })
            .await
            .unwrap();
        let snapshot = second.snapshot().await.unwrap();
        assert_eq!(snapshot.resyncing, 1);
        assert_eq!(second_metrics.seq.load(Ordering::Acquire), 0);

        second.shutdown().await.unwrap();
        second_task.await.unwrap();
        drop(first_reply);
    }

    #[test]
    fn server_control_frames_are_plain_and_unsequenced() {
        let frame =
            encode_control(MsgType::WELCOME, Prefix::None, b"abc", Seq::UNSEQUENCED).unwrap();
        let decoded = decode(&frame);
        assert_eq!(decoded.header.msg_type, MsgType::WELCOME);
        assert_eq!(decoded.header.seq, Seq::UNSEQUENCED);
        assert!(!decoded.header.flags.contains(Flags::ENC));
    }
}
