//! One PSK session: handshake, replay, uplink and downlink.
//!
//! ```text
//! HELLO(plain, ctrl prefix: applied_seq, epoch_seen, sealed AUTH)
//!   -> WELCOME(plain body + server proof + sealed ACCEPT)
//! STEADY (enc key): STREAM_DATA* + ORDERED up, ORDERED* down
//! ```
//!
//! The downlink applies events to SQLite in batches of up to 64 events or
//! 4 MiB, one `BEGIN IMMEDIATE` per batch. The uplink reads the durable outbox
//! and sends each row, coalescing adjacent writes. Neither task touches the
//! other's stream: the transport is split once, after `WELCOME`.
//!
//! Replay needs no extra entry point: `HELLO`'s `CtrlPrefix` carries the local
//! watermark, the server replays from there, and the client skips any frame at
//! or below `meta.applied_seq` that a restart re-delivers.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;

use super::db::{ApplyOutcome, ClientDb, DbError, OutboxOp};
use super::lifecycle::{EXIT_AUTH, EXIT_DISCONNECTED, EXIT_OK, State, WriteGate};
use super::replay::{MAX_BATCH_BYTES, MAX_BATCH_EVENTS, RemoteEvent};
use super::status::{Conntrace, Counters, TraceEntry};
use super::writer::{CoalesceTuning, Coalescer, LocalOp, LocalSeq, QueuedOp, Span, WireOp};
use crate::protocol::crypto::{NonceMinter, Opener, PskKeyRing, Sealer, SessionKey};
use crate::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
use crate::protocol::handshake::{CLIENT_HANDSHAKE_TIMEOUT_MS, ClientHandshake, HandshakeError};
use crate::protocol::messages::{
    CompactionState, Error as ErrorMessage, FieldMap, Kick, OpClass, Ping, Pong, SyncEnd,
    WcpWriter, Welcome, fid,
};
use crate::protocol::{
    Caps, CtrlPrefix, Flags, FrameBuf, FrameDecoder, FrameEncoder, FrameHeader, FrameRef, Limits,
    MsgType, OpId, Prefix, RoutePrefix, Seq, SessionId, StreamId,
};
use crate::store::sqlite::{ChunkRef, EventKind, EventPayload, RejectState};
use crate::transport::{DialOptions, Endpoint, EventsStream, HttpTransport, RpcStream, Transport};

/// How long the whole handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How often an idle uplink looks for a new outbox row.
const IDLE_POLL: Duration = Duration::from_millis(2);

/// How often the client reports its applied watermark to the server.
const PING_INTERVAL: Duration = Duration::from_secs(1);

/// How long a replay batch waits for more ORDERED frames before committing.
///
/// The transport may deliver one frame per chunk; without this window every
/// ORDERED would become its own transaction. The window matches the writer's
/// aggregate window and bounds how long an isolated event stays unapplied.
const REPLAY_BATCH_WINDOW: Duration = Duration::from_millis(2);

/// How long a replay may make no progress before the session resyncs.
///
/// The server owes every event between the durable `applied_seq` and the
/// `WELCOME` watermark. A quiet downlink in that state is a stall, not a
/// slow replay: the durable cursor is the only safe way out, because a
/// reconnect makes the server replay the missing events again.
const REPLAY_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the session checks replay progress.
const REPLAY_STALL_CHECK: Duration = Duration::from_secs(1);

/// Largest number of outbox rows one uplink page holds.
const OUTBOX_PAGE: usize = 64;

/// Largest aggregate the uplink builds.
/// Why the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionExit {
    pub code: i32,
    pub reason: &'static str,
}

impl SessionExit {
    const fn ok() -> Self {
        Self {
            code: EXIT_OK,
            reason: "unmounted",
        }
    }

    const fn disconnected() -> Self {
        Self {
            code: EXIT_DISCONNECTED,
            reason: "disconnected",
        }
    }

    /// A transient end the driver may retry from `applied_seq`.
    const fn resync() -> Self {
        Self {
            code: EXIT_DISCONNECTED,
            reason: "resync",
        }
    }
}

/// One session's fixed inputs.
pub struct SessionOptions {
    pub endpoint: Endpoint,
    pub ring: PskKeyRing,
    pub mount_id: String,
}

impl std::fmt::Debug for SessionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionOptions")
            .field("endpoint", &self.endpoint)
            .field("mount_id", &self.mount_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Signal {
    CaughtUp,
    Disconnected,
    Resync,
    Kicked(crate::protocol::KickReason),
    Fatal(String),
}

/// How far one replay has advanced since the session attached.
///
/// The session samples the applied watermark and the received-frame count.
/// Either one moving is progress: a large file spends a long time in
/// `STREAM_DATA` before its `ORDERED` can advance the watermark, and that is
/// not a stall. A downlink that delivers nothing at all is.
#[derive(Debug)]
struct ReplayProgress {
    last_applied: u64,
    last_frames: u64,
    last_advance: Instant,
}

impl ReplayProgress {
    fn new(applied: u64, frames: u64) -> Self {
        Self {
            last_applied: applied,
            last_frames: frames,
            last_advance: Instant::now(),
        }
    }

    /// Record the current watermark and frame count; true when either moved.
    fn advanced(&mut self, applied: u64, frames: u64) -> bool {
        if applied <= self.last_applied && frames <= self.last_frames {
            return false;
        }
        self.last_applied = applied.max(self.last_applied);
        self.last_frames = frames.max(self.last_frames);
        self.last_advance = Instant::now();
        true
    }

    /// Time since the last observed progress.
    fn idle(&self) -> Duration {
        self.last_advance.elapsed()
    }
}

/// The watermark a replica may adopt instead of replaying a compacted log.
///
/// The test is deliberately local: the durable epoch and applied watermark,
/// plus the tree having content when the compaction point is non-zero. It
/// never compares state hashes, because inode ids differ between replicas of
/// the same tree and an independent import may carry other timestamps.
fn fast_forward_target(
    welcome: &Welcome,
    local_epoch: i64,
    local_applied: i64,
    local_content: bool,
) -> Option<u64> {
    let compaction = CompactionState {
        from_seq: welcome.compacted_from_seq,
        epoch: welcome.compacted_epoch,
        seq: welcome.compacted_seq,
    };
    if !welcome.caps.contains(Caps::COMPACTION_FASTFORWARD)
        || compaction.epoch != welcome.epoch
        || compaction.seq > welcome.current_seq.get()
    {
        return None;
    }
    if !compaction.admits(
        u64::try_from(local_epoch).ok()?,
        u64::try_from(local_applied).ok()?,
    ) {
        return None;
    }
    // An empty tree is only trustworthy when the compaction point was zero;
    // any later watermark means the tree lost content, so replay repairs it.
    if !local_content && compaction.from_seq != 0 {
        return None;
    }
    Some(compaction.seq)
}

/// Run one session until it disconnects or `shutdown` resolves.
pub async fn run(
    store: Arc<ClientDb>,
    options: SessionOptions,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    shutdown: &mut mpsc::Receiver<()>,
) -> SessionExit {
    if let Err(error) = store.reset_sent() {
        tracing::error!(event = "outbox_reset", error = %error, "cannot reset sent rows");
    }
    // A rejection marks the replica for a full replay. Reset before HELLO so
    // the handshake advertises `applied_seq = 0` and the server replays its
    // whole log; resetting after HELLO would tell the server we are current.
    if store.needs_resync().unwrap_or(false) {
        let epoch = store.epoch().unwrap_or(1);
        if let Err(error) = store.reset_epoch(epoch) {
            tracing::error!(event = "resync", error = %error, "cannot reset the replica");
            return SessionExit {
                code: 2,
                reason: "resync reset",
            };
        }
        if let Err(error) = store.clear_needs_resync() {
            tracing::warn!(event = "resync", error = %error, "cannot clear the resync flag");
        }
    }
    let applied = store.applied_seq().unwrap_or(0);
    let epoch_seen = store.epoch().unwrap_or(0);
    let client_id = match store.client_id() {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(event = "client_id", error = %error, "cannot read the local label");
            return SessionExit {
                code: 2,
                reason: "client id",
            };
        }
    };

    let dial_options = DialOptions::new(rand::random());
    let dial = HttpTransport::dial(&options.endpoint, &dial_options);
    let transport = match tokio::time::timeout(HANDSHAKE_TIMEOUT, dial).await {
        Ok(Ok(transport)) => transport,
        Ok(Err(error)) => {
            tracing::error!(event = "dial", error = %error, "cannot open the session");
            return SessionExit {
                code: 2,
                reason: "dial",
            };
        }
        Err(_) => {
            tracing::error!(event = "dial", "session dial timed out");
            return SessionExit {
                code: 2,
                reason: "dial timeout",
            };
        }
    };

    let handshake = handshake(
        transport,
        options.ring,
        client_id,
        applied,
        epoch_seen,
        &counters,
        &conntrace,
    )
    .await;
    let (transport, decoder, welcome, key) = match handshake {
        Ok(value) => value,
        Err(SessionError::Auth) => {
            tracing::error!(event = "handshake", "master password rejected");
            return SessionExit {
                code: EXIT_AUTH,
                reason: "authentication",
            };
        }
        Err(error) => {
            tracing::error!(event = "handshake", error = %error, "handshake failed");
            return SessionExit {
                code: 2,
                reason: "handshake",
            };
        }
    };

    let epoch = welcome.epoch;
    let current_seq = welcome.current_seq.get();
    let local_epoch = store.epoch().unwrap_or(0);
    let local_applied = store.applied_seq().unwrap_or(0);
    let local_content = store.has_content().unwrap_or(false);
    // The first client of an empty server is the seed source: its local tree
    // is the initial cluster state, so an epoch mismatch must not wipe it.
    //
    // `current_seq == 0` alone is ambiguous: a compacted server also restarts
    // its sequence at zero but keeps its state. A database that has never
    // synced still carries the schema-default epoch (1) and `applied_seq` 0;
    // a database that has synced carries a server epoch or a non-zero
    // watermark. Only the former seeds.
    let never_synced = local_applied == 0 && local_epoch == 1;
    let seed = current_seq == 0 && local_content && never_synced;
    let fast_forward = if seed {
        None
    } else {
        fast_forward_target(&welcome, local_epoch, local_applied, local_content)
    };
    let mut fast_forwarded = false;
    if let Some(applied) = fast_forward {
        if let (Ok(epoch), Ok(applied)) = (i64::try_from(epoch), i64::try_from(applied)) {
            match store.fast_forward(epoch, applied) {
                Ok(()) => {
                    fast_forwarded = true;
                    tracing::info!(
                        event = "compaction_fast_forward",
                        epoch,
                        from_seq = welcome.compacted_from_seq,
                        applied,
                        "compaction fast-forward"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        event = "compaction_fast_forward",
                        error = %error,
                        "cannot adopt the compacted epoch; replaying instead"
                    );
                }
            }
        }
    }
    if !seed
        && !fast_forwarded
        && (local_epoch != epoch as i64 || local_applied > current_seq as i64)
    {
        if let Err(error) = store.reset_epoch(epoch as i64) {
            tracing::error!(event = "epoch_reset", error = %error, "cannot reset the replica");
            return SessionExit {
                code: 2,
                reason: "epoch reset",
            };
        }
        tracing::info!(
            event = "epoch_reset",
            epoch,
            local_epoch,
            local_applied,
            "replaying the compacted log from zero"
        );
    }

    if seed {
        if let Err(error) = store.set_epoch(epoch as i64) {
            tracing::error!(event = "epoch", error = %error, "cannot record the server epoch");
            return SessionExit {
                code: 2,
                reason: "epoch",
            };
        }
        match store.seed(epoch as i64) {
            Ok(report) => tracing::info!(
                event = "seed",
                objects = report.objects,
                events = report.events,
                chunks = report.chunks,
                "uploading the local tree"
            ),
            Err(error) => tracing::error!(event = "seed", error = %error, "seed failed"),
        }
    }

    let key = Arc::new(key);
    let (rpc, events) = transport.split();
    let (signal_tx, mut signal_rx) = mpsc::channel::<Signal>(8);
    let (control_tx, control_rx) = mpsc::channel::<Vec<u8>>(32);
    // `local_applied` was read before the epoch reset above, so it may name
    // the previous history. The reset cleared the replica; the durable
    // watermark after the reset is the only value this session may use to
    // decide whether it is caught up.
    let applied = store.applied_seq().unwrap_or(0).max(0) as u64;
    let watermark = Arc::new(AtomicI64::new(applied.min(current_seq) as i64));

    let downlink_task = tokio::spawn(downlink(
        events,
        decoder,
        Arc::clone(&store),
        Arc::clone(&key),
        epoch,
        current_seq,
        Arc::clone(&gate),
        Arc::clone(&counters),
        Arc::clone(&conntrace),
        Arc::clone(&watermark),
        signal_tx.clone(),
        control_tx,
    ));
    let uplink_task = tokio::spawn(uplink(
        rpc,
        Arc::clone(&store),
        key,
        epoch,
        Arc::clone(&counters),
        Arc::clone(&conntrace),
        control_rx,
        signal_tx,
    ));

    let mut caught_up = current_seq == 0 || applied >= current_seq;
    tracing::info!(
        event = "replay_start",
        applied,
        current = current_seq,
        epoch,
        local_applied,
        local_epoch,
        caught_up,
        "session attached"
    );
    if caught_up {
        gate.set(State::Steady);
        let _ = store.mark_checkpoint();
        tracing::info!(
            event = "steady",
            applied,
            current = current_seq,
            "replica is current at attach"
        );
    }
    let mut progress = ReplayProgress::new(applied, counters.frames_in.load(Ordering::Relaxed));
    let mut stall_check = tokio::time::interval(REPLAY_STALL_CHECK);
    stall_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut exit = SessionExit::ok();
    loop {
        tokio::select! {
            signal = signal_rx.recv() => {
                match signal {
                    Some(Signal::CaughtUp) => {
                        if !caught_up {
                            caught_up = true;
                            gate.set(State::Steady);
                            let _ = store.mark_checkpoint();
                            tracing::info!(
                                event = "steady",
                                applied = store.applied_seq().unwrap_or(0),
                                current = current_seq,
                                "replay caught up"
                            );
                        }
                    }
                    Some(Signal::Kicked(reason)) => {
                        tracing::warn!(event = "kicked", reason = ?reason, "server ended the session");
                        exit = SessionExit::disconnected();
                        break;
                    }
                    Some(Signal::Resync) => {
                        tracing::warn!(event = "resync", "a rejection requires a replica replay");
                        exit = SessionExit {
                            code: EXIT_DISCONNECTED,
                            reason: "resync",
                        };
                        break;
                    }
                    Some(Signal::Fatal(reason)) => {
                        tracing::error!(event = "fatal", reason = %reason, "session stopped");
                        exit = SessionExit::disconnected();
                        break;
                    }
                    Some(Signal::Disconnected) | None => {
                        // A transport close is transient: the durable
                        // applied_seq is the replay cursor, so the driver
                        // reconnects instead of unmounting.
                        tracing::warn!(event = "disconnect", "session ended; reconnecting");
                        exit = SessionExit::resync();
                        break;
                    }
                }
            }
            _ = stall_check.tick() => {
                // A replay that stops advancing cannot be told apart from a
                // slow one by waiting longer: the server's log is the truth.
                // Reconnect from the durable cursor instead of staying
                // silently half-applied with the write gate open.
                if !caught_up {
                    let applied_now = watermark.load(Ordering::Acquire).max(0) as u64;
                    let frames_now = counters.frames_in.load(Ordering::Relaxed);
                    if progress.advanced(applied_now, frames_now) {
                        tracing::debug!(
                            event = "replay_progress",
                            applied = applied_now,
                            frames_in = frames_now,
                            current = current_seq,
                            "replay advanced"
                        );
                    } else if progress.idle() >= REPLAY_STALL_TIMEOUT {
                        tracing::error!(
                            event = "replay_stall",
                            applied = applied_now,
                            current = current_seq,
                            idle_ms = progress.idle().as_millis() as u64,
                            frames_in = frames_now,
                            "replay made no progress; reconnecting from applied_seq"
                        );
                        exit = SessionExit::resync();
                        break;
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!(event = "shutdown", "stopping the session");
                break;
            }
        }
    }

    // A resync exit keeps the mount alive: writes wait as EROFS while the
    // driver reconnects. A terminal exit unmounts.
    if exit.reason == "resync" {
        Counters::bump(&counters.resyncs);
        gate.set(State::Joining);
    } else {
        gate.set(State::Unmounting);
    }
    downlink_task.abort();
    uplink_task.abort();
    let _ = downlink_task.await;
    let _ = uplink_task.await;
    if let Err(error) = store.fsync() {
        tracing::warn!(event = "fsync", error = %error, "WAL checkpoint failed");
    }
    let _ = store.gc_chunks();
    exit
}

/// Why the handshake could not complete.
#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("transport: {0}")]
    Transport(#[from] crate::transport::TransportError),
    #[error("protocol: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("message: {0}")]
    Message(#[from] crate::protocol::MessageError),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::protocol::crypto::CryptoError),
    #[error("authentication failed")]
    Auth,
    #[error("server closed during the handshake")]
    Closed,
    #[error("unexpected message {0:?}")]
    Unexpected(MsgType),
    #[error("{0}")]
    Fatal(String),
}

/// Signal for a failure while sending on the uplink.
///
/// A transport end is transient: the durable `applied_seq` is the replay
/// cursor, so the driver reconnects instead of unmounting. A local database
/// or encoding failure is not, because a reconnect cannot repair it.
fn uplink_signal(error: SessionError) -> Signal {
    match error {
        SessionError::Transport(_) | SessionError::Closed => Signal::Disconnected,
        other => Signal::Fatal(other.to_string()),
    }
}

async fn handshake(
    mut transport: HttpTransport,
    ring: PskKeyRing,
    client_id: [u8; 16],
    applied: i64,
    epoch_seen: i64,
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(HttpTransport, FrameDecoder, Welcome, SessionKey), SessionError> {
    let now_ms = unix_millis();
    let deadline_ms = now_ms.saturating_add(CLIENT_HANDSHAKE_TIMEOUT_MS);
    let nonces = NonceMinter::with_instance(rand::random());
    let mut client = ClientHandshake::new(
        ring,
        crate::protocol::frame::ClientId::from_bytes(client_id),
        rand::random::<[u8; 32]>(),
        crate::protocol::version::ProtoVersion::CURRENT,
        crate::protocol::version::Caps::REQUIRED
            .union(crate::protocol::version::Caps::COMPACTION_FASTFORWARD),
        now_ms,
    );
    let ctrl = CtrlPrefix::new(
        Seq(u64::try_from(applied.max(0)).unwrap_or(0)),
        u64::try_from(epoch_seen.max(0)).unwrap_or(0),
    );
    let hello = client.hello(&nonces, &ctrl)?.encode()?;
    let prefix = Prefix::Ctrl(ctrl);
    let header = FrameHeader::new(MsgType::HELLO, Flags::CTRL, 0, Seq::UNSEQUENCED);
    send_frame(
        &mut transport,
        &header,
        &prefix,
        &hello,
        counters,
        conntrace,
    )
    .await?;

    let limits = Limits::default();
    let mut decoder = FrameDecoder::new(limits);
    let remaining_ms = deadline_ms.saturating_sub(unix_millis());
    if remaining_ms == 0 {
        return Err(SessionError::Handshake(HandshakeError::Timeout));
    }
    let welcome_frame = match tokio::time::timeout(
        Duration::from_millis(remaining_ms),
        read_frame(&mut transport, &mut decoder, counters, conntrace),
    )
    .await
    {
        Ok(Ok(frame)) => frame,
        // The server verifies the sealed AUTH before it sends WELCOME. A
        // wrong PSK, a tampered AUTH and a version rejection all close the
        // connection without a distinguishable reply, so a close before
        // WELCOME is the client's only authentication-failure signal.
        Ok(Err(SessionError::Closed)) => return Err(SessionError::Auth),
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(SessionError::Handshake(HandshakeError::Timeout)),
    };
    if welcome_frame.header.msg_type != MsgType::WELCOME {
        return Err(SessionError::Unexpected(welcome_frame.header.msg_type));
    }
    let welcome = Welcome::decode(&welcome_frame.body, &limits)?;
    let session_key = match client.on_welcome(&welcome, &welcome_frame.body, unix_millis()) {
        Ok(key) => key,
        Err(HandshakeError::AuthFailed) => return Err(SessionError::Auth),
        Err(error) => return Err(SessionError::Handshake(error)),
    };
    // The decoder may already hold frames that followed WELCOME in the same
    // HTTP chunk. Hand it to the downlink task instead of dropping them.
    Ok((transport, decoder, welcome, session_key))
}

async fn read_frame(
    transport: &mut HttpTransport,
    decoder: &mut FrameDecoder,
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<FrameBuf, SessionError> {
    loop {
        if let Some(frame) = decoder.next_frame_owned()? {
            Counters::bump(&counters.frames_in);
            conntrace.record(TraceEntry::new(
                super::net::wall_clock_us(),
                "in",
                format!("{:?}", frame.header.msg_type),
                frame.body.len() as u32,
                frame.header.seq,
            ));
            return Ok(frame);
        }
        match transport.recv().await? {
            Some(bytes) => decoder.push(&bytes)?,
            None => return Err(SessionError::Closed),
        }
    }
}

async fn send_frame(
    transport: &mut HttpTransport,
    header: &FrameHeader,
    prefix: &Prefix,
    body: &[u8],
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    send_bytes(transport, header, prefix, body, counters, conntrace).await
}

async fn send_bytes(
    transport: &mut HttpTransport,
    header: &FrameHeader,
    prefix: &Prefix,
    body: &[u8],
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    let mut header = *header;
    header.len = u32::try_from(prefix.encoded_len() + body.len())
        .map_err(|_| SessionError::Fatal("frame length overflow".to_owned()))?;
    let bytes = FrameEncoder::with_capacity(
        crate::protocol::HEADER_LEN + prefix.encoded_len() + body.len(),
    )
    .encode_owned(&FrameRef::new(&header, prefix, body))?;
    Counters::bump(&counters.frames_out);
    conntrace.record(TraceEntry::new(
        super::net::wall_clock_us(),
        "out",
        format!("{:?}", header.msg_type),
        body.len() as u32,
        header.seq,
    ));
    transport.send(Bytes::from(bytes)).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn downlink(
    mut events: EventsStream,
    mut decoder: FrameDecoder,
    store: Arc<ClientDb>,
    key: Arc<SessionKey>,
    epoch: u64,
    current_seq: u64,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    watermark: Arc<AtomicI64>,
    signal: mpsc::Sender<Signal>,
    control: mpsc::Sender<Vec<u8>>,
) {
    let limits = Limits::default();
    let opener = Opener::with_session_key(&key);
    let mut data = super::net::DataCache::new();
    let mut caught_up = current_seq == 0;
    let mut pending: Vec<RemoteEvent> = Vec::new();
    let mut pending_bytes = 0usize;
    let nonces = NonceMinter::with_instance(rand::random());

    loop {
        loop {
            let frame = match decoder.next_frame_owned() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    let _ = signal.send(Signal::Fatal(error.to_string())).await;
                    return;
                }
            };
            Counters::bump(&counters.frames_in);
            conntrace.record(TraceEntry::new(
                super::net::wall_clock_us(),
                "in",
                format!("{:?}", frame.header.msg_type),
                frame.body.len() as u32,
                frame.header.seq,
            ));
            // A control frame observes the stream after the events before it,
            // so commit the pending batch first. The frames that carry one
            // event's content (`RELAY` opens the stream, `STREAM_DATA` fills
            // it) only feed the cache for a later ORDERED and must not break
            // the batch.
            if !matches!(
                frame.header.msg_type,
                MsgType::ORDERED | MsgType::STREAM_DATA | MsgType::RELAY | MsgType::FLOW
            ) && !pending.is_empty()
            {
                tracing::debug!(
                    event = "replay_flush",
                    reason = "control",
                    frame = ?frame.header.msg_type,
                    events = pending.len(),
                    "control frame closed the pending batch"
                );
                if !settle_batch(
                    &store,
                    &mut pending,
                    &mut pending_bytes,
                    &watermark,
                    &counters,
                    &mut caught_up,
                    current_seq,
                    &gate,
                    &signal,
                )
                .await
                {
                    return;
                }
            }
            match frame.header.msg_type {
                MsgType::STREAM_DATA => {
                    if let Err(error) = data.push(&frame, &opener) {
                        tracing::warn!(event = "stream_data", error = %error, "dropping a bad fragment");
                    }
                }
                MsgType::ORDERED => {
                    // A frame without `F_EXTRA` must rebuild its payload from
                    // the committed tree, so earlier events have to land
                    // first. This only affects compacted or legacy servers.
                    let decoded = decode_ordered(
                        &store,
                        &opener,
                        &mut data,
                        &frame,
                        epoch,
                        pending.is_empty(),
                    );
                    let event = match decoded {
                        Ok(Some(event)) => event,
                        Ok(None) => {
                            if !settle_batch(
                                &store,
                                &mut pending,
                                &mut pending_bytes,
                                &watermark,
                                &counters,
                                &mut caught_up,
                                current_seq,
                                &gate,
                                &signal,
                            )
                            .await
                            {
                                return;
                            }
                            match decode_ordered(&store, &opener, &mut data, &frame, epoch, true) {
                                Ok(Some(event)) => event,
                                Ok(None) => {
                                    tracing::error!(
                                        event = "apply",
                                        seq = frame.header.seq.get(),
                                        "ORDERED payload still needs an uncommitted tree"
                                    );
                                    let _ = signal
                                        .send(Signal::Fatal(
                                            "apply: legacy ORDERED payload".to_owned(),
                                        ))
                                        .await;
                                    return;
                                }
                                Err(error) => {
                                    tracing::error!(event = "apply", seq = frame.header.seq.get(), error = %error, "cannot decode an event");
                                    Counters::bump(&counters.materialize_errors);
                                    let _ =
                                        signal.send(Signal::Fatal(format!("apply: {error}"))).await;
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!(event = "apply", seq = frame.header.seq.get(), error = %error, "cannot decode an event");
                            Counters::bump(&counters.materialize_errors);
                            let _ = signal.send(Signal::Fatal(format!("apply: {error}"))).await;
                            return;
                        }
                    };
                    let bytes = event.batch_bytes();
                    if (pending.len() >= MAX_BATCH_EVENTS
                        || (!pending.is_empty() && pending_bytes + bytes > MAX_BATCH_BYTES))
                        && !settle_batch(
                            &store,
                            &mut pending,
                            &mut pending_bytes,
                            &watermark,
                            &counters,
                            &mut caught_up,
                            current_seq,
                            &gate,
                            &signal,
                        )
                        .await
                    {
                        return;
                    }
                    pending_bytes += bytes;
                    pending.push(event);
                    if (pending.len() >= MAX_BATCH_EVENTS || pending_bytes >= MAX_BATCH_BYTES)
                        && !settle_batch(
                            &store,
                            &mut pending,
                            &mut pending_bytes,
                            &watermark,
                            &counters,
                            &mut caught_up,
                            current_seq,
                            &gate,
                            &signal,
                        )
                        .await
                    {
                        return;
                    }
                }
                MsgType::PING => {
                    let now = unix_seconds();
                    if let Ok(body) = (Pong { server_time: now }).encode() {
                        let mut header =
                            FrameHeader::new(MsgType::PONG, Flags::ENC, 0, Seq::UNSEQUENCED);
                        if let Ok(sealed) = Sealer::with_session_key(&key, &nonces).seal(
                            &mut header,
                            &Prefix::None,
                            &body,
                        ) {
                            if let Ok(bytes) = FrameEncoder::with_capacity(
                                crate::protocol::HEADER_LEN + sealed.as_bytes().len(),
                            )
                            .encode_owned(&FrameRef::new(&header, &Prefix::None, sealed.as_bytes()))
                            {
                                let _ = control.send(bytes).await;
                            }
                        }
                    }
                }
                MsgType::PONG => {}
                MsgType::KICK => {
                    if let Ok(opened) = opener.open(&frame.header, &frame.prefix, &frame.body) {
                        if let Ok(kick) = Kick::decode(opened.as_slice(), &limits) {
                            // A queue overflow would leave a sequence hole; a
                            // stalled session has stopped advancing while the
                            // server still owes events. Both are transport
                            // conditions, and both recover by reconnecting
                            // from the durable `applied_seq`. Every other
                            // reason is terminal for this mount.
                            if matches!(
                                kick.reason,
                                crate::protocol::KickReason::QueueOverflow
                                    | crate::protocol::KickReason::Stalled
                            ) {
                                tracing::warn!(
                                    event = "kick",
                                    reason = ?kick.reason,
                                    "server ended the downlink; reconnecting to replay"
                                );
                                let _ = signal.send(Signal::Resync).await;
                            } else {
                                let _ = signal.send(Signal::Kicked(kick.reason)).await;
                            }
                            return;
                        }
                    }
                    let _ = signal
                        .send(Signal::Fatal("unreadable KICK".to_owned()))
                        .await;
                    return;
                }
                MsgType::ERROR => {
                    if let Ok(error) = ErrorMessage::decode(&frame.body, &limits) {
                        if let Some((op_id, errno, rejection)) = decode_rejection(error.detail) {
                            let (state, resync) = match rejection {
                                RejectionState::Snapshot(state) => (Some(*state), false),
                                RejectionState::None => (None, false),
                                RejectionState::Resync => (None, true),
                            };
                            if let Err(store_error) = store.reject_op(op_id, errno, state) {
                                tracing::warn!(event = "reject", error = %store_error, "cannot record a rejection");
                            }
                            // The failed tombstone is durable before the
                            // replay request is recorded and signalled.
                            if resync {
                                if let Err(store_error) = store.mark_needs_resync() {
                                    tracing::warn!(event = "reject", error = %store_error, "cannot request a replay");
                                }
                            }
                            Counters::bump(&counters.ops_rejected);
                            if store.needs_resync().unwrap_or(false) {
                                let _ = signal.send(Signal::Resync).await;
                                return;
                            }
                            continue;
                        }
                        let _ = signal
                            .send(Signal::Fatal(format!("server error: {:?}", error.reason)))
                            .await;
                    } else {
                        let _ = signal
                            .send(Signal::Fatal("unreadable ERROR".to_owned()))
                            .await;
                    }
                    return;
                }
                MsgType::SYNC_END => {
                    if let Ok(opened) = opener.open(&frame.header, &frame.prefix, &frame.body) {
                        if let Ok(end) = SyncEnd::decode(opened.as_slice(), &limits) {
                            tracing::info!(event = "sync_end", reason = ?end.reason, "server ended the stream");
                        }
                    }
                }
                MsgType::LEAVE => {
                    // Advisory locks are session-scoped and die with the
                    // connection; nothing durable to do here.
                }
                MsgType::RELAY => {
                    // Stream-open marker for a write's content stream. The
                    // bytes follow in STREAM_DATA and the ORDERED names the
                    // data session; there is no payload here.
                }
                MsgType::WELCOME | MsgType::HELLO => {}
                other => {
                    tracing::warn!(event = "unexpected_frame", msg_type = ?other, "ignoring");
                }
            }
        }
        // The decoder is drained. A pending batch waits a short window for
        // more frames so a chunk-per-frame transport still batches; the size
        // caps and control frames flush it earlier.
        let chunk = if pending.is_empty() {
            match events.recv().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    let _ = signal.send(Signal::Disconnected).await;
                    return;
                }
                Err(error) => {
                    tracing::warn!(event = "disconnect", error = %error, "events stream failed");
                    let _ = signal.send(Signal::Disconnected).await;
                    return;
                }
            }
        } else {
            match tokio::time::timeout(REPLAY_BATCH_WINDOW, events.recv()).await {
                Ok(Ok(Some(bytes))) => bytes,
                Ok(Ok(None)) => {
                    if !settle_batch(
                        &store,
                        &mut pending,
                        &mut pending_bytes,
                        &watermark,
                        &counters,
                        &mut caught_up,
                        current_seq,
                        &gate,
                        &signal,
                    )
                    .await
                    {
                        return;
                    }
                    let _ = signal.send(Signal::Disconnected).await;
                    return;
                }
                Ok(Err(error)) => {
                    tracing::warn!(event = "disconnect", error = %error, "events stream failed");
                    let _ = signal.send(Signal::Disconnected).await;
                    return;
                }
                Err(_elapsed) => {
                    tracing::debug!(
                        event = "replay_flush",
                        reason = "idle",
                        events = pending.len(),
                        "idle window closed the pending batch"
                    );
                    if !settle_batch(
                        &store,
                        &mut pending,
                        &mut pending_bytes,
                        &watermark,
                        &counters,
                        &mut caught_up,
                        current_seq,
                        &gate,
                        &signal,
                    )
                    .await
                    {
                        return;
                    }
                    match events.recv().await {
                        Ok(Some(bytes)) => bytes,
                        Ok(None) => {
                            let _ = signal.send(Signal::Disconnected).await;
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(event = "disconnect", error = %error, "events stream failed");
                            let _ = signal.send(Signal::Disconnected).await;
                            return;
                        }
                    }
                }
            }
        };
        if let Err(error) = decoder.push(&chunk) {
            let _ = signal.send(Signal::Fatal(error.to_string())).await;
            return;
        }
    }
}

/// Decode one ORDERED frame into a batchable event.
///
/// Nothing is written here: the downlink accumulates decoded events and hands
/// them to [`ClientDb::apply_remote_batch`] as one transaction.
///
/// `Ok(None)` means the frame carries no `F_EXTRA`; rebuilding its payload
/// needs the tree as of the preceding event, which is still in the pending
/// batch. The caller commits that batch and decodes again.
fn decode_ordered(
    store: &ClientDb,
    opener: &Opener<'_>,
    data: &mut super::net::DataCache,
    frame: &FrameBuf,
    epoch: u64,
    allow_synthesize: bool,
) -> Result<Option<RemoteEvent>, DbError> {
    let opened = opener
        .open(&frame.header, &frame.prefix, &frame.body)
        .map_err(|_| DbError::Corrupt("ORDERED failed to open"))?;
    let limits = Limits::default();
    let fields = FieldMap::parse(opened.as_slice(), &limits)
        .map_err(|_| DbError::Corrupt("ORDERED body is not WCP"))?;
    let op_id = fields
        .fixed::<16>(fid::F_OP_ID)
        .map_err(|_| DbError::Corrupt("ORDERED op id"))?;
    let class_raw = fields
        .u8(fid::F_OP_CLASS)
        .map_err(|_| DbError::Corrupt("ORDERED class"))?
        .ok_or(DbError::Corrupt("ORDERED has no class"))?;
    let class = OpClass::from_u8(class_raw).map_err(|_| DbError::Corrupt("unknown op class"))?;
    let raw_path = fields
        .get(fid::F_PATH)
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let raw_path2 = fields
        .get(fid::F_PATH2)
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let raw_target = fields
        .get(fid::F_TARGET)
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    // LINK names the new entry in `F_PATH` and the existing inode in
    // `F_TARGET`; the event payload stores the existing path first.
    let (path, path2) = if class == OpClass::LINK {
        (raw_target, raw_path)
    } else {
        (raw_path, raw_path2)
    };
    let data_session = fields
        .fixed::<16>(fid::F_DATA_SESSION)
        .ok()
        .flatten()
        .map(SessionId::from_le_bytes);
    let offset = fields.u64(fid::F_OFFSET).ok().flatten().unwrap_or(0);
    let payload = match fields.get(fid::F_EXTRA) {
        Some(extra) => EventPayload::decode(kind_for(class), extra)
            .map_err(|_| DbError::Corrupt("ORDERED payload does not decode"))?,
        None if !allow_synthesize => return Ok(None),
        None => synthesize_payload(store, class, path, path2, offset, &fields)?,
    };
    Ok(Some(RemoteEvent {
        seq: frame.header.seq.get() as i64,
        epoch: epoch as i64,
        op_id,
        result: "ok".to_owned(),
        payload,
        path: path.map(str::to_owned),
        path2: path2.map(str::to_owned),
        data: data_session.and_then(|session| data.take(session)),
    }))
}

/// Apply and clear the pending replay batch.
///
/// Returns the highest sequence the transaction reached (including duplicates
/// and a rejection). `Err(())` means a fatal signal was sent and the downlink
/// must stop.
async fn flush_replay(
    store: &ClientDb,
    pending: &mut Vec<RemoteEvent>,
    pending_bytes: &mut usize,
    watermark: &AtomicI64,
    counters: &Counters,
    signal: &mpsc::Sender<Signal>,
) -> Result<Option<i64>, ()> {
    if pending.is_empty() {
        return Ok(None);
    }
    tracing::debug!(
        event = "replay_batch",
        events = pending.len(),
        bytes = *pending_bytes,
        "applying a replay batch"
    );
    let report = match store.apply_remote_batch(pending) {
        Ok(report) => report,
        Err(error) => {
            Counters::bump(&counters.materialize_errors);
            let replayable = match &error {
                // A gap means the peer's stream lost an event (or a frame
                // arrived out of order). A missing chunk means the local
                // cache lacks bytes this event needs. Both roll the batch
                // back, so the durable applied_seq is still the last
                // contiguous event. Reconnect: HELLO advertises it and the
                // server replays the hole with its content.
                DbError::Corrupt("event sequence gap") => Some("event sequence gap"),
                DbError::MissingChunk(_) => Some("missing chunk"),
                _ => None,
            };
            if let Some(reason) = replayable {
                let applied = store.applied_seq().unwrap_or(0);
                let missing = pending
                    .iter()
                    .map(|event| event.seq)
                    .find(|seq| *seq > applied + 1);
                tracing::warn!(
                    event = "apply",
                    events = pending.len(),
                    applied,
                    expected = applied + 1,
                    got = missing,
                    reason,
                    error = %error,
                    "replay cannot advance; reconnecting from applied_seq"
                );
                let _ = signal.send(Signal::Resync).await;
            } else {
                tracing::error!(
                    event = "apply",
                    events = pending.len(),
                    error = %error,
                    "cannot apply an event batch"
                );
                let _ = signal.send(Signal::Fatal(format!("apply: {error}"))).await;
            }
            return Err(());
        }
    };
    let mut last = None;
    for (event, outcome) in pending.iter().zip(report.outcomes.iter()) {
        last = Some(event.seq);
        match outcome {
            ApplyOutcome::Applied => {
                Counters::bump(&counters.ops_applied);
                watermark.store(event.seq, Ordering::Release);
            }
            ApplyOutcome::Duplicate => Counters::bump(&counters.ops_duplicate),
            ApplyOutcome::Rejected => {
                watermark.store(event.seq, Ordering::Release);
            }
        }
    }
    if report.rejected {
        tracing::warn!(
            event = "apply",
            skipped = pending.len().saturating_sub(report.outcomes.len()),
            "a rejection stopped the replay batch; the session will resync"
        );
    }
    pending.clear();
    *pending_bytes = 0;
    Ok(last)
}

/// Commit the pending batch and react to its outcome.
///
/// Returns false when the downlink must stop because a fatal error was
/// signalled or the session must resync.
#[allow(clippy::too_many_arguments)]
async fn settle_batch(
    store: &ClientDb,
    pending: &mut Vec<RemoteEvent>,
    pending_bytes: &mut usize,
    watermark: &AtomicI64,
    counters: &Counters,
    caught_up: &mut bool,
    current_seq: u64,
    gate: &WriteGate,
    signal: &mpsc::Sender<Signal>,
) -> bool {
    let last = match flush_replay(store, pending, pending_bytes, watermark, counters, signal).await
    {
        Ok(last) => last,
        Err(()) => return false,
    };
    if let Some(seq) = last {
        if !*caught_up && seq >= current_seq as i64 {
            *caught_up = true;
            // The server log is authoritative. Re-apply the pending local
            // intent on top of it, off the FUSE path, before opening the gate.
            if let Err(error) = store.replay_local_outbox() {
                tracing::warn!(
                    event = "replay_local",
                    error = %error,
                    "cannot re-apply the pending outbox"
                );
            }
            gate.set(State::Steady);
            let _ = signal.send(Signal::CaughtUp).await;
        }
    }
    if store.needs_resync().unwrap_or(false) {
        let _ = signal.send(Signal::Resync).await;
        return false;
    }
    true
}

/// Rebuild an event payload from ORDERED fields when the peer omitted
/// `F_EXTRA` (a compacted or legacy server).
fn synthesize_payload(
    store: &ClientDb,
    class: OpClass,
    path: Option<&str>,
    path2: Option<&str>,
    offset: u64,
    fields: &FieldMap<'_>,
) -> Result<EventPayload, DbError> {
    let path = path.ok_or(DbError::Corrupt("ORDERED has no path"))?;
    let object = store
        .lookup_by_path(path)
        .map_err(|_| DbError::Corrupt("ORDERED path is unknown"))?;
    let mode = fields.u32(fid::F_MODE).ok().flatten();
    let raw_mtime = fields.u64(fid::F_MTIME_NS).ok().flatten();
    let mtime_ns = raw_mtime
        .map(|value| value as i64)
        .unwrap_or_else(super::db::now_ns);
    // A pre-version-3 server wrote zero for the timestamped classes. Zero is
    // not a usable operation timestamp there, so treat it as absent instead
    // of stamping the parents with the Unix epoch.
    let timestamped_mtime = raw_mtime
        .filter(|value| *value != 0)
        .map(|value| value as i64);
    let uid = fields.u32(fid::F_UID).ok().flatten().unwrap_or(0);
    let gid = fields.u32(fid::F_GID).ok().flatten().unwrap_or(0);
    Ok(match class {
        OpClass::WRITE | OpClass::PWRITE => EventPayload::Write {
            ino: object.ino,
            offset,
            len: 0,
            size: 0,
            file_root: [0u8; 32],
            mtime_ns,
            chunks: Vec::new(),
        },
        OpClass::TRUNCATE => EventPayload::Truncate {
            ino: object.ino,
            size: fields.u64(fid::F_LENGTH).ok().flatten().unwrap_or(0),
            file_root: [0u8; 32],
            mtime_ns,
        },
        OpClass::SETATTR => EventPayload::Setattr {
            ino: object.ino,
            mode,
            uid: fields.u32(fid::F_UID).ok().flatten(),
            gid: fields.u32(fid::F_GID).ok().flatten(),
            mtime_ns: timestamped_mtime,
            size: fields.u64(fid::F_LENGTH).ok().flatten(),
        },
        OpClass::RENAME => EventPayload::Rename {
            ino: object.ino,
            mtime_ns: timestamped_mtime,
        },
        OpClass::UNLINK => EventPayload::Unlink {
            ino: object.ino,
            mtime_ns: timestamped_mtime,
        },
        OpClass::RMDIR => EventPayload::Rmdir {
            ino: object.ino,
            mtime_ns: timestamped_mtime,
        },
        OpClass::LINK => EventPayload::Link {
            ino: object.ino,
            mtime_ns: timestamped_mtime,
        },
        OpClass::MKDIR => EventPayload::CreateDir {
            ino: object.ino,
            mode: mode.unwrap_or(0o755),
            uid,
            gid,
            mtime_ns,
            file_root: object.file_root,
        },
        OpClass::CREATE_EXCL => EventPayload::CreateFile {
            ino: object.ino,
            mode: mode.unwrap_or(0o644),
            uid,
            gid,
            mtime_ns,
            file_root: object.file_root,
        },
        OpClass::SYMLINK => EventPayload::Symlink {
            ino: object.ino,
            mode: mode.unwrap_or(0o777),
            uid,
            gid,
            mtime_ns,
            target: object.target.clone().unwrap_or_default(),
            file_root: object.file_root,
        },
        OpClass::LEAVE => EventPayload::Leave,
        OpClass::SYNC_CTRL => EventPayload::SyncCtrl { code: 0 },
        _ => {
            let _ = path2;
            return Err(DbError::Corrupt(
                "unsupported ORDERED class without a payload",
            ));
        }
    })
}

fn kind_for(class: OpClass) -> EventKind {
    match class {
        OpClass::CREATE_EXCL => EventKind::CreateFile,
        OpClass::MKDIR => EventKind::CreateDir,
        OpClass::SYMLINK => EventKind::Symlink,
        OpClass::WRITE | OpClass::PWRITE => EventKind::Write,
        OpClass::TRUNCATE => EventKind::Truncate,
        OpClass::SETATTR => EventKind::Setattr,
        OpClass::RENAME => EventKind::Rename,
        OpClass::UNLINK => EventKind::Unlink,
        OpClass::RMDIR => EventKind::Rmdir,
        OpClass::LINK => EventKind::Link,
        OpClass::FCNTL_LOCK | OpClass::FLOCK => EventKind::Lock,
        OpClass::LEAVE => EventKind::Leave,
        OpClass::SYNC_CTRL => EventKind::SyncCtrl,
        _ => EventKind::SyncCtrl,
    }
}

/// The timestamp an outbox payload records for its operation.
///
/// `None` means the payload predates version 3 or carries no timestamp of its
/// own; the caller then falls back to the object's current value.
fn outbox_mtime(payload: &EventPayload) -> Option<i64> {
    match payload {
        EventPayload::CreateFile { mtime_ns, .. }
        | EventPayload::CreateDir { mtime_ns, .. }
        | EventPayload::Symlink { mtime_ns, .. }
        | EventPayload::Write { mtime_ns, .. }
        | EventPayload::Truncate { mtime_ns, .. } => Some(*mtime_ns),
        EventPayload::Setattr { mtime_ns, .. } => *mtime_ns,
        EventPayload::Rename { mtime_ns, .. }
        | EventPayload::Unlink { mtime_ns, .. }
        | EventPayload::Rmdir { mtime_ns, .. }
        | EventPayload::Link { mtime_ns, .. } => *mtime_ns,
        EventPayload::Lock { .. }
        | EventPayload::Unlock { .. }
        | EventPayload::Leave
        | EventPayload::SyncCtrl { .. } => None,
    }
}

/// What one `ERROR` detail carried for the rejected operation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RejectionState {
    /// The server sent no snapshot; there is nothing to replace.
    None,
    /// The server's authoritative snapshot of the affected path.
    Snapshot(Box<RejectState>),
    /// The snapshot did not fit the detail; replay the server log instead.
    Resync,
}

fn decode_rejection(detail: &[u8]) -> Option<([u8; 16], i32, RejectionState)> {
    if detail.len() < 20 {
        return None;
    }
    let mut op_id = [0u8; 16];
    op_id.copy_from_slice(&detail[..16]);
    let errno = i32::from_le_bytes([detail[16], detail[17], detail[18], detail[19]]);
    if detail.len() < 24 {
        return Some((op_id, errno, RejectionState::None));
    }
    let len = u32::from_le_bytes([detail[20], detail[21], detail[22], detail[23]]);
    let payload = &detail[24..];
    let state = if len == u32::MAX {
        // The server's snapshot exceeded the detail budget. Only this
        // explicit sentinel asks for a replay.
        RejectionState::Resync
    } else if len == 0 || payload.len() < len as usize {
        // A missing or truncated snapshot is not a replay request.
        RejectionState::None
    } else {
        match bincode::serde::decode_from_slice(
            &payload[..len as usize],
            bincode::config::standard(),
        ) {
            Ok((state, _)) => RejectionState::Snapshot(Box::new(state)),
            Err(_) => RejectionState::None,
        }
    };
    Some((op_id, errno, state))
}

#[allow(clippy::too_many_arguments)]
async fn uplink(
    mut rpc: RpcStream,
    store: Arc<ClientDb>,
    key: Arc<SessionKey>,
    epoch: u64,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    mut control: mpsc::Receiver<Vec<u8>>,
    signal: mpsc::Sender<Signal>,
) {
    let nonces = NonceMinter::with_instance(rand::random());
    let sealer = Sealer::with_session_key(&key, &nonces);
    let mut coalescer = Coalescer::new(CoalesceTuning::default());
    let started = Instant::now();
    let mut last_ping = started;

    loop {
        while let Ok(bytes) = control.try_recv() {
            if let Err(error) = rpc.send(Bytes::from(bytes)).await {
                tracing::warn!(event = "disconnect", error = %error, "uplink failed; reconnecting");
                let _ = signal.send(Signal::Disconnected).await;
                return;
            }
        }

        // A PING is the only frame that carries a watermark. Without one the
        // server keeps the value reported by HELLO, so a graceful drain waits
        // its full timeout even though the client has applied everything.
        if last_ping.elapsed() >= PING_INTERVAL {
            last_ping = Instant::now();
            if let Err(error) =
                send_ping(&mut rpc, &store, &sealer, epoch, &counters, &conntrace).await
            {
                let _ = signal.send(uplink_signal(error)).await;
                return;
            }
        }

        let page = match store.outbox_page(OUTBOX_PAGE) {
            Ok(page) => page,
            Err(error) => {
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
                return;
            }
        };

        if page.is_empty() {
            if let Some(wire) = coalescer.due(started.elapsed()) {
                if let Err(error) =
                    send_wire(&mut rpc, &store, &sealer, &wire, &[], &counters, &conntrace).await
                {
                    let _ = signal.send(uplink_signal(error)).await;
                    return;
                }
            } else {
                tokio::time::sleep(IDLE_POLL).await;
            }
            continue;
        }

        let mut cursor = 0usize;
        while cursor < page.len() {
            let op = &page[cursor];
            if let Some(queued) = queued_write(&store, op) {
                match coalescer.push(&queued, started.elapsed()) {
                    Ok(Some(wire)) => {
                        let members = members_for(&page, &wire);
                        if let Err(error) = send_wire(
                            &mut rpc, &store, &sealer, &wire, &members, &counters, &conntrace,
                        )
                        .await
                        {
                            let _ = signal.send(uplink_signal(error)).await;
                            return;
                        }
                        if let Err(error) = mark_sent(&store, &wire, &members) {
                            let _ = signal.send(Signal::Fatal(error.to_string())).await;
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        if let Some(wire) = coalescer.flush_all() {
                            let members = members_for(&page, &wire);
                            if let Err(error) = send_wire(
                                &mut rpc, &store, &sealer, &wire, &members, &counters, &conntrace,
                            )
                            .await
                            {
                                let _ = signal.send(uplink_signal(error)).await;
                                return;
                            }
                            if let Err(error) = mark_sent(&store, &wire, &members) {
                                let _ = signal.send(Signal::Fatal(error.to_string())).await;
                                return;
                            }
                        }
                        let Some(wire) = wire_from_queued(&queued) else {
                            continue;
                        };
                        let members = vec![op.clone()];
                        if let Err(error) = send_wire(
                            &mut rpc, &store, &sealer, &wire, &members, &counters, &conntrace,
                        )
                        .await
                        {
                            let _ = signal.send(uplink_signal(error)).await;
                            return;
                        }
                        if let Err(error) = mark_sent(&store, &wire, &members) {
                            let _ = signal.send(Signal::Fatal(error.to_string())).await;
                            return;
                        }
                    }
                }
            } else if matches!(op.decoded, EventPayload::Write { .. }) {
                // A write whose chunk bytes are not cached cannot travel;
                // leave it pending instead of sending a metadata-only frame.
                tracing::warn!(event = "uplink", op = ?op.op_id, "write has no cached chunks");
            } else {
                if let Some(wire) = coalescer.flush_all() {
                    let members = members_for(&page, &wire);
                    if let Err(error) = send_wire(
                        &mut rpc, &store, &sealer, &wire, &members, &counters, &conntrace,
                    )
                    .await
                    {
                        let _ = signal.send(uplink_signal(error)).await;
                        return;
                    }
                    if let Err(error) = mark_sent(&store, &wire, &members) {
                        let _ = signal.send(Signal::Fatal(error.to_string())).await;
                        return;
                    }
                }
                if let Err(error) =
                    send_meta(&mut rpc, &store, &sealer, op, &counters, &conntrace).await
                {
                    let _ = signal.send(uplink_signal(error)).await;
                    return;
                }
                if let Err(error) = store.mark_sent(op.op_id, &[op.op_id]) {
                    let _ = signal.send(Signal::Fatal(error.to_string())).await;
                    return;
                }
            }
            cursor += 1;
        }
        if let Some(wire) = coalescer.flush_all() {
            let members = members_for(&page, &wire);
            if let Err(error) = send_wire(
                &mut rpc, &store, &sealer, &wire, &members, &counters, &conntrace,
            )
            .await
            {
                let _ = signal.send(uplink_signal(error)).await;
                return;
            }
            if let Err(error) = mark_sent(&store, &wire, &members) {
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
                return;
            }
        }
    }
}

fn queued_write(store: &ClientDb, op: &OutboxOp) -> Option<QueuedOp> {
    let EventPayload::Write { ino, .. } = op.decoded else {
        return None;
    };
    let chunks = store.outbox_chunks(op.op_id).ok()?;
    if chunks.is_empty() || chunks.iter().any(|chunk| chunk.data.is_none()) {
        return None;
    }
    let first = chunks.first()?;
    let mut data = Vec::new();
    for chunk in &chunks {
        data.extend_from_slice(chunk.data.as_deref()?);
    }
    Some(QueuedOp::new(
        LocalSeq(op.seq as u64),
        OpId::from_bytes(op.op_id),
        LocalOp::Write {
            ino: crate::store::node_table::InodeId::from_bytes(ino),
            off: first.offset,
            data,
        },
    ))
}

fn wire_from_queued(queued: &QueuedOp) -> Option<WireOp> {
    match &queued.op {
        LocalOp::Write { ino, off, data } => Some(WireOp {
            span: Span::single(queued.seq),
            op_id: queued.op_id,
            ino: *ino,
            off: *off,
            data: data.clone(),
        }),
        _ => None,
    }
}

fn members_for(page: &[OutboxOp], wire: &WireOp) -> Vec<OutboxOp> {
    page.iter()
        .filter(|op| {
            let seq = LocalSeq(op.seq as u64);
            wire.span.contains(seq)
        })
        .cloned()
        .collect()
}

fn mark_sent(store: &ClientDb, wire: &WireOp, members: &[OutboxOp]) -> Result<(), DbError> {
    let ids: Vec<[u8; 16]> = if members.is_empty() {
        vec![*wire.op_id.as_bytes()]
    } else {
        members.iter().map(|op| op.op_id).collect()
    };
    store.mark_sent(*wire.op_id.as_bytes(), &ids)
}

/// Report the applied watermark and the epoch this session belongs to.
async fn send_ping(
    rpc: &mut RpcStream,
    store: &ClientDb,
    sealer: &Sealer<'_>,
    epoch: u64,
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    let applied = store.applied_seq().unwrap_or(0).max(0);
    let prefix = Prefix::Ctrl(CtrlPrefix::new(
        Seq(u64::try_from(applied).unwrap_or(0)),
        epoch,
    ));
    let body = Ping {
        client_time: unix_millis(),
    }
    .encode()?;
    let mut header = FrameHeader::new(
        MsgType::PING,
        Flags::ENC.with(Flags::CTRL),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = sealer.seal(&mut header, &prefix, &body)?;
    send_raw(
        rpc,
        &header,
        &prefix,
        sealed.as_bytes(),
        counters,
        conntrace,
    )
    .await
}

async fn send_wire(
    rpc: &mut RpcStream,
    store: &ClientDb,
    sealer: &Sealer<'_>,
    wire: &WireOp,
    members: &[OutboxOp],
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    let ino = wire.ino.to_bytes();
    // The outbox row keeps the path as of the write. `path_of` may already be
    // gone when a write is followed by an unlink before the uplink runs.
    let path = members
        .first()
        .and_then(|op| op.path.clone())
        .or_else(|| store.path_of(ino).ok())
        .unwrap_or_else(|| "/".to_owned());
    let object = store.getattr(ino).ok();
    let last_payload = members.last().map(|op| &op.decoded);
    let (mtime_ns, uid, gid) = object.as_ref().map_or_else(
        || {
            let mtime = match last_payload {
                Some(EventPayload::Write { mtime_ns, .. }) => *mtime_ns,
                _ => super::db::now_ns(),
            };
            (mtime, 0, 0)
        },
        |object| (object.mtime_ns, object.uid, object.gid),
    );
    let session = SessionId::new(rand::random());
    let data = wire.data.clone();
    let hash = crate::store::sqlite::chunk_hash(&data);

    // Chunk-aligned span: the event payload lists exactly the chunks carried
    // by the stream.
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let mut chunk_no = (wire.off / u64::from(crate::store::sqlite::CHUNK_BYTES)) as u32;
    while cursor < data.len() {
        let take = (data.len() - cursor).min(crate::store::sqlite::CHUNK_BYTES as usize);
        let bytes = &data[cursor..cursor + take];
        chunks.push(ChunkRef {
            chunk_no,
            hash: crate::store::sqlite::chunk_hash(bytes),
            offset: u64::from(chunk_no) * u64::from(crate::store::sqlite::CHUNK_BYTES),
            len: take as u32,
        });
        cursor += take;
        chunk_no += 1;
    }
    let size = object.as_ref().map_or_else(
        || match last_payload {
            Some(EventPayload::Write { size, .. }) => *size,
            _ => wire.off + data.len() as u64,
        },
        |object| object.size,
    );
    let file_root = object.as_ref().map_or_else(
        || match last_payload {
            Some(EventPayload::Write { file_root, .. }) => *file_root,
            _ => [0u8; 32],
        },
        |object| object.file_root,
    );
    let payload = if members.len() == 1 {
        members[0].decoded.clone()
    } else {
        EventPayload::Write {
            ino,
            offset: wire.off,
            len: data.len() as u64,
            size,
            file_root,
            mtime_ns,
            chunks: chunks.clone(),
        }
    };
    let encoded = payload
        .encode()
        .map_err(|error| SessionError::Fatal(format!("payload encode: {error}")))?;

    // `WRITE` replaces the whole file with the stream; `PWRITE` patches the
    // range at `F_OFFSET`. A write that starts at chunk zero but covers less
    // than the file is still a patch, so the class must compare both the
    // offset and the stream length against the object size.
    let class = write_class(wire.off, data.len(), size);
    let mut fields = vec![
        (fid::F_CLIENT_ID, wire_client_id(store)),
        (fid::F_OP_ID, wire.op_id.as_bytes().to_vec()),
        (fid::F_OP_CLASS, vec![class.get()]),
        (fid::F_PATH, path.into_bytes()),
        (fid::F_MTIME_NS, (mtime_ns as u64).to_le_bytes().to_vec()),
        (fid::F_UID, uid.to_le_bytes().to_vec()),
        (fid::F_GID, gid.to_le_bytes().to_vec()),
        (fid::F_DATA_SESSION, session.to_le_bytes().to_vec()),
        (fid::F_TOTAL_LEN, (data.len() as u64).to_le_bytes().to_vec()),
        (fid::F_DATA_HASH, hash.to_vec()),
    ];
    if class == OpClass::PWRITE {
        fields.push((fid::F_OFFSET, wire.off.to_le_bytes().to_vec()));
    }
    fields.push((fid::F_EXTRA, encoded));

    send_stream(rpc, sealer, session, &data, counters, conntrace).await?;
    let body = encode_fields(&fields)?;
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = sealer.seal(&mut header, &Prefix::None, &body)?;
    send_raw(
        rpc,
        &header,
        &Prefix::None,
        sealed.as_bytes(),
        counters,
        conntrace,
    )
    .await
}

/// The wire class for one buffered write.
///
/// `WRITE` replaces the whole file with the stream. Only an offset-zero
/// stream whose length equals the object size qualifies; every other range
/// is a `PWRITE` patch.
fn write_class(off: u64, len: usize, size: u64) -> OpClass {
    if off == 0 && len as u64 == size {
        OpClass::WRITE
    } else {
        OpClass::PWRITE
    }
}

async fn send_meta(
    rpc: &mut RpcStream,
    store: &ClientDb,
    sealer: &Sealer<'_>,
    op: &OutboxOp,
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    let path = op
        .path
        .clone()
        .or_else(|| op.ino.and_then(|ino| store.path_of(ino).ok()))
        .ok_or_else(|| SessionError::Fatal("outbox row has no path".to_owned()))?;
    let object = op.ino.and_then(|ino| store.getattr(ino).ok());
    let (fallback_mtime, uid, gid) = object
        .as_ref()
        .map_or((super::db::now_ns(), 0, 0), |object| {
            (object.mtime_ns, object.uid, object.gid)
        });
    // The payload is the operation's authoritative timestamp. In particular
    // an unlink or rmdir has already tombstoned its object locally, so
    // `getattr` cannot supply the value the server must record on the parent.
    // A `setattr` with no timestamp keeps the object's mtime; zero is the
    // wire's "leave it alone" value for that class.
    let mtime_ns = match &op.decoded {
        EventPayload::Setattr { mtime_ns: None, .. } => 0,
        other => outbox_mtime(other).unwrap_or(fallback_mtime),
    };
    let class = match op.kind {
        EventKind::CreateFile => OpClass::CREATE_EXCL,
        EventKind::CreateDir => OpClass::MKDIR,
        EventKind::Symlink => OpClass::SYMLINK,
        EventKind::Write => OpClass::WRITE,
        EventKind::Truncate => OpClass::TRUNCATE,
        EventKind::Setattr => OpClass::SETATTR,
        EventKind::Rename => OpClass::RENAME,
        EventKind::Unlink => OpClass::UNLINK,
        EventKind::Rmdir => OpClass::RMDIR,
        EventKind::Link => OpClass::LINK,
        EventKind::Lock | EventKind::Unlock => OpClass::FCNTL_LOCK,
        EventKind::Leave => OpClass::LEAVE,
        EventKind::SyncCtrl => OpClass::SYNC_CTRL,
    };
    let wire_path = match (&op.decoded, &op.path2) {
        (EventPayload::Link { .. }, Some(new_path)) => new_path.clone(),
        _ => path.clone(),
    };
    let mut fields = vec![
        (fid::F_CLIENT_ID, wire_client_id(store)),
        (fid::F_OP_ID, op.op_id.to_vec()),
        (fid::F_OP_CLASS, vec![class.get()]),
        (fid::F_PATH, wire_path.into_bytes()),
        (fid::F_MTIME_NS, (mtime_ns as u64).to_le_bytes().to_vec()),
        (fid::F_UID, uid.to_le_bytes().to_vec()),
        (fid::F_GID, gid.to_le_bytes().to_vec()),
    ];
    match &op.decoded {
        EventPayload::CreateFile { mode, .. } => {
            fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
            fields.push((fid::F_OP_FLAGS, 0u32.to_le_bytes().to_vec()));
        }
        EventPayload::CreateDir { mode, .. } => {
            fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
        }
        EventPayload::Symlink { mode, target, .. } => {
            fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
            fields.push((fid::F_TARGET, target.clone()));
        }
        EventPayload::Truncate { size, .. } => {
            fields.push((fid::F_LENGTH, size.to_le_bytes().to_vec()));
        }
        EventPayload::Setattr {
            mode,
            uid,
            gid,
            mtime_ns,
            size,
            ..
        } => {
            if let Some(mode) = mode {
                fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
            }
            // `F_UID`, `F_GID` and `F_MTIME_NS` are already in the base
            // fields from the post-change object; adding them again would
            // duplicate a WCP field.
            let _ = (uid, gid, mtime_ns);
            if let Some(size) = size {
                fields.push((fid::F_LENGTH, size.to_le_bytes().to_vec()));
            }
        }
        EventPayload::Rename { .. } => {
            if let Some(path2) = &op.path2 {
                fields.push((fid::F_PATH2, path2.as_bytes().to_vec()));
            }
        }
        EventPayload::Link { .. } => {
            // The existing path is the link target.
            fields.push((fid::F_TARGET, path.as_bytes().to_vec()));
        }
        _ => {}
    }
    let encoded = op
        .decoded
        .encode()
        .map_err(|error| SessionError::Fatal(format!("payload encode: {error}")))?;
    fields.push((fid::F_EXTRA, encoded));

    let body = encode_fields(&fields)?;
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = sealer.seal(&mut header, &Prefix::None, &body)?;
    send_raw(
        rpc,
        &header,
        &Prefix::None,
        sealed.as_bytes(),
        counters,
        conntrace,
    )
    .await
}

async fn send_stream(
    rpc: &mut RpcStream,
    sealer: &Sealer<'_>,
    session: SessionId,
    data: &[u8],
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    if data.is_empty() {
        return Ok(());
    }
    let fragmenter = Fragmenter::new(session, StreamId::OP_DATA, data.len() as u64)
        .map_err(|error| SessionError::Fatal(format!("fragment: {error}")))?;
    for index in 0..fragmenter.total_chunks() {
        let length = fragmenter
            .chunk_len(index)
            .map_err(|error| SessionError::Fatal(format!("fragment: {error}")))?;
        let start = index as usize * CHUNK_PLAIN;
        let end = start + length;
        let fragment = fragmenter
            .fragment(index, &data[start..end])
            .map_err(|error| SessionError::Fatal(format!("fragment: {error}")))?;
        let prefix = Prefix::Route(RoutePrefix::new(
            session,
            StreamId::OP_DATA,
            fragment.index,
            fragment.total,
        ));
        let mut header = FrameHeader::new(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        let sealed = sealer.seal(&mut header, &prefix, fragment.plaintext)?;
        send_raw(
            rpc,
            &header,
            &prefix,
            sealed.as_bytes(),
            counters,
            conntrace,
        )
        .await?;
    }
    Ok(())
}

async fn send_raw(
    rpc: &mut RpcStream,
    header: &FrameHeader,
    prefix: &Prefix,
    body: &[u8],
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(), SessionError> {
    let bytes = FrameEncoder::with_capacity(
        crate::protocol::HEADER_LEN + prefix.encoded_len() + body.len(),
    )
    .encode_owned(&FrameRef::new(header, prefix, body))?;
    Counters::bump(&counters.frames_out);
    conntrace.record(TraceEntry::new(
        super::net::wall_clock_us(),
        "out",
        format!("{:?}", header.msg_type),
        body.len() as u32,
        header.seq,
    ));
    rpc.send(Bytes::from(bytes)).await?;
    Ok(())
}

fn encode_fields(fields: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, SessionError> {
    let mut writer = WcpWriter::new();
    for (field, value) in fields {
        writer.bytes(*field, value);
    }
    writer
        .finish()
        .map_err(|error| SessionError::Fatal(format!("WCP encode: {error}")))
}

fn wire_client_id(store: &ClientDb) -> Vec<u8> {
    store
        .client_id()
        .map(|id| id.to_vec())
        .unwrap_or_else(|_| vec![0u8; 16])
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_transport_end_is_a_resync_not_a_fatal_exit() {
        // The downlink already reports a closed stream as Disconnected. The
        // uplink used to turn the same condition into Fatal, which the
        // driver treats as terminal and exits 10.
        assert_eq!(
            uplink_signal(SessionError::Transport(
                crate::transport::TransportError::Closed
            )),
            Signal::Disconnected
        );
        assert_eq!(uplink_signal(SessionError::Closed), Signal::Disconnected);
        assert_eq!(
            uplink_signal(SessionError::Fatal("encode".to_owned())),
            Signal::Fatal("encode".to_owned())
        );
    }

    #[test]
    fn hello_prefix_carries_the_local_watermark_and_epoch() {
        let prefix = CtrlPrefix::new(Seq(42), 7);
        let bytes = prefix.encode();
        let decoded = CtrlPrefix::decode(&bytes).unwrap();
        assert_eq!(decoded.applied_seq, Seq(42));
        assert_eq!(decoded.epoch_seen, 7);
        assert!(decoded.validate().is_ok());
    }

    fn compacted_welcome() -> Welcome {
        Welcome {
            proto: crate::protocol::version::ProtoVersion::CURRENT,
            caps: Caps::REQUIRED.union(Caps::COMPACTION_FASTFORWARD),
            epoch: 8,
            current_seq: Seq(20),
            compacted_from_seq: 300,
            compacted_epoch: 8,
            compacted_seq: 20,
            client_id: crate::protocol::frame::ClientId::from_bytes([0; 16]),
            resync: crate::protocol::ResyncMode::None,
            limits: crate::protocol::WelcomeLimits {
                max_frame: 131_072,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 8,
            },
            server_time: 0,
            server_nonce: [0; 32],
            session_id: SessionId(1),
        }
    }

    #[test]
    fn fast_forward_adopts_the_compacted_watermark() {
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 7, 300, true),
            Some(20)
        );
    }

    #[test]
    fn fast_forward_rejects_a_watermark_off_the_compaction_point() {
        // A lagging replica replays: the synthetic log starts at 1, so its
        // watermark cannot be trusted as the pre-compaction state.
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 7, 299, true),
            None
        );
        // A watermark past the compaction point names a state the compacted
        // log cannot describe; this is corruption, not a fast-forward.
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 7, 301, true),
            None
        );
    }

    #[test]
    fn fast_forward_requires_the_epoch_before_the_compaction() {
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 6, 300, true),
            None
        );
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 8, 300, true),
            None
        );
    }

    #[test]
    fn fast_forward_rejects_an_empty_tree_after_content_existed() {
        assert_eq!(
            fast_forward_target(&compacted_welcome(), 7, 300, false),
            None
        );

        let mut empty = compacted_welcome();
        empty.compacted_from_seq = 0;
        empty.compacted_seq = 1;
        empty.current_seq = Seq(1);
        assert_eq!(fast_forward_target(&empty, 7, 0, false), Some(1));
    }

    #[test]
    fn fast_forward_requires_the_client_capability() {
        let mut welcome = compacted_welcome();
        welcome.caps = Caps::REQUIRED;
        assert_eq!(fast_forward_target(&welcome, 7, 300, true), None);
    }

    #[test]
    fn fast_forward_rejects_a_watermark_beyond_the_current_sequence() {
        let mut welcome = compacted_welcome();
        welcome.compacted_seq = 21;
        assert_eq!(fast_forward_target(&welcome, 7, 300, true), None);
    }

    #[test]
    fn a_semantic_rejection_names_the_operation_and_errno() {
        let mut detail = vec![0xab; 16];
        detail.extend_from_slice(&(-28i32).to_le_bytes());
        detail.extend_from_slice(b"no space");
        let (op_id, errno, state) = decode_rejection(&detail).unwrap();
        assert_eq!(op_id, [0xab; 16]);
        assert_eq!(errno, -28);
        assert_eq!(state, RejectionState::None);
        assert!(decode_rejection(&detail[..19]).is_none());
    }

    #[test]
    fn a_resync_marker_decodes_as_resync() {
        let mut detail = vec![0xab; 16];
        detail.extend_from_slice(&(-17i32).to_le_bytes());
        detail.extend_from_slice(&u32::MAX.to_le_bytes());
        let (op_id, errno, state) = decode_rejection(&detail).unwrap();
        assert_eq!(op_id, [0xab; 16]);
        assert_eq!(errno, -17);
        assert_eq!(state, RejectionState::Resync);
    }

    #[test]
    fn an_empty_snapshot_length_decodes_as_none() {
        let mut detail = vec![0xab; 16];
        detail.extend_from_slice(&0i32.to_le_bytes());
        detail.extend_from_slice(&0u32.to_le_bytes());
        let (_, _, state) = decode_rejection(&detail).unwrap();
        assert_eq!(state, RejectionState::None);
    }

    #[test]
    fn a_rejection_snapshot_decodes_and_a_corrupt_one_stays_empty() {
        let snapshot = RejectState {
            path: "/big".to_owned(),
            object: None,
            chunks: Vec::new(),
            data: Vec::new(),
            parent: Some([3; 16]),
            name: Some("big".to_owned()),
        };
        let encoded =
            bincode::serde::encode_to_vec(&snapshot, bincode::config::standard()).unwrap();
        let mut detail = vec![0xcd; 16];
        detail.extend_from_slice(&0i32.to_le_bytes());
        detail.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        detail.extend_from_slice(&encoded);
        let (_, _, state) = decode_rejection(&detail).unwrap();
        assert_eq!(state, RejectionState::Snapshot(Box::new(snapshot)));

        // A corrupt payload is not a resync request.
        let mut corrupt = vec![0xcd; 16];
        corrupt.extend_from_slice(&0i32.to_le_bytes());
        corrupt.extend_from_slice(&3u32.to_le_bytes());
        corrupt.extend_from_slice(&[0xff; 3]);
        let (_, _, state) = decode_rejection(&corrupt).unwrap();
        assert_eq!(state, RejectionState::None);
    }

    #[test]
    fn every_order_class_maps_to_an_event_kind() {
        assert_eq!(kind_for(OpClass::CREATE_EXCL), EventKind::CreateFile);
        assert_eq!(kind_for(OpClass::MKDIR), EventKind::CreateDir);
        assert_eq!(kind_for(OpClass::SYMLINK), EventKind::Symlink);
        assert_eq!(kind_for(OpClass::PWRITE), EventKind::Write);
        assert_eq!(kind_for(OpClass::TRUNCATE), EventKind::Truncate);
        assert_eq!(kind_for(OpClass::RENAME), EventKind::Rename);
        assert_eq!(kind_for(OpClass::UNLINK), EventKind::Unlink);
        assert_eq!(kind_for(OpClass::RMDIR), EventKind::Rmdir);
        assert_eq!(kind_for(OpClass::LINK), EventKind::Link);
    }

    #[tokio::test]
    async fn a_sequence_gap_requests_a_resync_instead_of_a_fatal_exit() {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open(dir.path().join("client.db"), [7u8; 16]).unwrap();
        let mut pending = vec![RemoteEvent {
            seq: 2,
            epoch: 1,
            op_id: None,
            result: "ok".to_owned(),
            payload: EventPayload::Leave,
            path: None,
            path2: None,
            data: None,
        }];
        let mut pending_bytes = 0usize;
        let watermark = AtomicI64::new(0);
        let counters = Counters::default();
        let (signal, mut signals) = mpsc::channel(8);

        let result = flush_replay(
            &db,
            &mut pending,
            &mut pending_bytes,
            &watermark,
            &counters,
            &signal,
        )
        .await;

        assert!(result.is_err());
        match signals.recv().await {
            Some(Signal::Resync) => {}
            other => panic!("expected Resync, got {other:?}"),
        }
        // The failed batch rolled back; the durable watermark is unchanged so
        // the reconnect replays from the missing sequence.
        assert_eq!(db.applied_seq().unwrap(), 0);
    }

    #[test]
    fn a_partial_write_from_offset_zero_is_a_pwrite() {
        let size = 150 * 1024;
        // One byte at offset zero over a larger file must not become WRITE:
        // the server would replace the file with the single-byte stream.
        assert_eq!(write_class(0, 1, size), OpClass::PWRITE);
        assert_eq!(write_class(0, 64 * 1024, size), OpClass::PWRITE);
        assert_eq!(write_class(10, 1, size), OpClass::PWRITE);
        // The whole file at offset zero is the only WRITE.
        assert_eq!(write_class(0, size as usize, size), OpClass::WRITE);
        assert_eq!(write_class(0, 0, 0), OpClass::WRITE);
    }
}
