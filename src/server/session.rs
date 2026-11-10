//! Per-connection tasks: PSK handshake, uplink reader, downlink writer, replay.
//!
//! One session is two independent HTTP requests. This module owns the
//! connection state machine:
//!
//! ```text
//! rpc     HELLO(plain + sealed AUTH) -> WELCOME(plain + proof + sealed ACCEPT)
//!         then ORDERED/PING/LEAVE/RELAY frames sealed under the PSK enc key
//! events  park under X-SM-Nonce; the handshake writes WELCOME through it
//! writer  control first, then data; KICK is deferred until data drains
//! replay  reads events from SQLite and pushes them before live broadcasts
//! ```
//!
//! An unauthenticated connection never enters the online table. `client_id`
//! is decoded because the wire still carries it, but it is never trusted:
//! routing and broadcast identity are the server-assigned `SessionId`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::body::Incoming;
use tokio::sync::{mpsc, oneshot};

use crate::crypto::secret::MasterKey;
use crate::protocol::crypto::{NonceMinter, Opener, PskKeyRing, PskSalt, Sealer};
use crate::protocol::handshake::{HelloInput, NonceReplayGuard, ServerHandshake};
use crate::protocol::messages::{Message, Pong, WelcomeLimits, decode_plain, decode_sealed};
use crate::protocol::{
    Caps, ErrorMessage, Flags, FrameBuf, FrameDecoder, FrameHeader, FrameRef, KickReason, MsgType,
    Prefix, PrefixKind, ResyncMode, RoutePrefix, Seq, SessionId, StreamId, TrnReason, encode_frame,
};
use crate::store::sqlite::EventPayload;
use crate::transport::{AcceptedHttp, BodyStream, MpscSender, PeerId};

use super::config::ServeConfig;
use super::online::{Outbox, QueueStats};
use super::sequencer::{
    AttachRequest, DetachCause, ReplayStep, Sequencer, WatermarkReport, encode_control, now_secs,
    server_caps, wall_clock_us,
};
use super::wire::WireOp;

/// Shared handles for every connection task.
#[derive(Clone)]
pub(crate) struct SessionContext {
    /// Actor handle.
    pub sequencer: Sequencer,
    /// Server configuration.
    pub config: Arc<ServeConfig>,
    /// Master key; per-connection rings are derived from it (HKDF only).
    pub master: Arc<MasterKey>,
    /// Server-wide HELLO nonce replay window.
    pub guard: Arc<tokio::sync::Mutex<NonceReplayGuard>>,
}

/// Spawn the task that owns one accepted HTTP half.
pub(crate) fn spawn(accepted: AcceptedHttp, context: SessionContext) {
    match accepted {
        AcceptedHttp::Rpc {
            peer,
            nonce,
            body,
            end,
            ..
        } => {
            tokio::spawn(run_rpc(context, peer, nonce, body, end));
        }
        AcceptedHttp::Events { nonce, out, .. } => {
            tokio::spawn(run_events(context, nonce, out));
        }
    }
}

async fn run_events(context: SessionContext, nonce: u64, out: MpscSender) {
    let _ = context.sequencer.events(nonce, out).await;
}

/// Whether the reader loop continues.
enum Flow {
    Continue,
    Close,
}

/// One authenticated, attached session.
struct RpcSession {
    session_id: SessionId,
    generation: u64,
    ctrl_tx: mpsc::Sender<Bytes>,
    detach: DetachCause,
    /// Steady-state PSK ring, derived once the session attaches.
    ring: Arc<crate::protocol::crypto::PskKeyRing>,
    streams: HashMap<(SessionId, StreamId), DataStream>,
    assembled: HashMap<SessionId, Vec<u8>>,
}

/// Server-side reassembly of one `OP_DATA` stream.
///
/// The protocol [`crate::protocol::fragment::Reassembler`] holds a
/// `Box<dyn ChunkSink>`, which is not `Send`; a connection task must be
/// `Send`, so the server keeps this small ordered buffer instead. The wire
/// invariants are the same: `index < total`, every non-final fragment is
/// exactly 64 KiB, duplicates are dropped, and completion is exactly once.
struct DataStream {
    total: u32,
    next: u32,
    received: u32,
    reorder: BTreeMap<u32, Vec<u8>>,
    buffer: Vec<u8>,
}

/// Largest assembled `OP_DATA` stream the server buffers.
const MAX_CONTENT_BYTES: usize = 64 << 20;

/// Largest out-of-order window for one stream, matching the protocol layer.
const MAX_REORDER_CHUNKS: usize = 8;

impl DataStream {
    fn new(total: u32) -> Option<Self> {
        (total > 0).then_some(Self {
            total,
            next: 0,
            received: 0,
            reorder: BTreeMap::new(),
            buffer: Vec::new(),
        })
    }

    /// Returns `Ok(true)` when this fragment completed the stream.
    fn push(&mut self, index: u32, total: u32, data: &[u8]) -> Result<bool, ()> {
        if total != self.total || index >= self.total {
            return Err(());
        }
        if data.len() > crate::protocol::CHUNK_PLAIN {
            return Err(());
        }
        if index + 1 < self.total && data.len() != crate::protocol::CHUNK_PLAIN {
            return Err(());
        }
        if index < self.next || self.reorder.contains_key(&index) {
            return Ok(false);
        }
        if self.buffer.len().saturating_add(data.len()) > MAX_CONTENT_BYTES {
            return Err(());
        }
        if index == self.next {
            self.buffer.extend_from_slice(data);
            self.next += 1;
            self.received += 1;
            while let Some(chunk) = self.reorder.remove(&self.next) {
                self.buffer.extend_from_slice(&chunk);
                self.next += 1;
            }
        } else {
            if self.reorder.len() >= MAX_REORDER_CHUNKS {
                return Err(());
            }
            self.reorder.insert(index, data.to_vec());
            self.received += 1;
        }
        Ok(self.received == self.total && self.next == self.total)
    }
}

/// Uplink state before the session is attached.
enum Phase {
    Hello,
    Steady(RpcSession),
}

async fn run_rpc(
    context: SessionContext,
    peer: PeerId,
    nonce: u64,
    mut body: BodyStream<Incoming>,
    end: oneshot::Sender<()>,
) {
    let mut decoder = FrameDecoder::new(context.config.limits);
    let mut phase = Phase::Hello;
    let mut writer_closed: Option<oneshot::Receiver<()>> = None;

    'session: loop {
        let next = match writer_closed.as_mut() {
            Some(closed) => {
                tokio::select! {
                    biased;
                    _ = closed => break 'session,
                    chunk = body.next_bytes() => chunk,
                }
            }
            None => body.next_bytes().await,
        };
        match next {
            Ok(Some(chunk)) => {
                if let Err(error) = decoder.push(&chunk) {
                    let reason = error.to_wire().unwrap_or(TrnReason::BadFrame);
                    send_error(&phase, reason, &[]);
                    break 'session;
                }
                loop {
                    match decoder.next_frame_owned() {
                        Ok(Some(frame)) => {
                            match advance(
                                &context,
                                &mut phase,
                                &mut writer_closed,
                                peer,
                                nonce,
                                frame,
                            )
                            .await
                            {
                                Ok(Flow::Continue) => {}
                                Ok(Flow::Close) => break 'session,
                                Err(()) => break 'session,
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let reason = error.to_wire().unwrap_or(TrnReason::BadFrame);
                            send_error(&phase, reason, &[]);
                            break 'session;
                        }
                    }
                }
            }
            Ok(None) => break 'session,
            Err(_) => break 'session,
        }
    }

    if let Phase::Steady(session) = phase {
        let _ = context
            .sequencer
            .detach(session.session_id, session.generation, session.detach)
            .await;
    }
    let _ = end.send(());
}

async fn advance(
    context: &SessionContext,
    phase: &mut Phase,
    writer_closed: &mut Option<oneshot::Receiver<()>>,
    peer: PeerId,
    nonce: u64,
    frame: FrameBuf,
) -> Result<Flow, ()> {
    match phase {
        Phase::Hello => start_hello(context, phase, writer_closed, peer, nonce, frame).await,
        Phase::Steady(session) => handle_frame(context, session, frame).await,
    }
}

async fn start_hello(
    context: &SessionContext,
    phase: &mut Phase,
    writer_closed: &mut Option<oneshot::Receiver<()>>,
    peer: PeerId,
    nonce: u64,
    frame: FrameBuf,
) -> Result<Flow, ()> {
    if frame.header.msg_type != MsgType::HELLO || frame.header.seq != Seq::UNSEQUENCED {
        return Err(());
    }
    let Some(ctrl) = frame.prefix.as_ctrl() else {
        return Err(());
    };
    if ctrl.validate().is_err() {
        return Err(());
    }
    let hello = match decode_plain(MsgType::HELLO, &frame.body, &context.config.limits) {
        Ok(Message::Hello(hello)) => hello,
        _ => return Err(()),
    };
    let ring = context
        .master
        .derive_psk_keyring(&PskSalt::DEFAULT)
        .map_err(|_| ())?;
    let epoch = context.sequencer.epoch().get();
    let current_seq = context.sequencer.current_seq();
    let compaction = context.sequencer.compaction();
    let limits = WelcomeLimits {
        max_frame: context.config.limits.effective_cap(),
        credit_bytes: context.config.welcome.credit_bytes,
        session_ttl_s: context.config.welcome.session_ttl_s,
        max_sessions: context.config.welcome.max_sessions,
    };
    let mut handshake =
        ServerHandshake::new(ring, epoch, current_seq, compaction, limits, server_caps());

    let session_id = random_session_id();
    let server_nonce = random_32();
    let proof_nonce = random_12();
    let accept_nonce = random_12();
    let fast_forward = hello.caps.contains(Caps::COMPACTION_FASTFORWARD)
        && compaction.epoch == epoch
        && compaction.seq <= current_seq.get()
        && compaction.admits(ctrl.epoch_seen, ctrl.applied_seq.get());
    let input = HelloInput {
        session_id,
        server_nonce,
        proof_nonce,
        accept_nonce,
        server_time: now_secs().max(0) as u64,
        resync: if fast_forward {
            ResyncMode::None
        } else if ctrl.epoch_seen != epoch || ctrl.applied_seq > current_seq {
            ResyncMode::Full
        } else {
            ResyncMode::None
        },
        ctrl: *ctrl,
    };
    // Authenticate before recording the nonce. An unauthenticated flood can
    // therefore not evict a captured nonce from the bounded replay window.
    // The lock spans the check, the verification and the record so two
    // connections cannot both accept the same nonce.
    let now_ms = now_millis();
    let mut guard = context.guard.lock().await;
    if guard.contains(hello.client_nonce, now_ms) {
        return Err(());
    }
    let accepted = match handshake.on_hello(&hello, input) {
        Ok(accepted) => accepted,
        Err(_) => return Err(()),
    };
    guard.record(hello.client_nonce, now_ms);
    drop(guard);

    let pair = match context.sequencer.pair(nonce).await {
        Ok(pair) => pair,
        Err(_) => return Err(()),
    };
    let downlink = match (pair.events, pair.wait) {
        (Some(out), _) => out,
        (None, Some(wait)) => {
            match tokio::time::timeout(context.config.hello_timeout, wait).await {
                Ok(Ok(out)) => out,
                _ => {
                    context.sequencer.cancel_pair(nonce).await;
                    return Err(());
                }
            }
        }
        (None, None) => return Err(()),
    };
    let welcome = encode_control(
        MsgType::WELCOME,
        Prefix::None,
        &accepted.body,
        Seq::UNSEQUENCED,
    )
    .map_err(|_| ())?;
    if downlink.send(welcome).await.is_err() {
        return Err(());
    }

    // `HELLO.AUTH` already verified, so the session may attach immediately.
    // `WELCOME` is queued on the events stream before the writer starts, so
    // the client always sees it before any replayed or live frame.
    let (outbox, data, ctrl_tx) = Outbox::new(&context.config.outbox);
    let request = AttachRequest {
        session_id: accepted.session_id,
        nonce,
        peer,
        outbox,
        epoch_seen: ctrl.epoch_seen,
        applied_seq: ctrl.applied_seq,
        fast_forward: hello.caps.contains(Caps::COMPACTION_FASTFORWARD),
    };
    let reply = match context.sequencer.attach(request).await {
        Ok(reply) => reply,
        Err(_) => return Err(()),
    };
    let (closed_tx, closed_rx) = oneshot::channel();
    tokio::spawn(run_writer(
        downlink,
        data,
        ctrl_tx,
        Arc::clone(&reply.queued),
        closed_tx,
    ));
    if reply.replay_from <= reply.current_seq {
        tokio::spawn(run_replay(
            context.clone(),
            accepted.session_id,
            reply.generation,
            reply.replay_from,
            reply.current_seq,
            reply.replay_tx.clone(),
            Arc::clone(&reply.queued),
        ));
    }
    *writer_closed = Some(closed_rx);
    let ring = Arc::new(
        context
            .master
            .derive_psk_keyring(&PskSalt::DEFAULT)
            .map_err(|_| ())?,
    );
    *phase = Phase::Steady(RpcSession {
        session_id: accepted.session_id,
        generation: reply.generation,
        ctrl_tx: reply.ctrl_tx,
        detach: DetachCause::Disconnected,
        ring,
        streams: HashMap::new(),
        assembled: HashMap::new(),
    });
    Ok(Flow::Continue)
}

async fn handle_frame(
    context: &SessionContext,
    session: &mut RpcSession,
    frame: FrameBuf,
) -> Result<Flow, ()> {
    if frame.header.seq != Seq::UNSEQUENCED {
        send_error_steady(session, TrnReason::Protocol);
        session.detach = DetachCause::Protocol;
        return Ok(Flow::Close);
    }
    let msg_type = frame.header.msg_type;
    match msg_type {
        MsgType::ORDERED => {
            if frame.prefix.kind() != PrefixKind::None {
                return protocol_close(session);
            }
            match decode_ordered(context, session, &frame).await {
                Ok(Some(wire_op)) => {
                    if wire_op.class.is_leave() {
                        let wire =
                            encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
                                .map_err(|_| ())?;
                        let _ = context.sequencer.leave(session.session_id, wire).await;
                        session.detach = DetachCause::ClientLeft;
                        return Ok(Flow::Close);
                    }
                    let content = match wire_op.data {
                        Some(data) => match session.assembled.remove(&data.session) {
                            Some(bytes) => {
                                if bytes.len() as u64 != data.total_len
                                    || blake3::hash(&bytes).as_bytes() != &data.data_hash
                                {
                                    send_error_steady(session, TrnReason::BadFrame);
                                    session.detach = DetachCause::Protocol;
                                    return Ok(Flow::Close);
                                }
                                Some(bytes)
                            }
                            None => {
                                send_error_detail_steady(
                                    session,
                                    TrnReason::Protocol,
                                    b"data stream missing",
                                );
                                return Ok(Flow::Continue);
                            }
                        },
                        None => None,
                    };
                    let wire =
                        encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
                            .map_err(|_| ())?;
                    let request = super::store::CommitRequest {
                        session: session.session_id.to_le_bytes(),
                        op: wire_op,
                        content,
                        wire,
                        created_at: now_secs(),
                    };
                    if context
                        .sequencer
                        .ordered(session.session_id, request)
                        .await
                        .is_err()
                    {
                        return Ok(Flow::Close);
                    }
                    Ok(Flow::Continue)
                }
                Ok(None) => Ok(Flow::Continue),
                Err(()) => protocol_close(session),
            }
        }
        MsgType::PING => {
            let Some(ctrl) = frame.prefix.as_ctrl() else {
                return protocol_close(session);
            };
            if ctrl.validate().is_err() {
                return protocol_close(session);
            }
            let plain = match open_steady(session, &frame) {
                Ok(plain) => plain,
                Err(()) => {
                    send_error_steady(session, TrnReason::BadFrame);
                    session.detach = DetachCause::Protocol;
                    return Ok(Flow::Close);
                }
            };
            let ping = match decode_sealed(MsgType::PING, plain.as_slice(), &context.config.limits)
            {
                Ok(Message::Ping(ping)) => ping,
                _ => return protocol_close(session),
            };
            let _ = ping;
            let report = WatermarkReport {
                session: session.session_id,
                applied_seq: ctrl.applied_seq,
                epoch_seen: ctrl.epoch_seen,
                rtt_ms: None,
                at: Instant::now(),
            };
            let _ = context.sequencer.watermark(report).await;
            let nonces = NonceMinter::new(&mut rand::rng());
            if let Some(pong) = encode_pong(&session.ring, &nonces, wall_clock_us()) {
                let _ = session.ctrl_tx.try_send(pong);
            }
            Ok(Flow::Continue)
        }
        MsgType::LEAVE => {
            if frame.prefix.kind() != PrefixKind::None {
                return protocol_close(session);
            }
            let wire = encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
                .map_err(|_| ())?;
            let _ = context.sequencer.leave(session.session_id, wire).await;
            session.detach = DetachCause::ClientLeft;
            Ok(Flow::Close)
        }
        MsgType::ACK | MsgType::RESPONSE => {
            let _ = context.sequencer.seen(session.session_id).await;
            Ok(Flow::Continue)
        }
        MsgType::RELAY | MsgType::FLOW | MsgType::SYNC_END | MsgType::STREAM_DATA => {
            if frame.prefix.kind() != PrefixKind::Route {
                return protocol_close(session);
            }
            let Some(prefix) = frame.prefix.as_route().copied() else {
                return protocol_close(session);
            };
            if msg_type == MsgType::STREAM_DATA && prefix.stream == StreamId::OP_DATA {
                return handle_stream_data(context, session, &frame, prefix).await;
            }
            // The `RELAY{CTRL}` open and `SYNC_END` that bracket an OP_DATA
            // stream are local to the content path; forwarding the close to
            // the relay hub would answer with `SessionUnknown`.
            let content_session = session.assembled.contains_key(&prefix.session_id)
                || session
                    .streams
                    .keys()
                    .any(|(id, _)| *id == prefix.session_id);
            if content_session {
                return Ok(Flow::Continue);
            }
            if msg_type == MsgType::RELAY
                && prefix.stream == StreamId::CTRL
                && prefix.total_chunks == 0
            {
                // Opening a relay session for OP_DATA is handled locally;
                // other streams still go through the relay hub.
                if let Ok(plain) = open_steady(session, &frame) {
                    if plain.is_empty() {
                        return Ok(Flow::Continue);
                    }
                }
            }
            if context
                .sequencer
                .relay(session.session_id, frame)
                .await
                .is_err()
            {
                return Ok(Flow::Close);
            }
            Ok(Flow::Continue)
        }
        _ => protocol_close(session),
    }
}

async fn decode_ordered(
    context: &SessionContext,
    session: &mut RpcSession,
    frame: &FrameBuf,
) -> Result<Option<WireOp>, ()> {
    let plain = open_steady(session, frame).map_err(|_| {
        send_error_steady(session, TrnReason::BadFrame);
        session.detach = DetachCause::Protocol;
    })?;
    let ordered = match decode_sealed(MsgType::ORDERED, plain.as_slice(), &context.config.limits) {
        Ok(Message::Ordered(ordered)) => ordered,
        _ => return Err(()),
    };
    match WireOp::from_ordered(&ordered) {
        Ok(op) => Ok(Some(op)),
        Err(reject) => {
            let op_id = ordered.op_id.to_bytes();
            let detail = super::wire::reject_body(
                op_id,
                reject,
                None,
                usize::from(context.config.limits.detail_max),
            );
            send_error_detail_steady(session, TrnReason::Protocol, &detail);
            Ok(None)
        }
    }
}

async fn handle_stream_data(
    context: &SessionContext,
    session: &mut RpcSession,
    frame: &FrameBuf,
    prefix: RoutePrefix,
) -> Result<Flow, ()> {
    let plain = open_steady(session, frame).map_err(|_| {
        send_error_steady(session, TrnReason::BadFrame);
        session.detach = DetachCause::Protocol;
    })?;
    let key = (prefix.session_id, prefix.stream);
    let entry = match session.streams.entry(key) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            match DataStream::new(prefix.total_chunks) {
                Some(stream) => entry.insert(stream),
                None => {
                    send_error_steady(session, TrnReason::BadFrame);
                    session.detach = DetachCause::Protocol;
                    return Ok(Flow::Close);
                }
            }
        }
    };
    match entry.push(prefix.chunk_index, prefix.total_chunks, plain.as_slice()) {
        Ok(false) => {
            // Live readers need the same fragment; the actor fans out the
            // original sealed bytes to every Online session except the author.
            let _ = context
                .sequencer
                .relay(session.session_id, frame.clone())
                .await;
            Ok(Flow::Continue)
        }
        Ok(true) => {
            let data = std::mem::take(&mut entry.buffer);
            session.assembled.insert(prefix.session_id, data);
            session.streams.remove(&key);
            let _ = context
                .sequencer
                .relay(session.session_id, frame.clone())
                .await;
            Ok(Flow::Continue)
        }
        Err(()) => {
            session.streams.remove(&key);
            send_error_steady(session, TrnReason::BadFrame);
            session.detach = DetachCause::Protocol;
            Ok(Flow::Close)
        }
    }
}

fn open_steady(
    session: &RpcSession,
    frame: &FrameBuf,
) -> Result<crate::protocol::crypto::Opened, ()> {
    Opener::with_session_key(&session.ring.session_key())
        .open(&frame.header, &frame.prefix, &frame.body)
        .map_err(|_| ())
}

fn encode_pong(ring: &PskKeyRing, nonces: &NonceMinter, server_time: u64) -> Option<Bytes> {
    let body = (Pong { server_time }).encode().ok()?;
    let mut header = FrameHeader::new(MsgType::PONG, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = Sealer::with_session_key(&ring.session_key(), nonces)
        .seal(&mut header, &Prefix::None, &body)
        .ok()?;
    let bytes = encode_frame(&FrameRef::new(&header, &Prefix::None, sealed.as_bytes())).ok()?;
    Some(Bytes::from(bytes))
}

fn protocol_close(session: &mut RpcSession) -> Result<Flow, ()> {
    send_error_steady(session, TrnReason::Protocol);
    session.detach = DetachCause::Protocol;
    Ok(Flow::Close)
}

fn send_error(phase: &Phase, reason: TrnReason, detail: &[u8]) {
    let Phase::Steady(session) = phase else {
        return;
    };
    send_error_detail_steady(session, reason, detail);
}

fn send_error_steady(session: &RpcSession, reason: TrnReason) {
    send_error_detail_steady(session, reason, &[]);
}

fn send_error_detail_steady(session: &RpcSession, reason: TrnReason, detail: &[u8]) {
    let Ok(body) = (ErrorMessage {
        reason,
        detail,
        session_id: Some(session.session_id),
    })
    .encode() else {
        return;
    };
    if let Ok(frame) = encode_control(MsgType::ERROR, Prefix::None, &body, Seq::UNSEQUENCED) {
        let _ = session.ctrl_tx.try_send(frame);
    }
}

async fn run_writer(
    out: MpscSender,
    mut data: mpsc::Receiver<Bytes>,
    mut ctrl: mpsc::Receiver<Bytes>,
    queued: Arc<QueueStats>,
    closed: oneshot::Sender<()>,
) {
    let mut deferred_kick: Option<Bytes> = None;
    loop {
        tokio::select! {
            biased;
            Some(frame) = ctrl.recv(), if deferred_kick.is_none() => {
                if is_kick(&frame) {
                    deferred_kick = Some(frame);
                    continue;
                }
                if out.send(frame).await.is_err() {
                    break;
                }
            }
            Some(frame) = data.recv() => {
                let len = frame.len();
                if out.send(frame).await.is_err() {
                    break;
                }
                queued.sub(len);
            }
            else => break,
        }
    }
    if let Some(kick) = deferred_kick {
        let sent = out.send(kick).await;
        tracing::debug!(sent = sent.is_ok(), "deferred kick sent");
    }
    let _ = closed.send(());
}

fn is_kick(frame: &Bytes) -> bool {
    frame.len() >= crate::protocol::HEADER_LEN
        && frame[0] == crate::protocol::MAGIC
        && frame[2] == MsgType::KICK.get()
}

/// Largest byte run replay hands to the downlink in one chunk.
///
/// A chunk is not a frame: HTTP chunk boundaries carry no protocol meaning,
/// and the receiver's decoder splits frames from any byte run. Coalescing
/// keeps one syscall and one HTTP chunk for many events instead of one per
/// event.
const REPLAY_CHUNK_BYTES: usize = 64 * 1024;

/// How long one replay chunk may wait for downlink capacity.
///
/// A replay that cannot hand one bounded chunk to the writer for this long is
/// not socket backpressure: the writer is wedged (a body nobody reads, a
/// receiver that stopped polling). Ending the session is the only recovery
/// that keeps the event log authoritative, because the client then reconnects
/// and replays from its durable cursor.
const REPLAY_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Replay events between two keepalive `PONG` frames.
///
/// A `PONG` carries no sequence number and no event, so it cannot advance or
/// reorder the log. It exists only so a receiver that is still materialising
/// a batch can distinguish "the server is reading the next page" from "the
/// downlink is dead". The value matches the client's batch size, so a
/// keepalive never splits a batch more finely than the receiver already does.
const REPLAY_KEEPALIVE_EVENTS: u32 = 64;

/// Wall-clock interval between two keepalive `PONG` frames during replay.
///
/// The client watchdog is 45 s; five seconds leaves ample room for a slow
/// SQLite page read without ever approaching it.
const REPLAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Why a replay stopped before it reached the live stream.
#[derive(Debug, thiserror::Error)]
enum ReplayError {
    /// The store could not read the event log or its chunks.
    #[error("store: {0}")]
    Store(String),
    /// A stored write event cannot produce a complete content stream.
    #[error("content: {0}")]
    Content(String),
    /// A frame could not be synthesized from the stored event.
    #[error("frame: {0}")]
    Frame(String),
    /// The writer or its body is gone.
    #[error("downlink queue closed")]
    Closed,
    /// The writer did not take a chunk within [`REPLAY_SEND_TIMEOUT`].
    #[error("downlink made no progress for {0:?}")]
    Stalled(Duration),
}

/// Accumulates replay frames into bounded byte runs.
struct ReplayChunk {
    tx: mpsc::Sender<Bytes>,
    /// Downlink accounting shared with the writer.
    ///
    /// Replay traffic is charged here for the same reason live traffic is:
    /// `healthz` and the stall verdict must see how much replay data is
    /// queued, and the writer marks every chunk it drains.
    queued: Arc<QueueStats>,
    buf: Vec<u8>,
}

impl ReplayChunk {
    fn new(tx: mpsc::Sender<Bytes>, queued: Arc<QueueStats>) -> Self {
        Self {
            tx,
            queued,
            buf: Vec::with_capacity(REPLAY_CHUNK_BYTES),
        }
    }

    /// Add one frame, sending the buffer when it is full.
    async fn push(&mut self, frame: &[u8]) -> Result<(), ReplayError> {
        if !self.buf.is_empty() && self.buf.len() + frame.len() > REPLAY_CHUNK_BYTES {
            self.flush().await?;
        }
        self.buf.extend_from_slice(frame);
        if self.buf.len() >= REPLAY_CHUNK_BYTES {
            self.flush().await?;
        }
        Ok(())
    }

    /// Send everything buffered, bounded by [`REPLAY_SEND_TIMEOUT`].
    async fn flush(&mut self) -> Result<(), ReplayError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.buf = Vec::with_capacity(REPLAY_CHUNK_BYTES);
        self.queued.add(chunk.len());
        match tokio::time::timeout(REPLAY_SEND_TIMEOUT, self.tx.send(chunk)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(ReplayError::Closed),
            Err(_) => Err(ReplayError::Stalled(REPLAY_SEND_TIMEOUT)),
        }
    }
}

/// Replay `(replay_from ..= current)` from SQLite, then switch to live.
///
/// A failure ends the session instead of leaving it in `Replaying` forever:
/// the client's durable cursor is the only state a reconnect needs, and a
/// stranded session would keep a sequence gap open with no way to close it.
async fn run_replay(
    context: SessionContext,
    session_id: SessionId,
    generation: u64,
    replay_from: Seq,
    current_seq: Seq,
    tx: mpsc::Sender<Bytes>,
    queued: Arc<QueueStats>,
) {
    match replay_stream(
        &context,
        session_id,
        generation,
        replay_from,
        current_seq,
        tx,
        queued,
    )
    .await
    {
        Ok(()) => tracing::debug!(
            session = ?session_id,
            generation,
            from = replay_from.get(),
            current = current_seq.get(),
            "replay reached the live stream"
        ),
        Err(error) => {
            tracing::error!(
                event = "replay_failed",
                session = ?session_id,
                generation,
                from = replay_from.get(),
                current = current_seq.get(),
                error = %error,
                "replay stopped before the live stream; ending the session so the client replays from its cursor"
            );
            if context
                .sequencer
                .kick(session_id, generation, KickReason::Stalled)
                .await
                .is_err()
            {
                tracing::warn!(
                    session = ?session_id,
                    generation,
                    "cannot ask the sequencer to end a failed replay"
                );
            }
        }
    }
}

/// Read the log from `replay_from` to `current_seq` and hand every event to
/// the writer in wire order.
async fn replay_stream(
    context: &SessionContext,
    session_id: SessionId,
    generation: u64,
    replay_from: Seq,
    current_seq: Seq,
    tx: mpsc::Sender<Bytes>,
    queued: Arc<QueueStats>,
) -> Result<(), ReplayError> {
    let store = context.sequencer.store();
    let epoch = context.sequencer.epoch().get() as i64;
    let ring = context
        .master
        .derive_psk_keyring(&PskSalt::DEFAULT)
        .map_err(|error| ReplayError::Frame(error.to_string()))?;
    let nonces = NonceMinter::new(&mut rand::rng());
    let mut next = replay_from.get();
    let mut target = current_seq.get();
    let mut chunk = ReplayChunk::new(tx, queued);
    let mut events_since_keepalive = 0u32;
    let mut last_keepalive = Instant::now();
    loop {
        while next <= target {
            let page = store
                .events(
                    epoch,
                    next.saturating_sub(1) as i64,
                    context.config.replay_batch,
                )
                .await
                .map_err(ReplayError::Store)?;
            if page.is_empty() {
                break;
            }
            for event in page {
                let seq = event.seq.max(0) as u64;
                if seq > target {
                    break;
                }
                events_since_keepalive = events_since_keepalive.saturating_add(1);
                if events_since_keepalive >= REPLAY_KEEPALIVE_EVENTS
                    || last_keepalive.elapsed() >= REPLAY_KEEPALIVE_INTERVAL
                {
                    let pong = encode_pong(&ring, &nonces, now_secs().max(0) as u64)
                        .ok_or_else(|| ReplayError::Frame("keepalive PONG".to_owned()))?;
                    chunk.push(&pong).await?;
                    events_since_keepalive = 0;
                    last_keepalive = Instant::now();
                }
                let content = replay_content(&store, &event).await?;
                if let Some(data) = &content {
                    // Seal the whole content stream before queueing any of
                    // it. A `RELAY` that reached the receiver without its
                    // `STREAM_DATA` leaves the replica waiting for bytes
                    // that will never come; building every frame first makes
                    // the open marker and its fragments inseparable.
                    let frames = super::wire::replay_content_frames(&event, &ring, &nonces, data)
                        .map_err(|error| ReplayError::Content(error.to_string()))?;
                    for frame in &frames {
                        chunk.push(frame).await?;
                    }
                }
                // Rebuild every frame from the stored event. The sidecar's
                // author frame carries the author's payload, which is not
                // necessarily what the server committed: paths resolve to
                // server inodes and a PWRITE event describes the complete
                // file. Live and replay receivers must see the same bytes.
                // Synthesized frames are unsequenced and must be stamped.
                let frame = super::wire::replay_ordered_with_content(
                    &event,
                    &ring,
                    &nonces,
                    content.as_deref(),
                )
                .and_then(|bytes| super::wire::with_seq(&bytes, Seq(seq)))
                .map_err(|error| ReplayError::Frame(format!("seq {seq}: {error}")))?;
                chunk.push(&frame).await?;
                // Flush on the event boundary. The receiver only observes
                // whole chunks, so this is the only place where
                // `RELAY`/`STREAM_DATA`/`ORDERED` can be made to travel
                // together instead of waiting for a 64 KiB or batch edge.
                chunk.flush().await?;
                next = seq.saturating_add(1);
            }
        }
        chunk.flush().await?;
        match context
            .sequencer
            .replay_done(session_id, generation, Seq(next.saturating_sub(1)))
            .await
        {
            Ok(ReplayStep::Online) => return Ok(()),
            Ok(ReplayStep::Continue { target: new_target }) => {
                target = new_target.get();
            }
            Err(error) => return Err(ReplayError::Store(error.to_string())),
        }
    }
}

async fn replay_content(
    store: &super::store::StoreHandle,
    event: &crate::store::sqlite::EventRow,
) -> Result<Option<Vec<u8>>, ReplayError> {
    let payload = event
        .decode()
        .map_err(|error| ReplayError::Content(format!("event {} payload: {error}", event.seq)))?;
    let EventPayload::Write { chunks, size, .. } = payload else {
        return Ok(None);
    };
    if chunks.is_empty() {
        return Ok(None);
    }
    let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or(0).min(4 << 20));
    for chunk in chunks {
        // A missing chunk is not a slow read: replaying the ORDERED without
        // its bytes would give the receiver a hash mismatch. Stop here and
        // let the loud error name the event.
        let bytes = store
            .chunk_data(chunk.hash)
            .await
            .map_err(ReplayError::Store)?
            .ok_or_else(|| {
                ReplayError::Content(format!("event {} references a missing chunk", event.seq))
            })?;
        data.extend_from_slice(&bytes);
    }
    Ok(Some(data))
}

fn random_session_id() -> SessionId {
    loop {
        let id = SessionId(rand::random::<u128>());
        if id != SessionId::ZERO {
            return id;
        }
    }
}

fn random_32() -> [u8; 32] {
    rand::random()
}

fn random_12() -> [u8; 12] {
    rand::random()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn server_kick_detection_reads_only_the_plaintext_header() {
        let mut header = FrameHeader::new(MsgType::KICK, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = 30;
        let kick =
            Bytes::from(encode_frame(&FrameRef::new(&header, &Prefix::None, &[0; 30])).unwrap());
        assert!(is_kick(&kick));
        let ordered = encode_control(MsgType::ORDERED, Prefix::None, &[0; 30], Seq(1)).unwrap();
        assert!(!is_kick(&ordered));
        assert!(!is_kick(&Bytes::from_static(b"short")));
    }

    /// The replay keepalive is a `PONG` with `Seq::UNSEQUENCED`: a receiver
    /// can count it as traffic without advancing or reordering the log.
    #[test]
    fn replay_keepalive_is_an_unsequenced_control_frame() {
        let ring = PskKeyRing::derive(&[7u8; 32], &PskSalt::DEFAULT).unwrap();
        let nonces = NonceMinter::with_instance(0x0102_0304_0506_0708);
        let bytes = encode_pong(&ring, &nonces, 42).unwrap();

        let mut decoder = FrameDecoder::new(crate::protocol::Limits::default());
        decoder.push(&bytes).unwrap();
        let frame = decoder
            .next_frame_owned()
            .unwrap()
            .expect("one complete keepalive frame");
        assert_eq!(frame.header.msg_type, MsgType::PONG);
        assert_eq!(frame.header.seq, Seq::UNSEQUENCED);
        assert_eq!(frame.prefix.kind(), PrefixKind::None);

        let opened = Opener::with_session_key(&ring.session_key())
            .open(&frame.header, &frame.prefix, &frame.body)
            .unwrap();
        let pong = Pong::decode(opened.as_slice(), &crate::protocol::Limits::default()).unwrap();
        assert_eq!(pong.server_time, 42);
    }
}
