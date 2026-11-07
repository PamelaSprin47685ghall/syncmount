//! One PSK session: handshake, replay, uplink and downlink.
//!
//! ```text
//! HELLO(plain, ctrl prefix: applied_seq, epoch_seen)
//!   -> WELCOME(plain body + server proof)
//! AUTH(sealed under the handshake key)
//!   -> ACCEPT(sealed under the handshake key)
//! STEADY (enc key): STREAM_DATA* + ORDERED up, ORDERED* down
//! ```
//!
//! The downlink applies events to SQLite as they arrive. The uplink reads the
//! durable outbox and sends each row, coalescing adjacent writes. Neither task
//! touches the other's stream: the transport is split once, after `ACCEPT`.
//!
//! Replay needs no extra entry point: `HELLO`'s `CtrlPrefix` carries the local
//! watermark, the server replays from there, and the client skips any frame at
//! or below `meta.applied_seq` that a restart re-delivers.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;

use super::db::{ClientDb, DbError, OutboxOp};
use super::lifecycle::{EXIT_AUTH, EXIT_DISCONNECTED, EXIT_OK, State, WriteGate};
use super::status::{Conntrace, Counters, TraceEntry};
use super::writer::{CoalesceTuning, Coalescer, LocalOp, LocalSeq, QueuedOp, Span, WireOp};
use crate::protocol::crypto::{NonceMinter, Opener, PskKeyRing, Sealer, SessionKey};
use crate::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
use crate::protocol::handshake::{ClientHandshake, HandshakeError};
use crate::protocol::messages::{
    Error as ErrorMessage, FieldMap, Kick, OpClass, Ping, Pong, SyncEnd, WcpWriter, Welcome, fid,
};
use crate::protocol::{
    CtrlPrefix, Flags, FrameBuf, FrameDecoder, FrameEncoder, FrameHeader, FrameRef, Limits,
    MsgType, OpId, Prefix, RoutePrefix, Seq, SessionId, StreamId,
};
use crate::store::sqlite::{ChunkRef, EventKind, EventPayload};
use crate::transport::{DialOptions, Endpoint, EventsStream, HttpTransport, RpcStream, Transport};

/// How long the whole handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How often an idle uplink looks for a new outbox row.
const IDLE_POLL: Duration = Duration::from_millis(2);

/// How often the client reports its applied watermark to the server.
const PING_INTERVAL: Duration = Duration::from_secs(1);

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

#[derive(Debug)]
enum Signal {
    CaughtUp,
    Disconnected,
    Kicked(crate::protocol::KickReason),
    Fatal(String),
}

/// Run one session until it disconnects or `shutdown` resolves.
pub async fn run(
    store: Arc<ClientDb>,
    options: SessionOptions,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    mut shutdown: mpsc::Receiver<()>,
) -> SessionExit {
    if let Err(error) = store.reset_sent() {
        tracing::error!(event = "outbox_reset", error = %error, "cannot reset sent rows");
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
    let (transport, welcome, key) = match handshake {
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
    if !seed && (local_epoch != epoch as i64 || local_applied > current_seq as i64) {
        if let Err(error) = store.reset_epoch(epoch as i64) {
            tracing::error!(event = "epoch_reset", error = %error, "cannot reset the replica");
            return SessionExit {
                code: 2,
                reason: "epoch reset",
            };
        }
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
    let watermark = Arc::new(AtomicI64::new(local_applied.min(current_seq as i64)));

    let downlink_task = tokio::spawn(downlink(
        events,
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

    let mut caught_up = current_seq == 0 || local_applied >= current_seq as i64;
    if caught_up {
        gate.set(State::Steady);
    }
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
                            tracing::info!(event = "steady", applied = store.applied_seq().unwrap_or(0), "replay caught up");
                        }
                    }
                    Some(Signal::Kicked(reason)) => {
                        tracing::warn!(event = "kicked", reason = ?reason, "server ended the session");
                        exit = SessionExit::disconnected();
                        break;
                    }
                    Some(Signal::Fatal(reason)) => {
                        tracing::error!(event = "fatal", reason = %reason, "session stopped");
                        exit = SessionExit::disconnected();
                        break;
                    }
                    Some(Signal::Disconnected) | None => {
                        tracing::warn!(event = "disconnect", "session ended");
                        exit = SessionExit::disconnected();
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

    gate.set(State::Unmounting);
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

async fn handshake(
    mut transport: HttpTransport,
    ring: PskKeyRing,
    client_id: [u8; 16],
    applied: i64,
    epoch_seen: i64,
    counters: &Counters,
    conntrace: &Conntrace,
) -> Result<(HttpTransport, Welcome, SessionKey), SessionError> {
    let now_ms = unix_millis();
    let nonces = NonceMinter::with_instance(rand::random());
    let mut client = ClientHandshake::new(
        ring,
        crate::protocol::frame::ClientId::from_bytes(client_id),
        rand::random::<[u8; 32]>(),
        crate::protocol::version::ProtoVersion::CURRENT,
        crate::protocol::version::Caps::REQUIRED,
        now_ms,
    );
    let hello = client.hello().encode()?;
    let prefix = Prefix::Ctrl(CtrlPrefix::new(
        Seq(u64::try_from(applied.max(0)).unwrap_or(0)),
        u64::try_from(epoch_seen.max(0)).unwrap_or(0),
    ));
    let header = FrameHeader::new(MsgType::HELLO, Flags::CTRL, 0, Seq::UNSEQUENCED);
    send_frame(&mut transport, &header, &prefix, &hello, counters, conntrace).await?;

    let limits = Limits::default();
    let mut decoder = FrameDecoder::new(limits);
    let welcome_frame = read_frame(&mut transport, &mut decoder, counters, conntrace).await?;
    if welcome_frame.header.msg_type != MsgType::WELCOME {
        return Err(SessionError::Unexpected(welcome_frame.header.msg_type));
    }
    let welcome = Welcome::decode(&welcome_frame.body, &limits)?;
    let auth = match client.on_welcome(&welcome, &welcome_frame.body, now_ms) {
        Ok(auth) => auth,
        Err(HandshakeError::AuthFailed) => return Err(SessionError::Auth),
        Err(error) => return Err(SessionError::Handshake(error)),
    };

    let keys = client
        .handshake_keys()
        .ok_or(SessionError::Auth)?;
    let mut auth_header = FrameHeader::new(MsgType::AUTH, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = keys
        .sealer(&nonces)
        .seal(&mut auth_header, &Prefix::None, &auth.encode())?;
    send_bytes(&mut transport, &auth_header, &Prefix::None, sealed.as_bytes(), counters, conntrace)
        .await?;

    let accept_frame = read_frame(&mut transport, &mut decoder, counters, conntrace).await?;
    if accept_frame.header.msg_type != MsgType::ACCEPT {
        return Err(SessionError::Unexpected(accept_frame.header.msg_type));
    }
    let session_key = match client.open_accept(&accept_frame.header, &accept_frame.body, now_ms) {
        Ok(key) => key,
        Err(HandshakeError::AuthFailed) => return Err(SessionError::Auth),
        Err(error) => return Err(SessionError::Handshake(error)),
    };
    Ok((transport, welcome, session_key))
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
    let mut decoder = FrameDecoder::new(limits);
    let opener = Opener::with_session_key(&key);
    let mut data = super::net::DataCache::new();
    let mut caught_up = current_seq == 0;
    let nonces = NonceMinter::with_instance(rand::random());

    loop {
        let chunk = match events.recv().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                let _ = signal.send(Signal::Disconnected).await;
                return;
            }
            Err(error) => {
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
                return;
            }
        };
        if let Err(error) = decoder.push(&chunk) {
            let _ = signal.send(Signal::Fatal(error.to_string())).await;
            return;
        }
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
            match frame.header.msg_type {
                MsgType::STREAM_DATA => {
                    if let Err(error) = data.push(&frame, &opener) {
                        tracing::warn!(event = "stream_data", error = %error, "dropping a bad fragment");
                    }
                }
                MsgType::ORDERED => {
                    match apply_ordered(&store, &opener, &mut data, &frame, epoch, &counters) {
                        Ok(applied) => {
                            let seq = frame.header.seq.get() as i64;
                            if applied {
                                watermark.store(seq, Ordering::Release);
                            }
                            if !caught_up && seq >= current_seq as i64 {
                                caught_up = true;
                                gate.set(State::Steady);
                                let _ = signal.send(Signal::CaughtUp).await;
                            }
                        }
                        Err(error) => {
                            tracing::error!(event = "apply", seq = frame.header.seq.get(), error = %error, "cannot apply an event");
                            Counters::bump(&counters.materialize_errors);
                            let _ = signal
                                .send(Signal::Fatal(format!("apply: {error}")))
                                .await;
                            return;
                        }
                    }
                }
                MsgType::PING => {
                    let now = unix_seconds();
                    if let Ok(body) = (Pong { server_time: now }).encode() {
                        let mut header =
                            FrameHeader::new(MsgType::PONG, Flags::ENC, 0, Seq::UNSEQUENCED);
                        if let Ok(sealed) = Sealer::with_session_key(&key, &nonces)
                            .seal(&mut header, &Prefix::None, &body)
                        {
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
                            let _ = signal.send(Signal::Kicked(kick.reason)).await;
                            return;
                        }
                    }
                    let _ = signal.send(Signal::Fatal("unreadable KICK".to_owned())).await;
                    return;
                }
                MsgType::ERROR => {
                    if let Ok(error) = ErrorMessage::decode(&frame.body, &limits) {
                        if let Some((op_id, errno)) = decode_rejection(error.detail) {
                            if let Err(store_error) = store.reject_op(op_id, errno) {
                                tracing::warn!(event = "reject", error = %store_error, "cannot record a rejection");
                            }
                            Counters::bump(&counters.ops_rejected);
                            continue;
                        }
                        let _ = signal
                            .send(Signal::Fatal(format!("server error: {:?}", error.reason)))
                            .await;
                    } else {
                        let _ = signal.send(Signal::Fatal("unreadable ERROR".to_owned())).await;
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
                MsgType::WELCOME | MsgType::AUTH | MsgType::ACCEPT | MsgType::HELLO => {}
                other => {
                    tracing::warn!(event = "unexpected_frame", msg_type = ?other, "ignoring");
                }
            }
        }
    }
}

fn apply_ordered(
    store: &ClientDb,
    opener: &Opener<'_>,
    data: &mut super::net::DataCache,
    frame: &FrameBuf,
    epoch: u64,
    counters: &Counters,
) -> Result<bool, DbError> {
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
        None => synthesize_payload(store, class, path, path2, offset, &fields)?,
    };
    let bytes = data_session.and_then(|session| data.take(session));
    let outcome = store.apply_remote(
        frame.header.seq.get() as i64,
        epoch as i64,
        op_id,
        "ok",
        &payload,
        path,
        path2,
        bytes.as_deref(),
    )?;
    match outcome {
        super::db::ApplyOutcome::Applied => {
            Counters::bump(&counters.ops_applied);
            Ok(true)
        }
        super::db::ApplyOutcome::Duplicate => {
            Counters::bump(&counters.ops_duplicate);
            Ok(false)
        }
        super::db::ApplyOutcome::Rejected => Ok(true),
    }
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
    let mtime_ns = fields
        .u64(fid::F_MTIME_NS)
        .ok()
        .flatten()
        .map(|value| value as i64)
        .unwrap_or_else(super::db::now_ns);
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
            mtime_ns: fields.u64(fid::F_MTIME_NS).ok().flatten().map(|v| v as i64),
        },
        OpClass::RENAME => EventPayload::Rename { ino: object.ino },
        OpClass::UNLINK => EventPayload::Unlink { ino: object.ino },
        OpClass::RMDIR => EventPayload::Rmdir { ino: object.ino },
        OpClass::LINK => EventPayload::Link { ino: object.ino },
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
            return Err(DbError::Corrupt("unsupported ORDERED class without a payload"));
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

fn decode_rejection(detail: &[u8]) -> Option<([u8; 16], i32)> {
    if detail.len() < 20 {
        return None;
    }
    let mut op_id = [0u8; 16];
    op_id.copy_from_slice(&detail[..16]);
    let errno = i32::from_le_bytes([detail[16], detail[17], detail[18], detail[19]]);
    Some((op_id, errno))
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
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                if let Err(error) = send_wire(
                    &mut rpc,
                    &store,
                    &sealer,
                    &wire,
                    &[],
                    &counters,
                    &conntrace,
                )
                .await
                {
                    let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                            &mut rpc,
                            &store,
                            &sealer,
                            &wire,
                            &members,
                            &counters,
                            &conntrace,
                        )
                        .await
                        {
                            let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                                &mut rpc,
                                &store,
                                &sealer,
                                &wire,
                                &members,
                                &counters,
                                &conntrace,
                            )
                            .await
                            {
                                let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                            &mut rpc,
                            &store,
                            &sealer,
                            &wire,
                            &members,
                            &counters,
                            &conntrace,
                        )
                        .await
                        {
                            let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                        &mut rpc,
                        &store,
                        &sealer,
                        &wire,
                        &members,
                        &counters,
                        &conntrace,
                    )
                    .await
                    {
                        let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                    let _ = signal.send(Signal::Fatal(error.to_string())).await;
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
                &mut rpc,
                &store,
                &sealer,
                &wire,
                &members,
                &counters,
                &conntrace,
            )
            .await
            {
                let _ = signal.send(Signal::Fatal(error.to_string())).await;
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

    let class = if wire.off == 0 {
        OpClass::WRITE
    } else {
        OpClass::PWRITE
    };
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
    if wire.off != 0 {
        fields.push((fid::F_OFFSET, wire.off.to_le_bytes().to_vec()));
    }
    fields.push((fid::F_EXTRA, encoded));

    send_stream(rpc, sealer, session, &data, counters, conntrace).await?;
    let body = encode_fields(&fields)?;
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = sealer.seal(&mut header, &Prefix::None, &body)?;
    send_raw(rpc, &header, &Prefix::None, sealed.as_bytes(), counters, conntrace).await
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
    let (mtime_ns, uid, gid) = object.as_ref().map_or((super::db::now_ns(), 0, 0), |object| {
        (object.mtime_ns, object.uid, object.gid)
    });
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
            ..
        } => {
            if let Some(mode) = mode {
                fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
            }
            if let Some(uid) = uid {
                fields.push((fid::F_UID, uid.to_le_bytes().to_vec()));
            }
            if let Some(gid) = gid {
                fields.push((fid::F_GID, gid.to_le_bytes().to_vec()));
            }
            if let Some(mtime_ns) = mtime_ns {
                fields.push((fid::F_MTIME_NS, (*mtime_ns as u64).to_le_bytes().to_vec()));
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
    send_raw(rpc, &header, &Prefix::None, sealed.as_bytes(), counters, conntrace).await
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
        send_raw(rpc, &header, &prefix, sealed.as_bytes(), counters, conntrace).await?;
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
    store.client_id().map(|id| id.to_vec()).unwrap_or_else(|_| vec![0u8; 16])
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
    fn hello_prefix_carries_the_local_watermark_and_epoch() {
        let prefix = CtrlPrefix::new(Seq(42), 7);
        let bytes = prefix.encode();
        let decoded = CtrlPrefix::decode(&bytes).unwrap();
        assert_eq!(decoded.applied_seq, Seq(42));
        assert_eq!(decoded.epoch_seen, 7);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn a_semantic_rejection_names_the_operation_and_errno() {
        let mut detail = vec![0xab; 16];
        detail.extend_from_slice(&(-28i32).to_le_bytes());
        detail.extend_from_slice(b"no space");
        let (op_id, errno) = decode_rejection(&detail).unwrap();
        assert_eq!(op_id, [0xab; 16]);
        assert_eq!(errno, -28);
        assert!(decode_rejection(&detail[..19]).is_none());
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
}
