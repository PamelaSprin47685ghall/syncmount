//! Downlink: frame decoding, routing and the bounded ORDERED channel.
//!
//! Owner: W12 (E5). See 41 §2.8/§7.1, 44 §2.4 and 53 W12.
//!
//! The downlink has one job: turn a byte stream into frames and put each frame
//! on exactly one route. It does not decrypt `ORDERED`, `RESPONSE`, `RELAY`,
//! `ACK` or `STREAM_DATA`; those carry ciphertext and belong to the replay or
//! sync layers. It *does* decode the plaintext control frames the server may
//! author without keys (44 D3):
//!
//! | type | handling |
//! |---|---|
//! | ORDERED / LEAVE | sequenced, bounded channel |
//! | PONG | update the heartbeat handle, bounded channel |
//! | KICK | update the handle, emit, then stop (INV-14) |
//! | ERROR | emit, then stop |
//! | FLOW / SYNC_END / WELCOME | decode, bounded channel |
//! | RESPONSE / RELAY / ACK / STREAM_DATA | opaque owned frame |
//!
//! The channel is bounded on purpose. If the replay task falls behind, the
//! downlink stops reading, the HTTP body stops draining, and TCP backpressure
//! reaches the server. No unbounded queue exists in the path.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::client::replayer::{IncomingOp, Op, OpAttrs, OpBody};
use crate::client::status::{Conntrace, Counters, TraceEntry};
use crate::protocol::ProtocolError;
use crate::protocol::crypto::CryptoError;
use crate::protocol::identity::{
    self, AuthBlock, KeyDirectory, KeyEpoch, PublicKey, Signature, SignedOp,
};
use crate::protocol::messages::MessageError;
use crate::protocol::messages::fid;
use crate::protocol::{
    Flags, FrameBuf, FrameDecoder, FrameHeader, KickReason, Leave, Limits, Message, MsgType,
    OpArgs, Ordered, Prefix, Seq, SyncEndReason, TrnReason, Welcome, decode_plain, decode_sealed,
};
use crate::transport::{Transport, TransportError};

/// Default channel depth when the caller does not pick one.
pub const DEFAULT_DEPTH: usize = super::DEFAULT_DOWNLINK_DEPTH;

/// One routed downlink event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownlinkItem {
    /// A sequenced operation, still sealed.
    Ordered(FrameBuf),
    /// A server notice that releases one client's locks.
    Leave {
        /// Complete frame, for the replay sequence.
        frame: FrameBuf,
        /// Decoded notice.
        leave: Leave,
    },
    /// A sealed response to a request.
    Response(FrameBuf),
    /// A sealed relay payload.
    Relay(FrameBuf),
    /// A sealed acknowledgement.
    Ack(FrameBuf),
    /// A raw sealed stream fragment.
    StreamData(FrameBuf),
    /// A plaintext synchronization terminator.
    SyncEnd {
        /// Why synchronization ended.
        reason: SyncEndReason,
        /// Diagnostic bytes.
        detail: Option<Vec<u8>>,
    },
    /// A server-authored welcome (normally consumed by the handshake).
    Welcome(Welcome),
    /// Additional flow-control credit.
    Flow {
        /// Credit in bytes.
        grant_bytes: u32,
    },
    /// A heartbeat answer. `current_seq` comes from the frame header.
    Pong {
        /// Server clock.
        server_time: u64,
        /// Server watermark at the time of the answer.
        current_seq: Seq,
    },
    /// The server ordered this client off the cluster.
    Kick(KickReason),
    /// The server rejected one request or the session.
    Error {
        /// Transport reason.
        reason: TrnReason,
        /// Diagnostic bytes.
        detail: Vec<u8>,
    },
}

/// Why the downlink loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownlinkOutcome {
    /// Clean end of the events stream.
    Eof,
    /// A KICK was received and delivered.
    Kicked(KickReason),
    /// An ERROR was received and delivered.
    ServerError {
        /// Transport reason.
        reason: TrnReason,
    },
    /// The bounded channel's receiver was dropped.
    ReceiverGone,
}

/// Downlink failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DownlinkError {
    /// The byte transport failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// A frame boundary or flag was invalid.
    #[error("frame: {0}")]
    Protocol(#[from] ProtocolError),
    /// A plaintext body was invalid.
    #[error("message: {0}")]
    Message(#[from] MessageError),
    /// AEAD authentication failed while opening an `ORDERED` body.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// A message type that only travels client-to-server appeared downlink.
    #[error("message type {0:?} is not legal on the downlink")]
    WrongDirection(MsgType),
    /// A sequenced type arrived with `seq == 0`.
    #[error("message type {0:?} must be sequenced")]
    Unsequenced(MsgType),
    /// An `ORDERED` body had no `op_id` outside `KEY_ANNOUNCE`.
    #[error("ORDERED body has no op_id")]
    MissingOpId,
    /// A `KEY_ANNOUNCE` must be consumed by the identity layer, not the
    /// filesystem replay engine.
    #[error("KEY_ANNOUNCE belongs to the identity layer")]
    KeyAnnounce,
    /// An operation class this build cannot turn into a replay operation.
    #[error("unsupported op class {0}")]
    UnsupportedOpClass(u8),
    /// The author's signature did not verify against the key directory.
    ///
    /// The frame is untrusted: it must be dropped, never applied, and
    /// `applied_seq` must not move past it (50 §5.1).
    #[error("untrusted operation: {0}")]
    Untrusted(identity::SignatureError),
    /// The carried `F_PAYLOAD_HASH` differs from the canonical op body.
    #[error("ORDERED payload hash does not match the canonical body")]
    PayloadHashMismatch,
}

/// Heartbeat/health view shared with the connection driver.
#[derive(Clone, Debug)]
pub struct DownlinkHandle {
    inner: Arc<Mutex<Health>>,
}

#[derive(Debug)]
struct Health {
    last_pong: Option<Instant>,
    server_seq: Seq,
    kick: Option<KickReason>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            last_pong: None,
            server_seq: Seq::UNSEQUENCED,
            kick: None,
        }
    }
}

impl DownlinkHandle {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Health::default())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Health> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// When the last PONG arrived.
    pub fn last_pong(&self) -> Option<Instant> {
        self.lock().last_pong
    }

    /// Age of the last PONG, or `None` if none arrived.
    pub fn last_pong_age(&self, now: Instant) -> Option<Duration> {
        self.last_pong().map(|at| now.saturating_duration_since(at))
    }

    /// Server watermark from the last PONG.
    pub fn server_seq(&self) -> Seq {
        self.lock().server_seq
    }

    /// KICK reason, once one was seen.
    pub fn kick(&self) -> Option<KickReason> {
        self.lock().kick
    }

    fn note_pong(&self, at: Instant, current_seq: Seq) {
        let mut health = self.lock();
        health.last_pong = Some(at);
        health.server_seq = current_seq;
    }

    fn note_kick(&self, reason: KickReason) {
        self.lock().kick = Some(reason);
    }
}

/// A downlink reader over any byte transport.
pub struct Downlink<T> {
    events: T,
    decoder: FrameDecoder,
    /// Frames read during the JOIN handshake, before this loop started.
    ///
    /// They precede everything still in `decoder`, so they are routed first.
    backlog: std::collections::VecDeque<FrameBuf>,
    tx: mpsc::Sender<DownlinkItem>,
    handle: DownlinkHandle,
    limits: Limits,
    counters: Option<Arc<Counters>>,
    conntrace: Option<Arc<Conntrace>>,
}

impl<T> fmt::Debug for Downlink<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Downlink")
            .field("buffered", &self.decoder.buffered())
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl<T: Transport + Send> Downlink<T> {
    /// Build a downlink with a fresh decoder.
    pub fn new(events: T, depth: usize) -> (Self, mpsc::Receiver<DownlinkItem>, DownlinkHandle) {
        Self::with_decoder(events, FrameDecoder::new(Limits::default()), depth)
    }

    /// Build a downlink that continues from an existing decoder.
    ///
    /// The handshake may have buffered bytes after `WELCOME`; handing the
    /// decoder over preserves them instead of dropping a frame at the split.
    pub fn with_decoder(
        events: T,
        decoder: FrameDecoder,
        depth: usize,
    ) -> (Self, mpsc::Receiver<DownlinkItem>, DownlinkHandle) {
        let limits = decoder.limits();
        let (tx, rx) = mpsc::channel(depth.max(1));
        let handle = DownlinkHandle::new();
        (
            Self {
                events,
                decoder,
                backlog: std::collections::VecDeque::new(),
                tx,
                handle: handle.clone(),
                limits,
                counters: None,
                conntrace: None,
            },
            rx,
            handle,
        )
    }

    /// Route frames that were read before this downlink started.
    ///
    /// The JOIN handshake reads frames to find its verdict; anything else it
    /// read belongs to the stream and must be delivered before new bytes.
    pub fn with_backlog(mut self, frames: Vec<FrameBuf>) -> Self {
        self.backlog = frames.into();
        self
    }

    /// Attach status observers. Failure to record never affects routing.
    pub fn with_observers(mut self, counters: Arc<Counters>, conntrace: Arc<Conntrace>) -> Self {
        self.counters = Some(counters);
        self.conntrace = Some(conntrace);
        self
    }

    /// Read until EOF, KICK, ERROR or a dropped receiver.
    pub async fn run(mut self) -> Result<DownlinkOutcome, DownlinkError> {
        loop {
            let next = match self.backlog.pop_front() {
                Some(frame) => Some(frame),
                None => self.decoder.next_frame_owned()?,
            };
            if let Some(frame) = next {
                if let Some(outcome) = self.route(frame).await? {
                    return Ok(outcome);
                }
                continue;
            }
            match self.events.recv().await? {
                Some(chunk) => self.decoder.push(&chunk)?,
                None => {
                    self.decoder.finish()?;
                    return Ok(DownlinkOutcome::Eof);
                }
            }
        }
    }

    async fn route(&mut self, frame: FrameBuf) -> Result<Option<DownlinkOutcome>, DownlinkError> {
        let msg_type = frame.header.msg_type;
        if let Some(counters) = &self.counters {
            Counters::bump(&counters.frames_in);
        }
        if let Some(conntrace) = &self.conntrace {
            conntrace.record(TraceEntry::new(
                super::wall_clock_us(),
                "in",
                msg_type.name(),
                u32::try_from(frame.body.len()).unwrap_or(u32::MAX),
                frame.header.seq,
            ));
        }
        match msg_type {
            MsgType::ORDERED => {
                if !frame.header.seq.is_sequenced() {
                    return Err(DownlinkError::Unsequenced(msg_type));
                }
                if !self.emit(DownlinkItem::Ordered(frame)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::LEAVE => {
                if !frame.header.seq.is_sequenced() {
                    return Err(DownlinkError::Unsequenced(msg_type));
                }
                let Message::Leave(leave) = decode_plain(msg_type, &frame.body, &self.limits)?
                else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                if !self.emit(DownlinkItem::Leave { frame, leave }).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::PONG => {
                let Message::Pong(pong) = decode_plain(msg_type, &frame.body, &self.limits)? else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                self.handle.note_pong(Instant::now(), frame.header.seq);
                if !self
                    .emit(DownlinkItem::Pong {
                        server_time: pong.server_time,
                        current_seq: frame.header.seq,
                    })
                    .await?
                {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::KICK => {
                let Message::Kick(kick) = decode_plain(msg_type, &frame.body, &self.limits)? else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                self.handle.note_kick(kick.reason);
                if !self.emit(DownlinkItem::Kick(kick.reason)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
                return Ok(Some(DownlinkOutcome::Kicked(kick.reason)));
            }
            MsgType::ERROR => {
                let Message::Error(error) = decode_plain(msg_type, &frame.body, &self.limits)?
                else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                let reason = error.reason;
                let detail = error.detail.to_vec();
                if !self.emit(DownlinkItem::Error { reason, detail }).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
                // Relay setup is best-effort: a single-client cluster has no
                // peer, and a stale relay session is expected after a write.
                // Those two answers must not tear down an otherwise healthy
                // session. Every other ERROR remains terminal.
                if matches!(reason, TrnReason::NoPeer | TrnReason::SessionUnknown) {
                    return Ok(None);
                }
                return Ok(Some(DownlinkOutcome::ServerError { reason }));
            }
            MsgType::FLOW => {
                let Message::Flow(flow) = decode_plain(msg_type, &frame.body, &self.limits)? else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                if !self
                    .emit(DownlinkItem::Flow {
                        grant_bytes: flow.grant_bytes,
                    })
                    .await?
                {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::SYNC_END => {
                let Message::SyncEnd(end) = decode_plain(msg_type, &frame.body, &self.limits)?
                else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                if !self
                    .emit(DownlinkItem::SyncEnd {
                        reason: end.reason,
                        detail: end.detail.map(<[u8]>::to_vec),
                    })
                    .await?
                {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::WELCOME => {
                let Message::Welcome(welcome) = decode_plain(msg_type, &frame.body, &self.limits)?
                else {
                    return Err(DownlinkError::WrongDirection(msg_type));
                };
                if !self.emit(DownlinkItem::Welcome(welcome)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::RESPONSE => {
                if !self.emit(DownlinkItem::Response(frame)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::RELAY => {
                if !self.emit(DownlinkItem::Relay(frame)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::ACK => {
                if !self.emit(DownlinkItem::Ack(frame)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::STREAM_DATA => {
                if !self.emit(DownlinkItem::StreamData(frame)).await? {
                    return Ok(Some(DownlinkOutcome::ReceiverGone));
                }
            }
            MsgType::HELLO | MsgType::PING => return Err(DownlinkError::WrongDirection(msg_type)),
            _ => return Err(DownlinkError::WrongDirection(msg_type)),
        }
        Ok(None)
    }

    async fn emit(&self, item: DownlinkItem) -> Result<bool, DownlinkError> {
        Ok(self.tx.send(item).await.is_ok())
    }
}

/// Open and convert one sealed `ORDERED` frame into a replay operation.
///
/// `open` authenticates the AEAD envelope and returns plaintext WCP bytes.
/// The caller supplies the production opener (`Opener<KeyRing>`); tests can
/// supply the identity to exercise the routing/conversion path without keys.
/// The sequence and epoch are taken from the frame header and the accepted
/// `WELCOME`, because `ORDERED` deliberately carries neither.
///
/// This function authenticates the envelope only. The author's signature is
/// checked by [`decode_ordered_verified`], which every production caller must
/// use: the AEAD proves cluster-key possession, not authorship.
pub fn decode_ordered<F>(
    frame: &FrameBuf,
    epoch: u64,
    limits: &Limits,
    open: F,
) -> Result<IncomingOp, DownlinkError>
where
    F: FnOnce(&FrameHeader, &Prefix, &[u8]) -> Result<Vec<u8>, CryptoError>,
{
    decode_ordered_inner(frame, epoch, limits, open, None)
}

/// Open, authenticate and verify one sealed `ORDERED` frame.
///
/// After the envelope and the WCP body are valid, the author's Ed25519
/// signature is checked against `keys` (50 §5.1). The hash signed is the one
/// recomputed from the canonical op body; the value carried in
/// `F_PAYLOAD_HASH` is compared but never trusted (44 §4.7).
///
/// # Errors
///
/// [`DownlinkError::Untrusted`] when the key is unknown or the signature does
/// not verify, [`DownlinkError::PayloadHashMismatch`] when the carried hash
/// and the body disagree, and the errors of [`decode_ordered`].
pub fn decode_ordered_verified<F>(
    frame: &FrameBuf,
    epoch: u64,
    limits: &Limits,
    open: F,
    keys: &KeyDirectory,
) -> Result<IncomingOp, DownlinkError>
where
    F: FnOnce(&FrameHeader, &Prefix, &[u8]) -> Result<Vec<u8>, CryptoError>,
{
    decode_ordered_inner(frame, epoch, limits, open, Some(keys))
}

fn decode_ordered_inner<F>(
    frame: &FrameBuf,
    epoch: u64,
    limits: &Limits,
    open: F,
    keys: Option<&KeyDirectory>,
) -> Result<IncomingOp, DownlinkError>
where
    F: FnOnce(&FrameHeader, &Prefix, &[u8]) -> Result<Vec<u8>, CryptoError>,
{
    if frame.header.msg_type != MsgType::ORDERED {
        return Err(DownlinkError::WrongDirection(frame.header.msg_type));
    }
    if !frame.header.seq.is_sequenced() {
        return Err(DownlinkError::Unsequenced(MsgType::ORDERED));
    }
    let plaintext = open(&frame.header, &frame.prefix, &frame.body)?;
    let Message::Ordered(ordered) = decode_sealed(MsgType::ORDERED, &plaintext, limits)? else {
        return Err(DownlinkError::WrongDirection(MsgType::ORDERED));
    };
    if let Some(keys) = keys {
        verify_ordered(&ordered, frame.header.flags, keys)?;
    }
    let op = ordered_to_op(&ordered)?;
    Ok(IncomingOp::new(frame.header.seq, epoch, op))
}

/// Verify the author signature of a decoded `ORDERED` body.
///
/// `KEY_ANNOUNCE` carries no `F_SIG`; it is consumed by the identity layer and
/// never reaches this function (see [`ordered_to_op`]).
fn verify_ordered(
    ordered: &Ordered<'_>,
    flags: Flags,
    keys: &KeyDirectory,
) -> Result<(), DownlinkError> {
    let op_id = ordered.op_id.ok_or(DownlinkError::MissingOpId)?;
    let carried = ordered
        .payload_hash
        .ok_or(DownlinkError::PayloadHashMismatch)?;
    let sig = ordered
        .sig
        .ok_or(DownlinkError::Untrusted(identity::SignatureError::Invalid))?;

    let canonical = ordered
        .canonical_bytes_excluding(&[
            fid::F_SIG,
            fid::F_PAYLOAD_HASH,
            fid::F_SENDER_PUB,
            fid::F_KEY_MAC,
        ])
        .map_err(MessageError::Wcp)?;
    let hash = identity::payload_hash(&canonical);
    if hash != carried {
        return Err(DownlinkError::PayloadHashMismatch);
    }

    let signature = Signature::from_bytes(sig);
    let op = SignedOp {
        client: ordered.client_id,
        epoch: KeyEpoch(ordered.key_epoch),
        op_id,
        op_class: ordered.op_class,
        msg_type: MsgType::ORDERED,
        flags,
        payload_hash: &hash,
        signature: &signature,
    };
    match ordered.sender_pub {
        // An inline key is bound to the claimed `client_id` by
        // `verify_op_with_auth`; it needs no directory entry.
        Some(public) => {
            let public = PublicKey::from_bytes(public);
            let block = AuthBlock::with_inline_public(identity::skid(&public), signature, public);
            keys.verify_op_with_auth(&block, &op)
                .map_err(DownlinkError::Untrusted)
        }
        None => keys.verify_op(&op).map_err(DownlinkError::Untrusted),
    }
}

fn ordered_to_op(ordered: &Ordered<'_>) -> Result<Op, DownlinkError> {
    if ordered.op_class.is_key_announce() {
        return Err(DownlinkError::KeyAnnounce);
    }
    let op_id = ordered.op_id.ok_or(DownlinkError::MissingOpId)?;
    let attrs = ordered.attrs.map(|attrs| OpAttrs {
        mode: None,
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: attrs.mtime_ns,
    });
    let body = match ordered.args {
        OpArgs::Write(data) => OpBody::Write(data),
        OpArgs::Pwrite { offset, data } => OpBody::Pwrite { offset, data },
        OpArgs::Truncate { length } => OpBody::Truncate { length },
        OpArgs::Setattr { mode } => OpBody::Setattr { mode },
        OpArgs::Rename { path2 } => OpBody::Rename {
            path2: path2.as_str().to_owned(),
        },
        OpArgs::Unlink | OpArgs::Rmdir | OpArgs::Leave => OpBody::None,
        OpArgs::Mkdir { mode } => OpBody::Mkdir { mode },
        OpArgs::Link { target } => OpBody::Link {
            target: target.as_str().to_owned(),
        },
        OpArgs::Symlink { target } => OpBody::Symlink {
            target: target.to_owned(),
        },
        OpArgs::CreateExcl { mode, flags } => OpBody::CreateExcl { mode, flags },
        OpArgs::Flock { lock_type, action } => OpBody::Lock {
            lock_type,
            action,
            start: 0,
            len: 0,
            flock: true,
        },
        OpArgs::FcntlLock {
            lock_type,
            action,
            start,
            len,
        } => OpBody::Lock {
            lock_type,
            action,
            start,
            len,
            flock: false,
        },
        OpArgs::SyncCtrl => OpBody::SyncCtrl,
        OpArgs::KeyAnnounce { .. } => OpBody::None,
    };
    Ok(Op {
        op_id,
        client_id: ordered.client_id,
        class: ordered.op_class,
        path: ordered.path_str().map(str::to_owned),
        attrs,
        body,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::VecDeque;

    use super::*;
    use crate::protocol::{
        BodyEncoding, ClientId, DataRef, Flags, FrameEncoder, FrameRef, Kick, OpClass, OpId, Pong,
        WcpWriter, identity::Identity, identity::MemoryIdentity, messages::FieldMap, messages::fid,
    };
    use crate::transport::{StreamKind, Transport};

    struct Scripted {
        chunks: VecDeque<Result<Option<bytes::Bytes>, TransportError>>,
    }

    impl Scripted {
        fn new(chunks: Vec<bytes::Bytes>) -> Self {
            Self {
                chunks: chunks.into_iter().map(|chunk| Ok(Some(chunk))).collect(),
            }
        }
    }

    impl Transport for Scripted {
        fn send(
            &mut self,
            _chunk: bytes::Bytes,
        ) -> crate::transport::BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Err(TransportError::WrongDirection(StreamKind::Events, "send")) })
        }

        fn recv(
            &mut self,
        ) -> crate::transport::BoxFut<'_, Result<Option<bytes::Bytes>, TransportError>> {
            Box::pin(async move { self.chunks.pop_front().unwrap_or(Ok(None)) })
        }

        fn close(&mut self) -> crate::transport::BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn frame(msg_type: MsgType, flags: Flags, seq: Seq, body: Vec<u8>) -> FrameBuf {
        let mut header = FrameHeader::new(msg_type, flags, 0, seq);
        header.len = body.len() as u32;
        FrameBuf::new(header, Prefix::None, body)
    }

    fn sealed(msg_type: MsgType, seq: Seq, body: Vec<u8>) -> FrameBuf {
        frame(msg_type, Flags::EMPTY.with(Flags::ENC), seq, body)
    }

    fn routed(msg_type: MsgType, seq: Seq, body: Vec<u8>, sealed: bool) -> FrameBuf {
        let mut flags = Flags::EMPTY.with(Flags::ROUTED);
        if sealed {
            flags = flags.with(Flags::ENC);
        }
        let prefix = Prefix::Route(crate::protocol::RoutePrefix::new(
            crate::protocol::SessionId::ZERO,
            crate::protocol::StreamId::CTRL,
            0,
            0,
        ));
        let mut header = FrameHeader::new(msg_type, flags, 0, seq);
        header.len = (prefix.encoded_len() + body.len()) as u32;
        FrameBuf::new(header, prefix, body)
    }

    fn bytes_of(frame: &FrameBuf) -> bytes::Bytes {
        bytes::Bytes::from(
            crate::protocol::encode_frame(&FrameRef::new(
                &frame.header,
                &frame.prefix,
                &frame.body,
            ))
            .expect("encode frame"),
        )
    }

    fn pong(seq: u64, server_time: u64) -> FrameBuf {
        let body = Pong { server_time }.encode().expect("pong");
        frame(MsgType::PONG, Flags::EMPTY, Seq(seq), body)
    }

    fn kick(reason: KickReason) -> FrameBuf {
        let body = Kick { reason }.encode().expect("kick");
        frame(MsgType::KICK, Flags::EMPTY, Seq(1), body)
    }

    fn server_error(reason: TrnReason) -> FrameBuf {
        let body = crate::protocol::ErrorMessage {
            reason,
            detail: b"stop",
            session_id: None,
        }
        .encode()
        .expect("error");
        frame(MsgType::ERROR, Flags::EMPTY, Seq::UNSEQUENCED, body)
    }

    /// 51 C2 / 41 §7.1: PONG updates the heartbeat handle and reaches the
    /// consumer; EOF is a clean outcome.
    #[tokio::test]
    async fn u_downlink_pong_and_eof() {
        let (downlink, mut rx, handle) =
            Downlink::new(Scripted::new(vec![bytes_of(&pong(7, 99))]), 4);
        let task = tokio::spawn(downlink.run());

        let item = rx.recv().await.expect("pong item");
        assert_eq!(
            item,
            DownlinkItem::Pong {
                server_time: 99,
                current_seq: Seq(7),
            }
        );
        assert_eq!(handle.server_seq(), Seq(7));
        assert!(handle.last_pong().is_some());
        assert!(handle.last_pong_age(Instant::now()).is_some());

        assert_eq!(
            task.await.expect("task").expect("outcome"),
            DownlinkOutcome::Eof
        );
    }

    /// 45 INV-14: KICK is delivered and stops the loop with its reason.
    #[tokio::test]
    async fn u_downlink_kick_stops() {
        let (downlink, mut rx, handle) = Downlink::new(
            Scripted::new(vec![bytes_of(&kick(KickReason::HeartbeatTimeout))]),
            4,
        );
        let outcome = downlink.run().await.expect("run");
        assert_eq!(
            outcome,
            DownlinkOutcome::Kicked(KickReason::HeartbeatTimeout)
        );
        assert_eq!(handle.kick(), Some(KickReason::HeartbeatTimeout));
        assert_eq!(
            rx.recv().await.expect("kick item"),
            DownlinkItem::Kick(KickReason::HeartbeatTimeout)
        );
    }

    /// ERROR is a terminal server decision, delivered before the loop ends.
    #[tokio::test]
    async fn u_downlink_error_stops() {
        let (downlink, mut rx, _) = Downlink::new(
            Scripted::new(vec![bytes_of(&server_error(TrnReason::Protocol))]),
            4,
        );
        let outcome = downlink.run().await.expect("run");
        assert_eq!(
            outcome,
            DownlinkOutcome::ServerError {
                reason: TrnReason::Protocol
            }
        );
        assert_eq!(
            rx.recv().await.expect("error item"),
            DownlinkItem::Error {
                reason: TrnReason::Protocol,
                detail: b"stop".to_vec(),
            }
        );
    }

    /// A single-client cluster answers relay setup with `TRN_NO_PEER`; that
    /// hint must not tear down an otherwise healthy session.
    #[tokio::test]
    async fn u_downlink_no_peer_is_non_fatal() {
        let (downlink, mut rx, _) = Downlink::new(
            Scripted::new(vec![bytes_of(&server_error(TrnReason::NoPeer))]),
            4,
        );
        let outcome = downlink.run().await.expect("run");
        assert_eq!(outcome, DownlinkOutcome::Eof);
        assert!(matches!(
            rx.recv().await.expect("error item"),
            DownlinkItem::Error {
                reason: TrnReason::NoPeer,
                ..
            }
        ));
    }

    /// 41 §7.1: the ORDERED queue is bounded. A second frame cannot pass
    /// until the first is consumed.
    #[tokio::test]
    async fn u_downlink_ordered_channel_is_bounded() {
        let first = sealed(MsgType::ORDERED, Seq(5), vec![0x5a; 40]);
        let second = sealed(MsgType::ORDERED, Seq(6), vec![0x5b; 40]);
        let chunk =
            bytes::Bytes::from([bytes_of(&first).as_ref(), bytes_of(&second).as_ref()].concat());
        let (downlink, mut rx, _) = Downlink::new(Scripted::new(vec![chunk]), 1);
        let task = tokio::spawn(downlink.run());

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "the second send must wait for capacity"
        );

        let item = rx.recv().await.expect("first");
        match item {
            DownlinkItem::Ordered(frame) => assert_eq!(frame.header.seq, Seq(5)),
            other => panic!("unexpected first item: {other:?}"),
        }

        let item = rx.recv().await.expect("second");
        match item {
            DownlinkItem::Ordered(frame) => assert_eq!(frame.header.seq, Seq(6)),
            other => panic!("unexpected second item: {other:?}"),
        }
        assert_eq!(
            task.await.expect("task").expect("outcome"),
            DownlinkOutcome::Eof
        );
    }

    fn ordered_body(class: OpClass, path: &str, mode: u32) -> Vec<u8> {
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &[0x11; 16]);
        writer.u32(fid::F_KEY_EPOCH, 1);
        writer.bytes(fid::F_OP_ID, &[0x22; 16]);
        writer.u8(fid::F_OP_CLASS, class.get());
        writer.str(fid::F_PATH, path);
        writer.u64(fid::F_MTIME_NS, 123);
        writer.u32(fid::F_UID, 1000);
        writer.u32(fid::F_GID, 1000);
        if class == OpClass::MKDIR {
            writer.u32(fid::F_MODE, mode);
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
        writer.bytes(fid::F_SIG, &[0x44; 64]);
        writer.finish().expect("ordered body")
    }

    /// 41 §2.8 / W12: an ORDERED body becomes an owned replay operation at
    /// the explicit decryption seam.
    #[test]
    fn u_downlink_decode_ordered() {
        let body = ordered_body(OpClass::MKDIR, "/d", 0o755);
        let frame = sealed(MsgType::ORDERED, Seq(5), body);
        let incoming = decode_ordered(&frame, 9, &Limits::default(), |_, _, plain| {
            Ok(plain.to_vec())
        })
        .expect("decode ordered");

        assert_eq!(incoming.seq, Seq(5));
        assert_eq!(incoming.epoch, 9);
        assert_eq!(incoming.op.op_id, OpId::from_bytes([0x22; 16]));
        assert_eq!(incoming.op.client_id, ClientId::from_bytes([0x11; 16]));
        assert_eq!(incoming.op.class, OpClass::MKDIR);
        assert_eq!(incoming.op.path.as_deref(), Some("/d"));
        assert_eq!(incoming.op.body, OpBody::Mkdir { mode: 0o755 });
        let attrs = incoming.op.attrs.expect("attrs");
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.mtime_ns, 123);
    }

    /// 44 INV-08: a failed AEAD open never reaches the replay engine.
    #[test]
    fn u_downlink_decode_ordered_rejects_bad_tag() {
        let frame = sealed(
            MsgType::ORDERED,
            Seq(5),
            ordered_body(OpClass::MKDIR, "/d", 0o755),
        );
        let error = decode_ordered(&frame, 9, &Limits::default(), |_, _, _| {
            Err(CryptoError::Aead)
        })
        .expect_err("bad tag");
        assert!(matches!(error, DownlinkError::Crypto(CryptoError::Aead)));
    }

    // -----------------------------------------------------------------------
    // W22: ORDERED signature verification
    // -----------------------------------------------------------------------

    fn cluster() -> crate::protocol::crypto::ClusterId {
        crate::protocol::crypto::ClusterId::from_bytes([0x11; 16])
    }

    fn signer() -> MemoryIdentity {
        MemoryIdentity::from_seed(cluster(), KeyEpoch::INITIAL, [0x41; 32])
    }

    /// A body signed exactly as the uplink signs one, with the signed fields
    /// under the caller's control.
    fn signed_body(
        identity: &MemoryIdentity,
        op_id: [u8; 16],
        carried_hash: Option<[u8; 32]>,
        signature: Option<[u8; 64]>,
    ) -> Vec<u8> {
        let op_id = OpId::from_bytes(op_id);
        let fields = vec![
            (fid::F_CLIENT_ID, identity.client_id().as_bytes().to_vec()),
            (
                fid::F_KEY_EPOCH,
                identity.key_epoch().get().to_le_bytes().to_vec(),
            ),
            (fid::F_OP_ID, op_id.as_bytes().to_vec()),
            (fid::F_OP_CLASS, vec![OpClass::MKDIR.get()]),
            (fid::F_PATH, b"/d".to_vec()),
            (fid::F_MTIME_NS, 123u64.to_le_bytes().to_vec()),
            (fid::F_UID, 1000u32.to_le_bytes().to_vec()),
            (fid::F_GID, 1000u32.to_le_bytes().to_vec()),
            (fid::F_MODE, 0o755u32.to_le_bytes().to_vec()),
        ];

        let mut unsigned = WcpWriter::new();
        for (field, value) in &fields {
            unsigned.bytes(*field, value);
        }
        let unsigned = unsigned.finish().expect("unsigned body");
        let map = FieldMap::parse(&unsigned, &Limits::default()).expect("field map");
        let canonical = map
            .canonical_bytes_excluding(&[
                fid::F_SIG,
                fid::F_PAYLOAD_HASH,
                fid::F_SENDER_PUB,
                fid::F_KEY_MAC,
            ])
            .expect("canonical");
        let hash = crate::protocol::identity::payload_hash(&canonical);
        let signature = signature.unwrap_or_else(|| {
            identity
                .sign_op(op_id, OpClass::MKDIR, MsgType::ORDERED, Flags::ENC, &hash)
                .to_bytes()
        });

        let mut writer = WcpWriter::new();
        for (field, value) in &fields {
            writer.bytes(*field, value);
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &carried_hash.unwrap_or(hash));
        writer.bytes(fid::F_SIG, &signature);
        writer.finish().expect("signed body")
    }

    fn directory_with(identity: &MemoryIdentity) -> KeyDirectory {
        let mut keys = KeyDirectory::new(cluster());
        let announce = crate::protocol::identity::KeyAnnounce::sign(
            identity,
            &cluster(),
            KeyEpoch::INITIAL,
            None,
        );
        keys.trust(&announce).expect("trust own key");
        keys
    }

    /// 50 §5.1: a correctly signed ORDERED verifies against the directory and
    /// still converts into the replay operation.
    #[test]
    fn u_downlink_verify_ordered_accepts_signed() {
        let identity = signer();
        let keys = directory_with(&identity);
        let frame = sealed(
            MsgType::ORDERED,
            Seq(5),
            signed_body(&identity, [0x22; 16], None, None),
        );
        let incoming = decode_ordered_verified(
            &frame,
            9,
            &Limits::default(),
            |_, _, plain| Ok(plain.to_vec()),
            &keys,
        )
        .expect("verified ordered");
        assert_eq!(incoming.seq, Seq(5));
        assert_eq!(incoming.op.client_id, identity.client_id());
        assert_eq!(incoming.op.class, OpClass::MKDIR);
        assert_eq!(incoming.op.path.as_deref(), Some("/d"));
    }

    /// A signature that does not verify must stop the frame here: it is
    /// dropped, never applied, and `applied_seq` cannot advance past it.
    #[test]
    fn u_downlink_verify_ordered_rejects_tampered_signature() {
        let identity = signer();
        let keys = directory_with(&identity);
        let body = signed_body(&identity, [0x22; 16], None, Some([0x44; 64]));
        let frame = sealed(MsgType::ORDERED, Seq(5), body.clone());
        let error = decode_ordered_verified(
            &frame,
            9,
            &Limits::default(),
            |_, _, plain| Ok(plain.to_vec()),
            &keys,
        )
        .expect_err("bad signature");
        assert!(matches!(
            error,
            DownlinkError::Untrusted(identity::SignatureError::Invalid)
        ));

        // The same bytes pass the unverified seam: the gate is the signature
        // check, not the decoder.
        assert!(
            decode_ordered(&frame, 9, &Limits::default(), |_, _, plain| Ok(
                plain.to_vec()
            ))
            .is_ok()
        );
    }

    /// A frame whose author has no key in the directory is untrusted, not
    /// accepted on the strength of the AEAD alone.
    #[test]
    fn u_downlink_verify_ordered_rejects_unknown_author() {
        let identity = signer();
        let keys = KeyDirectory::new(cluster());
        let frame = sealed(
            MsgType::ORDERED,
            Seq(5),
            signed_body(&identity, [0x22; 16], None, None),
        );
        let error = decode_ordered_verified(
            &frame,
            9,
            &Limits::default(),
            |_, _, plain| Ok(plain.to_vec()),
            &keys,
        )
        .expect_err("unknown key");
        assert!(matches!(
            error,
            DownlinkError::Untrusted(identity::SignatureError::UnknownKey { .. })
        ));
    }

    /// The carried hash is compared with the canonical body; a mismatch is a
    /// different failure from a bad signature.
    #[test]
    fn u_downlink_verify_ordered_rejects_payload_hash_mismatch() {
        let identity = signer();
        let keys = directory_with(&identity);
        let frame = sealed(
            MsgType::ORDERED,
            Seq(5),
            signed_body(&identity, [0x22; 16], Some([0x99; 32]), None),
        );
        let error = decode_ordered_verified(
            &frame,
            9,
            &Limits::default(),
            |_, _, plain| Ok(plain.to_vec()),
            &keys,
        )
        .expect_err("hash mismatch");
        assert!(matches!(error, DownlinkError::PayloadHashMismatch));
    }

    /// The canonical hash of a body for `op_id`, independent of the signature.
    fn body_hash(identity: &MemoryIdentity, op_id: [u8; 16]) -> [u8; 32] {
        let body = signed_body(identity, op_id, None, Some([0u8; 64]));
        let map = FieldMap::parse(&body, &Limits::default()).expect("field map");
        crate::protocol::identity::payload_hash(
            &map.canonical_bytes_excluding(&[
                fid::F_SIG,
                fid::F_PAYLOAD_HASH,
                fid::F_SENDER_PUB,
                fid::F_KEY_MAC,
            ])
            .expect("canonical"),
        )
    }

    /// Replaying another author's op under a different `op_id` fails: the id
    /// is inside the signed message.
    #[test]
    fn u_downlink_verify_ordered_binds_op_id() {
        let identity = signer();
        let keys = directory_with(&identity);
        // Signed for op 0x22 but carried as 0x23.
        let signature = identity
            .sign_op(
                OpId::from_bytes([0x22; 16]),
                OpClass::MKDIR,
                MsgType::ORDERED,
                Flags::ENC,
                &body_hash(&identity, [0x23; 16]),
            )
            .to_bytes();
        let frame = sealed(
            MsgType::ORDERED,
            Seq(5),
            signed_body(&identity, [0x23; 16], None, Some(signature)),
        );
        let error = decode_ordered_verified(
            &frame,
            9,
            &Limits::default(),
            |_, _, plain| Ok(plain.to_vec()),
            &keys,
        )
        .expect_err("op id is bound");
        assert!(matches!(
            error,
            DownlinkError::Untrusted(identity::SignatureError::Invalid)
        ));
    }

    /// Plaintext control frames and opaque sealed frames each get exactly one
    /// route; a mixed chunk preserves their order.
    #[tokio::test]
    async fn u_downlink_routes_control_and_raw_frames() {
        let leave_body = Leave {
            client_id: ClientId::from_bytes([0x77; 16]),
            reason: 0,
            last_signed_seq: 7,
        }
        .encode()
        .expect("leave");
        let leave = frame(MsgType::LEAVE, Flags::EMPTY, Seq(9), leave_body);

        let flow_body = crate::protocol::Flow { grant_bytes: 4096 }
            .encode()
            .expect("flow");
        let flow = routed(MsgType::FLOW, Seq::UNSEQUENCED, flow_body, false);

        let sync_body = crate::protocol::SyncEnd {
            reason: SyncEndReason::Done,
            detail: Some(b"ok"),
        }
        .encode()
        .expect("sync end");
        let sync_end = routed(MsgType::SYNC_END, Seq::UNSEQUENCED, sync_body, false);

        let stream = routed(MsgType::STREAM_DATA, Seq(10), vec![0x99; 40], true);

        let chunk = bytes::Bytes::from(
            [
                bytes_of(&leave).as_ref(),
                bytes_of(&flow).as_ref(),
                bytes_of(&sync_end).as_ref(),
                bytes_of(&stream).as_ref(),
            ]
            .concat(),
        );
        let (downlink, mut rx, _) = Downlink::new(Scripted::new(vec![chunk]), 8);
        let outcome = downlink.run().await.expect("run");
        assert_eq!(outcome, DownlinkOutcome::Eof);

        assert!(matches!(
            rx.recv().await.expect("leave"),
            DownlinkItem::Leave { .. }
        ));
        assert_eq!(
            rx.recv().await.expect("flow"),
            DownlinkItem::Flow { grant_bytes: 4096 }
        );
        assert_eq!(
            rx.recv().await.expect("sync end"),
            DownlinkItem::SyncEnd {
                reason: SyncEndReason::Done,
                detail: Some(b"ok".to_vec()),
            }
        );
        assert!(matches!(
            rx.recv().await.expect("stream"),
            DownlinkItem::StreamData(_)
        ));
    }

    /// The frame type gate is explicit: an unsequenced ORDERED is invalid.
    #[test]
    fn u_downlink_rejects_unsequenced_ordered() {
        let frame = sealed(MsgType::ORDERED, Seq::UNSEQUENCED, vec![0; 40]);
        let error = decode_ordered(&frame, 9, &Limits::default(), |_, _, plain| {
            Ok(plain.to_vec())
        })
        .expect_err("unsequenced");
        assert!(matches!(
            error,
            DownlinkError::Unsequenced(MsgType::ORDERED)
        ));
    }

    /// `DataRef` is part of the `WRITE` body and must survive the conversion.
    #[test]
    fn u_downlink_decode_ordered_write_ref() {
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &[0x11; 16]);
        writer.u32(fid::F_KEY_EPOCH, 1);
        writer.bytes(fid::F_OP_ID, &[0x23; 16]);
        writer.u8(fid::F_OP_CLASS, OpClass::WRITE.get());
        writer.str(fid::F_PATH, "/f");
        writer.u64(fid::F_MTIME_NS, 1);
        writer.u32(fid::F_UID, 1);
        writer.u32(fid::F_GID, 1);
        writer.bytes(fid::F_DATA_SESSION, &[0x55; 16]);
        writer.u64(fid::F_TOTAL_LEN, 1024);
        writer.bytes(fid::F_DATA_HASH, &[0x66; 32]);
        writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
        writer.bytes(fid::F_SIG, &[0x44; 64]);
        let frame = sealed(MsgType::ORDERED, Seq(8), writer.finish().expect("body"));

        let incoming = decode_ordered(&frame, 1, &Limits::default(), |_, _, plain| {
            Ok(plain.to_vec())
        })
        .expect("decode write");
        match incoming.op.body {
            OpBody::Write(DataRef {
                session,
                total_len,
                data_hash,
            }) => {
                assert_eq!(session.to_le_bytes(), [0x55; 16]);
                assert_eq!(total_len, 1024);
                assert_eq!(data_hash, [0x66; 32]);
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    /// The sealed min length is enforced by the frame decoder, not by this
    /// module; this asserts the test helper really sets `ENC`.
    #[test]
    fn u_downlink_sealed_flag() {
        let frame = sealed(MsgType::ORDERED, Seq(5), vec![0; 40]);
        assert_eq!(
            frame.header.flags.bits() & Flags::ENC.bits(),
            Flags::ENC.bits()
        );
        assert_eq!(frame.header.msg_type.body_encoding(), BodyEncoding::Sealed);
        assert_eq!(
            FrameEncoder::new()
                .encode_owned(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
                .expect("encode")
                .len(),
            21 + 40
        );
    }
}
