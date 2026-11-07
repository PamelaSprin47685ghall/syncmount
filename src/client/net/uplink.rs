//! Outbox consumer: `LocalOp` -> signed/sealed `ORDERED` -> `Uplink`.
//!
//! The write path never touches the network. This task is the only reader of
//! [`Outbox`] and the only writer of the RPC stream, so sequence order on the
//! wire is exactly the order the outbox allocated.
//!
//! # Data operations
//!
//! `WRITE`/`PWRITE` carry only a [`DataRef`] in the `ORDERED` body. The bytes
//! travel on a relay stream first (`RELAY{CTRL}` opens the session, then
//! `STREAM_DATA{OP_DATA}` fragments), then the `ORDERED` frame follows on the
//! same ordered connection. A reader therefore has the complete stream before
//! the replay engine asks for it. A write with no peer is still sequenced;
//! the server answers `TRN_NO_PEER`, which the downlink treats as a non-fatal
//! relay hint rather than a session failure.
//!
//! # Volatility
//!
//! There is no retransmission and no durable outbox. On disconnect the task
//! stops, the remaining `LocalOp`s are dropped with the process, and a remount
//! reconciles cluster-wins (39 decision 7).
//!
//! # Heartbeat
//!
//! The task also owns the `PING` schedule: it is the only writer of the RPC
//! stream, so a second task must never send. Every loop iteration asks
//! [`Heartbeat`] whether the applied watermark changed, and a change goes out
//! as a sealed `PING` before the next outbox item. An unchanged watermark
//! sends nothing: an idle mount has zero uplink traffic, and the connection
//! alone proves liveness. The schedule lives and dies with the task: the
//! lifecycle aborts it when the write gate closes, and a failed write ends it
//! with the session.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::client::lifecycle::{Cause, Event};
use crate::client::status::{Conntrace, Counters, TraceEntry};
use crate::client::writer::{LocalOp, Outbox, QueuedOp};
use crate::protocol::crypto::{KeyRing, NonceMinter, Sealer};
use crate::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
use crate::protocol::identity::{Identity, payload_hash};
use crate::protocol::messages::{FieldMap, OpClass, SyncEnd, WcpError, WcpWriter, fid};
use crate::protocol::{
    Flags, FrameBuf, FrameHeader, Limits, MsgType, OpId, Prefix, RoutePrefix, Seq, SessionId,
    StreamId, SyncEndReason,
};
use crate::store::{BackingStore, Errno, InodeId, NodeTable, PosixBacking};

use super::conn::{Uplink, UplinkError};
use super::heartbeat::{Heartbeat, Watermark, WatermarkReader, ping_frame};

/// How often an idle uplink looks for a newly committed operation.
///
/// `Outbox` has no wakeup primitive and W11 owns that file; 1 ms keeps the
/// write path inside its p99 budget without a busy loop.
const IDLE_POLL: Duration = Duration::from_millis(1);

/// One encoded operation plus the payload that must precede it.
struct EncodedOp {
    frame: FrameBuf,
    data: Option<(SessionId, Vec<u8>)>,
}

/// Attributes placed in every file-operation body.
#[derive(Clone, Copy)]
struct WireAttrs {
    uid: u32,
    gid: u32,
    mtime_ns: u64,
}

/// Outbox consumer.
pub struct UplinkTask {
    outbox: Arc<Outbox>,
    uplink: Uplink,
    identity: Arc<dyn Identity + Send + Sync>,
    ring: Arc<KeyRing>,
    nonces: NonceMinter,
    nodes: Arc<NodeTable>,
    backing: Arc<PosixBacking>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    watermark: WatermarkReader,
    events: mpsc::Sender<Event>,
    /// Ready-made control frames from another client task.
    ///
    /// The task stays the only writer of the RPC stream: a producer hands
    /// over a complete frame and this loop writes it. The JOIN proof answer
    /// is the only current user.
    control: Option<mpsc::Receiver<FrameBuf>>,
}

impl fmt::Debug for UplinkTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UplinkTask")
            .field("client_id", &self.identity.client_id())
            .field("key_epoch", &self.identity.key_epoch())
            .field("outbox", &self.outbox)
            .field("watermark", &self.watermark)
            .finish_non_exhaustive()
    }
}

impl UplinkTask {
    /// Assemble the task from the client's shared parts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        outbox: Arc<Outbox>,
        uplink: Uplink,
        identity: Arc<dyn Identity + Send + Sync>,
        ring: Arc<KeyRing>,
        nodes: Arc<NodeTable>,
        backing: Arc<PosixBacking>,
        counters: Arc<Counters>,
        conntrace: Arc<Conntrace>,
        watermark: WatermarkReader,
        events: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            outbox,
            uplink,
            identity,
            ring,
            nonces: NonceMinter::with_instance(rand::random::<u64>()),
            nodes,
            backing,
            counters,
            conntrace,
            watermark,
            events,
            control: None,
        }
    }

    /// Write complete frames handed over by another task.
    ///
    /// The queue is bounded by the producer, and `run` drains it before each
    /// outbox item, so a producer can never stall the write path: a full
    /// queue simply drops on the producer side.
    pub fn with_control(mut self, control: mpsc::Receiver<FrameBuf>) -> Self {
        self.control = Some(control);
        self
    }

    /// Drain the outbox and report the watermark until aborted or the uplink
    /// fails.
    pub async fn run(mut self) {
        let mut heartbeat = Heartbeat::new();
        loop {
            loop {
                let Some(control) = self.control.as_mut() else {
                    break;
                };
                let Ok(frame) = control.try_recv() else {
                    break;
                };
                if let Err(error) = self.send_frame(&frame).await {
                    self.stop(error).await;
                    return;
                }
            }
            if let Some(watermark) = heartbeat.due(Instant::now(), self.watermark.read()) {
                if let Err(error) = self.send_ping(watermark).await {
                    self.stop(error).await;
                    return;
                }
            }
            let Some(queued) = self.outbox.take_ready() else {
                tokio::time::sleep(IDLE_POLL).await;
                continue;
            };
            if let Err(error) = self.send(queued).await {
                self.stop(error).await;
                return;
            }
        }
    }

    /// Report the watermark so the server's lag diagnostic stays current.
    /// Only a changed watermark reaches this method; an idle session never
    /// calls it.
    async fn send_ping(&mut self, watermark: Watermark) -> Result<(), UplinkError> {
        let client_time = u64::try_from(super::wall_clock_us()).unwrap_or(0);
        let frame = ping_frame(watermark, client_time, &self.ring, &self.nonces)?;
        self.send_frame(&frame).await
    }

    /// Report one terminal uplink failure and stop the task.
    async fn stop(&self, error: UplinkError) {
        tracing::error!(%error, "uplink stopped");
        let _ = self
            .events
            .send(Event::Disconnected(Cause::WriteError))
            .await;
    }

    async fn send(&mut self, queued: QueuedOp) -> Result<(), UplinkError> {
        let Some(encoded) = self.encode(&queued)? else {
            return Ok(());
        };
        if let Some((session, data)) = encoded.data {
            self.send_stream(session, &data).await?;
        }
        self.send_frame(&encoded.frame).await?;
        Ok(())
    }

    fn encode(&self, queued: &QueuedOp) -> Result<Option<EncodedOp>, UplinkError> {
        let op_id = queued.op_id;
        match &queued.op {
            LocalOp::Write { ino, off, data } => {
                let path = self.path(*ino)?;
                let attrs = self.attrs(*ino)?;
                let session = SessionId::new(rand::random::<u128>());
                let hash = *blake3::hash(data).as_bytes();
                let (class, mut fields) = if *off == 0 {
                    (
                        OpClass::WRITE,
                        self.base_fields(OpClass::WRITE, op_id, &path, attrs),
                    )
                } else {
                    (
                        OpClass::PWRITE,
                        self.base_fields(OpClass::PWRITE, op_id, &path, attrs),
                    )
                };
                fields.push((fid::F_DATA_SESSION, session.to_le_bytes().to_vec()));
                fields.push((fid::F_TOTAL_LEN, data.len().to_le_bytes().to_vec()));
                fields.push((fid::F_DATA_HASH, hash.to_vec()));
                if *off != 0 {
                    fields.push((fid::F_OFFSET, off.to_le_bytes().to_vec()));
                }
                Ok(Some(EncodedOp {
                    frame: self.seal_ordered(op_id, class, fields)?,
                    data: Some((session, data.clone())),
                }))
            }
            LocalOp::Truncate { ino, size } => {
                let path = self.path(*ino)?;
                let attrs = self.attrs(*ino)?;
                let mut fields = self.base_fields(OpClass::TRUNCATE, op_id, &path, attrs);
                fields.push((fid::F_LENGTH, size.to_le_bytes().to_vec()));
                Ok(Some(EncodedOp {
                    frame: self.seal_ordered(op_id, OpClass::TRUNCATE, fields)?,
                    data: None,
                }))
            }
            LocalOp::SetAttr { ino, delta } => {
                let path = self.path(*ino)?;
                let current = self.attrs(*ino)?;
                let attrs = WireAttrs {
                    uid: delta.uid.unwrap_or(current.uid),
                    gid: delta.gid.unwrap_or(current.gid),
                    mtime_ns: delta.mtime.map(timespec_ns).unwrap_or(current.mtime_ns),
                };
                let mut fields = self.base_fields(OpClass::SETATTR, op_id, &path, attrs);
                if let Some(mode) = delta.mode {
                    fields.push((fid::F_MODE, mode.to_le_bytes().to_vec()));
                }
                Ok(Some(EncodedOp {
                    frame: self.seal_ordered(op_id, OpClass::SETATTR, fields)?,
                    data: None,
                }))
            }
            LocalOp::Xattr { .. } => {
                // v1 has no xattr op_class. The local change is already on
                // disk; advertising it would require a protocol extension.
                tracing::warn!("xattr has no v1 op_class; keeping it local");
                Ok(None)
            }
            LocalOp::Meta { class, body, .. } => {
                let fields = self.meta_fields(*class, op_id, body)?;
                Ok(Some(EncodedOp {
                    frame: self.seal_ordered(op_id, *class, fields)?,
                    data: None,
                }))
            }
        }
    }

    fn path(&self, ino: InodeId) -> Result<String, UplinkError> {
        let relative = self.nodes.path_of(ino).ok_or(Errno::ENOENT)?;
        if relative.as_os_str().is_empty() {
            return Ok("/".to_owned());
        }
        relative
            .to_str()
            .map(|path| format!("/{path}"))
            .ok_or(Errno::EINVAL)
            .map_err(UplinkError::from)
    }

    fn attrs(&self, ino: InodeId) -> Result<WireAttrs, UplinkError> {
        let attr = BackingStore::getattr(self.backing.as_ref(), ino)?;
        Ok(WireAttrs {
            uid: attr.uid,
            gid: attr.gid,
            mtime_ns: timespec_ns(attr.mtime),
        })
    }

    fn base_fields(
        &self,
        class: OpClass,
        op_id: OpId,
        path: &str,
        attrs: WireAttrs,
    ) -> Vec<(u8, Vec<u8>)> {
        vec![
            (
                fid::F_CLIENT_ID,
                self.identity.client_id().as_bytes().to_vec(),
            ),
            (
                fid::F_KEY_EPOCH,
                self.identity.key_epoch().get().to_le_bytes().to_vec(),
            ),
            (fid::F_OP_ID, op_id.as_bytes().to_vec()),
            (fid::F_OP_CLASS, vec![class.get()]),
            (fid::F_PATH, path.as_bytes().to_vec()),
            (fid::F_MTIME_NS, attrs.mtime_ns.to_le_bytes().to_vec()),
            (fid::F_UID, attrs.uid.to_le_bytes().to_vec()),
            (fid::F_GID, attrs.gid.to_le_bytes().to_vec()),
        ]
    }

    fn meta_fields(
        &self,
        class: OpClass,
        op_id: OpId,
        body: &[u8],
    ) -> Result<Vec<(u8, Vec<u8>)>, UplinkError> {
        let map = FieldMap::parse(body, &Limits::default())?;
        let mut fields = Vec::new();
        for (field, value) in map.iter() {
            if matches!(
                field,
                fid::F_WCP_VER
                    | fid::F_CLIENT_ID
                    | fid::F_KEY_EPOCH
                    | fid::F_OP_ID
                    | fid::F_OP_CLASS
                    | fid::F_PAYLOAD_HASH
                    | fid::F_SIG
                    | fid::F_SENDER_PUB
                    | fid::F_KEY_MAC
            ) {
                continue;
            }
            fields.push((field, value.to_vec()));
        }
        fields.push((
            fid::F_CLIENT_ID,
            self.identity.client_id().as_bytes().to_vec(),
        ));
        fields.push((
            fid::F_KEY_EPOCH,
            self.identity.key_epoch().get().to_le_bytes().to_vec(),
        ));
        fields.push((fid::F_OP_ID, op_id.as_bytes().to_vec()));
        fields.push((fid::F_OP_CLASS, vec![class.get()]));
        Ok(fields)
    }

    fn seal_ordered(
        &self,
        op_id: OpId,
        class: OpClass,
        fields: Vec<(u8, Vec<u8>)>,
    ) -> Result<FrameBuf, UplinkError> {
        let unsigned = fields_to_wcp(&fields)?;
        let map = FieldMap::parse(&unsigned, &Limits::default())?;
        let canonical = map.canonical_bytes_excluding(&[
            fid::F_SIG,
            fid::F_PAYLOAD_HASH,
            fid::F_SENDER_PUB,
            fid::F_KEY_MAC,
        ])?;
        let hash = payload_hash(&canonical);
        let signature = self
            .identity
            .sign_op(op_id, class, MsgType::ORDERED, Flags::ENC, &hash);
        let mut writer = WcpWriter::new();
        for (field, value) in fields {
            if field != fid::F_WCP_VER {
                writer.bytes(field, &value);
            }
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &hash);
        writer.bytes(fid::F_SIG, signature.as_bytes());
        let body = writer.finish()?;
        self.seal(MsgType::ORDERED, Flags::ENC, Prefix::None, &body)
    }

    async fn send_stream(&mut self, session: SessionId, data: &[u8]) -> Result<(), UplinkError> {
        let open = self.seal(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0)),
            &WcpWriter::new().finish()?,
        )?;
        self.send_frame(&open).await?;

        let fragmenter = Fragmenter::new(session, StreamId::OP_DATA, data.len() as u64)?;
        for index in 0..fragmenter.total_chunks() {
            let length = fragmenter.chunk_len(index)?;
            let start = index as usize * CHUNK_PLAIN;
            let end = start + length;
            let fragment = fragmenter.fragment(index, &data[start..end])?;
            let prefix =
                RoutePrefix::new(session, StreamId::OP_DATA, index, fragmenter.total_chunks());
            let frame = self.seal(
                MsgType::STREAM_DATA,
                Flags::ENC.with(Flags::ROUTED),
                Prefix::Route(prefix),
                fragment.plaintext,
            )?;
            self.send_frame(&frame).await?;
        }

        // Close the relay session explicitly. Without this, the next write's
        // `open` counts as a source change and the server's retry budget is
        // consumed after three writes.
        let body = SyncEnd {
            reason: SyncEndReason::Done,
            detail: None,
        }
        .encode()?;
        let prefix = RoutePrefix::new(session, StreamId::CTRL, 0, 0);
        let mut header = FrameHeader::new(MsgType::SYNC_END, Flags::ROUTED, 0, Seq::UNSEQUENCED);
        header.len = (RoutePrefix::ENCODED_LEN + body.len()) as u32;
        self.send_frame(&FrameBuf::new(header, Prefix::Route(prefix), body))
            .await?;
        Ok(())
    }

    async fn send_frame(&mut self, frame: &FrameBuf) -> Result<(), UplinkError> {
        Counters::bump(&self.counters.frames_out);
        self.conntrace.record(TraceEntry::new(
            super::wall_clock_us(),
            "out",
            frame.header.msg_type.name(),
            u32::try_from(frame.body.len()).unwrap_or(u32::MAX),
            frame.header.seq,
        ));
        self.uplink.send(frame).await
    }

    fn seal(
        &self,
        msg_type: MsgType,
        flags: Flags,
        prefix: Prefix,
        plaintext: &[u8],
    ) -> Result<FrameBuf, UplinkError> {
        let mut header = FrameHeader::new(msg_type, flags, 0, Seq::UNSEQUENCED);
        let sealer = Sealer::new(&self.ring, &self.nonces);
        let sealed = sealer.seal(&mut header, &prefix, plaintext)?;
        Ok(FrameBuf::new(header, prefix, sealed.into_vec()))
    }
}

fn fields_to_wcp(fields: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, WcpError> {
    let mut writer = WcpWriter::new();
    for (field, value) in fields {
        if *field != fid::F_WCP_VER {
            writer.bytes(*field, value);
        }
    }
    writer.finish()
}

fn timespec_ns(time: crate::store::Timespec) -> u64 {
    let seconds = time.sec.max(0) as u64;
    let nanos = time.nsec.clamp(0, 999_999_999) as u64;
    seconds.saturating_mul(1_000_000_000).saturating_add(nanos)
}
