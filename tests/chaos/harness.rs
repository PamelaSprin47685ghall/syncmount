//! Shared harness for the M4 chaos matrix.
//!
//! Two seams are enough to exercise every fault without privileged helpers:
//!
//! * [`SeqServer`] runs the real sequencer actor in-process. A [`SeqSession`]
//!   owns the two outbox receivers, so a test can drop, duplicate, reorder or
//!   delay whole frames and then inspect the exact KICK / ORDERED result.
//! * [`HttpServer`] runs the real HTTP acceptor. `join_client` drives the real
//!   `Client::join` handshake through an optional TCP fault proxy.
//!
//! Nothing here writes product state: every path lives under `tempfile`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use syncmount::client::Client;
use syncmount::client::config::{
    Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
};
use syncmount::client::net::ConnParts;
use syncmount::client::replayer::{
    Fatal, IncomingOp, Op, OpAttrs, OpBody, OpData, PendingOverlay, Progress, Replayer,
};
use syncmount::protocol::crypto::{ClusterId, KeyRing, NonceMinter, Opener, Sealer};
use syncmount::protocol::messages::{Kick, Message, OpClass, Ping, WcpWriter, fid};
use syncmount::protocol::{
    ClientId, CtrlPrefix, DataRef, Flags, FrameBuf, FrameDecoder, FrameHeader, FrameRef,
    KickReason, Limits, MsgType, OpId, Prefix, Seq, decode_plain, encode_frame,
};
use syncmount::server::{
    Epoch, HelloRequest, Metrics, Outbox, OutboxConfig, QueueStats, SeqSnapshot, Sequencer,
    ServeConfig, Server, WatermarkReport,
};
use syncmount::store::{Errno, PosixBacking, RootFd};
use syncmount::transport::{DialOptions, Endpoint, HttpTransport, MpscBody, MpscSender, PeerId};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// One fixed cluster id for every test. Keys never leave the process.
pub const CLUSTER: ClusterId = ClusterId::from_bytes([0x4d; 16]);
/// Deterministic mtime for replayed metadata.
pub const MTIME_NS: u64 = 1_700_000_000_000_000_000;
/// Default wait for one frame or state transition.
pub const WAIT: Duration = Duration::from_secs(5);
/// Liveness ceiling from 34 §4 / 45 §6.4.
pub const RECOVER: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// Decode exactly one wire frame. Panics on a truncated or invalid frame.
pub fn decode_frame(bytes: &[u8]) -> FrameBuf {
    let mut decoder = FrameDecoder::new(Limits::default());
    decoder.push(bytes).unwrap();
    decoder.next_frame_owned().unwrap().unwrap()
}

/// Encode one owned frame.
pub fn wire(frame: &FrameBuf) -> Vec<u8> {
    encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body)).unwrap()
}

/// A frame the server only needs to route: the body is opaque ciphertext.
pub fn dummy_ordered() -> FrameBuf {
    let body = vec![0x5a; 40];
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    header.len = u32::try_from(body.len()).unwrap();
    FrameBuf::new(header, Prefix::None, body)
}

/// Build a plaintext control frame (HELLO, PING, ...).
pub fn control_frame(msg_type: MsgType, prefix: Prefix, body: Vec<u8>, seq: Seq) -> Vec<u8> {
    let mut flags = Flags::EMPTY;
    match prefix.kind() {
        syncmount::protocol::PrefixKind::None => {}
        syncmount::protocol::PrefixKind::Route => flags = flags.with(Flags::ROUTED),
        syncmount::protocol::PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
    }
    if msg_type.body_encoding() == syncmount::protocol::BodyEncoding::Sealed {
        flags = flags.with(Flags::ENC);
    }
    let mut header = FrameHeader::new(msg_type, flags, 0, seq);
    header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
    encode_frame(&FrameRef::new(&header, &prefix, &body)).unwrap()
}

/// Decode a plaintext control body.
pub fn decode_plain_frame(frame: &FrameBuf) -> Message<'_> {
    decode_plain(frame.header.msg_type, &frame.body, &Limits::default()).unwrap()
}

/// Read one frame from a channel, or `None` on timeout/close.
pub async fn recv_frame(rx: &mut mpsc::Receiver<Bytes>, timeout: Duration) -> Option<FrameBuf> {
    let bytes = tokio::time::timeout(timeout, rx.recv()).await.ok()??;
    Some(decode_frame(&bytes))
}

/// Read one frame from an HTTP transport.
pub async fn recv_transport(transport: &mut HttpTransport, timeout: Duration) -> Option<FrameBuf> {
    let bytes = tokio::time::timeout(timeout, transport.recv())
        .await
        .ok()?
        .ok()??;
    Some(decode_frame(&bytes))
}

// ---------------------------------------------------------------------------
// Sealed ORDERED frames
// ---------------------------------------------------------------------------

/// Builds real AEAD-sealed `ORDERED` frames for one author.
pub struct OpEncoder {
    pub client: ClientId,
    pub ring: Arc<KeyRing>,
    nonces: NonceMinter,
    next: u64,
}

impl OpEncoder {
    pub fn new(client: ClientId, ring: Arc<KeyRing>) -> Self {
        Self {
            client,
            ring,
            nonces: NonceMinter::with_instance(0x51ce),
            next: 0,
        }
    }

    pub fn next_op_id(&mut self) -> OpId {
        self.next += 1;
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&self.client.to_bytes()[..8]);
        raw[8..].copy_from_slice(&self.next.to_le_bytes());
        OpId::from_bytes(raw)
    }

    pub fn frame(&mut self, class: OpClass, path: &str) -> FrameBuf {
        let op_id = self.next_op_id();
        self.frame_with_id(op_id, class, path)
    }

    pub fn frame_with_id(&mut self, op_id: OpId, class: OpClass, path: &str) -> FrameBuf {
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &self.client.to_bytes());
        writer.u32(fid::F_KEY_EPOCH, 1);
        writer.bytes(fid::F_OP_ID, &op_id.to_bytes());
        writer.u8(fid::F_OP_CLASS, class.get());
        if class.requires_file_attrs() {
            writer.str(fid::F_PATH, path);
            writer.u64(fid::F_MTIME_NS, MTIME_NS);
            writer.u32(fid::F_UID, 1000);
            writer.u32(fid::F_GID, 1000);
        }
        match class {
            OpClass::MKDIR => {
                writer.u32(fid::F_MODE, 0o755);
            }
            OpClass::CREATE_EXCL => {
                writer.u32(fid::F_MODE, 0o644);
                writer.u32(fid::F_OP_FLAGS, 0);
            }
            OpClass::RENAME => {
                writer.str(fid::F_PATH2, "/renamed");
            }
            _ => {}
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
        writer.bytes(fid::F_SIG, &[0x44; 64]);
        let plaintext = writer.finish().unwrap();

        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        let sealed = Sealer::new(&self.ring, &self.nonces)
            .seal(&mut header, &Prefix::None, &plaintext)
            .unwrap();
        FrameBuf::new(header, Prefix::None, sealed.into_vec())
    }

    pub fn frame_wire(&mut self, class: OpClass, path: &str) -> (FrameBuf, Vec<u8>) {
        let frame = self.frame(class, path);
        let bytes = wire(&frame);
        (frame, bytes)
    }
}

/// Open one sealed `ORDERED` frame into a replay operation.
pub fn open_ordered(frame: &FrameBuf, epoch: u64, ring: &KeyRing) -> Result<IncomingOp, String> {
    syncmount::client::net::decode_ordered(frame, epoch, &Limits::default(), |h, p, b| {
        Opener::new(ring)
            .open(h, p, b)
            .map(|opened| opened.to_vec())
    })
    .map_err(|error| format!("{error:?}"))
}

/// A synthetic replay operation for tests that do not need the wire path.
pub fn incoming(
    seq: u64,
    epoch: u64,
    client: ClientId,
    class: OpClass,
    path: &str,
    seed: u64,
) -> IncomingOp {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&client.to_bytes()[..8]);
    raw[8..].copy_from_slice(&seed.to_le_bytes());
    let attrs = OpAttrs {
        mode: None,
        uid: 1000,
        gid: 1000,
        mtime_ns: MTIME_NS,
    };
    let body = match class {
        OpClass::MKDIR => OpBody::Mkdir { mode: 0o755 },
        OpClass::CREATE_EXCL => OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        },
        _ => OpBody::None,
    };
    let op = Op::new(OpId::from_bytes(raw), client, class, path)
        .with_attrs(attrs)
        .with_body(body);
    IncomingOp::new(Seq(seq), epoch, op)
}

/// Payload source that is never touched by metadata-only operations.
pub struct NoData;

impl OpData for NoData {
    fn read(&self, _data: &DataRef) -> Result<Vec<u8>, Errno> {
        Err(Errno::EIO)
    }
}

/// A replayer with a short reorder window so gap tests finish quickly.
pub fn replayer(client: ClientId, epoch: u64, reorder_wait: Duration) -> Replayer {
    let tuning = Tuning {
        reorder_wait,
        ..Tuning::default()
    };
    Replayer::new(
        client,
        Seq::UNSEQUENCED,
        epoch,
        &tuning,
        Arc::new(PendingOverlay::new()),
    )
}

/// Apply one synthetic operation against a real backing directory.
pub fn apply(
    replayer: &mut Replayer,
    dir: &Path,
    op: IncomingOp,
    elapsed: Duration,
) -> Result<Progress, Fatal> {
    let backing = PosixBacking::new(RootFd::open_before_mount(dir).unwrap());
    replayer.on_ordered(op, elapsed, &backing, &NoData)
}

// ---------------------------------------------------------------------------
// Sequencer harness
// ---------------------------------------------------------------------------

pub struct SeqServer {
    pub seq: Sequencer,
    pub epoch: Epoch,
    pub metrics: Arc<Metrics>,
    pub config: Arc<ServeConfig>,
    task: Option<JoinHandle<()>>,
}

impl SeqServer {
    pub fn start(epoch: u64, config: ServeConfig) -> Self {
        let config = Arc::new(config);
        let epoch = Epoch::new(epoch);
        let metrics = Arc::new(Metrics::new(epoch));
        let (seq, task) = Sequencer::start(Arc::clone(&config), epoch, Arc::clone(&metrics));
        Self {
            seq,
            epoch,
            metrics,
            config,
            task: Some(task),
        }
    }

    pub async fn stop(mut self) {
        let _ = self.seq.shutdown().await;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub async fn snapshot(&self) -> SeqSnapshot {
        self.seq.snapshot().await.unwrap()
    }
}

/// One attached sequencer session with both outbox receivers in hand.
pub struct SeqSession {
    pub id: ClientId,
    pub nonce: u64,
    pub data: mpsc::Receiver<Bytes>,
    pub ctrl: mpsc::Receiver<Bytes>,
    pub data_tx: mpsc::Sender<Bytes>,
    pub ctrl_tx: mpsc::Sender<Bytes>,
    pub queued: Arc<QueueStats>,
    _events: Option<MpscSender>,
}

impl SeqSession {
    pub async fn attach(
        server: &SeqServer,
        id: ClientId,
        nonce: u64,
        applied: Seq,
        epoch_seen: u64,
        outbox: Option<OutboxConfig>,
    ) -> Self {
        Self::attach_with(
            &server.seq,
            &server.config,
            id,
            nonce,
            applied,
            epoch_seen,
            outbox,
        )
        .await
    }

    pub async fn attach_with(
        seq: &Sequencer,
        config: &ServeConfig,
        id: ClientId,
        nonce: u64,
        applied: Seq,
        epoch_seen: u64,
        outbox: Option<OutboxConfig>,
    ) -> Self {
        let (events_tx, _events_body) = MpscBody::channel(8);
        seq.events(nonce, events_tx).await.unwrap();
        let (outbox, data, ctrl) = Outbox::new(&outbox.unwrap_or(config.outbox));
        let data_tx = outbox.data.clone();
        let _ctrl_tx = outbox.ctrl.clone();
        let reply = seq
            .hello(HelloRequest {
                nonce,
                client_id: id,
                epoch_seen,
                applied_seq: applied,
                peer: PeerId::from_serial(nonce),
                outbox,
                data,
                ctrl,
            })
            .await
            .unwrap();
        Self {
            id,
            nonce,
            data: reply.data,
            ctrl: reply.ctrl,
            data_tx,
            ctrl_tx: reply.ctrl_tx,
            queued: reply.queued,
            _events: reply.events,
        }
    }

    pub async fn next_data(&mut self, timeout: Duration) -> Option<FrameBuf> {
        recv_frame(&mut self.data, timeout).await
    }

    pub async fn next_ctrl(&mut self, timeout: Duration) -> Option<FrameBuf> {
        recv_frame(&mut self.ctrl, timeout).await
    }

    /// Drain control frames until a `KICK`, returning its reason.
    pub async fn expect_kick(&mut self, timeout: Duration) -> KickReason {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let frame = self
                .next_ctrl(remaining)
                .await
                .expect("control stream closed before KICK");
            if frame.header.msg_type == MsgType::KICK {
                match decode_plain_frame(&frame) {
                    Message::Kick(Kick { reason }) => return reason,
                    other => panic!("expected KICK body, got {other:?}"),
                }
            }
        }
    }

    /// Queue `bytes` of backlog without touching the actor's frame stream.
    pub fn add_backlog(&mut self, bytes: usize) {
        let chunk = Bytes::from(vec![0x7e; bytes]);
        self.data_tx.try_send(chunk).unwrap();
        self.queued.add(bytes);
    }

    pub fn report(&self, applied: Seq, epoch_seen: u64, at: Instant) -> WatermarkReport {
        WatermarkReport {
            client: self.id,
            applied_seq: applied,
            epoch_seen,
            rtt_ms: None,
            at,
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP harness
// ---------------------------------------------------------------------------

pub struct HttpServer {
    pub addr: SocketAddr,
    pub seq: Sequencer,
    pub metrics: Arc<Metrics>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl HttpServer {
    pub async fn start() -> Self {
        let server = Server::bind(ServeConfig::for_tests()).await.unwrap();
        let addr = server.local_addr().unwrap();
        let seq = server.sequencer();
        let metrics = server.metrics();
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        Self {
            addr,
            seq,
            metrics,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
    }

    pub async fn snapshot(&self) -> SeqSnapshot {
        self.seq.snapshot().await.unwrap()
    }
}

/// A real client after `Client::join`; the caller owns the replay pump.
pub struct Joined {
    pub client: Client,
    pub parts: ConnParts,
}

/// Drive the production JOIN path against `addr`, keeping the error.
pub async fn try_join_client(
    addr: SocketAddr,
    mountpoint: &Path,
    run_dir: &Path,
    id: ClientId,
    applied: Seq,
    epoch_seen: u64,
) -> Result<Joined, syncmount::client::ClientError> {
    let config = Config {
        endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).unwrap(),
        mountpoint: mountpoint.to_path_buf(),
        client_id: id,
        instance: InstanceId(1),
        mount_id: format!("chaos-{:x}", id.to_bytes()[0]),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir: run_dir.to_path_buf(),
        allow_empty_view: false,
    };
    let mut client = Client::new(config).with_cluster(CLUSTER);
    let parts = client.join(applied, epoch_seen).await?;
    Ok(Joined { client, parts })
}

/// Drive the production JOIN path against `addr`.
pub async fn join_client(
    addr: SocketAddr,
    mountpoint: &Path,
    run_dir: &Path,
    id: ClientId,
    applied: Seq,
    epoch_seen: u64,
) -> Joined {
    try_join_client(addr, mountpoint, run_dir, id, applied, epoch_seen)
        .await
        .unwrap()
}

/// Dial the HTTP transport and send one `HELLO`.
pub async fn http_hello(
    addr: SocketAddr,
    id: ClientId,
    applied: Seq,
    epoch_seen: u64,
    reserved: u16,
) -> (HttpTransport, syncmount::protocol::Welcome) {
    let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
    let mut transport = tokio::time::timeout(
        Duration::from_secs(2),
        HttpTransport::dial(&endpoint, &DialOptions::random()),
    )
    .await
    .unwrap()
    .unwrap();
    let hello = syncmount::protocol::Hello::new(
        syncmount::protocol::ProtoVersion::CURRENT,
        syncmount::protocol::Caps::REQUIRED,
        id,
        [7u8; 32],
    );
    let body = hello.encode().unwrap();
    let mut prefix = CtrlPrefix::new(applied, epoch_seen);
    prefix.reserved = reserved;
    let frame = control_frame(MsgType::HELLO, Prefix::Ctrl(prefix), body, Seq::UNSEQUENCED);
    transport.send(frame.into()).await.unwrap();
    let welcome = recv_transport(&mut transport, Duration::from_secs(2))
        .await
        .expect("WELCOME");
    assert_eq!(welcome.header.msg_type, MsgType::WELCOME);
    match decode_plain_frame(&welcome) {
        Message::Welcome(welcome) => (transport, welcome),
        other => panic!("expected WELCOME, got {other:?}"),
    }
}

/// Send one sealed `PING` with the given control prefix.
pub async fn http_ping(
    transport: &mut HttpTransport,
    ring: &KeyRing,
    applied: Seq,
    epoch_seen: u64,
    reserved: u16,
) {
    let mut prefix = CtrlPrefix::new(applied, epoch_seen);
    prefix.reserved = reserved;
    let nonces = NonceMinter::with_instance(0x7069);
    let body = Ping { client_time: 0 }.encode().unwrap();
    let mut header = FrameHeader::new(
        MsgType::PING,
        Flags::ENC.with(Flags::CTRL),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = Sealer::new(ring, &nonces)
        .seal(&mut header, &Prefix::Ctrl(prefix), &body)
        .unwrap();
    let frame = FrameBuf::new(header, Prefix::Ctrl(prefix), sealed.into_vec());
    transport.send(wire(&frame).into()).await.unwrap();
}

/// Wait until `predicate` holds or the timeout expires.
pub async fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return predicate();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Whether `/proc/mounts` lists this exact mountpoint.
pub fn mounted(mountpoint: &Path) -> bool {
    let needle = mountpoint.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .is_some_and(|entry| entry == needle.as_ref())
            })
        })
        .unwrap_or(false)
}

/// Best-effort cleanup after a failed FUSE test.
pub fn force_unmount(mountpoint: &Path) {
    let _ = std::process::Command::new("fusermount3")
        .arg("-uz")
        .arg(mountpoint)
        .status();
}

// ---------------------------------------------------------------------------
// Filesystem oracle
// ---------------------------------------------------------------------------

/// Stable path -> content digest for the user-visible tree.
///
/// Reserved `.syncmount-*` entries are skipped: they are internal by design.
pub fn tree_digest(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    walk(root, Path::new(""), &mut out);
    out
}

fn walk(root: &Path, rel: &Path, out: &mut BTreeMap<String, String>) {
    let directory = root.join(rel);
    let Ok(entries) = fs::read_dir(&directory) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            !path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(".syncmount"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let child = rel.join(&name);
        let key = child.to_string_lossy().into_owned();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            out.insert(key, "dir".to_owned());
            walk(root, &child, out);
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(&path).unwrap();
            out.insert(key, format!("symlink:{}", target.display()));
        } else {
            let bytes = fs::read(&path).unwrap();
            let hash = blake3::hash(&bytes);
            out.insert(key, format!("file:{}:{}", bytes.len(), hash.to_hex()));
        }
    }
}

/// The empty-cluster oracle used by the cluster-wins tests.
pub fn empty_tree() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// Temp root with `mnt` and `run` children.
pub fn mount_fixture() -> (TempDir, PathBuf, PathBuf) {
    let root = TempDir::new().unwrap();
    let mnt = root.path().join("mnt");
    let run = root.path().join("run");
    fs::create_dir(&mnt).unwrap();
    fs::create_dir(&run).unwrap();
    (root, mnt, run)
}
