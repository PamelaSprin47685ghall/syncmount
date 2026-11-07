//! M2 exit acceptance harness (31:M2-1..M2-11), protocol/loopback layer.
//!
//! The harness is deliberately library-level: `Server` plus two client-side
//! sessions (`Conn`/`Uplink`/`Downlink`/`Replayer`). It does not mount FUSE
//! for the replication items, because the W13b write path is not attached to
//! the outbox yet; the data payload is supplied through the `OpData` port,
//! which is the same seam W16 will fill with the chunk store. M2-8 and M2-11
//! do use a real FUSE mount where the item requires it.
//!
//! Every test prints a `M2 evidence:` line; the internal M2 runner (not
//! published) captures one log per test. Failures are real acceptance
//! failures, not skips.
//!
//! Run one item at a time so each transcript is clean:
//!
//! ```text
//! SYNCMOUNT_REQUIRE_FUSE=1 \
//!   cargo test --test m2_acceptance -- --nocapture --test-threads=1 \
//!   --exact m2_3_a_write_b_read_p99
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use syncmount::client::Client;
use syncmount::client::config::{
    Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
};
use syncmount::client::lifecycle::{
    Action, Cause, Event, JoinOutcome, Lifecycle, ResyncReason as LifecycleResyncReason, State,
};
use syncmount::client::net::{Downlink, DownlinkItem, Uplink, decode_ordered};
use syncmount::client::replayer::{
    Fatal, IncomingOp, Namespace, Op, OpAttrs, OpBody, OpData, PendingOverlay, Replayer,
    ResyncReason as ReplayResyncReason,
};
use syncmount::protocol::crypto::{ClusterId, KeyRing};
use syncmount::protocol::messages::{OpClass, WcpWriter, fid};
use syncmount::protocol::{
    ClientId, DataRef, Flags, FrameBuf, FrameDecoder, FrameHeader, FrameRef, Limits, MsgType, OpId,
    Prefix, Seq, SessionId, encode_frame,
};
use syncmount::sync::{
    Blockmap, ChunkId, ChunkKind, ChunkReader, DeltaPeer, JoinView, Manifest, RemoteView, SyncError,
};
use syncmount::server::{ServeConfig, Server};
use syncmount::store::{Errno, PosixBacking, RootFd};
use syncmount::transport::{AcceptedHttp, HttpAcceptor};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

const MTIME_NS: u64 = 1_700_000_000_000_000_000;
const WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// One operation description for the test encoder.
struct OpSpec<'a> {
    class: OpClass,
    path: &'a str,
    payload: Option<Vec<u8>>,
    offset: u64,
    path2: Option<&'a str>,
    length: Option<u64>,
    mode: u32,
}

impl<'a> OpSpec<'a> {
    fn new(class: OpClass, path: &'a str) -> Self {
        Self {
            class,
            path,
            payload: None,
            offset: 0,
            path2: None,
            length: None,
            mode: 0o755,
        }
    }

    fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    fn offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    fn path2(mut self, path2: &'a str) -> Self {
        self.path2 = Some(path2);
        self
    }

    fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

/// Shared plaintext for `WRITE`/`PWRITE` references.
///
/// W16 replaces this with the chunk store; the replay engine only sees the
/// `OpData` port, so the acceptance exercises the same verification path
/// (`total_len` and `data_hash` are checked before the disk write).
#[derive(Default)]
struct TestData {
    map: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl TestData {
    fn insert(&self, session: SessionId, bytes: Vec<u8>) {
        self.map
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(session.to_le_bytes(), bytes);
    }
}

impl OpData for TestData {
    fn read(&self, data: &DataRef) -> Result<Vec<u8>, Errno> {
        self.map
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&data.session.to_le_bytes())
            .cloned()
            .ok_or(Errno::EIO)
    }
}

/// Build signed-shaped `ORDERED` bodies. Signatures are opaque to the server
/// and to the replay engine; W4 verifies them in the identity layer.
struct OpBuilder {
    client: ClientId,
    next: u64,
    data: Arc<TestData>,
}

impl OpBuilder {
    fn new(client: ClientId, data: Arc<TestData>) -> Self {
        Self {
            client,
            next: 0,
            data,
        }
    }

    fn frame(&mut self, spec: OpSpec<'_>) -> (OpId, FrameBuf) {
        self.next += 1;
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&self.client.to_bytes()[..8]);
        raw[8..].copy_from_slice(&self.next.to_le_bytes());
        let op_id = OpId::from_bytes(raw);

        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &self.client.to_bytes());
        writer.u32(fid::F_KEY_EPOCH, 1);
        writer.bytes(fid::F_OP_ID, &op_id.to_bytes());
        writer.u8(fid::F_OP_CLASS, spec.class.get());
        if spec.class.requires_file_attrs() {
            writer.str(fid::F_PATH, spec.path);
            writer.u64(fid::F_MTIME_NS, MTIME_NS);
            writer.u32(fid::F_UID, 1000);
            writer.u32(fid::F_GID, 1000);
        }
        match spec.class {
            OpClass::MKDIR => {
                writer.u32(fid::F_MODE, spec.mode);
            }
            OpClass::CREATE_EXCL => {
                writer.u32(fid::F_MODE, spec.mode);
                writer.u32(fid::F_OP_FLAGS, 0);
            }
            OpClass::RENAME => {
                writer.str(fid::F_PATH2, spec.path2.expect("rename path2"));
            }
            OpClass::TRUNCATE => {
                writer.u64(fid::F_LENGTH, spec.length.expect("truncate length"));
            }
            OpClass::WRITE | OpClass::PWRITE => {
                let payload = spec.payload.expect("write payload");
                let session = SessionId::from_le_bytes(op_id.to_bytes());
                let hash = *blake3::hash(&payload).as_bytes();
                self.data.insert(session, payload.clone());
                writer.bytes(fid::F_DATA_SESSION, &session.to_le_bytes());
                writer.u64(fid::F_TOTAL_LEN, payload.len() as u64);
                writer.bytes(fid::F_DATA_HASH, &hash);
                if spec.class == OpClass::PWRITE {
                    writer.u64(fid::F_OFFSET, spec.offset);
                }
            }
            _ => {}
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
        writer.bytes(fid::F_SIG, &[0x44; 64]);
        let body = writer.finish().expect("WCP body");
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(body.len()).expect("frame body fits u32");
        (op_id, FrameBuf::new(header, Prefix::None, body))
    }
}

fn op_for(seq: u64, client: ClientId, class: OpClass, path: &str) -> IncomingOp {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&seq.to_le_bytes());
    raw[8..].copy_from_slice(&client.to_bytes()[..8]);
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
    IncomingOp::new(Seq(seq), 1, op)
}

fn dummy_frame(seed: u8) -> Vec<u8> {
    let body = vec![seed; 40];
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    header.len = 40;
    encode_frame(&FrameRef::new(&header, &Prefix::None, &body)).expect("dummy frame")
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Client session harness
// ---------------------------------------------------------------------------

struct ClientNode {
    id: ClientId,
    uplink: Uplink,
    builder: OpBuilder,
    applied: watch::Receiver<u64>,
    verdicts: Arc<Mutex<BTreeMap<OpId, Result<(), Errno>>>>,
    order: Arc<Mutex<Vec<(u64, OpId)>>>,
    errors: Arc<Mutex<Vec<String>>>,
    downlink_done: Arc<AtomicBool>,
    stop: Option<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

/// The M2 control-plane harness has no relay ports. A second JOIN would
/// otherwise be refused because a holder view is unreachable without them.
/// An empty view at sequence zero is exact and deletes nothing.
#[derive(Debug)]
struct EmptyView;

#[derive(Debug)]
struct NoChunks;

impl ChunkReader for NoChunks {
    fn read(&self, _kind: ChunkKind, _id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        Ok(None)
    }
}

impl JoinView for EmptyView {
    fn remote(&self) -> RemoteView {
        RemoteView {
            reference: None,
            manifest: Manifest::new(Seq::UNSEQUENCED, Vec::new()),
            blockmap: Blockmap::new(Seq::UNSEQUENCED, Vec::new(), Vec::new())
                .expect("empty blockmap"),
        }
    }

    fn chunks(&self) -> Arc<dyn ChunkReader> {
        Arc::new(NoChunks)
    }

    fn delta(&self) -> Option<Arc<dyn DeltaPeer>> {
        None
    }
}

impl ClientNode {
    async fn connect(
        addr: std::net::SocketAddr,
        id: ClientId,
        dir: &Path,
        data: Arc<TestData>,
    ) -> Self {
        let config = Config {
            endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
            mountpoint: dir.to_path_buf(),
            client_id: id,
            instance: InstanceId(1),
            mount_id: "m2-acceptance".to_string(),
            tuning: Tuning::default(),
            password: PasswordSource::Tty,
            run_dir: dir.to_path_buf(),
            allow_empty_view: false,
        };
        // The JOIN runs the cluster-wins step: a remount deletes local-only
        // paths and installs the cluster view (31:M2-8).
        let mut client = Client::new(config)
            .with_cluster(ClusterId::from_bytes([9; 16]))
            .with_join_view(Arc::new(EmptyView));
        let parts = client.join(Seq::UNSEQUENCED, 0).await.expect("JOIN");
        let epoch = parts.welcome.epoch;
        let covered = parts.welcome.current_seq;
        let mut replayer = client.take_replayer().expect("replayer after JOIN");

        let (downlink, mut rx, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 256);
        let backing = Arc::new(PosixBacking::new(
            RootFd::open_before_mount(dir).expect("open backing root"),
        ));
        let _state = replayer.state_handle();

        let (applied_tx, applied_rx) = watch::channel(covered.get());
        let verdicts = Arc::new(Mutex::new(BTreeMap::new()));
        let order = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));

        let downlink_done = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&downlink_done);
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let downlink_task = tokio::spawn(async move {
            tokio::select! {
                _ = downlink.run() => {}
                _ = &mut stop_rx => {}
            }
            done.store(true, Ordering::Release);
        });

        let replay_verdicts = Arc::clone(&verdicts);
        let replay_order = Arc::clone(&order);
        let replay_errors = Arc::clone(&errors);
        let replay_backing = Arc::clone(&backing);
        let replay_data = Arc::clone(&data);
        let replay_task = tokio::spawn(async move {
            let start = Instant::now();
            while let Some(item) = rx.recv().await {
                match item {
                    DownlinkItem::Ordered(frame) => {
                        let decoded =
                            decode_ordered(&frame, epoch, &Limits::default(), |_, _, plain| {
                                Ok(plain.to_vec())
                            });
                        match decoded {
                            Ok(incoming) => {
                                let op_id = incoming.op.op_id;
                                let seq = incoming.seq.get();
                                match replayer.on_ordered(
                                    incoming,
                                    start.elapsed(),
                                    replay_backing.as_ref(),
                                    replay_data.as_ref(),
                                ) {
                                    Ok(progress) => {
                                        replay_verdicts
                                            .lock()
                                            .unwrap_or_else(|poison| poison.into_inner())
                                            .insert(op_id, progress.verdict);
                                        replay_order
                                            .lock()
                                            .unwrap_or_else(|poison| poison.into_inner())
                                            .push((seq, op_id));
                                        let _ = applied_tx.send(progress.applied.get());
                                    }
                                    Err(fatal) => replay_errors
                                        .lock()
                                        .unwrap_or_else(|poison| poison.into_inner())
                                        .push(format!("{fatal:?}")),
                                }
                            }
                            Err(error) => replay_errors
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .push(format!("decode: {error:?}")),
                        }
                    }
                    DownlinkItem::Leave { .. } => {}
                    _ => {}
                }
            }
        });

        Self {
            id,
            uplink: parts.uplink,
            builder: OpBuilder::new(id, data),
            applied: applied_rx,
            verdicts,
            order,
            errors,
            downlink_done,
            stop: Some(stop_tx),
            tasks: vec![downlink_task, replay_task],
        }
    }

    async fn send(&mut self, frame: &FrameBuf) -> Result<(), String> {
        self.uplink
            .send(frame)
            .await
            .map_err(|error| error.to_string())
    }

    async fn wait_applied(&self, seq: u64, timeout: Duration) -> Result<(), String> {
        let mut applied = self.applied.clone();
        tokio::time::timeout(timeout, applied.wait_for(|value| *value >= seq))
            .await
            .map_err(|_| format!("client {} did not reach seq {seq}", self.id))?
            .map(|_| ())
            .map_err(|error| format!("client {} watch closed: {error}", self.id))
    }

    fn own_verdict(&self, op_id: OpId) -> Option<Result<(), Errno>> {
        self.verdicts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&op_id)
            .copied()
    }

    fn order(&self) -> Vec<(u64, OpId)> {
        self.order
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn downlink_done(&self) -> bool {
        self.downlink_done.load(Ordering::Acquire)
    }

    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for ClientNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Harness {
    addr: std::net::SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Harness {
    async fn boot() -> Self {
        let server = Server::bind(ServeConfig::for_tests()).await.expect("bind");
        let addr = server.local_addr().expect("local addr");
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        Self { addr, stop, task }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

// ---------------------------------------------------------------------------
// Filesystem snapshot helpers
// ---------------------------------------------------------------------------

fn tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    walk(root, Path::new(""), &mut out);
    out
}

fn walk(root: &Path, rel: &Path, out: &mut BTreeMap<String, String>) {
    let directory = root.join(rel);
    let mut entries: Vec<_> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("readdir {}: {error}", directory.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        let child = rel.join(&name);
        let key = child.to_string_lossy().into_owned();
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        if metadata.is_dir() {
            out.insert(key, "dir".to_string());
            walk(root, &child, out);
        } else {
            let bytes = fs::read(&path).expect("read file");
            out.insert(key, format!("file:{}:{}", bytes.len(), sha256(&bytes)));
        }
    }
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    predicate()
}

fn mounted(mnt: &Path) -> bool {
    let needle = mnt.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mountpoint| mountpoint == needle.as_ref())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn force_unmount(mnt: &Path) {
    let _ = Command::new("fusermount3").arg("-uz").arg(mnt).status();
}

// ---------------------------------------------------------------------------
// M2-1: server startup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_1_library_server_starts_without_panic() {
    let server = Server::bind(ServeConfig::for_tests())
        .await
        .expect("server bind");
    let addr = server.local_addr().expect("local addr");
    let metrics = server.metrics();
    let (stop, stop_rx) = oneshot::channel();
    let task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let mut stream = TcpStream::connect(addr).await.expect("connect healthz");
    stream
        .write_all(b"GET /__syncmount/healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write healthz");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read healthz");
    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "healthz status: {text}");
    assert!(text.contains("\"status\":\"ok\""), "healthz body: {text}");
    assert!(text.contains("\"mode\":\"serve\""), "healthz body: {text}");
    assert!(!task.is_finished(), "server task must still be running");
    assert_eq!(metrics.clients.load(Ordering::Relaxed), 0);

    println!(
        "M2 evidence: M2-1 library Server::bind addr={addr} healthz=200 no-panic task_alive=true"
    );
    let _ = stop.send(());
    let joined = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server shutdown timeout");
    assert!(joined.is_ok(), "server task ended badly: {joined:?}");
}

#[test]
fn m2_1_cli_server_listens() {
    use std::process::Stdio;

    // 31:M2-1 is the literal CLI form. The server runs until a signal, so the
    // test watches its JSON log for the `listening` event and then kills it;
    // `output()` would wait forever.
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("server.log");
    let file = fs::File::create(&log).expect("log file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syncmount"))
        .args([
            "server",
            "http://127.0.0.1:0/sync",
            "--listen",
            "127.0.0.1:0",
            "--log-format",
            "json",
        ])
        .stdout(Stdio::from(file.try_clone().expect("clone log")))
        .stderr(Stdio::from(file))
        .spawn()
        .expect("run syncmount server");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = fs::read_to_string(&log).unwrap_or_default();
        if text.contains("\"event\":\"listening\"") {
            break;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("server exited before listening: {status:?} log={text}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    println!("M2 evidence: M2-1 literal CLI `syncmount server` log={text}");
    assert!(
        text.contains("\"event\":\"listening\""),
        "no listening event: {text}"
    );
    assert!(
        text.contains("\"addr\":\"127.0.0.1:"),
        "no bound address in the listening event: {text}"
    );
}

// ---------------------------------------------------------------------------
// M2-2: HTTP/1.1 keepalive
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_2_http11_keepalive_two_frames_one_connection() {
    let mut acceptor = HttpAcceptor::bind("127.0.0.1:0".parse().expect("addr"), "/")
        .await
        .expect("bind acceptor");
    let addr = acceptor.local_addr().expect("acceptor addr");
    let connections = acceptor.connection_counter();
    let accept = tokio::spawn(async move { acceptor.accept_http().await });

    let first = dummy_frame(0x11);
    let second = dummy_frame(0x22);
    let mut payload = Vec::new();
    payload.extend_from_slice(&first);
    payload.extend_from_slice(&second);

    let mut request = Vec::new();
    request.extend_from_slice(
        b"POST /rpc HTTP/1.1\r\nHost: test\r\nX-SM-Nonce: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    request.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    request.extend_from_slice(&payload);
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(&request).await.expect("write request");

    let accepted = tokio::time::timeout(Duration::from_secs(2), accept)
        .await
        .expect("accept timeout")
        .expect("accept task")
        .expect("accepted request");
    let AcceptedHttp::Rpc { mut body, end, .. } = accepted else {
        panic!("expected an RPC half");
    };
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next_bytes().await.expect("body chunk") {
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= payload.len() {
            break;
        }
    }
    drop(end);

    let mut decoder = FrameDecoder::new(Limits::default());
    decoder.push(&bytes).expect("decode push");
    let one = decoder
        .next_frame_owned()
        .expect("decode one")
        .expect("first frame");
    let two = decoder
        .next_frame_owned()
        .expect("decode two")
        .expect("second frame");
    assert_eq!(one.header.msg_type, MsgType::ORDERED);
    assert_eq!(two.header.msg_type, MsgType::ORDERED);
    assert_eq!(one.header.body_len().expect("body len"), 40);
    assert_eq!(two.header.body_len().expect("body len"), 40);

    let count = connections.load(Ordering::Relaxed);
    assert_eq!(count, 1, "two frames must share one TCP connection");
    println!(
        "M2 evidence: M2-2 frames=2 msg_type=ORDERED tcp_connections={count} \
         payload_bytes={} body_len=40",
        payload.len()
    );
}

// ---------------------------------------------------------------------------
// M2-3: A writes, B reads, p99
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_3_a_write_b_read_p99() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir_a = TempDir::new().expect("dir a");
    let dir_b = TempDir::new().expect("dir b");
    let mut a = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x0a; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let b = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x0b; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    let (_, create) = a.builder.frame(OpSpec::new(OpClass::CREATE_EXCL, "/f"));
    a.send(&create).await.expect("send create");
    a.wait_applied(1, WAIT).await.expect("a create");
    b.wait_applied(1, WAIT).await.expect("b create");
    assert!(dir_b.path().join("f").is_file(), "B must see /f");

    let mut latencies = Vec::new();
    for index in 0..100u64 {
        let payload = vec![(index % 251) as u8; 1024];
        let (_, frame) = a.builder.frame(
            OpSpec::new(OpClass::PWRITE, "/f")
                .offset(0)
                .payload(payload.clone()),
        );
        let started = Instant::now();
        a.send(&frame).await.expect("send pwrite");
        let expected = 2 + index;
        a.wait_applied(expected, WAIT).await.expect("a pwrite");
        b.wait_applied(expected, WAIT).await.expect("b pwrite");
        latencies.push(started.elapsed());
        let seen = fs::read(dir_b.path().join("f")).expect("read B /f");
        assert_eq!(seen, payload, "iteration {index}");
    }
    assert!(a.errors().is_empty(), "A replay errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B replay errors: {:?}", b.errors());

    latencies.sort();
    let index = ((latencies.len() as f64 * 0.99).ceil() as usize)
        .saturating_sub(1)
        .min(latencies.len() - 1);
    let p99 = latencies[index];
    println!(
        "M2 evidence: M2-3 iterations=100 payload=1024B p99={:?} max={:?} \
         final_sha256={}",
        p99,
        latencies.last().copied().unwrap_or_default(),
        sha256(&fs::read(dir_b.path().join("f")).expect("final read"))
    );
    assert!(
        p99 <= Duration::from_millis(50),
        "M2-3 target p99 <= 50ms, observed {p99:?}"
    );

    drop(a);
    drop(b);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-4: same-offset LWW, no tearing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_4_same_offset_lww_no_tearing() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir_a = TempDir::new().expect("dir a");
    let dir_b = TempDir::new().expect("dir b");
    let mut a = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x1a; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let mut b = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x1b; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    let (_, create) = a.builder.frame(OpSpec::new(OpClass::CREATE_EXCL, "/f"));
    a.send(&create).await.expect("create");
    a.wait_applied(1, WAIT).await.expect("a create");
    b.wait_applied(1, WAIT).await.expect("b create");

    let payload_a = vec![0xaa; 4096];
    let payload_b = vec![0xbb; 4096];
    let (id_a, frame_a) = a.builder.frame(
        OpSpec::new(OpClass::PWRITE, "/f")
            .offset(0)
            .payload(payload_a.clone()),
    );
    let (id_b, frame_b) = b.builder.frame(
        OpSpec::new(OpClass::PWRITE, "/f")
            .offset(0)
            .payload(payload_b.clone()),
    );
    let (sent_a, sent_b) = tokio::join!(a.send(&frame_a), b.send(&frame_b));
    sent_a.expect("send a");
    sent_b.expect("send b");
    a.wait_applied(3, WAIT).await.expect("a apply");
    b.wait_applied(3, WAIT).await.expect("b apply");

    let order = a.order();
    let last = order
        .iter()
        .filter(|(seq, _)| *seq >= 2)
        .max_by_key(|(seq, _)| *seq)
        .expect("two writes applied");
    let expected = if last.1 == id_a {
        payload_a.clone()
    } else if last.1 == id_b {
        payload_b.clone()
    } else {
        panic!("unknown winner {:?}", last.1);
    };

    let bytes_a = fs::read(dir_a.path().join("f")).expect("read a");
    let bytes_b = fs::read(dir_b.path().join("f")).expect("read b");
    assert_eq!(bytes_a, bytes_b, "both clients must converge");
    assert_eq!(bytes_a, expected, "LWW winner must be the last seq");
    assert!(
        bytes_a == payload_a || bytes_a == payload_b,
        "torn write: first 16 = {:02x?}",
        &bytes_a[..16]
    );
    assert!(a.errors().is_empty(), "A errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B errors: {:?}", b.errors());

    println!(
        "M2 evidence: M2-4 winner_seq={} winner_client={:?} sha256_a={} sha256_b={} \
         length={} no_tearing=true",
        last.0,
        if last.1 == id_a { "A" } else { "B" },
        sha256(&bytes_a),
        sha256(&bytes_b),
        bytes_a.len()
    );

    drop(a);
    drop(b);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-5: non-overlapping writes both survive
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_5_non_overlapping_writes_survive() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir_a = TempDir::new().expect("dir a");
    let dir_b = TempDir::new().expect("dir b");
    let mut a = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x2a; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let mut b = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x2b; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    let (_, create) = a.builder.frame(OpSpec::new(OpClass::CREATE_EXCL, "/f"));
    a.send(&create).await.expect("create");
    a.wait_applied(1, WAIT).await.expect("a create");
    b.wait_applied(1, WAIT).await.expect("b create");

    let low = vec![0x11; 4096];
    let high = vec![0x22; 4096];
    let (_, frame_a) = a.builder.frame(
        OpSpec::new(OpClass::PWRITE, "/f")
            .offset(0)
            .payload(low.clone()),
    );
    let (_, frame_b) = b.builder.frame(
        OpSpec::new(OpClass::PWRITE, "/f")
            .offset(4096)
            .payload(high.clone()),
    );
    let (sent_a, sent_b) = tokio::join!(a.send(&frame_a), b.send(&frame_b));
    sent_a.expect("send a");
    sent_b.expect("send b");
    a.wait_applied(3, WAIT).await.expect("a apply");
    b.wait_applied(3, WAIT).await.expect("b apply");

    let mut expected = vec![0u8; 8192];
    expected[..4096].copy_from_slice(&low);
    expected[4096..].copy_from_slice(&high);
    let bytes_a = fs::read(dir_a.path().join("f")).expect("read a");
    let bytes_b = fs::read(dir_b.path().join("f")).expect("read b");
    assert_eq!(bytes_a, expected, "A lost a non-overlapping range");
    assert_eq!(bytes_b, expected, "B lost a non-overlapping range");
    assert!(a.errors().is_empty(), "A errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B errors: {:?}", b.errors());

    println!(
        "M2 evidence: M2-5 ranges=[0,4096) and [4096,8192) both preserved \
         sha256_a={} sha256_b={}",
        sha256(&bytes_a),
        sha256(&bytes_b)
    );

    drop(a);
    drop(b);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-6: rename/unlink serial arbitration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_6_rename_unlink_serial_arbitration() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir_a = TempDir::new().expect("dir a");
    let dir_b = TempDir::new().expect("dir b");
    let mut a = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x3a; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let mut b = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x3b; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    // Setup: /a = "A", /b = "B".
    for (index, (path, payload)) in [("/a", b"A"), ("/b", b"B")].iter().enumerate() {
        let (_, create) = a
            .builder
            .frame(OpSpec::new(OpClass::CREATE_EXCL, path).mode(0o644));
        a.send(&create).await.expect("create");
        let (_, write) = a.builder.frame(
            OpSpec::new(OpClass::PWRITE, path)
                .offset(0)
                .payload(payload.to_vec()),
        );
        a.send(&write).await.expect("write");
        let expected = 1 + (index as u64 * 2) + 1;
        a.wait_applied(expected, WAIT).await.expect("a setup");
        b.wait_applied(expected, WAIT).await.expect("b setup");
    }

    let (rename_id, rename) = a
        .builder
        .frame(OpSpec::new(OpClass::RENAME, "/a").path2("/b"));
    let (unlink_id, unlink) = b.builder.frame(OpSpec::new(OpClass::UNLINK, "/a"));
    let (sent_a, sent_b) = tokio::join!(a.send(&rename), b.send(&unlink));
    sent_a.expect("send rename");
    sent_b.expect("send unlink");
    a.wait_applied(6, WAIT).await.expect("a arbitration");
    b.wait_applied(6, WAIT).await.expect("b arbitration");

    let a_rename = a.own_verdict(rename_id).expect("A rename verdict");
    let b_unlink = b.own_verdict(unlink_id).expect("B unlink verdict");
    let successes = usize::from(a_rename.is_ok()) + usize::from(b_unlink.is_ok());
    assert_eq!(
        successes, 1,
        "exactly one contender must win: {a_rename:?} {b_unlink:?}"
    );
    assert_eq!(
        a.own_verdict(rename_id),
        b.own_verdict(rename_id),
        "rename verdict differs between clients"
    );
    assert_eq!(
        a.own_verdict(unlink_id),
        b.own_verdict(unlink_id),
        "unlink verdict differs between clients"
    );

    let tree_a = tree(dir_a.path());
    let tree_b = tree(dir_b.path());
    assert_eq!(tree_a, tree_b, "final trees differ");
    assert!(!tree_a.contains_key("a"), "loser left /a behind");
    let b_bytes = fs::read(dir_a.path().join("b")).expect("read /b");
    if a_rename.is_ok() {
        assert_eq!(b_bytes, b"A", "rename winner must replace /b with old /a");
    } else {
        assert_eq!(b_bytes, b"B", "unlink winner must leave old /b intact");
    }
    assert!(a.errors().is_empty(), "A errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B errors: {:?}", b.errors());

    println!(
        "M2 evidence: M2-6 rename_verdict={a_rename:?} unlink_verdict={b_unlink:?} \
         winner={} final_tree={:?}",
        if a_rename.is_ok() { "rename" } else { "unlink" },
        tree_a
    );

    drop(a);
    drop(b);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-7: O_EXCL race
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_7_create_excl_exactly_one_wins() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir_a = TempDir::new().expect("dir a");
    let dir_b = TempDir::new().expect("dir b");
    let mut a = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x4a; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let mut b = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x4b; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    let (id_a, frame_a) = a
        .builder
        .frame(OpSpec::new(OpClass::CREATE_EXCL, "/x").mode(0o644));
    let (id_b, frame_b) = b
        .builder
        .frame(OpSpec::new(OpClass::CREATE_EXCL, "/x").mode(0o644));
    let (sent_a, sent_b) = tokio::join!(a.send(&frame_a), b.send(&frame_b));
    sent_a.expect("send a");
    sent_b.expect("send b");
    a.wait_applied(2, WAIT).await.expect("a apply");
    b.wait_applied(2, WAIT).await.expect("b apply");

    let verdict_a = a.own_verdict(id_a).expect("A verdict");
    let verdict_b = b.own_verdict(id_b).expect("B verdict");
    let successes = usize::from(verdict_a.is_ok()) + usize::from(verdict_b.is_ok());
    assert_eq!(
        successes, 1,
        "exactly one O_EXCL must win: {verdict_a:?} {verdict_b:?}"
    );
    let loser = if verdict_a.is_ok() {
        verdict_b
    } else {
        verdict_a
    };
    assert_eq!(loser, Err(Errno::EEXIST), "loser must see EEXIST");
    assert!(dir_a.path().join("x").is_file(), "A missing /x");
    assert!(dir_b.path().join("x").is_file(), "B missing /x");
    assert!(a.errors().is_empty(), "A errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B errors: {:?}", b.errors());

    println!(
        "M2 evidence: M2-7 verdict_a={verdict_a:?} verdict_b={verdict_b:?} \
         exactly_one_success=true loser=EEXIST"
    );

    drop(a);
    drop(b);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-8: disconnect -> unmount -> exit 10
// ---------------------------------------------------------------------------

fn drive_to_steady(lifecycle: &mut Lifecycle) {
    lifecycle.on(Event::Prepared(Ok(())));
    lifecycle.on(Event::LockAcquired(Ok(())));
    lifecycle.on(Event::Cleaned(Ok(())));
    lifecycle.on(Event::FuseMounted(Ok(())));
    lifecycle.on(Event::Joined(Ok(JoinOutcome {
        epoch: 1,
        covered: 0,
    })));
}

#[test]
fn m2_8_lifecycle_disconnect_unmount_exit10() {
    let mut lifecycle = Lifecycle::new();
    drive_to_steady(&mut lifecycle);
    assert_eq!(lifecycle.state(), State::Steady);

    let actions = lifecycle.on(Event::Disconnected(Cause::Eof));
    assert_eq!(lifecycle.state(), State::Unmounting);
    assert_eq!(lifecycle.exit_code(), 10);
    assert!(actions.contains(&Action::CloseWriteGate));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Quiesce(_)))
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Flush(_)))
    );

    assert_eq!(lifecycle.on(Event::FlushDone), vec![Action::Unmount]);
    let actions = lifecycle.on(Event::UnmountTried(Ok(())));
    assert_eq!(lifecycle.state(), State::Exited);
    assert_eq!(lifecycle.exit_code(), 10);
    assert!(actions.contains(&Action::ReleaseLock));
    assert!(actions.contains(&Action::Exit(10)));

    println!(
        "M2 evidence: M2-8 lifecycle Disconnected(Eof) -> Unmounting -> Unmount -> Exited exit=10"
    );
}

fn smoke_config() -> fuser::Config {
    let mut config = syncmount::fuse::mount_config();
    config
        .mount_options
        .retain(|option| *option != fuser::MountOption::AutoUnmount);
    config.acl = fuser::SessionACL::Owner;
    config
}

fn fuse_ready() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("not Linux".to_string());
    }
    if !Path::new("/dev/fuse").exists() {
        return Err("/dev/fuse is missing".to_string());
    }
    let fusermount = PathBuf::from("/usr/bin/fusermount3");
    if !fusermount.is_file() {
        return Err("fusermount3 not found".to_string());
    }
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(&fusermount).map_err(|error| error.to_string())?;
    if metadata.permissions().mode() & 0o4000 == 0 {
        return Err("fusermount3 is not setuid".to_string());
    }
    Ok(())
}

fn require_fuse() -> bool {
    match fuse_ready() {
        Ok(()) => true,
        Err(reason) => {
            if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                panic!("FUSE required but unavailable: {reason}");
            }
            eprintln!("SKIP[FUSE] {reason}");
            false
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2_8_disconnect_unmount() {
    if !require_fuse() {
        return;
    }

    let server = Server::bind(ServeConfig::for_tests()).await.expect("bind");
    let addr = server.local_addr().expect("local addr");
    let metrics = server.metrics();
    let (stop, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let root = TempDir::new().expect("root");
    let mnt = root.path().join("mnt");
    let run_dir = root.path().join("run");
    fs::create_dir(&mnt).expect("mnt");
    fs::create_dir(&run_dir).expect("run dir");

    let config = Config {
        endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
        mountpoint: mnt.clone(),
        client_id: ClientId::from_bytes([0x8a; 16]),
        instance: InstanceId(1),
        mount_id: "m2-8-disconnect".to_string(),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir,
        allow_empty_view: false,
    };
    let ring =
        Arc::new(KeyRing::derive(&[7u8; 32], &ClusterId::from_bytes([9u8; 16])).expect("key ring"));
    let mut client_task = tokio::spawn(async move { Client::new(config).run(ring).await });

    assert!(
        wait_until(Duration::from_secs(5), || mounted(&mnt)),
        "client did not mount {}",
        mnt.display()
    );
    assert!(
        wait_until(Duration::from_secs(5), || {
            metrics.clients.load(Ordering::Relaxed) >= 1
        }),
        "client did not join"
    );

    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;

    let outcome = tokio::time::timeout(Duration::from_secs(5), &mut client_task).await;
    match outcome {
        Ok(Ok(Ok(code))) => {
            assert_eq!(code, 10, "disconnect must exit 10");
            assert!(
                wait_until(Duration::from_secs(5), || !mounted(&mnt)),
                "mount {} survived disconnect",
                mnt.display()
            );
            println!(
                "M2 evidence: M2-8 real FUSE mount, server shutdown -> client exit=10, \
                 /proc/mounts entry removed"
            );
        }
        Ok(Ok(Err(error))) => panic!("client error: {error}"),
        Ok(Err(join)) => panic!("client task: {join}"),
        Err(_) => {
            let finished = client_task.is_finished();
            let still_mounted = mounted(&mnt);
            println!(
                "M2 evidence: M2-8 real FUSE disconnect: client_exit=timeout task_finished={finished} \
                 mount_present={still_mounted}; fuser AutoUnmount umount_and_join hang"
            );
            client_task.abort();
            force_unmount(&mnt);
            panic!(
                "client did not exit within 5s after disconnect: task_finished={finished} \
                 mount_present={still_mounted}; fuser AutoUnmount umount_and_join is the known \
                 W13a hang (M1 notes the same path)"
            );
        }
    }
}

#[tokio::test]
async fn m2_8_network_disconnect_detected() {
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir = TempDir::new().expect("backing");
    let node = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x8c; 16]),
        dir.path(),
        Arc::clone(&data),
    )
    .await;
    harness.shutdown().await;

    let mut observed = false;
    for _ in 0..200 {
        if node.downlink_done() {
            observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(observed, "downlink did not observe server shutdown");
    println!(
        "M2 evidence: M2-8 transport downlink ended after server shutdown (disconnect detected)"
    );
    drop(node);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2_8_external_unmount_unblocks_client() {
    if !require_fuse() {
        return;
    }

    let server = Server::bind(ServeConfig::for_tests()).await.expect("bind");
    let addr = server.local_addr().expect("local addr");
    let metrics = server.metrics();
    let (stop, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let root = TempDir::new().expect("root");
    let mnt = root.path().join("mnt");
    let run_dir = root.path().join("run");
    fs::create_dir(&mnt).expect("mnt");
    fs::create_dir(&run_dir).expect("run dir");

    let config = Config {
        endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
        mountpoint: mnt.clone(),
        client_id: ClientId::from_bytes([0x8d; 16]),
        instance: InstanceId(2),
        mount_id: "m2-8-external-unmount".to_string(),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir,
        allow_empty_view: false,
    };
    let ring =
        Arc::new(KeyRing::derive(&[7u8; 32], &ClusterId::from_bytes([9u8; 16])).expect("key ring"));
    let mut client_task = tokio::spawn(async move { Client::new(config).run(ring).await });

    assert!(
        wait_until(Duration::from_secs(5), || mounted(&mnt)),
        "client did not mount {}",
        mnt.display()
    );
    assert!(
        wait_until(Duration::from_secs(5), || {
            metrics.clients.load(Ordering::Relaxed) >= 1
        }),
        "client did not join"
    );

    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mounted_before = mounted(&mnt);
    let unmount = Command::new("fusermount3")
        .arg("-u")
        .arg(&mnt)
        .output()
        .expect("run fusermount3 -u");
    let outcome = tokio::time::timeout(Duration::from_secs(5), &mut client_task).await;
    let code = match outcome {
        Ok(Ok(Ok(code))) => Some(code),
        Ok(Ok(Err(error))) => panic!("client error: {error}"),
        Ok(Err(join)) => panic!("client task: {join}"),
        Err(_) => {
            client_task.abort();
            None
        }
    };
    force_unmount(&mnt);
    println!(
        "M2 evidence: M2-8 external unmount: mounted_before={mounted_before}          fusermount3_exit={:?} client_exit={code:?}",
        unmount.status.code()
    );
    assert_eq!(
        code,
        Some(10),
        "external fusermount did not unblock the client; the hang is not only AutoUnmount"
    );
}

#[tokio::test]
async fn m2_8_remount_cluster_wins() {
    // A remount must discard local-only state and install the cluster view.
    // The JOIN runs the W17 cluster-wins step: with an empty cluster the
    // remote manifest is empty, so every local path is `LocalOnly`.
    let harness = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let dir = TempDir::new().expect("backing");
    fs::write(dir.path().join("local-only.txt"), b"local").expect("local-only");
    let node = ClientNode::connect(
        harness.addr,
        ClientId::from_bytes([0x8b; 16]),
        dir.path(),
        Arc::clone(&data),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let survived = dir.path().join("local-only.txt").exists();
    let trash = dir.path().join(".syncmount-staging/trash");
    let mut recovered = Vec::new();
    for entry in fs::read_dir(&trash).expect("trash directory") {
        let path = entry.expect("trash entry").path();
        if path.is_file() {
            recovered.push(fs::read(&path).expect("read trash entry"));
        }
    }
    let report = format!("trash entries={}", recovered.len());
    println!(
        "M2 evidence: M2-8 remount cluster-wins: local-only.txt survived JOIN={survived} ({report})"
    );
    assert!(
        !survived,
        "M2-8 remount cluster-wins not implemented: local-only.txt survived JOIN"
    );
    assert!(
        recovered.iter().any(|bytes| bytes.as_slice() == b"local"),
        "M2-8 cluster-wins must keep the removed bytes readable in trash: {recovered:?}"
    );

    drop(node);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// M2-9: seq gap / epoch -> resync trigger
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m2_9_seq_gap_epoch_resync_trigger() {
    let dir = TempDir::new().expect("backing");
    let backing = PosixBacking::new(RootFd::open_before_mount(dir.path()).expect("root"));
    let data = TestData::default();
    let tuning = Tuning {
        reorder_wait: Duration::from_millis(10),
        ..Tuning::default()
    };
    let client = ClientId::from_bytes([0x9a; 16]);
    let mut replayer = Replayer::new(
        client,
        Seq::UNSEQUENCED,
        1,
        &tuning,
        Arc::new(PendingOverlay::new()),
    );

    let first = op_for(1, client, OpClass::CREATE_EXCL, "/a");
    let progress = replayer
        .on_ordered(first, Duration::ZERO, &backing, &data)
        .expect("seq 1");
    assert_eq!(progress.applied, Seq(1));

    let third = op_for(3, client, OpClass::CREATE_EXCL, "/c");
    let progress = replayer
        .on_ordered(third, Duration::ZERO, &backing, &data)
        .expect("seq 3 buffers");
    assert!(progress.buffered, "seq 3 must wait for seq 2");

    let timeout = replayer
        .poll_timeout(Duration::from_millis(50))
        .expect("gap timeout");
    assert!(
        matches!(timeout, Fatal::Resync(ReplayResyncReason::SeqGap)),
        "expected SeqGap, got {timeout:?}"
    );
    replayer
        .begin_resync(Seq(1), 1, Duration::from_millis(50))
        .expect("begin resync");
    assert_eq!(replayer.applied(), Seq(1));

    let next_epoch = op_for(2, client, OpClass::CREATE_EXCL, "/b");
    let mismatch = IncomingOp::new(Seq(2), 2, next_epoch.op);
    let error = replayer
        .on_ordered(mismatch, Duration::from_millis(60), &backing, &data)
        .expect_err("epoch mismatch");
    assert!(
        matches!(error, Fatal::Resync(ReplayResyncReason::EpochChanged)),
        "expected EpochChanged, got {error:?}"
    );

    let mut lifecycle = Lifecycle::new();
    drive_to_steady(&mut lifecycle);
    let actions = lifecycle.on(Event::Resync(LifecycleResyncReason::SeqGap));
    assert_eq!(lifecycle.state(), State::Joining);
    assert!(
        actions.contains(&Action::StartJoin),
        "resync must re-JOIN: {actions:?}"
    );
    assert!(
        actions.contains(&Action::CloseWriteGate),
        "resync must close the write gate: {actions:?}"
    );

    println!(
        "M2 evidence: M2-9 gap seq=1,3 -> buffered -> SeqGap; begin_resync(covered=1) -> \
         applied=1; epoch 2 frame -> EpochChanged; lifecycle STEADY -> JOINING with StartJoin"
    );
}

// ---------------------------------------------------------------------------
// M2-10: duplicate and shuffled delivery
// ---------------------------------------------------------------------------

fn apply_once(
    replayer: &mut Replayer,
    incoming: IncomingOp,
    backing: &PosixBacking,
    data: &TestData,
    now: Duration,
) {
    let seq = incoming.seq;
    replayer
        .on_ordered(incoming, now, backing, data)
        .unwrap_or_else(|error| panic!("apply seq {seq:?}: {error:?}"));
}

#[test]
fn m2_10_duplicate_and_shuffle_idempotent() {
    let reference_dir = TempDir::new().expect("reference backing");
    let test_dir = TempDir::new().expect("test backing");
    let reference_backing =
        PosixBacking::new(RootFd::open_before_mount(reference_dir.path()).expect("root"));
    let test_backing = PosixBacking::new(RootFd::open_before_mount(test_dir.path()).expect("root"));
    let data = TestData::default();
    let client = ClientId::from_bytes([0xaa; 16]);
    let tuning = Tuning::default();

    let mut reference = Replayer::new(
        client,
        Seq::UNSEQUENCED,
        1,
        &tuning,
        Arc::new(PendingOverlay::new()),
    );
    let mut subject = Replayer::new(
        client,
        Seq::UNSEQUENCED,
        1,
        &tuning,
        Arc::new(PendingOverlay::new()),
    );

    let mut ops = vec![
        op_for(1, client, OpClass::MKDIR, "/d"),
        op_for(2, client, OpClass::CREATE_EXCL, "/d/a"),
        op_for(3, client, OpClass::PWRITE, "/d/a"),
        op_for(4, client, OpClass::CREATE_EXCL, "/d/b"),
        op_for(5, client, OpClass::PWRITE, "/d/b"),
        op_for(6, client, OpClass::RENAME, "/d/a"),
        op_for(7, client, OpClass::UNLINK, "/d/b"),
        op_for(8, client, OpClass::MKDIR, "/d/sub"),
        op_for(9, client, OpClass::CREATE_EXCL, "/d/sub/x"),
        op_for(10, client, OpClass::TRUNCATE, "/d/c"),
    ];

    // Fill the payload/body fields the direct `op_for` helper leaves generic.
    ops[2].op.body = OpBody::Pwrite {
        offset: 0,
        data: DataRef {
            session: SessionId::from_le_bytes([0x31; 16]),
            total_len: 5,
            data_hash: *blake3::hash(b"hello").as_bytes(),
        },
    };
    data.insert(SessionId::from_le_bytes([0x31; 16]), b"hello".to_vec());
    ops[4].op.body = OpBody::Pwrite {
        offset: 0,
        data: DataRef {
            session: SessionId::from_le_bytes([0x32; 16]),
            total_len: 5,
            data_hash: *blake3::hash(b"world").as_bytes(),
        },
    };
    data.insert(SessionId::from_le_bytes([0x32; 16]), b"world".to_vec());
    ops[5].op.body = OpBody::Rename {
        path2: "/d/c".to_string(),
    };
    ops[9].op.body = OpBody::Truncate { length: 2 };

    for (index, op) in ops.iter().enumerate() {
        apply_once(
            &mut reference,
            IncomingOp::new(Seq((index + 1) as u64), 1, op.op.clone()),
            &reference_backing,
            &data,
            Duration::from_millis(index as u64),
        );
    }
    assert_eq!(reference.applied(), Seq(10));

    // Shuffle: every operation arrives ten times, out of order. The reorder
    // buffer holds the future sequences; duplicates replace the same slot and
    // then dedup by op_id.
    let shuffled = [4usize, 0, 8, 2, 6, 9, 1, 7, 3, 5];
    let mut tick = 0u64;
    for _ in 0..10 {
        for index in shuffled {
            let op = &ops[index];
            apply_once(
                &mut subject,
                IncomingOp::new(Seq((index + 1) as u64), 1, op.op.clone()),
                &test_backing,
                &data,
                Duration::from_micros(tick),
            );
            tick += 1;
        }
    }
    assert_eq!(
        subject.applied(),
        Seq(10),
        "shuffled/duplicated stream must drain"
    );
    assert_eq!(
        subject.snapshot_hash(),
        reference.snapshot_hash(),
        "replay state diverged"
    );
    assert_eq!(
        tree(test_dir.path()),
        tree(reference_dir.path()),
        "backing trees diverged"
    );

    println!(
        "M2 evidence: M2-10 ops=10 deliveries=100 (10x dup, shuffled) applied={:?} \
         state_hash={} tree_equal=true",
        subject.applied(),
        hex(&subject.snapshot_hash())
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// M2-11: write p99 (target, non-blocking)
// ---------------------------------------------------------------------------

#[test]
fn m2_11_write_p99() {
    if !require_fuse() {
        return;
    }
    let root = TempDir::new().expect("root");
    let mnt = root.path().join("mnt");
    fs::create_dir(&mnt).expect("mnt");
    let backing = Arc::new(PosixBacking::new(
        RootFd::open_before_mount(&mnt).expect("root"),
    ));
    let filesystem = syncmount::fuse::FuseFs::new(backing);
    let config = smoke_config();
    let session = fuser::Session::new(filesystem, &mnt, &config)
        .expect("fuse session")
        .spawn()
        .expect("spawn fuse");
    assert!(
        wait_until(Duration::from_secs(5), || mounted(&mnt)),
        "mount did not appear"
    );

    let (p99_ms, method) = match run_fio(&mnt) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("fio unavailable or failed: {error}; falling back to pwrite probe");
            (pwrite_probe(&mnt), "pwrite-probe".to_string())
        }
    };

    let _ = Command::new("fusermount3").arg("-u").arg(&mnt).status();
    drop(session);
    let target_met = p99_ms < 5.0;
    println!(
        "M2 evidence: M2-11 method={method} write_p99={p99_ms:.3}ms target_lt_5ms={target_met} \
         (target only; not a release blocker)"
    );
    assert!(p99_ms < 100.0, "write path is unusable: p99 {p99_ms:.3}ms");
}

fn run_fio(mnt: &Path) -> Result<(f64, String), String> {
    let filename = mnt.join("fio.dat");
    let base = [
        "--name=m2_11",
        "--size=32m",
        "--bs=4k",
        "--rw=write",
        "--ioengine=psync",
        "--output-format=json",
        "--group_reporting",
    ];
    for direct in ["1", "0"] {
        let output = Command::new("fio")
            .args(base)
            .arg(format!("--filename={}", filename.display()))
            .arg(format!("--direct={direct}"))
            .output()
            .map_err(|error| format!("spawn fio: {error}"))?;
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|error| format!("fio json: {error}"))?;
        if let Some(ns) = value["jobs"][0]["write"]["clat_ns"]["percentile"]["99.000000"].as_f64() {
            return Ok((ns / 1_000_000.0, format!("fio-direct={direct}")));
        }
    }
    Err("fio did not produce clat_ns p99".to_string())
}

fn pwrite_probe(mnt: &Path) -> f64 {
    let path = mnt.join("probe.dat");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&path)
        .expect("open probe");
    let buffer = [0x5a; 4096];
    let mut samples = Vec::with_capacity(1000);
    for index in 0..1000u64 {
        let started = Instant::now();
        file.write_at(&buffer, index * 4096).expect("pwrite");
        samples.push(started.elapsed());
    }
    samples.sort();
    let index = ((samples.len() as f64 * 0.99).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    samples[index].as_secs_f64() * 1000.0
}

// Keep the unused-import warning honest if a helper stops using it.
#[allow(dead_code)]
fn _namespace_is_public(_namespace: Namespace) {}
