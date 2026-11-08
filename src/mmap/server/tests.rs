//! End-to-end tests for the 1.1 mm HTTP server.
//!
//! Every test opens a real SQLite database in a temporary directory, speaks
//! SMM1 over a real HTTP/1.1 loopback connection, and rebuilds files through
//! the real rsync engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::TcpStream;

use crate::mmap::base;
use crate::mmap::proto::{
    Aborted, BatchState, BatchStateMessage, Checkout, DirVersion, ErrorBody, ErrorCode, FileData,
    FileRead, HEADER_MAC, HEADER_SEQ, HEADER_SESSION, Header, Hello, Instruction,
    InstructionWriter, Limits, LockAcquire, LockGranted, LockRelease, LockRenew, MacParts, Message,
    SessionKeys, SignatureRequest, SignatureState, Signatures, Snapshot, UploadAbort, UploadBegin,
    UploadCommit, UploadMode, UploadPlan, UploadResult, Welcome, decode_frame, derive_hello_key,
    derive_session_key, hello_proof, verify_welcome,
};
use crate::mmap::types::{BatchId, EntryKind, LockId, ROOT_INO};

use super::manifest::wire_manifest_hash;
use super::{MmapConfig, MmapServer, ServerState};

const NS: &str = "/private-mm";
const WIRE_NS: &str = "private-mm";
const MASTER: [u8; 32] = [0x5A; 32];

// ---------------------------------------------------------------------------
// HTTP and SMM1 client
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    state: Arc<ServerState>,
    task: tokio::task::JoinHandle<()>,
    _temp: TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_server() -> TestServer {
    start_server_with(|_| {}).await
}

async fn start_server_with(configure: impl FnOnce(&mut MmapConfig)) -> TestServer {
    let temp = TempDir::new().unwrap();
    let mut config = MmapConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        NS,
        temp.path().join("mm.db"),
        temp.path().join("spool"),
        MASTER,
    );
    configure(&mut config);
    let server = MmapServer::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    let state = server.state();
    let task = tokio::spawn(server.run());
    TestServer {
        addr,
        state,
        task,
        _temp: temp,
    }
}

struct Frame {
    status: u16,
    header: Option<Header>,
    meta: Vec<u8>,
    payload: Vec<u8>,
}

impl Frame {
    fn decode<M: Message>(&self) -> M {
        let header = self.header.as_ref().expect("frame header");
        decode_frame(header, &self.meta).unwrap()
    }

    fn error(&self) -> ErrorBody {
        self.decode()
    }

    fn assert_status(&self, status: u16) {
        assert_eq!(self.status, status, "body: {:?}", self.header);
    }
}

async fn http_call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Vec<u8>,
    headers: &[(&str, String)],
) -> (u16, Vec<u8>) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, "test");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Full::new(Bytes::from(body))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

fn parse_frame(status: u16, bytes: Vec<u8>) -> Frame {
    if bytes.is_empty() {
        return Frame {
            status,
            header: None,
            meta: Vec::new(),
            payload: Vec::new(),
        };
    }
    let header = Header::decode_with_limits(&bytes[..24], &Limits::new()).unwrap();
    let meta_end = 24 + header.meta_len as usize;
    let payload_end = meta_end + header.data_len as usize;
    assert_eq!(bytes.len(), payload_end, "response frame length");
    Frame {
        status,
        header: Some(header),
        meta: bytes[24..meta_end].to_vec(),
        payload: bytes[meta_end..].to_vec(),
    }
}

fn frame_bytes<M: Message>(message: &M, payload: &[u8]) -> Vec<u8> {
    let meta = message.encode_meta().unwrap();
    let header = Header::new(
        M::KIND,
        u32::try_from(meta.len()).unwrap(),
        payload.len() as u64,
        &Limits::new(),
    )
    .unwrap();
    let mut bytes = Vec::with_capacity(24 + meta.len() + payload.len());
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(payload);
    bytes
}

struct Client {
    addr: SocketAddr,
    client_id: [u8; 16],
    session_id: [u8; 16],
    key: [u8; 32],
    seq: u64,
}

impl Client {
    fn new(addr: SocketAddr, client_id: [u8; 16]) -> Self {
        Self {
            addr,
            client_id,
            session_id: [0u8; 16],
            key: [0u8; 32],
            seq: 0,
        }
    }

    async fn hello(&mut self) {
        let now = super::auth::current_timestamp_ms();
        let client_nonce = rand::random::<[u8; 32]>();
        let hello = Hello {
            client_id: self.client_id,
            client_nonce,
            timestamp_ms: now,
            proof: hello_proof(
                &derive_hello_key(&MASTER),
                &self.client_id,
                &client_nonce,
                now,
            ),
        };
        let path = format!("{NS}/mm/v1/hello");
        let (status, bytes) =
            http_call(self.addr, "POST", &path, frame_bytes(&hello, &[]), &[]).await;
        assert_eq!(status, 200, "hello status");
        let frame = parse_frame(status, bytes);
        let welcome: Welcome = frame.decode();
        verify_welcome(&welcome, &derive_hello_key(&MASTER), &hello.client_nonce).unwrap();
        self.session_id = welcome.session_id;
        self.key = derive_session_key(
            &MASTER,
            &hello.client_nonce,
            &welcome.server_nonce,
            &welcome.session_id,
        );
        self.seq = 0;
    }

    fn mac(&self, method: &str, path: &str, seq: u64, meta: &[u8], payload: &[u8]) -> String {
        let parts = MacParts {
            method,
            path,
            seq,
            meta_hash: *blake3::hash(meta).as_bytes(),
            payload_hash: *blake3::hash(payload).as_bytes(),
        };
        let keys = SessionKeys::new(self.key, self.session_id, u64::MAX);
        hex::encode(keys.mac(&parts).unwrap())
    }

    async fn post<M: Message>(&mut self, endpoint: &str, message: &M, payload: &[u8]) -> Frame {
        let path = format!("{NS}/mm/v1/{endpoint}");
        let meta = message.encode_meta().unwrap();
        self.seq += 1;
        let mac = self.mac("POST", &path, self.seq, &meta, payload);
        let headers = [
            (HEADER_SESSION, hex::encode(self.session_id)),
            (HEADER_SEQ, self.seq.to_string()),
            (HEADER_MAC, mac),
        ];
        let (status, bytes) = http_call(
            self.addr,
            "POST",
            &path,
            frame_bytes(message, payload),
            &headers,
        )
        .await;
        parse_frame(status, bytes)
    }

    async fn get(&mut self, endpoint_and_query: &str) -> Frame {
        let path = format!("{NS}/mm/v1/{endpoint_and_query}");
        self.seq += 1;
        let mac = self.mac("GET", &path, self.seq, &[], &[]);
        let headers = [
            (HEADER_SESSION, hex::encode(self.session_id)),
            (HEADER_SEQ, self.seq.to_string()),
            (HEADER_MAC, mac),
        ];
        let (status, bytes) = http_call(self.addr, "GET", &path, Vec::new(), &headers).await;
        parse_frame(status, bytes)
    }

    async fn checkout(&mut self, dir_path: &str) -> Snapshot {
        let frame = self
            .post(
                "checkout",
                &Checkout {
                    namespace: WIRE_NS.to_owned(),
                    dir_path: dir_path.to_owned(),
                    bodies: 0,
                    if_dir_version: None,
                    if_snapshot_seq: None,
                },
                &[],
            )
            .await;
        frame.assert_status(200);
        frame.decode()
    }

    async fn checkout_bodies(&mut self, dir_path: &str) -> (Snapshot, Vec<u8>) {
        let frame = self
            .post(
                "checkout",
                &Checkout {
                    namespace: WIRE_NS.to_owned(),
                    dir_path: dir_path.to_owned(),
                    bodies: 1,
                    if_dir_version: None,
                    if_snapshot_seq: None,
                },
                &[],
            )
            .await;
        frame.assert_status(200);
        let snapshot = frame.decode();
        (snapshot, frame.payload)
    }

    async fn lock(&mut self, dir_path: &str) -> LockGranted {
        let frame = self
            .post(
                "lock/acquire",
                &LockAcquire {
                    namespace: WIRE_NS.to_owned(),
                    dir_path: dir_path.to_owned(),
                    client_id: self.client_id,
                    session_id: self.session_id,
                    lock_id: None,
                },
                &[],
            )
            .await;
        frame.assert_status(200);
        frame.decode()
    }

    async fn begin(
        &mut self,
        snapshot: &Snapshot,
        lock: &LockGranted,
        mut entries: Vec<crate::mmap::proto::Entry>,
        mode: UploadMode,
    ) -> (Batch, UploadPlan) {
        entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        let structural = entries
            .iter()
            .filter(|entry| entry.kind == crate::mmap::proto::EntryKind::Dir)
            .cloned()
            .collect::<Vec<_>>();
        let batch_id = BatchId::new_random();
        let manifest_hash = wire_manifest_hash(&entries).unwrap();
        let request = UploadBegin {
            namespace: WIRE_NS.to_owned(),
            dir_path: snapshot.dir_path.clone(),
            dir_ino: snapshot.dir_ino,
            epoch: snapshot.epoch,
            base_seq: snapshot.base_seq,
            dir_version: snapshot.dir_version,
            batch_id: *batch_id.as_bytes(),
            lock_id: lock.lock_id,
            client_id: self.client_id,
            manifest_hash,
            entries,
            structural,
            dir_attrs: snapshot.dir_attrs,
            mode,
        };
        let frame = self.post("upload/begin", &request, &[]).await;
        frame.assert_status(200);
        let plan: UploadPlan = frame.decode();
        (
            Batch {
                batch_id,
                lock_id: LockId::from_bytes(lock.lock_id),
                epoch: request.epoch,
                base_seq: request.base_seq,
                dir_version: request.dir_version,
                manifest_hash,
                entries: request.entries.clone(),
            },
            plan,
        )
    }

    async fn commit(&mut self, batch: &Batch, payload: Vec<u8>) -> Frame {
        self.post(
            "upload/commit",
            &UploadCommit {
                namespace: WIRE_NS.to_owned(),
                batch_id: *batch.batch_id.as_bytes(),
                lock_id: *batch.lock_id.as_bytes(),
                epoch: batch.epoch,
                base_seq: batch.base_seq,
                dir_version: batch.dir_version,
                manifest_hash: batch.manifest_hash,
            },
            &payload,
        )
        .await
    }

    async fn commit_ok(&mut self, batch: &Batch, payload: Vec<u8>) -> UploadResult {
        let frame = self.commit(batch, payload).await;
        frame.assert_status(200);
        frame.decode()
    }
}

struct Batch {
    batch_id: BatchId,
    lock_id: LockId,
    epoch: u64,
    base_seq: u64,
    dir_version: [u8; 32],
    manifest_hash: [u8; 32],
    entries: Vec<crate::mmap::proto::Entry>,
}

// ---------------------------------------------------------------------------
// Manifest helpers
// ---------------------------------------------------------------------------

fn chunk_refs(content: &[u8]) -> Vec<crate::store::sqlite::ChunkRef> {
    content
        .chunks(65_536)
        .enumerate()
        .map(|(index, bytes)| crate::store::sqlite::ChunkRef {
            chunk_no: index as u32,
            hash: *blake3::hash(bytes).as_bytes(),
            offset: index as u64 * 65_536,
            len: bytes.len() as u32,
        })
        .collect()
}

fn file_root(content: &[u8]) -> [u8; 32] {
    base::file_root(EntryKind::File, None, &chunk_refs(content))
}

fn put_file(name: &str, ino: [u8; 16], content: &[u8], mtime: u64) -> crate::mmap::proto::Entry {
    crate::mmap::proto::Entry {
        name: name.to_owned(),
        ino: Some(ino),
        kind: crate::mmap::proto::EntryKind::File,
        op: crate::mmap::proto::EntryOp::Put,
        from_name: None,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: mtime,
        size: content.len() as u64,
        file_root: Some(file_root(content)),
        content_hash: Some(*blake3::hash(content).as_bytes()),
        target: None,
    }
}

fn put_dir(name: &str, ino: [u8; 16]) -> crate::mmap::proto::Entry {
    crate::mmap::proto::Entry {
        name: name.to_owned(),
        ino: Some(ino),
        kind: crate::mmap::proto::EntryKind::Dir,
        op: crate::mmap::proto::EntryOp::DirAdd,
        from_name: None,
        mode: 0o755,
        uid: 1000,
        gid: 1000,
        mtime_ns: 11,
        size: 0,
        file_root: Some(base::dir_root()),
        content_hash: None,
        target: None,
    }
}

fn put_symlink(name: &str, ino: [u8; 16], target: &[u8]) -> crate::mmap::proto::Entry {
    crate::mmap::proto::Entry {
        name: name.to_owned(),
        ino: Some(ino),
        kind: crate::mmap::proto::EntryKind::Symlink,
        op: crate::mmap::proto::EntryOp::Put,
        from_name: None,
        mode: 0o777,
        uid: 1000,
        gid: 1000,
        mtime_ns: 12,
        size: target.len() as u64,
        file_root: Some(base::symlink_root(target)),
        content_hash: None,
        target: Some(target.to_vec()),
    }
}

fn rename(mut entry: crate::mmap::proto::Entry, from: &str, to: &str) -> crate::mmap::proto::Entry {
    entry.name = to.to_owned();
    entry.from_name = Some(from.to_owned());
    entry.op = crate::mmap::proto::EntryOp::Rename;
    entry
}

fn rename_dir(
    mut entry: crate::mmap::proto::Entry,
    from: &str,
    to: &str,
) -> crate::mmap::proto::Entry {
    entry.name = to.to_owned();
    entry.from_name = Some(from.to_owned());
    entry.op = crate::mmap::proto::EntryOp::DirRename;
    entry
}

fn delete(mut entry: crate::mmap::proto::Entry) -> crate::mmap::proto::Entry {
    entry.op = crate::mmap::proto::EntryOp::Delete;
    entry.content_hash = None;
    entry.file_root = None;
    entry.target = None;
    entry.size = 0;
    entry
}

fn remove_dir(mut entry: crate::mmap::proto::Entry) -> crate::mmap::proto::Entry {
    entry.op = crate::mmap::proto::EntryOp::DirRemove;
    entry
}

fn instructions(
    entries: &[crate::mmap::proto::Entry],
    contents: &HashMap<String, Vec<u8>>,
) -> Vec<u8> {
    let mut writer = InstructionWriter::new(Vec::new());
    for (index, entry) in entries.iter().enumerate() {
        if entry.kind != crate::mmap::proto::EntryKind::File
            || entry.op == crate::mmap::proto::EntryOp::Delete
        {
            continue;
        }
        let file = u32::try_from(index).unwrap();
        match entry.op {
            crate::mmap::proto::EntryOp::Put => {
                let content = contents.get(&entry.name).expect("PUT content");
                for chunk in content.chunks(8 * 1024 * 1024) {
                    writer
                        .write(Instruction::Literal {
                            file_index: file,
                            len: u32::try_from(chunk.len()).unwrap(),
                        })
                        .unwrap();
                    writer.write_literal(chunk).unwrap();
                }
                writer
                    .write(Instruction::EndFile { file_index: file })
                    .unwrap();
            }
            crate::mmap::proto::EntryOp::Keep | crate::mmap::proto::EntryOp::Rename => {
                writer
                    .write(Instruction::Unchanged {
                        file_index: file,
                        content_hash: entry.content_hash.expect("content hash"),
                    })
                    .unwrap();
                writer
                    .write(Instruction::EndFile { file_index: file })
                    .unwrap();
            }
            _ => {}
        }
    }
    writer.write(Instruction::EndBatch).unwrap();
    writer.finish().unwrap()
}

fn entries_of(snapshot: &Snapshot) -> Vec<crate::mmap::proto::Entry> {
    snapshot.entries.clone()
}

fn find<'a>(entries: &'a [crate::mmap::proto::Entry], name: &str) -> &'a crate::mmap::proto::Entry {
    entries.iter().find(|entry| entry.name == name).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn healthz_auth_checkout_and_304() {
    let server = start_server().await;
    let (status, bytes) =
        http_call(server.addr, "GET", "/__syncmount/healthz", Vec::new(), &[]).await;
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("\"status\":\"ok\""));
    assert!(text.contains("\"mode\":\"mmap\""));

    let mut client = Client::new(server.addr, [1u8; 16]);
    client.hello().await;

    let snapshot = client.checkout("/").await;
    assert_eq!(snapshot.dir_path, "/");
    assert_eq!(snapshot.dir_ino, ROOT_INO);
    assert_eq!(snapshot.base_seq, 1);
    assert_eq!(snapshot.snapshot_seq, 0);
    assert!(snapshot.entries.is_empty());

    let frame = client
        .post(
            "checkout",
            &Checkout {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                bodies: 0,
                if_dir_version: Some(snapshot.dir_version),
                if_snapshot_seq: None,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 304);
    assert!(frame.header.is_none());

    // Unknown directory is a 404 with the SMM1 error vocabulary.
    let frame = client
        .post(
            "checkout",
            &Checkout {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/missing".to_owned(),
                bodies: 0,
                if_dir_version: None,
                if_snapshot_seq: None,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 404);
    assert_eq!(frame.error().code, ErrorCode::DirNotFound);
}

#[tokio::test]
async fn request_mac_and_sequence_are_enforced() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [2u8; 16]);
    client.hello().await;

    // A forged MAC is rejected and does not advance the sequence.
    let path = format!("{NS}/mm/v1/checkout");
    let message = Checkout {
        namespace: WIRE_NS.to_owned(),
        dir_path: "/".to_owned(),
        bodies: 0,
        if_dir_version: None,
        if_snapshot_seq: None,
    };
    let meta = message.encode_meta().unwrap();
    client.seq += 1;
    let seq = client.seq;
    let headers = [
        (HEADER_SESSION, hex::encode(client.session_id)),
        (HEADER_SEQ, seq.to_string()),
        (HEADER_MAC, "00".repeat(32)),
    ];
    let (status, bytes) = http_call(
        server.addr,
        "POST",
        &path,
        frame_bytes(&message, &[]),
        &headers,
    )
    .await;
    let frame = parse_frame(status, bytes);
    assert_eq!(frame.status, 401);
    assert_eq!(frame.error().code, ErrorCode::AuthFailed);

    // The same sequence still works with the right MAC.
    let mac = client.mac("POST", &path, seq, &meta, &[]);
    let headers = [
        (HEADER_SESSION, hex::encode(client.session_id)),
        (HEADER_SEQ, seq.to_string()),
        (HEADER_MAC, mac),
    ];
    let (status, bytes) = http_call(
        server.addr,
        "POST",
        &path,
        frame_bytes(&message, &[]),
        &headers,
    )
    .await;
    parse_frame(status, bytes).assert_status(200);

    // Replay of an accepted sequence fails.
    let headers = [
        (HEADER_SESSION, hex::encode(client.session_id)),
        (HEADER_SEQ, seq.to_string()),
        (HEADER_MAC, client.mac("POST", &path, seq, &meta, &[])),
    ];
    let (status, bytes) = http_call(
        server.addr,
        "POST",
        &path,
        frame_bytes(&message, &[]),
        &headers,
    )
    .await;
    let frame = parse_frame(status, bytes);
    assert_eq!(frame.status, 401);
    assert_eq!(frame.error().code, ErrorCode::AuthFailed);
}

#[tokio::test]
async fn lock_is_exclusive_but_checkout_is_not_and_expiry_is_enforced() {
    let server = start_server_with(|config| {
        config.lock_ttl_ms = 20;
    })
    .await;
    let mut first = Client::new(server.addr, [3u8; 16]);
    let mut second = Client::new(server.addr, [4u8; 16]);
    first.hello().await;
    second.hello().await;

    let granted = first.lock("/").await;
    assert_eq!(granted.dir_path, "/");
    assert_eq!(granted.base_seq, 1);
    assert_eq!(granted.ttl_ms, 20);

    // Checkout never reads the lock.
    first.checkout("/").await;

    let frame = second
        .post(
            "lock/acquire",
            &LockAcquire {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                client_id: second.client_id,
                session_id: second.session_id,
                lock_id: None,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 423);
    let error = frame.error();
    assert_eq!(error.code, ErrorCode::LockHeld);
    assert_eq!(error.owner_client, Some(first.client_id));
    assert!(error.retry_after_ms.is_some());

    // Releasing is idempotent.
    let frame = first
        .post(
            "lock/release",
            &LockRelease {
                lock_id: granted.lock_id,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 204);
    let frame = first
        .post(
            "lock/release",
            &LockRelease {
                lock_id: granted.lock_id,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 204);

    // A short lease expires and renewal reports LOCK_EXPIRED.
    let granted = second.lock("/").await;
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let frame = second
        .post(
            "lock/renew",
            &LockRenew {
                lock_id: granted.lock_id,
                progress_bytes: Some(0),
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 423);
    assert_eq!(frame.error().code, ErrorCode::LockExpired);
    second.checkout("/").await;
}

#[tokio::test]
async fn upload_adds_reads_and_is_idempotent() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [5u8; 16]);
    client.hello().await;

    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let content = b"hello".to_vec();
    let mut entries = entries_of(&snapshot);
    entries.push(put_file("a.txt", [1; 16], &content, 20));
    let (batch, plan) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    assert_eq!(plan.plan.len(), 1);

    let mut contents = HashMap::new();
    contents.insert("a.txt".to_owned(), content.clone());
    let payload = instructions(&batch.entries, &contents);
    let result = client.commit_ok(&batch, payload).await;
    assert_eq!(result.snapshot_seq, 1);
    assert_eq!(result.base_seq_after, 2);
    assert_eq!(result.entry_count, 1);
    assert_eq!(result.bytes, 5);

    // Repeated commit with the same batch id returns the stored result and
    // does not advance the sequence again.
    let repeated = client.commit_ok(&batch, Vec::new()).await;
    assert_eq!(repeated, result);

    let (snapshot, bodies) = client.checkout_bodies("/").await;
    assert_eq!(snapshot.snapshot_seq, 1);
    assert_eq!(snapshot.entries.len(), 1);
    let entry = &snapshot.entries[0];
    assert_eq!(entry.name, "a.txt");
    assert_eq!(entry.size, 5);
    assert_eq!(entry.content_hash, Some(*blake3::hash(&content).as_bytes()));
    assert_eq!(bodies, content);

    let frame = client
        .post(
            "file/read",
            &FileRead {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                name: "a.txt".to_owned(),
                ino: entry.ino.unwrap(),
                file_root: entry.file_root.unwrap(),
                range_offset: 1,
                range_len: 3,
            },
            &[],
        )
        .await;
    frame.assert_status(200);
    let data: FileData = frame.decode();
    assert_eq!(data.range_offset, 1);
    assert_eq!(data.range_len, 3);
    assert_eq!(data.range_hash, *blake3::hash(b"ell").as_bytes());
    assert_eq!(frame.payload, b"ell");

    let version = client
        .get(&format!("version?dir_ino={}", hex::encode(ROOT_INO)))
        .await;
    version.assert_status(200);
    let version: DirVersion = version.decode();
    assert_eq!(version.dir_path, "/");
    assert_eq!(version.base_seq, 2);
    assert_eq!(version.dir_version, result.dir_version_after);

    let status = client
        .get(&format!("batch/{}", hex::encode(batch.batch_id.as_bytes())))
        .await;
    status.assert_status(200);
    let status: BatchStateMessage = status.decode();
    assert_eq!(status.state, BatchState::Committed);
    assert_eq!(status.snapshot_seq, Some(result.snapshot_seq));
}

#[tokio::test]
async fn signatures_and_copy_rebuild_a_delta() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [6u8; 16]);
    client.hello().await;

    // Seed a file.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let base_content = b"hello".to_vec();
    let mut entries = entries_of(&snapshot);
    entries.push(put_file("a.txt", [1; 16], &base_content, 20));
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let mut contents = HashMap::new();
    contents.insert("a.txt".to_owned(), base_content.clone());
    let payload = instructions(&batch.entries, &contents);
    client.commit_ok(&batch, payload).await;

    // The next upload asks for signatures.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let new_content = b"hello world".to_vec();
    let request = SignatureRequest {
        namespace: WIRE_NS.to_owned(),
        dir_path: "/".to_owned(),
        dir_ino: snapshot.dir_ino,
        epoch: snapshot.epoch,
        base_seq: snapshot.base_seq,
        dir_version: snapshot.dir_version,
        lock_id: lock.lock_id,
        batch_id: *BatchId::new_random().as_bytes(),
        files: vec![crate::mmap::proto::SignatureFile {
            name: "a.txt".to_owned(),
            ino: Some(find(&snapshot.entries, "a.txt").ino.unwrap()),
            size: new_content.len() as u64,
            local_file_root: file_root(&new_content),
        }],
    };
    let frame = client.post("signatures", &request, &[]).await;
    // A signature request needs a live upload row; create the batch first.
    assert_eq!(frame.status, 404);
    let _ = frame;

    let mut entries = entries_of(&snapshot);
    entries.retain(|entry| entry.name != "a.txt");
    entries.push(put_file(
        "a.txt",
        find(&snapshot.entries, "a.txt").ino.unwrap(),
        &new_content,
        21,
    ));
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let request = SignatureRequest {
        batch_id: *batch.batch_id.as_bytes(),
        ..request
    };
    let frame = client.post("signatures", &request, &[]).await;
    frame.assert_status(200);
    let signatures: Signatures = frame.decode();
    assert_eq!(signatures.files.len(), 1);
    let signature = &signatures.files[0];
    assert_eq!(signature.state, SignatureState::Delta);
    assert!(signature.block_count >= 1);
    let block = signature.blocks[0];
    assert_eq!(block.block_len, base_content.len() as u32);

    let mut writer = InstructionWriter::new(Vec::new());
    writer
        .write(Instruction::Copy {
            file_index: 0,
            block_index: 0,
            strong: block.strong,
        })
        .unwrap();
    writer
        .write(Instruction::Literal {
            file_index: 0,
            len: 6,
        })
        .unwrap();
    writer.write_literal(b" world").unwrap();
    writer
        .write(Instruction::EndFile { file_index: 0 })
        .unwrap();
    writer.write(Instruction::EndBatch).unwrap();
    let payload = writer.finish().unwrap();
    let result = client.commit_ok(&batch, payload).await;
    assert_eq!(result.bytes, new_content.len() as u64);

    let (_, bodies) = client.checkout_bodies("/").await;
    assert_eq!(bodies, new_content);
}

#[tokio::test]
async fn large_literals_span_the_instruction_reader_buffer() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [16u8; 16]);
    client.hello().await;

    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let first = vec![0xABu8; 150_000];
    let second = vec![0xCDu8; 130_000];
    let entries = vec![
        put_file("a.bin", [1; 16], &first, 20),
        put_file("b.bin", [2; 16], &second, 21),
    ];
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let mut contents = HashMap::new();
    contents.insert("a.bin".to_owned(), first.clone());
    contents.insert("b.bin".to_owned(), second.clone());
    let payload = instructions(&batch.entries, &contents);
    let result = client.commit_ok(&batch, payload).await;
    assert_eq!(result.bytes, (first.len() + second.len()) as u64);

    let (snapshot, bodies) = client.checkout_bodies("/").await;
    assert_eq!(snapshot.entries.len(), 2);
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(bodies, expected);
}

#[tokio::test]
async fn errors_and_rollback_leave_the_tree_untouched() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [7u8; 16]);
    client.hello().await;

    // MANIFEST_INCOMPLETE: the manifest omits the current entry.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let frame = client
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq,
                dir_version: snapshot.dir_version,
                batch_id: *BatchId::new_random().as_bytes(),
                lock_id: lock.lock_id,
                client_id: client.client_id,
                manifest_hash: wire_manifest_hash(&[]).unwrap(),
                entries: Vec::new(),
                structural: Vec::new(),
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    // The root is empty, so this is a valid empty manifest rather than an
    // incomplete one. It begins successfully; abort it.
    assert_eq!(frame.status, 200);
    let plan: UploadPlan = frame.decode();
    let abort = client
        .post(
            "upload/abort",
            &UploadAbort {
                batch_id: plan.batch_id,
                lock_id: lock.lock_id,
            },
            &[],
        )
        .await;
    abort.assert_status(200);

    // Seed a file.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let old = b"hello".to_vec();
    let mut entries = entries_of(&snapshot);
    entries.push(put_file("a.txt", [1; 16], &old, 20));
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let mut contents = HashMap::new();
    contents.insert("a.txt".to_owned(), old.clone());
    let payload = instructions(&batch.entries, &contents);
    let seeded = client.commit_ok(&batch, payload).await;
    assert_eq!(seeded.snapshot_seq, 1);

    // The manifest must list every direct entry. Omitting the committed file
    // is MANIFEST_INCOMPLETE, not an implicit delete.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let empty: Vec<crate::mmap::proto::Entry> = Vec::new();
    let frame = client
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq,
                dir_version: snapshot.dir_version,
                batch_id: *BatchId::new_random().as_bytes(),
                lock_id: lock.lock_id,
                client_id: client.client_id,
                manifest_hash: wire_manifest_hash(&empty).unwrap(),
                entries: empty,
                structural: Vec::new(),
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 409);
    let error = frame.error();
    assert_eq!(error.code, ErrorCode::ManifestIncomplete);
    assert_eq!(error.missing, vec!["a.txt".to_owned()]);

    // HASH_MISMATCH: the manifest promises different bytes than the stream.
    let mut entries = entries_of(&snapshot);
    let mut changed = put_file("a.txt", [1; 16], b"good", 21);
    changed.name = "a.txt".to_owned();
    entries.retain(|entry| entry.name != "a.txt");
    entries.push(changed);
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let mut writer = InstructionWriter::new(Vec::new());
    writer
        .write(Instruction::Literal {
            file_index: 0,
            len: 3,
        })
        .unwrap();
    writer.write_literal(b"bad").unwrap();
    writer
        .write(Instruction::EndFile { file_index: 0 })
        .unwrap();
    writer.write(Instruction::EndBatch).unwrap();
    let payload = writer.finish().unwrap();
    let frame = client.commit(&batch, payload).await;
    assert_eq!(frame.status, 422);
    let error = frame.error();
    assert_eq!(error.code, ErrorCode::HashMismatch);
    assert!(error.retry_full);

    // Tree and sequence are unchanged.
    let (snapshot, bodies) = client.checkout_bodies("/").await;
    assert_eq!(snapshot.snapshot_seq, 1);
    assert_eq!(bodies, old);
    let status = client
        .get(&format!("batch/{}", hex::encode(batch.batch_id.as_bytes())))
        .await;
    status.assert_status(200);
    let status: BatchStateMessage = status.decode();
    assert_eq!(status.state, BatchState::Open);

    // Abort releases the failed batch and lock.
    let abort = client
        .post(
            "upload/abort",
            &UploadAbort {
                batch_id: *batch.batch_id.as_bytes(),
                lock_id: *batch.lock_id.as_bytes(),
            },
            &[],
        )
        .await;
    abort.assert_status(200);
    let aborted: Aborted = abort.decode();
    assert_eq!(aborted.batch_id, *batch.batch_id.as_bytes());
    client.lock("/").await;
}

#[tokio::test]
async fn directory_add_rename_and_remove_rules() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [8u8; 16]);
    client.hello().await;

    // Add an empty child directory.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let mut entries = entries_of(&snapshot);
    entries.push(put_dir("sub", [2; 16]));
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    client.commit_ok(&batch, payload).await;

    let root = client.checkout("/").await;
    let sub = find(&root.entries, "sub");
    assert_eq!(sub.op, crate::mmap::proto::EntryOp::Keep);
    assert_eq!(sub.kind, crate::mmap::proto::EntryKind::Dir);
    let child = client.checkout("/sub").await;
    assert_eq!(child.dir_ino, [2; 16]);
    assert!(child.entries.is_empty());

    // Add a file inside the child directory.
    let lock = client.lock("/sub").await;
    let mut child_entries = entries_of(&child);
    child_entries.push(put_file("inner.txt", [3; 16], b"inner", 30));
    let (batch, _) = client
        .begin(&child, &lock, child_entries, UploadMode::Delta)
        .await;
    let mut contents = HashMap::new();
    contents.insert("inner.txt".to_owned(), b"inner".to_vec());
    let payload = instructions(&batch.entries, &contents);
    client.commit_ok(&batch, payload).await;

    // Removing a non-empty directory fails without changing the tree.
    let root = client.checkout("/").await;
    let lock = client.lock("/").await;
    let mut entries = vec![remove_dir(find(&root.entries, "sub").clone())];
    let (batch, _) = client
        .begin(&root, &lock, entries.clone(), UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    let frame = client.commit(&batch, payload).await;
    assert_eq!(frame.status, 409);
    assert_eq!(frame.error().code, ErrorCode::DirNotEmpty);
    assert_eq!(client.checkout("/").await.entries.len(), 1);
    let abort = client
        .post(
            "upload/abort",
            &UploadAbort {
                batch_id: *batch.batch_id.as_bytes(),
                lock_id: *batch.lock_id.as_bytes(),
            },
            &[],
        )
        .await;
    abort.assert_status(200);

    // Rename the directory; the child content survives and its path moves.
    let _ = entries.pop();
    let lock = client.lock("/").await;
    let mut child_entry = find(&root.entries, "sub").clone();
    child_entry = rename_dir(child_entry, "sub", "renamed");
    let entries = vec![child_entry];
    let (batch, _) = client.begin(&root, &lock, entries, UploadMode::Delta).await;
    let payload = instructions(&batch.entries, &HashMap::new());
    client.commit_ok(&batch, payload).await;

    let root = client.checkout("/").await;
    assert!(find(&root.entries, "renamed").kind == crate::mmap::proto::EntryKind::Dir);
    let child = client.checkout("/renamed").await;
    assert_eq!(child.dir_ino, [2; 16]);
    assert_eq!(child.entries.len(), 1);
    assert_eq!(child.entries[0].name, "inner.txt");

    // Remove the file, then the empty directory.
    let lock = client.lock("/renamed").await;
    let mut child_entries = entries_of(&child);
    let inner = child_entries.pop().unwrap();
    child_entries.push(delete(inner));
    let (batch, _) = client
        .begin(&child, &lock, child_entries, UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    client.commit_ok(&batch, payload).await;
    assert!(client.checkout("/renamed").await.entries.is_empty());

    let root = client.checkout("/").await;
    let lock = client.lock("/").await;
    let entries = vec![remove_dir(find(&root.entries, "renamed").clone())];
    let (batch, _) = client.begin(&root, &lock, entries, UploadMode::Delta).await;
    let payload = instructions(&batch.entries, &HashMap::new());
    client.commit_ok(&batch, payload).await;
    assert!(client.checkout("/").await.entries.is_empty());
}

#[tokio::test]
async fn file_rename_symlink_and_shm_blob_are_direct_entries() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [9u8; 16]);
    client.hello().await;

    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let blob = vec![0u8, 1, 2, 0xff, 0x00];
    let entries = vec![
        put_file("a.txt", [1; 16], b"one", 20),
        put_symlink("link", [2; 16], b"a.txt"),
        put_file("data-shm", [3; 16], &blob, 22),
    ];
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let mut contents = HashMap::new();
    contents.insert("a.txt".to_owned(), b"one".to_vec());
    contents.insert("data-shm".to_owned(), blob.clone());
    let payload = instructions(&batch.entries, &contents);
    client.commit_ok(&batch, payload).await;

    // Rename a.txt -> b.txt while keeping its inode and content.
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let mut entries = entries_of(&snapshot);
    let a = find(&entries, "a.txt").clone();
    entries.retain(|entry| entry.name != "a.txt");
    entries.push(rename(a, "a.txt", "b.txt"));
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    client.commit_ok(&batch, payload).await;

    let (snapshot, bodies) = client.checkout_bodies("/").await;
    assert!(snapshot.entries.iter().any(|entry| entry.name == "b.txt"));
    assert!(!snapshot.entries.iter().any(|entry| entry.name == "a.txt"));
    let link = find(&snapshot.entries, "link");
    assert_eq!(link.kind, crate::mmap::proto::EntryKind::Symlink);
    assert_eq!(link.target.as_deref(), Some(&b"a.txt"[..]));
    let mut expected = b"one".to_vec();
    expected.extend_from_slice(&blob);
    assert_eq!(bodies, expected);
    assert_eq!(find(&snapshot.entries, "b.txt").size, 3);
}

#[tokio::test]
async fn directory_rename_respects_subtree_locks() {
    let server = start_server().await;
    let mut owner = Client::new(server.addr, [14u8; 16]);
    let mut blocker = Client::new(server.addr, [15u8; 16]);
    owner.hello().await;
    blocker.hello().await;

    let snapshot = owner.checkout("/").await;
    let lock = owner.lock("/").await;
    let entries = vec![put_dir("sub", [2; 16])];
    let (batch, _) = owner
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    owner.commit_ok(&batch, payload).await;

    let child_lock = blocker.lock("/sub").await;
    let snapshot = owner.checkout("/").await;
    let lock = owner.lock("/").await;
    let entries = vec![rename_dir(
        find(&snapshot.entries, "sub").clone(),
        "sub",
        "renamed",
    )];
    let structural = entries
        .iter()
        .filter(|entry| entry.kind == crate::mmap::proto::EntryKind::Dir)
        .cloned()
        .collect::<Vec<_>>();
    let frame = owner
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq,
                dir_version: snapshot.dir_version,
                batch_id: *BatchId::new_random().as_bytes(),
                lock_id: lock.lock_id,
                client_id: owner.client_id,
                manifest_hash: wire_manifest_hash(&entries).unwrap(),
                entries,
                structural,
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 423);
    assert_eq!(frame.error().code, ErrorCode::LockHeld);

    let release = blocker
        .post(
            "lock/release",
            &LockRelease {
                lock_id: child_lock.lock_id,
            },
            &[],
        )
        .await;
    assert_eq!(release.status, 204);

    let entries = vec![rename_dir(
        find(&owner.checkout("/").await.entries, "sub").clone(),
        "sub",
        "renamed",
    )];
    let (batch, _) = owner
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    let payload = instructions(&batch.entries, &HashMap::new());
    owner.commit_ok(&batch, payload).await;
    assert!(
        owner
            .checkout("/")
            .await
            .entries
            .iter()
            .any(|entry| entry.name == "renamed")
    );
}

#[tokio::test]
async fn base_change_batch_conflict_and_404_are_reported() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [10u8; 16]);
    client.hello().await;
    let snapshot = client.checkout("/").await;

    let frame = client
        .get(&format!("batch/{}", hex::encode([0xAA; 16])))
        .await;
    assert_eq!(frame.status, 404);
    assert_eq!(frame.error().code, ErrorCode::BatchNotFound);

    let frame = client
        .get(&format!("version?dir_ino={}", hex::encode([0xBB; 16])))
        .await;
    assert_eq!(frame.status, 404);
    assert_eq!(frame.error().code, ErrorCode::DirNotFound);

    // BASE_CHANGED carries the server's current base.
    let lock = client.lock("/").await;
    let entries = vec![put_file("x", [1; 16], b"x", 20)];
    let batch_id = BatchId::new_random();
    let manifest_hash = wire_manifest_hash(&entries).unwrap();
    let frame = client
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq + 7,
                dir_version: snapshot.dir_version,
                batch_id: *batch_id.as_bytes(),
                lock_id: lock.lock_id,
                client_id: client.client_id,
                manifest_hash,
                entries,
                structural: Vec::new(),
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 409);
    let error = frame.error();
    assert_eq!(error.code, ErrorCode::BaseChanged);
    assert_eq!(error.base_seq, Some(snapshot.base_seq));
    assert_eq!(error.request_base_seq, Some(snapshot.base_seq + 7));
    assert_eq!(error.dir_version, Some(snapshot.dir_version));

    // BATCH_CONFLICT: same id, different manifest. The first begin is valid
    // for the empty root and stays open; the second reuses the id.
    let empty: Vec<crate::mmap::proto::Entry> = Vec::new();
    let frame = client
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq,
                dir_version: snapshot.dir_version,
                batch_id: *batch_id.as_bytes(),
                lock_id: lock.lock_id,
                client_id: client.client_id,
                manifest_hash: wire_manifest_hash(&empty).unwrap(),
                entries: empty,
                structural: Vec::new(),
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    frame.assert_status(200);

    let entries = vec![put_file("y", [2; 16], b"y", 21)];
    let manifest_hash = wire_manifest_hash(&entries).unwrap();
    let frame = client
        .post(
            "upload/begin",
            &UploadBegin {
                namespace: WIRE_NS.to_owned(),
                dir_path: "/".to_owned(),
                dir_ino: snapshot.dir_ino,
                epoch: snapshot.epoch,
                base_seq: snapshot.base_seq,
                dir_version: snapshot.dir_version,
                batch_id: *batch_id.as_bytes(),
                lock_id: lock.lock_id,
                client_id: client.client_id,
                manifest_hash,
                entries,
                structural: Vec::new(),
                dir_attrs: snapshot.dir_attrs,
                mode: UploadMode::Delta,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 409);
    assert_eq!(frame.error().code, ErrorCode::BatchConflict);
}

#[tokio::test]
async fn a_payload_over_the_limit_is_413() {
    let server = start_server_with(|config| {
        config.limits = Limits {
            max_data_len: 8,
            ..Limits::new()
        };
    })
    .await;
    let mut client = Client::new(server.addr, [11u8; 16]);
    client.hello().await;
    // A checkout frame declares an 8-byte payload; the cap rejects it before
    // any meta is parsed.
    let path = format!("{NS}/mm/v1/checkout");
    let message = Checkout {
        namespace: WIRE_NS.to_owned(),
        dir_path: "/".to_owned(),
        bodies: 0,
        if_dir_version: None,
        if_snapshot_seq: None,
    };
    client.seq += 1;
    let meta = message.encode_meta().unwrap();
    let mac = client.mac("POST", &path, client.seq, &meta, b"123456789");
    let headers = [
        (HEADER_SESSION, hex::encode(client.session_id)),
        (HEADER_SEQ, client.seq.to_string()),
        (HEADER_MAC, mac),
    ];
    let (status, bytes) = http_call(
        server.addr,
        "POST",
        &path,
        frame_bytes(&message, b"123456789"),
        &headers,
    )
    .await;
    let frame = parse_frame(status, bytes);
    assert_eq!(frame.status, 413);
    assert_eq!(frame.error().code, ErrorCode::TooLarge);
}

#[tokio::test]
async fn sweeper_aborts_expired_uploads() {
    let server = start_server_with(|config| {
        config.lock_ttl_ms = 5;
    })
    .await;
    let mut client = Client::new(server.addr, [12u8; 16]);
    client.hello().await;
    let snapshot = client.checkout("/").await;
    let lock = client.lock("/").await;
    let entries = vec![put_file("a", [1; 16], b"a", 20)];
    let (batch, _) = client
        .begin(&snapshot, &lock, entries, UploadMode::Delta)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    server.state.sweep_once().await;
    let frame = client
        .get(&format!("batch/{}", hex::encode(batch.batch_id.as_bytes())))
        .await;
    frame.assert_status(200);
    let status: BatchStateMessage = frame.decode();
    assert_eq!(status.state, BatchState::Aborted);
}

#[tokio::test]
async fn wrong_namespace_and_unknown_route_are_rejected() {
    let server = start_server().await;
    let mut client = Client::new(server.addr, [13u8; 16]);
    client.hello().await;
    let frame = client
        .post(
            "checkout",
            &Checkout {
                namespace: "other".to_owned(),
                dir_path: "/".to_owned(),
                bodies: 0,
                if_dir_version: None,
                if_snapshot_seq: None,
            },
            &[],
        )
        .await;
    assert_eq!(frame.status, 400);

    let (status, _) = http_call(
        server.addr,
        "GET",
        &format!("{NS}/mm/v1/nope"),
        Vec::new(),
        &[],
    )
    .await;
    assert_eq!(status, 404);
}
