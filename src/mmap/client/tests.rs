//! End-to-end tests for the 1.1 mm client.
//!
//! Every test starts a real `MmapServer` on a loopback ephemeral port with a
//! temporary database and spool. No mock server stands in for SMM1, HTTP or
//! the commit transaction.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;
use tokio::runtime::Runtime;

use crate::mmap::base;
use crate::mmap::client::{
    MM_URL_PREFIX, MM_WIRE_NAMESPACE, MmClientConfig, MmHttpClient, MmNamespace,
};
use crate::mmap::proto::{ErrorBody, ErrorCode, HEADER_LEN, Header, Limits, Message};
use crate::mmap::rsync::Instruction as RsyncInstruction;
use crate::mmap::server::{MmapConfig, MmapServer};
use crate::mmap::shadow::{
    CheckoutOutcome, CheckoutRequest, FileReadRequest, LockRequest, LockResponse, MmRemote,
    RemoteError, Shadow, ShadowConfig, ShadowError, SignatureFile, SignaturesRequest, UploadAbort,
    UploadBegin, UploadCommit, UploadFile, UploadPhase, UploadRequest, UploadResponse,
};
use crate::mmap::types::{BatchId, EntryKind, EntryOp, Ino, LockId, ManifestEntry, ROOT_INO};

const MASTER: [u8; 32] = [0x5A; 32];

struct TestServer {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    runtime: Option<Runtime>,
    _temp: TempDir,
}

impl TestServer {
    fn start(namespace: &str) -> Self {
        let temp = TempDir::new().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let config = MmapConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            namespace,
            temp.path().join("mm.db"),
            temp.path().join("spool"),
            MASTER,
        );
        let (addr, server) = runtime.block_on(async {
            let server = MmapServer::bind(config).await.unwrap();
            let addr = server.local_addr().unwrap();
            (addr, server)
        });
        let (tx, rx) = tokio::sync::oneshot::channel();
        runtime.spawn(async move {
            server
                .run_with_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Self {
            addr,
            shutdown: Some(tx),
            runtime: Some(runtime),
            _temp: temp,
        }
    }

    fn url(&self, prefix: &str) -> String {
        format!("http://{}{}", self.addr, prefix)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

fn client(server: &TestServer, master: [u8; 32], client_id: Option<[u8; 16]>) -> MmHttpClient {
    let mut config = MmClientConfig::from_url(&server.url(MM_URL_PREFIX), master).unwrap();
    if let Some(client_id) = client_id {
        config.client_id = client_id;
    }
    MmHttpClient::new(config).unwrap()
}

fn checkout_root(client: &MmHttpClient) -> crate::mmap::shadow::CheckoutSnapshot {
    match client
        .checkout(&CheckoutRequest {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            if_base: None,
            if_snapshot: None,
            bodies: false,
        })
        .unwrap()
    {
        CheckoutOutcome::Snapshot(snapshot) => snapshot,
        CheckoutOutcome::NotModified { .. } => panic!("full checkout returned 304"),
    }
}

fn acquire(client: &MmHttpClient, base: crate::mmap::types::MmBase) -> LockId {
    match client
        .lock(&LockRequest::Acquire {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base,
            batch_id: None,
            ttl_ms: 60_000,
        })
        .unwrap()
    {
        LockResponse::Granted(granted) => granted.lock_id,
        other => panic!("unexpected lock response: {other:?}"),
    }
}

fn put_manifest(name: &str, ino: Ino, bytes: &[u8]) -> ManifestEntry {
    let chunks: Vec<crate::store::sqlite::ChunkRef> = bytes
        .chunks(64 * 1024)
        .enumerate()
        .map(|(index, chunk)| crate::store::sqlite::ChunkRef {
            chunk_no: index as u32,
            hash: *blake3::hash(chunk).as_bytes(),
            offset: (index as u64) * 64 * 1024,
            len: chunk.len() as u32,
        })
        .collect();
    ManifestEntry {
        name: name.to_owned(),
        ino,
        kind: EntryKind::File,
        op: EntryOp::Put,
        from_name: None,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        size: bytes.len() as u64,
        file_root: base::file_root(EntryKind::File, None, &chunks),
        content_hash: Some(*blake3::hash(bytes).as_bytes()),
        target: None,
    }
}

fn file_manifest(
    snapshot: &crate::mmap::shadow::CheckoutSnapshot,
    extra: Vec<ManifestEntry>,
) -> Vec<ManifestEntry> {
    let mut entries: Vec<ManifestEntry> = snapshot
        .entries
        .iter()
        .map(|entry| entry.manifest_entry(EntryOp::Keep))
        .collect();
    entries.extend(extra);
    entries
}

fn commit_for(
    batch_id: BatchId,
    lock_id: LockId,
    base: crate::mmap::types::MmBase,
    manifest: Vec<ManifestEntry>,
    file: UploadFile,
) -> UploadCommit {
    let bytes = file.size;
    UploadCommit {
        batch_id,
        lock_id,
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base,
        manifest,
        files: vec![file],
        bytes,
    }
}

fn literal_file(index: u32, ino: Ino, bytes: &[u8]) -> UploadFile {
    let chunks: Vec<crate::store::sqlite::ChunkRef> = bytes
        .chunks(64 * 1024)
        .enumerate()
        .map(|(i, chunk)| crate::store::sqlite::ChunkRef {
            chunk_no: i as u32,
            hash: *blake3::hash(chunk).as_bytes(),
            offset: (i as u64) * 64 * 1024,
            len: chunk.len() as u32,
        })
        .collect();
    UploadFile {
        manifest_index: index,
        ino,
        version: 1,
        size: bytes.len() as u64,
        file_root: base::file_root(EntryKind::File, None, &chunks),
        content_hash: *blake3::hash(bytes).as_bytes(),
        source: None,
        instructions: vec![
            RsyncInstruction::Literal {
                file: index,
                bytes: bytes.to_vec(),
            },
            RsyncInstruction::EndFile { file: index },
            RsyncInstruction::EndBatch,
        ],
        unchanged: false,
    }
}

#[test]
fn namespace_mapping_is_pinned_and_a_wrong_label_is_rejected() {
    assert_eq!(MmNamespace::private_mm().url_prefix(), MM_URL_PREFIX);
    assert_eq!(MmNamespace::private_mm().wire_label(), MM_WIRE_NAMESPACE);
    assert_eq!(
        MmNamespace::new("/private-mm").unwrap().wire_label(),
        "private-mm"
    );
    assert!(MmNamespace::new("private-mm").is_err());
    assert!(MmNamespace::new("/private").is_err());
    assert!(MmNamespace::new("/a/b").is_err());

    let server = TestServer::start(MM_URL_PREFIX);
    let good = client(&server, MASTER, None);
    let snapshot = checkout_root(&good);
    assert_eq!(snapshot.dir_ino, ROOT_INO);

    let wrong =
        MmHttpClient::new(MmClientConfig::from_url(&server.url("/other-mm"), MASTER).unwrap())
            .unwrap();
    let error = wrong
        .checkout(&CheckoutRequest {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            if_base: None,
            if_snapshot: None,
            bodies: false,
        })
        .unwrap_err();
    assert!(
        matches!(error, RemoteError::NotFound),
        "an unrouted prefix must not be mistaken for a valid namespace: {error:?}"
    );
}

#[test]
fn fsync_uploads_a_file_and_checkout_bodies_verify_it() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let (attr, handle) = shadow
        .create(Shadow::root_ino(), "hello.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    assert_eq!(attr.kind, EntryKind::File);
    shadow
        .write(handle.fuse_ino, handle.id, 0, b"hello world")
        .unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();

    let reader = client(&server, MASTER, None);
    let outcome = reader
        .checkout(&CheckoutRequest {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            if_base: None,
            if_snapshot: None,
            bodies: true,
        })
        .unwrap();
    let CheckoutOutcome::Snapshot(snapshot) = outcome else {
        panic!("expected a snapshot");
    };
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.name == "hello.txt")
        .unwrap();
    assert_eq!(entry.kind, EntryKind::File);
    assert_eq!(entry.size, 11);
    assert_eq!(snapshot.bodies.len(), 1);
    assert_eq!(snapshot.bodies[0].bytes, b"hello world");

    let data = reader
        .file_read(&FileReadRequest {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            name: "hello.txt".to_owned(),
            ino: entry.ino,
            file_root: entry.file_root,
            offset: 6,
            len: 5,
        })
        .unwrap();
    assert_eq!(data.offset, 6);
    assert_eq!(data.bytes, b"world");
    assert_eq!(data.range_hash, *blake3::hash(b"world").as_bytes());

    let version = reader.dir_version(ROOT_INO).unwrap();
    assert_eq!(version.base.dir_seq, snapshot.base.dir_seq);
    assert_eq!(version.base.dir_version, snapshot.base.dir_version);
}

#[test]
fn commit_plan_round_trips_two_literal_groups() {
    let a = vec![0x61u8; 150_000];
    let b = vec![0x62u8; 130_000];
    let manifest = vec![
        put_manifest("a.bin", [0x31; 16], &a),
        put_manifest("b.bin", [0x32; 16], &b),
    ];
    let commit = UploadCommit {
        batch_id: BatchId::from_bytes([0x41; 16]),
        lock_id: LockId::from_bytes([0x42; 16]),
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base: crate::mmap::types::MmBase::new(1, crate::mmap::types::DirSeq::new(1), [0; 32]),
        manifest,
        files: vec![
            literal_file(0, [0x31; 16], &a),
            literal_file(1, [0x32; 16], &b),
        ],
        bytes: (a.len() + b.len()) as u64,
    };
    let plan = super::wire::CommitPlan::build(&commit).unwrap();
    let mut bytes = Vec::new();
    plan.write_to(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, plan.data_len);
    assert_eq!(*blake3::hash(&bytes).as_bytes(), plan.payload_hash);
    let mut reader = crate::mmap::proto::InstructionReader::new(std::io::Cursor::new(bytes));
    let mut literals = Vec::new();
    loop {
        match reader.next_instruction().unwrap() {
            Some(crate::mmap::proto::Instruction::Literal { len, .. }) => {
                let mut data = vec![0u8; len as usize];
                reader.read_literal(&mut data).unwrap();
                literals.extend_from_slice(&data);
            }
            Some(crate::mmap::proto::Instruction::EndBatch) => break,
            Some(_) => {}
            None => panic!("stream ended without END_BATCH"),
        }
    }
    reader.finish().unwrap();
    assert_eq!(literals.len(), a.len() + b.len());
}

#[test]
fn fsync_uploads_multiple_chunked_files_in_one_batch() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let first = vec![0x61u8; 150_000];
    let second = vec![0x62u8; 130_000];
    let (_, handle_a) = shadow
        .create(Shadow::root_ino(), "a.bin", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(handle_a.fuse_ino, handle_a.id, 0, &first)
        .unwrap();
    let (_, handle_b) = shadow
        .create(Shadow::root_ino(), "b.bin", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(handle_b.fuse_ino, handle_b.id, 0, &second)
        .unwrap();
    shadow.fsync(handle_a.fuse_ino, Some(handle_a.id)).unwrap();

    let reader = client(&server, MASTER, None);
    let outcome = reader
        .checkout(&CheckoutRequest {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            if_base: None,
            if_snapshot: None,
            bodies: true,
        })
        .unwrap();
    let CheckoutOutcome::Snapshot(snapshot) = outcome else {
        panic!("expected a snapshot");
    };
    let body_a = snapshot
        .bodies
        .iter()
        .find(|body| {
            snapshot
                .entries
                .iter()
                .any(|entry| entry.name == "a.bin" && entry.ino == body.ino)
        })
        .unwrap();
    let body_b = snapshot
        .bodies
        .iter()
        .find(|body| {
            snapshot
                .entries
                .iter()
                .any(|entry| entry.name == "b.bin" && entry.ino == body.ino)
        })
        .unwrap();
    assert_eq!(body_a.bytes, first);
    assert_eq!(body_b.bytes, second);
}

#[test]
fn stale_base_is_base_changed_and_reported_as_eagain() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "a.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(handle.fuse_ino, handle.id, 0, b"a").unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();

    let reader = client(&server, MASTER, Some([0x11; 16]));
    let stale = checkout_root(&reader);
    let old_base = stale.base;

    // A second commit changes the directory base after the checkout.
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "b.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(handle.fuse_ino, handle.id, 0, b"b").unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();

    let lock_id = acquire(&reader, old_base);
    let batch_id = BatchId::new_random();
    let manifest = stale
        .entries
        .iter()
        .map(|entry| entry.manifest_entry(EntryOp::Keep))
        .collect::<Vec<_>>();
    let error = reader
        .upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: old_base,
            manifest,
        }))
        .unwrap_err();
    let RemoteError::BaseChanged {
        current,
        snapshot_seq,
    } = error
    else {
        panic!("expected BASE_CHANGED, got {error:?}");
    };
    assert!(current.dir_seq > old_base.dir_seq);
    assert!(snapshot_seq.get() >= 2);
    let shadow_error = ShadowError::Remote(RemoteError::BaseChanged {
        current,
        snapshot_seq,
    });
    assert_eq!(shadow_error.errno(), libc::EAGAIN);
    reader.lock(&LockRequest::Release { lock_id }).unwrap();
}

#[test]
fn second_writer_gets_lock_held_eagain_without_a_retry() {
    let server = TestServer::start(MM_URL_PREFIX);
    let owner = client(&server, MASTER, Some([0x21; 16]));
    let snapshot = checkout_root(&owner);
    let owner_lock = acquire(&owner, snapshot.base);

    let contender = client(&server, MASTER, Some([0x22; 16]));
    let error = contender
        .lock(&LockRequest::Acquire {
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: snapshot.base,
            batch_id: None,
            ttl_ms: 60_000,
        })
        .unwrap_err();
    assert!(
        matches!(error, RemoteError::LockHeld { .. }),
        "unexpected error: {error:?}"
    );
    let shadow_error = ShadowError::Remote(error);
    assert_eq!(shadow_error.errno(), libc::EAGAIN);

    // A shadow fsync against the held directory does not retry: exactly one
    // acquire attempt is made and the dirty generation survives.
    let shadow_dir = TempDir::new().unwrap();
    let counting = Arc::new(CountingRemote::new(client(
        &server,
        MASTER,
        Some([0x23; 16]),
    )));
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            counting.clone(),
        )
        .unwrap(),
    );
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "c.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(handle.fuse_ino, handle.id, 0, b"c").unwrap();
    let error = shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap_err();
    assert_eq!(error.errno(), libc::EAGAIN);
    assert_eq!(counting.acquires(), 1);
    // The batch id is durable before BEGIN, so a crashed fsync can still
    // query the server on restart.
    let state = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(state.batch_id.is_some());
    assert_eq!(state.upload_state, UploadPhase::Locked);

    owner
        .lock(&LockRequest::Release {
            lock_id: owner_lock,
        })
        .unwrap();
}

struct CountingRemote {
    inner: MmHttpClient,
    acquires: Mutex<u64>,
}

impl CountingRemote {
    fn new(inner: MmHttpClient) -> Self {
        Self {
            inner,
            acquires: Mutex::new(0),
        }
    }

    fn acquires(&self) -> u64 {
        *self.acquires.lock().unwrap()
    }
}

impl MmRemote for CountingRemote {
    fn checkout(&self, request: &CheckoutRequest) -> Result<CheckoutOutcome, RemoteError> {
        self.inner.checkout(request)
    }

    fn signatures(
        &self,
        request: &SignaturesRequest,
    ) -> Result<crate::mmap::shadow::SignaturesResponse, RemoteError> {
        self.inner.signatures(request)
    }

    fn upload(&self, request: &UploadRequest) -> Result<UploadResponse, RemoteError> {
        self.inner.upload(request)
    }

    fn lock(&self, request: &LockRequest) -> Result<LockResponse, RemoteError> {
        if matches!(request, LockRequest::Acquire { .. }) {
            *self.acquires.lock().unwrap() += 1;
        }
        self.inner.lock(request)
    }

    fn file_read(
        &self,
        request: &FileReadRequest,
    ) -> Result<crate::mmap::shadow::FileData, RemoteError> {
        self.inner.file_read(request)
    }
}

#[test]
fn batch_ack_loss_adopts_a_committed_result() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "seed.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(handle.fuse_ino, handle.id, 0, b"seed")
        .unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();

    let proxy = DropProxy::start(server.addr);
    let url = format!("http://{}{}", proxy.addr, MM_URL_PREFIX);
    let reader = MmHttpClient::new(MmClientConfig::from_url(&url, MASTER).unwrap()).unwrap();
    let snapshot = checkout_root(&reader);
    let lock_id = acquire(&reader, snapshot.base);
    let batch_id = BatchId::new_random();
    let content = b"lost acknowledgement";
    let extra = put_manifest("lost.txt", [0x77; 16], content);
    let manifest = file_manifest(&snapshot, vec![extra]);
    let index = manifest
        .iter()
        .position(|entry| entry.name == "lost.txt")
        .unwrap();
    let file = literal_file(index as u32, [0x77; 16], content);
    let plan = reader
        .upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: snapshot.base,
            manifest: manifest.clone(),
        }))
        .unwrap();
    assert!(matches!(plan, UploadResponse::Plan(_)));

    proxy.drop_next_commit();
    let response = reader
        .upload(&UploadRequest::Commit(commit_for(
            batch_id,
            lock_id,
            snapshot.base,
            manifest,
            file,
        )))
        .unwrap();
    let UploadResponse::Committed(result) = response else {
        panic!("expected a committed batch");
    };
    assert_eq!(result.batch_id, batch_id);
    let status = reader.batch_status(batch_id).unwrap();
    assert_eq!(status.state, crate::mmap::proto::BatchState::Committed);
    assert_eq!(status.snapshot_seq, Some(result.snapshot_seq));

    let after = checkout_root(&reader);
    assert!(after.entries.iter().any(|entry| entry.name == "lost.txt"));
    reader.lock(&LockRequest::Release { lock_id }).unwrap();
}

#[test]
fn open_batch_is_resent_after_a_lost_commit_request() {
    let server = TestServer::start(MM_URL_PREFIX);
    let proxy = DropProxy::start(server.addr);
    let url = format!("http://{}{}", proxy.addr, MM_URL_PREFIX);
    let reader = MmHttpClient::new(MmClientConfig::from_url(&url, MASTER).unwrap()).unwrap();
    let snapshot = checkout_root(&reader);
    let lock_id = acquire(&reader, snapshot.base);
    let batch_id = BatchId::new_random();
    let content = b"resent body";
    let extra = put_manifest("resend.txt", [0x78; 16], content);
    let manifest = file_manifest(&snapshot, vec![extra]);
    let index = manifest
        .iter()
        .position(|entry| entry.name == "resend.txt")
        .unwrap();
    let file = literal_file(index as u32, [0x78; 16], content);
    reader
        .upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: snapshot.base,
            manifest: manifest.clone(),
        }))
        .unwrap();

    proxy.drop_next_commit_request();
    let response = reader
        .upload(&UploadRequest::Commit(commit_for(
            batch_id,
            lock_id,
            snapshot.base,
            manifest,
            file,
        )))
        .unwrap();
    assert!(matches!(response, UploadResponse::Committed(_)));
    let after = checkout_root(&reader);
    assert!(after.entries.iter().any(|entry| entry.name == "resend.txt"));
    reader.lock(&LockRequest::Release { lock_id }).unwrap();
}

#[test]
fn aborted_batch_is_reported_for_rebuild() {
    let server = TestServer::start(MM_URL_PREFIX);
    let reader = client(&server, MASTER, None);
    let snapshot = checkout_root(&reader);
    let lock_id = acquire(&reader, snapshot.base);
    let batch_id = BatchId::new_random();
    reader
        .upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: snapshot.base,
            manifest: Vec::new(),
        }))
        .unwrap();
    reader
        .upload(&UploadRequest::Abort(UploadAbort { batch_id, lock_id }))
        .unwrap();
    let status = reader.batch_status(batch_id).unwrap();
    assert_eq!(status.state, crate::mmap::proto::BatchState::Aborted);
}

#[test]
fn fsync_uploads_and_deletes_a_symlink() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    shadow
        .symlink(Shadow::root_ino(), "link", b"target/name", 1000, 1000)
        .unwrap();
    shadow.fsyncdir(Shadow::root_ino()).unwrap();

    let reader = client(&server, MASTER, None);
    let snapshot = checkout_root(&reader);
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.name == "link")
        .unwrap();
    assert_eq!(entry.kind, EntryKind::Symlink);
    assert_eq!(entry.target.as_deref(), Some(&b"target/name"[..]));

    shadow.unlink(Shadow::root_ino(), "link").unwrap();
    shadow.fsyncdir(Shadow::root_ino()).unwrap();
    let snapshot = checkout_root(&reader);
    assert!(!snapshot.entries.iter().any(|entry| entry.name == "link"));
}

#[test]
fn fsync_uploads_an_explicit_delete() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "gone.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(handle.fuse_ino, handle.id, 0, b"bye").unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();
    shadow.unlink(Shadow::root_ino(), "gone.txt").unwrap();
    shadow.fsyncdir(Shadow::root_ino()).unwrap();

    let reader = client(&server, MASTER, None);
    let snapshot = checkout_root(&reader);
    assert!(
        !snapshot
            .entries
            .iter()
            .any(|entry| entry.name == "gone.txt"),
        "delete was not applied"
    );
}

#[test]
fn signatures_work_before_and_after_begin() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Arc::new(
        Shadow::open(
            ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
            Arc::new(client(&server, MASTER, None)),
        )
        .unwrap(),
    );
    let (_attr, handle) = shadow
        .create(Shadow::root_ino(), "sig.txt", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(handle.fuse_ino, handle.id, 0, b"abcdefgh")
        .unwrap();
    shadow.fsync(handle.fuse_ino, Some(handle.id)).unwrap();

    let reader = client(&server, MASTER, None);
    let snapshot = checkout_root(&reader);
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.name == "sig.txt")
        .unwrap();
    let lock_id = acquire(&reader, snapshot.base);
    let changed = put_manifest("sig.txt", entry.ino, b"abcdZZZZ");
    let request = SignaturesRequest {
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base: snapshot.base,
        files: vec![SignatureFile {
            name: "sig.txt".to_owned(),
            ino: entry.ino,
            size: changed.size,
            file_root: changed.file_root,
        }],
    };
    // The shadow asks before BEGIN; the client must not fail on the missing
    // upload row and must produce a usable delta basis.
    let local = reader.signatures(&request).unwrap();
    assert_eq!(local.files.len(), 1);
    assert!(!local.files[0].unchanged);
    assert!(local.files[0].signature.is_some());

    let unchanged = SignaturesRequest {
        files: vec![SignatureFile {
            name: "sig.txt".to_owned(),
            ino: entry.ino,
            size: entry.size,
            file_root: entry.file_root,
        }],
        ..request.clone()
    };
    let same = reader.signatures(&unchanged).unwrap();
    assert!(same.files[0].unchanged);

    // After BEGIN the server endpoint is available and returns the same
    // classification.
    let manifest = snapshot
        .entries
        .iter()
        .map(|entry| entry.manifest_entry(EntryOp::Keep))
        .collect::<Vec<_>>();
    let batch_id = BatchId::new_random();
    reader
        .upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: "/".to_owned(),
            dir_ino: ROOT_INO,
            base: snapshot.base,
            manifest,
        }))
        .unwrap();
    let remote = reader.signatures(&request).unwrap();
    assert_eq!(remote.files.len(), 1);
    assert!(!remote.files[0].unchanged);
    assert!(remote.files[0].signature.is_some());
    reader
        .upload(&UploadRequest::Abort(UploadAbort { batch_id, lock_id }))
        .unwrap();
    reader.lock(&LockRequest::Release { lock_id }).unwrap();
}

/// A loopback proxy that can discard one commit request or one commit
/// response. It speaks enough HTTP/1.1 to frame the client's single request
/// per connection; the server always answers with `Connection: close`.
struct DropProxy {
    addr: SocketAddr,
    drop_response: Arc<AtomicBool>,
    drop_request: Arc<AtomicBool>,
    unauthorized: Arc<AtomicBool>,
    _handle: thread::JoinHandle<()>,
}

impl DropProxy {
    fn start(server: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let drop_response = Arc::new(AtomicBool::new(false));
        let drop_request = Arc::new(AtomicBool::new(false));
        let unauthorized = Arc::new(AtomicBool::new(false));
        let unauthorized_body = Arc::new(unauthorized_response());
        let response = Arc::clone(&drop_response);
        let request = Arc::clone(&drop_request);
        let inject = Arc::clone(&unauthorized);
        let inject_body = Arc::clone(&unauthorized_body);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { break };
                let Ok(bytes) = read_http_request(&mut client) else {
                    continue;
                };
                let is_commit = request_line_has(&bytes, "/upload/commit");
                if !is_commit
                    && request_line_has(&bytes, "/checkout")
                    && inject.swap(false, Ordering::SeqCst)
                {
                    let mut response = format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        inject_body.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(&inject_body);
                    let _ = client.write_all(&response);
                    let _ = client.flush();
                    continue;
                }
                if is_commit && request.swap(false, Ordering::SeqCst) {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let Ok(mut upstream) = TcpStream::connect(server) else {
                    continue;
                };
                if upstream.write_all(&bytes).is_err() {
                    continue;
                }
                let mut body = Vec::new();
                if upstream.read_to_end(&mut body).is_err() {
                    continue;
                }
                if is_commit && response.swap(false, Ordering::SeqCst) {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let _ = client.write_all(&body);
                let _ = client.flush();
            }
        });
        Self {
            addr,
            drop_response,
            drop_request,
            unauthorized,
            _handle: handle,
        }
    }

    fn drop_next_commit(&self) {
        self.drop_response.store(true, Ordering::SeqCst);
    }

    fn drop_next_commit_request(&self) {
        self.drop_request.store(true, Ordering::SeqCst);
    }

    fn inject_unauthorized(&self) {
        self.unauthorized.store(true, Ordering::SeqCst);
    }
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        if let Some(head) = find_headers_end(&bytes) {
            let text = String::from_utf8_lossy(&bytes[..head]);
            let length = content_length(&text).unwrap_or(0);
            if bytes.len() >= head + length {
                return Ok(bytes);
            }
        }
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn find_headers_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn request_line_has(bytes: &[u8], needle: &str) -> bool {
    let Some(end) = find_headers_end(bytes) else {
        return false;
    };
    String::from_utf8_lossy(&bytes[..end]).contains(needle)
}

fn unauthorized_response() -> Vec<u8> {
    let body = ErrorBody::new(ErrorCode::AuthFailed);
    let meta = body.encode_meta().unwrap();
    let header = Header::new(
        ErrorBody::KIND,
        u32::try_from(meta.len()).unwrap(),
        0,
        &Limits::new(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&meta);
    assert_eq!(bytes.len(), HEADER_LEN + meta.len());
    bytes
}

#[test]
fn unauthorized_response_triggers_one_hello_and_a_replay() {
    let server = TestServer::start(MM_URL_PREFIX);
    let proxy = DropProxy::start(server.addr);
    let url = format!("http://{}{}", proxy.addr, MM_URL_PREFIX);
    let reader = MmHttpClient::new(MmClientConfig::from_url(&url, MASTER).unwrap()).unwrap();
    proxy.inject_unauthorized();
    let snapshot = checkout_root(&reader);
    assert_eq!(snapshot.dir_ino, ROOT_INO);
}

#[test]
fn dir_not_empty_keeps_its_detail_and_maps_to_enotempty() {
    let mut body = ErrorBody::new(ErrorCode::DirNotEmpty);
    body.detail = Some("directory /d is not empty".to_owned());
    let error = super::remote::map_failure(super::http::WireFailure::Status {
        status: 409,
        body: Box::new(body),
    });
    assert_eq!(
        error,
        RemoteError::DirNotEmpty("directory /d is not empty".to_owned())
    );
    assert!(
        !error.is_conflict(),
        "not every 409 is a retryable conflict"
    );
    assert_eq!(
        ShadowError::Remote(error).errno(),
        libc::ENOTEMPTY,
        "a non-empty directory is not a batch id conflict"
    );
}

#[test]
fn rmdir_deletes_the_real_server_child_entries_before_the_parent() {
    let server = TestServer::start(MM_URL_PREFIX);
    let shadow_dir = TempDir::new().unwrap();
    let shadow = Shadow::open(
        ShadowConfig::new(shadow_dir.path(), MM_URL_PREFIX),
        Arc::new(client(&server, MASTER, None)),
    )
    .unwrap();

    let child = shadow
        .mkdir(Shadow::root_ino(), "d", 0o755, 0, 1000, 1000)
        .unwrap();
    let (file, handle) = shadow
        .create(child.fuse_ino, "f", 0o644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow.release(handle.id).unwrap();

    shadow.unlink(child.fuse_ino, "f").unwrap();
    shadow.rmdir(Shadow::root_ino(), "d").unwrap();

    // The real server must already see an empty child before it accepts the
    // parent batch that removes it.
    let reader = client(&server, MASTER, None);
    let child_snapshot = match reader
        .checkout(&CheckoutRequest {
            dir_path: "/d".to_owned(),
            dir_ino: child.ino,
            if_base: None,
            if_snapshot: None,
            bodies: false,
        })
        .unwrap()
    {
        CheckoutOutcome::Snapshot(snapshot) => snapshot,
        CheckoutOutcome::NotModified { .. } => panic!("a full checkout cannot be 304"),
    };
    assert!(child_snapshot.entries.is_empty());

    shadow.fsyncdir(Shadow::root_ino()).unwrap();
    let root = checkout_root(&reader);
    assert!(!root.entries.iter().any(|entry| entry.name == "d"));
}
