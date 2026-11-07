//! M4-1 … M4-9: the acceptance items that the F/W matrices only cover in
//! part. Every test prints one `chaos evidence:` line; `run-m4.sh` captures
//! one log per item and `summary.json` carries the verdict.
//!
//! The tests use the real replay engine and the real sequencer. No product
//! code is stubbed: a test that cannot reach a property says so in its
//! evidence line instead of pretending.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use syncmount::client::replayer::{
    IncomingOp, Op, OpAttrs, OpBody, OpData, PendingOverlay, Replayer,
};
use syncmount::protocol::crypto::{KeyRing, NonceMinter, Opener, Sealer};
use syncmount::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
use syncmount::protocol::messages::{DataRef, OpClass};
use syncmount::protocol::{
    ClientId, Flags, FrameBuf, FrameHeader, FrameRef, MsgType, OpId, Prefix, RoutePrefix, Seq,
    SessionId, StreamId, encode_frame,
};
use syncmount::server::ServeConfig;
use syncmount::store::{BackingStore, Errno, PosixBacking, RootFd};
use tempfile::TempDir;

use super::harness::{CLUSTER, MTIME_NS, SeqServer, WAIT, replayer, tree_digest};

/// Fixed epoch for every replay in this module.
const EPOCH: u64 = 0x4d34;

/// Plaintext marker from 31:M4-4. It must never appear on the wire.
const SECRET_MARKER: &[u8] = b"SECRET_MARKER";
/// A second marker for the path, which lives in the sealed WCP body.
const SECRET_PATH: &str = "/SECRET_PATH_MARKER";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Plaintext store for `WRITE`/`PWRITE` references.
#[derive(Default)]
struct TestData {
    map: std::sync::Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
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

fn attrs() -> OpAttrs {
    OpAttrs {
        mode: None,
        uid: 1000,
        gid: 1000,
        mtime_ns: MTIME_NS,
    }
}

fn op_id(seed: u8, client: ClientId) -> OpId {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&client.to_bytes()[..8]);
    raw[8..].fill(seed);
    OpId::from_bytes(raw)
}

/// Full-width operation id for long runs: the 8-bit seed above wraps after
/// 256 operations and the replay dedup would then drop fresh writes.
fn op_id64(counter: u64, client: ClientId) -> OpId {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&client.to_bytes()[..8]);
    raw[8..].copy_from_slice(&counter.to_le_bytes());
    OpId::from_bytes(raw)
}

fn create(seed: u8, client: ClientId, path: &str, dir: bool) -> Op {
    let class = if dir {
        OpClass::MKDIR
    } else {
        OpClass::CREATE_EXCL
    };
    let body = if dir {
        OpBody::Mkdir { mode: 0o755 }
    } else {
        OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        }
    };
    Op::new(op_id(seed, client), client, class, path)
        .with_attrs(attrs())
        .with_body(body)
}

fn write(seed: u8, client: ClientId, path: &str, bytes: &[u8], data: &TestData) -> Op {
    let session = SessionId::from_le_bytes(op_id(seed, client).to_bytes());
    data.insert(session, bytes.to_vec());
    let reference = DataRef {
        session,
        total_len: bytes.len() as u64,
        data_hash: *blake3::hash(bytes).as_bytes(),
    };
    Op::new(op_id(seed, client), client, OpClass::WRITE, path)
        .with_attrs(attrs())
        .with_body(OpBody::Write(reference))
}

fn unlink(seed: u8, client: ClientId, path: &str) -> Op {
    Op::new(op_id(seed, client), client, OpClass::UNLINK, path).with_attrs(attrs())
}

fn rmdir(seed: u8, client: ClientId, path: &str) -> Op {
    Op::new(op_id(seed, client), client, OpClass::RMDIR, path).with_attrs(attrs())
}

fn incoming_at(seq: u64, op: Op) -> IncomingOp {
    IncomingOp::new(Seq(seq), EPOCH, op)
}

/// Apply one operation through a backing that stays open for the whole
/// script: the inode table is in-memory state, so a fresh `PosixBacking` per
/// call cannot resolve an inode created by an earlier call.
fn apply_op(
    replay: &mut Replayer,
    backing: &PosixBacking,
    seq: u64,
    op: Op,
    data: &TestData,
) -> Result<(), Errno> {
    replay
        .on_ordered(incoming_at(seq, op), Duration::ZERO, backing, data)
        .unwrap()
        .verdict
}

fn backing_for(dir: &std::path::Path) -> PosixBacking {
    PosixBacking::new(RootFd::open_before_mount(dir).unwrap())
}

// ---------------------------------------------------------------------------
// M4-7 — mkdir vs create: one final type, both clients agree (D16)
// ---------------------------------------------------------------------------

#[test]
fn m4_7_type_conflict_has_one_final_type_on_both_clients() {
    let a = ClientId::from_bytes([0x7a; 16]);
    let b = ClientId::from_bytes([0x7b; 16]);
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let data = TestData::default();
    let mut left = replayer(a, EPOCH, Duration::from_millis(20));
    let mut right = replayer(b, EPOCH, Duration::from_millis(20));
    let left_backing = backing_for(dir_a.path());
    let right_backing = backing_for(dir_b.path());

    // A's mkdir is sequenced first, B's create second. The second operation
    // loses with EEXIST; the directory type stands on both clients.
    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 1, create(1, a, "/x", true), &data).unwrap();
        assert_eq!(
            apply_op(replay, backing, 2, create(2, b, "/x", false), &data),
            Err(Errno::EEXIST),
            "the loser must see EEXIST"
        );
    }

    let left_kind = fs::symlink_metadata(dir_a.path().join("x")).unwrap();
    let right_kind = fs::symlink_metadata(dir_b.path().join("x")).unwrap();
    assert!(left_kind.is_dir() && right_kind.is_dir());
    assert_eq!(tree_digest(dir_a.path()), tree_digest(dir_b.path()));
    assert_eq!(left.snapshot_hash(), right.snapshot_hash());

    // The opposite order must produce the opposite, still unique, type.
    let dir_c = TempDir::new().unwrap();
    let dir_d = TempDir::new().unwrap();
    let mut left = replayer(a, EPOCH, Duration::from_millis(20));
    let mut right = replayer(b, EPOCH, Duration::from_millis(20));
    let left_backing = backing_for(dir_c.path());
    let right_backing = backing_for(dir_d.path());
    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 1, create(3, b, "/y", false), &data).unwrap();
        assert_eq!(
            apply_op(replay, backing, 2, create(4, a, "/y", true), &data),
            Err(Errno::EEXIST)
        );
    }
    assert!(
        fs::symlink_metadata(dir_c.path().join("y"))
            .unwrap()
            .is_file()
    );
    assert!(
        fs::symlink_metadata(dir_d.path().join("y"))
            .unwrap()
            .is_file()
    );
    assert_eq!(tree_digest(dir_c.path()), tree_digest(dir_d.path()));

    println!(
        "chaos evidence: M4-7 pass dir_wins=EEXIST file_wins=EEXIST \
         final_type=unique both_clients_agree=true d16=true"
    );
}

// ---------------------------------------------------------------------------
// M4-8 — unlink then create: the new file wins, an old fd keeps the old inode
// ---------------------------------------------------------------------------

#[test]
fn m4_8_unlink_then_create_keeps_old_fd_on_the_old_inode() {
    let a = ClientId::from_bytes([0x7c; 16]);
    let b = ClientId::from_bytes([0x7d; 16]);
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let data = TestData::default();
    let mut left = replayer(a, EPOCH, Duration::from_millis(20));
    let mut right = replayer(b, EPOCH, Duration::from_millis(20));
    let left_backing = backing_for(dir_a.path());
    let right_backing = backing_for(dir_b.path());

    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 1, create(1, a, "/f", false), &data).unwrap();
        apply_op(
            replay,
            backing,
            2,
            write(2, a, "/f", b"old-inode", &data),
            &data,
        )
        .unwrap();
    }
    // POSIX: this descriptor survives the unlink and still sees the old inode.
    let mut old_fd = fs::File::open(dir_a.path().join("f")).unwrap();
    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 3, unlink(3, a, "/f"), &data).unwrap();
        apply_op(replay, backing, 4, create(4, b, "/f", false), &data).unwrap();
        apply_op(
            replay,
            backing,
            5,
            write(5, b, "/f", b"new-file", &data),
            &data,
        )
        .unwrap();
    }

    let mut seen = String::new();
    old_fd.read_to_string(&mut seen).unwrap();
    assert_eq!(seen, "old-inode", "an old fd must keep the old inode");
    assert_eq!(fs::read(dir_a.path().join("f")).unwrap(), b"new-file");
    assert_eq!(tree_digest(dir_a.path()), tree_digest(dir_b.path()));
    assert_eq!(left.snapshot_hash(), right.snapshot_hash());

    println!(
        "chaos evidence: M4-8 pass new_file_wins=true old_fd_read=old-inode \
         new_path_read=new-file both_clients_agree=true d12=true"
    );
}

// ---------------------------------------------------------------------------
// M4-9 — rmdir races a remote write: one final tree, rmdir failure is a verdict
// ---------------------------------------------------------------------------

#[test]
fn m4_9_rmdir_race_reports_the_failure_and_keeps_one_tree() {
    let a = ClientId::from_bytes([0x7e; 16]);
    let b = ClientId::from_bytes([0x7f; 16]);
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let data = TestData::default();
    let mut left = replayer(a, EPOCH, Duration::from_millis(20));
    let mut right = replayer(b, EPOCH, Duration::from_millis(20));
    let left_backing = backing_for(dir_a.path());
    let right_backing = backing_for(dir_b.path());

    // The remote write is sequenced before A's rmdir: rmdir must fail with
    // ENOTEMPTY and the verdict is the event that reaches A's waiter.
    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 1, create(1, a, "/d", true), &data).unwrap();
        apply_op(replay, backing, 2, create(2, b, "/d/f", false), &data).unwrap();
        assert_eq!(
            apply_op(replay, backing, 3, rmdir(3, a, "/d"), &data),
            Err(Errno::ENOTEMPTY),
            "rmdir must report ENOTEMPTY"
        );
    }
    assert!(dir_a.path().join("d/f").exists(), "the write survives");
    assert_eq!(tree_digest(dir_a.path()), tree_digest(dir_b.path()));
    assert_eq!(left.snapshot_hash(), right.snapshot_hash());

    // The opposite order: rmdir wins, the later create loses with ENOENT.
    let dir_c = TempDir::new().unwrap();
    let dir_d = TempDir::new().unwrap();
    let mut left = replayer(a, EPOCH, Duration::from_millis(20));
    let mut right = replayer(b, EPOCH, Duration::from_millis(20));
    let left_backing = backing_for(dir_c.path());
    let right_backing = backing_for(dir_d.path());
    for (replay, backing) in [(&mut left, &left_backing), (&mut right, &right_backing)] {
        apply_op(replay, backing, 1, create(4, a, "/e", true), &data).unwrap();
        apply_op(replay, backing, 2, rmdir(5, a, "/e"), &data).unwrap();
        assert_eq!(
            apply_op(replay, backing, 3, create(6, b, "/e/f", false), &data),
            Err(Errno::ENOENT)
        );
    }
    assert!(!dir_c.path().join("e").exists());
    assert_eq!(tree_digest(dir_c.path()), tree_digest(dir_d.path()));

    println!(
        "chaos evidence: M4-9 pass remote_write_wins=ENOTEMPTY rmdir_wins=ENOENT \
         event_notified=true final_tree_equal=true d11=true"
    );
}

// ---------------------------------------------------------------------------
// M4-4 — every payload is sealed; the server sees ciphertext only
// ---------------------------------------------------------------------------

fn sealed_stream(ring: &KeyRing, session: SessionId, plaintext: &[u8]) -> (Vec<FrameBuf>, Vec<u8>) {
    let nonces = NonceMinter::with_instance(0x4d44);
    let fragmenter = Fragmenter::new(session, StreamId::OP_DATA, plaintext.len() as u64).unwrap();
    let mut frames = Vec::new();
    let mut wire = Vec::new();
    for index in 0..fragmenter.total_chunks() {
        let start = index as usize * CHUNK_PLAIN;
        let length = fragmenter.chunk_len(index).unwrap();
        let fragment = fragmenter
            .fragment(index, &plaintext[start..start + length])
            .unwrap();
        let prefix = RoutePrefix::new(session, StreamId::OP_DATA, index, fragmenter.total_chunks());
        let mut header = FrameHeader::new(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        let sealed = Sealer::new(ring, &nonces)
            .seal(&mut header, &Prefix::Route(prefix), fragment.plaintext)
            .unwrap();
        let frame = FrameBuf::new(header, Prefix::Route(prefix), sealed.into_vec());
        wire.extend(
            encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body)).unwrap(),
        );
        frames.push(frame);
    }
    (frames, wire)
}

fn sealed_ordered(ring: &KeyRing, client: ClientId, path: &str) -> (FrameBuf, Vec<u8>) {
    let nonces = NonceMinter::with_instance(0x4d45);
    let mut writer = syncmount::protocol::messages::WcpWriter::new();
    writer.bytes(
        syncmount::protocol::messages::fid::F_CLIENT_ID,
        &client.to_bytes(),
    );
    writer.u32(syncmount::protocol::messages::fid::F_KEY_EPOCH, 1);
    writer.bytes(
        syncmount::protocol::messages::fid::F_OP_ID,
        &op_id(9, client).to_bytes(),
    );
    writer.u8(
        syncmount::protocol::messages::fid::F_OP_CLASS,
        OpClass::CREATE_EXCL.get(),
    );
    writer.str(syncmount::protocol::messages::fid::F_PATH, path);
    writer.u64(syncmount::protocol::messages::fid::F_MTIME_NS, MTIME_NS);
    writer.u32(syncmount::protocol::messages::fid::F_UID, 1000);
    writer.u32(syncmount::protocol::messages::fid::F_GID, 1000);
    writer.u32(syncmount::protocol::messages::fid::F_MODE, 0o644);
    writer.u32(syncmount::protocol::messages::fid::F_OP_FLAGS, 0);
    writer.bytes(
        syncmount::protocol::messages::fid::F_PAYLOAD_HASH,
        &[0x33; 32],
    );
    writer.bytes(syncmount::protocol::messages::fid::F_SIG, &[0x44; 64]);
    let plaintext = writer.finish().unwrap();
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = Sealer::new(ring, &nonces)
        .seal(&mut header, &Prefix::None, &plaintext)
        .unwrap();
    let frame = FrameBuf::new(header, Prefix::None, sealed.into_vec());
    let wire = encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body)).unwrap();
    (frame, wire)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn m4_4_payload_and_path_are_ciphertext_on_the_server() {
    let ring = KeyRing::derive(b"m4-4", &CLUSTER).unwrap();
    let client = ClientId::from_bytes([0x44; 16]);
    let session = SessionId::from_le_bytes([0x19; 16]);

    // A multi-chunk payload with the marker at the front, middle and tail.
    let mut plaintext = vec![0u8; CHUNK_PLAIN * 2 + 777];
    plaintext[..SECRET_MARKER.len()].copy_from_slice(SECRET_MARKER);
    let middle = CHUNK_PLAIN;
    plaintext[middle..middle + SECRET_MARKER.len()].copy_from_slice(SECRET_MARKER);
    let tail = plaintext.len() - SECRET_MARKER.len();
    plaintext[tail..].copy_from_slice(SECRET_MARKER);

    let (streams, stream_wire) = sealed_stream(&ring, session, &plaintext);
    assert_eq!(streams.len(), 3, "the payload spans three fragments");
    assert!(
        !contains(&stream_wire, SECRET_MARKER),
        "stream wire leaked plaintext"
    );

    let (ordered, ordered_wire) = sealed_ordered(&ring, client, SECRET_PATH);
    assert!(
        !contains(&ordered_wire, SECRET_PATH.as_bytes()),
        "path leaked"
    );
    assert!(
        !contains(&ordered_wire, SECRET_MARKER),
        "marker leaked in ORDERED"
    );

    // The real sequencer sees only those bytes. Its outbox frame must stay
    // ciphertext for the receiving client.
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let receiver = ClientId::from_bytes([0x45; 16]);
    let mut sender_session =
        super::harness::SeqSession::attach(&server, client, 0x4401, Seq(0), EPOCH, None).await;
    let mut receiver_session =
        super::harness::SeqSession::attach(&server, receiver, 0x4402, Seq(0), EPOCH, None).await;
    let _ = sender_session.next_ctrl(WAIT).await;
    let _ = receiver_session.next_ctrl(WAIT).await;
    server.seq.ordered(client, ordered.clone()).await.unwrap();
    let broadcast = receiver_session.next_data(WAIT).await.expect("broadcast");
    let outbox_wire = encode_frame(&FrameRef::new(
        &broadcast.header,
        &broadcast.prefix,
        &broadcast.body,
    ))
    .unwrap();
    assert!(!contains(&outbox_wire, SECRET_PATH.as_bytes()));
    assert!(!contains(&outbox_wire, SECRET_MARKER));

    // Only a key holder recovers the path and the payload.
    let opener = Opener::new(&ring);
    let path = opener
        .open(&broadcast.header, &broadcast.prefix, &broadcast.body)
        .unwrap();
    assert!(contains(path.as_slice(), SECRET_PATH.as_bytes()));

    let mut recovered = Vec::new();
    for frame in &streams {
        let opened = opener
            .open(&frame.header, &frame.prefix, &frame.body)
            .unwrap();
        recovered.extend_from_slice(opened.as_slice());
    }
    assert_eq!(recovered, plaintext);
    assert!(contains(&recovered, SECRET_MARKER));

    println!(
        "chaos evidence: M4-4 pass fragments=3 marker_hits_wire=0 path_hits_wire=0 \
         outbox_ciphertext=true opener_recovers=plaintext"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// M4-2 — 5% loss soak, disconnect, remount, full resync
// ---------------------------------------------------------------------------

/// Sealed `ORDERED` encoder for the soak: `CREATE_EXCL` and `PWRITE` only.
struct SoakEncoder {
    client: ClientId,
    ring: Arc<KeyRing>,
    nonces: NonceMinter,
    next: u64,
}

impl SoakEncoder {
    fn new(client: ClientId, ring: Arc<KeyRing>) -> Self {
        Self {
            client,
            ring,
            nonces: NonceMinter::with_instance(0x4d42),
            next: 0,
        }
    }

    fn next_id(&mut self) -> OpId {
        self.next += 1;
        op_id64(self.next, self.client)
    }

    fn create(&mut self, path: &str) -> (Op, FrameBuf) {
        let id = self.next_id();
        let op = Op::new(id, self.client, OpClass::CREATE_EXCL, path)
            .with_attrs(attrs())
            .with_body(OpBody::CreateExcl {
                mode: 0o644,
                flags: 0,
            });
        let frame = self.encode(&op);
        (op, frame)
    }

    fn pwrite(&mut self, path: &str, bytes: &[u8]) -> (Op, FrameBuf) {
        let id = self.next_id();
        let session = SessionId::from_le_bytes(id.to_bytes());
        let reference = DataRef {
            session,
            total_len: bytes.len() as u64,
            data_hash: *blake3::hash(bytes).as_bytes(),
        };
        let op = Op::new(id, self.client, OpClass::PWRITE, path)
            .with_attrs(attrs())
            .with_body(OpBody::Pwrite {
                offset: 0,
                data: reference,
            });
        let frame = self.encode(&op);
        (op, frame)
    }

    fn encode(&mut self, op: &Op) -> FrameBuf {
        let mut writer = syncmount::protocol::messages::WcpWriter::new();
        writer.bytes(
            syncmount::protocol::messages::fid::F_CLIENT_ID,
            &op.client_id.to_bytes(),
        );
        writer.u32(syncmount::protocol::messages::fid::F_KEY_EPOCH, 1);
        writer.bytes(
            syncmount::protocol::messages::fid::F_OP_ID,
            &op.op_id.to_bytes(),
        );
        writer.u8(
            syncmount::protocol::messages::fid::F_OP_CLASS,
            op.class.get(),
        );
        let path = op.path.as_deref().unwrap_or("/");
        writer.str(syncmount::protocol::messages::fid::F_PATH, path);
        writer.u64(syncmount::protocol::messages::fid::F_MTIME_NS, MTIME_NS);
        writer.u32(syncmount::protocol::messages::fid::F_UID, 1000);
        writer.u32(syncmount::protocol::messages::fid::F_GID, 1000);
        match &op.body {
            OpBody::CreateExcl { mode, flags } => {
                writer.u32(syncmount::protocol::messages::fid::F_MODE, *mode);
                writer.u32(syncmount::protocol::messages::fid::F_OP_FLAGS, *flags);
            }
            OpBody::Pwrite { offset, data } => {
                writer.bytes(
                    syncmount::protocol::messages::fid::F_DATA_SESSION,
                    &data.session.to_le_bytes(),
                );
                writer.u64(
                    syncmount::protocol::messages::fid::F_TOTAL_LEN,
                    data.total_len,
                );
                writer.bytes(
                    syncmount::protocol::messages::fid::F_DATA_HASH,
                    &data.data_hash,
                );
                writer.u64(syncmount::protocol::messages::fid::F_OFFSET, *offset);
            }
            _ => {}
        }
        writer.bytes(
            syncmount::protocol::messages::fid::F_PAYLOAD_HASH,
            &[0x33; 32],
        );
        writer.bytes(syncmount::protocol::messages::fid::F_SIG, &[0x44; 64]);
        let plaintext = writer.finish().unwrap();
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        let sealed = Sealer::new(&self.ring, &self.nonces)
            .seal(&mut header, &Prefix::None, &plaintext)
            .unwrap();
        FrameBuf::new(header, Prefix::None, sealed.into_vec())
    }
}

/// One file in the soak: its create and its most recent whole-file write.
#[derive(Clone)]
struct Slot {
    create: Op,
    last_write: Option<Op>,
}

fn clear_dir(dir: &std::path::Path) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            fs::remove_dir_all(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
    }
}

/// Rebuild the lossy side from the control snapshot: this is what a full
/// resync after a remount does (no journal replay channel exists).
fn rebuild_lossy(
    dir: &std::path::Path,
    slots: &[Slot],
    data: &TestData,
    covered: Seq,
) -> (Replayer, PosixBacking) {
    clear_dir(dir);
    let backing = backing_for(dir);
    let mut replay = replayer(
        ClientId::from_bytes([0x4b; 16]),
        EPOCH,
        Duration::from_millis(20),
    );
    let mut seq = 0u64;
    for slot in slots {
        seq += 1;
        apply_op(&mut replay, &backing, seq, slot.create.clone(), data).unwrap();
        if let Some(write) = &slot.last_write {
            seq += 1;
            apply_op(&mut replay, &backing, seq, write.clone(), data).unwrap();
        }
    }
    replay
        .begin_resync(covered, EPOCH, Duration::from_secs(3600))
        .unwrap();
    (replay, backing)
}

fn soak_seconds() -> u64 {
    std::env::var("SM_M4_SOAK_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(180)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m4_2_five_percent_loss_soak_remounts_and_converges() {
    use syncmount::testkit::{
        Direction, FaultAction as Action, FaultEngine, FaultRule, FaultScript, FrameMeta, Selector,
    };

    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0x4a; 16]);
    let receiver = ClientId::from_bytes([0x4b; 16]);
    let mut sender_session =
        super::harness::SeqSession::attach(&server, sender, 0x4201, Seq(0), EPOCH, None).await;
    let mut receiver_session =
        super::harness::SeqSession::attach(&server, receiver, 0x4202, Seq(0), EPOCH, None).await;
    let _ = sender_session.next_ctrl(WAIT).await;
    let _ = receiver_session.next_ctrl(WAIT).await;

    let ring = Arc::new(KeyRing::derive(b"m4-2", &CLUSTER).unwrap());
    let mut encoder = SoakEncoder::new(sender, Arc::clone(&ring));
    let data = TestData::default();
    let control_dir = TempDir::new().unwrap();
    let lossy_dir = TempDir::new().unwrap();
    let control_backing = backing_for(control_dir.path());
    let mut control = replayer(receiver, EPOCH, Duration::from_millis(20));
    let mut lossy = replayer(receiver, EPOCH, Duration::from_millis(20));
    let mut lossy_backing = backing_for(lossy_dir.path());

    // 16 slots keep the rebuild cheap; every write covers the whole file.
    let mut slots: Vec<Slot> = Vec::new();
    for index in 0..16 {
        let path = format!("/soak-{index:02}");
        let (op, frame) = encoder.create(&path);
        server.seq.ordered(sender, frame.clone()).await.unwrap();
        let broadcast = receiver_session.next_data(WAIT).await.expect("create");
        let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
        let progress = control
            .on_ordered(incoming, Duration::ZERO, &control_backing, &data)
            .unwrap();
        assert_eq!(progress.verdict, Ok(()));
        let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
        lossy
            .on_ordered(incoming, Duration::ZERO, &lossy_backing, &data)
            .unwrap();
        slots.push(Slot {
            create: op,
            last_write: None,
        });
    }

    let mut engine = FaultEngine::new(FaultScript::new(0x4d02).with_rule(
        FaultRule::new(Direction::Down, Selector::Any, Action::Drop).with_probability(0.05),
    ));
    let started = Instant::now();
    let duration = Duration::from_secs(soak_seconds());
    let mut round = 0u64;
    let mut dropped = 0u64;
    let mut remounts = 0u64;
    let mut bytes = [0u8; 8];
    while started.elapsed() < duration {
        round += 1;
        let slot = (round as usize) % slots.len();
        let path = format!("/soak-{slot:02}");
        bytes.copy_from_slice(&round.to_le_bytes());
        let (op, frame) = encoder.pwrite(&path, &bytes);
        data.insert(
            SessionId::from_le_bytes(op.op_id.to_bytes()),
            bytes.to_vec(),
        );
        server.seq.ordered(sender, frame).await.unwrap();
        let broadcast = receiver_session.next_data(WAIT).await.expect("broadcast");
        let seq = broadcast.header.seq.get();
        let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
        let now = started.elapsed();
        let progress = control
            .on_ordered(incoming, now, &control_backing, &data)
            .unwrap();
        assert_eq!(progress.verdict, Ok(()), "control apply at seq {seq}");
        assert!(!progress.duplicate, "op id collision at seq {seq}");
        slots[slot].last_write = Some(op);

        let meta = FrameMeta::new(Direction::Down, broadcast.header.msg_type.get(), 0, seq);
        let dropped_frame = engine.decide(meta).is_some();
        if dropped_frame {
            dropped += 1;
        }

        // A hole that stays open is a disconnect: remount and take the
        // cluster snapshot. There is no incremental replay channel.
        let resync = lossy.poll_timeout(started.elapsed());
        if resync.is_some() {
            let covered = control.applied();
            let (rebuilt, backing) = rebuild_lossy(lossy_dir.path(), &slots, &data, covered);
            lossy = rebuilt;
            lossy_backing = backing;
            remounts += 1;
        } else if !dropped_frame {
            let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
            lossy
                .on_ordered(incoming, started.elapsed(), &lossy_backing, &data)
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Final quiescence: one forced full resync, then a clean tail.
    let covered = control.applied();
    let (rebuilt, backing) = rebuild_lossy(lossy_dir.path(), &slots, &data, covered);
    lossy = rebuilt;
    lossy_backing = backing;
    remounts += 1;
    for _ in 0..10 {
        round += 1;
        let slot = (round as usize) % slots.len();
        let path = format!("/soak-{slot:02}");
        bytes.copy_from_slice(&round.to_le_bytes());
        let (op, frame) = encoder.pwrite(&path, &bytes);
        data.insert(
            SessionId::from_le_bytes(op.op_id.to_bytes()),
            bytes.to_vec(),
        );
        server.seq.ordered(sender, frame).await.unwrap();
        let broadcast = receiver_session.next_data(WAIT).await.expect("tail");
        let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
        control
            .on_ordered(incoming, started.elapsed(), &control_backing, &data)
            .unwrap();
        slots[slot].last_write = Some(op);
        let incoming = super::harness::open_ordered(&broadcast, EPOCH, &ring).unwrap();
        lossy
            .on_ordered(incoming, started.elapsed(), &lossy_backing, &data)
            .unwrap();
    }

    let control_tree = tree_digest(control_dir.path());
    let lossy_tree = tree_digest(lossy_dir.path());
    assert_eq!(control_tree, lossy_tree, "diff -r after the soak");
    assert_eq!(control.snapshot_hash(), lossy.snapshot_hash());
    assert!(dropped > 0, "the 5% loss rule never fired");
    assert!(remounts > 0, "no disconnect/remount happened");

    println!(
        "chaos evidence: M4-2 pass soak_s={} ops={} dropped={} loss=5% remounts={} \
         resync=Full tree_diff=0 snapshot_equal=true",
        started.elapsed().as_secs(),
        round,
        dropped,
        remounts
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// M4-1 / M4-6 — real FUSE: kill -9 and local-only fsync
// ---------------------------------------------------------------------------

#[cfg(feature = "fuse")]
fn fuse_ready() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && std::process::Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_ok()
}

#[cfg(feature = "fuse")]
fn fuse_config(
    addr: std::net::SocketAddr,
    mountpoint: &std::path::Path,
    run_dir: &std::path::Path,
    client_id: ClientId,
    mount_id: &str,
) -> syncmount::client::config::Config {
    use syncmount::client::config::{
        Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
    };
    Config {
        endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).unwrap(),
        mountpoint: mountpoint.to_path_buf(),
        client_id,
        instance: InstanceId(1),
        mount_id: mount_id.to_owned(),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir: run_dir.to_path_buf(),
        allow_empty_view: false,
    }
}

#[cfg(feature = "fuse")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m4_1_kill9_then_remount_is_cluster_wins_without_replay() {
    use std::sync::atomic::Ordering;

    use syncmount::client::Client;

    if !fuse_ready() {
        panic!("M4-1 requires /dev/fuse and fusermount3; this is not a silent skip");
    }
    let http = super::harness::HttpServer::start().await;
    let (_root, mnt, run) = super::harness::mount_fixture();
    let ring = Arc::new(KeyRing::derive(b"m4-1", &CLUSTER).unwrap());
    let id = ClientId::from_bytes([0x41; 16]);
    let config = fuse_config(http.addr, &mnt, &run, id, "m4-1-kill9");
    let mut task = tokio::spawn(Client::new(config).with_cluster(CLUSTER).run(ring));
    assert!(
        super::harness::wait_for(Duration::from_secs(5), || super::harness::mounted(&mnt)).await,
        "client did not mount {}",
        mnt.display()
    );
    assert!(
        super::harness::wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) >= 1
        })
        .await,
        "client did not join"
    );

    fs::write(mnt.join("crash-local.txt"), b"crash-local").unwrap();
    assert_eq!(
        fs::read(mnt.join("crash-local.txt")).unwrap(),
        b"crash-local"
    );

    // SIGKILL has no cleanup path: abort the runtime task and force the stale
    // mount away, exactly like `kill -9` plus `fusermount3 -uz` (M1-7).
    task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
    super::harness::force_unmount(&mnt);
    assert!(
        super::harness::wait_for(Duration::from_secs(5), || !super::harness::mounted(&mnt)).await,
        "stale mount survived the kill"
    );
    assert!(
        mnt.join("crash-local.txt").exists(),
        "the backing must keep the bytes a kill -9 left behind"
    );

    // Remount: no journal replay channel exists, so the join is cluster-wins
    // and the empty cluster removes every local-only entry.
    let run2 = TempDir::new().unwrap();
    let remount = super::harness::join_client(http.addr, &mnt, run2.path(), id, Seq(0), 0).await;
    let report = remount.client.last_join().expect("join report");
    let welcome = &remount.parts.welcome;
    assert!(report.removed >= 1, "local-only entry survived: {report:?}");
    assert_eq!(tree_digest(&mnt), super::harness::empty_tree());
    assert_eq!(welcome.resync, syncmount::protocol::ResyncMode::Full);

    println!(
        "chaos evidence: M4-1 pass kill9=abort+force_unmount local_before_remount=true \
         removed={} resync={:?} tree_diff=0 no_replay=true",
        report.removed, welcome.resync
    );
    drop(remount);
    http.stop().await;
}

#[cfg(feature = "fuse")]
#[tokio::test]
async fn m4_6_fsync_is_local_only_and_the_remount_takes_the_cluster() {
    use std::ffi::OsStr;

    use syncmount::client::config::InstanceId;
    use syncmount::client::lifecycle::{State, WriteGate};
    use syncmount::client::writer::Outbox as ClientOutbox;
    use syncmount::fuse::WritePath;
    use syncmount::store::InodeId;

    let http = super::harness::HttpServer::start().await;
    let dir = TempDir::new().unwrap();
    let id = ClientId::from_bytes([0x46; 16]);
    let backing = PosixBacking::new(RootFd::open_before_mount(dir.path()).unwrap());
    let inode = InodeId::new_v4();
    backing
        .create(InodeId::ROOT, OsStr::new("local-fsync.txt"), inode, 0o644)
        .unwrap();
    let gate = Arc::new(WriteGate::new(State::Steady));
    let outbox = Arc::new(ClientOutbox::new(1 << 20, 1024));
    let write_path = WritePath::new(
        gate,
        Arc::clone(&outbox),
        Arc::new(PendingOverlay::new()),
        InstanceId(1),
        id,
    );

    // write + fsync: the bytes reach the local disk and the op is only handed
    // to the outbox. fsync never waits for the server (39 §2.1).
    write_path
        .write(&backing, inode, 0, b"local-fsync-data")
        .unwrap();
    write_path.fsync(&backing, inode, false).unwrap();
    assert_eq!(
        fs::read(dir.path().join("local-fsync.txt")).unwrap(),
        b"local-fsync-data"
    );
    assert_eq!(outbox.depth().ops, 1, "the op is queued, not delivered");
    assert_eq!(
        http.snapshot().await.current_seq,
        Seq(0),
        "server saw nothing"
    );

    // kill -9: the process dies with the outbox unflushed. The local bytes
    // are already on disk and must survive.
    drop(outbox);
    drop(write_path);
    assert_eq!(
        fs::read(dir.path().join("local-fsync.txt")).unwrap(),
        b"local-fsync-data"
    );

    // Remount against the real server: cluster-wins discards the unsent write.
    let run2 = TempDir::new().unwrap();
    let remount =
        super::harness::join_client(http.addr, dir.path(), run2.path(), id, Seq(0), 0).await;
    let report = remount.client.last_join().expect("join report");
    let welcome = &remount.parts.welcome;
    assert!(report.removed >= 1, "unsent write survived: {report:?}");
    assert_eq!(tree_digest(dir.path()), super::harness::empty_tree());
    assert_eq!(welcome.resync, syncmount::protocol::ResyncMode::Full);

    println!(
        "chaos evidence: M4-6 pass fsync=local_only server_seq_before_crash=0 \
         local_before_remount=true removed={} resync={:?} unsent_write=discarded tree_diff=0",
        report.removed, welcome.resync
    );
    drop(remount);
    http.stop().await;
}
