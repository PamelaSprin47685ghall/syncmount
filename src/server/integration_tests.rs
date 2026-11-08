//! Server integration tests: handshake, ordered commit, replay and compaction.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::crypto::secret::MasterKey;
use crate::protocol::crypto::{NonceMinter, PskKeyRing, PskSalt, Sealer};
use crate::protocol::handshake::{ClientHandshake, ClientPhase};
use crate::protocol::messages::{DataRef, Message, WcpWriter, fid};
use crate::protocol::{
    Caps, ClientId, CtrlPrefix, Flags, FrameBuf, FrameDecoder, FrameHeader, FrameRef, KickReason,
    Limits, MsgType, OpClass, Prefix, ProtoVersion, Seq, SessionId, decode_plain, decode_sealed,
    encode_frame,
};
use crate::server::Server;
use crate::server::config::ServeConfig;
use crate::server::online::Outbox;
use crate::server::sequencer::{AttachRequest, DetachCause, ReplayStep, Sequencer, now_secs};
use crate::server::store::{CommitRequest, StoreHandle};
use crate::server::wire::WireOp;
use crate::transport::{DialOptions, Endpoint, HttpTransport, PeerId};

const MASTER: &[u8] = b"server-integration-test";

struct Harness {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    config: Arc<ServeConfig>,
    store: StoreHandle,
    sequencer: Sequencer,
    actor: tokio::task::JoinHandle<()>,
    epoch: u64,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with_config(ServeConfig::for_tests()).await
    }

    async fn start_with_config(config: ServeConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.db");
        let path_for_thread = path.clone();
        let (store, meta) =
            tokio::task::spawn_blocking(move || StoreHandle::start(path_for_thread))
                .await
                .unwrap()
                .unwrap();
        let master = master();
        let ring = Arc::new(master.derive_psk_keyring(&PskSalt::DEFAULT).unwrap());
        let config = Arc::new(config);
        let metrics = Arc::new(crate::server::Metrics::new(crate::server::Epoch::new(
            meta.epoch as u64,
        )));
        let (sequencer, actor) =
            Sequencer::start(Arc::clone(&config), meta, store.clone(), ring, metrics);
        Self {
            _dir: dir,
            path,
            config,
            store,
            sequencer,
            actor,
            epoch: meta.epoch as u64,
        }
    }

    async fn attach(
        &self,
        nonce: u64,
        applied: Seq,
    ) -> (SessionId, u64, mpsc::Receiver<Bytes>, mpsc::Receiver<Bytes>) {
        let (outbox, data, ctrl) = Outbox::new(&self.config.outbox);
        let session_id = SessionId(rand::random::<u128>().max(1));
        let reply = self
            .sequencer
            .attach(AttachRequest {
                session_id,
                nonce,
                peer: PeerId::from_serial(nonce),
                outbox,
                epoch_seen: self.epoch,
                applied_seq: applied,
            })
            .await
            .unwrap();
        (session_id, reply.generation, data, ctrl)
    }

    async fn stop(self) -> tempfile::TempDir {
        let _ = self.sequencer.shutdown().await;
        let _ = self.actor.await;
        let _ = self.store.shutdown().await;
        self._dir
    }
}

fn master() -> MasterKey {
    MasterKey::derive_psk_from_password(MASTER, &PskSalt::DEFAULT).unwrap()
}

fn psk() -> [u8; 32] {
    *master().as_bytes()
}

fn decode(bytes: &Bytes) -> FrameBuf {
    let mut decoder = FrameDecoder::new(Limits::default());
    decoder.push(bytes).unwrap();
    decoder.next_frame_owned().unwrap().unwrap()
}

fn dummy_wire() -> Vec<u8> {
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let body = vec![0x5a; 30];
    header.len = body.len() as u32;
    encode_frame(&FrameRef::new(&header, &Prefix::None, &body)).unwrap()
}

fn create_op(op_id: [u8; 16], path: &str) -> WireOp {
    WireOp {
        op_id,
        class: OpClass::CREATE_EXCL,
        path: path.to_owned(),
        path2: None,
        target: None,
        mode: Some(0o644),
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        data: None,
        offset: None,
        length: None,
        lock_type: None,
        lock_action: None,
        lock_start: None,
        lock_len: None,
    }
}

fn request(op: WireOp) -> CommitRequest {
    CommitRequest {
        session: [9; 16],
        op,
        content: None,
        wire: dummy_wire(),
        created_at: now_secs(),
    }
}

async fn recv_seq(rx: &mut mpsc::Receiver<Bytes>) -> FrameBuf {
    let bytes = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for a frame")
        .expect("downlink closed");
    decode(&bytes)
}

async fn recv_ordered(rx: &mut mpsc::Receiver<Bytes>) -> FrameBuf {
    loop {
        let frame = recv_seq(rx).await;
        if frame.header.msg_type == MsgType::ORDERED {
            return frame;
        }
    }
}

fn write_op(
    op_id: [u8; 16],
    path: &str,
    data: &[u8],
    class: OpClass,
    offset: Option<u64>,
) -> WireOp {
    WireOp {
        op_id,
        class,
        path: path.to_owned(),
        path2: None,
        target: None,
        mode: None,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        data: Some(DataRef {
            session: SessionId(9),
            total_len: data.len() as u64,
            data_hash: *blake3::hash(data).as_bytes(),
        }),
        offset,
        length: None,
        lock_type: None,
        lock_action: None,
        lock_start: None,
        lock_len: None,
    }
}

#[tokio::test]
async fn ordered_commits_are_serial_and_broadcast_with_unique_seq() {
    let harness = Harness::start().await;
    let (first, _, mut first_data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    let (second, _, mut second_data, _) = harness.attach(2, Seq::UNSEQUENCED).await;

    harness
        .sequencer
        .ordered(first, request(create_op([1; 16], "/a")))
        .await
        .unwrap();
    let frame = recv_seq(&mut first_data).await;
    assert_eq!(frame.header.msg_type, MsgType::ORDERED);
    assert_eq!(frame.header.seq, Seq(1));
    let frame = recv_seq(&mut second_data).await;
    assert_eq!(frame.header.seq, Seq(1));

    harness
        .sequencer
        .ordered(second, request(create_op([2; 16], "/b")))
        .await
        .unwrap();
    let frame = recv_seq(&mut first_data).await;
    assert_eq!(frame.header.seq, Seq(2));
    let frame = recv_seq(&mut second_data).await;
    assert_eq!(frame.header.seq, Seq(2));

    let snapshot = harness.sequencer.snapshot().await.unwrap();
    assert_eq!(snapshot.current_seq, Seq(2));
    assert_eq!(snapshot.clients, 2);
    assert_eq!(snapshot.online, 2);

    let db =
        crate::store::sqlite::Db::open(&harness.path, crate::store::sqlite::Role::Server).unwrap();
    let read = db.read().unwrap();
    assert!(read.object_by_path("/a").unwrap().is_some());
    assert!(read.object_by_path("/b").unwrap().is_some());
    drop(read);
    drop(db);

    let _ = harness.stop().await;
}

#[tokio::test]
async fn plan_reject_consumes_no_seq_and_reaches_only_the_author() {
    let harness = Harness::start().await;
    let (author, _, mut data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([1; 16], "/a")))
        .await
        .unwrap();
    let _ = recv_seq(&mut data).await;

    harness
        .sequencer
        .ordered(author, request(create_op([2; 16], "/a")))
        .await
        .unwrap();
    let error = recv_seq(&mut ctrl).await;
    assert_eq!(error.header.msg_type, MsgType::ERROR);
    let body = match decode_plain(MsgType::ERROR, &error.body, &Limits::default()).unwrap() {
        Message::Error(error) => error,
        other => panic!("expected ERROR, got {other:?}"),
    };
    assert_eq!(body.reason, crate::protocol::TrnReason::Protocol);
    assert_eq!(&body.detail[..16], &[2; 16]);
    assert_eq!(
        i32::from_le_bytes(body.detail[16..20].try_into().unwrap()),
        crate::state::Errno::EEXIST.raw()
    );

    let snapshot = harness.sequencer.snapshot().await.unwrap();
    assert_eq!(
        snapshot.current_seq,
        Seq(1),
        "a rejection must not consume a seq"
    );
    assert!(
        data.try_recv().is_err(),
        "a rejection must not be broadcast"
    );

    let _ = harness.stop().await;
}

#[tokio::test]
async fn an_oversized_reject_state_becomes_a_resync_marker() {
    let harness = Harness::start().await;
    let (author, _, mut data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;

    harness
        .sequencer
        .ordered(author, request(create_op([1; 16], "/big")))
        .await
        .unwrap();
    let _ = recv_ordered(&mut data).await;

    // One MiB is sixteen chunks; the rejection state for this path carries
    // the object, every chunk ref and every chunk's data.
    let content = vec![0x5a; 1024 * 1024];
    let mut write = request(write_op([2; 16], "/big", &content, OpClass::WRITE, None));
    write.content = Some(content);
    harness.sequencer.ordered(author, write).await.unwrap();
    let _ = recv_ordered(&mut data).await;

    harness
        .sequencer
        .ordered(author, request(create_op([3; 16], "/big")))
        .await
        .unwrap();
    let error = recv_seq(&mut ctrl).await;
    assert_eq!(error.header.msg_type, MsgType::ERROR);
    let body = match decode_plain(MsgType::ERROR, &error.body, &Limits::default()).unwrap() {
        Message::Error(error) => error,
        other => panic!("expected ERROR, got {other:?}"),
    };
    let detail_max = usize::from(Limits::default().detail_max);
    assert!(
        body.detail.len() <= detail_max,
        "detail is {} bytes, limit {detail_max}",
        body.detail.len()
    );
    assert_eq!(&body.detail[..16], &[3; 16]);
    assert_eq!(
        u32::from_le_bytes(body.detail[20..24].try_into().unwrap()),
        u32::MAX,
        "an oversized state must become the resync sentinel"
    );
    let encoded = body.encode().unwrap();
    let decoded = match decode_plain(MsgType::ERROR, &encoded, &Limits::default()).unwrap() {
        Message::Error(error) => error,
        other => panic!("expected ERROR, got {other:?}"),
    };
    assert_eq!(decoded.detail, body.detail);
    assert_eq!(
        harness.sequencer.snapshot().await.unwrap().current_seq,
        Seq(2),
        "a rejection must not consume a seq"
    );
    assert!(
        data.try_recv().is_err(),
        "a rejection must not be broadcast"
    );

    let _ = harness.stop().await;
}

#[tokio::test]
async fn duplicate_op_returns_the_original_seq_without_a_new_event() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([7; 16], "/a")))
        .await
        .unwrap();
    let first = recv_seq(&mut data).await;
    assert_eq!(first.header.seq, Seq(1));

    let retry = create_op([7; 16], "/elsewhere");
    harness
        .sequencer
        .ordered(author, request(retry))
        .await
        .unwrap();
    let echo = recv_seq(&mut data).await;
    assert_eq!(echo.header.seq, Seq(1));
    assert_eq!(
        harness.sequencer.snapshot().await.unwrap().current_seq,
        Seq(1)
    );

    let _ = harness.stop().await;
}

#[tokio::test]
async fn restart_recovers_epoch_seq_and_state() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    for (index, path) in ["/one", "/two"].into_iter().enumerate() {
        let mut op = create_op([(index + 1) as u8; 16], path);
        op.op_id = [(index + 1) as u8; 16];
        harness
            .sequencer
            .ordered(author, request(op))
            .await
            .unwrap();
        let _ = recv_seq(&mut data).await;
    }
    let epoch = harness.epoch;
    let path = harness.path.clone();
    let dir = harness.stop().await;

    let reopened = path.clone();
    let (store, meta) = tokio::task::spawn_blocking(move || StoreHandle::start(reopened))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.epoch as u64, epoch);
    assert_eq!(meta.seq, 2);
    let db = crate::store::sqlite::Db::open(&path, crate::store::sqlite::Role::Server).unwrap();
    let read = db.read().unwrap();
    assert!(read.object_by_path("/one").unwrap().is_some());
    assert!(read.object_by_path("/two").unwrap().is_some());
    drop(read);
    drop(db);
    assert_eq!(store.events(meta.epoch, 0, 16).await.unwrap().len(), 2);
    store.shutdown().await.unwrap();
    drop(dir);
}

#[tokio::test]
async fn compaction_bumps_epoch_and_keeps_the_state() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([1; 16], "/a")))
        .await
        .unwrap();
    let _ = recv_seq(&mut data).await;

    let report = harness.sequencer.compact().await.unwrap();
    assert_eq!(report.epoch, harness.epoch as i64 + 1);
    assert!(report.events >= 1);
    let snapshot = harness.sequencer.snapshot().await.unwrap();
    assert_eq!(snapshot.epoch, report.epoch as u64);
    assert_eq!(snapshot.current_seq, Seq(report.events));

    let db =
        crate::store::sqlite::Db::open(&harness.path, crate::store::sqlite::Role::Server).unwrap();
    let read = db.read().unwrap();
    assert!(read.object_by_path("/a").unwrap().is_some());
    assert_eq!(read.meta_i64("epoch").unwrap(), report.epoch);
    drop(read);
    drop(db);

    let _ = harness.stop().await;
}

#[tokio::test]
async fn replay_cursor_flips_to_online_only_when_caught_up() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    for index in 1..=3u8 {
        harness
            .sequencer
            .ordered(
                author,
                request(create_op([index; 16], &format!("/f{index}"))),
            )
            .await
            .unwrap();
        let _ = recv_seq(&mut data).await;
    }

    let (replayer, generation, mut replay_data, _) = harness.attach(2, Seq::UNSEQUENCED).await;
    let events = harness
        .store
        .events(harness.epoch as i64, 0, 16)
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    let ring = PskKeyRing::derive(&psk(), &PskSalt::DEFAULT).unwrap();
    let nonces = NonceMinter::new(&mut rand::rng());
    for event in &events {
        let frame = crate::server::wire::replay_ordered(event, &ring, &nonces).unwrap();
        let frame = crate::server::wire::with_seq(&frame, Seq(event.seq as u64)).unwrap();
        let decoded = decode(&Bytes::from(frame));
        assert_eq!(decoded.header.seq, Seq(event.seq as u64));
    }

    let step = harness
        .sequencer
        .replay_done(replayer, generation, Seq(1))
        .await
        .unwrap();
    assert_eq!(step, ReplayStep::Continue { target: Seq(3) });
    let step = harness
        .sequencer
        .replay_done(replayer, generation, Seq(3))
        .await
        .unwrap();
    assert_eq!(step, ReplayStep::Online);
    assert!(
        replay_data.try_recv().is_err(),
        "live frames start after replay"
    );

    let _ = harness.stop().await;
}

#[tokio::test]
async fn write_persists_chunks_and_replay_content_round_trips() {
    let harness = Harness::start().await;
    let (author, _, mut data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([4; 16], "/w")))
        .await
        .unwrap();
    let frame = recv_seq(&mut data).await;
    assert_eq!(frame.header.seq, Seq(1));
    let bytes = b"hello world".to_vec();
    let op = WireOp {
        op_id: [5; 16],
        class: OpClass::WRITE,
        path: "/w".to_owned(),
        path2: None,
        target: None,
        mode: None,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        data: Some(DataRef {
            session: SessionId(9),
            total_len: bytes.len() as u64,
            data_hash: *blake3::hash(&bytes).as_bytes(),
        }),
        offset: None,
        length: None,
        lock_type: None,
        lock_action: None,
        lock_start: None,
        lock_len: None,
    };
    let mut request = request(op);
    request.content = Some(bytes.clone());
    harness.sequencer.ordered(author, request).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = recv_seq(&mut data).await;
            if frame.header.msg_type == MsgType::ORDERED {
                return frame;
            }
        }
    })
    .await
    {
        Ok(frame) => {
            assert_eq!(frame.header.seq, Seq(2), "write must be sequenced");
        }
        _ => {
            if let Ok(Some(frame)) = tokio::time::timeout(Duration::from_secs(1), ctrl.recv()).await
            {
                let frame = decode(&frame);
                let body = match decode_plain(MsgType::ERROR, &frame.body, &Limits::default()) {
                    Ok(Message::Error(error)) => error,
                    other => panic!("expected ERROR, got {other:?}"),
                };
                panic!("write was rejected: {:?} {:?}", body.reason, body.detail);
            }
            panic!("no broadcast and no error for the write");
        }
    }

    let db =
        crate::store::sqlite::Db::open(&harness.path, crate::store::sqlite::Role::Server).unwrap();
    let read = db.read().unwrap();
    let object = read.object_by_path("/w").unwrap().unwrap();
    assert_eq!(object.size, bytes.len() as u64);
    assert_eq!(object.block_count, 1);
    let chunks = read.object_chunks(object.ino).unwrap();
    assert_eq!(chunks.len(), 1);
    let chunk = read.chunk(chunks[0].hash).unwrap().unwrap();
    assert_eq!(chunk.data.as_deref(), Some(bytes.as_slice()));
    drop(read);
    drop(db);

    let events = harness
        .store
        .events(harness.epoch as i64, 0, 16)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    let write_event = events
        .iter()
        .find(|event| event.kind == crate::store::sqlite::EventKind::Write)
        .unwrap();
    let mut replay = Vec::new();
    for chunk in write_event
        .decode()
        .map(|payload| match payload {
            crate::store::sqlite::EventPayload::Write { chunks, .. } => chunks,
            _ => Vec::new(),
        })
        .unwrap()
    {
        replay.extend(harness.store.chunk_data(chunk.hash).await.unwrap().unwrap());
    }
    assert_eq!(replay, bytes);

    let ring = PskKeyRing::derive(&psk(), &PskSalt::DEFAULT).unwrap();
    let nonces = NonceMinter::new(&mut rand::rng());
    let frame = crate::server::wire::replay_ordered_with_content(
        write_event,
        &ring,
        &nonces,
        Some(&replay),
    )
    .unwrap();
    let frame = decode(&Bytes::from(frame));
    let opened = crate::protocol::crypto::Opener::with_session_key(&ring.session_key())
        .open(&frame.header, &frame.prefix, &frame.body)
        .unwrap();
    let ordered =
        match decode_sealed(MsgType::ORDERED, opened.as_slice(), &Limits::default()).unwrap() {
            Message::Ordered(ordered) => ordered,
            other => panic!("expected ORDERED, got {other:?}"),
        };
    let extra = ordered.fields.get(fid::F_EXTRA).unwrap();
    assert_eq!(extra, write_event.payload.as_slice());

    let _ = harness.stop().await;
}

/// A live PWRITE broadcast must describe the server's complete file, not the
/// author's one-chunk patch. The frame is rebuilt from the committed event,
/// and the content stream is the same complete file the replay path sends.
#[tokio::test]
async fn a_live_pwrite_broadcast_carries_the_server_file() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([4; 16], "/w")))
        .await
        .unwrap();
    let _ = recv_ordered(&mut data).await;

    let initial: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
    let mut write = request(write_op([5; 16], "/w", &initial, OpClass::WRITE, None));
    write.content = Some(initial.clone());
    harness.sequencer.ordered(author, write).await.unwrap();
    let _ = recv_ordered(&mut data).await;

    let patch = b"Z";
    let mut pwrite = request(write_op(
        [6; 16],
        "/w",
        patch,
        OpClass::PWRITE,
        Some(0),
    ));
    pwrite.content = Some(patch.to_vec());
    harness.sequencer.ordered(author, pwrite).await.unwrap();

    let ring = PskKeyRing::derive(&psk(), &PskSalt::DEFAULT).unwrap();
    let mut stream = Vec::new();
    let ordered = loop {
        let frame = recv_seq(&mut data).await;
        match frame.header.msg_type {
            MsgType::STREAM_DATA => {
                let opened =
                    crate::protocol::crypto::Opener::with_session_key(&ring.session_key())
                        .open(&frame.header, &frame.prefix, &frame.body)
                        .unwrap();
                stream.extend_from_slice(opened.as_slice());
            }
            MsgType::ORDERED => break frame,
            _ => {}
        }
    };
    assert_eq!(ordered.header.seq, Seq(3));
    let opened = crate::protocol::crypto::Opener::with_session_key(&ring.session_key())
        .open(&ordered.header, &ordered.prefix, &ordered.body)
        .unwrap();
    let message = decode_sealed(MsgType::ORDERED, opened.as_slice(), &Limits::default()).unwrap();
    let Message::Ordered(ordered) = message else {
        panic!("expected ORDERED, got {message:?}");
    };
    let extra = ordered.fields.get(fid::F_EXTRA).unwrap();
    let payload =
        crate::store::sqlite::EventPayload::decode(crate::store::sqlite::EventKind::Write, extra)
            .unwrap();
    match payload {
        crate::store::sqlite::EventPayload::Write { chunks, size, .. } => {
            assert_eq!(size, 100_000);
            assert_eq!(chunks.len(), 2, "the event describes the whole file");
            assert_eq!(chunks[0].len, 65_536);
            assert_eq!(chunks[1].len, 34_464);
        }
        other => panic!("expected a write payload, got {other:?}"),
    }
    let mut expected = initial;
    expected[0] = b'Z';
    assert_eq!(stream, expected, "the live stream is the server's file");

    let _ = harness.stop().await;
}

#[tokio::test]
async fn op_data_fragments_are_fanned_out_to_live_readers() {
    let harness = Harness::start().await;
    let (author, _, mut author_data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    let (_, _, mut reader_data, _) = harness.attach(2, Seq::UNSEQUENCED).await;
    let session = SessionId(0x5151);
    let prefix = Prefix::Route(crate::protocol::RoutePrefix::new(
        session,
        crate::protocol::StreamId::OP_DATA,
        0,
        1,
    ));
    let body = vec![0x5a; 100];
    let mut header = FrameHeader::new(
        MsgType::STREAM_DATA,
        Flags::ENC.with(Flags::ROUTED),
        0,
        Seq::UNSEQUENCED,
    );
    header.len = (prefix.encoded_len() + body.len()) as u32;
    let frame = FrameBuf::new(header, prefix, body);
    harness.sequencer.relay(author, frame).await.unwrap();
    let received = recv_seq(&mut reader_data).await;
    assert_eq!(received.header.msg_type, MsgType::STREAM_DATA);
    assert_eq!(
        received.prefix.as_route().map(|prefix| prefix.session_id),
        Some(session)
    );
    assert!(author_data.try_recv().is_err(), "the author is not echoed");

    let _ = harness.stop().await;
}

#[tokio::test]
async fn drain_waits_for_watermarks_and_reports_a_timeout() {
    let harness = Harness::start().await;
    let (author, _, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    let (other, _, _other_data, _other_ctrl) = harness.attach(2, Seq::UNSEQUENCED).await;
    harness
        .sequencer
        .ordered(author, request(create_op([1; 16], "/a")))
        .await
        .unwrap();
    let _ = recv_seq(&mut data).await;

    let timeout = harness
        .sequencer
        .drain(Duration::from_millis(20))
        .await
        .unwrap();
    assert!(timeout.timed_out);
    assert_eq!(timeout.current_seq, Seq(1));
    assert_eq!(timeout.applied_min, Seq::UNSEQUENCED);

    for session in [author, other] {
        harness
            .sequencer
            .watermark(crate::server::WatermarkReport {
                session,
                applied_seq: Seq(1),
                epoch_seen: harness.epoch,
                rtt_ms: None,
                at: std::time::Instant::now(),
            })
            .await
            .unwrap();
    }
    let report = harness
        .sequencer
        .drain(Duration::from_secs(1))
        .await
        .unwrap();
    assert!(!report.timed_out);
    assert_eq!(report.applied_min, Seq(1));

    let _ = harness.stop().await;
}

#[tokio::test]
async fn http_psk_handshake_then_ordered_broadcast() {
    let server = Server::bind(ServeConfig::for_tests(), master())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let psk_bytes = psk();
    let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
    let mut transport = HttpTransport::dial(&endpoint, &DialOptions::random())
        .await
        .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let ring = PskKeyRing::derive(&psk_bytes, &PskSalt::DEFAULT).unwrap();
    let mut client = ClientHandshake::new(
        ring,
        ClientId::from_bytes([3; 16]),
        [7; 32],
        ProtoVersion::CURRENT,
        Caps::REQUIRED,
        now_ms,
    );
    let nonces = NonceMinter::new(&mut rand::rng());
    let ctrl = CtrlPrefix::new(Seq::UNSEQUENCED, 0);
    let hello = client.hello(&nonces, &ctrl).unwrap().encode().unwrap();
    let hello_frame = crate::server::sequencer::encode_control(
        MsgType::HELLO,
        Prefix::Ctrl(ctrl),
        &hello,
        Seq::UNSEQUENCED,
    )
    .unwrap();
    transport.send(hello_frame).await.unwrap();

    let welcome_bytes = transport.recv().await.unwrap().unwrap();
    let welcome_frame = decode(&welcome_bytes);
    assert_eq!(welcome_frame.header.msg_type, MsgType::WELCOME);
    let welcome =
        match decode_plain(MsgType::WELCOME, &welcome_frame.body, &Limits::default()).unwrap() {
            Message::Welcome(welcome) => welcome,
            other => panic!("expected WELCOME, got {other:?}"),
        };
    // One client flight and one server flight: the next frame after HELLO is
    // WELCOME, and the client is steady as soon as it verifies that frame.
    let session_key = client
        .on_welcome(&welcome, &welcome_frame.body, now_ms)
        .unwrap();
    assert_eq!(client.phase(), ClientPhase::Steady);

    let mut writer = WcpWriter::new();
    writer.bytes(fid::F_CLIENT_ID, &[3; 16]);
    writer.u8(fid::F_OP_CLASS, OpClass::CREATE_EXCL.get());
    writer.str(fid::F_PATH, "/hello");
    writer.u64(fid::F_MTIME_NS, 1);
    writer.u32(fid::F_UID, 1000);
    writer.u32(fid::F_GID, 1000);
    writer.u32(fid::F_MODE, 0o644);
    writer.u32(fid::F_OP_FLAGS, 0);
    writer.bytes(fid::F_OP_ID, &[4; 16]);
    let body = writer.finish().unwrap();
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let sealed = Sealer::with_session_key(&session_key, &nonces)
        .seal(&mut header, &Prefix::None, &body)
        .unwrap();
    transport
        .send(Bytes::from(
            encode_frame(&FrameRef::new(&header, &Prefix::None, sealed.as_bytes())).unwrap(),
        ))
        .await
        .unwrap();

    let broadcast = transport.recv().await.unwrap().unwrap();
    let broadcast = decode(&broadcast);
    assert_eq!(broadcast.header.msg_type, MsgType::ORDERED);
    assert_eq!(broadcast.header.seq, Seq(1));
    let opened = crate::protocol::crypto::Opener::with_session_key(&session_key)
        .open(&broadcast.header, &broadcast.prefix, &broadcast.body)
        .unwrap();
    let ordered =
        match decode_sealed(MsgType::ORDERED, opened.as_slice(), &Limits::default()).unwrap() {
            Message::Ordered(ordered) => ordered,
            other => panic!("expected ORDERED, got {other:?}"),
        };
    assert_eq!(ordered.op_id.to_bytes(), [4; 16]);
    assert_eq!(ordered.path_str(), Some("/hello"));

    transport.close().await.unwrap();
    let _ = stop_tx.send(());
    task.await.unwrap();
}

#[tokio::test]
async fn replayed_hello_is_closed_before_welcome() {
    let server = Server::bind(ServeConfig::for_tests(), master())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let ring = PskKeyRing::derive(&psk(), &PskSalt::DEFAULT).unwrap();
    let client = ClientHandshake::new(
        ring,
        ClientId::from_bytes([9; 16]),
        [0x5a; 32],
        ProtoVersion::CURRENT,
        Caps::REQUIRED,
        now_ms,
    );
    let ctrl = CtrlPrefix::new(Seq::UNSEQUENCED, 0);
    let hello = client
        .hello(&NonceMinter::new(&mut rand::rng()), &ctrl)
        .unwrap()
        .encode()
        .unwrap();
    let hello_frame = crate::server::sequencer::encode_control(
        MsgType::HELLO,
        Prefix::Ctrl(ctrl),
        &hello,
        Seq::UNSEQUENCED,
    )
    .unwrap();

    // First use of the nonce succeeds.
    let mut first = HttpTransport::dial(&endpoint, &DialOptions::random())
        .await
        .unwrap();
    first.send(hello_frame.clone()).await.unwrap();
    let welcome = first.recv().await.unwrap().unwrap();
    assert_eq!(decode(&welcome).header.msg_type, MsgType::WELCOME);
    first.close().await.unwrap();

    // The same HELLO is a replay. The server must close before WELCOME.
    let mut replay = HttpTransport::dial(&endpoint, &DialOptions::random())
        .await
        .unwrap();
    replay.send(hello_frame).await.unwrap();
    if let Ok(Ok(Some(bytes))) =
        tokio::time::timeout(Duration::from_secs(3), replay.recv()).await
    {
        let frame = decode(&bytes);
        assert_ne!(
            frame.header.msg_type,
            MsgType::WELCOME,
            "a replayed HELLO must not be accepted"
        );
    }
    let _ = replay.close().await;
    let _ = stop_tx.send(());
    task.await.unwrap();
}

#[tokio::test]
async fn group_commit_broadcasts_a_batch_in_sequence_order() {
    let harness = Harness::start().await;
    let (first, _, mut first_data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    let (_second, _, mut second_data, _) = harness.attach(2, Seq::UNSEQUENCED).await;

    // Three operations enter the actor back to back, inside one window.
    for index in 1..=3u8 {
        harness
            .sequencer
            .ordered(
                first,
                request(create_op([index; 16], &format!("/f{index}"))),
            )
            .await
            .unwrap();
    }
    for expected in 1..=3u64 {
        let frame = recv_ordered(&mut first_data).await;
        assert_eq!(frame.header.seq, Seq(expected));
        let frame = recv_ordered(&mut second_data).await;
        assert_eq!(frame.header.seq, Seq(expected));
    }

    let snapshot = harness.sequencer.snapshot().await.unwrap();
    assert_eq!(snapshot.current_seq, Seq(3));
    let db =
        crate::store::sqlite::Db::open(&harness.path, crate::store::sqlite::Role::Server).unwrap();
    let read = db.read().unwrap();
    for index in 1..=3u8 {
        assert!(
            read.object_by_path(&format!("/f{index}")).unwrap().is_some(),
            "/f{index} must be committed"
        );
    }
    drop(read);
    drop(db);

    let _ = harness.stop().await;
}

#[tokio::test]
async fn a_full_outbox_kicks_instead_of_skipping_an_ordered_frame() {
    // A zero-frame budget overflows on the first data frame. The server must
    // end the session instead of dropping the frame: a later ORDERED would
    // expose a sequence hole that the client cannot repair.
    let mut config = ServeConfig::for_tests();
    config.outbox.cap_frames = 0;
    config.outbox.cap_bytes = 1;
    let harness = Harness::start_with_config(config).await;
    let (session, _, mut data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;

    harness
        .sequencer
        .ordered(session, request(create_op([7; 16], "/full")))
        .await
        .unwrap();

    assert!(
        data.try_recv().is_err(),
        "a frame that cannot be queued must not reach the stream"
    );
    let kick = recv_seq(&mut ctrl).await;
    assert_eq!(kick.header.msg_type, MsgType::KICK);

    // The kicked session still owned advisory locks, so the server must
    // release them through a committed LEAVE. The create committed as seq 1;
    // a LEAVE makes it seq 2.
    let mut seq = harness.sequencer.snapshot().await.unwrap().current_seq;
    for _ in 0..100 {
        if seq == Seq(2) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        seq = harness.sequencer.snapshot().await.unwrap().current_seq;
    }
    assert_eq!(seq, Seq(2), "the kicked session's LEAVE must be committed");

    let _ = harness.stop().await;
}

#[tokio::test]
async fn group_commit_keeps_rejections_out_of_the_transaction() {
    let harness = Harness::start().await;
    let (author, _, mut data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;

    // The middle operation is rejected; the two around it must still commit
    // consecutively and the rejection must reach only the author.
    harness
        .sequencer
        .ordered(author, request(create_op([1; 16], "/a")))
        .await
        .unwrap();
    harness
        .sequencer
        .ordered(author, request(create_op([2; 16], "/a")))
        .await
        .unwrap();
    harness
        .sequencer
        .ordered(author, request(create_op([3; 16], "/b")))
        .await
        .unwrap();

    let first = recv_ordered(&mut data).await;
    assert_eq!(first.header.seq, Seq(1));
    let second = recv_ordered(&mut data).await;
    assert_eq!(second.header.seq, Seq(2));
    let error = recv_seq(&mut ctrl).await;
    assert_eq!(error.header.msg_type, MsgType::ERROR);
    let body = match decode_plain(MsgType::ERROR, &error.body, &Limits::default()).unwrap() {
        Message::Error(error) => error,
        other => panic!("expected ERROR, got {other:?}"),
    };
    assert_eq!(&body.detail[..16], &[2; 16]);
    assert_eq!(
        i32::from_le_bytes(body.detail[16..20].try_into().unwrap()),
        crate::state::Errno::EEXIST.raw()
    );
    assert!(
        data.try_recv().is_err(),
        "the rejected operation must not be broadcast"
    );

    let snapshot = harness.sequencer.snapshot().await.unwrap();
    assert_eq!(snapshot.current_seq, Seq(2));
    let _ = harness.stop().await;
}

/// A session whose watermark stops advancing is ended, not kept attached.
///
/// The failed deployment logged `pending_ops=16` every 31 s for minutes and
/// left the session in place. A slow client is allowed to be slow; a client
/// whose `applied_seq` has not moved at all while the server owes events is
/// wedged, and a reconnect is the only recovery.
#[tokio::test]
async fn a_stalled_watermark_ends_the_session() {
    let harness = Harness::start().await;
    let (author, author_generation, mut data, _) = harness.attach(1, Seq::UNSEQUENCED).await;
    for index in 1..=3u8 {
        harness
            .sequencer
            .ordered(
                author,
                request(create_op([index; 16], &format!("/f{index}"))),
            )
            .await
            .unwrap();
        let _ = recv_seq(&mut data).await;
    }
    // The author is caught up; only the replayer may be diagnosed as stalled.
    harness
        .sequencer
        .detach(author, author_generation, DetachCause::WriterClosed)
        .await
        .unwrap();
    let (_replayer, _generation, _data, mut ctrl) = harness.attach(2, Seq(0)).await;
    assert_eq!(harness.sequencer.snapshot().await.unwrap().clients, 1);

    harness
        .sequencer
        .tick(Instant::now() + super::health::STALL_KICK + Duration::from_secs(1))
        .await
        .unwrap();
    let frame = recv_seq(&mut ctrl).await;
    assert_eq!(
        frame.header.msg_type,
        MsgType::KICK,
        "a stalled session must receive a KICK"
    );
    assert_eq!(harness.sequencer.snapshot().await.unwrap().clients, 0);

    let _ = harness.stop().await;
}

/// A failed replay ends its own generation only.
#[tokio::test]
async fn a_replay_failure_kick_checks_the_generation() {
    let harness = Harness::start().await;
    let (session, generation, _data, mut ctrl) = harness.attach(1, Seq::UNSEQUENCED).await;

    harness
        .sequencer
        .kick(session, generation + 1, KickReason::Stalled)
        .await
        .unwrap();
    assert_eq!(
        harness.sequencer.snapshot().await.unwrap().clients,
        1,
        "a stale generation must not end its successor"
    );

    harness
        .sequencer
        .kick(session, generation, KickReason::Stalled)
        .await
        .unwrap();
    let frame = recv_seq(&mut ctrl).await;
    assert_eq!(frame.header.msg_type, MsgType::KICK);
    assert_eq!(harness.sequencer.snapshot().await.unwrap().clients, 0);

    let _ = harness.stop().await;
}
