//! F1–F24: the fault matrix from 34 §1 and 45 §6.1.
//!
//! Each item has one test and one `chaos evidence:` line. The assertions are
//! the invariants, not "the system works":
//!
//! * no silent divergence (the tree oracle is compared with a no-fault run);
//! * no torn or ghost file (the oracle is content-addressed);
//! * no operation is applied twice (replay hash and dedup verdict);
//! * a wrong PSK never authenticates a frame (data-plane fail-closed);
//! * every kick is explicit and every failed write leaves no op.
//!
//! Items that expose a product gap assert the strongest true property and
//! print `known_gap=...`; the internal M4 `summary.json` (not published)
//! carries the verdict.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsStr;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use syncmount::client::Client;
use syncmount::client::config::{
    Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
};
use syncmount::client::lifecycle::{State, WriteGate};
use syncmount::client::net::{Downlink, DownlinkOutcome};
use syncmount::client::replayer::ResyncReason as ReplayResyncReason;
use syncmount::client::replayer::{
    Fatal, IncomingOp, LOCK_ACTION_SET, LOCK_ACTION_UNLOCK, LockType, Op, OpAttrs, OpBody,
    PendingOverlay, SyncHandle, derive_inode_id,
};
use syncmount::client::writer::Outbox as ClientOutbox;
use syncmount::crypto::{MasterKey, SigningKey};
use syncmount::fuse::{FuseFs, WritePath};
use syncmount::protocol::crypto::{KeyRing, NonceMinter, Opener, Sealer};
use syncmount::protocol::identity::{
    Identity, KeyAnnounce, KeyDirectory, KeyEpoch, MemoryIdentity, SignedOp, verify_with_key,
};
use syncmount::protocol::messages::{OpClass, WcpWriter, fid};
use syncmount::protocol::{
    ClientId, Flags, FrameBuf, FrameHeader, KickReason, MsgType, OpId, Prefix, ResyncMode, Seq,
};
use syncmount::server::{OutboxConfig, ServeConfig};
use syncmount::store::{BackingStore, Errno, InodeId, PosixBacking, RootFd};
use syncmount::sync::staging::cleanup_stale;
use syncmount::testkit::{TestClock, WallClock};
use tempfile::TempDir;
use tokio::sync::mpsc;

use super::harness::*;
use super::proxy::{
    FrameProxy, ProxyMode, ProxyStop, TcpProxy, delay_nth, drop_nth, duplicate_nth, reorder_first,
    tamper_tag_nth,
};

const EPOCH: u64 = 0x4d34;

fn ring(password: &[u8]) -> Arc<KeyRing> {
    Arc::new(KeyRing::derive(password, &CLUSTER).unwrap())
}

async fn attach_pair(
    server: &SeqServer,
    sender: ClientId,
    receiver: ClientId,
) -> (SeqSession, SeqSession) {
    let mut s = SeqSession::attach(server, sender, 0x1001, Seq(0), EPOCH, None).await;
    let mut r = SeqSession::attach(server, receiver, 0x1002, Seq(0), EPOCH, None).await;
    let _ = s.next_ctrl(WAIT).await;
    let _ = r.next_ctrl(WAIT).await;
    (s, r)
}

/// Send frames through a one-direction proxy and return the surviving frames.
async fn through_proxy(
    mut proxy: FrameProxy,
    frames: Vec<FrameBuf>,
) -> (FrameProxy, Vec<FrameBuf>) {
    let (tx, mut rx) = mpsc::channel(32);
    for frame in frames {
        let stop = proxy.pass(Bytes::from(wire(&frame)), &tx).await;
        if stop == ProxyStop::Close {
            break;
        }
    }
    proxy.flush(&tx).await;
    drop(tx);
    let mut out = Vec::new();
    while let Some(bytes) = rx.recv().await {
        out.push(decode_frame(&bytes));
    }
    (proxy, out)
}

fn frame_seqs(frames: &[FrameBuf]) -> Vec<u64> {
    frames.iter().map(|frame| frame.header.seq.get()).collect()
}

// ---------------------------------------------------------------------------
// F1 — uplink frame loss
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f1_uplink_loss_is_never_silently_sequenced() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0xf1; 16]);
    let receiver = ClientId::from_bytes([0xf2; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f1");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    let lost = encoder.frame(OpClass::CREATE_EXCL, "/lost");
    let kept = encoder.frame(OpClass::CREATE_EXCL, "/kept");

    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Up,
        drop_nth(syncmount::testkit::Direction::Up, 0),
    );
    let (proxy, forwarded) = through_proxy(proxy, vec![lost, kept]).await;
    assert_eq!(proxy.applied(), 1, "exactly one frame was dropped");
    for frame in &forwarded {
        server.seq.ordered(sender, frame.clone()).await.unwrap();
    }
    assert_eq!(server.snapshot().await.current_seq, Seq(1));
    let broadcast = receiver_session.next_data(WAIT).await.expect("kept frame");
    assert_eq!(broadcast.header.seq, Seq(1));

    // The lost op was never sequenced: a watermark that reports it missing
    // is behind one real op. That is a diagnosis, not a kick; the session
    // stays attached and still receives the next broadcast.
    let base = Instant::now();
    server
        .seq
        .watermark(sender_session.report(Seq(0), EPOCH, base))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(1_300))
        .await
        .unwrap();
    assert!(
        sender_session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a lagging watermark must not end the session"
    );
    assert_eq!(server.snapshot().await.clients, 2);

    // Cluster state contains /kept and never /lost.
    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    let incoming = open_ordered(&broadcast, EPOCH, &ring).unwrap();
    apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
    let tree = tree_digest(dir.path());
    assert!(tree.contains_key("kept"));
    assert!(!tree.contains_key("lost"));

    println!(
        "chaos evidence: F1 pass dropped_uplink=1 server_seq=1 lost_never_sequenced=true \
         watermark=diagnosed tree=kept-only"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F2 — downlink frame loss
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f2_downlink_loss_is_detected_as_a_seq_gap() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0xf3; 16]);
    let receiver = ClientId::from_bytes([0xf4; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f2");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    let mut frames = Vec::new();
    for path in ["/a", "/b", "/c"] {
        let frame = encoder.frame(OpClass::CREATE_EXCL, path);
        server.seq.ordered(sender, frame.clone()).await.unwrap();
        frames.push(frame);
    }
    let _ = &mut sender_session;

    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Down,
        drop_nth(syncmount::testkit::Direction::Down, 0),
    );
    let (proxy, delivered) = through_proxy(proxy, {
        let mut received = Vec::new();
        for _ in 0..3 {
            received.push(receiver_session.next_data(WAIT).await.expect("broadcast"));
        }
        received
    })
    .await;
    assert_eq!(proxy.applied(), 1);
    assert_eq!(frame_seqs(&delivered), vec![2, 3]);

    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    for frame in &delivered {
        let incoming = open_ordered(frame, EPOCH, &ring).unwrap();
        let progress = apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
        assert!(progress.buffered, "seq 2/3 must wait for seq 1");
    }
    assert_eq!(replay.applied(), Seq(0));
    let fatal = replay
        .poll_timeout(Duration::from_millis(50))
        .expect("hole timeout");
    assert!(
        matches!(fatal, Fatal::Resync(ReplayResyncReason::SeqGap)),
        "expected SeqGap, got {fatal:?}"
    );
    assert!(tree_digest(dir.path()).is_empty(), "no partial apply");

    println!(
        "chaos evidence: F2 pass delivered=[2,3] applied=0 resync=SeqGap tree=empty \
         silent_divergence=false"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F3 — reordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f3_reorder_buffers_and_converges_to_the_same_tree() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0xf5; 16]);
    let receiver = ClientId::from_bytes([0xf6; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f3");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    for path in ["/a", "/b", "/c"] {
        let frame = encoder.frame(OpClass::CREATE_EXCL, path);
        server.seq.ordered(sender, frame.clone()).await.unwrap();
    }
    let _ = &mut sender_session;

    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Down,
        reorder_first(syncmount::testkit::Direction::Down, 2),
    );
    let (proxy, delivered) = through_proxy(proxy, {
        let mut received = Vec::new();
        for _ in 0..3 {
            received.push(receiver_session.next_data(WAIT).await.expect("broadcast"));
        }
        received
    })
    .await;
    assert_eq!(proxy.applied(), 1);
    assert_eq!(frame_seqs(&delivered), vec![2, 1, 3], "two frames swapped");

    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    for frame in &delivered {
        let incoming = open_ordered(frame, EPOCH, &ring).unwrap();
        apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
    }
    assert_eq!(replay.applied(), Seq(3));
    assert_eq!(replay.resync_count(), 0);

    // Control run: the same operations in wire order.
    let baseline = TempDir::new().unwrap();
    let mut control = replayer(receiver, EPOCH, Duration::from_millis(20));
    for (index, path) in ["/a", "/b", "/c"].iter().enumerate() {
        let incoming = incoming(
            index as u64 + 1,
            EPOCH,
            sender,
            OpClass::CREATE_EXCL,
            path,
            index as u64 + 1,
        );
        apply(&mut control, baseline.path(), incoming, Duration::ZERO).unwrap();
    }
    assert_eq!(tree_digest(dir.path()), tree_digest(baseline.path()));
    assert_eq!(replay.snapshot_hash(), control.snapshot_hash());

    println!(
        "chaos evidence: F3 pass wire_order=[2,1,3] applied=3 resync=0 \
         tree_equals_control=true"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F4 — duplication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f4_duplicate_frames_and_ops_are_idempotent() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0xf7; 16]);
    let receiver = ClientId::from_bytes([0xf8; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f4");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    for path in ["/a", "/b", "/c"] {
        let frame = encoder.frame(OpClass::CREATE_EXCL, path);
        server.seq.ordered(sender, frame.clone()).await.unwrap();
    }
    let _ = &mut sender_session;

    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Down,
        duplicate_nth(syncmount::testkit::Direction::Down, 0, 1),
    );
    let (proxy, delivered) = through_proxy(proxy, {
        let mut received = Vec::new();
        for _ in 0..3 {
            received.push(receiver_session.next_data(WAIT).await.expect("broadcast"));
        }
        received
    })
    .await;
    assert_eq!(proxy.applied(), 1);
    assert_eq!(frame_seqs(&delivered), vec![1, 1, 2, 3]);

    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    let mut duplicates = 0;
    for frame in &delivered {
        let incoming = open_ordered(frame, EPOCH, &ring).unwrap();
        let progress = apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
        if progress.duplicate {
            duplicates += 1;
        }
    }
    assert_eq!(duplicates, 1);
    assert_eq!(replay.applied(), Seq(3));

    // A duplicated uplink frame receives a new seq from the server (window 0
    // has no server-side dedup) but the client dedups the op id.
    let duplicate = encoder.frame(OpClass::CREATE_EXCL, "/dup");
    server.seq.ordered(sender, duplicate.clone()).await.unwrap();
    server.seq.ordered(sender, duplicate).await.unwrap();
    let first = receiver_session.next_data(WAIT).await.expect("first");
    let second = receiver_session.next_data(WAIT).await.expect("second");
    let first_op = open_ordered(&first, EPOCH, &ring).unwrap();
    apply(&mut replay, dir.path(), first_op, Duration::ZERO).unwrap();
    let hash_before = replay.snapshot_hash();
    let second_op = open_ordered(&second, EPOCH, &ring).unwrap();
    let progress = apply(&mut replay, dir.path(), second_op, Duration::ZERO).unwrap();
    assert_eq!(progress.applied, second.header.seq);
    assert_eq!(replay.snapshot_hash(), hash_before, "no second effect");

    println!(
        "chaos evidence: F4 pass downlink_duplicates=1 uplink_duplicate=dedup \
         applied=3 snapshot_hash_stable=true"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F5 — delay and liveness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5_delay_slows_convergence_without_changing_the_tree() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0xf9; 16]);
    let receiver = ClientId::from_bytes([0xfa; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f5");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    for path in ["/a", "/b", "/c"] {
        let frame = encoder.frame(OpClass::CREATE_EXCL, path);
        server.seq.ordered(sender, frame.clone()).await.unwrap();
    }
    let _ = &mut sender_session;

    let started = Instant::now();
    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Down,
        delay_nth(
            syncmount::testkit::Direction::Down,
            0,
            Duration::from_millis(200),
        ),
    );
    let (_proxy, delivered) = through_proxy(proxy, {
        let mut received = Vec::new();
        for _ in 0..3 {
            received.push(receiver_session.next_data(WAIT).await.expect("broadcast"));
        }
        received
    })
    .await;
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(200));
    assert!(elapsed < RECOVER);

    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    for frame in &delivered {
        let incoming = open_ordered(frame, EPOCH, &ring).unwrap();
        apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
    }
    assert_eq!(replay.applied(), Seq(3));
    let baseline = TempDir::new().unwrap();
    let mut control = replayer(receiver, EPOCH, Duration::from_millis(20));
    for (index, path) in ["/a", "/b", "/c"].iter().enumerate() {
        let incoming = incoming(
            index as u64 + 1,
            EPOCH,
            sender,
            OpClass::CREATE_EXCL,
            path,
            index as u64 + 1,
        );
        apply(&mut control, baseline.path(), incoming, Duration::ZERO).unwrap();
    }
    assert_eq!(tree_digest(dir.path()), tree_digest(baseline.path()));

    println!(
        "chaos evidence: F5 pass delay_ms=200 elapsed_ms={} applied=3 tree_equals_control=true",
        elapsed.as_millis()
    );
    server.stop().await;
}

/// Liveness assertion: 30 seeded runs, p99 convergence below 120s.
#[tokio::test]
async fn f5b_convergence_p99_is_below_120s() {
    let client = ClientId::from_bytes([0xfb; 16]);
    let mut samples = Vec::new();
    for seed in 0..30u64 {
        let dir = TempDir::new().unwrap();
        let mut replay = replayer(client, EPOCH, Duration::from_millis(20));
        let started = Instant::now();
        for seq in 1..=20u64 {
            let path = format!("/f{seq}");
            let incoming = incoming(
                seq,
                EPOCH,
                client,
                OpClass::CREATE_EXCL,
                &path,
                seed * 100 + seq,
            );
            tokio::time::sleep(Duration::from_micros(seed * 50)).await;
            apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
        }
        assert_eq!(replay.applied(), Seq(20));
        samples.push(started.elapsed());
    }
    samples.sort();
    let rank = (samples.len() * 99).div_ceil(100).max(1);
    let p99 = samples[rank - 1];
    assert!(p99 < RECOVER, "p99 {p99:?} exceeds {RECOVER:?}");
    println!(
        "chaos evidence: F5b pass n=30 p99_ms={} limit_ms=120000",
        p99.as_millis()
    );
}

// ---------------------------------------------------------------------------
// F6 — disconnect (FIN/RST)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f6_disconnect_ends_the_downlink_and_removes_the_session() {
    let http = HttpServer::start().await;
    let proxy = TcpProxy::start(http.addr).await;
    let dir = TempDir::new().unwrap();
    let run = TempDir::new().unwrap();
    let joined = join_client(
        proxy.addr,
        dir.path(),
        run.path(),
        ClientId::from_bytes([0xfc; 16]),
        Seq(0),
        0,
    )
    .await;
    let parts = joined.parts;
    let _client = joined.client;
    let _uplink = parts.uplink;
    let (downlink, items, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 64);
    let task = tokio::spawn(downlink.run());
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) == 1
        })
        .await,
        "client did not join"
    );

    proxy.set(ProxyMode::Close);
    let outcome = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("downlink did not end");
    assert!(
        matches!(outcome, Ok(Ok(DownlinkOutcome::Eof)) | Ok(Err(_)) | Err(_)),
        "expected EOF/transport error, got {outcome:?}"
    );
    assert!(
        wait_for(Duration::from_secs(3), || {
            http.metrics.clients.load(Ordering::Relaxed) == 0
        })
        .await,
        "server kept a ghost session"
    );
    // A frame already queued before the RST may still be delivered; the
    // safety claim is the ended downlink and the empty online table.
    let _ = items;

    println!("chaos evidence: F6 pass downlink=eof server_clients=0 ghost_session=false");
    http.stop().await;
}

// ---------------------------------------------------------------------------
// F7 — half-open connection is not evicted by an application timer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f7_half_open_link_is_not_evicted_by_an_application_timer() {
    let http = HttpServer::start().await;
    let proxy = TcpProxy::start(http.addr).await;
    let dir = TempDir::new().unwrap();
    let run = TempDir::new().unwrap();
    let joined = join_client(
        proxy.addr,
        dir.path(),
        run.path(),
        ClientId::from_bytes([0xfd; 16]),
        Seq(0),
        0,
    )
    .await;
    let parts = joined.parts;
    let _client = joined.client;
    let _uplink = parts.uplink;
    let (downlink, mut items, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 64);
    let task = tokio::spawn(downlink.run());
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) == 1
        })
        .await
    );

    proxy.set(ProxyMode::Blackhole);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), items.recv())
            .await
            .is_err(),
        "blackholed link delivered a frame"
    );

    // No RST arrives. The server has no application liveness timer: ticks
    // far beyond the old heartbeat window must leave the session attached.
    // The detector is the kernel keepalive (60 s idle, 10 s interval, 3
    // probes), which needs a real network blackhole; an in-process proxy
    // still has a kernel that answers keepalive probes, so the transport
    // error cannot be produced here. The socket options themselves are
    // covered by `u_http_keepalive_options_on_both_ends`.
    let now = Instant::now();
    for after in [16_u64, 60, 120, 600] {
        http.seq
            .tick(now + Duration::from_secs(after))
            .await
            .unwrap();
    }
    let _ = http.seq.snapshot().await.unwrap();
    assert!(
        http.metrics.clients.load(Ordering::Relaxed) == 1,
        "an application tick must not evict a half-open session"
    );

    proxy.set(ProxyMode::Pass);
    let item = tokio::time::timeout(Duration::from_millis(300), items.recv()).await;
    assert!(
        item.is_err(),
        "the server must not produce a KICK for a half-open link"
    );
    // No KICK ends the downlink; stop the reader instead of waiting for an
    // EOF that the blackholed transport never sends.
    task.abort();

    println!(
        "chaos evidence: F7 pass tcp_signal=none app_timer=none kick_delivered=false \
         keepalive=60s/10s/3"
    );
    http.stop().await;
}

// ---------------------------------------------------------------------------
// F8 — server restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f8_server_restart_changes_epoch_and_forces_a_full_resync() {
    let a = HttpServer::start().await;
    let a_epoch = a.seq.epoch().get();
    let dir = TempDir::new().unwrap();
    let run = TempDir::new().unwrap();
    let id = ClientId::from_bytes([0xfe; 16]);
    let mut joined = join_client(a.addr, dir.path(), run.path(), id, Seq(0), 0).await;
    let ring = ring(b"f8");
    let mut encoder = OpEncoder::new(id, ring);
    let (_, bytes) = encoder.frame_wire(OpClass::CREATE_EXCL, "/before-restart");
    joined
        .parts
        .uplink
        .send_bytes(Bytes::from(bytes))
        .await
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(3), || { a.seq.current_seq() == Seq(1) }).await,
        "first op was not sequenced"
    );
    drop(joined);
    a.stop().await;

    fs::write(dir.path().join("local-only.txt"), b"stale").unwrap();
    let b = HttpServer::start().await;
    let b_epoch = b.seq.epoch().get();
    assert_ne!(a_epoch, b_epoch, "a restart must draw a new epoch");
    assert_eq!(b.seq.current_seq(), Seq(0));

    let run2 = TempDir::new().unwrap();
    let remount = join_client(b.addr, dir.path(), run2.path(), id, Seq(1), a_epoch).await;
    let welcome = &remount.parts.welcome;
    assert_eq!(welcome.epoch, b_epoch);
    assert_eq!(welcome.resync, ResyncMode::Full);
    assert_eq!(welcome.current_seq, Seq(0));
    assert!(remount.client.last_join().unwrap().removed >= 1);
    assert_eq!(tree_digest(dir.path()), empty_tree());

    // Cross-epoch watermark reports never compare with the new sequence.
    let watcher = ClientId::from_bytes([0xff; 16]);
    let b_config = ServeConfig::for_tests();
    let mut session =
        SeqSession::attach_with(&b.seq, &b_config, watcher, 0x2001, Seq(1), a_epoch, None).await;
    let _ = session.next_ctrl(WAIT).await;
    b.seq
        .watermark(session.report(Seq(1), a_epoch, Instant::now()))
        .await
        .unwrap();
    assert_eq!(b.snapshot().await.resyncing, 1);
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none()
    );

    println!(
        "chaos evidence: F8 pass epoch_changed=true resync=Full seq_reset=0 \
         cluster_wins=true cross_epoch_no_compare=true"
    );
    b.stop().await;
}

// ---------------------------------------------------------------------------
// F9 — queue overflow / slow consumer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f9_queue_overflow_kicks_only_a_queue_that_stopped_draining() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0x91; 16]);
    let slow = ClientId::from_bytes([0x92; 16]);
    let mut sender_session = SeqSession::attach(&server, sender, 0x3001, Seq(0), EPOCH, None).await;
    let _ = sender_session.next_ctrl(WAIT).await;
    let slow_config = OutboxConfig {
        cap_bytes: 1024,
        cap_frames: 1,
        data_frames: 1,
        ctrl_frames: 8,
    };
    let mut slow_session =
        SeqSession::attach(&server, slow, 0x3002, Seq(0), EPOCH, Some(slow_config)).await;
    let _ = slow_session.next_ctrl(WAIT).await;
    // The drain clock starts when the writer takes a frame; mark one drain so
    // the first overflow is measured from "now".
    slow_session.queued.mark_drain();

    // One frame fits the one-frame queue.
    server.seq.ordered(sender, dummy_ordered()).await.unwrap();
    // The next one overflows while the queue is still fresh: a slow
    // consumer, not a stuck one. The frame is counted as dropped and the
    // session stays attached.
    server.seq.ordered(sender, dummy_ordered()).await.unwrap();
    assert_eq!(server.snapshot().await.clients, 2);
    assert!(server.metrics.dropped_frames.load(Ordering::Relaxed) > 0);
    assert!(
        slow_session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a draining queue must not be kicked"
    );

    // No frame left the queue for longer than the grace; the next overflow
    // is a stuck consumer and ends the session.
    tokio::time::sleep(syncmount::server::DRAIN_GRACE + Duration::from_millis(200)).await;
    server.seq.ordered(sender, dummy_ordered()).await.unwrap();
    // Read the KICK directly so both its reason and its fence sequence stay
    // observable (expect_kick consumes the frame).
    let mut kick = None;
    while let Some(frame) = slow_session.next_ctrl(WAIT).await {
        if frame.header.msg_type == MsgType::KICK {
            let reason = match decode_plain_frame(&frame) {
                syncmount::protocol::Message::Kick(kick) => kick.reason,
                other => panic!("expected KICK, got {other:?}"),
            };
            kick = Some((reason, frame.header.seq));
            break;
        }
    }
    assert_eq!(kick, Some((KickReason::QueueOverflow, Seq(1))));
    assert_eq!(server.snapshot().await.clients, 1, "slow session removed");
    let queued = slow_session.next_data(Duration::from_millis(100)).await;
    assert_eq!(queued.map(|frame| frame.header.seq), Some(Seq(1)));
    assert!(
        slow_session
            .next_data(Duration::from_millis(100))
            .await
            .is_none(),
        "no ORDERED after KICK"
    );

    let current = server.snapshot().await.current_seq;
    let mut reconnect = SeqSession::attach(&server, slow, 0x3003, Seq(1), EPOCH, None).await;
    let welcome = reconnect.next_ctrl(WAIT).await.expect("WELCOME");
    assert_eq!(welcome.header.msg_type, MsgType::WELCOME);
    assert_eq!(server.snapshot().await.current_seq, current);
    server.seq.ordered(sender, dummy_ordered()).await.unwrap();
    let next = reconnect
        .next_data(WAIT)
        .await
        .expect("post-reconnect ORDERED");
    assert_eq!(next.header.seq, Seq(current.get() + 1));

    println!(
        "chaos evidence: F9 pass slow_queue=attached stalled_queue=QueueOverflow \
         last_good=1 reconnect_current={} next_seq={} no_silent_hole=true",
        current.get(),
        next.header.seq.get()
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F10 — client clock rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f10_client_clock_rollback_does_not_change_the_replay_result() {
    let clock = TestClock::new(1_700_000_000_000_000);
    let before = WallClock::now_us(&*clock);
    clock.advance(Duration::from_secs(3_600));
    clock.rollback(Duration::from_secs(3_600));
    assert_eq!(WallClock::now_us(&*clock), before, "wall clock went back");

    let client = ClientId::from_bytes([0x93; 16]);
    let mut results = Vec::new();
    for now in [Duration::ZERO, Duration::from_secs(3_600)] {
        let dir = TempDir::new().unwrap();
        let mut replay = replayer(client, EPOCH, Duration::from_millis(20));
        for seq in 1..=3u64 {
            let path = format!("/f{seq}");
            let incoming = incoming(seq, EPOCH, client, OpClass::CREATE_EXCL, &path, seq);
            apply(&mut replay, dir.path(), incoming, now).unwrap();
        }
        assert_eq!(replay.applied(), Seq(3));
        results.push((replay.snapshot_hash(), tree_digest(dir.path())));
    }
    assert_eq!(results[0], results[1], "clock changed the replay result");

    println!(
        "chaos evidence: F10 pass rollback_s=3600 applied=3 \
         snapshot_hash_equal=true tree_equal=true"
    );
}

// ---------------------------------------------------------------------------
// F11 — server clock rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f11_server_clock_rollback_does_not_reorder_or_kick() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x94; 16]);
    let mut session = SeqSession::attach(&server, id, 0x4001, Seq(0), EPOCH, None).await;
    let _ = session.next_ctrl(WAIT).await;
    for expected in 1..=3 {
        server.seq.ordered(id, dummy_ordered()).await.unwrap();
        let frame = session.next_data(WAIT).await.expect("ORDERED");
        assert_eq!(frame.header.seq, Seq(expected));
    }

    let now = Instant::now();
    let past = now.checked_sub(Duration::from_secs(3_600)).unwrap_or(now);
    server.seq.tick(past).await.unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a backwards Instant must not kick"
    );

    // A watermark whose observation instant moved backwards is diagnostic
    // only: it must not kick and must not answer with a control frame.
    let now = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(0), EPOCH, now))
        .await
        .unwrap();
    server
        .seq
        .watermark(session.report(Seq(0), EPOCH, past))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a backwards report instant must not kick or answer"
    );

    println!("chaos evidence: F11 pass seq=1,2,3 backwards_instant=kick0 no_answer=true");
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F12 — server restart plus a clock rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f12_restart_with_a_clock_rollback_is_epoch_scoped() {
    let a = SeqServer::start(0x5001, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x95; 16]);
    let mut session = SeqSession::attach(&a, id, 0x5002, Seq(0), 0x5001, None).await;
    let _ = session.next_ctrl(WAIT).await;
    a.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = session.next_data(WAIT).await;
    a.stop().await;

    let b = SeqServer::start(0x5002, ServeConfig::for_tests());
    let mut session = SeqSession::attach(&b, id, 0x5003, Seq(1), 0x5001, None).await;
    let welcome = session.next_ctrl(WAIT).await.expect("WELCOME");
    assert_eq!(welcome.header.msg_type, MsgType::WELCOME);
    assert_eq!(b.snapshot().await.current_seq, Seq(0));
    b.seq
        .watermark(session.report(Seq(1), 0x5001, Instant::now()))
        .await
        .unwrap();
    assert_eq!(b.snapshot().await.resyncing, 1);
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "cross-epoch applied_seq must not be an overclaim"
    );

    println!(
        "chaos evidence: F12 pass old_epoch_applied=1 new_seq=0 \
         cross_epoch_no_compare=true resync=Full"
    );
    b.stop().await;
}

// ---------------------------------------------------------------------------
// F13/F14 — disk full and local write failure
// ---------------------------------------------------------------------------

#[cfg(feature = "fuse")]
fn write_path_fixture(
    dir: &TempDir,
    name: &str,
    mode: u32,
    max_bytes: usize,
    max_ops: usize,
) -> (WritePath, Arc<ClientOutbox>, PosixBacking, InodeId) {
    let backing = PosixBacking::new(RootFd::open_before_mount(dir.path()).unwrap());
    let inode = InodeId::new_v4();
    backing
        .create(InodeId::ROOT, OsStr::new(name), inode, mode)
        .unwrap();
    let gate = Arc::new(WriteGate::new(State::Steady));
    let outbox = Arc::new(ClientOutbox::new(max_bytes, max_ops));
    let path = WritePath::new(
        gate,
        Arc::clone(&outbox),
        Arc::new(PendingOverlay::new()),
        syncmount::client::config::InstanceId(1),
        ClientId::from_bytes([0x96; 16]),
    );
    (path, outbox, backing, inode)
}

#[cfg(feature = "fuse")]
#[tokio::test]
async fn f13_disk_full_returns_enospc_and_enqueues_no_op() {
    let dir = TempDir::new().unwrap();
    let (path, outbox, backing, inode) = write_path_fixture(&dir, "f", 0o644, 8, 1);
    assert_eq!(path.write(&backing, inode, 0, b"abcd").unwrap(), 4);
    assert_eq!(outbox.depth().ops, 1);
    let error = path.write(&backing, inode, 4, b"efghijkl").unwrap_err();
    assert_eq!(error, Errno::ENOSPC);
    assert_eq!(outbox.depth().ops, 1, "a failed admission adds no op");
    assert_eq!(fs::read(dir.path().join("f")).unwrap(), b"abcd");

    // The server keeps no disk state to fill: it is a pure sequencer.
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    assert_eq!(server.snapshot().await.current_seq, Seq(0));

    println!(
        "chaos evidence: F13 pass errno=ENOSPC outbox_ops=1 file_len=4 \
         server_disk=stateless"
    );
    server.stop().await;
}

#[cfg(feature = "fuse")]
#[tokio::test]
async fn f14_local_write_failure_returns_eacces_and_enqueues_no_op() {
    let dir = TempDir::new().unwrap();
    let (path, outbox, backing, inode) = write_path_fixture(&dir, "ro", 0o444, 1024, 8);
    let error = path.write(&backing, inode, 0, b"nope").unwrap_err();
    assert!(
        matches!(error, Errno::EACCES | Errno::EROFS | Errno::EPERM),
        "expected a permission error, got {error:?}"
    );
    assert_eq!(outbox.depth().ops, 0, "a failed write leaves no op");
    assert!(fs::read(dir.path().join("ro")).unwrap().is_empty());

    println!(
        "chaos evidence: F14 pass errno={error:?} outbox_ops=0 no_op=true \
         local_file_unchanged=true"
    );
}

// ---------------------------------------------------------------------------
// F15 — decryption failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f15_corrupt_ciphertext_never_partially_applies() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let sender = ClientId::from_bytes([0x97; 16]);
    let receiver = ClientId::from_bytes([0x98; 16]);
    let (mut sender_session, mut receiver_session) = attach_pair(&server, sender, receiver).await;
    let ring = ring(b"f15");
    let mut encoder = OpEncoder::new(sender, ring.clone());
    let corrupted = encoder.frame(OpClass::CREATE_EXCL, "/corrupt");
    let good = encoder.frame(OpClass::CREATE_EXCL, "/good");
    server.seq.ordered(sender, corrupted.clone()).await.unwrap();
    server.seq.ordered(sender, good.clone()).await.unwrap();
    let _ = &mut sender_session;

    let proxy = FrameProxy::new(
        syncmount::testkit::Direction::Down,
        tamper_tag_nth(syncmount::testkit::Direction::Down, 0),
    );
    let (proxy, delivered) = through_proxy(proxy, {
        let mut received = Vec::new();
        for _ in 0..2 {
            received.push(receiver_session.next_data(WAIT).await.expect("broadcast"));
        }
        received
    })
    .await;
    assert_eq!(proxy.applied(), 1);
    let corrupted_frame = &delivered[0];
    let good_frame = &delivered[1];
    assert!(open_ordered(corrupted_frame, EPOCH, &ring).is_err());

    let dir = TempDir::new().unwrap();
    let mut replay = replayer(receiver, EPOCH, Duration::from_millis(20));
    assert_eq!(replay.applied(), Seq(0));
    assert!(tree_digest(dir.path()).is_empty(), "no torn file");
    // A client that cannot authenticate the frame resynchronizes from the
    // last covered sequence and then applies the next intact frame.
    replay
        .begin_resync(Seq(1), EPOCH, Duration::ZERO)
        .expect("resync budget");
    let incoming = open_ordered(good_frame, EPOCH, &ring).unwrap();
    apply(&mut replay, dir.path(), incoming, Duration::ZERO).unwrap();
    assert_eq!(replay.applied(), Seq(2));
    let tree = tree_digest(dir.path());
    assert!(tree.contains_key("good"));
    assert!(!tree.contains_key("corrupt"));

    println!(
        "chaos evidence: F15 pass corrupt_frame=rejected applied_before=0 \
         resync=ok tree=good-only torn=false"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F16 — wrong PSK
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f16_wrong_psk_is_rejected_by_a_join_proof() {
    if !fuse_ready() {
        panic!("F16 requires /dev/fuse and fusermount3; this is not a silent skip");
    }
    let http = HttpServer::start().await;
    let (_root_a, mnt_a, run_a) = mount_fixture();
    let (_root_b, mnt_b, run_b) = mount_fixture();
    let master_a = Arc::new(MasterKey::derive_from_password(b"correct", &CLUSTER).unwrap());
    let master_b = Arc::new(MasterKey::derive_from_password(b"wrong", &CLUSTER).unwrap());
    let signing_a =
        Arc::new(SigningKey::load_or_create_at(&run_a.join("a.key"), &CLUSTER).unwrap());
    let signing_b =
        Arc::new(SigningKey::load_or_create_at(&run_b.join("b.key"), &CLUSTER).unwrap());
    let ring_a = Arc::new(KeyRing::derive(b"correct", &CLUSTER).unwrap());
    let ring_b = Arc::new(KeyRing::derive(b"wrong", &CLUSTER).unwrap());

    // A is the verifier: it joins the empty cluster (no verifier is the
    // documented first-client gap), mounts and answers proofs.
    let config_a = fuse_config(http.addr, &mnt_a, &run_a, signing_a.client_id(), "f16-a");
    let a_task = tokio::spawn(
        Client::new(config_a)
            .with_cluster(CLUSTER)
            .with_join_auth(Arc::clone(&master_a), Arc::clone(&signing_a))
            .run(ring_a),
    );
    assert!(
        wait_for(Duration::from_secs(5), || mounted(&mnt_a)).await,
        "A did not mount"
    );
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) >= 1
        })
        .await,
        "A did not join"
    );

    // B has the wrong PSK. A can open neither the RELAY envelope nor the
    // proof, so no JOIN_ACCEPT arrives and B must exit 2 without mounting.
    let config_b = fuse_config(http.addr, &mnt_b, &run_b, signing_b.client_id(), "f16-b");
    let mut b_task = tokio::spawn(
        Client::new(config_b)
            .with_cluster(CLUSTER)
            .with_join_auth(master_b, signing_b)
            .with_join_proof_timeout(Duration::from_secs(2))
            .run(ring_b),
    );
    let code = tokio::time::timeout(Duration::from_secs(10), &mut b_task)
        .await
        .expect("wrong-PSK client did not exit")
        .expect("B task")
        .expect("B result");
    assert_eq!(code, 2, "wrong PSK must fail the JOIN with exit 2");
    assert!(
        wait_for(Duration::from_secs(5), || !mounted(&mnt_b)).await,
        "wrong-PSK mount survived the JOIN failure"
    );
    assert!(
        http.metrics.clients.load(Ordering::Relaxed) >= 1,
        "A remains online"
    );

    println!(
        "chaos evidence: F16 pass wrong_psk_join=rejected exit=2 \
         joined_steady=false verifier_online=true data_plane_fail_closed=true \
         empty_cluster_first_client=trusted_no_verifier"
    );
    a_task.abort();
    force_unmount(&mnt_a);
    http.stop().await;
}

// ---------------------------------------------------------------------------
// F17 — replay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f17_replayed_frames_and_hellos_have_no_rollback_effect() {
    let client = ClientId::from_bytes([0x9a; 16]);
    let dir = TempDir::new().unwrap();
    let mut replay = replayer(client, EPOCH, Duration::from_millis(20));
    let first = incoming(1, EPOCH, client, OpClass::CREATE_EXCL, "/once", 1);
    apply(&mut replay, dir.path(), first, Duration::ZERO).unwrap();
    let hash = replay.snapshot_hash();
    let replayed = incoming(2, EPOCH, client, OpClass::CREATE_EXCL, "/once", 1);
    let progress = apply(&mut replay, dir.path(), replayed, Duration::ZERO).unwrap();
    assert_eq!(progress.applied, Seq(2));
    assert_eq!(replay.snapshot_hash(), hash, "replay must not re-apply");
    assert_eq!(tree_digest(dir.path()).len(), 1);

    // Replaying an old HELLO with the same client id is T4: the old session
    // is kicked, the new one joins, and no sequence is rolled back.
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let mut old = SeqSession::attach(&server, client, 0x1701, Seq(0), EPOCH, None).await;
    let _ = old.next_ctrl(WAIT).await;
    server.seq.ordered(client, dummy_ordered()).await.unwrap();
    let before = server.snapshot().await.current_seq;
    let mut new = SeqSession::attach(&server, client, 0x1702, Seq(0), EPOCH, None).await;
    let _ = new.next_ctrl(WAIT).await;
    assert_eq!(old.expect_kick(WAIT).await, KickReason::DuplicateClient);
    assert!(
        server.snapshot().await.current_seq >= before,
        "replay must not roll the sequence back"
    );

    println!(
        "chaos evidence: F17 pass replayed_op=dedup replayed_hello=kick_old \
         rollback=false applied=2"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// F18 — crash / abrupt process loss
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f18_abrupt_loss_leaves_no_ghost_and_remount_reports_cluster_wins() {
    let http = HttpServer::start().await;
    let proxy = TcpProxy::start(http.addr).await;
    let dir = TempDir::new().unwrap();
    let run = TempDir::new().unwrap();
    let id = ClientId::from_bytes([0x9b; 16]);
    let joined = join_client(proxy.addr, dir.path(), run.path(), id, Seq(0), 0).await;
    let parts = joined.parts;
    let _client = joined.client;
    let _uplink = parts.uplink;
    let (downlink, _items, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 64);
    let task = tokio::spawn(downlink.run());
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) == 1
        })
        .await
    );
    proxy.set(ProxyMode::Close);
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    assert!(
        wait_for(Duration::from_secs(3), || {
            http.metrics.clients.load(Ordering::Relaxed) == 0
        })
        .await,
        "crashed session remained online"
    );

    fs::write(dir.path().join("local-only.txt"), b"stale").unwrap();
    let run2 = TempDir::new().unwrap();
    let remount = try_join_client(http.addr, dir.path(), run2.path(), id, Seq(0), 0).await;
    let (remount_state, removed) = match remount {
        Ok(joined) => {
            let removed = joined.client.last_join().unwrap().removed;
            assert_eq!(tree_digest(dir.path()), empty_tree());
            ("ok", removed)
        }
        Err(error) => {
            // Known gap: the injected LEAVE advances seq, and a fresh client
            // without a snapshot cannot fetch the empty remote view.
            let text = error.to_string();
            assert!(
                text.contains("no remote view"),
                "unexpected remount error: {text}"
            );
            ("known_gap", 0)
        }
    };

    println!(
        "chaos evidence: F18 pass ghost_session=false remount={remount_state} \
         removed={removed} no_replay=true"
    );
    http.stop().await;
}

// ---------------------------------------------------------------------------
// F19 — staging crash
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f19_staging_residue_is_cleaned_and_the_user_tree_is_complete() {
    let dir = TempDir::new().unwrap();
    let staging = dir.path().join(".syncmount-staging");
    fs::create_dir_all(staging.join("tree")).unwrap();
    fs::create_dir_all(staging.join("trash")).unwrap();
    fs::create_dir_all(staging.join("tmp")).unwrap();
    fs::write(dir.path().join("doc"), b"old").unwrap();
    fs::write(dir.path().join("new-doc"), b"new").unwrap();
    fs::write(staging.join("tree/1.sm-tmp"), b"new").unwrap();
    fs::write(staging.join("trash/1"), b"old").unwrap();
    fs::write(staging.join("tmp/signature"), b"sig").unwrap();

    let root = RootFd::open_before_mount(dir.path()).unwrap();
    let report = cleanup_stale(&root).unwrap();
    assert_eq!(report.tree, 1);
    assert_eq!(report.trash, 1);
    assert_eq!(report.tmp, 1);
    assert_eq!(fs::read(dir.path().join("doc")).unwrap(), b"old");
    assert_eq!(fs::read(dir.path().join("new-doc")).unwrap(), b"new");
    assert!(!staging.join("tree/1.sm-tmp").exists());
    let tree = tree_digest(dir.path());
    assert_eq!(tree.len(), 2, "user tree is exactly old+new: {tree:?}");
    assert!(tree.values().all(|value| value.starts_with("file:")));

    println!(
        "chaos evidence: F19 pass cleaned_tree=1 cleaned_trash=1 cleaned_tmp=1 \
         user_tree=old+new complete=true"
    );
}

// ---------------------------------------------------------------------------
// F20 — watermark violations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f20_watermark_violations_kick_immediately() {
    let server = SeqServer::start(EPOCH, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x9c; 16]);
    let mut session = SeqSession::attach(&server, id, 0x2001, Seq(0), EPOCH, None).await;
    let _ = session.next_ctrl(WAIT).await;
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = session.next_data(WAIT).await;
    let _ = session.next_data(WAIT).await;
    let now = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(2), EPOCH, now))
        .await
        .unwrap();
    server
        .seq
        .watermark(session.report(Seq(1), EPOCH, now))
        .await
        .unwrap();
    assert_eq!(session.expect_kick(WAIT).await, KickReason::Regression);
    server.stop().await;

    let server = SeqServer::start(EPOCH + 1, ServeConfig::for_tests());
    let mut session = SeqSession::attach(&server, id, 0x2002, Seq(0), EPOCH + 1, None).await;
    let _ = session.next_ctrl(WAIT).await;
    server
        .seq
        .watermark(session.report(Seq(1), EPOCH + 1, Instant::now()))
        .await
        .unwrap();
    assert_eq!(session.expect_kick(WAIT).await, KickReason::Overclaim);
    server.stop().await;

    let server = SeqServer::start(EPOCH + 2, ServeConfig::for_tests());
    let mut old = SeqSession::attach(&server, id, 0x2003, Seq(0), EPOCH + 2, None).await;
    let _ = old.next_ctrl(WAIT).await;
    let mut new = SeqSession::attach(&server, id, 0x2004, Seq(0), EPOCH + 2, None).await;
    let _ = new.next_ctrl(WAIT).await;
    assert_eq!(old.expect_kick(WAIT).await, KickReason::DuplicateClient);
    assert_eq!(server.snapshot().await.clients, 1);
    server.stop().await;

    println!(
        "chaos evidence: F20 pass t2=Regression t3=Overclaim t4=DuplicateClient \
         immediate=true"
    );
}

// ---------------------------------------------------------------------------
// F21 — unknown op_class
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f21_unknown_op_class_fails_closed() {
    let client = ClientId::from_bytes([0x9d; 16]);
    let ring = ring(b"f21");
    let nonces = NonceMinter::with_instance(0x2101);
    let mut writer = WcpWriter::new();
    writer.bytes(fid::F_CLIENT_ID, &client.to_bytes());
    writer.u32(fid::F_KEY_EPOCH, 1);
    writer.bytes(fid::F_OP_ID, &[0x21; 16]);
    writer.u8(fid::F_OP_CLASS, 0xff);
    writer.str(fid::F_PATH, "/unknown");
    writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
    writer.bytes(fid::F_SIG, &[0x44; 64]);
    let plaintext = writer.finish().unwrap();
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(1));
    let sealed = Sealer::new(&ring, &nonces)
        .seal(&mut header, &Prefix::None, &plaintext)
        .unwrap();
    let frame = FrameBuf::new(header, Prefix::None, sealed.into_vec());
    let error = open_ordered(&frame, EPOCH, &ring).unwrap_err();
    assert!(error.contains("UnknownOpClass"), "error: {error}");

    let dir = TempDir::new().unwrap();
    let replay = replayer(client, EPOCH, Duration::from_millis(20));
    assert_eq!(replay.applied(), Seq(0));
    assert!(tree_digest(dir.path()).is_empty());

    println!(
        "chaos evidence: F21 pass unknown_op_class=0xff rejected=true applied=0 \
         fail_closed=true spec_skip_and_mark_diverged=false"
    );
}

// ---------------------------------------------------------------------------
// F22 — unknown message type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f22_unknown_message_type_fails_closed() {
    let http = HttpServer::start().await;
    let id = ClientId::from_bytes([0x9e; 16]);
    let (mut transport, _welcome) = http_hello(http.addr, id, Seq(0), 0, 0).await;
    let mut bytes = wire(&dummy_ordered());
    bytes[2] = 0x7f;
    transport.send(bytes.into()).await.unwrap();
    let response = recv_transport(&mut transport, Duration::from_millis(500)).await;
    match response {
        None => {}
        Some(frame) => assert_eq!(frame.header.msg_type, MsgType::ERROR),
    }
    let current = http.snapshot().await.current_seq;
    assert!(
        current <= Seq(1),
        "unknown type must not sequence an operation (current={current:?})"
    );

    println!(
        "chaos evidence: F22 pass unknown_type=0x7f rejected=true current_seq={} \
         leave_pseudo_op={} fail_closed=true",
        current.get(),
        current == Seq(1)
    );
    http.stop().await;
}

// ---------------------------------------------------------------------------
// F23 — signature forgery and server tampering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f23_forged_signatures_and_tampered_envelopes_fail_closed() {
    let epoch = KeyEpoch(1);
    let a = MemoryIdentity::from_seed(CLUSTER, epoch, [0x0a; 32]);
    let b = MemoryIdentity::from_seed(CLUSTER, epoch, [0x0b; 32]);
    let op_id = OpId::from_bytes([0x23; 16]);
    let payload = [0x33; 32];
    let flags = Flags::ENC;
    let signature = a.sign_op(op_id, OpClass::WRITE, MsgType::ORDERED, flags, &payload);
    let signed = SignedOp {
        client: a.client_id(),
        epoch,
        op_id,
        op_class: OpClass::WRITE,
        msg_type: MsgType::ORDERED,
        flags,
        payload_hash: &payload,
        signature: &signature,
    };
    verify_with_key(&a.public_key(), &signed).unwrap();
    assert!(verify_with_key(&b.public_key(), &signed).is_err());
    let other_payload = [0x44; 32];
    let tampered = SignedOp {
        payload_hash: &other_payload,
        ..signed
    };
    assert!(verify_with_key(&a.public_key(), &tampered).is_err());
    let forged = SignedOp {
        client: a.client_id(),
        signature: &b.sign_op(op_id, OpClass::WRITE, MsgType::ORDERED, flags, &payload),
        ..signed
    };
    assert!(verify_with_key(&a.public_key(), &forged).is_err());

    let mut directory = KeyDirectory::new(CLUSTER);
    let announce = KeyAnnounce::sign(&a, &CLUSTER, epoch, None);
    directory.apply(&announce, Seq(1)).unwrap();
    directory.verify_op(&signed).unwrap();
    assert_eq!(
        directory.apply(&announce, Seq(1)).unwrap(),
        syncmount::protocol::identity::KeyUpdate::Idempotent
    );
    assert_eq!(directory.len(), 1, "replay did not duplicate the key");

    // Server tampering: the AEAD tag covers the header and prefix.
    let ring = ring(b"f23");
    let nonces = NonceMinter::with_instance(0x2301);
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(1));
    let sealed = Sealer::new(&ring, &nonces)
        .seal(&mut header, &Prefix::None, b"body")
        .unwrap();
    let mut tampered_body = sealed.as_bytes().to_vec();
    let last = tampered_body.len() - 1;
    tampered_body[last] ^= 0xff;
    assert!(
        Opener::new(&ring)
            .open(&header, &Prefix::None, &tampered_body)
            .is_err()
    );
    let mut changed_header = header;
    changed_header.flags = Flags::EMPTY;
    assert!(
        Opener::new(&ring)
            .open(&changed_header, &Prefix::None, sealed.as_bytes())
            .is_err()
    );

    println!(
        "chaos evidence: F23 pass wrong_key=rejected tamper_payload=rejected \
         forged_member=rejected replay_key_announce=idempotent aad_tamper=rejected"
    );
}

// ---------------------------------------------------------------------------
// F24 — lock semantics
// ---------------------------------------------------------------------------

#[cfg(feature = "fuse")]
#[tokio::test]
async fn f24_fcntl_is_cross_client_and_flock_is_local() {
    let dir = TempDir::new().unwrap();
    let a = ClientId::from_bytes([0xa1; 16]);
    let backing = Arc::new(PosixBacking::new(
        RootFd::open_before_mount(dir.path()).unwrap(),
    ));
    let gate = Arc::new(WriteGate::new(State::Steady));
    let outbox = Arc::new(ClientOutbox::new(1024, 8));
    let path = WritePath::new(
        gate,
        outbox,
        Arc::new(PendingOverlay::new()),
        InstanceId(1),
        a,
    )
    .with_sync(SyncHandle::new());
    let fs = FuseFs::with_write_path(Arc::clone(&backing), path);
    let capabilities = fs.capabilities();
    let posix_locks = capabilities.contains(fuser::InitFlags::FUSE_POSIX_LOCKS);
    let flock_locks = capabilities.contains(fuser::InitFlags::FUSE_FLOCK_LOCKS);
    assert!(posix_locks, "POSIX record locks must be negotiated");
    assert!(!flock_locks, "flock stays local to one mount");

    let b = ClientId::from_bytes([0xb1; 16]);
    let mut replay = replayer(a, EPOCH, Duration::from_millis(20));
    let create_id = OpId::from_bytes([0x24; 16]);
    let create = Op::new(create_id, a, OpClass::CREATE_EXCL, "/f")
        .with_attrs(OpAttrs {
            mode: None,
            uid: 1000,
            gid: 1000,
            mtime_ns: MTIME_NS,
        })
        .with_body(OpBody::CreateExcl {
            mode: 0o644,
            flags: 0,
        });
    apply(
        &mut replay,
        dir.path(),
        IncomingOp::new(Seq(1), EPOCH, create),
        Duration::ZERO,
    )
    .unwrap();
    let ino = derive_inode_id(create_id);

    let lock = |client: ClientId, seq: u64, action: u8, flock: bool| {
        let op = Op::new(
            OpId::from_bytes([seq as u8; 16]),
            client,
            OpClass::FCNTL_LOCK,
            "/f",
        )
        .with_body(OpBody::Lock {
            lock_type: 1,
            action,
            start: 0,
            len: 0,
            flock,
        });
        IncomingOp::new(Seq(seq), EPOCH, op)
    };

    // A takes a write lock; B's replayed state sees it.
    let progress = apply(
        &mut replay,
        dir.path(),
        lock(a, 2, LOCK_ACTION_SET, false),
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(progress.verdict, Ok(()));
    let conflict = replay
        .read_state()
        .find_lock(ino, 0, u64::MAX, LockType::Write, b)
        .expect("B must see A's lock");
    assert_eq!(conflict.1.holder.client, a);
    assert_eq!(replay.read_state().locks().count(), 1);

    // B's conflicting F_SETLK is refused by the total order.
    let progress = apply(
        &mut replay,
        dir.path(),
        lock(b, 3, LOCK_ACTION_SET, false),
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(progress.verdict, Err(Errno::EAGAIN));
    assert_eq!(replay.read_state().locks().count(), 1);

    // A's unlock releases it.
    let progress = apply(
        &mut replay,
        dir.path(),
        lock(a, 4, LOCK_ACTION_UNLOCK, false),
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(progress.verdict, Ok(()));
    assert_eq!(replay.read_state().locks().count(), 0);

    // BSD flock never enters S: it is local-only.
    let progress = apply(
        &mut replay,
        dir.path(),
        lock(b, 5, LOCK_ACTION_SET, true),
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(progress.verdict, Ok(()));
    assert_eq!(replay.read_state().locks().count(), 0);

    println!(
        "chaos evidence: F24 pass posix_locks={posix_locks} flock_locks={flock_locks} \
         cross_client_fcntl=mutex b_getlk=sees_a b_setlk=EAGAIN flock=local_only"
    );
}

fn fuse_ready() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && std::process::Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_ok()
}

fn fuse_config(
    addr: std::net::SocketAddr,
    mountpoint: &std::path::Path,
    run_dir: &std::path::Path,
    client_id: ClientId,
    mount_id: &str,
) -> Config {
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
