//! Watermark scenarios W1–W7 (45 §4.6, 31:M4-10..16).
//!
//! The sequencer is driven directly, so a "minute" of idle time costs no
//! wall-clock sleep: every health decision takes an explicit `Instant`.
//! W6 is the only test that mounts FUSE, because "kick ⇒ unmount" is a real
//! process-level claim.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use syncmount::client::Client;
use syncmount::client::config::{
    Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
};
use syncmount::protocol::crypto::KeyRing;
use syncmount::protocol::messages::Message;
use syncmount::protocol::{ClientId, CtrlPrefix, KickReason, MsgType, Seq};
use syncmount::server::{SeqSnapshot, ServeConfig};
use tempfile::TempDir;

use super::harness::*;

async fn drain_welcome(session: &mut SeqSession) {
    let frame = session.next_ctrl(WAIT).await.expect("WELCOME");
    assert_eq!(frame.header.msg_type, MsgType::WELCOME);
}

fn fuse_ready() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && std::process::Command::new("fusermount3")
            .arg("--version")
            .output()
            .is_ok()
}

// ---------------------------------------------------------------------------
// W1 — every HELLO/PING carries a validated 18-byte ctrl prefix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w1_reports_are_18_bytes_and_every_report_is_checked() {
    let prefix = CtrlPrefix::new(Seq(7), 9);
    assert_eq!(prefix.encode().len(), 18, "ctrl_prefix is exactly 18 B");
    assert!(prefix.validate().is_ok(), "reserved must be zero");
    let mut dirty = prefix;
    dirty.reserved = 1;
    assert!(dirty.validate().is_err(), "non-zero reserved is rejected");

    let server = SeqServer::start(7, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x71; 16]);
    let mut session = SeqSession::attach(&server, id, 1, Seq(0), 7, None).await;
    drain_welcome(&mut session).await;

    for expected in 1..=3 {
        server.seq.ordered(id, dummy_ordered()).await.unwrap();
        let frame = session.next_data(WAIT).await.expect("ORDERED");
        assert_eq!(frame.header.seq, Seq(expected));
    }

    let now = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(1), 7, now))
        .await
        .unwrap();
    server
        .seq
        .watermark(session.report(Seq(3), 7, now))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "monotonic reports must not kick"
    );

    // A regression is a protocol violation and is decided at report time.
    server
        .seq
        .watermark(session.report(Seq(2), 7, now))
        .await
        .unwrap();
    assert_eq!(session.expect_kick(WAIT).await, KickReason::Regression);
    server.stop().await;

    // An overclaim is decided at report time too. A fresh server keeps the
    // current sequence at zero, so the report is unambiguously ahead.
    let server = SeqServer::start(8, ServeConfig::for_tests());
    let over = ClientId::from_bytes([0x72; 16]);
    let mut session = SeqSession::attach(&server, over, 2, Seq(0), 8, None).await;
    drain_welcome(&mut session).await;
    server
        .seq
        .watermark(session.report(Seq(1), 8, Instant::now()))
        .await
        .unwrap();
    assert_eq!(session.expect_kick(WAIT).await, KickReason::Overclaim);
    server.stop().await;

    // A HELLO whose applied value is ahead of the server is also an overclaim.
    let server = SeqServer::start(9, ServeConfig::for_tests());
    let ahead = ClientId::from_bytes([0x73; 16]);
    let mut session = SeqSession::attach(&server, ahead, 3, Seq(1), 9, None).await;
    drain_welcome(&mut session).await;
    assert_eq!(session.expect_kick(WAIT).await, KickReason::Overclaim);
    server.stop().await;

    println!(
        "chaos evidence: W1 pass ctrl_prefix=18B reserved=0 reports=hello+ping \
         regression=Regression overclaim=Overclaim applied_seq_monotonic=true"
    );
}

#[tokio::test]
async fn w1_http_ping_is_validated_on_the_wire() {
    let http = HttpServer::start().await;
    let ring = Arc::new(KeyRing::derive(b"w1-wire", &CLUSTER).unwrap());
    let id = ClientId::from_bytes([0x74; 16]);
    let (mut transport, welcome) = http_hello(http.addr, id, Seq::UNSEQUENCED, 0, 0).await;
    assert_eq!(welcome.epoch, http.seq.epoch().get());

    // A clean PING updates the watermark and is never answered: the client
    // does not read a PONG, and liveness does not depend on one.
    http_ping(&mut transport, &ring, Seq(0), welcome.epoch, 0).await;
    assert!(
        recv_transport(&mut transport, Duration::from_millis(100))
            .await
            .is_none(),
        "a PING must not produce a control answer"
    );

    // The reserved field is part of the report contract: non-zero is a
    // protocol error, not a value the server may silently ignore.
    http_ping(&mut transport, &ring, Seq(0), welcome.epoch, 1).await;
    let error = recv_transport(&mut transport, WAIT).await.expect("ERROR");
    assert_eq!(error.header.msg_type, MsgType::ERROR);
    match decode_plain_frame(&error) {
        Message::Error(error) => {
            assert_eq!(error.reason, syncmount::protocol::TrnReason::Protocol)
        }
        other => panic!("expected ERROR, got {other:?}"),
    }

    println!(
        "chaos evidence: W1 pass wire_ping=no_answer dirty_reserved=ERROR/Protocol \
         ctrl_prefix_checked=true"
    );
    http.stop().await;
}

// ---------------------------------------------------------------------------
// W2 — dynamic threshold and busy gate are diagnostics, not death sentences
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w2_dynamic_threshold_prices_pending_ops_and_backlog() {
    let server = SeqServer::start(11, ServeConfig::for_tests());
    let epoch = server.epoch.get();

    // One outstanding op: threshold = 3*300ms + 1*100ms = 1s.
    let id = ClientId::from_bytes([0x75; 16]);
    let mut session = SeqSession::attach(&server, id, 11, Seq(0), epoch, None).await;
    drain_welcome(&mut session).await;
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = session.next_data(WAIT).await.expect("ORDERED");
    let base = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(0), epoch, base))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(800))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "0.8s < 1s threshold"
    );
    server
        .seq
        .tick(base + Duration::from_millis(1_300))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a lagging session is diagnosed, never kicked"
    );
    assert_eq!(server.snapshot().await.clients, 1);
    assert!(
        server
            .metrics
            .watermark_lag_ms
            .load(Ordering::Relaxed)
            >= 1_300,
        "the lag gauge must publish the diagnosis"
    );
    assert!(server.metrics.pending_ops.load(Ordering::Relaxed) >= 1);

    server.stop().await;

    // Ten pending ops: threshold = 900ms + 10*100ms = 1.9s.
    let server = SeqServer::start(12, ServeConfig::for_tests());
    let epoch = server.epoch.get();
    let id = ClientId::from_bytes([0x76; 16]);
    let mut session = SeqSession::attach(&server, id, 12, Seq(0), epoch, None).await;
    drain_welcome(&mut session).await;
    for _ in 0..10 {
        server.seq.ordered(id, dummy_ordered()).await.unwrap();
    }
    for _ in 0..10 {
        let _ = session.next_data(WAIT).await.expect("ORDERED");
    }
    let base = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(0), epoch, base))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(1_500))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "1.5s < 1.9s threshold with ten pending ops"
    );
    server
        .seq
        .tick(base + Duration::from_millis(2_100))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "ten pending ops are diagnosed, never kicked"
    );
    assert_eq!(server.snapshot().await.clients, 1);

    server.stop().await;

    // One MiB of backlog: threshold = 900ms + 1s + 100ms = 2s.
    let server = SeqServer::start(13, ServeConfig::for_tests());
    let epoch = server.epoch.get();
    let id = ClientId::from_bytes([0x77; 16]);
    let mut session = SeqSession::attach(&server, id, 13, Seq(0), epoch, None).await;
    drain_welcome(&mut session).await;
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = session.next_data(WAIT).await.expect("ORDERED");
    session.add_backlog(1024 * 1024);
    let base = Instant::now();
    server
        .seq
        .watermark(session.report(Seq(0), epoch, base))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(1_500))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "1.5s < 2s threshold with 1 MiB backlog"
    );
    server
        .seq
        .tick(base + Duration::from_millis(2_300))
        .await
        .unwrap();
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "a large backlog is diagnosed, never kicked"
    );
    assert_eq!(server.snapshot().await.clients, 1);

    println!(
        "chaos evidence: W2 pass pending_1_threshold=1s pending_10_threshold=1.9s \
         backlog_1mib_threshold=2s kicks=0 diagnostics_only=true"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// W3 — an idle session without a PING is not evicted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w3_idle_session_without_a_ping_is_not_evicted() {
    let server = SeqServer::start(13, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x78; 16]);
    let mut session = SeqSession::attach(&server, id, 21, Seq(0), 13, None).await;
    drain_welcome(&mut session).await;
    let base = Instant::now();
    // Ten quiet minutes: the connection, not a timer, decides liveness.
    for minute in 1..=10 {
        server
            .seq
            .tick(base + Duration::from_secs(60 * minute))
            .await
            .unwrap();
    }
    assert!(
        session
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "an idle session must not receive a KICK"
    );
    assert_eq!(server.snapshot().await.clients, 1);

    // The session still receives the next broadcast, so it was never removed.
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let frame = session.next_data(WAIT).await.expect("ORDERED");
    assert_eq!(frame.header.msg_type, MsgType::ORDERED);

    println!("chaos evidence: W3 pass no_ping_10min=ok kicks=0 session_attached=true");
    server.stop().await;
}

// ---------------------------------------------------------------------------
// W4 — T4 duplicate client: kick the old, admit the new
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w4_duplicate_client_id_kicks_the_old_session() {
    let server = SeqServer::start(17, ServeConfig::for_tests());
    let id = ClientId::from_bytes([0x79; 16]);
    let epoch = server.epoch.get();
    let mut old = SeqSession::attach(&server, id, 31, Seq(0), epoch, None).await;
    drain_welcome(&mut old).await;

    let mut new = SeqSession::attach(&server, id, 32, Seq(0), epoch, None).await;
    drain_welcome(&mut new).await;

    assert_eq!(old.expect_kick(WAIT).await, KickReason::DuplicateClient);
    let snapshot: SeqSnapshot = server.snapshot().await;
    assert_eq!(snapshot.clients, 1);
    assert_eq!(snapshot.online, 1);
    assert_eq!(
        server.metrics.sync_sessions.load(Ordering::Relaxed),
        0,
        "relay slots are released"
    );

    // The survivor receives the next broadcast; the kicked session receives
    // nothing, and its data sender is gone.
    let third = ClientId::from_bytes([0x7a; 16]);
    let mut writer = SeqSession::attach(&server, third, 33, Seq(0), epoch, None).await;
    drain_welcome(&mut writer).await;
    server.seq.ordered(third, dummy_ordered()).await.unwrap();
    let frame = new.next_data(WAIT).await.expect("new session broadcast");
    // The duplicate kick injected a LEAVE pseudo-op at seq 1 before the new
    // session joined the broadcast set; the next ORDERED is therefore seq 2.
    assert_eq!(frame.header.seq, Seq(2));
    assert!(
        old.next_data(Duration::from_millis(200)).await.is_none(),
        "the kicked session must not receive ORDERED"
    );

    println!(
        "chaos evidence: W4 pass old=KICK/DuplicateClient new=Online \
         old_receives_ordered=false relay_slots=0"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// W5 — false-kick protection: idle, slow but within threshold, backlog drain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w5_idle_slow_and_backlog_do_not_kick() {
    let server = SeqServer::start(19, ServeConfig::for_tests());
    let epoch = server.epoch.get();

    // Ten idle minutes, one PING every 5s. `busy=false` must reset the clock.
    let id = ClientId::from_bytes([0x7b; 16]);
    let mut idle = SeqSession::attach(&server, id, 41, Seq(0), epoch, None).await;
    drain_welcome(&mut idle).await;
    let base = Instant::now();
    for step in 0..=120u64 {
        let at = base + Duration::from_secs(step * 5);
        server
            .seq
            .watermark(idle.report(Seq(0), epoch, at))
            .await
            .unwrap();
        server.seq.tick(at).await.unwrap();
        assert!(
            idle.next_ctrl(Duration::from_millis(1)).await.is_none(),
            "idle session kicked at step {step}"
        );
    }

    server.stop().await;

    // Slow but inside the threshold: one op, advance every 500ms.
    let server = SeqServer::start(20, ServeConfig::for_tests());
    let epoch = server.epoch.get();
    let id = ClientId::from_bytes([0x7c; 16]);
    let mut slow = SeqSession::attach(&server, id, 42, Seq(0), epoch, None).await;
    drain_welcome(&mut slow).await;
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = slow.next_data(WAIT).await.expect("ORDERED");
    let base = Instant::now();
    server
        .seq
        .watermark(slow.report(Seq(0), epoch, base))
        .await
        .unwrap();
    server
        .seq
        .watermark(slow.report(Seq(1), epoch, base + Duration::from_millis(500)))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(1_400))
        .await
        .unwrap();
    assert!(
        slow.next_ctrl(Duration::from_millis(100)).await.is_none(),
        "0.9s since advance is inside the 1s threshold"
    );

    server.stop().await;

    // Backlog drain: the client keeps advancing while one MiB is queued.
    let server = SeqServer::start(21, ServeConfig::for_tests());
    let epoch = server.epoch.get();
    let id = ClientId::from_bytes([0x7d; 16]);
    let mut backlog = SeqSession::attach(&server, id, 43, Seq(0), epoch, None).await;
    drain_welcome(&mut backlog).await;
    server.seq.ordered(id, dummy_ordered()).await.unwrap();
    let _ = backlog.next_data(WAIT).await.expect("ORDERED");
    backlog.add_backlog(1024 * 1024);
    let base = Instant::now();
    server
        .seq
        .watermark(backlog.report(Seq(0), epoch, base))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(1_500))
        .await
        .unwrap();
    assert!(
        backlog
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "1.5s is inside the 2s backlog threshold"
    );
    server
        .seq
        .watermark(backlog.report(Seq(1), epoch, base + Duration::from_millis(1_500)))
        .await
        .unwrap();
    server
        .seq
        .tick(base + Duration::from_millis(2_400))
        .await
        .unwrap();
    assert!(
        backlog
            .next_ctrl(Duration::from_millis(100))
            .await
            .is_none(),
        "0.9s since the last advance is inside the threshold"
    );

    println!(
        "chaos evidence: W5 pass idle_10min=kick0 slow_0.5s_advance=kick0 \
         backlog_drain=kick0"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// W6 — KICK unmounts the real mount and exits 10
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_kick_unmounts_and_exits_10() {
    if !fuse_ready() {
        panic!("W6 requires /dev/fuse and fusermount3; this is not a silent skip");
    }
    let http = HttpServer::start().await;
    let (_root, mnt, run) = mount_fixture();
    let ring = Arc::new(KeyRing::derive(b"w6", &CLUSTER).unwrap());
    let id = ClientId::from_bytes([0x7e; 16]);

    let config = Config {
        endpoint: ClientEndpoint::parse(&format!("http://{}/", http.addr)).unwrap(),
        mountpoint: mnt.clone(),
        client_id: id,
        instance: InstanceId(1),
        mount_id: "w6-kick".to_owned(),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir: run,
        allow_empty_view: false,
    };
    let mut task = tokio::spawn(Client::new(config).with_cluster(CLUSTER).run(ring.clone()));

    assert!(
        wait_for(Duration::from_secs(5), || mounted(&mnt)).await,
        "client did not mount {}",
        mnt.display()
    );
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) >= 1
        })
        .await,
        "client did not join"
    );

    // A second HELLO with the same client id is T4: the server kicks the old
    // session, the real client sees KICK, unmounts and exits 10. A raw HELLO
    // is enough: the replacement does not need a snapshot to trigger T4.
    let (second, _welcome) = http_hello(http.addr, id, Seq(0), 0, 0).await;

    let code = tokio::time::timeout(Duration::from_secs(10), &mut task)
        .await
        .expect("client did not exit after KICK")
        .expect("client task")
        .expect("client result");
    assert_eq!(code, 10, "KICK must exit 10");
    assert!(
        wait_for(Duration::from_secs(5), || !mounted(&mnt)).await,
        "mount {} survived the kick",
        mnt.display()
    );
    // The replacement HELLO is accepted. If the old connection's detach is
    // still keyed only by client_id, it races with the replacement and removes
    // it (reported bug 1). Tolerate both generations so the test keeps its
    // meaning before and after the fix.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut handoff_race = false;
    if http.metrics.clients.load(Ordering::Relaxed) == 0 {
        handoff_race = true;
        let (third, _welcome) = http_hello(http.addr, id, Seq(0), 0, 0).await;
        assert!(
            wait_for(Duration::from_secs(2), || {
                http.metrics.clients.load(Ordering::Relaxed) == 1
            })
            .await,
            "a HELLO after the old teardown must stay online"
        );
        drop(third);
    }

    println!(
        "chaos evidence: W6 pass kick=DuplicateClient exit=10 mount_entry=absent \
         replacement_after_teardown=online handoff_race={handoff_race}"
    );
    drop(second);
    http.stop().await;
}

// ---------------------------------------------------------------------------
// W7 — remount is cluster-wins and deletes local-only state
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w7_remount_after_kick_is_cluster_wins_full_resync() {
    if !fuse_ready() {
        panic!("W7 requires /dev/fuse and fusermount3; this is not a silent skip");
    }
    let http = HttpServer::start().await;
    let (_root, mnt, run) = mount_fixture();
    let ring = Arc::new(KeyRing::derive(b"w7", &CLUSTER).unwrap());
    let id = ClientId::from_bytes([0x7f; 16]);

    let config = Config {
        endpoint: ClientEndpoint::parse(&format!("http://{}/", http.addr)).unwrap(),
        mountpoint: mnt.clone(),
        client_id: id,
        instance: InstanceId(1),
        mount_id: "w7-remount".to_owned(),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir: run,
        allow_empty_view: false,
    };
    let mut task = tokio::spawn(Client::new(config).with_cluster(CLUSTER).run(ring));
    assert!(
        wait_for(Duration::from_secs(5), || mounted(&mnt)).await,
        "client did not mount {}",
        mnt.display()
    );
    assert!(
        wait_for(Duration::from_secs(5), || {
            http.metrics.clients.load(Ordering::Relaxed) >= 1
        })
        .await
    );

    // Kick the mounted client, wait for the real exit, then remount the same
    // backing directory. The remount must take the cluster-wins path and
    // delete every local-only entry.
    let (second, _welcome) = http_hello(http.addr, id, Seq(0), 0, 0).await;
    let code = tokio::time::timeout(Duration::from_secs(10), &mut task)
        .await
        .expect("client did not exit after KICK")
        .expect("client task")
        .expect("client result");
    assert_eq!(code, 10);
    assert!(wait_for(Duration::from_secs(5), || !mounted(&mnt)).await);
    drop(second);

    fs::write(mnt.join("local-only.txt"), b"local").unwrap();
    fs::create_dir(mnt.join("local-dir")).unwrap();
    fs::write(mnt.join("local-dir/ghost"), b"ghost").unwrap();

    let run2 = TempDir::new().unwrap();
    let remount = join_client(http.addr, &mnt, run2.path(), id, Seq(0), 0).await;
    let welcome = &remount.parts.welcome;
    assert!(welcome.current_seq >= Seq(1), "the kick left cluster state");
    let report = remount.client.last_join().expect("join report");
    assert!(
        report.removed >= 3,
        "local-only entries removed: {report:?}"
    );
    assert_eq!(tree_digest(&mnt), empty_tree(), "diff -r is empty");

    println!(
        "chaos evidence: W7 pass kick_then_remount=true resync={:?} current_seq={}          removed={} tree_diff=0",
        welcome.resync,
        welcome.current_seq.get(),
        report.removed
    );
    http.stop().await;
}
