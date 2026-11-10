//! Replay throughput: one client and eleven clients against a real HTTP
//! server, with a real SQLite replica on each client.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use syncmount::client::db::OutboxState;
use syncmount::client::ops::CreateAttrs;
use syncmount::client::session::{self, SessionOptions};
use syncmount::client::{ClientDb, Conntrace, Counters, State, WriteGate};
use syncmount::crypto::MasterKey;
use syncmount::protocol::crypto::PskSalt;
use syncmount::protocol::{DataRef, OpClass, SessionId};
use syncmount::server::config::ServeConfig;
use syncmount::server::store::StoreHandle;
use syncmount::server::wire::WireOp;
use syncmount::server::{CommitOutcome, CommitRequest, Server};
use syncmount::store::sqlite::{EventPayload, ROOT_INO};
use syncmount::transport::Endpoint;
use tokio::sync::mpsc;

const MASTER: &[u8] = b"replay-throughput-master";

fn master() -> MasterKey {
    MasterKey::derive_psk_from_password(MASTER, &PskSalt::DEFAULT).unwrap()
}

/// Append `total` create events straight to the server's event log.
///
/// The store's commit path clones its whole mirror per operation, so seeding
/// 50k events through it takes minutes. Replay reads only the event rows and
/// rebuilds every frame from them, so a direct append produces exactly the
/// input the replay path sees.
fn seed(db: &std::path::Path, total: usize) {
    let conn = rusqlite::Connection::open(db).unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO events
                   (seq, epoch, op_id, session_id, kind, path, path2, ino, payload,
                    result, applied, created_at)
                 VALUES (?1, 1, ?2, NULL, 'create_file', ?3, NULL, ?4, ?5, 'ok', 1, 1)",
            )
            .unwrap();
        for index in 0..total {
            let seq = index as i64 + 1;
            let mut op_id = [0u8; 16];
            op_id[..8].copy_from_slice(&(seq as u64).to_le_bytes());
            let mut ino = [0u8; 16];
            ino[..8].copy_from_slice(&(seq as u64 + 1).to_le_bytes());
            let payload = EventPayload::CreateFile {
                ino,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime_ns: seq,
                file_root: [0u8; 32],
            }
            .encode()
            .unwrap();
            insert
                .execute(rusqlite::params![
                    seq,
                    op_id.as_slice(),
                    format!("/file-{index}"),
                    ino.as_slice(),
                    payload
                ])
                .unwrap();
        }
    }
    tx.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'seq'",
        [total as i64],
    )
    .unwrap();
    tx.commit().unwrap();
}

async fn start_server(dir: &std::path::Path, total: usize) -> (Server, Endpoint) {
    let db = dir.join("server.db");
    let (store, _meta) = StoreHandle::start(db.clone()).unwrap();
    store.shutdown().await.unwrap();
    seed(&db, total);

    let config = ServeConfig {
        db_path: db,
        ..ServeConfig::loopback()
    };
    let server = Server::bind(config, master()).await.unwrap();
    let addr = server.local_addr().unwrap();
    let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
    (server, endpoint)
}

/// Build one `WireOp` for the seeding path.
fn seed_op(
    id: u64,
    class: OpClass,
    path: &str,
    mode: Option<u32>,
    data: Option<(&[u8], u128)>,
) -> WireOp {
    let mut op_id = [0u8; 16];
    op_id[..8].copy_from_slice(&id.to_le_bytes());
    WireOp {
        op_id,
        class,
        path: path.to_owned(),
        path2: None,
        target: None,
        mode,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        data: data.map(|(bytes, session)| DataRef {
            session: SessionId(session),
            total_len: bytes.len() as u64,
            data_hash: *blake3::hash(bytes).as_bytes(),
        }),
        offset: None,
        length: None,
        lock_type: None,
        lock_action: None,
        lock_start: None,
        lock_len: None,
    }
}

async fn seed_commit(store: &StoreHandle, op: WireOp, content: Option<Vec<u8>>) {
    let request = CommitRequest {
        session: [7u8; 16],
        op,
        content,
        // Replay rebuilds every frame from the event, so the stored wire is
        // only the sidecar's copy of the author's frame.
        wire: Vec::new(),
        created_at: 1,
    };
    match store.commit(request).await {
        CommitOutcome::Applied { .. } => {}
        other => panic!("seed commit was not applied: {other:?}"),
    }
}

/// Commit `files` files of `bytes` bytes each under `/d`, then pad the log to
/// `total` events.
///
/// The failed deployment's public log was 25 events: nine metadata events
/// followed by content. This reproduces that shape through the real commit
/// path, so the event log, the chunks and the replay frames are the ones
/// production would build.
async fn seed_tree(store: &StoreHandle, files: usize, bytes: usize, total: usize) -> usize {
    seed_commit(
        store,
        seed_op(1, OpClass::MKDIR, "/d", Some(0o755), None),
        None,
    )
    .await;
    let mut events = 1;
    for index in 0..files {
        let path = format!("/d/f{index}");
        seed_commit(
            store,
            seed_op(
                10 + index as u64 * 2,
                OpClass::CREATE_EXCL,
                &path,
                Some(0o644),
                None,
            ),
            None,
        )
        .await;
        events += 1;
        let data = vec![b'a' + (index % 26) as u8; bytes];
        seed_commit(
            store,
            seed_op(
                11 + index as u64 * 2,
                OpClass::WRITE,
                &path,
                None,
                Some((&data, 0x1000 + index as u128)),
            ),
            Some(data),
        )
        .await;
        events += 1;
    }
    // Pad with metadata-only events so the log length matches production and
    // the replay has to interleave content with small frames.
    let mut id = 10_000u64;
    while events + 3 < total {
        let index = events % files;
        seed_commit(
            store,
            seed_op(
                id,
                OpClass::SETATTR,
                &format!("/d/f{index}"),
                Some(0o600),
                None,
            ),
            None,
        )
        .await;
        id += 1;
        events += 1;
    }
    while events < total {
        let path = format!("/pad{}", events);
        seed_commit(
            store,
            seed_op(id, OpClass::MKDIR, &path, Some(0o755), None),
            None,
        )
        .await;
        id += 1;
        events += 1;
    }
    events
}

/// Start a server whose log holds a real tree with content.
async fn start_content_server(
    dir: &Path,
    files: usize,
    bytes: usize,
    total: usize,
) -> (Server, Endpoint, usize) {
    let db = dir.join("server.db");
    let (store, _meta) = StoreHandle::start(db.clone()).unwrap();
    let events = seed_tree(&store, files, bytes, total).await;
    store.shutdown().await.unwrap();
    let config = ServeConfig {
        db_path: db,
        ..ServeConfig::loopback()
    };
    let server = Server::bind(config, master()).await.unwrap();
    let addr = server.local_addr().unwrap();
    let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
    (server, endpoint, events)
}

struct ClientHandle {
    db: Arc<ClientDb>,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    shutdown: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<session::SessionExit>,
}

/// One replica and its observability handles, without a running session.
struct Replica {
    db: Arc<ClientDb>,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
}

fn spawn_client(
    dir: &std::path::Path,
    name: &str,
    endpoint: &Endpoint,
    ring: &syncmount::protocol::crypto::PskKeyRing,
) -> ClientHandle {
    spawn_client_with_meta(dir, name, endpoint, ring, None)
}

/// Force the durable cursor to a previous history, as a proto 2 replica would
/// carry it into a proto 3 handshake.
fn force_stale_meta(db: &Path, epoch: i64, applied: i64) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute("UPDATE meta SET value = ?1 WHERE key = 'epoch'", [epoch])
        .unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'applied_seq'",
        [applied],
    )
    .unwrap();
}

fn spawn_client_with_meta(
    dir: &std::path::Path,
    name: &str,
    endpoint: &Endpoint,
    ring: &syncmount::protocol::crypto::PskKeyRing,
    stale: Option<(i64, i64)>,
) -> ClientHandle {
    let Replica {
        db,
        gate,
        counters,
        conntrace,
    } = client_parts(dir, name, stale);
    let (shutdown, shutdown_rx) = mpsc::channel(1);
    let mut shutdown_rx = shutdown_rx;
    let options = SessionOptions {
        endpoint: endpoint.clone(),
        ring: ring.clone(),
        mount_id: name.to_owned(),
    };
    let run_db = Arc::clone(&db);
    let run_gate = Arc::clone(&gate);
    let run_counters = Arc::clone(&counters);
    let run_trace = Arc::clone(&conntrace);
    let task = tokio::spawn(async move {
        session::run(
            run_db,
            options,
            run_gate,
            run_counters,
            run_trace,
            &mut shutdown_rx,
        )
        .await
    });
    ClientHandle {
        db,
        gate,
        counters,
        conntrace,
        shutdown,
        task,
    }
}

/// Open one replica and its observability handles without starting a session.
fn client_parts(dir: &std::path::Path, name: &str, stale: Option<(i64, i64)>) -> Replica {
    let db_path = dir.join(format!("{name}.db"));
    let db = Arc::new(ClientDb::open(&db_path, [7u8; 16]).unwrap());
    if let Some((epoch, applied)) = stale {
        force_stale_meta(&db_path, epoch, applied);
    }
    let gate = Arc::new(WriteGate::new(State::Joining));
    let counters = Arc::new(Counters::default());
    let conntrace = Arc::new(Conntrace::default());
    Replica {
        db,
        gate,
        counters,
        conntrace,
    }
}

async fn wait_applied(handle: &ClientHandle, target: i64, deadline: Duration) -> Duration {
    let started = Instant::now();
    loop {
        if handle.db.applied_seq().unwrap() >= target {
            return started.elapsed();
        }
        assert!(
            !handle.task.is_finished(),
            "client exited before reaching applied_seq {target}"
        );
        assert!(
            started.elapsed() < deadline,
            "client did not reach applied_seq {target} within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_client_replays_fifty_thousand_events() {
    let dir = tempfile::tempdir().unwrap();
    let total = 50_000usize;
    let (server, endpoint) = start_server(dir.path(), total).await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let client = spawn_client(dir.path(), "solo", &endpoint, &ring);
    let elapsed = wait_applied(&client, total as i64, Duration::from_secs(120)).await;
    eprintln!(
        "REPLAY one total={total} elapsed={elapsed:?} rate={:.0}/s",
        total as f64 / elapsed.as_secs_f64()
    );
    assert!(
        total as f64 / elapsed.as_secs_f64() >= 1000.0,
        "replay rate below 1000 events/s: {elapsed:?} for {total}"
    );

    let _ = client.shutdown.send(()).await;
    let exit = client.task.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

/// An idle session must not scan the outbox at a fixed rate.
///
/// The 1.0 uplink scanned every 2 ms, about five thousand times in ten
/// seconds. The event-driven uplink scans only when a commit, a control frame
/// or the PING wakes it, so ten idle seconds cost a few dozen scans.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_uplink_does_not_poll_the_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (server, endpoint) = start_server(dir.path(), 1).await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let client = spawn_client(dir.path(), "idle", &endpoint, &ring);
    wait_applied(&client, 1, Duration::from_secs(30)).await;
    let steady_deadline = Instant::now() + Duration::from_secs(10);
    while client.gate.state() != State::Steady {
        assert!(
            !client.task.is_finished(),
            "client exited before reaching steady"
        );
        assert!(
            Instant::now() < steady_deadline,
            "client never reached steady"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Let the last echo land before the idle window starts.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let before = client.db.outbox_scans();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let scans = client.db.outbox_scans().saturating_sub(before);
    eprintln!("IDLE outbox scans in 10 s: {scans}");
    assert!(
        scans <= 60,
        "an idle uplink scanned the outbox {scans} times in 10 s; the 2 ms poll is back"
    );
    assert!(!client.task.is_finished(), "the idle session exited");

    let _ = client.shutdown.send(()).await;
    let exit = client.task.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

/// A commit wakes an idle uplink instead of waiting for a timer.
///
/// The deadline is shorter than both the one-second fallback and the PING
/// interval, so only the outbox notifier can satisfy it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_wakes_an_idle_uplink() {
    let dir = tempfile::tempdir().unwrap();
    let (server, endpoint) = start_server(dir.path(), 1).await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let client = spawn_client(dir.path(), "wake", &endpoint, &ring);
    wait_applied(&client, 1, Duration::from_secs(30)).await;
    let steady_deadline = Instant::now() + Duration::from_secs(10);
    while client.gate.state() != State::Steady {
        assert!(
            !client.task.is_finished(),
            "client exited before reaching steady"
        );
        assert!(
            Instant::now() < steady_deadline,
            "client never reached steady"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Let the uplink enter its idle wait.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let scans_before = client.db.outbox_scans();

    let started = Instant::now();
    client
        .db
        .create_file(
            ROOT_INO,
            OsStr::new("wake"),
            CreateAttrs::new(0o644, 1000, 1000),
        )
        .unwrap();
    let deadline = Duration::from_millis(500);
    while client.db.outbox_count(OutboxState::Pending).unwrap() != 0 {
        assert!(
            started.elapsed() < deadline,
            "the uplink did not send the committed row within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        client.db.outbox_scans() > scans_before,
        "the uplink sent the row without scanning the outbox"
    );
    eprintln!("WAKE committed row sent in {:?}", started.elapsed());

    let _ = client.shutdown.send(()).await;
    let exit = client.task.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn eleven_clients_replay_ten_thousand_each_within_a_minute() {
    let dir = tempfile::tempdir().unwrap();
    let per_client = 10_000usize;
    let (server, endpoint) = start_server(dir.path(), per_client).await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let started = Instant::now();
    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let mut clients = Vec::new();
    for index in 0..11 {
        clients.push(spawn_client(
            dir.path(),
            &format!("client-{index}"),
            &endpoint,
            &ring,
        ));
    }
    let mut slowest = Duration::ZERO;
    for client in &clients {
        let elapsed = wait_applied(client, per_client as i64, Duration::from_secs(60)).await;
        slowest = slowest.max(elapsed);
    }
    let wall = started.elapsed();
    eprintln!(
        "REPLAY eleven per_client={per_client} wall={wall:?} slowest={slowest:?} rate={:.0}/s",
        (per_client * clients.len()) as f64 / wall.as_secs_f64()
    );
    assert!(
        wall <= Duration::from_secs(60),
        "eleven clients did not catch up within 60s: {wall:?}"
    );
    for client in &clients {
        assert!(!client.task.is_finished(), "a client exited during replay");
        assert_eq!(client.db.applied_seq().unwrap(), per_client as i64);
    }
    for client in &clients {
        let _ = client.shutdown.send(()).await;
    }
    for client in clients {
        let exit = client.task.await.unwrap();
        assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    }
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

/// Forward one direction of a TCP stream with a fixed propagation delay.
///
/// The reader keeps reading while earlier chunks wait, so the path has the
/// round-trip latency of a real link without serialising chunk delivery.
async fn delayed_pipe<R, W>(mut from: R, mut to: W, delay: Duration)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (tx, mut rx) = mpsc::channel::<(Instant, bytes::Bytes)>(4096);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if tx
                        .send((Instant::now(), bytes::Bytes::copy_from_slice(&buf[..read])))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    while let Some((arrived, chunk)) = rx.recv().await {
        tokio::time::sleep_until(tokio::time::Instant::from_std(arrived + delay)).await;
        if to.write_all(&chunk).await.is_err() {
            break;
        }
    }
    reader.abort();
    let _ = to.shutdown().await;
}

/// Listen on a fresh port and forward every connection to `upstream` with a
/// one-way delay. Two directions of `delay` make the round trip `2 * delay`.
async fn delay_proxy(upstream: u16, delay: Duration) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else {
                continue;
            };
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            let (client_rx, client_tx) = client.into_split();
            let (server_rx, server_tx) = server.into_split();
            tokio::spawn(delayed_pipe(client_rx, server_tx, delay));
            tokio::spawn(delayed_pipe(server_rx, client_tx, delay));
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_client_replays_ten_thousand_events_over_251ms_rtt() {
    let dir = tempfile::tempdir().unwrap();
    let total = 10_000usize;
    let (server, _endpoint) = start_server(dir.path(), total).await;
    let port = delay_proxy(
        server.local_addr().unwrap().port(),
        Duration::from_millis(125),
    )
    .await;
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let client = spawn_client(dir.path(), "delayed", &endpoint, &ring);
    let elapsed = wait_applied(&client, total as i64, Duration::from_secs(120)).await;
    eprintln!(
        "REPLAY rtt251 total={total} elapsed={elapsed:?} rate={:.0}/s",
        total as f64 / elapsed.as_secs_f64()
    );
    assert!(
        total as f64 / elapsed.as_secs_f64() >= 100.0,
        "replay rate below 100 events/s at 251 ms RTT: {elapsed:?} for {total}"
    );

    let _ = client.shutdown.send(()).await;
    let exit = client.task.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

/// Forward every connection to `upstream`, and stop the server-to-client
/// direction once for `stall` after `limit` bytes have crossed.
///
/// A single pause, not a slow link: the reader stops reading, so the kernel
/// buffers and the server's writer fill exactly as they do when the client's
/// downlink task is wedged. The pause applies once, so a reconnect runs on an
/// unhindered path.
async fn stall_proxy(upstream: u16, limit: usize, stall: Duration) -> u16 {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let stalled = Arc::new(AtomicBool::new(false));
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else {
                continue;
            };
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            let (mut client_rx, mut client_tx) = client.into_split();
            let (mut server_rx, mut server_tx) = server.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut client_rx, &mut server_tx).await;
                let _ = server_tx.shutdown().await;
            });
            let stalled = Arc::clone(&stalled);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let mut forwarded = 0usize;
                loop {
                    match server_rx.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            forwarded += read;
                            if forwarded > limit && !stalled.swap(true, Ordering::SeqCst) {
                                eprintln!("STALL proxy pausing the downlink for {stall:?}");
                                tokio::time::sleep(stall).await;
                            }
                            if client_tx.write_all(&buf[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = client_tx.shutdown().await;
            });
        }
    });
    port
}

/// Reconnect a session after a resync, mirroring the client driver.
async fn drive_sessions(
    replica: Replica,
    endpoint: Endpoint,
    ring: syncmount::protocol::crypto::PskKeyRing,
    mount_id: String,
    mut shutdown: mpsc::Receiver<()>,
) -> session::SessionExit {
    let Replica {
        db,
        gate,
        counters,
        conntrace,
    } = replica;
    let mut attempts = 0u32;
    loop {
        let started = Instant::now();
        let before = db.applied_seq().unwrap_or(0);
        let exit = session::run(
            Arc::clone(&db),
            SessionOptions {
                endpoint: endpoint.clone(),
                ring: ring.clone(),
                mount_id: mount_id.clone(),
            },
            Arc::clone(&gate),
            Arc::clone(&counters),
            Arc::clone(&conntrace),
            &mut shutdown,
        )
        .await;
        if exit.reason != "resync" {
            return exit;
        }
        let after = db.applied_seq().unwrap_or(0);
        if after > before || started.elapsed() >= Duration::from_secs(10) {
            attempts = 0;
        }
        attempts = attempts.saturating_add(1);
        assert!(attempts <= 6, "reconnect budget exhausted after {attempts}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn in_entries(handle: &ClientHandle) -> Vec<syncmount::client::status::TraceEntry> {
    handle
        .conntrace
        .snapshot()
        .into_iter()
        .filter(|entry| entry.dir == "in")
        .collect()
}

/// Every `RELAY` open must be followed by at least one `STREAM_DATA` before
/// the `ORDERED` that names the stream.
fn assert_content_order(trace: &[syncmount::client::status::TraceEntry]) {
    let mut open = false;
    let mut fragments = 0usize;
    for entry in trace {
        match entry.kind.as_str() {
            "RELAY" => {
                assert!(
                    !open || fragments > 0,
                    "a RELAY open replaced another open without STREAM_DATA"
                );
                open = true;
                fragments = 0;
            }
            "STREAM_DATA" => {
                assert!(open, "STREAM_DATA without a RELAY open");
                fragments += 1;
            }
            "ORDERED" if open => {
                assert!(
                    fragments > 0,
                    "ORDERED named a content stream that never arrived"
                );
                open = false;
            }
            _ => {}
        }
    }
    assert!(!open || fragments > 0, "the trace ended inside a stream");
}

/// The failed deployment's shape: a replica from a previous epoch replays a
/// compacted log with content. The write gate must stay closed until the
/// durable watermark equals the handshake watermark, and every byte must
/// arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_epoch_reset_replays_content_before_the_gate_opens() {
    let dir = tempfile::tempdir().unwrap();
    let files = 7usize;
    let bytes = 200 * 1024usize;
    let (server, _endpoint, total) = start_content_server(dir.path(), files, bytes, 25).await;
    // Pause the downlink once mid-replay so the gate is sampled while the
    // watermark is still behind. The pause is below the watchdog budget, so
    // this test observes the gate rather than the recovery path.
    let port = stall_proxy(
        server.local_addr().unwrap().port(),
        128 * 1024,
        Duration::from_millis(1500),
    )
    .await;
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    // A proto 2 replica: epoch 3 with a 6179-event watermark, while the
    // compacted proto 3 log restarts at 1.
    let client = spawn_client_with_meta(dir.path(), "stale", &endpoint, &ring, Some((3, 6179)));

    let deadline = Instant::now() + Duration::from_secs(60);
    // The forced 6179-event cursor is not this history. Wait until the epoch
    // reset has replaced it before sampling progress.
    while client.db.applied_seq().unwrap() > total as i64 {
        assert!(
            Instant::now() < deadline,
            "the replica was never reset for the new epoch"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut steady_early = false;
    while client.db.applied_seq().unwrap() < total as i64 {
        if client.gate.state() == State::Steady {
            steady_early = true;
        }
        assert!(
            Instant::now() < deadline,
            "replay did not reach {total}: applied {}",
            client.db.applied_seq().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !steady_early,
        "the write gate opened before the replay watermark reached the handshake watermark"
    );

    // The gate opens only after the batch that covers the handshake
    // watermark commits.
    let gate_deadline = Instant::now() + Duration::from_secs(10);
    while client.gate.state() != State::Steady {
        assert!(
            Instant::now() < gate_deadline,
            "the gate never opened after applied reached {total}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    for index in 0..files {
        let path = format!("/d/f{index}");
        let object = client.db.lookup_by_path(&path).unwrap();
        assert_eq!(
            object.size, bytes as u64,
            "{path} has the wrong size after replay"
        );
        let data = client.db.read_at(object.ino, 0, bytes as u32).unwrap();
        assert_eq!(data.len(), bytes, "{path} is short after replay");
        assert!(
            data.iter().all(|byte| *byte == b'a' + (index % 26) as u8),
            "{path} carries the wrong bytes after replay"
        );
    }
    assert_content_order(&in_entries(&client));
    assert_eq!(
        client
            .counters
            .ops_applied
            .load(std::sync::atomic::Ordering::Relaxed),
        total as u64,
        "every replayed event must be counted as applied"
    );

    let _ = client.shutdown.send(()).await;
    let exit = client.task.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}

/// A downlink that goes silent mid-replay must not leave the mount half
/// applied. The session watchdog resyncs, the driver reconnects from the
/// durable cursor, and the replay finishes on the new connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_stalled_replay_resyncs_and_finishes_from_the_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let files = 7usize;
    let bytes = 200 * 1024usize;
    let (server, _endpoint, total) = start_content_server(dir.path(), files, bytes, 25).await;
    let port = stall_proxy(
        server.local_addr().unwrap().port(),
        128 * 1024,
        // Longer than the 45 s watchdog. The proxy pauses every downlink
        // frame, including the keepalive PONG, so only the receive silence
        // can trigger the resync.
        Duration::from_secs(50),
    )
    .await;
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(server.run_with_shutdown(async {
        let _ = stop_rx.await;
    }));

    let ring = master().derive_psk_keyring(&PskSalt::DEFAULT).unwrap();
    let replica = client_parts(dir.path(), "stalled", Some((3, 6179)));
    let db = Arc::clone(&replica.db);
    let gate = Arc::clone(&replica.gate);
    let counters = Arc::clone(&replica.counters);
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let driver = tokio::spawn({
        let endpoint = endpoint.clone();
        let ring = ring.clone();
        async move { drive_sessions(replica, endpoint, ring, "stalled".to_owned(), shutdown_rx).await }
    });

    let started = Instant::now();
    while db.applied_seq().unwrap() > total as i64 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the replica was never reset for the new epoch"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut steady_early = false;
    loop {
        let applied = db.applied_seq().unwrap();
        if gate.state() == State::Steady && applied < total as i64 {
            steady_early = true;
        }
        if applied >= total as i64 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "replay did not recover after the stall: applied {applied} of {total}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!steady_early, "the gate opened before the replay finished");
    assert!(
        counters.resyncs.load(std::sync::atomic::Ordering::Relaxed) >= 1,
        "the stalled session did not resync"
    );
    for index in 0..files {
        let path = format!("/d/f{index}");
        let object = db.lookup_by_path(&path).unwrap();
        assert_eq!(object.size, bytes as u64, "{path} is incomplete");
    }

    let _ = shutdown_tx.send(()).await;
    let exit = driver.await.unwrap();
    assert_ne!(exit.code, 10, "client must not exit 10: {exit:?}");
    let _ = stop_tx.send(());
    let _ = server_task.await;
}
