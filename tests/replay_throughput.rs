//! Replay throughput: one client and eleven clients against a real HTTP
//! server, with a real SQLite replica on each client.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use syncmount::client::session::{self, SessionOptions};
use syncmount::client::{ClientDb, Conntrace, Counters, State, WriteGate};
use syncmount::crypto::MasterKey;
use syncmount::protocol::crypto::PskSalt;
use syncmount::server::config::ServeConfig;
use syncmount::server::store::StoreHandle;
use syncmount::server::Server;
use syncmount::store::sqlite::EventPayload;
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

struct ClientHandle {
    db: Arc<ClientDb>,
    shutdown: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<session::SessionExit>,
}

fn spawn_client(
    dir: &std::path::Path,
    name: &str,
    endpoint: &Endpoint,
    ring: &syncmount::protocol::crypto::PskKeyRing,
) -> ClientHandle {
    let db_path = dir.join(format!("{name}.db"));
    let db = Arc::new(ClientDb::open(db_path, [7u8; 16]).unwrap());
    let gate = Arc::new(WriteGate::new(State::Joining));
    let counters = Arc::new(Counters::default());
    let conntrace = Arc::new(Conntrace::default());
    let (shutdown, shutdown_rx) = mpsc::channel(1);
    let mut shutdown_rx = shutdown_rx;
    let options = SessionOptions {
        endpoint: endpoint.clone(),
        ring: ring.clone(),
        mount_id: name.to_owned(),
    };
    let run_db = Arc::clone(&db);
    let task = tokio::spawn(async move {
        session::run(run_db, options, gate, counters, conntrace, &mut shutdown_rx).await
    });
    ClientHandle { db, shutdown, task }
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
