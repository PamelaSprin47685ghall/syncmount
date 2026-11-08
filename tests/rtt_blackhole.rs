//! Real-mount proof that every FUSE hot-path callback is local-first.
//!
//! One server, one client, one real FUSE mount. After the mount reaches
//! STEADY, the server process is stopped with `SIGSTOP`, which is a total RTT
//! blackhole: the TCP connection stays open, but no echo, no `ORDERED`
//! confirmation and no outbox acknowledgement can arrive. Every hot-path
//! syscall is then timed. A callback that waits for the server would hang
//! until the test's per-operation deadline; a local-first callback returns in
//! milliseconds.
//!
//! The test also checks the other half of the contract: the outbox grows
//! while the server is stopped, the client process stays alive, and `SIGCONT`
//! lets the durable outbox drain without a restart.
//!
//! Run explicitly:
//!
//! ```text
//! cargo test --test rtt_blackhole -- --nocapture
//! ```
//!
//! `SYNCMOUNT_REQUIRE_FUSE=1` turns a missing FUSE stack into a failure
//! instead of a skip.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};
use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

const PSK: &[u8] = b"rtt-blackhole-master-psk";
const BIN: &str = env!("CARGO_BIN_EXE_syncmount");
const POLL: Duration = Duration::from_millis(50);
const READY: Duration = Duration::from_secs(30);
/// Per-syscall watchdog. A callback waiting for a stopped server never
/// returns; this bound turns that into a named failure instead of a hang.
const OP_TIMEOUT: Duration = Duration::from_secs(5);
/// The contract says an op above 100 ms is suspicious. With a stopped server
/// any RTT wait is unbounded, so this is the assertion that matters.
const OP_LIMIT: Duration = Duration::from_millis(100);
/// A graceful server stop can take the full 30 s drain budget.
const SERVER_STOP: Duration = Duration::from_secs(45);
const CLIENT_STOP: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// cluster harness
// ---------------------------------------------------------------------------

struct Env {
    dir: TempDir,
    key: PathBuf,
    run_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("master.key");
        fs::write(&key, PSK).expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");
        let run_dir = dir.path().join("run");
        fs::create_dir_all(&run_dir).expect("run dir");
        Self { dir, key, run_dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn server(&self, db_name: &str) -> Server {
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let url = format!("http://{addr}/sync");
        let mut cmd = Command::new(BIN);
        cmd.args(["--log-format", "json", "--log-level", "info", "server"])
            .arg(&url)
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--db")
            .arg(self.path(db_name))
            .arg("--key-file")
            .arg(&self.key);
        clean_env(&mut cmd);
        let mut proc = Proc::spawn(&mut cmd, self.path("server.log"));
        wait_until("server listen", READY, || {
            if let Some(status) = proc.try_wait() {
                return Err(format!("server exited with {status}\n{}", proc.tail()));
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                Ok(true)
            } else {
                Err(format!("no listener on {addr}"))
            }
        });
        Server {
            proc,
            db: self.path(db_name),
            port,
        }
    }

    fn client(&self, name: &str, db_name: &str, server: &Server) -> Client {
        let mountpoint = self.path(&format!("mnt-{name}"));
        fs::create_dir_all(&mountpoint).expect("mountpoint");
        let url = format!("http://127.0.0.1:{}/sync", server.port);
        let mut cmd = Command::new(BIN);
        cmd.args(["--log-format", "json", "--log-level", "info", "client"])
            .arg(&url)
            .arg(&mountpoint)
            .arg("--db")
            .arg(self.path(db_name))
            .arg("--key-file")
            .arg(&self.key);
        clean_env(&mut cmd);
        cmd.env("SYNCMOUNT_RUN_DIR", &self.run_dir);
        let proc = Proc::spawn(&mut cmd, self.path(&format!("client-{name}.log")));
        Client {
            proc,
            db: self.path(db_name),
            mountpoint,
        }
    }
}

struct Proc {
    child: Child,
    log: PathBuf,
}

impl Proc {
    fn spawn(cmd: &mut Command, log: PathBuf) -> Self {
        let out = File::create(&log).expect("log file");
        let err = out.try_clone().expect("clone log file");
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        let child = cmd.spawn().expect("spawn");
        Self { child, log }
    }

    fn signal(&self, signal: Signal) {
        if let Some(pid) = Pid::from_raw(self.child.id() as i32) {
            let _ = kill_process(pid, signal);
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    fn kill_wait(&mut self) {
        self.signal(Signal::KILL);
        let _ = self.child.wait();
    }

    fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                self.kill_wait();
                panic!(
                    "{} did not exit within {timeout:?}\n{}",
                    self.log.display(),
                    self.tail()
                );
            }
            thread::sleep(POLL);
        }
    }

    fn tail(&self) -> String {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(80)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if self.try_wait().is_none() {
            self.kill_wait();
        }
    }
}

struct Server {
    proc: Proc,
    db: PathBuf,
    port: u16,
}

struct Client {
    proc: Proc,
    db: PathBuf,
    mountpoint: PathBuf,
}

impl Client {
    fn wait_mounted(&mut self) {
        wait_until("client mounted", READY, || {
            if let Some(status) = self.proc.try_wait() {
                return Err(format!("client exited with {status}\n{}", self.proc.tail()));
            }
            if is_mounted(&self.mountpoint) {
                Ok(true)
            } else {
                Err(format!(
                    "{} is not in /proc/mounts",
                    self.mountpoint.display()
                ))
            }
        });
    }

    fn stop_graceful(&mut self) -> ExitStatus {
        self.proc.signal(Signal::TERM);
        self.proc.wait_exit(CLIENT_STOP)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.proc.try_wait().is_none() {
            self.proc.signal(Signal::TERM);
            for _ in 0..100 {
                if self.proc.try_wait().is_some() {
                    break;
                }
                thread::sleep(POLL);
            }
            if self.proc.try_wait().is_none() {
                self.proc.kill_wait();
            }
        }
        // Lazy unmount; `-z` never blocks on a busy mount.
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg("-z")
            .arg(&self.mountpoint)
            .status();
    }
}

fn clean_env(cmd: &mut Command) {
    for key in [
        "SYNCMOUNT_LISTEN",
        "SYNCMOUNT_SERVER_DB",
        "SYNCMOUNT_MASTER_PASSWORD",
        "SYNCMOUNT_MASTER_PASSWORD_FILE",
        "SYNCMOUNT_DB",
        "SYNCMOUNT_STATE_DIR",
        "SYNCMOUNT_RUN_DIR",
        "RUST_LOG",
        "SYNCMOUNT_LOG",
    ] {
        cmd.env_remove(key);
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn fuse_available() -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .map_err(|error| format!("cannot open /dev/fuse: {error}"))?;
    let path = std::env::var_os("PATH").ok_or("PATH is unset")?;
    if std::env::split_paths(&path).any(|dir| dir.join("fusermount3").is_file()) {
        Ok(())
    } else {
        Err("fusermount3 is not in PATH".to_owned())
    }
}

fn wait_until<F>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Result<bool, String>,
{
    let deadline = Instant::now() + timeout;
    let mut last = String::from("no observation");
    loop {
        match check() {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => last = error,
        }
        if Instant::now() >= deadline {
            panic!("timed out after {timeout:?} waiting for {what}; last: {last}");
        }
        thread::sleep(POLL);
    }
}

fn wait_value<T, F>(what: &str, timeout: Duration, mut check: F) -> T
where
    F: FnMut() -> Result<T, String>,
{
    let deadline = Instant::now() + timeout;
    let mut last;
    loop {
        match check() {
            Ok(value) => return value,
            Err(error) => last = error,
        }
        if Instant::now() >= deadline {
            panic!("timed out after {timeout:?} waiting for {what}; last: {last}");
        }
        thread::sleep(POLL);
    }
}

fn is_mounted(mountpoint: &Path) -> bool {
    let needle = mountpoint.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|mounts| {
            mounts
                .lines()
                .any(|line| line.split_whitespace().nth(1) == Some(needle.as_ref()))
        })
        .unwrap_or(false)
}

fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 1..].trim_start().chars().next()
}

// ---------------------------------------------------------------------------
// SQLite probes (read-only; never take the client's flock)
// ---------------------------------------------------------------------------

fn open_ro(path: &Path) -> Option<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let _ = conn.busy_timeout(Duration::from_millis(250));
    Some(conn)
}

fn db_i64(path: &Path, key: &str) -> Option<i64> {
    open_ro(path)?
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .ok()
}

fn db_count(path: &Path, sql: &str) -> Option<i64> {
    open_ro(path)?.query_row(sql, [], |row| row.get(0)).ok()
}

fn db_count_op(path: &Path, sql: &str, op_id: [u8; 16]) -> Option<i64> {
    open_ro(path)?
        .query_row(sql, [op_id.as_slice()], |row| row.get(0))
        .ok()
}

fn ino_at(path: &Path, name: &str) -> Option<[u8; 16]> {
    let bytes: Vec<u8> = open_ro(path)?
        .query_row("SELECT ino FROM names WHERE path = ?1", [name], |row| {
            row.get(0)
        })
        .ok()?;
    bytes.try_into().ok()
}

/// The server's authoritative content for one path, read from its SQLite
/// replica: `names` -> ino, `objects.size`, `object_chunks` in chunk order
/// and the `chunks.data` bytes concatenated.
fn server_content(server_db: &Path, path: &str) -> Option<Vec<u8>> {
    let conn = open_ro(server_db)?;
    // One read transaction, so the size and the chunk list come from the same
    // committed state.
    let tx = conn.unchecked_transaction().ok()?;
    let ino: Vec<u8> = tx
        .query_row("SELECT ino FROM names WHERE path = ?1", [path], |row| {
            row.get(0)
        })
        .ok()?;
    let size: i64 = tx
        .query_row(
            "SELECT size FROM objects WHERE ino = ?1",
            [ino.as_slice()],
            |row| row.get(0),
        )
        .ok()?;
    let content = {
        let mut stmt = tx
            .prepare(
                "SELECT chunks.data
                   FROM object_chunks
                   JOIN chunks ON chunks.hash = object_chunks.chunk_hash
                  WHERE object_chunks.ino = ?1
                  ORDER BY object_chunks.chunk_no",
            )
            .ok()?;
        let rows = stmt
            .query_map([ino.as_slice()], |row| row.get::<_, Option<Vec<u8>>>(0))
            .ok()?;
        let mut content = Vec::with_capacity(usize::try_from(size).ok()?);
        for row in rows {
            let data = row.ok()?;
            content.extend_from_slice(&data?);
        }
        content
    };
    tx.commit().ok()?;
    Some(content)
}

fn outbox_depth(client_db: &Path) -> i64 {
    db_count(
        client_db,
        "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')",
    )
    .unwrap_or(-1)
}

/// The operation id of the newest create for `path` still waiting for a
/// verdict.
fn outbox_op_id(client_db: &Path, path: &str) -> Option<[u8; 16]> {
    let bytes: Vec<u8> = open_ro(client_db)?
        .query_row(
            "SELECT op_id FROM outbox
              WHERE path = ?1 AND kind = 'create_file'
                AND state IN ('pending', 'sent')
              ORDER BY created_at DESC LIMIT 1",
            [path],
            |row| row.get(0),
        )
        .ok()?;
    bytes.try_into().ok()
}

fn outbox_state(client_db: &Path, op_id: [u8; 16]) -> Option<String> {
    open_ro(client_db)?
        .query_row(
            "SELECT state FROM outbox WHERE op_id = ?1",
            [op_id.as_slice()],
            |row| row.get(0),
        )
        .ok()
}

fn outbox_attempts(client_db: &Path, op_id: [u8; 16]) -> Option<i64> {
    open_ro(client_db)?
        .query_row(
            "SELECT attempts FROM outbox WHERE op_id = ?1",
            [op_id.as_slice()],
            |row| row.get(0),
        )
        .ok()
}

fn wait_process_state(pid: u32, wanted: char) {
    wait_until("process state", READY, || match process_state(pid) {
        Some(state) if state == wanted => Ok(true),
        other => Err(format!("state is {other:?}, wanted {wanted:?}")),
    });
}

fn wait_process_running(pid: u32) {
    wait_until("process running", READY, || match process_state(pid) {
        Some('T') | None => Err(format!("state is {:?}", process_state(pid))),
        Some(_) => Ok(true),
    });
}

fn write_retry(mount: &Path, rel: &str, data: &[u8]) {
    let path = mount.join(rel);
    retry("write_retry", || {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(data)?;
        file.sync_all()
    });
}

fn wait_file(mount: &Path, rel: &str, expected: &[u8]) {
    let path = mount.join(rel);
    wait_until("file content", READY, || match fs::read(&path) {
        Ok(bytes) if bytes == expected => Ok(true),
        Ok(bytes) => Err(format!("content is {:?}", String::from_utf8_lossy(&bytes))),
        Err(error) => Err(format!("read: {error}")),
    });
}

/// Like [`wait_file`], but includes the client log when the deadline expires.
fn wait_file_logged(mount: &Path, rel: &str, expected: &[u8], proc: &mut Proc) {
    let path = mount.join(rel);
    let deadline = Instant::now() + READY;
    let mut last;
    loop {
        if let Some(status) = proc.try_wait() {
            panic!(
                "client exited with {status} while waiting for {rel}\nclient log:\n{}",
                proc.tail()
            );
        }
        match fs::read(&path) {
            Ok(bytes) if bytes == expected => return,
            Ok(bytes) => last = format!("content is {:?}", String::from_utf8_lossy(&bytes)),
            Err(error) => last = format!("read: {error}"),
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {rel} ({last})\nclient log:\n{}",
                proc.tail()
            );
        }
        thread::sleep(POLL);
    }
}

/// Deterministic multi-chunk content for the rejection fixture: one MiB with
/// a distinguishable tail, so a truncated or empty copy fails the comparison.
fn clash_content() -> Vec<u8> {
    let mut data: Vec<u8> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
    let tail = data.len() - 8;
    data[tail..].copy_from_slice(b"tailmark");
    data
}

/// Wait until the mount content equals the server's current authoritative
/// content for the path. After a resync the client adopts the server's tree,
/// so the assertion names no fixed byte string.
fn wait_file_matches_server(mount: &Path, rel: &str, server_db: &Path, proc: &mut Proc) {
    let path = mount.join(rel);
    let server_path = format!("/{rel}");
    let deadline = Instant::now() + READY;
    let mut last;
    loop {
        if let Some(status) = proc.try_wait() {
            panic!(
                "client exited with {status} while waiting for {rel} to converge\nclient log:\n{}",
                proc.tail()
            );
        }
        match (fs::read(&path), server_content(server_db, &server_path)) {
            (Ok(bytes), Some(server)) if bytes == server => return,
            (Ok(bytes), Some(server)) => {
                last = format!("mount {} B, server {} B", bytes.len(), server.len());
            }
            (Ok(_), None) => last = "server has no content for the path".to_owned(),
            (Err(error), _) => last = format!("read: {error}"),
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {rel} to match the server ({last})\nclient log:\n{}",
                proc.tail()
            );
        }
        thread::sleep(POLL);
    }
}

/// Wait until the server's authoritative content for one path is `expected`.
fn wait_server_content(server_db: &Path, path: &str, expected: &[u8]) {
    wait_until(
        "server authoritative content",
        READY,
        || match server_content(server_db, path) {
            Some(bytes) if bytes == expected => Ok(true),
            Some(bytes) => Err(format!("server content is {} B", bytes.len())),
            None => Err("server has no content for the path".to_owned()),
        },
    );
}

fn wait_synced(client_db: &Path, server_db: &Path) {
    wait_until("outbox drained and client caught up", READY, || {
        let seq = db_i64(server_db, "seq").unwrap_or(-1);
        let applied = db_i64(client_db, "applied_seq").unwrap_or(-1);
        let pending = outbox_depth(client_db);
        if applied >= seq && pending == 0 {
            Ok(true)
        } else {
            Err(format!("seq={seq} applied={applied} outbox={pending}"))
        }
    });
}

// ---------------------------------------------------------------------------
// syscall helpers
// ---------------------------------------------------------------------------

fn retryable(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if [
                rustix::io::Errno::AGAIN.raw_os_error(),
                rustix::io::Errno::BUSY.raw_os_error(),
                rustix::io::Errno::ROFS.raw_os_error(),
                rustix::io::Errno::NOTCONN.raw_os_error(),
            ]
            .contains(&code)
    )
}

fn retry<T>(what: &str, mut body: impl FnMut() -> std::io::Result<T>) -> T {
    let deadline = Instant::now() + READY;
    loop {
        match body() {
            Ok(value) => return value,
            Err(error) if retryable(&error) && Instant::now() < deadline => {
                thread::sleep(POLL);
            }
            Err(error) => panic!("{what} failed: {error}"),
        }
    }
}

/// Run `body` on a watchdog thread and return the elapsed time of the body
/// itself (not the drop of its return value).
fn measure<T, F>(name: &str, body: F) -> Duration
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let start = Instant::now();
        let value = body();
        let elapsed = start.elapsed();
        drop(value);
        let _ = tx.send(elapsed);
    });
    match rx.recv_timeout(OP_TIMEOUT) {
        Ok(elapsed) => {
            handle.join().expect("measurement thread panicked");
            elapsed
        }
        Err(_) => panic!("{name} did not complete within {OP_TIMEOUT:?}; it waits for the server"),
    }
}

struct Samples {
    rows: Vec<(&'static str, Duration)>,
}

impl Samples {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }

    fn push(&mut self, name: &'static str, elapsed: Duration) {
        println!("op={name} elapsed_us={}", elapsed.as_micros());
        self.rows.push((name, elapsed));
    }

    fn assert_local(&self) {
        for (name, elapsed) in &self.rows {
            assert!(
                *elapsed < OP_LIMIT,
                "{name} took {elapsed:?} with a stopped server (limit {OP_LIMIT:?})"
            );
        }
        let max = self
            .rows
            .iter()
            .map(|(_, elapsed)| *elapsed)
            .max()
            .expect("at least one sample");
        println!("hot_path_max_us={}", max.as_micros());
    }
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

#[test]
#[serial_test::serial]
fn hot_path_ops_complete_while_the_server_is_stopped() {
    if let Err(reason) = fuse_available() {
        if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
            panic!("FUSE is required but unavailable: {reason}");
        }
        eprintln!("SKIP hot_path_ops_complete_while_the_server_is_stopped: {reason}");
        return;
    }

    let env = Env::new();
    let mut server = env.server("server.db");
    let mut client = env.client("blackhole", "client.db", &server);
    client.wait_mounted();
    let mount = client.mountpoint.clone();

    // Wait for STEADY: a write is refused with EROFS/ENOTCONN while JOINING.
    retry("warm-up create", || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(mount.join(".warm"))
    });
    retry("warm-up write", || {
        fs::write(mount.join("f"), vec![7u8; 8192])
    });
    retry("warm-up fsync", || {
        File::options()
            .write(true)
            .open(mount.join("f"))?
            .sync_all()
    });
    retry("setup directory", || fs::create_dir(mount.join("d")));

    // Exercise every callback once before the blackhole, so the measured
    // calls do not pay first-use costs (lazy mount setup, empty WAL, etc.).
    retry("warm-up read", || {
        let mut file = File::open(mount.join("f"))?;
        let mut buf = vec![0u8; 4096];
        file.read_exact(&mut buf)?;
        Ok(())
    });
    retry("warm-up mkdir", || fs::create_dir(mount.join("wd")));
    retry("warm-up rename", || {
        fs::rename(mount.join("f"), mount.join("f.warm"))
    });
    retry("warm-up rename back", || {
        fs::rename(mount.join("f.warm"), mount.join("f"))
    });
    retry("warm-up link", || {
        fs::hard_link(mount.join("f"), mount.join("whard"))
    });
    retry("warm-up symlink", || symlink("f", mount.join("wsym")));
    retry("warm-up truncate", || {
        File::options()
            .write(true)
            .open(mount.join("f"))?
            .set_len(4096)
    });
    retry("warm-up setattr", || {
        fs::set_permissions(mount.join("f"), fs::Permissions::from_mode(0o644))
    });
    retry("warm-up create", || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(mount.join("w1"))
    });
    retry("warm-up unlink", || fs::remove_file(mount.join("w1")));
    retry("warm-up rmdir", || fs::remove_dir(mount.join("wd")));
    retry("warm-up hard unlink", || {
        fs::remove_file(mount.join("whard"))
    });
    retry("warm-up symlink unlink", || {
        fs::remove_file(mount.join("wsym"))
    });
    retry("warm-up flush", || {
        let mut file = File::options().write(true).open(mount.join("f"))?;
        file.write_all(b"x")?;
        Ok(())
    });
    retry("warm-up release", || File::open(mount.join("f")).map(drop));
    retry("warm-up unlink", || fs::remove_file(mount.join(".warm")));

    // Everything is local and durable before the blackhole.
    wait_synced(&client.db, &server.db);
    assert_eq!(outbox_depth(&client.db), 0, "warm-up must be acknowledged");

    let pid = server.proc.pid();
    server.proc.signal(Signal::STOP);
    wait_until("server stopped", READY, || match process_state(pid) {
        Some('T') => Ok(true),
        other => Err(format!("server state is {other:?}")),
    });
    // Let any echo that was already in flight settle. Nothing new can arrive.
    thread::sleep(Duration::from_millis(200));

    let mut samples = Samples::new();
    let f = mount.join("f");
    let buf = vec![0u8; 4096];

    // read
    {
        let path = f.clone();
        let read = buf.clone();
        samples.push(
            "read",
            measure("read", move || {
                let mut file = File::open(&path).expect("open for read");
                let mut got = read;
                file.read_exact(&mut got).expect("read_exact");
            }),
        );
    }

    // write
    {
        let path = f.clone();
        let data = vec![9u8; 4096];
        samples.push(
            "write",
            measure("write", move || {
                let mut file = File::options()
                    .write(true)
                    .open(&path)
                    .expect("open for write");
                file.write_all(&data).expect("write_all");
            }),
        );
    }

    // create
    {
        let path = mount.join("new");
        samples.push(
            "create",
            measure("create", move || {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .expect("create_new")
            }),
        );
    }

    // mkdir
    {
        let path = mount.join("newdir");
        samples.push(
            "mkdir",
            measure("mkdir", move || fs::create_dir(&path).expect("create_dir")),
        );
    }

    // unlink
    {
        let path = mount.join("new");
        samples.push(
            "unlink",
            measure("unlink", move || {
                fs::remove_file(&path).expect("remove_file")
            }),
        );
    }

    // rmdir
    {
        let path = mount.join("newdir");
        samples.push(
            "rmdir",
            measure("rmdir", move || fs::remove_dir(&path).expect("remove_dir")),
        );
    }

    // rename (and back, so later ops still use `f`)
    {
        let from = f.clone();
        let to = mount.join("renamed");
        samples.push(
            "rename",
            measure("rename", move || {
                fs::rename(&from, &to).expect("rename");
            }),
        );
        retry("rename back", || {
            fs::rename(mount.join("renamed"), mount.join("f"))
        });
    }

    // link
    {
        let from = f.clone();
        let to = mount.join("hard2");
        samples.push(
            "link",
            measure("link", move || {
                fs::hard_link(&from, &to).expect("hard_link");
            }),
        );
    }

    // symlink
    {
        let to = mount.join("link");
        samples.push(
            "symlink",
            measure("symlink", move || {
                symlink("f", &to).expect("symlink");
            }),
        );
    }

    // truncate (setattr with size)
    {
        let path = f.clone();
        samples.push(
            "truncate",
            measure("truncate", move || {
                File::options()
                    .write(true)
                    .open(&path)
                    .expect("open for truncate")
                    .set_len(4096)
                    .expect("set_len");
            }),
        );
    }

    // setattr (mode)
    {
        let path = f.clone();
        samples.push(
            "setattr",
            measure("setattr", move || {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("set_permissions");
            }),
        );
    }

    // flush: close a write-opened file; FUSE_FLUSH commits the buffer.
    {
        let path = f.clone();
        samples.push(
            "flush",
            measure("flush", move || {
                let mut file = File::options()
                    .write(true)
                    .open(&path)
                    .expect("open for flush");
                file.write_all(b"flush").expect("buffered write");
                drop(file);
            }),
        );
    }

    // release: close a read-opened file; FUSE_RELEASE has no dirty buffer.
    {
        let path = f.clone();
        samples.push(
            "release",
            measure("release", move || {
                let file = File::open(&path).expect("open for release");
                drop(file);
            }),
        );
    }

    // fsync
    {
        let path = f.clone();
        samples.push(
            "fsync",
            measure("fsync", move || {
                File::open(&path)
                    .expect("open for fsync")
                    .sync_all()
                    .expect("sync_all");
            }),
        );
    }

    samples.assert_local();

    // The local effects are durable and the outbox grew; the client is alive.
    let grown = outbox_depth(&client.db);
    println!("outbox_depth_during_blackhole={grown}");
    assert!(
        grown >= 10,
        "the outbox must hold the unacknowledged operations, got {grown}"
    );
    assert!(
        client.proc.try_wait().is_none(),
        "the client exited while the server was stopped\n{}",
        client.proc.tail()
    );

    // Recovery: the same process resends without a restart.
    server.proc.signal(Signal::CONT);
    wait_until("server resumed", READY, || match process_state(pid) {
        Some('T') | None => Err(format!("server state is {:?}", process_state(pid))),
        Some(_) => Ok(true),
    });
    wait_synced(&client.db, &server.db);

    // The server applied the operations that were issued while it was frozen.
    let names = db_count(
        &server.db,
        "SELECT COUNT(*) FROM names
          WHERE path IN ('/f', '/d', '/link', '/hard2')",
    )
    .unwrap_or(-1);
    assert_eq!(names, 4, "server is missing a name created locally");
    let (size, mode) = open_ro(&server.db)
        .expect("open server db")
        .query_row(
            "SELECT o.size, o.mode FROM objects o JOIN names n ON n.ino = o.ino
              WHERE n.path = '/f'",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("server /f");
    assert_eq!(size, 4096, "server did not apply the local truncate");
    assert_eq!(mode & 0o7777, 0o600, "server did not apply the local chmod");
    assert_eq!(outbox_depth(&client.db), 0, "recovered outbox must drain");

    let status = client.stop_graceful();
    assert_eq!(
        status.code(),
        Some(0),
        "client must stop cleanly\n{}",
        client.proc.tail()
    );
    let mountpoint = client.mountpoint.clone();
    drop(client);
    wait_until("mount unmounted", READY, || {
        if is_mounted(&mountpoint) {
            Err(format!("{} is still mounted", mountpoint.display()))
        } else {
            Ok(true)
        }
    });

    server.proc.signal(Signal::TERM);
    let status = server.proc.wait_exit(SERVER_STOP);
    assert_eq!(
        status.code(),
        Some(0),
        "server must stop cleanly\n{}",
        server.proc.tail()
    );
}

/// A rejection is asynchronous: the syscall commits locally and returns while
/// the server is still frozen, then the background undoes the effect. The test
/// deliberately observes the silent content change that follows the verdict;
/// applications must expect it.
#[test]
#[serial_test::serial]
fn rejected_create_is_undone_after_the_blackhole() {
    if let Err(reason) = fuse_available() {
        if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
            panic!("FUSE is required but unavailable: {reason}");
        }
        eprintln!("SKIP rejected_create_is_undone_after_the_blackhole: {reason}");
        return;
    }

    let env = Env::new();
    let mut server = env.server("reject-blackhole.db");
    let mut a = env.client("a", "a.db", &server);
    let mut b = env.client("b", "b.db", &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&a.db, &server.db);
    wait_synced(&b.db, &server.db);

    // B owns the name on the server. A learns it, then a test-only edit makes
    // A forget it while keeping its applied_seq current: the deterministic
    // form of "A never saw B's create", the lost race a rejection resolves.
    // The content is large enough that the rejection snapshot (object, chunk
    // list and chunk data) exceeds the 512-byte ERROR detail, so the server
    // sends the resync marker instead of the snapshot.
    let clash = clash_content();
    write_retry(&b.mountpoint, "clash.txt", &clash);
    wait_file(&a.mountpoint, "clash.txt", &clash);
    wait_synced(&a.db, &server.db);

    let a_pid = a.proc.pid();
    a.proc.signal(Signal::STOP);
    wait_process_state(a_pid, 'T');
    {
        let conn = Connection::open(&a.db).expect("open A database");
        let _ = conn.busy_timeout(Duration::from_secs(5));
        let removed = conn
            .execute("DELETE FROM names WHERE path = '/clash.txt'", [])
            .expect("forget the server's name");
        assert_eq!(removed, 1, "A must have had the name before the fixture");
    }
    a.proc.signal(Signal::CONT);
    wait_process_running(a_pid);
    wait_until(
        "A revalidates the forgotten name",
        READY,
        || match fs::metadata(a.mountpoint.join("clash.txt")) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            other => Err(format!("metadata: {other:?}")),
        },
    );

    // Blackhole the server. The create commits locally and returns; the
    // rejection is still sitting in the stopped server.
    let server_pid = server.proc.pid();
    server.proc.signal(Signal::STOP);
    wait_process_state(server_pid, 'T');
    thread::sleep(Duration::from_millis(200));

    let path = a.mountpoint.join("clash.txt");
    let deadline = Instant::now() + READY;
    let (file, create_elapsed) = loop {
        let attempt = Instant::now();
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => break (file, attempt.elapsed()),
            Err(error) if error.kind() == ErrorKind::AlreadyExists && Instant::now() < deadline => {
                // The kernel can still hold the old positive dentry; it
                // revalidates after the entry TTL.
                thread::sleep(POLL);
            }
            Err(error) => panic!("create failed after {attempt:?}: {error}"),
        }
    };
    let close_started = Instant::now();
    drop(file);
    let close_elapsed = close_started.elapsed();
    println!(
        "rejected_create_us={} rejected_close_us={}",
        create_elapsed.as_micros(),
        close_elapsed.as_micros()
    );
    assert!(
        create_elapsed < OP_LIMIT,
        "the rejected create waited {create_elapsed:?} (limit {OP_LIMIT:?})"
    );
    assert!(
        close_elapsed < OP_LIMIT,
        "the rejected close (flush/release) waited {close_elapsed:?} (limit {OP_LIMIT:?})"
    );
    assert_eq!(
        fs::read(&path).expect("read optimistic content"),
        b"",
        "the optimistic create must be visible before the verdict"
    );

    // An unrelated local effect, created during the same blackhole. The
    // affected-path replacement must keep it (the pending outbox row is
    // resent after the rebase).
    let keep = a.mountpoint.join("keep.txt");
    let keep_path = keep.clone();
    let keep_elapsed = measure("unrelated create+write+fsync", move || {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&keep_path)
            .expect("create unrelated file");
        file.write_all(b"keep\n").expect("write unrelated file");
        file.sync_all().expect("fsync unrelated file");
    });
    println!(
        "unrelated_create_write_fsync_us={}",
        keep_elapsed.as_micros()
    );
    assert!(
        keep_elapsed < OP_LIMIT,
        "the unrelated create/write/fsync waited {keep_elapsed:?} (limit {OP_LIMIT:?})"
    );
    assert_eq!(fs::read(&keep).expect("read unrelated content"), b"keep\n");

    let op_id = wait_value("the create is in the outbox", READY, || {
        outbox_op_id(&a.db, "/clash.txt").ok_or_else(|| "no pending create".to_owned())
    });
    // Server-side baseline: the rejected create must add no sequence, no
    // event and no op-id row. The accepted work is /keep.txt (create and
    // write, two events and two op ids) plus the LEAVE that the resync
    // disconnect records (one event, no op id).
    let server_seq_before = db_i64(&server.db, "seq").unwrap_or(-1);
    let server_events_before = db_count(&server.db, "SELECT COUNT(*) FROM events").unwrap_or(-1);
    let server_opids_before = db_count(&server.db, "SELECT COUNT(*) FROM op_ids").unwrap_or(-1);
    let server_clash_ino = ino_at(&server.db, "/clash.txt").expect("server /clash.txt");
    assert!(outbox_depth(&a.db) >= 1);
    // The verdict cannot arrive while the server is stopped. Keep the
    // blackhole longer than any local RTT; the syscall is already long gone.
    thread::sleep(Duration::from_millis(300));
    assert!(
        a.proc.try_wait().is_none(),
        "the client exited during the blackhole\n{}",
        a.proc.tail()
    );
    assert_eq!(fs::read(&path).unwrap(), b"");

    // Resume: the server rejects the create with EEXIST. The snapshot does
    // not fit the ERROR detail, so the client records the tombstone, asks for
    // a replay and adopts the server's tree; the failed row stays as a
    // tombstone. The test waits for the mount to match the server.
    server.proc.signal(Signal::CONT);
    wait_process_running(server_pid);
    wait_until(
        "the rejected row is a failed tombstone",
        READY,
        || match outbox_state(&a.db, op_id).as_deref() {
            Some("failed") => Ok(true),
            other => Err(format!("outbox state is {other:?}")),
        },
    );
    wait_file_matches_server(&a.mountpoint, "clash.txt", &server.db, &mut a.proc);
    // The rebase may drop the unrelated local effect for a moment and restore
    // it when the pending outbox row is re-sent. Bounded poll, not an
    // instantaneous assertion.
    wait_file_logged(&a.mountpoint, "keep.txt", b"keep\n", &mut a.proc);
    assert!(
        a.proc.try_wait().is_none(),
        "the client exited after the background rollback\n{}",
        a.proc.tail()
    );

    // The unrelated create reaches the server; the failed tombstone does not
    // block the outbox.
    wait_synced(&a.db, &server.db);
    assert_eq!(
        db_count(
            &server.db,
            "SELECT COUNT(*) FROM names WHERE path = '/keep.txt'"
        )
        .unwrap_or(-1),
        1,
        "the unrelated create must reach the server"
    );
    assert_eq!(
        db_i64(&server.db, "seq").unwrap_or(-1),
        server_seq_before + 3,
        "the rejection consumes no sequence; keep create/write and the resync LEAVE do"
    );
    assert_eq!(
        db_count(&server.db, "SELECT COUNT(*) FROM events").unwrap_or(-1),
        server_events_before + 3,
        "a rejection must not write an event"
    );
    assert_eq!(
        db_count(&server.db, "SELECT COUNT(*) FROM op_ids").unwrap_or(-1),
        server_opids_before + 2,
        "a rejection must not record an op id"
    );
    assert_eq!(
        db_count(
            &server.db,
            "SELECT COUNT(*) FROM events WHERE kind = 'leave'"
        ),
        Some(1),
        "the resync disconnect records exactly one LEAVE"
    );
    assert_eq!(
        ino_at(&server.db, "/clash.txt"),
        Some(server_clash_ino),
        "the rejected create must not replace the server name"
    );
    assert_eq!(
        db_count_op(
            &server.db,
            "SELECT COUNT(*) FROM events WHERE op_id = ?1",
            op_id
        )
        .unwrap_or(-1),
        0,
        "the rejected op must have no event row"
    );
    assert_eq!(
        db_count_op(
            &server.db,
            "SELECT COUNT(*) FROM op_ids WHERE op_id = ?1",
            op_id
        )
        .unwrap_or(-1),
        0,
        "the rejected op must have no op-id row"
    );
    assert_eq!(
        outbox_state(&a.db, op_id).as_deref(),
        Some("failed"),
        "a rejection must stay a failed tombstone across the rebase"
    );
    assert!(
        outbox_attempts(&a.db, op_id).unwrap_or(i64::MAX) <= 1,
        "a failed tombstone must not be resent by the rebase"
    );

    // A normal write after convergence is theirs=local: A truncates the file
    // and writes short content, the server adopts it and the mount keeps it.
    let short = b"after resync\n";
    retry("post-rejection write", || {
        fs::write(a.mountpoint.join("clash.txt"), short)
    });
    wait_server_content(&server.db, "/clash.txt", short);
    wait_file_logged(&a.mountpoint, "clash.txt", short, &mut a.proc);
    assert_eq!(
        fs::read(a.mountpoint.join("clash.txt")).expect("read post-rejection content"),
        short,
        "the mount must keep A's post-resync write"
    );
    assert_eq!(
        server_content(&server.db, "/clash.txt").as_deref(),
        Some(&short[..]),
        "the server must hold A's post-resync write"
    );
    wait_synced(&a.db, &server.db);

    let status = a.stop_graceful();
    assert_eq!(
        status.code(),
        Some(0),
        "client must stop cleanly\n{}",
        a.proc.tail()
    );
    let mountpoint = a.mountpoint.clone();
    drop(a);
    wait_until("mount unmounted", READY, || {
        if is_mounted(&mountpoint) {
            Err(format!("{} is still mounted", mountpoint.display()))
        } else {
            Ok(true)
        }
    });

    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);

    server.proc.signal(Signal::TERM);
    let status = server.proc.wait_exit(SERVER_STOP);
    assert_eq!(
        status.code(),
        Some(0),
        "server must stop cleanly\n{}",
        server.proc.tail()
    );
}
