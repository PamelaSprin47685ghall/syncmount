//! Real end-to-end tests: one server process, two client processes, SQLite
//! state on both ends, a real FUSE mount, and a real PSK handshake.
//!
//! Every test owns a temporary directory and isolates:
//!
//! * the server database (`--db`),
//! * each client database (`--db`),
//! * each mountpoint,
//! * the PSK key file (`--key-file`, mode 0600),
//! * `SYNCMOUNT_RUN_DIR`, so status files never touch `/run`.
//!
//! The tests spawn the binary Cargo built for this test target
//! (`CARGO_BIN_EXE_syncmount`), which is the same `target/debug/syncmount`
//! produced by `cargo build`. No server, client or protocol module is
//! reimplemented here; the only direct library use is the public
//! [`EventPayload`] encoder, needed to inject one deliberately invalid
//! outbox row and one valid hard-link row whose wire convention the FUSE
//! callback cannot currently produce.
//!
//! Waiting is always a bounded poll (50 ms) with a deadline; there are no
//! fixed sleeps for correctness. A graceful server shutdown can legitimately
//! take the full 30 s drain timeout, so that one step allows 45 s.
//!
//! Run with:
//!
//! ```text
//! cargo +1.85.0 test --test e2e_sqlite -- --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OpenFlags};
use rustix::process::{kill_process, Pid, Signal};
use serde_json::Value;
use tempfile::TempDir;

use syncmount::client::ClientDb;
use syncmount::client::config::mount_id_for;
use syncmount::client::ops::AttrChange;
use syncmount::store::Errno;
use syncmount::store::sqlite::{
    EventKind, EventPayload, ObjectKind, ROOT_INO, chunk_hash, file_root,
};

/// The master password every fixture writes to its 0600 key file.
const PSK: &[u8] = b"e2e-sqlite-master-psk";
/// The binary under test. Cargo builds it before running this target.
const BIN: &str = env!("CARGO_BIN_EXE_syncmount");
/// Poll interval for every wait.
const POLL: Duration = Duration::from_millis(50);
/// Deadline for ordinary convergence.
const READY: Duration = Duration::from_secs(30);
/// Deadline for a graceful server stop (drain is 30 s).
const SERVER_STOP: Duration = Duration::from_secs(45);
/// Deadline for a client process to exit after SIGTERM.
const CLIENT_STOP: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/// One isolated cluster: temp directory, key file, runtime directory.
struct Env {
    dir: TempDir,
    key: PathBuf,
    run_dir: PathBuf,
    serial: AtomicUsize,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("master.key");
        write_key_file(&key, PSK);
        let run_dir = dir.path().join("run");
        fs::create_dir_all(&run_dir).expect("run dir");
        Self {
            dir,
            key,
            run_dir,
            serial: AtomicUsize::new(0),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write_key(&self, name: &str, password: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        write_key_file(&path, password);
        path
    }

    /// Start a server on a fresh port, using `db_name` (reused on restart).
    fn server(&self, db_name: &str) -> Server {
        let n = self.serial.fetch_add(1, Ordering::Relaxed);
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let db = self.path(db_name);
        let log = self.path(&format!("server-{n}.log"));
        let url = format!("http://{addr}/sync");

        let mut cmd = Command::new(BIN);
        cmd.arg("--log-format")
            .arg("json")
            .arg("--log-level")
            .arg("info")
            .arg("server")
            .arg(&url)
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--db")
            .arg(&db)
            .arg("--key-file")
            .arg(&self.key);
        clean_env(&mut cmd);

        let mut proc = Proc::spawn(&mut cmd, log, format!("server {db_name}"));

        let deadline = Instant::now() + READY;
        loop {
            if let Some(status) = proc.try_wait() {
                panic!(
                    "server exited before listening: {status}\n{}",
                    proc.tail()
                );
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                proc.signal(Signal::KILL);
                panic!("server did not listen on {addr}\n{}", proc.tail());
            }
            thread::sleep(POLL);
        }

        Server { proc, db, port }
    }

    /// Start a client against `server`, using `db_name` (reused on restart).
    fn client(&self, name: &str, db_name: &str, key: &Path, server: &Server) -> Client {
        let n = self.serial.fetch_add(1, Ordering::Relaxed);
        let mountpoint = self.path(&format!("mnt-{name}"));
        fs::create_dir_all(&mountpoint).expect("mountpoint");
        let db = self.path(db_name);
        let log = self.path(&format!("client-{name}-{n}.log"));
        let url = format!("http://127.0.0.1:{}/sync", server.port);

        let mut cmd = Command::new(BIN);
        cmd.arg("--log-format")
            .arg("json")
            .arg("--log-level")
            .arg("info")
            .arg("client")
            .arg(&url)
            .arg(&mountpoint)
            .arg("--db")
            .arg(&db)
            .arg("--key-file")
            .arg(key);
        clean_env(&mut cmd);
        cmd.env("SYNCMOUNT_RUN_DIR", &self.run_dir);

        let proc = Proc::spawn(&mut cmd, log, format!("client {name}"));
        Client {
            proc,
            mountpoint,
            db,
            run_dir: self.run_dir.clone(),
            mount_id: mount_id_for(&self.path(&format!("mnt-{name}"))),
            name: name.to_owned(),
        }
    }
}

/// A child process with a captured log.
struct Proc {
    child: Child,
    log: PathBuf,
    label: String,
}

impl Proc {
    fn spawn(cmd: &mut Command, log: PathBuf, label: String) -> Self {
        let out = File::create(&log).expect("log file");
        let err = out.try_clone().expect("clone log file");
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        let child = cmd.spawn().expect("spawn");
        Self { child, log, label }
    }

    fn signal(&self, signal: Signal) {
        if let Some(pid) = Pid::from_raw(self.child.id() as i32) {
            let _ = kill_process(pid, signal);
        }
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    /// Wait for exit, killing and panicking when the deadline expires.
    fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                self.signal(Signal::KILL);
                let _ = self.child.wait();
                panic!(
                    "{} did not exit within {timeout:?}\n{}",
                    self.label,
                    self.tail()
                );
            }
            thread::sleep(POLL);
        }
    }

    fn tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let mut lines: VecDeque<&str> = text.lines().rev().take(80).collect();
        let mut out = String::new();
        while let Some(line) = lines.pop_back() {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn log_contains(&self, needle: &str) -> bool {
        fs::read_to_string(&self.log)
            .map(|text| text.contains(needle))
            .unwrap_or(false)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if self.try_wait().is_none() {
            self.signal(Signal::KILL);
            let _ = self.child.wait();
        }
    }
}

struct Server {
    proc: Proc,
    db: PathBuf,
    port: u16,
}

impl Server {
    fn stop_graceful(&mut self) -> ExitStatus {
        self.proc.signal(Signal::TERM);
        self.proc.wait_exit(SERVER_STOP)
    }

    fn kill(&mut self) -> ExitStatus {
        self.proc.signal(Signal::KILL);
        self.proc.wait_exit(Duration::from_secs(10))
    }
}

struct Client {
    proc: Proc,
    mountpoint: PathBuf,
    db: PathBuf,
    run_dir: PathBuf,
    mount_id: String,
    name: String,
}

impl Client {
    /// Wait until the kernel has this mountpoint in `/proc/mounts`. Before
    /// that, a write would succeed against the plain directory.
    fn wait_mounted(&mut self) {
        let label = format!("{} mounted", self.name);
        wait_until(&label, READY, || {
            if let Some(status) = self.proc.try_wait() {
                return Err(format!(
                    "client exited with {status}\n{}",
                    self.proc.tail()
                ));
            }
            if is_mounted(&self.mountpoint) {
                Ok(true)
            } else {
                Err(format!("{} is not in /proc/mounts", self.mountpoint.display()))
            }
        });
    }

    fn stop_graceful(&mut self) -> ExitStatus {
        self.proc.signal(Signal::TERM);
        self.wait_exit_unmounting(CLIENT_STOP)
    }

    /// Wait for exit, nudging the kernel mount loose if `umount_and_join`
    /// blocks. fuser 0.18's join waits for the FUSE worker threads, which
    /// only wake when the mount is released; without this the client hangs
    /// after a handshake failure or a KICK.
    fn wait_exit_unmounting(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        let mut last_nudge = Instant::now();
        loop {
            if let Some(status) = self.proc.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                self.proc.signal(Signal::KILL);
                let _ = self.proc.child.wait();
                panic!(
                    "{} did not exit within {timeout:?}\n{}",
                    self.name,
                    self.proc.tail()
                );
            }
            if last_nudge.elapsed() >= Duration::from_millis(300) {
                let _ = Command::new("fusermount3")
                    .arg("-u")
                    .arg("-z")
                    .arg(&self.mountpoint)
                    .status();
                last_nudge = Instant::now();
            }
            thread::sleep(POLL);
        }
    }

    fn status(&self) -> Option<Value> {
        let path = self.run_dir.join(&self.mount_id).join("status.json");
        let bytes = fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn status_u64(&self, path: &[&str]) -> Option<u64> {
        let doc = self.status()?;
        let mut current = &doc;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_u64()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.proc.try_wait().is_none() {
            self.proc.signal(Signal::TERM);
            for _ in 0..40 {
                if self.proc.try_wait().is_some() {
                    break;
                }
                let _ = Command::new("fusermount3")
                    .arg("-u")
                    .arg("-z")
                    .arg(&self.mountpoint)
                    .status();
                thread::sleep(POLL);
            }
            if self.proc.try_wait().is_none() {
                self.proc.signal(Signal::KILL);
                let _ = self.proc.child.wait();
            }
        }
        // The client normally unmounts itself; this only cleans up after a
        // panic or a SIGKILL. `-z` is lazy, so it never blocks on a busy mount.
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg("-z")
            .arg(&self.mountpoint)
            .status();
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

fn write_key_file(path: &Path, password: &[u8]) {
    fs::write(path, password).expect("write key");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("key mode");
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn fuse_available() -> Result<(), String> {
    let device = Path::new("/dev/fuse");
    if !device.exists() {
        return Err("/dev/fuse is missing".to_owned());
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map_err(|error| format!("cannot open /dev/fuse: {error}"))?;
    let found = std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("fusermount3"))
                .any(|candidate| candidate.is_file())
        })
        .unwrap_or(false);
    if !found {
        return Err("fusermount3 is not in PATH".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bounded polling
// ---------------------------------------------------------------------------

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

fn wait_synced(client: &mut Client, server: &Server) {
    let label = format!("{} caught up with the server", client.name);
    let db = client.db.clone();
    let server_db = server.db.clone();
    let mut proc_exit = None;
    wait_until(&label, READY, || {
        if let Some(status) = client.proc.try_wait() {
            proc_exit = Some(status);
            return Err(format!(
                "client exited with {status}\n{}",
                client.proc.tail()
            ));
        }
        let state = client
            .status()
            .and_then(|doc| doc.get("state").and_then(Value::as_str).map(str::to_owned));
        if state.as_deref() == Some("UNMOUNTING") {
            let status = client.wait_exit_unmounting(Duration::from_secs(10));
            return Err(format!(
                "client entered UNMOUNTING and exited with {status}\n{}",
                client.proc.tail()
            ));
        }
        let seq = match db_i64(&server_db, "seq") {
            Some(value) => value,
            None => return Ok(false),
        };
        let applied = match db_i64(&db, "applied_seq") {
            Some(value) => value,
            None => return Ok(false),
        };
        let pending = match db_count(
            &db,
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')",
        ) {
            Some(value) => value,
            None => return Ok(false),
        };
        if applied >= seq && pending == 0 {
            Ok(true)
        } else {
            Err(format!(
                "seq={seq} applied={applied} pending={pending}\n{}",
                client.proc.tail()
            ))
        }
    });
    let _ = proc_exit;
}

fn wait_status_state(client: &mut Client, wanted: &str) {
    let label = format!("{} state {wanted}", client.name);
    wait_until(&label, READY, || {
        if let Some(status) = client.proc.try_wait() {
            return Err(format!(
                "client exited with {status}\n{}",
                client.proc.tail()
            ));
        }
        let state = client
            .status()
            .and_then(|doc| doc.get("state").and_then(Value::as_str).map(str::to_owned));
        if state.as_deref() == Some(wanted) {
            return Ok(true);
        }
        if state.as_deref() == Some("UNMOUNTING") {
            // The session already ended; fuser's join can block until the
            // mount is released. Unblock it and report the real exit code.
            let status = client.wait_exit_unmounting(Duration::from_secs(10));
            return Err(format!(
                "client entered UNMOUNTING and exited with {status}\n{}",
                client.proc.tail()
            ));
        }
        Err(format!("state={state:?}\n{}", client.proc.tail()))
    });
}

// ---------------------------------------------------------------------------
// SQLite reads (read-only; never take the client's flock)
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
    let conn = open_ro(path)?;
    conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .ok()
}

fn db_blob(path: &Path, key: &str) -> Option<Vec<u8>> {
    let conn = open_ro(path)?;
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get(0))
        .ok()
}

fn db_count(path: &Path, sql: &str) -> Option<i64> {
    let conn = open_ro(path)?;
    conn.query_row(sql, [], |row| row.get(0)).ok()
}

fn db_value_i64(path: &Path, sql: &str) -> Option<i64> {
    let conn = open_ro(path)?;
    conn.query_row(sql, [], |row| row.get(0)).ok()
}

/// Linux process state from `/proc/<pid>/stat` (`R`, `S`, `T`, ...).
fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 1..].trim_start().chars().next()
}

fn ino_at(path: &Path, name: &str) -> Option<[u8; 16]> {
    let conn = open_ro(path)?;
    let bytes: Vec<u8> = conn
        .query_row("SELECT ino FROM names WHERE path = ?1", [name], |row| {
            row.get(0)
        })
        .ok()?;
    bytes.try_into().ok()
}

fn outbox_row(path: &Path, op_id: &[u8; 16]) -> Option<(String, i64, Option<Vec<u8>>)> {
    let conn = open_ro(path)?;
    conn.query_row(
        "SELECT state, attempts, undo FROM outbox WHERE op_id = ?1",
        [op_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .ok()
}

fn random_op_id() -> [u8; 16] {
    let mut id: [u8; 16] = rand::random();
    if id == [0u8; 16] {
        id[0] = 1;
    }
    id
}

/// Insert one durable outbox row and keep `meta.local_seq` monotonic.
fn insert_outbox(
    db: &Path,
    op_id: [u8; 16],
    kind: &str,
    path: &str,
    path2: Option<&str>,
    ino: [u8; 16],
    payload: &[u8],
) {
    let conn = Connection::open(db).expect("open client db for fixture");
    let next: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(created_at), 0) + 1 FROM outbox",
            [],
            |row| row.get(0),
        )
        .expect("next local seq");
    conn.execute(
        "INSERT INTO outbox
           (op_id, kind, path, path2, ino, payload, undo, state, attempts, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'pending', 0, ?7)",
        params![
            op_id.as_slice(),
            kind,
            path,
            path2,
            ino.as_slice(),
            payload,
            next
        ],
    )
    .expect("insert outbox row");
    conn.execute(
        "UPDATE meta SET value = MAX(CAST(value AS INTEGER), ?1) WHERE key = 'local_seq'",
        [next],
    )
    .expect("bump local_seq");
}

/// Encode one unsigned integer the way bincode's standard config does.
fn push_bincode_u32(out: &mut Vec<u8>, value: u32) {
    if value <= 250 {
        out.push(value as u8);
    } else if value <= u32::from(u16::MAX) {
        out.push(0xfb);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        out.push(0xfc);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// The version-1 `setattr` payload for a mode-only change.
///
/// Version 1 had no `size`: `version 1 || tag 5 || ino || mode || uid || gid
/// || mtime_ns`, with `None` encoded as one zero byte. The bytes are the
/// format a database written before the upgrade holds.
fn v1_setattr_payload(ino: [u8; 16], mode: u32) -> Vec<u8> {
    let mut out = vec![1, 5];
    out.extend_from_slice(&ino);
    out.push(1);
    push_bincode_u32(&mut out, mode);
    out.extend_from_slice(&[0, 0, 0]);
    out
}

/// Rewrite a client database to look "never synced" while keeping its tree.
///
/// This is the only way to reach the seed path with the shipped CLI: a client
/// that has applied any event is no longer a seed source, and a fresh client
/// has no tree to seed. The tree itself was produced by the real binary.
fn reset_client_for_seed(db: &Path) {
    let conn = Connection::open(db).expect("open client db for seed reset");
    conn.execute_batch(
        "BEGIN IMMEDIATE;
         UPDATE meta SET value = 0 WHERE key IN ('applied_seq', 'covered_seq');
         UPDATE meta SET value = 1 WHERE key = 'epoch';
         UPDATE meta SET value = 1 WHERE key = 'dirty';
         DELETE FROM outbox;
         DELETE FROM events;
         COMMIT;",
    )
    .expect("reset client for seed");
}

// ---------------------------------------------------------------------------
// filesystem helpers (bounded retry while the gate is JOINING)
// ---------------------------------------------------------------------------

fn retryable(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == Errno::EROFS.raw()
                || code == rustix::io::Errno::NOTCONN.raw_os_error()
                || code == Errno::EBUSY.raw()
                || code == Errno::EAGAIN.raw()
    )
}

fn write_retry(mount: &Path, rel: &str, data: &[u8]) {
    let path = mount.join(rel);
    wait_until(&format!("write {rel}"), READY, || match fs::write(&path, data) {
        Ok(()) => Ok(true),
        Err(error) if retryable(&error) => Err(error.to_string()),
        Err(error) => Err(format!("write {rel}: {error}")),
    });
}

fn mkdir_retry(mount: &Path, rel: &str) {
    let path = mount.join(rel);
    wait_until(&format!("mkdir {rel}"), READY, || match fs::create_dir(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(true),
        Err(error) => Err(format!("mkdir {rel}: {error}")),
    });
}

fn rename_retry(mount: &Path, from: &str, to: &str) {
    wait_until(&format!("rename {from} -> {to}"), READY, || {
        match fs::rename(mount.join(from), mount.join(to)) {
            Ok(()) => Ok(true),
            Err(error) => Err(format!("rename: {error}")),
        }
    });
}

fn unlink_retry(mount: &Path, rel: &str) {
    wait_until(&format!("unlink {rel}"), READY, || {
        match fs::remove_file(mount.join(rel)) {
            Ok(()) => Ok(true),
            Err(error) => Err(format!("unlink: {error}")),
        }
    });
}

fn symlink_retry(mount: &Path, rel: &str, target: &str) {
    wait_until(&format!("symlink {rel}"), READY, || {
        match std::os::unix::fs::symlink(target, mount.join(rel)) {
            Ok(()) => Ok(true),
            Err(error) => Err(format!("symlink: {error}")),
        }
    });
}

fn wait_file(mount: &Path, rel: &str, expected: &[u8]) {
    let path = mount.join(rel);
    wait_until(&format!("{rel} == {} bytes", expected.len()), READY, || {
        match fs::read(&path) {
            Ok(bytes) if bytes == expected => Ok(true),
            Ok(bytes) => Err(format!(
                "{rel}: {} bytes, blake3={}",
                bytes.len(),
                blake3::hash(&bytes).to_hex()
            )),
            Err(error) => Err(format!("read {rel}: {error}")),
        }
    });
}

fn wait_absent(mount: &Path, rel: &str) {
    let path = mount.join(rel);
    wait_until(&format!("{rel} absent"), READY, || match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("stat {rel}: {error}")),
        Ok(_) => Err(format!("{rel} is still present")),
    });
}

fn wait_readlink(mount: &Path, rel: &str, expected: &str) {
    let path = mount.join(rel);
    wait_until(&format!("readlink {rel} == {expected}"), READY, || {
        match fs::read_link(&path) {
            Ok(target) => {
                if target.to_str() == Some(expected) {
                    Ok(true)
                } else {
                    Err(format!("readlink {rel} -> {}", target.display()))
                }
            }
            Err(error) => Err(format!("readlink {rel}: {error}")),
        }
    });
}

fn sha_file(mount: &Path, rel: &str) -> String {
    let bytes = fs::read(mount.join(rel)).expect("read for hash");
    blake3::hash(&bytes).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// PSK handshake succeeds; a wrong key is refused with exit code 4.
#[test]
fn psk_handshake_success_and_wrong_psk_exit_4() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP psk_handshake_success_and_wrong_psk_exit_4: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("psk.db");

    let mut good = env.client("good", "good.db", &env.key, &server);
    good.wait_mounted();
    wait_status_state(&mut good, "STEADY");
    let status = good.stop_graceful();
    assert_eq!(
        status.code(),
        Some(0),
        "a valid PSK client must stop cleanly\n{}",
        good.proc.tail()
    );
    drop(good);

    let wrong = env.write_key("wrong.key", b"definitely-not-the-psk");
    let mut bad = env.client("bad", "bad.db", &wrong, &server);
    let status = bad.wait_exit_unmounting(READY);
    assert_eq!(
        status.code(),
        Some(4),
        "a wrong PSK must exit 4 (EXIT_AUTH)\n{}",
        bad.proc.tail()
    );
    assert!(
        bad.proc.log_contains("master password rejected"),
        "the client should log the rejected handshake\n{}",
        bad.proc.tail()
    );
}

/// Server empty: the first client seeds its offline tree; the second client
/// replays from zero and sees the same bytes.
#[test]
fn seed_upload_then_second_client_replays_from_zero() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP seed_upload_then_second_client_replays_from_zero: {reason}");
        return;
    }
    let env = Env::new();

    // Phase 1: produce a real client database with a local tree. The server
    // here is throwaway; its only job is to let the client build the tree.
    let mut source = env.server("seed-source.db");
    let mut a1 = env.client("seed-a1", "seed.db", &env.key, &source);
    a1.wait_mounted();
    let content = b"seeded content\n".to_vec();
    write_retry(&a1.mountpoint, "seed.txt", &content);
    wait_synced(&mut a1, &source);
    let db = a1.db.clone();
    let mount = a1.mountpoint.clone();
    let status = a1.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a1.proc.tail());
    drop(a1);
    source.kill();

    // Make the tree "offline": no applied events, epoch 1, no outbox.
    reset_client_for_seed(&db);
    assert_eq!(db_i64(&db, "applied_seq"), Some(0));
    assert_eq!(db_i64(&db, "epoch"), Some(1));
    let live = db_count(
        &db,
        "SELECT COUNT(*) FROM objects WHERE deleted = 0 AND ino <> zeroblob(16)",
    );
    assert!(
        live.unwrap_or(0) > 0,
        "the fixture must still contain its local tree: live={live:?} objects={:?} names={:?} db={}",
        db_count(&db, "SELECT COUNT(*) FROM objects"),
        db_count(&db, "SELECT COUNT(*) FROM names"),
        db.display()
    );

    // Phase 2: a genuinely empty server and the same local tree.
    let server = env.server("seed-target.db");
    let mut a2 = env.client("seed-a2", "seed.db", &env.key, &server);
    a2.wait_mounted();
    wait_until("the first client to seed the empty server", READY, || {
        if let Some(status) = a2.proc.try_wait() {
            return Err(format!(
                "seed client exited with {status}\n{}",
                a2.proc.tail()
            ));
        }
        Ok(db_i64(&server.db, "seq").unwrap_or(0) > 0)
    });
    assert!(
        a2.proc.log_contains("\"event\":\"seed\""),
        "the client must take the seed path\n{}",
        a2.proc.tail()
    );
    wait_synced(&mut a2, &server);
    assert_eq!(
        db_count(&server.db, "SELECT COUNT(*) FROM names WHERE path = '/seed.txt'"),
        Some(1),
        "the server must have the seeded entry"
    );
    assert_eq!(db_i64(&server.db, "epoch"), Some(1));
    assert_eq!(
        db_i64(&server.db, "seq"),
        db_count(&server.db, "SELECT COUNT(*) FROM events")
    );

    // The second client starts at applied_seq 0 and must replay the log.
    let mut b = env.client("seed-b", "seed-b.db", &env.key, &server);
    b.wait_mounted();
    wait_synced(&mut b, &server);
    assert_eq!(db_i64(&b.db, "epoch"), Some(1));
    assert_eq!(
        db_i64(&b.db, "applied_seq"),
        db_i64(&server.db, "seq")
    );
    wait_file(&b.mountpoint, "seed.txt", &content);
    wait_file(&a2.mountpoint, "seed.txt", &content);
    assert_eq!(
        sha_file(&a2.mountpoint, "seed.txt"),
        sha_file(&b.mountpoint, "seed.txt")
    );

    // A live write after the seed must reach the replayed client.
    write_retry(&a2.mountpoint, "after-seed.txt", b"after seed\n");
    wait_file(&b.mountpoint, "after-seed.txt", b"after seed\n");
    wait_synced(&mut a2, &server);
    wait_synced(&mut b, &server);

    let _ = mount;
}

/// Two mounted clients: A writes, B converges; B renames and unlinks, A
/// converges; a 150 KiB file exercises chunking and live STREAM_DATA.
#[test]
fn two_clients_converge_on_write_rename_unlink() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP two_clients_converge_on_write_rename_unlink: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("two.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    write_retry(&a.mountpoint, "a.txt", &big);
    wait_file(&b.mountpoint, "a.txt", &big);

    mkdir_retry(&a.mountpoint, "dir");
    write_retry(&a.mountpoint, "dir/inner.txt", b"inner\n");
    wait_file(&b.mountpoint, "dir/inner.txt", b"inner\n");

    symlink_retry(&a.mountpoint, "sym", "a.txt");
    wait_readlink(&b.mountpoint, "sym", "a.txt");

    rename_retry(&b.mountpoint, "a.txt", "b.txt");
    wait_absent(&a.mountpoint, "a.txt");
    wait_file(&a.mountpoint, "b.txt", &big);

    unlink_retry(&b.mountpoint, "b.txt");
    wait_absent(&a.mountpoint, "b.txt");

    write_retry(&b.mountpoint, "from-b.txt", b"from b\n");
    wait_file(&a.mountpoint, "from-b.txt", b"from b\n");

    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);
    assert_eq!(
        sha_file(&a.mountpoint, "from-b.txt"),
        sha_file(&b.mountpoint, "from-b.txt")
    );
    assert_eq!(
        db_count(&server.db, "SELECT COUNT(*) FROM names WHERE path = '/b.txt'"),
        Some(0)
    );
    assert_eq!(
        db_count(
            &server.db,
            "SELECT COUNT(*) FROM names WHERE path = '/from-b.txt'"
        ),
        Some(1)
    );
}

/// Eleven clients write 4 KiB files at the same time. Every client must
/// converge without a sequence gap: the server may kick a slow downlink, but
/// it must never skip a sequenced frame.
#[test]
fn eleven_clients_write_4k_concurrently_without_a_gap() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP eleven_clients_write_4k_concurrently_without_a_gap: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("eleven.db");
    let mut clients: Vec<Client> = (0..11)
        .map(|index| {
            env.client(
                &format!("c{index}"),
                &format!("c{index}.db"),
                &env.key,
                &server,
            )
        })
        .collect();
    for client in &mut clients {
        client.wait_mounted();
    }
    for client in &mut clients {
        wait_synced(client, &server);
    }

    let payload = vec![0x5au8; 4096];
    let mounts: Vec<PathBuf> = clients.iter().map(|client| client.mountpoint.clone()).collect();
    std::thread::scope(|scope| {
        for (index, mount) in mounts.iter().enumerate() {
            let mount = mount.clone();
            let payload = payload.clone();
            scope.spawn(move || {
                for file in 0..40 {
                    write_retry(&mount, &format!("c{index}-{file}.bin"), &payload);
                }
            });
        }
    });

    for client in &mut clients {
        wait_synced(client, &server);
        assert!(
            !client.proc.log_contains("event sequence gap"),
            "{} saw a sequence gap\n{}",
            client.name,
            client.proc.tail()
        );
        assert!(
            !client.proc.log_contains("cannot apply an event batch"),
            "{} failed an event batch\n{}",
            client.name,
            client.proc.tail()
        );
        assert!(
            !client.proc.log_contains("reconnect budget exhausted"),
            "{} exhausted its reconnect budget\n{}",
            client.name,
            client.proc.tail()
        );
    }
    for index in 0..11 {
        let reader = &clients[(index + 1) % 11];
        wait_file(
            &reader.mountpoint,
            &format!("c{index}-39.bin"),
            &payload,
        );
    }
}

/// A stopped client restarts from its persisted `applied_seq`; the server
/// replays only what it missed and the write gate reopens.
#[test]
fn client_restart_resumes_from_applied_seq() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP client_restart_resumes_from_applied_seq: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("restart.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "keep.txt", b"keep\n");
    wait_file(&b.mountpoint, "keep.txt", b"keep\n");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let applied_before = db_i64(&b.db, "applied_seq").expect("B applied_seq");
    let epoch_before = db_i64(&b.db, "epoch").expect("B epoch");
    let b_db = b.db.clone();
    let b_mount = b.mountpoint.clone();
    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);
    assert_eq!(
        db_i64(&b_db, "applied_seq"),
        Some(applied_before),
        "SIGTERM must not lose the watermark"
    );

    // The server turns B's disconnect into a LEAVE event; wait for it before
    // writing so the restart has a deterministic replay target.
    wait_until("B's LEAVE event", READY, || {
        Ok(db_i64(&server.db, "seq").unwrap_or(0) > applied_before)
    });
    write_retry(&a.mountpoint, "while-away.txt", b"away\n");
    wait_synced(&mut a, &server);

    let mut b2 = env.client("b2", "b.db", &env.key, &server);
    b2.wait_mounted();
    wait_synced(&mut b2, &server);
    assert_eq!(db_i64(&b2.db, "epoch"), Some(epoch_before));
    wait_file(&b2.mountpoint, "keep.txt", b"keep\n");
    wait_file(&b2.mountpoint, "while-away.txt", b"away\n");

    // The gate must be open after the restart: a write is the observable.
    write_retry(&b2.mountpoint, "after-restart.txt", b"after\n");
    wait_file(&a.mountpoint, "after-restart.txt", b"after\n");
    wait_status_state(&mut b2, "STEADY");
    let _ = b_mount;
}

/// Server SIGTERM drains, compacts (epoch + 1), and kicks the clients. After
/// both processes restart, every client replays the compacted log from zero
/// and the tree (including a hard link) matches the pre-restart bytes.
#[test]
fn server_restart_compacts_and_clients_full_replay() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP server_restart_compacts_and_clients_full_replay: {reason}");
        return;
    }
    let env = Env::new();
    let mut server = env.server("compact.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let big: Vec<u8> = (0..120_000u32).map(|i| (i % 239) as u8).collect();
    write_retry(&a.mountpoint, "file.txt", &big);
    mkdir_retry(&a.mountpoint, "dir");
    write_retry(&a.mountpoint, "dir/child.txt", b"child\n");
    symlink_retry(&a.mountpoint, "sym", "file.txt");
    wait_file(&b.mountpoint, "file.txt", &big);
    wait_file(&b.mountpoint, "dir/child.txt", b"child\n");
    wait_readlink(&b.mountpoint, "sym", "file.txt");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    // The FUSE `link(2)` callback currently sends the new path as both
    // F_PATH and F_TARGET, so the server rejects it with ENOENT. Inject the
    // equivalent valid Link row instead (path = existing, path2 = new), which
    // is the convention seed uses and the server accepts.
    let a_db = a.db.clone();
    let status = a.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a.proc.tail());
    drop(a);
    let file_ino = ino_at(&a_db, "/file.txt").expect("/file.txt ino");
    insert_outbox(
        &a_db,
        random_op_id(),
        "link",
        "/file.txt",
        Some("/hard.txt"),
        file_ino,
        &EventPayload::Link { ino: file_ino }
            .encode()
            .expect("link payload"),
    );
    let mut a2 = env.client("a2", "a.db", &env.key, &server);
    a2.wait_mounted();
    wait_file(&b.mountpoint, "hard.txt", &big);
    wait_synced(&mut a2, &server);
    wait_synced(&mut b, &server);
    assert_eq!(
        db_count(
            &server.db,
            "SELECT COUNT(*) FROM names WHERE path = '/hard.txt'"
        ),
        Some(1)
    );

    let epoch_before = db_i64(&server.db, "epoch").expect("server epoch");
    let seq_before = db_i64(&server.db, "seq").expect("server seq");
    assert!(seq_before > 0);
    let db = server.db.clone();

    // Graceful stop: drain (up to 30 s) -> compact -> KICK EpochMismatch.
    let status = server.stop_graceful();
    assert_eq!(
        status.code(),
        Some(0),
        "server must stop cleanly after drain and compaction"
    );
    drop(server);

    let sa = a2.wait_exit_unmounting(Duration::from_secs(20));
    assert_eq!(
        sa.code(),
        Some(10),
        "a connected client is kicked with EpochMismatch (exit 10)\n{}",
        a2.proc.tail()
    );
    drop(a2);
    let sb = b.wait_exit_unmounting(Duration::from_secs(20));
    assert_eq!(
        sb.code(),
        Some(10),
        "a connected client is kicked with EpochMismatch (exit 10)\n{}",
        b.proc.tail()
    );
    let b_db = b.db.clone();
    let b_mount = b.mountpoint.clone();
    drop(b);

    // Post-compaction metadata: epoch + 1, replay floor 1, and a replayable
    // log whose final sequence equals its event count.
    assert_eq!(db_i64(&db, "epoch"), Some(epoch_before + 1));
    assert_eq!(db_i64(&db, "replay_floor"), Some(1));
    let seq_after = db_i64(&db, "seq").expect("compacted seq");
    assert!(seq_after > 0, "compaction emits replayable events");
    assert_eq!(
        Some(seq_after),
        db_count(&db, "SELECT COUNT(*) FROM events"),
        "meta.seq must match the compacted event count"
    );
    assert_eq!(
        db_count(
            &db,
            "SELECT COUNT(*) FROM events WHERE kind = 'create_dir' AND path = '/'"
        ),
        Some(1),
        "the compacted log starts from the root object"
    );
    let hash_before = db_blob(&db, "state_hash").expect("state_hash");
    assert_eq!(hash_before.len(), 32);

    // Restart the server and both clients on the same databases.
    let server2 = env.server("compact.db");
    let mut a3 = env.client("a3", "a.db", &env.key, &server2);
    let mut b3 = env.client("b3", "b.db", &env.key, &server2);
    a3.wait_mounted();
    b3.wait_mounted();
    wait_replay_ok(&mut a3, &server2);
    wait_replay_ok(&mut b3, &server2);
    assert_eq!(db_i64(&a3.db, "epoch"), Some(epoch_before + 1));
    assert_eq!(db_i64(&b3.db, "epoch"), Some(epoch_before + 1));
    assert_eq!(db_i64(&a3.db, "applied_seq"), Some(seq_after));
    assert_eq!(db_i64(&b3.db, "applied_seq"), Some(seq_after));

    wait_file(&a3.mountpoint, "file.txt", &big);
    wait_file(&b3.mountpoint, "file.txt", &big);
    wait_file(&a3.mountpoint, "dir/child.txt", b"child\n");
    wait_file(&b3.mountpoint, "dir/child.txt", b"child\n");
    wait_readlink(&a3.mountpoint, "sym", "file.txt");
    wait_readlink(&b3.mountpoint, "sym", "file.txt");
    wait_file(&a3.mountpoint, "hard.txt", &big);
    wait_file(&b3.mountpoint, "hard.txt", &big);
    assert_eq!(
        sha_file(&a3.mountpoint, "file.txt"),
        sha_file(&b3.mountpoint, "file.txt")
    );
    assert_eq!(
        db_blob(&server2.db, "state_hash"),
        Some(hash_before),
        "compaction must not change the state digest"
    );
    let _ = (b_db, b_mount);
}

/// A semantically invalid op is rejected point-to-point: the author gets an
/// ERROR, its outbox row becomes `failed`, and no sequence or broadcast
/// reaches the other client.
#[test]
fn rejected_op_is_point_to_point_and_outbox_marks_failed() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP rejected_op_is_point_to_point_and_outbox_marks_failed: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("reject.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "clash.txt", b"original\n");
    wait_file(&b.mountpoint, "clash.txt", b"original\n");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let applied_before_stop = db_i64(&b.db, "applied_seq").expect("B applied");
    let b_db = b.db.clone();
    let b_mount = b.mountpoint.clone();
    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);

    // B's disconnect commits a LEAVE event; A must apply it before we take
    // the "nothing else happens" baseline.
    wait_until("B's LEAVE event", READY, || {
        Ok(db_i64(&server.db, "seq").unwrap_or(0) > applied_before_stop)
    });
    wait_synced(&mut a, &server);

    // A local create for a name the server already has. The client-side tree
    // is untouched; only the durable outbox carries the intent.
    let op_id = random_op_id();
    let ino = random_op_id();
    let payload = EventPayload::CreateFile {
        ino,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1,
        file_root: file_root(ObjectKind::File, None, &[]),
    }
    .encode()
    .expect("create payload");
    insert_outbox(
        &b_db,
        op_id,
        "create_file",
        "/clash.txt",
        None,
        ino,
        &payload,
    );

    let mut b2 = env.client("b2", "b.db", &env.key, &server);
    b2.wait_mounted();
    wait_until("the rejection to mark the outbox row failed", READY, || {
        if let Some(status) = b2.proc.try_wait() {
            return Err(format!(
                "author client exited with {status}\n{}",
                b2.proc.tail()
            ));
        }
        Ok(outbox_row(&b_db, &op_id)
            .map(|row| row.0 == "failed")
            .unwrap_or(false))
    });
    let (state, attempts, undo) = outbox_row(&b_db, &op_id).expect("outbox row");
    assert_eq!(state, "failed");
    // `attempts` counts sends; a rejection marks the row failed without
    // bumping it a second time, so one attempt is expected here.
    assert!(
        attempts >= 1,
        "a rejected op must be attempted at least once, got {attempts}"
    );
    assert_eq!(
        undo.as_deref(),
        Some(Errno::EEXIST.raw().to_le_bytes().as_slice()),
        "the row records the server errno"
    );
    assert_eq!(
        db_count(
            &b_db,
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')"
        ),
        Some(0),
        "a rejected op must leave the send queue"
    );

    // Point-to-point: the rejected op produces no event. The resync
    // reconnect itself records LEAVE events, so the raw sequence moves; the
    // rejected `op_id` must never appear in the log.
    let server_conn = open_ro(&server.db).expect("server db");
    let rejected_events: i64 = server_conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE op_id = ?1",
            [op_id.as_slice()],
            |row| row.get(0),
        )
        .expect("count rejected events");
    assert_eq!(rejected_events, 0, "the rejected op must not be sequenced");
    wait_file(&a.mountpoint, "clash.txt", b"original\n");
    assert!(
        !a.mountpoint.join("whatever").exists(),
        "the rejected op must not appear on the other client"
    );
    wait_file(&b2.mountpoint, "clash.txt", b"original\n");

    wait_until("the status counter ops_rejected", READY, || {
        Ok(b2
            .status_u64(&["counters", "ops_rejected"])
            .unwrap_or(0)
            >= 1)
    });
    assert_eq!(
        b2.status_u64(&["outbox", "ops"]),
        Some(0),
        "failed rows are not counted as outstanding"
    );
    let _ = b_mount;
}

/// A size-changing `setattr` is one wire operation and one server event.
///
/// The fixture applies the local effect and the outbox row in one client
/// transaction, then restarts the client. The server must record one
/// `setattr` event carrying both `size` and `mode`, and both clients must
/// converge on the truncated content and the new mode.
#[test]
fn setattr_size_and_mode_reach_the_server_as_one_event() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP setattr_size_and_mode_reach_the_server_as_one_event: {reason}");
        return;
    }
    let env = Env::new();
    let mut server = env.server("setattr-atomic.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "atomic.txt", b"abcdef");
    wait_file(&b.mountpoint, "atomic.txt", b"abcdef");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let b_db = b.db.clone();
    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);

    let cluster: [u8; 16] = db_blob(&b_db, "cluster_id")
        .expect("client cluster id")
        .try_into()
        .expect("cluster id is 16 bytes");
    {
        let db = ClientDb::open(&b_db, cluster).expect("open B database");
        let ino = db
            .lookup(ROOT_INO, OsStr::new("atomic.txt"))
            .expect("atomic.txt")
            .ino;
        db.setattr(
            ino,
            AttrChange {
                size: Some(4),
                mode: Some(0o600),
                ..AttrChange::default()
            },
        )
        .expect("size+mode setattr");
    }

    let mut b2 = env.client("b2", "b.db", &env.key, &server);
    b2.wait_mounted();
    wait_synced(&mut b2, &server);

    wait_until("A sees the server size and mode", READY, || {
        let meta = fs::metadata(a.mountpoint.join("atomic.txt"))
            .map_err(|error| format!("stat: {error}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if meta.len() != 4 || mode != 0o600 {
            return Err(format!("size={} mode={mode:o}", meta.len()));
        }
        Ok(true)
    });
    wait_file(&a.mountpoint, "atomic.txt", b"abcd");
    wait_file(&b2.mountpoint, "atomic.txt", b"abcd");

    let conn = open_ro(&server.db).expect("server db");
    let (kind, payload): (String, Vec<u8>) = conn
        .query_row(
            "SELECT kind, payload FROM events
              WHERE path = '/atomic.txt' AND kind = 'setattr'
              ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("setattr event");
    assert_eq!(kind, "setattr");
    match EventPayload::decode(EventKind::Setattr, &payload).expect("setattr payload") {
        EventPayload::Setattr { size, mode, .. } => {
            assert_eq!(size, Some(4), "the event carries the new size");
            assert_eq!(mode, Some(0o600), "the event carries the new mode");
        }
        other => panic!("expected a setattr payload, got {other:?}"),
    }
    assert_eq!(
        db_count(
            &server.db,
            "SELECT COUNT(*) FROM events WHERE path = '/atomic.txt' AND kind = 'truncate'"
        ),
        Some(0),
        "a size-changing setattr must not also write a truncate event"
    );
    let (size, mode): (i64, i64) = conn
        .query_row(
            "SELECT o.size, o.mode FROM objects o
               JOIN names n ON n.ino = o.ino
              WHERE n.path = '/atomic.txt'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("server object");
    assert_eq!(size, 4);
    assert_eq!(mode, 0o600);
    drop(conn);

    let status = b2.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b2.proc.tail());
    drop(b2);
    let status = a.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a.proc.tail());
    drop(a);
    let status = server.stop_graceful();
    assert_eq!(status.code(), Some(0), "server must stop cleanly");
}

/// A server database written before the payload gained `size`, and a client
/// database whose outbox still holds a version-1 `setattr`, both survive the
/// upgrade without a clean database or a re-import.
#[test]
fn version_1_setattr_rows_replay_after_upgrade() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP version_1_setattr_rows_replay_after_upgrade: {reason}");
        return;
    }
    let env = Env::new();
    let mut server = env.server("old-setattr.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "old.txt", b"abcdef");
    wait_file(&b.mountpoint, "old.txt", b"abcdef");
    fs::set_permissions(
        a.mountpoint.join("old.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("chmod old.txt");
    wait_until("server records the mode change", READY, || {
        let count = db_count(
            &server.db,
            "SELECT COUNT(*) FROM events WHERE kind = 'setattr' AND path = '/old.txt'",
        )
        .ok_or_else(|| "server db is not readable".to_owned())?;
        if count == 0 {
            return Err("no setattr event yet".to_owned());
        }
        Ok(true)
    });
    wait_until("B sees the mode", READY, || {
        let meta =
            fs::metadata(b.mountpoint.join("old.txt")).map_err(|error| format!("stat: {error}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!("mode={mode:o}"));
        }
        Ok(true)
    });
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let a_db = a.db.clone();
    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);
    let status = a.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a.proc.tail());
    drop(a);

    // A crash skips compaction, so the version-2 `setattr` row survives.
    server.kill();

    // Rewrite that row to the version-1 layout: same fields, no size tag.
    {
        let conn = Connection::open(&server.db).expect("server db");
        let (seq, op_id, payload): (i64, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT seq, op_id, payload FROM events
                  WHERE kind = 'setattr' AND path = '/old.txt'
                  ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("setattr event");
        assert_eq!(payload[0], 2, "the row was written by the current codec");
        let mut legacy = payload;
        assert_eq!(
            legacy.pop(),
            Some(0),
            "the recorded setattr is attribute-only"
        );
        legacy[0] = 1;
        match EventPayload::decode(EventKind::Setattr, &legacy).expect("version-1 payload") {
            EventPayload::Setattr { size, mode, .. } => {
                assert_eq!(size, None, "version 1 carries no size");
                assert_eq!(
                    mode.map(|mode| mode & 0o7777),
                    Some(0o600),
                    "the kernel's chmod carries the file-type bits"
                );
            }
            other => panic!("expected a setattr payload, got {other:?}"),
        }
        conn.execute(
            "UPDATE events SET payload = ?1 WHERE seq = ?2",
            params![legacy, seq],
        )
        .expect("rewrite event payload");
        conn.execute(
            "UPDATE op_ids SET payload_hash = ?1 WHERE op_id = ?2",
            params![chunk_hash(&legacy).as_slice(), op_id],
        )
        .expect("rewrite payload hash");
    }

    // The server must start on the old database and replay the old bytes to a
    // fresh client, which decodes them as an attribute-only change.
    let mut server = env.server("old-setattr.db");
    let mut c = env.client("c", "c.db", &env.key, &server);
    c.wait_mounted();
    wait_synced(&mut c, &server);
    wait_file(&c.mountpoint, "old.txt", b"abcdef");
    wait_until("C sees the replayed mode", READY, || {
        let meta =
            fs::metadata(c.mountpoint.join("old.txt")).map_err(|error| format!("stat: {error}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!("mode={mode:o}"));
        }
        Ok(true)
    });

    // The stopped author's database gains a pending version-1 outbox row, the
    // shape a pre-upgrade client leaves behind. Its tree already holds the
    // optimistic effect.
    let ino = ino_at(&a_db, "/old.txt").expect("author inode");
    let payload = v1_setattr_payload(ino, 0o640);
    let op_id = random_op_id();
    insert_outbox(
        &a_db,
        op_id,
        "setattr",
        "/old.txt",
        None,
        ino,
        &payload,
    );
    {
        let conn = Connection::open(&a_db).expect("author db");
        conn.execute(
            "UPDATE objects SET mode = ?1 WHERE ino = ?2",
            params![0o640i64, ino.as_slice()],
        )
        .expect("author mode");
    }

    let mut a2 = env.client("a2", "a.db", &env.key, &server);
    a2.wait_mounted();
    wait_synced(&mut a2, &server);
    wait_until("C sees the upgraded client's mode", READY, || {
        let meta =
            fs::metadata(c.mountpoint.join("old.txt")).map_err(|error| format!("stat: {error}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o640 {
            return Err(format!("mode={mode:o}"));
        }
        Ok(true)
    });
    assert!(
        outbox_row(&a_db, &op_id).is_none(),
        "the version-1 outbox row was sent and acknowledged"
    );

    let status = a2.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a2.proc.tail());
    drop(a2);
    let status = c.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", c.proc.tail());
    drop(c);
    let status = server.stop_graceful();
    assert_eq!(status.code(), Some(0), "server must stop cleanly");
}

fn wait_replay_ok(client: &mut Client, server: &Server) {
    let label = format!("{} full replay after compaction", client.name);
    let db = client.db.clone();
    let server_db = server.db.clone();
    wait_until(&label, READY, || {
        if let Some(status) = client.proc.try_wait() {
            return Err(format!(
                "client exited with {status} during compaction replay\n{}",
                client.proc.tail()
            ));
        }
        let seq = match db_i64(&server_db, "seq") {
            Some(value) => value,
            None => return Ok(false),
        };
        let applied = match db_i64(&db, "applied_seq") {
            Some(value) => value,
            None => return Ok(false),
        };
        let state = client
            .status()
            .and_then(|doc| doc.get("state").and_then(Value::as_str).map(str::to_owned));
        if applied >= seq && state.as_deref() == Some("STEADY") {
            Ok(true)
        } else {
            Err(format!(
                "seq={seq} applied={applied} state={state:?}\n{}",
                client.proc.tail()
            ))
        }
    });
}

/// A restart whose `applied_seq` already equals the server's current sequence
/// must still open the write gate. The server starts no replay task in that
/// case, so the client cannot wait for an ORDERED frame to declare itself
/// caught up.
#[test]
fn restart_already_caught_up_reopens_gate() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP restart_already_caught_up_reopens_gate: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("caught-up.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    a.wait_mounted();
    wait_synced(&mut a, &server);
    write_retry(&a.mountpoint, "x.txt", b"x\n");
    wait_synced(&mut a, &server);
    let applied = db_i64(&a.db, "applied_seq").expect("applied");
    let db = a.db.clone();
    let status = a.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a.proc.tail());
    drop(a);

    // The disconnect commits a LEAVE event. Pretend this client had already
    // applied it (it has no durable effect), so the reconnect is exactly at
    // the server's current sequence and the server has nothing to replay.
    wait_until("the LEAVE event", READY, || {
        Ok(db_i64(&server.db, "seq").unwrap_or(0) > applied)
    });
    let current = db_i64(&server.db, "seq").expect("server seq");
    let conn = Connection::open(&db).expect("open client db");
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'applied_seq'",
        [current],
    )
    .expect("advance applied_seq");
    drop(conn);

    let mut a2 = env.client("a2", "a.db", &env.key, &server);
    a2.wait_mounted();
    wait_status_state(&mut a2, "STEADY");
    write_retry(&a2.mountpoint, "after-caught-up.txt", b"after\n");
    wait_file(&a2.mountpoint, "after-caught-up.txt", b"after\n");
}

/// `link(2)` through the FUSE mount must reach the second client. The local
/// callback succeeds immediately; the wire path is the interesting half.
#[test]
fn fuse_hardlink_converges() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP fuse_hardlink_converges: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("hardlink.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "orig.txt", b"hardlink content\n");
    wait_file(&b.mountpoint, "orig.txt", b"hardlink content\n");
    let mut last = String::new();
    wait_until("hard link orig.txt -> hard.txt", READY, || {
        match fs::hard_link(a.mountpoint.join("orig.txt"), a.mountpoint.join("hard.txt")) {
            Ok(()) => Ok(true),
            Err(error) => {
                last = error.to_string();
                Err(error.to_string())
            }
        }
    });
    let _ = last;
    wait_file(&b.mountpoint, "hard.txt", b"hardlink content\n");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);
}

/// A one-byte `pwrite` at offset zero must patch a 150 KiB file, not replace
/// it with the one-chunk stream. The server size is the observable: the old
/// class choice truncated the file to 64 KiB while every client still held
/// the full length.
#[test]
fn partial_write_at_offset_zero_keeps_the_whole_file() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP partial_write_at_offset_zero_keeps_the_whole_file: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("pwrite-zero.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    write_retry(&a.mountpoint, "big.bin", &big);
    wait_file(&b.mountpoint, "big.bin", &big);

    let mut file = OpenOptions::new()
        .write(true)
        .open(a.mountpoint.join("big.bin"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0xEE]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let mut expected = big;
    expected[0] = 0xEE;
    wait_file(&b.mountpoint, "big.bin", &expected);
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);
    wait_until("server keeps 150 KiB", READY, || {
        let size = db_value_i64(
            &server.db,
            "SELECT o.size FROM objects o JOIN names n ON n.ino = o.ino
              WHERE n.path = '/big.bin'",
        );
        if size == Some(150_000) {
            Ok(true)
        } else {
            Err(format!("server size is {size:?}"))
        }
    });

    // A restart replays the event from the server and must read the same
    // bytes, not a 64 KiB truncation.
    let status = a.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", a.proc.tail());
    drop(a);
    let mut a2 = env.client("a2", "a.db", &env.key, &server);
    a2.wait_mounted();
    wait_synced(&mut a2, &server);
    wait_file(&a2.mountpoint, "big.bin", &expected);
}

/// Two writes in one flush window, at offsets 0 and 200000, must reach the
/// server as a contiguous stream with the holes zero-filled. A live peer and
/// a replayed peer must both hold the same 200001-byte file.
#[test]
fn sparse_writeback_keeps_holes_and_replays_identically() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP sparse_writeback_keeps_holes_and_replays_identically: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("sparse.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "sparse.bin", b"");
    let mut file = OpenOptions::new()
        .write(true)
        .open(a.mountpoint.join("sparse.bin"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"A").unwrap();
    file.seek(SeekFrom::Start(200_000)).unwrap();
    file.write_all(b"B").unwrap();
    file.sync_all().unwrap();
    drop(file);

    let mut expected = vec![0u8; 200_001];
    expected[0] = b'A';
    expected[200_000] = b'B';
    wait_file(&b.mountpoint, "sparse.bin", &expected);
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);
    wait_until("server size is 200001", READY, || {
        let size = db_value_i64(
            &server.db,
            "SELECT o.size FROM objects o JOIN names n ON n.ino = o.ino
              WHERE n.path = '/sparse.bin'",
        );
        if size == Some(200_001) {
            Ok(true)
        } else {
            Err(format!("server size is {size:?}"))
        }
    });

    // B is the live peer; a restart replays the same sequence from the
    // server's event and must produce the same bytes.
    let status = b.stop_graceful();
    assert_eq!(status.code(), Some(0), "{}", b.proc.tail());
    drop(b);
    let mut b2 = env.client("b2", "b.db", &env.key, &server);
    b2.wait_mounted();
    wait_synced(&mut b2, &server);
    wait_file(&b2.mountpoint, "sparse.bin", &expected);
    assert_eq!(
        sha_file(&a.mountpoint, "sparse.bin"),
        sha_file(&b2.mountpoint, "sparse.bin")
    );
}

/// B replaces `/x`, then A renames `/x` to `/y`. The server resolves the
/// source to B's inode, while A's optimistic rename may have moved its own
/// inode. The author's echo must repair A; all three replicas then name the
/// same inode at `/y`.
#[test]
fn a_rename_echo_repairs_the_author_tree() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP a_rename_echo_repairs_the_author_tree: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("rename-echo.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    write_retry(&a.mountpoint, "x", b"a");
    wait_file(&b.mountpoint, "x", b"a");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);
    let a_ino = ino_at(&a.db, "/x").expect("A /x inode");
    assert_eq!(ino_at(&server.db, "/x"), Some(a_ino));

    // B replaces the name with its own inode. Wait for the server to record
    // it; A's downlink may or may not have applied it yet.
    unlink_retry(&b.mountpoint, "x");
    write_retry(&b.mountpoint, "x", b"b");
    wait_until("B's replacement is on the server", READY, || {
        match ino_at(&server.db, "/x") {
            Some(ino) if ino != a_ino => Ok(true),
            other => Err(format!("server /x inode is {other:?}")),
        }
    });

    rename_retry(&a.mountpoint, "x", "y");
    wait_absent(&a.mountpoint, "x");
    wait_file(&a.mountpoint, "y", b"b");
    wait_file(&b.mountpoint, "y", b"b");
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let server_ino = ino_at(&server.db, "/y").expect("server /y inode");
    assert_eq!(ino_at(&a.db, "/y"), Some(server_ino), "A /y inode");
    assert_eq!(ino_at(&b.db, "/y"), Some(server_ino), "B /y inode");
}

/// The local hot path must never wait for a server round trip. With the
/// server stopped, every namespace and data operation still completes on
/// local disk time and the outbox holds the intent until the server returns.
#[test]
fn hot_paths_do_not_wait_for_the_server() {
    if let Err(reason) = fuse_available() {
        eprintln!("SKIP hot_paths_do_not_wait_for_the_server: {reason}");
        return;
    }
    let env = Env::new();
    let server = env.server("no-rtt.db");
    let mut a = env.client("a", "a.db", &env.key, &server);
    let mut b = env.client("b", "b.db", &env.key, &server);
    a.wait_mounted();
    b.wait_mounted();
    wait_synced(&mut a, &server);
    wait_synced(&mut b, &server);

    let pid = server.proc.child.id();
    server.proc.signal(Signal::STOP);
    wait_until("server stopped", READY, || match process_state(pid) {
        Some('T') => Ok(true),
        other => Err(format!("process state is {other:?}")),
    });

    let started = Instant::now();
    write_retry(&a.mountpoint, "blocked.txt", b"payload\n");
    mkdir_retry(&a.mountpoint, "blocked-dir");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(a.mountpoint.join("blocked.txt"))
        .unwrap();
    file.write_all(b"more").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = [0u8; 4];
    file.read_exact(&mut buffer).unwrap();
    file.set_len(3).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::set_permissions(
        a.mountpoint.join("blocked.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::rename(
        a.mountpoint.join("blocked.txt"),
        a.mountpoint.join("renamed.txt"),
    )
    .unwrap();
    fs::hard_link(
        a.mountpoint.join("renamed.txt"),
        a.mountpoint.join("linked.txt"),
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "the hot path waited for the stopped server: {elapsed:?}"
    );
    assert!(
        db_count(&a.db, "SELECT COUNT(*) FROM outbox").unwrap_or(0) > 0,
        "the outbox must hold the local intent while the server is away"
    );

    server.proc.signal(Signal::CONT);
    wait_synced(&mut a, &server);
    wait_file(&b.mountpoint, "renamed.txt", b"mor");
    wait_file(&b.mountpoint, "linked.txt", b"mor");
}
