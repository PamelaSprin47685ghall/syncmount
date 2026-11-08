//! Shared fixture for 1.1 `--mmap` tests.
//!
//! Every test gets one [`TempDir`] with an isolated layout:
//!
//! ```text
//! $T/
//!   master.key             32 random bytes, mode 0600
//!   run/                   SYNCMOUNT_RUN_DIR
//!   state-<client>/        SYNCMOUNT_STATE_DIR (client.db + shadow)
//!   mnt-<client>/          mountpoint
//!   server-*.db            explicit server databases
//!   logs/
//! ```
//!
//! The harness never guesses a server namespace: callers pass the canonical
//! namespace (`/private-mm`, `/public-mm`, `/private`), and the URL path is
//! the namespace. Server databases are always explicit so two namespaces can
//! never collide on the 1.0 default file name.
//!
//! # Status
//!
//! Real mounting tests wait for `/proc/mounts`, then for the client's
//! `status.json` lifecycle state to become `STEADY`. Both waits are bounded
//! polls; there are no fixed sleeps for correctness.
//!
//! # Shadow
//!
//! The 1.1 client has not landed a shadow flag yet. [`MmapEnv::shadow_dir`]
//! returns `state-<client>/shadow`, the layout the design assumes. If the
//! implementation exposes `--shadow-dir`, change this one function.
//!
//! # Scope
//!
//! This module is test infrastructure only. It does not reimplement checkout,
//! checkin, rsync or locking; library-level tests call the real
//! `syncmount::mmap` modules, and process-level tests spawn the real binary.

#![allow(dead_code)]
#![allow(missing_debug_implementations)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use serde_json::Value;
use tempfile::TempDir;

use syncmount::client::config::mount_id_for;
use syncmount::mmap::{MmDb, MmRole};

/// The binary Cargo built for this test target.
pub const BIN: &str = env!("CARGO_BIN_EXE_syncmount");
/// Poll interval for every wait.
pub const POLL: Duration = Duration::from_millis(50);
/// Deadline for ordinary convergence.
pub const READY: Duration = Duration::from_secs(30);
/// Deadline for a graceful server stop (drain is 30 s).
pub const SERVER_STOP: Duration = Duration::from_secs(45);
/// Deadline for a client process to exit after SIGTERM.
pub const CLIENT_STOP: Duration = Duration::from_secs(15);
/// Linux SIGKILL number, used to assert a real signal death.
pub const SIGKILL: i32 = 9;

/// One isolated cluster: temp directory, key file, runtime directory, logs.
pub struct MmapEnv {
    dir: TempDir,
    key: PathBuf,
    run_dir: PathBuf,
    logs: PathBuf,
    serial: AtomicUsize,
    ports: Mutex<Vec<(String, u16)>>,
}

impl Default for MmapEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapEnv {
    /// Create the layout and a fresh 32-byte key file.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("master.key");
        let mut secret = rand::random::<[u8; 32]>();
        while secret == [0; 32] {
            secret = rand::random::<[u8; 32]>();
        }
        // `parse_mm_key` trims ASCII whitespace, so a raw 32-byte key whose
        // first or last byte happens to be whitespace is rejected. The
        // hexadecimal spelling is stable and has no whitespace.
        fs::write(&key, hex::encode(secret)).expect("write master key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");

        let run_dir = dir.path().join("run");
        let logs = dir.path().join("logs");
        fs::create_dir_all(&run_dir).expect("run dir");
        fs::create_dir_all(&logs).expect("logs dir");
        Self {
            dir,
            key,
            run_dir,
            logs,
            serial: AtomicUsize::new(0),
            ports: Mutex::new(Vec::new()),
        }
    }

    /// One path directly under the temp root.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The 0600 master key file.
    pub fn key_path(&self) -> &Path {
        &self.key
    }

    /// `SYNCMOUNT_RUN_DIR` for every client.
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// Captured process logs.
    pub fn logs_dir(&self) -> &Path {
        &self.logs
    }

    /// `SYNCMOUNT_STATE_DIR` for one client.
    pub fn state_dir(&self, name: &str) -> PathBuf {
        self.path(&format!("state-{name}"))
    }

    /// Provisional shadow root for one client (see module docs).
    pub fn shadow_dir(&self, name: &str) -> PathBuf {
        self.state_dir(name).join("shadow")
    }

    /// Mountpoint for one client.
    pub fn mount_dir(&self, name: &str) -> PathBuf {
        self.path(&format!("mnt-{name}"))
    }

    /// Open an mm database under the temp root.
    pub fn mm_db(&self, role: MmRole, namespace: &str, db_name: &str) -> MmDb {
        MmDb::open(self.path(db_name), role, namespace).expect("open mm database")
    }

    /// Start a server for one namespace and wait until its port accepts.
    ///
    /// The URL path is the namespace and the database is always explicit.
    pub fn server(&self, namespace: &str, db_name: &str) -> Server {
        let n = self.serial.fetch_add(1, Ordering::Relaxed);
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let db = self.path(db_name);
        let spool = self.path(&format!("spool-{n}"));
        fs::create_dir_all(&spool).expect("spool dir");
        let log = self.logs.join(format!("server-{n}.log"));
        let url = format!("http://{addr}{namespace}");

        let mut cmd = Command::new(BIN);
        cmd.arg("--log-format")
            .arg("json")
            .arg("--log-level")
            .arg("info")
            .arg("mm-server")
            .arg(&url)
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--db")
            .arg(&db)
            .arg("--spool-dir")
            .arg(&spool)
            .arg("--key-file")
            .arg(&self.key);
        clean_env(&mut cmd);

        let mut proc = Proc::spawn(&mut cmd, log, format!("server {namespace}"));
        let deadline = Instant::now() + READY;
        loop {
            if let Some(status) = proc.try_wait() {
                panic!("server exited before listening: {status}\n{}", proc.tail());
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

        self.record_port(namespace, port);
        Server {
            proc,
            db,
            port,
            namespace: namespace.to_owned(),
            url,
        }
    }

    /// Start an mm client against the most recent server for `namespace`.
    ///
    /// `mmap` is retained for call-site compatibility; every process-level
    /// test in this suite uses the 1.1 mm client. Passing `false` is a test
    /// bug, not a 1.0 mode switch.
    pub fn client(&self, namespace: &str, name: &str, mmap: bool) -> Client {
        let port = self.last_port(namespace);
        self.client_at(namespace, name, mmap, port)
    }

    /// Start a client against an explicit TCP port.
    ///
    /// This is how a test puts [`CountingProxy`] between one client and the
    /// server while other clients keep dialing the server directly.
    pub fn client_at(&self, namespace: &str, name: &str, mmap: bool, port: u16) -> Client {
        assert!(mmap, "MmapEnv only starts the 1.1 mm-client");
        let n = self.serial.fetch_add(1, Ordering::Relaxed);
        let state_dir = self.state_dir(name);
        let mountpoint = self.mount_dir(name);
        let shadow = self.shadow_dir(name);
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::create_dir_all(&shadow).expect("shadow dir");
        fs::create_dir_all(&mountpoint).expect("mountpoint");
        let db = shadow
            .join("mm")
            .join(namespace.trim_start_matches('/'))
            .join("shadow.db");
        let log = self.logs.join(format!("client-{name}-{n}.log"));
        let url = format!("http://127.0.0.1:{port}{namespace}");
        let mount_id = mount_id_for(&mountpoint);

        let mut cmd = Command::new(BIN);
        cmd.arg("--log-format")
            .arg("json")
            .arg("--log-level")
            .arg("info")
            .arg("mm-client")
            .arg(&url)
            .arg(&mountpoint)
            .arg("--shadow-dir")
            .arg(&shadow)
            .arg("--key-file")
            .arg(&self.key);
        clean_env(&mut cmd);

        let proc = Proc::spawn(&mut cmd, log, format!("client {name}"));
        Client {
            proc,
            mountpoint,
            db,
            state_dir,
            run_dir: self.run_dir.clone(),
            mount_id,
            name: name.to_owned(),
        }
    }

    /// Port of the most recently started server for `namespace`.
    ///
    /// The harness keeps one server per namespace in ordinary tests; this
    /// helper also covers the two-server isolation layout by remembering the
    /// last start.
    fn last_port(&self, namespace: &str) -> u16 {
        self.ports
            .lock()
            .expect("server ports")
            .iter()
            .rev()
            .find(|(name, _)| name == namespace)
            .map(|(_, port)| *port)
            .expect("client needs a server for its namespace")
    }

    /// A byte-counting TCP proxy in front of `upstream`.
    pub fn proxy(&self, upstream: u16) -> CountingProxy {
        CountingProxy::start(upstream)
    }
}

/// Server ports by namespace, so `client` finds the matching listener.
///
/// Kept out of [`MmapEnv`]'s public API; tests that need an explicit port use
/// [`Server::port`].
impl MmapEnv {
    fn record_port(&self, namespace: &str, port: u16) {
        self.ports
            .lock()
            .expect("server ports")
            .push((namespace.to_owned(), port));
    }
}

/// A child process with a captured log.
pub struct Proc {
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

/// One server process and its explicit database.
pub struct Server {
    proc: Proc,
    /// Port the server listens on.
    pub port: u16,
    /// The database file passed to `--db`.
    pub db: PathBuf,
    /// URL namespace.
    pub namespace: String,
    /// Full endpoint URL.
    pub url: String,
}

impl Server {
    /// `SIGTERM` and wait for the drain to finish.
    pub fn stop_graceful(&mut self) -> ExitStatus {
        self.proc.signal(Signal::TERM);
        self.proc.wait_exit(SERVER_STOP)
    }

    /// `SIGKILL` and assert the process died by signal 9.
    pub fn kill9(&mut self) -> ExitStatus {
        self.proc.signal(Signal::KILL);
        let status = self.proc.wait_exit(Duration::from_secs(10));
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(SIGKILL),
            "server {} did not die by SIGKILL",
            self.namespace
        );
        status
    }

    /// Wait for exit with a deadline.
    pub fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        self.proc.wait_exit(timeout)
    }

    /// Last 80 log lines.
    pub fn tail(&self) -> String {
        self.proc.tail()
    }

    /// True when the captured log contains `needle`.
    pub fn log_contains(&self, needle: &str) -> bool {
        self.proc.log_contains(needle)
    }
}

/// One client process, its mountpoint, database and state root.
pub struct Client {
    proc: Proc,
    /// Mountpoint passed to the client.
    pub mountpoint: PathBuf,
    /// Client database (`--db`).
    pub db: PathBuf,
    /// `SYNCMOUNT_STATE_DIR`.
    pub state_dir: PathBuf,
    run_dir: PathBuf,
    /// Stable mount id used by `/run/syncmount/<mount_id>/status.json`.
    pub mount_id: String,
    /// Test-local client name.
    pub name: String,
}

impl Client {
    /// Wait until `/proc/mounts` contains the mountpoint.
    pub fn wait_mounted(&mut self) {
        let label = format!("{} mounted", self.name);
        wait_until(&label, READY, || {
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

    /// Wait for the optional lifecycle document to reach `STEADY`.
    ///
    /// The 1.1 `mm-client` does not publish the 1.0 `status.json`; mount
    /// readiness is its only readiness signal. If a status document is
    /// absent, this method is a no-op after [`Self::wait_mounted`]. If one
    /// exists, it must reach `STEADY`.
    pub fn wait_steady(&mut self) {
        if self.status().is_none() {
            return;
        }
        let label = format!("{} steady", self.name);
        wait_until(&label, READY, || {
            if let Some(status) = self.proc.try_wait() {
                return Err(format!("client exited with {status}\n{}", self.proc.tail()));
            }
            match self.status() {
                Some(doc) if doc.get("state").and_then(Value::as_str) == Some("STEADY") => Ok(true),
                Some(doc) => Err(format!("client state is {doc}")),
                None => Err("status.json is not readable yet".to_owned()),
            }
        });
    }

    /// Current `status.json`, if it exists and parses.
    pub fn status(&self) -> Option<Value> {
        let path = self.run_dir.join(&self.mount_id).join("status.json");
        let bytes = fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// One numeric field from `status.json`.
    pub fn status_u64(&self, path: &[&str]) -> Option<u64> {
        let doc = self.status()?;
        let mut current = &doc;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_u64()
    }

    /// `SIGTERM` plus the lazy-unmount nudge fuser 0.18 needs.
    pub fn stop_graceful(&mut self) -> ExitStatus {
        self.proc.signal(Signal::TERM);
        self.wait_exit_unmounting(CLIENT_STOP)
    }

    /// `SIGKILL` and assert the process died by signal 9.
    pub fn kill9(&mut self) -> ExitStatus {
        self.proc.signal(Signal::KILL);
        let status = self.proc.wait_exit(Duration::from_secs(10));
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(SIGKILL),
            "client {} did not die by SIGKILL",
            self.name
        );
        status
    }

    /// The provisional shadow root for this client.
    pub fn shadow(&self) -> PathBuf {
        self.state_dir.join("shadow")
    }

    /// Last 80 log lines.
    pub fn tail(&self) -> String {
        self.proc.tail()
    }

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

/// A TCP proxy that counts both directions and can cut live connections.
pub struct CountingProxy {
    /// Local port clients connect to.
    pub port: u16,
    streams: Arc<Mutex<Vec<TcpStream>>>,
    client_to_server: Arc<AtomicU64>,
    server_to_client: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
}

impl CountingProxy {
    /// Start forwarding to `upstream` on a fresh localhost port.
    pub fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("proxy bind");
        listener.set_nonblocking(true).expect("proxy nonblocking");
        let port = listener.local_addr().expect("proxy addr").port();
        let streams = Arc::new(Mutex::new(Vec::new()));
        let client_to_server = Arc::new(AtomicU64::new(0));
        let server_to_client = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let accepted = Arc::clone(&streams);
        let outbound = Arc::clone(&client_to_server);
        let inbound = Arc::clone(&server_to_client);
        let running = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let Ok(server) = TcpStream::connect(("127.0.0.1", upstream)) else {
                            continue;
                        };
                        let _ = client.set_nodelay(true);
                        let _ = server.set_nodelay(true);
                        accepted.lock().expect("proxy streams").extend([
                            client.try_clone().expect("client clone"),
                            server.try_clone().expect("server clone"),
                        ]);
                        let (mut from, mut to) = (
                            client.try_clone().expect("client"),
                            server.try_clone().expect("server"),
                        );
                        let count = Arc::clone(&outbound);
                        thread::spawn(move || {
                            let _ = copy_counted(&mut from, &mut to, &count);
                        });
                        let (mut from, mut to) = (server, client);
                        let count = Arc::clone(&inbound);
                        thread::spawn(move || {
                            let _ = copy_counted(&mut from, &mut to, &count);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            streams,
            client_to_server,
            server_to_client,
            stop,
            listener: Some(handle),
        }
    }

    /// `(client -> server, server -> client)` bytes.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.client_to_server.load(Ordering::Relaxed),
            self.server_to_client.load(Ordering::Relaxed),
        )
    }

    /// Close every live socket; the listener stays up so reconnect succeeds.
    pub fn cut(&self) {
        for stream in self.streams.lock().expect("proxy streams").drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.cut();
        if let Some(handle) = self.listener.take() {
            let _ = handle.join();
        }
    }
}

fn copy_counted(from: &mut TcpStream, to: &mut TcpStream, count: &AtomicU64) -> io::Result<u64> {
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = from.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        to.write_all(&buffer[..read])?;
        total += read as u64;
        count.fetch_add(read as u64, Ordering::Relaxed);
    }
}

/// One file-system entry captured for byte-level tree comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPrint {
    pub kind: &'static str,
    pub mode: u32,
    pub size: u64,
    pub hash: [u8; 32],
}

/// Recursively hash and describe a tree.
///
/// Paths are relative to `root` and use `/` separators; the root itself is
/// not an entry. Symlinks are hashed by target bytes, directories by a fixed
/// empty digest, because a directory's own bytes are its children.
pub fn tree_manifest(root: &Path) -> BTreeMap<String, EntryPrint> {
    let mut out = BTreeMap::new();
    walk(root, Path::new(""), &mut out);
    out
}

fn walk(root: &Path, relative: &Path, out: &mut BTreeMap<String, EntryPrint>) {
    let dir = root.join(relative);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) => panic!("read_dir {}: {error}", dir.display()),
    };
    for entry in entries {
        let entry = entry.expect("dir entry");
        let child = relative.join(entry.file_name());
        let key = child.to_string_lossy().replace('\\', "/");
        let metadata = fs::symlink_metadata(entry.path()).expect("symlink_metadata");
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).expect("readlink");
            let bytes = target.to_string_lossy().into_owned().into_bytes();
            out.insert(
                key,
                EntryPrint {
                    kind: "symlink",
                    mode,
                    size: bytes.len() as u64,
                    hash: blake3_bytes(&bytes),
                },
            );
        } else if metadata.is_dir() {
            out.insert(
                key,
                EntryPrint {
                    kind: "dir",
                    mode,
                    size: 0,
                    hash: blake3_bytes(b"dir"),
                },
            );
            walk(root, &child, out);
        } else if metadata.is_file() {
            out.insert(
                key,
                EntryPrint {
                    kind: "file",
                    mode,
                    size: metadata.len(),
                    hash: blake3_file(&entry.path()),
                },
            );
        } else {
            out.insert(
                key,
                EntryPrint {
                    kind: "other",
                    mode,
                    size: metadata.len(),
                    hash: [0; 32],
                },
            );
        }
    }
}

/// Stream one file through BLAKE3.
pub fn blake3_file(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).expect("open for hashing");
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read for hashing");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    *hasher.finalize().as_bytes()
}

fn blake3_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Compare two trees entry by entry and panic with the first differences.
pub fn assert_trees_equal(left: &Path, right: &Path) {
    let left_map = tree_manifest(left);
    let right_map = tree_manifest(right);
    let missing: Vec<_> = left_map
        .keys()
        .filter(|key| !right_map.contains_key(*key))
        .collect();
    let extra: Vec<_> = right_map
        .keys()
        .filter(|key| !left_map.contains_key(*key))
        .collect();
    let changed: Vec<_> = left_map
        .iter()
        .filter(|(key, value)| right_map.get(*key).is_some_and(|other| other != *value))
        .map(|(key, _)| key)
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty() && changed.is_empty(),
        "trees differ\nmissing in right: {missing:?}\nextra in right: {extra:?}\nchanged: {changed:?}\nleft: {left_map:#?}\nright: {right_map:#?}"
    );
}

/// True when `/proc/mounts` contains the mountpoint.
pub fn is_mounted(mountpoint: &Path) -> bool {
    let needle = mountpoint.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|mounts| {
            mounts
                .lines()
                .any(|line| line.split_whitespace().nth(1) == Some(needle.as_ref()))
        })
        .unwrap_or(false)
}

/// Probe `/dev/fuse` and `fusermount3`.
pub fn fuse_probe() -> Result<(), String> {
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

/// Probe FUSE, turning a missing capability into a panic when required.
pub fn fuse_available() -> Result<(), String> {
    let probe = fuse_probe();
    if probe.is_err() && std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
        panic!("FUSE is required but unavailable: {:?}", probe);
    }
    probe
}

/// Print a SKIP line and return true when FUSE cannot run here.
pub fn skip_without_fuse(test: &str) -> bool {
    match fuse_available() {
        Ok(()) => false,
        Err(reason) => {
            eprintln!("SKIP {test}: {reason}");
            true
        }
    }
}

/// Bounded polling helper shared by the process-level tests.
pub fn wait_until<F>(what: &str, timeout: Duration, mut check: F)
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
            panic!("timed out waiting for {what}: {last}");
        }
        thread::sleep(POLL);
    }
}

fn clean_env(cmd: &mut Command) {
    for key in [
        "SYNCMOUNT_LISTEN",
        "SYNCMOUNT_SERVER_DB",
        "SYNCMOUNT_MM_LISTEN",
        "SYNCMOUNT_MM_DB",
        "SYNCMOUNT_MM_SPOOL",
        "SYNCMOUNT_MM_KEY",
        "SYNCMOUNT_MASTER_PASSWORD",
        "SYNCMOUNT_MASTER_PASSWORD_FILE",
        "SYNCMOUNT_DB",
        "SYNCMOUNT_STATE_DIR",
        "SYNCMOUNT_RUN_DIR",
        "SYNCMOUNT_TEST_FAILPOINT",
        "SYNCMOUNT_TEST_UPLOAD_LOCK_TTL_MS",
        "SYNCMOUNT_TEST_CHECKIN_DELAY_MS",
        "SYNCMOUNT_TEST_DISABLE_BACKOFF",
        "SYNCMOUNT_TEST_PAUSE_CHECKIN",
        "SYNCMOUNT_TEST_CORRUPT_DELTA",
        "SYNCMOUNT_REQUIRE_MMAP",
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
