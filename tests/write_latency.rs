//! Ignored real-mount write-latency benchmark: one server, one client, a real
//! FUSE mount, and one deterministic 21 MiB file.
//!
//! Measures each write syscall for 200 × 4 KiB then 20 × 1 MiB at increasing
//! offsets, with one `fsync` after each batch and none in between. Prints
//! p50/p99/max in microseconds, verifies sampled ranges after the final
//! fsync, and leaves no mount behind.
//!
//! Run explicitly; normal `cargo test` skips it:
//! `cargo test --test write_latency -- --ignored --nocapture`
//!
//! `SYNCMOUNT_PERF_ASSERT=1` turns the baseline thresholds into assertions;
//! `SYNCMOUNT_REQUIRE_FUSE=1` turns a missing FUSE stack into a failure.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

const PSK: &[u8] = b"write-latency-master-psk";
const BIN: &str = env!("CARGO_BIN_EXE_syncmount");
const POLL: Duration = Duration::from_millis(50);
const READY: Duration = Duration::from_secs(30);
/// A graceful server stop can take the full 30 s drain budget.
const SERVER_STOP: Duration = Duration::from_secs(45);
/// The benchmark leaves about 21 MiB in the outbox; allow time to drain.
const CLIENT_STOP: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/// One isolated cluster: temp directory, key file, runtime directory.
struct Env {
    dir: TempDir,
    key: PathBuf,
    run_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("master.key");
        write_key_file(&key, PSK);
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
        Server { proc, port }
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
        Client { proc, mountpoint }
    }
}

/// A child process with a captured log.
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

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    fn kill_wait(&mut self) {
        self.signal(Signal::KILL);
        let _ = self.child.wait();
    }

    /// Wait for exit, killing and panicking when the deadline expires.
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
    port: u16,
}

struct Client {
    proc: Proc,
    mountpoint: PathBuf,
}

impl Client {
    /// Wait until the kernel has this mountpoint in `/proc/mounts`.
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
        // The client normally unmounts itself; this only cleans up after a
        // panic or a SIGKILL. `-z` is lazy, so it never blocks on a busy mount.
        nudge(&self.mountpoint);
    }
}

/// Lazy unmount. `-z` never blocks on a busy mount.
fn nudge(mountpoint: &Path) {
    let _ = Command::new("fusermount3")
        .arg("-u")
        .arg("-z")
        .arg(mountpoint)
        .status();
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

/// Errors the FUSE client reports while the write gate is not open yet.
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

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

/// Byte `offset` of the deterministic pattern is `offset % 251`.
fn pattern(offset: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((offset + i as u64) % 251) as u8)
        .collect()
}

/// Nearest-rank percentile on an ascending slice.
fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    let n = sorted.len();
    let rank = (pct * n).div_ceil(100);
    sorted[rank.saturating_sub(1).min(n - 1)]
}

/// Print one summary line and return p50.
fn report(label: &str, samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    let p50 = percentile(samples, 50);
    let p99 = percentile(samples, 99);
    let max = *samples.last().expect("at least one sample");
    println!(
        "{label} n={} p50_us={} p99_us={} max_us={}",
        samples.len(),
        p50.as_micros(),
        p99.as_micros(),
        max.as_micros()
    );
    p50
}

/// Open the benchmark file, retrying while the client is still JOINING.
fn open_bench_file(path: &Path) -> File {
    let deadline = Instant::now() + READY;
    loop {
        match OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(path)
        {
            Ok(file) => return file,
            Err(error) if retryable(&error) && Instant::now() < deadline => {
                thread::sleep(POLL);
            }
            Err(error) => panic!("cannot open {}: {error}", path.display()),
        }
    }
}

/// One measured `write_all`, retried on gate-closed errors. Only the
/// successful syscall is timed; a retry rewinds to `offset` first, and the
/// deterministic pattern makes the rewrite idempotent.
fn write_measured(file: &mut File, offset: u64, buf: &[u8]) -> Duration {
    let mut retries = 0u32;
    loop {
        let start = Instant::now();
        match file.write_all(buf) {
            Ok(()) => {
                if retries > 0 {
                    eprintln!("write at offset {offset} succeeded after {retries} retries");
                }
                return start.elapsed();
            }
            Err(error) if retryable(&error) && retries < 100 => {
                retries += 1;
                file.seek(SeekFrom::Start(offset))
                    .expect("rewind after retryable write");
                thread::sleep(POLL);
            }
            Err(error) => panic!("write at offset {offset} failed: {error}"),
        }
    }
}

fn timed_sync(file: &mut File) -> Duration {
    let start = Instant::now();
    file.sync_all().expect("fsync benchmark file");
    start.elapsed()
}

#[test]
#[ignore = "real-mount write-latency benchmark; run with --ignored --nocapture"]
fn write_latency_real_mount() {
    if let Err(reason) = fuse_available() {
        if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
            panic!("FUSE is required but unavailable: {reason}");
        }
        eprintln!("SKIP write_latency_real_mount: {reason}");
        return;
    }

    let env = Env::new();
    let mut server = env.server("server.db");
    let mut client = env.client("bench", "client.db", &server);
    client.wait_mounted();

    let path = client.mountpoint.join("latency.bin");
    let mut file = open_bench_file(&path);

    const SMALL_LEN: usize = 4096;
    const SMALL_N: usize = 200;
    const LARGE_LEN: usize = 1 << 20;
    const LARGE_N: usize = 20;

    let mut offset = 0u64;
    let mut small = Vec::with_capacity(SMALL_N);
    for _ in 0..SMALL_N {
        let buf = pattern(offset, SMALL_LEN);
        small.push(write_measured(&mut file, offset, &buf));
        offset += SMALL_LEN as u64;
    }
    let small_fsync = timed_sync(&mut file);

    let mut large = Vec::with_capacity(LARGE_N);
    for _ in 0..LARGE_N {
        let buf = pattern(offset, LARGE_LEN);
        large.push(write_measured(&mut file, offset, &buf));
        offset += LARGE_LEN as u64;
    }
    let large_fsync = timed_sync(&mut file);

    drop(file);
    let size = fs::metadata(&path).expect("benchmark metadata").len();
    println!("fsync_4k_us={}", small_fsync.as_micros());
    println!("fsync_1m_us={}", large_fsync.as_micros());
    println!("file_size_bytes={size} expected_bytes={offset}");

    let p50_small = report("4k", &mut small);
    let p50_large = report("1m", &mut large);

    // Verify the deterministic content at the start, middle, and end.
    let mut readback = File::open(&path).expect("reopen benchmark file");
    let middle = (offset / 2 / SMALL_LEN as u64) * SMALL_LEN as u64;
    let last = offset - SMALL_LEN as u64;
    for sample in [0, middle, last] {
        let mut got = vec![0u8; SMALL_LEN];
        readback.seek(SeekFrom::Start(sample)).expect("seek sample");
        readback.read_exact(&mut got).expect("read sample");
        assert_eq!(
            got,
            pattern(sample, SMALL_LEN),
            "content mismatch at offset {sample}"
        );
    }
    println!("verified samples at offsets 0, {middle}, {last}");
    assert_eq!(size, offset, "final file size must match the written bytes");

    if std::env::var("SYNCMOUNT_PERF_ASSERT").as_deref() == Ok("1") {
        assert!(
            p50_small < Duration::from_micros(1000),
            "4KiB p50 {} us >= 1000 us",
            p50_small.as_micros()
        );
        assert!(
            p50_large < Duration::from_micros(10_000),
            "1MiB p50 {} us >= 10000 us",
            p50_large.as_micros()
        );
    }

    // Stop the client first so the mount is released, then drain the server.
    // Both waits are bounded; the tempdir drops last.
    let status = client.stop_graceful();
    assert_eq!(
        status.code(),
        Some(0),
        "client must stop cleanly\n{}",
        client.proc.tail()
    );
    let mountpoint = client.mountpoint.clone();
    drop(client);
    wait_until("benchmark mount unmounted", READY, || {
        if is_mounted(&mountpoint) {
            Err(format!("{} is still in /proc/mounts", mountpoint.display()))
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
    drop(server);
}
