//! Fault-injection tests for the 1.1 `--mmap` path.
//!
//! These tests kill real client and server processes and cut a counting proxy.
//! They are ignored until `src/mmap/{server,client,shadow}` lands; running them
//! earlier is expected to fail.
//!
//! Run with:
//!
//! ```text
//! cargo test --test chaos_mmap -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serial_test::serial;

use mmap_harness::{
    MmapEnv, assert_trees_equal, blake3_file, skip_without_fuse, tree_manifest, wait_until,
};
use rusqlite::Connection;
use syncmount::mmap::now_ms;

/// Deadline for ordinary convergence.
const READY: Duration = Duration::from_secs(30);

/// Deterministic bytes, so a failure shows the same payload every run.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 32) as u8);
    }
    out
}

/// Write `bytes` below `root`, creating parent directories.
fn write_at(root: &Path, relative: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, bytes).unwrap();
    path
}

/// `fsync(2)` a path through the mount; this is the client's checkin point.
fn fsync_path(path: &Path) {
    let deadline = Instant::now() + READY;
    loop {
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all());
        match result {
            Ok(()) => return,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("fsync {} failed: {error}", path.display()),
        }
    }
}

/// `fsync(2)` a directory, which commits its structural entries (mkdir).
fn fsync_dir(path: &Path) {
    let deadline = Instant::now() + READY;
    loop {
        let result = OpenOptions::new()
            .read(true)
            .open(path)
            .and_then(|file| file.sync_all());
        match result {
            Ok(()) => return,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("fsync {} failed: {error}", path.display()),
        }
    }
}

/// Move every upload lease past its deadline in the live server database.
fn expire_all_locks(db: &Path) {
    let conn = Connection::open(db).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.execute("UPDATE mm_locks SET expires_at_ms = ?1", [now_ms() - 1])
        .unwrap();
}

fn lock_count(db: &Path) -> i64 {
    let conn = Connection::open(db).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.query_row("SELECT COUNT(*) FROM mm_locks", [], |row| row.get(0))
        .unwrap()
}

#[test]
#[serial]
fn crash_uploads_then_recovers_without_half_batch() {
    if skip_without_fuse("crash_uploads_then_recovers_without_half_batch") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "chaos-crash");
    let mut a = env.client("/private-mm", "crash-a", true);
    a.wait_mounted();
    a.wait_steady();

    let payload = pattern(8 << 20, 0x0bad_c0de);
    let expected = env.run_dir().join("crash-expected.bin");
    fs::write(&expected, &payload).unwrap();
    let expected_hash = blake3_file(&expected);
    let relative = "crash/big.bin";
    let path = write_at(&a.mountpoint, relative, &payload);
    fsync_dir(&a.mountpoint);
    let baseline = a.status_u64(&["applied_seq"]);

    // Kill the client while the explicit checkin is in flight. The 8 MiB
    // write makes the window wide enough for the signal to land inside it.
    let sync_path = path.clone();
    let syncer = thread::spawn(move || -> std::io::Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(sync_path)?;
        file.sync_all()
    });
    thread::sleep(Duration::from_millis(25));
    let killed = a.kill9();
    assert!(!killed.success(), "SIGKILL must not report a clean exit");
    match syncer.join() {
        Ok(Ok(())) => eprintln!("the checkin finished before the kill"),
        Ok(Err(error)) => eprintln!("the checkin failed with the dead client: {error}"),
        Err(_) => eprintln!("the checkin thread panicked with the dead client"),
    }
    // Drop unmounts the dead client's stale mountpoint, so the restart can
    // reuse the same name, database and mountpoint.
    drop(a);
    // The killed uploader cannot renew its lease. Expire it on the server so
    // the restart exercises recovery instead of waiting the 60 s production
    // TTL, and let the sweeper abort the orphan upload.
    expire_all_locks(&server.db);
    wait_until("the server sweeps the killed client's lease", READY, || {
        Ok(lock_count(&server.db) == 0)
    });

    // Restart under the same client name, so the harness reopens the same
    // database and the same state directory.
    let mut a2 = env.client("/private-mm", "crash-a", true);
    a2.wait_mounted();
    a2.wait_steady();
    if let (Some(before), Some(after)) = (baseline, a2.status_u64(&["applied_seq"])) {
        assert!(
            after >= before,
            "applied_seq regressed across the crash: {before} -> {after}"
        );
    }

    let recovered = a2.mountpoint.join(relative);
    if recovered.exists() {
        assert_eq!(
            fs::metadata(&recovered).unwrap().len(),
            payload.len() as u64,
            "a partially uploaded batch must never become visible"
        );
        assert_eq!(
            blake3_file(&recovered),
            expected_hash,
            "a half-written batch must never become visible"
        );
        eprintln!("the interrupted checkin left the complete file visible");
    } else {
        eprintln!("the interrupted checkin left no file visible; committing a fresh batch");
        write_at(&a2.mountpoint, relative, &payload);
    }
    fsync_path(&recovered);

    let mut b = env.client("/private-mm", "crash-b", true);
    b.wait_mounted();
    b.wait_steady();
    wait_until("the recovered batch reaches client B", READY, || {
        Ok(b.mountpoint.join(relative).exists())
    });
    assert_eq!(blake3_file(&b.mountpoint.join(relative)), expected_hash);
    assert_trees_equal(&a2.mountpoint, &b.mountpoint);

    let _ = b.stop_graceful();
    let _ = a2.stop_graceful();
    let _ = server.stop_graceful();
}

#[test]
#[serial]
fn proxy_cut_retries_on_next_fsync() {
    if skip_without_fuse("proxy_cut_retries_on_next_fsync") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "chaos-proxy");
    let proxy = env.proxy(server.port);
    let mut a = env.client_at("/private-mm", "proxy-a", true, proxy.port);
    a.wait_mounted();
    a.wait_steady();

    let payload = pattern(32 << 20, 0x51c7);
    let path = write_at(&a.mountpoint, "proxy.bin", &payload);
    let sync_path = path.clone();
    let syncer = thread::spawn(move || -> std::io::Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(sync_path)?;
        file.sync_all()
    });
    thread::sleep(Duration::from_millis(5));
    proxy.cut();
    match syncer.join() {
        Ok(Ok(())) => eprintln!("the first checkin finished before the cut"),
        Ok(Err(error)) => eprintln!("the first checkin failed at the cut: {error}"),
        Err(_) => eprintln!("the first checkin thread panicked at the cut"),
    }

    // The connection is gone. The next fsync must reconnect through the
    // still-listening proxy and finish the batch; a transport failure may
    // surface once before that retry.
    let updated = pattern(32 << 20, 0x51c8);
    fs::write(&path, &updated).unwrap();
    let deadline = std::time::Instant::now() + READY;
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .and_then(|file| file.sync_all())
        {
            Ok(()) => break,
            Err(error) if std::time::Instant::now() < deadline => {
                eprintln!("fsync after cut returned {error}; retrying");
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("fsync did not recover after the proxy cut: {error}"),
        }
    }

    let after = proxy.bytes();
    assert!(
        after.0 > 0 && after.1 > 0,
        "the recovered client must cross the proxy again: {after:?}"
    );
    let mut b = env.client("/private-mm", "proxy-b", true);
    b.wait_mounted();
    b.wait_steady();
    wait_until("client B sees the retried batch", READY, || match fs::read(
        b.mountpoint.join("proxy.bin"),
    ) {
        Ok(bytes) if bytes == updated => Ok(true),
        Ok(bytes) => Err(format!(
            "B has {} bytes, expected {}",
            bytes.len(),
            updated.len()
        )),
        Err(error) => Err(format!("B cannot read proxy.bin yet: {error}")),
    });

    let _ = b.stop_graceful();
    let _ = a.stop_graceful();
    let _ = server.stop_graceful();
}

#[test]
#[serial]
fn server_kill_after_commit_is_idempotent() {
    if skip_without_fuse("server_kill_after_commit_is_idempotent") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "chaos-idem");
    let mut a = env.client("/private-mm", "idem-a", true);
    a.wait_mounted();
    a.wait_steady();

    let payload = pattern(4 << 20, 0x1de);
    let relative = "idem/data.bin";
    let path = write_at(&a.mountpoint, relative, &payload);
    fsync_dir(&a.mountpoint);
    let expected_hash = blake3_file(&path);
    fsync_path(&path);
    if let Some(base) = a.status_u64(&["applied_seq"]) {
        wait_until("the committed batch is applied locally", READY, || {
            Ok(a.status_u64(&["applied_seq"]).is_some_and(|now| now > base))
        });
    }
    let before = tree_manifest(&a.mountpoint);
    assert_eq!(blake3_file(&path), expected_hash);

    // Kill the server after the commit. The restart opens the same database.
    assert!(
        !server.kill9().success(),
        "SIGKILL must not report a clean exit"
    );
    let _ = a.kill9();
    drop(a);
    drop(server);

    let mut server2 = env.server("/private-mm", "chaos-idem");
    let mut a2 = env.client("/private-mm", "idem-a", true);
    a2.wait_mounted();
    a2.wait_steady();
    wait_until(
        "client A rejoins and shows the committed file",
        READY,
        || Ok(a2.mountpoint.join(relative).exists()),
    );
    assert_eq!(
        blake3_file(&a2.mountpoint.join(relative)),
        expected_hash,
        "the committed bytes survive the server crash"
    );
    assert_eq!(
        tree_manifest(&a2.mountpoint),
        before,
        "one committed batch applies exactly once, with no duplicate entry"
    );

    if a2.status_u64(&["outbox", "ops"]).is_some() {
        wait_until(
            "the client's outbox drains after the restart",
            READY,
            || Ok(a2.status_u64(&["outbox", "ops"]) == Some(0)),
        );
    }

    let mut b = env.client("/private-mm", "idem-b", true);
    b.wait_mounted();
    b.wait_steady();
    wait_until("client B sees the single committed batch", READY, || {
        Ok(b.mountpoint.join(relative).exists())
    });
    assert_eq!(blake3_file(&b.mountpoint.join(relative)), expected_hash);
    assert_trees_equal(&a2.mountpoint, &b.mountpoint);

    let _ = b.stop_graceful();
    let _ = a2.stop_graceful();
    let _ = server2.stop_graceful();
}
