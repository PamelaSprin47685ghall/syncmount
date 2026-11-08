//! Recovery tests for the 1.1 `--mmap` path: an upload lock left behind by a
//! killed client, and a server restarted from the same database.
//!
//! Run with:
//!
//! ```text
//! cargo test --test mmap_recovery --features "mmap-tests slow-tests" \
//!     -- --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serial_test::serial;

use mmap_harness::{MmapEnv, skip_without_fuse, tree_manifest, wait_until};
use rusqlite::Connection;
use syncmount::mmap::now_ms;

/// Deadline for ordinary convergence.
const READY: Duration = Duration::from_secs(30);
/// Deadline for one fsync that must not block on a stale lock.
const FSYNC_DEADLINE: Duration = Duration::from_secs(30);

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
fn ttl_reclaims_upload_lock_after_kill9() {
    if skip_without_fuse("ttl_reclaims_upload_lock_after_kill9") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "recovery-ttl");
    let mut a = env.client("/private-mm", "ttl-a", true);
    a.wait_mounted();
    a.wait_steady();

    // Kill the client while it holds the upload lock for a 16 MiB checkin.
    let payload = pattern(16 << 20, 0x7e1);
    let relative = "locks/held.bin";
    let path = write_at(&a.mountpoint, relative, &payload);
    fsync_dir(&a.mountpoint);
    let sync_path = path.clone();
    let syncer = thread::spawn(move || -> std::io::Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(sync_path)?;
        file.sync_all()
    });
    thread::sleep(Duration::from_millis(20));
    assert!(!a.kill9().success(), "SIGKILL must not report a clean exit");
    match syncer.join() {
        Ok(Ok(())) => eprintln!("the upload lock was released before the kill"),
        Ok(Err(error)) => eprintln!("the checkin failed with the dead client: {error}"),
        Err(_) => eprintln!("the checkin thread panicked with the dead client"),
    }
    // Drop unmounts the dead client before the replacement works on the path.
    drop(a);

    // The production TTL is 60 s. Force every lease past its deadline on the
    // server database and let the sweeper run, so the recovery path is tested
    // without a 60 s wall clock. No client may see a permanent 423 after it.
    expire_all_locks(&server.db);
    wait_until("the server sweeps the expired upload lock", READY, || {
        Ok(lock_count(&server.db) == 0)
    });

    let mut b = env.client("/private-mm", "ttl-b", true);
    b.wait_mounted();
    b.wait_steady();
    let replacement = pattern(8 << 10, 0xbeef);
    let b_path = write_at(&b.mountpoint, relative, &replacement);
    fsync_dir(&b.mountpoint);
    let baseline = b.status_u64(&["applied_seq"]);

    // Run the fsync on a worker so a lock that never expires fails the test
    // with a message about 423 instead of hanging the whole suite forever.
    let (sender, receiver) = mpsc::channel();
    let fsync_target = b_path.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + FSYNC_DEADLINE;
        let result = loop {
            let attempt = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&fsync_target)
                .and_then(|file| file.sync_all());
            match attempt {
                Ok(()) => break Ok(()),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => break Err(error),
            }
        };
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(FSYNC_DEADLINE) {
        Ok(Ok(())) => {
            eprintln!("the second client's fsync completed after the stale lease expired")
        }
        Ok(Err(error)) => panic!(
            "the second client's fsync failed; the stale upload lock was not reclaimed: {error}"
        ),
        Err(_) => panic!(
            "the second client's fsync blocked past {FSYNC_DEADLINE:?}; \
             the server kept returning 423 for the stale upload lock"
        ),
    }
    assert_eq!(fs::read(&b_path).unwrap(), replacement);

    if let Some(base) = baseline {
        wait_until("the recovery upload is applied locally", READY, || {
            Ok(b.status_u64(&["applied_seq"]).is_some_and(|now| now > base))
        });
    }

    // A fresh client proves the server accepted the recovery upload, not just
    // that the local mount returned bytes from its cache.
    let mut c = env.client("/private-mm", "ttl-c", true);
    c.wait_mounted();
    c.wait_steady();
    wait_until("a fresh client sees the recovery upload", READY, || {
        Ok(c.mountpoint.join(relative).exists())
    });
    assert_eq!(fs::read(c.mountpoint.join(relative)).unwrap(), replacement);

    let _ = c.stop_graceful();
    let _ = b.stop_graceful();
    let _ = server.stop_graceful();
}

#[test]
#[serial]
fn server_restart_keeps_committed_batches() {
    if skip_without_fuse("server_restart_keeps_committed_batches") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "recovery-restart");
    let mut a = env.client("/private-mm", "restart-a", true);
    a.wait_mounted();
    a.wait_steady();

    let payload = pattern(256 << 10, 0x5e9);
    let relative = "committed/keep.bin";
    let path = write_at(&a.mountpoint, relative, &payload);
    fsync_dir(&a.mountpoint);
    fsync_path(&path);
    if let Some(base) = a.status_u64(&["applied_seq"]) {
        wait_until("the committed batch is applied locally", READY, || {
            Ok(a.status_u64(&["applied_seq"]).is_some_and(|now| now > base))
        });
    }

    // B checks out the committed tree before the crash, and becomes the
    // reference manifest for the post-restart checkout.
    let mut b = env.client("/private-mm", "restart-b", true);
    b.wait_mounted();
    b.wait_steady();
    wait_until("B replays the committed batch", READY, || {
        Ok(b.mountpoint.join(relative).exists())
    });
    assert_eq!(fs::read(b.mountpoint.join(relative)).unwrap(), payload);
    let before = tree_manifest(&b.mountpoint);

    assert!(
        !server.kill9().success(),
        "SIGKILL must not report a clean exit"
    );
    let _ = a.kill9();
    let _ = b.kill9();
    drop(a);
    drop(b);
    drop(server);

    // Same database name => the same server database file. A brand-new
    // client checks out from the server, so the bytes cannot come from a
    // local replica that survived the crash.
    let mut server2 = env.server("/private-mm", "recovery-restart");
    let mut c = env.client("/private-mm", "restart-c", true);
    c.wait_mounted();
    c.wait_steady();
    wait_until(
        "a fresh client checks out the committed tree after the server restart",
        READY,
        || Ok(c.mountpoint.join(relative).exists()),
    );
    assert_eq!(
        fs::read(c.mountpoint.join(relative)).unwrap(),
        payload,
        "a restart must not lose a committed batch"
    );
    assert_eq!(
        tree_manifest(&c.mountpoint),
        before,
        "the restarted server reproduces the committed tree exactly"
    );

    let _ = c.stop_graceful();
    let _ = server2.stop_graceful();
}
