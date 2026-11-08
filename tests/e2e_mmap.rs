//! End-to-end tests for the 1.1 `--mmap` path.
//!
//! Every test drives real processes through `tests/mmap_harness`: one server,
//! one or two clients, a real FUSE mount and the master-key file. The tests
//! are ignored until `src/mmap/{server,client,shadow}` lands; running them
//! earlier is expected to fail.
//!
//! Run with:
//!
//! ```text
//! cargo test --test e2e_mmap -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serial_test::serial;

use mmap_harness::{
    MmapEnv, assert_trees_equal, blake3_file, skip_without_fuse, tree_manifest, wait_until,
};

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
fn write_at(root: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, bytes).unwrap();
    path
}

/// `fsync(2)` a path through the mount. This is the explicit checkin point of
/// the mmap client.
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
                // EAGAIN is the documented "retry on the next fsync" signal.
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

#[test]
#[serial]
fn mmap_shared_write_visible_and_fsync_checks_in() {
    if skip_without_fuse("mmap_shared_write_visible_and_fsync_checks_in") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "e2e-shared");
    let mut a = env.client("/private-mm", "shared-a", true);
    a.wait_mounted();
    a.wait_steady();

    let baseline = a.status_u64(&["applied_seq"]);
    let payload = pattern(1 << 20, 0x51ed);
    let relative = "shared.bin";
    let path = write_at(&a.mountpoint, relative, &payload);
    assert_eq!(
        fs::read(&path).unwrap(),
        payload,
        "the 1 MiB write must read back through the mount"
    );

    fsync_path(&path);
    if let Some(base) = baseline {
        wait_until("client A observes its own checkin", READY, || {
            Ok(a.status_u64(&["applied_seq"]).is_some_and(|now| now > base))
        });
    }

    let mut b = env.client("/private-mm", "shared-b", true);
    b.wait_mounted();
    b.wait_steady();
    wait_until("client B replays the checked-in file", READY, || {
        Ok(b.mountpoint.join(relative).exists())
    });

    assert_eq!(
        fs::read(b.mountpoint.join(relative)).unwrap(),
        payload,
        "both mounts carry the checked-in bytes"
    );
    assert_trees_equal(&a.mountpoint, &b.mountpoint);

    let _ = b.stop_graceful();
    let _ = a.stop_graceful();
    let _ = server.stop_graceful();
}

#[test]
#[serial]
fn munmap_and_close_do_not_checkin() {
    if skip_without_fuse("munmap_and_close_do_not_checkin") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "e2e-close");
    let mut a = env.client("/private-mm", "close-a", true);
    a.wait_mounted();
    a.wait_steady();

    let baseline = a.status_u64(&["applied_seq"]);
    let payload = pattern(64 << 10, 0xc105e);
    let relative = "closed.bin";
    // `fs::write` closes the file descriptor and every mapping is dropped
    // when the call returns. No explicit fsync happens here.
    let path = write_at(&a.mountpoint, relative, &payload);
    assert_eq!(fs::read(&path).unwrap(), payload);

    // Give an accidental asynchronous checkin time to show up, and give the
    // status writer (a 5 s interval) time to publish the unchanged counter.
    thread::sleep(Duration::from_secs(6));
    if let Some(base) = baseline {
        assert_eq!(
            a.status_u64(&["applied_seq"]),
            Some(base),
            "close without fsync must not advance applied_seq"
        );
    }

    let mut b = env.client("/private-mm", "close-b", true);
    b.wait_mounted();
    b.wait_steady();
    thread::sleep(Duration::from_millis(1500));
    assert!(
        !b.mountpoint.join(relative).exists(),
        "close without fsync must not check in: client B sees an empty tree"
    );

    // The explicit checkin is fsync: only now may the file cross the wire.
    fsync_path(&path);
    wait_until("client B sees the file only after fsync", READY, || {
        Ok(b.mountpoint.join(relative).exists())
    });
    assert_eq!(fs::read(b.mountpoint.join(relative)).unwrap(), payload);

    let _ = b.stop_graceful();
    let _ = a.stop_graceful();
    let _ = server.stop_graceful();
}

#[test]
#[serial]
fn namespace_isolation_same_paths() {
    if skip_without_fuse("namespace_isolation_same_paths") {
        return;
    }
    let env = MmapEnv::new();
    let mut private = env.server("/private-mm", "iso-private");
    let mut public = env.server("/public-mm", "iso-public");
    let mut a = env.client("/private-mm", "iso-a", true);
    let mut b = env.client("/public-mm", "iso-b", true);
    a.wait_mounted();
    a.wait_steady();
    b.wait_mounted();
    b.wait_steady();

    let relative = "same/name.bin";
    let left = pattern(8 << 10, 1);
    let right = pattern(8 << 10, 2);
    assert_ne!(left, right);

    let left_path = write_at(&a.mountpoint, relative, &left);
    let right_path = write_at(&b.mountpoint, relative, &right);
    // A newly created child directory is local-only until its parent commits
    // the DIR_ADD entry. fsync the parent first, then the child batch.
    fsync_dir(&a.mountpoint);
    fsync_dir(&b.mountpoint);
    fsync_path(&left_path);
    fsync_path(&right_path);

    assert_eq!(fs::read(&left_path).unwrap(), left);
    assert_eq!(fs::read(&right_path).unwrap(), right);

    let private_tree = tree_manifest(&a.mountpoint);
    let public_tree = tree_manifest(&b.mountpoint);
    assert_eq!(
        private_tree.len(),
        public_tree.len(),
        "the two namespaces hold the same shape"
    );
    assert_ne!(
        private_tree, public_tree,
        "the same relative path with different bytes must not produce equal manifests"
    );

    // A write in /private-mm must never leak into /public-mm.
    let later = pattern(4 << 10, 3);
    fs::write(&left_path, &later).unwrap();
    fsync_path(&left_path);
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        fs::read(&right_path).unwrap(),
        right,
        "/public-mm keeps its own bytes"
    );
    assert_eq!(fs::read(&left_path).unwrap(), later);

    let _ = b.stop_graceful();
    let _ = a.stop_graceful();
    let _ = public.stop_graceful();
    let _ = private.stop_graceful();
}

#[test]
#[serial]
fn counting_proxy_measures_rsync_delta() {
    if skip_without_fuse("counting_proxy_measures_rsync_delta") {
        return;
    }
    let env = MmapEnv::new();
    let mut server = env.server("/private-mm", "e2e-delta");
    let proxy = env.proxy(server.port);
    assert_ne!(proxy.port, server.port, "the proxy listens on its own port");
    assert_eq!(
        proxy.bytes(),
        (0, 0),
        "no traffic before a client connects through the proxy"
    );

    let mut a = env.client_at("/private-mm", "delta-a", true, proxy.port);
    a.wait_mounted();
    a.wait_steady();

    let base = pattern(64 << 20, 0x64d317a);
    let path = a.mountpoint.join("delta.bin");
    // Keep one descriptor across both fsyncs. Opening the file again would
    // trigger the shadow's bodies checkout and count a full download as if it
    // were checkin traffic.
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(&base).unwrap();
    file.sync_all().unwrap();
    // Make sure the first batch is committed before taking the wire snapshot;
    // otherwise a slow initial upload lands in the measured delta window.
    let mut seen = env.client("/private-mm", "delta-seen", true);
    seen.wait_mounted();
    seen.wait_steady();
    wait_until("the baseline batch is committed", READY, || {
        Ok(seen.mountpoint.join("delta.bin").exists())
    });
    let after_first = proxy.bytes();
    assert!(
        after_first.0 > 0 && after_first.1 > 0,
        "the first checkin must cross the proxy: {after_first:?}"
    );

    let offset = 4 << 20;
    let patch = pattern(4 << 10, 0x9e37);
    file.write_all_at(&patch, offset as u64).unwrap();
    file.sync_all().unwrap();
    let after_second = proxy.bytes();
    let uploaded = after_second.0.saturating_sub(after_first.0);
    let downloaded = after_second.1.saturating_sub(after_first.1);
    let moved = uploaded + downloaded;
    let budget = (base.len() / 20) as u64;
    assert!(
        moved <= budget,
        "one 4 KiB change moved {moved} bytes (client->server {uploaded}, \
         server->client {downloaded}), budget {budget} (5% of 64 MiB)"
    );

    let mut expected = base.clone();
    expected[offset..offset + patch.len()].copy_from_slice(&patch);
    let mut b = seen;
    b.wait_mounted();
    b.wait_steady();
    wait_until("client B checks out the delta", READY, || {
        match fs::read(b.mountpoint.join("delta.bin")) {
            Ok(bytes) if bytes == expected => Ok(true),
            Ok(bytes) => Err(format!(
                "B has {} bytes with hash {}, expected {} bytes with hash {}",
                bytes.len(),
                hex::encode(blake3_file(&b.mountpoint.join("delta.bin"))),
                expected.len(),
                hex::encode(blake3::hash(&expected).as_bytes())
            )),
            Err(error) => Err(format!("B cannot read delta.bin yet: {error}")),
        }
    });

    let _ = b.stop_graceful();
    let _ = a.stop_graceful();
    let _ = server.stop_graceful();
}
