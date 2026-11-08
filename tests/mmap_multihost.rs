//! Manual two-host check: two independent `--mmap` clients must keep fcntl
//! locks local, so a lock held through the mount on host B does not block a
//! lock on the mount of host A.
//!
//! This file does not start either host: the operator places the same server
//! behind both clients, mounts the same namespace on both machines, and sets:
//!
//! * `SYNCMOUNT_MULTIHOST=1`,
//! * `SYNCMOUNT_HOST_A`, `SYNCMOUNT_HOST_B` — ssh destinations,
//! * `SYNCMOUNT_MOUNT_A`, `SYNCMOUNT_MOUNT_B` — the two mountpoints.
//!
//! The test uses `python3` and `ssh` on both ends; it adds no Rust dependency.
//! It is ignored because it needs two hosts and the mmap server that is still
//! being built.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serial_test::serial;

use mmap_harness::skip_without_fuse;

/// Hold an fcntl write lock on the path for 10 s, then exit.
const LOCK_SCRIPT: &str = "\
import fcntl, sys, time
f = open(sys.argv[1], 'r+')
fcntl.lockf(f, fcntl.LOCK_EX)
print('locked', flush=True)
time.sleep(10)
";

/// Try to take the same lock without blocking.
const TRY_SCRIPT: &str = "\
import fcntl, sys
f = open(sys.argv[1], 'r+')
fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
print('acquired', flush=True)
";

/// Quote one value for the remote POSIX shell that ssh runs.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// One ssh invocation with a single remote command string.
fn ssh(host: &str, command: &str) -> Command {
    let mut command_line = Command::new("ssh");
    command_line
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"])
        .arg(host)
        .arg(command);
    command_line
}

fn ssh_stdout(host: &str, command: &str) -> Result<String, String> {
    let output = ssh(host, command)
        .output()
        .map_err(|error| format!("ssh {host}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ssh {host} `{command}` failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Poll the remote mount until it shows `path`.
fn wait_remote_exists(host: &str, path: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let command = format!("test -e {}", shell_quote(path));
    loop {
        let visible = ssh(host, &command)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if visible {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "{path} did not appear on {host} within {timeout:?}; \
                 is the second mmap client mounted?"
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[serial]
#[ignore = "manual two-host run; waiting for mm-server"]
fn two_hosts_do_not_share_fcntl_locks() {
    if skip_without_fuse("two_hosts_do_not_share_fcntl_locks") {
        return;
    }
    if std::env::var("SYNCMOUNT_MULTIHOST").as_deref() != Ok("1") {
        eprintln!(
            "SKIP two_hosts_do_not_share_fcntl_locks: set SYNCMOUNT_MULTIHOST=1, \
             SYNCMOUNT_HOST_A, SYNCMOUNT_HOST_B, SYNCMOUNT_MOUNT_A and SYNCMOUNT_MOUNT_B"
        );
        return;
    }
    let (Ok(host_a), Ok(host_b)) = (
        std::env::var("SYNCMOUNT_HOST_A"),
        std::env::var("SYNCMOUNT_HOST_B"),
    ) else {
        eprintln!(
            "SKIP two_hosts_do_not_share_fcntl_locks: SYNCMOUNT_HOST_A and \
             SYNCMOUNT_HOST_B must both name an ssh destination"
        );
        return;
    };
    let (Ok(mount_a), Ok(mount_b)) = (
        std::env::var("SYNCMOUNT_MOUNT_A"),
        std::env::var("SYNCMOUNT_MOUNT_B"),
    ) else {
        eprintln!(
            "SKIP two_hosts_do_not_share_fcntl_locks: SYNCMOUNT_MOUNT_A and \
             SYNCMOUNT_MOUNT_B must both name a mounted mmap client"
        );
        return;
    };

    // The two destinations must be different machines; otherwise a shared
    // fcntl lock is correct and the test proves nothing.
    let name_a = ssh_stdout(&host_a, "hostname").unwrap();
    let name_b = ssh_stdout(&host_b, "hostname").unwrap();
    assert_ne!(
        name_a.trim(),
        name_b.trim(),
        "host A and host B report the same hostname; use two distinct machines"
    );
    for (label, host) in [("A", &host_a), ("B", &host_b)] {
        let fuse = ssh(host, "test -e /dev/fuse")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(fuse, "host {label} has no /dev/fuse");
    }
    assert!(
        Path::new(&mount_a).is_dir(),
        "SYNCMOUNT_MOUNT_A `{mount_a}` is not a local mounted directory"
    );
    let remote_mount = ssh(&host_b, &format!("test -d {}", shell_quote(&mount_b)))
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    assert!(
        remote_mount,
        "host B has no directory at SYNCMOUNT_MOUNT_B `{mount_b}`"
    );

    // Create the probe through the local mount and wait for the remote one to
    // replay it.
    let probe_a = Path::new(&mount_a).join("lock-probe");
    if !probe_a.exists() {
        fs::write(&probe_a, b"lock probe\n").unwrap();
    }
    let probe_b = Path::new(&mount_b).join("lock-probe");
    wait_remote_exists(&host_b, probe_b.to_str().unwrap(), Duration::from_secs(30));

    // Host B holds an exclusive fcntl lock through its mount.
    let remote_command = format!(
        "python3 -c {} {}",
        shell_quote(LOCK_SCRIPT),
        shell_quote(probe_b.to_str().unwrap())
    );
    let mut remote = ssh(&host_b, &remote_command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(remote.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(
        ready.trim(),
        "locked",
        "host B could not take the fcntl lock; ssh, python3 or the mount failed"
    );

    // Host A must still take its own lock: independent mounts do not share
    // fcntl locks. A blocking failure here means the server is emulating one
    // shared lock domain across hosts, which the design forbids.
    let local = Command::new("python3")
        .args(["-c", TRY_SCRIPT, probe_a.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        local.status.success(),
        "host A could not take its own fcntl lock while host B held one: \
         stdout `{}`, stderr `{}`",
        String::from_utf8_lossy(&local.stdout).trim(),
        String::from_utf8_lossy(&local.stderr).trim()
    );

    let _ = remote.kill();
    let _ = remote.wait();
}
