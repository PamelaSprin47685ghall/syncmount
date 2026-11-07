//! M1 exit acceptance harness (31:M1-1..M1-7), FUSE layer.
//!
//! Test-only: the release binary never contains this module. The CLI items
//! (M1-1 literal `syncmount client` invocation, M1-5) live in the internal
//! M1 runner (not published), because the `client` subcommand is W11/W12 work
//! and is not wired in the W13a tree.
//!
//! Run one item at a time so each transcript is a clean piece of evidence:
//!
//! ```text
//! SYNCMOUNT_REQUIRE_FUSE=1 \
//!   cargo test --test m1_acceptance -- --nocapture --test-threads=1 \
//!   --exact m1_1_mount
//! ```
//!
//! `m1_hold_child` is the crash fixture: the parent spawns this same test
//! binary, waits for the ready file, then sends SIGKILL. Without `M1_HOLD_MNT`
//! it is an immediate no-op, so a normal run of the file never blocks.

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use fuser::{BackgroundSession, Config, MountOption, SessionACL};
use syncmount::fuse::{FuseFs, mount_config};
use syncmount::store::{PosixBacking, RootFd};
use tempfile::TempDir;

/// Mount options for acceptance: `mount_config` minus `AutoUnmount`.
///
/// `AutoUnmount` is a W13b lifecycle feature; fuser 0.18's auto-unmount path
/// does not reliably wake the session thread on this host (known W13a issue).
/// The callback surface is what M1 exercises, so unmount explicitly through
/// `fusermount3`.
fn smoke_config() -> Config {
    let mut config = mount_config();
    config
        .mount_options
        .retain(|option| *option != MountOption::AutoUnmount);
    config.acl = SessionACL::Owner;
    config
}

fn find_fusermount() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("FUSERMOUNT_PATH") {
        return Some(PathBuf::from(path));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("fusermount3"))
        .find(|candidate| candidate.is_file())
}

fn fuse_ready() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("not Linux".to_string());
    }
    if !Path::new("/dev/fuse").exists() {
        return Err("/dev/fuse is missing".to_string());
    }
    let fusermount = find_fusermount().ok_or_else(|| "fusermount3 not found".to_string())?;
    let metadata =
        fs::metadata(&fusermount).map_err(|err| format!("stat {}: {err}", fusermount.display()))?;
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o4000 == 0 {
        return Err(format!("{} is not setuid", fusermount.display()));
    }
    Ok(())
}

/// Acceptance never skips silently: with `SYNCMOUNT_REQUIRE_FUSE=1` (set by
/// `run-m1.sh`) a missing FUSE stack is a hard failure.
fn require_fuse() -> bool {
    match fuse_ready() {
        Ok(()) => true,
        Err(reason) => {
            if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                panic!("FUSE required but unavailable: {reason}");
            }
            eprintln!("SKIP[FUSE] {reason}");
            false
        }
    }
}

fn tempdir(label: &str) -> TempDir {
    TempDir::new().unwrap_or_else(|err| panic!("tempdir for {label}: {err}"))
}

fn mounted(mnt: &Path) -> bool {
    let needle = mnt.to_string_lossy();
    fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mountpoint| mountpoint == needle.as_ref())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn mount_line(mnt: &Path) -> Option<String> {
    let needle = mnt.to_string_lossy();
    fs::read_to_string("/proc/mounts").ok().and_then(|text| {
        text.lines()
            .find(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mountpoint| mountpoint == needle.as_ref())
                    .unwrap_or(false)
            })
            .map(str::to_string)
    })
}

fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        sleep(Duration::from_millis(20));
    }
    predicate()
}

fn mount_at(backing: &Path, mnt: &Path) -> BackgroundSession {
    let root = RootFd::open_before_mount(backing)
        .unwrap_or_else(|err| panic!("open backing {}: {err}", backing.display()));
    let filesystem = FuseFs::new(Arc::new(PosixBacking::new(root)));
    let notify = filesystem.notify_handle();
    let session = fuser::spawn_mount(filesystem, mnt, &smoke_config())
        .unwrap_or_else(|err| panic!("mount {}: {err}", mnt.display()));
    notify.attach(session.notifier());
    assert!(
        wait_for(Duration::from_secs(10), || mounted(mnt)),
        "mountpoint {} never appeared in /proc/mounts",
        mnt.display()
    );
    session
}

/// Run one shell command, echoing it and its combined output into the
/// transcript. Returns the raw [`Output`] so callers can assert on status.
fn run(cwd: &Path, command: &str) -> Output {
    println!("$ {command}");
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|err| panic!("spawn {command:?}: {err}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    output
}

fn run_ok(cwd: &Path, command: &str) -> String {
    let output = run(cwd, command);
    assert!(
        output.status.success(),
        "command failed ({}) : {command}",
        output.status
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fails(cwd: &Path, command: &str) {
    let output = run(cwd, command);
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: {command}"
    );
}

fn unmount_force(mnt: &Path) {
    let output = Command::new("fusermount3")
        .arg("-uz")
        .arg(mnt)
        .output()
        .unwrap_or_else(|err| panic!("spawn fusermount3 -uz {}: {err}", mnt.display()));
    println!(
        "$ fusermount3 -uz {}\nexit={:?}\n{}",
        mnt.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wait_for(Duration::from_secs(10), || !mounted(mnt)),
        "{} is still mounted after fusermount3 -uz",
        mnt.display()
    );
}

fn unmount_plain(mnt: &Path) {
    let output = Command::new("fusermount3")
        .arg("-u")
        .arg(mnt)
        .output()
        .unwrap_or_else(|err| panic!("spawn fusermount3 -u {}: {err}", mnt.display()));
    println!(
        "$ fusermount3 -u {}\nexit={:?}\n{}",
        mnt.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "fusermount3 -u {} failed: {}",
        mnt.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wait_for(Duration::from_secs(10), || !mounted(mnt)),
        "{} is still mounted after fusermount3 -u",
        mnt.display()
    );
}

/// 31:M1-1 — mount succeeds and `/proc/mounts` shows the fuse entry.
#[test]
#[serial_test::serial]
fn m1_1_mount() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-1 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    fs::write(backing.path().join("hello"), b"hello\n")
        .unwrap_or_else(|err| panic!("seed backing: {err}"));

    let session = mount_at(backing.path(), mnt.path());
    let line = mount_line(mnt.path())
        .unwrap_or_else(|| panic!("no /proc/mounts entry for {}", mnt.path().display()));
    println!("mount entry: {line}");
    assert!(line.contains("fuse"), "mount entry is not fuse: {line}");
    println!(
        "$ mount | grep fuse\n{}",
        run_ok(mnt.path(), "mount | grep fuse")
    );
    let listing = run_ok(mnt.path(), "ls -A");
    assert!(
        listing.contains("hello"),
        "mounted tree is empty: {listing:?}"
    );
    println!("mounted tree: {listing:?}");

    unmount_force(mnt.path());
    session
        .join()
        .unwrap_or_else(|err| panic!("session join: {err}"));
    println!("########## M1-1 END ##########");
}

/// 31:M1-2 — echo/cat, mkdir, mv, rm, symlink on the mountpoint.
#[test]
#[serial_test::serial]
fn m1_2_basic_ops() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-2 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    let session = mount_at(backing.path(), mnt.path());

    assert_eq!(run_ok(mnt.path(), "echo hi > f && cat f"), "hi\n");
    run_ok(mnt.path(), "mkdir d");
    run_ok(mnt.path(), "mv f d/f");
    assert_eq!(run_ok(mnt.path(), "cat d/f"), "hi\n");
    run_ok(mnt.path(), "ln -s d/f link");
    assert_eq!(run_ok(mnt.path(), "readlink link").trim(), "d/f");
    assert_eq!(run_ok(mnt.path(), "cat link"), "hi\n");
    run_ok(mnt.path(), "echo gone > rm-me");
    run_ok(mnt.path(), "rm rm-me");
    run_fails(mnt.path(), "test -e rm-me");
    run_ok(mnt.path(), "rm d/f");
    run_ok(mnt.path(), "rmdir d");
    run_ok(mnt.path(), "rm link");
    let listing = run_ok(mnt.path(), "ls -A");
    assert_eq!(listing.trim(), "");

    unmount_force(mnt.path());
    session
        .join()
        .unwrap_or_else(|err| panic!("session join: {err}"));
    println!("########## M1-2 END ##########");
}

/// 31:M1-3 — stat/readdir/chmod/utimes/xattr read back correctly.
#[test]
#[serial_test::serial]
fn m1_3_metadata() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-3 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    let session = mount_at(backing.path(), mnt.path());

    run_ok(mnt.path(), "printf 12345 > meta");
    let stat = run_ok(mnt.path(), "stat -c '%s,%a,%y' meta");
    println!("stat -c '%s,%a,%y' meta => {stat:?}");
    assert!(stat.starts_with("5,644,"), "unexpected size/mode: {stat:?}");

    run_ok(mnt.path(), "chmod 640 meta");
    let mode = run_ok(mnt.path(), "stat -c %a meta");
    println!("stat -c %a meta => {mode:?}");
    assert_eq!(mode.trim(), "640");

    run_ok(mnt.path(), "TZ=UTC touch -m -d '2021-02-03 04:05:06' meta");
    let mtime = run_ok(mnt.path(), "TZ=UTC stat -c %y meta");
    println!("TZ=UTC stat -c %y meta => {mtime:?}");
    assert_eq!(mtime.trim(), "2021-02-03 04:05:06.000000000 +0000");

    run_ok(mnt.path(), "setfattr -n user.x -v hello meta");
    let value = run_ok(mnt.path(), "getfattr --only-values -n user.x meta");
    println!("getfattr --only-values -n user.x meta => {value:?}");
    assert_eq!(value, "hello");
    println!(
        "$ getfattr -d -m - meta\n{}",
        run_ok(mnt.path(), "getfattr -d -m - meta")
    );

    let listing = run_ok(mnt.path(), "ls -A");
    println!("readdir ls -A => {listing:?}");
    assert!(listing.lines().any(|name| name == "meta"));
    let find = run_ok(
        mnt.path(),
        "find . -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort",
    );
    println!("readdir find => {find:?}");
    assert!(find.lines().any(|name| name == "meta"));

    unmount_force(mnt.path());
    session
        .join()
        .unwrap_or_else(|err| panic!("session join: {err}"));
    println!("########## M1-3 END ##########");
}

/// 31:M1-4 — `fusermount3 -u` unmounts, no mount entry and no syncmount
/// process remain.
#[test]
#[serial_test::serial]
fn m1_4_unmount_clean() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-4 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    let session = mount_at(backing.path(), mnt.path());
    run_ok(mnt.path(), "echo clean > f");

    unmount_plain(mnt.path());
    assert!(!mounted(mnt.path()), "mount entry survived fusermount3 -u");
    session
        .join()
        .unwrap_or_else(|err| panic!("session join after external unmount: {err}"));

    // The mount table entry is gone and the session thread joined, so no
    // process can still hold this mount. A host-wide `pgrep -x syncmount`
    // would also see unrelated syncmount processes and is not a property of
    // this test.
    let listing = run_ok(mnt.path(), "ls -A");
    println!("mountpoint after unmount => {listing:?}");
    assert_eq!(listing.trim(), "", "mountpoint is not empty after unmount");
    println!(
        "mount table: no entry; backing f = {:?}",
        fs::read_to_string(backing.path().join("f"))
            .unwrap_or_else(|err| panic!("read backing f: {err}"))
    );
    println!("########## M1-4 END ##########");
}

/// The crash fixture. Mounts, reports ready, then blocks until SIGKILL.
#[test]
fn m1_hold_child() {
    let Ok(backing) = std::env::var("M1_HOLD_BACKING") else {
        println!("m1_hold_child: no M1_HOLD_MNT, no-op");
        return;
    };
    let mnt = std::env::var("M1_HOLD_MNT").unwrap_or_else(|err| panic!("M1_HOLD_MNT: {err}"));
    let ready = std::env::var("M1_HOLD_READY").unwrap_or_else(|err| panic!("M1_HOLD_READY: {err}"));
    let _session = mount_at(Path::new(&backing), Path::new(&mnt));
    fs::write(&ready, b"ready").unwrap_or_else(|err| panic!("write ready file: {err}"));
    println!(
        "m1_hold_child: mounted {} (pid {})",
        mnt,
        std::process::id()
    );
    loop {
        sleep(Duration::from_secs(60));
    }
}

struct Holder {
    child: Child,
    stdout_path: PathBuf,
}

impl Holder {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// Spawn `m1_hold_child`, wait for the mount, and hand the child back so the
/// caller can SIGKILL it.
fn spawn_holder(backing: &Path, mnt: &Path, control: &Path) -> Holder {
    let exe = std::env::current_exe().unwrap_or_else(|err| panic!("current_exe: {err}"));
    let ready = control.join("ready");
    let stdout_path = control.join("holder.out");
    let file = fs::File::create(&stdout_path)
        .unwrap_or_else(|err| panic!("create {}: {err}", stdout_path.display()));
    let mut child = Command::new(&exe)
        .args([
            "--exact",
            "m1_hold_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("M1_HOLD_BACKING", backing)
        .env("M1_HOLD_MNT", mnt)
        .env("M1_HOLD_READY", &ready)
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(
            fs::File::create(control.join("holder.err"))
                .unwrap_or_else(|err| panic!("create holder.err: {err}")),
        ))
        .spawn()
        .unwrap_or_else(|err| panic!("spawn holder {}: {err}", exe.display()));

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if ready.exists() && mounted(mnt) {
            break;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|err| panic!("try_wait holder: {err}"))
        {
            let stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
            let stderr = fs::read_to_string(control.join("holder.err")).unwrap_or_default();
            panic!("holder exited early: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        }
        assert!(
            Instant::now() < deadline,
            "holder did not become ready within 30s"
        );
        sleep(Duration::from_millis(20));
    }
    println!(
        "holder pid {} mounted {}; child stdout: {}",
        child.id(),
        mnt.display(),
        stdout_path.display()
    );
    Holder { child, stdout_path }
}

fn kill9(holder: Holder) {
    let pid = holder.pid();
    let status = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .unwrap_or_else(|err| panic!("spawn kill -9 {pid}: {err}"));
    println!("$ kill -9 {pid}\nkill exit={:?}", status.code());
    assert!(status.success(), "kill -9 {pid} failed");
    let mut child = holder.child;
    let status = child
        .wait()
        .unwrap_or_else(|err| panic!("wait holder {pid}: {err}"));
    println!(
        "holder exit: code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
    assert_eq!(status.signal(), Some(9), "holder was not killed by SIGKILL");
    let stdout = fs::read_to_string(&holder.stdout_path).unwrap_or_default();
    if !stdout.is_empty() {
        println!("holder stdout:\n{stdout}");
    }
}

/// 31:M1-6 — kill -9 the mounting process, clean the dead session, remount,
/// and find the backing tree intact.
#[test]
#[serial_test::serial]
fn m1_6_kill9_recover() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-6 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    let control = tempdir("control");
    fs::write(backing.path().join("keep"), b"before\n")
        .unwrap_or_else(|err| panic!("seed keep: {err}"));

    let holder = spawn_holder(backing.path(), mnt.path(), control.path());
    run_ok(mnt.path(), "echo crash-write > crash.txt");
    run_ok(mnt.path(), "mkdir crashdir");
    run_ok(mnt.path(), "echo inner > crashdir/inner.txt");
    let before = run_ok(
        backing.path(),
        "sha256sum keep crash.txt crashdir/inner.txt",
    );
    println!("backing hashes before kill:\n{before}");

    kill9(holder);
    assert!(mounted(mnt.path()), "mount disappeared without unmount");
    let after_kill = run_ok(
        backing.path(),
        "sha256sum keep crash.txt crashdir/inner.txt",
    );
    assert_eq!(before, after_kill, "backing changed across kill -9");

    unmount_force(mnt.path());
    let session = mount_at(backing.path(), mnt.path());
    assert_eq!(run_ok(mnt.path(), "cat keep"), "before\n");
    assert_eq!(run_ok(mnt.path(), "cat crash.txt"), "crash-write\n");
    assert_eq!(run_ok(mnt.path(), "cat crashdir/inner.txt"), "inner\n");
    let after_remount = run_ok(
        backing.path(),
        "sha256sum keep crash.txt crashdir/inner.txt",
    );
    assert_eq!(before, after_remount, "backing changed across remount");
    println!("remount reads OK; backing hashes unchanged:\n{after_remount}");

    unmount_plain(mnt.path());
    session
        .join()
        .unwrap_or_else(|err| panic!("session join: {err}"));
    println!("########## M1-6 END ##########");
}

/// 31:M1-7 — `fusermount3 -uz` clears a mount whose owner was killed.
#[test]
#[serial_test::serial]
fn m1_7_force_unmount() {
    if !require_fuse() {
        return;
    }
    println!("########## M1-7 BEGIN ##########");
    let backing = tempdir("backing");
    let mnt = tempdir("mnt");
    let control = tempdir("control");
    fs::write(backing.path().join("survive"), b"survive\n")
        .unwrap_or_else(|err| panic!("seed survive: {err}"));

    let holder = spawn_holder(backing.path(), mnt.path(), control.path());
    run_ok(mnt.path(), "echo force > f");
    let pid = holder.pid();
    kill9(holder);
    assert!(mounted(mnt.path()), "stale mount vanished before -uz");

    let output = run(
        control.path(),
        &format!("fusermount3 -uz {}", mnt.path().display()),
    );
    println!("fusermount3 -uz exit={:?}", output.status.code());
    assert!(
        output.status.success(),
        "fusermount3 -uz failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wait_for(Duration::from_secs(10), || !mounted(mnt.path())),
        "mount entry survived fusermount3 -uz"
    );
    println!("mounted after -uz: {}", mounted(mnt.path()));
    // See m1_4_unmount_clean: the mount table, the empty mountpoint and the
    // dead holder pid cover the process side without a host-wide pgrep.
    let listing = run_ok(mnt.path(), "ls -A");
    println!("mountpoint after -uz => {listing:?}");
    assert_eq!(listing.trim(), "", "mountpoint is not empty after -uz");
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "holder pid {pid} is still alive"
    );
    assert_eq!(
        fs::read_to_string(backing.path().join("survive"))
            .unwrap_or_else(|err| panic!("read survive: {err}")),
        "survive\n"
    );
    assert_eq!(
        fs::read_to_string(backing.path().join("f")).unwrap_or_else(|err| panic!("read f: {err}")),
        "force\n"
    );
    println!("########## M1-7 END ##########");
}
