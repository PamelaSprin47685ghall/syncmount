//! FUSE adapter: the outermost ring.
//!
//! This module translates kernel callbacks into [`store::BackingStore`]
//! calls. W13b attaches the write path: mutations enter the client's
//! [`client::Outbox`], and remote operations are materialised through
//! [`ReplayView`], which drops the kernel's cached view afterwards. The
//! module is gated by the `fuse` feature.
//!
//! ```text
//! kernel  ->  fuse::fs::FuseFs  ->  store::BackingStore
//!                    |                    |
//!                    +-- ino.rs ----------+ NodeTable (INodeNo <-> InodeId)
//!                    +-- write_path.rs ---+ client::Outbox / PendingOverlay
//!                    +-- notify.rs        (session notifier)
//!                    +-- replay.rs        (ReplayBacking -> inval_*)
//! ```

mod fs;
mod ino;
mod notify;
mod replay;
mod write_path;

pub use fs::{FuseBacking, FuseFs, INIT_CAPABILITIES};
pub use ino::{ATTR_TTL, ENTRY_TTL, GENERATION, id_of, ino_of};
pub use notify::Notify;
pub use replay::ReplayView;
pub use write_path::WritePath;

use fuser::{Config, MountOption, SessionACL};

/// Mount configuration for a local syncmount session.
///
/// `AutoUnmount` covers a crashed process; fuser requires an ACL other than
/// `Owner` for it, and this host's `/etc/fuse.conf` enables
/// `user_allow_other`. The mount is still limited to the owner and root by
/// `RootAndOwner`.
///
/// Eight worker threads and `clone_fd` follow the client skeleton: a blocking
/// callback must not stall the whole session.
pub fn mount_config() -> Config {
    mount_config_with(false)
}

/// Mount configuration with an explicit `allow_other` choice.
///
/// `allow_other` maps to [`SessionACL::All`]; the CLI refuses the option
/// before reaching here unless `/etc/fuse.conf` grants `user_allow_other`.
pub fn mount_config_with(allow_other: bool) -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("syncmount".to_string()),
        MountOption::Subtype("syncmount".to_string()),
        MountOption::AutoUnmount,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    config.acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::RootAndOwner
    };
    config.n_threads = Some(8);
    config.clone_fd = true;
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E6 / 18 §4.1: the lifecycle options are present, and the lock/IO
    /// capabilities are not requested here.
    #[test]
    fn u_fuse_mount_config() {
        let config = mount_config();
        assert!(config.mount_options.contains(&MountOption::AutoUnmount));
        assert!(
            config
                .mount_options
                .contains(&MountOption::FSName("syncmount".to_string()))
        );
        assert!(
            config
                .mount_options
                .contains(&MountOption::Subtype("syncmount".to_string()))
        );
        assert!(matches!(config.acl, SessionACL::RootAndOwner));
        assert_eq!(config.n_threads, Some(8));
        assert!(config.clone_fd);
    }

    /// `--allow-other` widens the ACL to every user; the default stays
    /// owner-and-root.
    #[test]
    fn u_fuse_mount_config_allow_other() {
        assert!(matches!(mount_config_with(true).acl, SessionACL::All));
        assert!(matches!(
            mount_config_with(false).acl,
            SessionACL::RootAndOwner
        ));
    }
}

#[cfg(all(test, feature = "fuse-tests"))]
mod mount_tests {
    use super::*;

    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use crate::client::{InstanceId, Outbox, PendingOverlay, State, Tuning, WriteGate};
    use crate::fuse::WritePath;
    use crate::protocol::frame::ClientId;
    use crate::store::{NodeTable, PosixBacking, RootFd};
    use tempfile::TempDir;

    fn find_fusermount() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("FUSERMOUNT_PATH") {
            return Some(PathBuf::from(path));
        }
        let path = std::env::var_os("PATH")?;
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join("fusermount3");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    fn fuse_ready() -> Result<(), String> {
        if !cfg!(target_os = "linux") {
            return Err("not Linux".to_string());
        }
        let dev = Path::new("/dev/fuse");
        if !dev.exists() {
            return Err("/dev/fuse is missing".to_string());
        }
        let fusermount = find_fusermount().ok_or_else(|| "fusermount3 not found".to_string())?;
        let metadata = std::fs::metadata(&fusermount)
            .map_err(|err| format!("stat {}: {err}", fusermount.display()))?;
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o4000 == 0 {
            return Err(format!("{} is not setuid", fusermount.display()));
        }
        Ok(())
    }

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

    fn mounted(path: &Path) -> bool {
        let needle = path.to_string_lossy().to_string();
        std::fs::read_to_string("/proc/mounts")
            .map(|mounts| {
                mounts.lines().any(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .map(|mountpoint| mountpoint == needle)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    fn run(cwd: &Path, command: &str) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|err| panic!("spawn {command:?}: {err}"));
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        println!("$ {command}\n{stdout}{stderr}");
        assert!(
            output.status.success(),
            "command failed: {command}\nstatus: {}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
        stdout
    }

    fn run_fails(cwd: &Path, command: &str) -> bool {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(cwd)
            .output()
            .unwrap_or_else(|err| panic!("spawn {command:?}: {err}"));
        println!(
            "$ {command} (expect failure)\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        !output.status.success()
    }

    /// A smoke-only config: `AutoUnmount` is a lifecycle feature owned by
    /// W13b, and fuser 0.18's auto-unmount path does not reliably wake the
    /// session thread on this host. The callback surface is what this test
    /// exercises, so unmount explicitly through fusermount3.
    fn smoke_config() -> Config {
        let mut config = mount_config();
        config
            .mount_options
            .retain(|option| *option != MountOption::AutoUnmount);
        config.acl = SessionACL::Owner;
        config
    }

    /// E6 / 45 §4.3, 31:M1-1..3: real mount, shell smoke, clean unmount.
    #[test]
    #[serial_test::serial]
    fn mount_smoke() {
        if !require_fuse() {
            return;
        }
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let root =
            RootFd::open_before_mount(tmp.path()).unwrap_or_else(|err| panic!("open root: {err}"));
        std::fs::create_dir(tmp.path().join(".syncmount-staging"))
            .unwrap_or_else(|err| panic!("mkdir reserved: {err}"));
        std::fs::write(tmp.path().join("existing"), b"old\n")
            .unwrap_or_else(|err| panic!("write existing: {err}"));

        let filesystem = FuseFs::new(Arc::new(PosixBacking::new(root)));
        let notify = filesystem.notify_handle();
        let config = smoke_config();
        let session = match fuser::spawn_mount(filesystem, tmp.path(), &config) {
            Ok(session) => session,
            Err(err) => {
                if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                    panic!("mount failed: {err}");
                }
                eprintln!("SKIP[FUSE] mount failed: {err}");
                return;
            }
        };
        notify.attach(session.notifier());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !mounted(tmp.path()) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            mounted(tmp.path()),
            "mountpoint not visible in /proc/mounts"
        );

        // Reserved names: invisible to lookup/readdir, occupied as targets.
        assert!(run_fails(tmp.path(), "test -e .syncmount-staging"));
        assert!(run_fails(tmp.path(), "mkdir .syncmount-staging"));
        let listing = run(tmp.path(), "ls -a");
        assert!(!listing.contains(".syncmount-staging"));
        assert!(!listing.contains(".syncmount-manifest"));
        assert!(!listing.contains(".audit.log"));

        // Local callback surface: write/read, mkdir, mv, symlink, rm.
        run(tmp.path(), "echo hello > f");
        assert_eq!(run(tmp.path(), "cat f"), "hello\n");
        assert_eq!(run(tmp.path(), "stat -c %s f").trim(), "6");
        run(tmp.path(), "mkdir d");
        run(tmp.path(), "mv f d/g");
        assert_eq!(run(tmp.path(), "cat d/g"), "hello\n");
        run(tmp.path(), "ln -s d/g link");
        assert_eq!(run(tmp.path(), "readlink link").trim(), "d/g");
        run(tmp.path(), "rm d/g");
        run(tmp.path(), "rmdir d");
        run(tmp.path(), "rm link");
        run(tmp.path(), "echo keep > keep");
        assert_eq!(run(tmp.path(), "cat existing"), "old\n");

        println!("unmounting with fusermount3 -uz");
        let _ = Command::new("fusermount3")
            .arg("-uz")
            .arg(tmp.path())
            .output();
        let unmount = session.umount_and_join();
        println!("session joined: {unmount:?}");
        assert!(unmount.is_ok(), "unmount failed: {unmount:?}");
        assert!(!mounted(tmp.path()), "mountpoint still in /proc/mounts");

        // The backing tree is ordinary again and contains the writes.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("keep"))
                .unwrap_or_else(|err| panic!("read keep: {err}")),
            "keep\n"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("existing"))
                .unwrap_or_else(|err| panic!("read existing: {err}")),
            "old\n"
        );
        assert!(tmp.path().join(".syncmount-staging").is_dir());
    }

    /// E6 / W13b / C-09: a real mount refuses mutations while the gate is
    /// closed and queues them once it opens.
    #[test]
    #[serial_test::serial]
    fn mount_write_path_gate() {
        if !require_fuse() {
            return;
        }
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir: {err}"));
        let root =
            RootFd::open_before_mount(tmp.path()).unwrap_or_else(|err| panic!("open root: {err}"));
        let nodes = Arc::new(NodeTable::new());
        let store = Arc::new(PosixBacking::with_nodes(Arc::new(root), nodes));
        let gate = Arc::new(WriteGate::new(State::Steady));
        let outbox = Arc::new(Outbox::with_tuning(&Tuning::default()));
        let pending = Arc::new(PendingOverlay::new());
        let path = WritePath::new(
            Arc::clone(&gate),
            Arc::clone(&outbox),
            pending,
            InstanceId(1),
            ClientId::from_bytes([1; 16]),
        );
        let filesystem = FuseFs::with_write_path(store, path);
        let notify = filesystem.notify_handle();
        let config = smoke_config();
        let session = match fuser::spawn_mount(filesystem, tmp.path(), &config) {
            Ok(session) => session,
            Err(err) => {
                if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                    panic!("mount failed: {err}");
                }
                eprintln!("SKIP[FUSE] mount failed: {err}");
                return;
            }
        };
        notify.attach(session.notifier());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !mounted(tmp.path()) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            mounted(tmp.path()),
            "mountpoint not visible in /proc/mounts"
        );

        run(tmp.path(), "echo hello > f");
        let queued = outbox.depth().ops;
        assert!(queued >= 1, "no operation queued after a write");

        gate.set(State::Joining);
        assert!(
            run_fails(tmp.path(), "echo blocked > g"),
            "a JOINING mount must refuse the write"
        );
        assert_eq!(outbox.depth().ops, queued);
        assert_eq!(run(tmp.path(), "cat f"), "hello\n");

        gate.set(State::Steady);
        run(tmp.path(), "echo later > g");
        assert!(outbox.depth().ops > queued);

        let _ = Command::new("fusermount3")
            .arg("-uz")
            .arg(tmp.path())
            .output();
        let unmount = session.umount_and_join();
        assert!(unmount.is_ok(), "unmount failed: {unmount:?}");
        assert!(!mounted(tmp.path()), "mountpoint still in /proc/mounts");
    }
}
