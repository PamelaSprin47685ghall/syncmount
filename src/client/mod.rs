//! Client entry point: open the SQLite replica, mount the view, run a session.
//!
//! The client has one persistent state, `client.db`. The mountpoint is a view
//! produced by [`crate::fuse::sqlite::SqliteFs`]; unmounting leaves the data
//! in the database, not in the directory. There is no manifest, snapshot,
//! self-view or bootstrap exchange: replay starts at
//! `meta.applied_seq + 1`, and an epoch change clears the replica and replays
//! the compacted stream from zero.
//!
//! ```text
//! BOOT -> LOCKED -> MOUNTING -> JOINING -> STEADY -> UNMOUNTING -> EXITED
//! ```
//!
//! The lifecycle is deliberately short, but a transient transport end does
//! not unmount: the driver reconnects from the durable `applied_seq` with a
//! bounded backoff. After the budget is exhausted the process exits with
//! [`lifecycle::EXIT_DISCONNECTED`]; the next start resends the outbox.

pub mod config;
pub mod db;
pub mod import;
pub mod lifecycle;
pub mod net;
pub mod ops;
pub mod replay;
pub mod session;
pub mod status;
pub mod writeback;
pub mod writer;

use std::env;
#[cfg(feature = "fuse")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "fuse")]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "fuse")]
use std::time::Instant;

use crate::protocol::crypto::PskKeyRing;
#[cfg(feature = "fuse")]
use crate::store::runtime_dir::RuntimeDir;

/// Consecutive short sessions allowed before the mount gives up.
#[cfg(feature = "fuse")]
const RECONNECT_ATTEMPTS: u32 = 6;
/// First reconnect delay; doubles per attempt up to 32x.
#[cfg(feature = "fuse")]
const RECONNECT_BASE: Duration = Duration::from_secs(1);
/// Ceiling for the reconnect delay.
///
/// An endpoint that is down for minutes must not turn every client into a
/// tight reconnect loop; the in-process budget still ends after a handful of
/// attempts and systemd restarts the process.
#[cfg(feature = "fuse")]
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// A session that lived this long resets the reconnect budget.
#[cfg(feature = "fuse")]
const HEALTHY_SESSION: Duration = Duration::from_secs(10);

pub use config::{Config, Tuning};
pub use db::{ClientDb, DbError};
pub use import::{ImportError, ImportOptions, ImportReport, import_into, import_tree};
pub use lifecycle::{State, WriteGate};
pub use session::SessionOptions;
pub use status::{Conntrace, Counters, StatusSnapshot, StatusWriter};
pub use writeback::{WritebackConfig, WritebackStats};

/// Environment variable holding an explicit database path.
pub const ENV_DB: &str = "SYNCMOUNT_DB";
/// Environment variable holding the state root.
pub const ENV_STATE_DIR: &str = "SYNCMOUNT_STATE_DIR";

/// Everything the client needs before it opens a connection.
#[derive(Clone, Debug)]
pub struct Client {
    config: Config,
    db_path: Option<PathBuf>,
    allow_other: bool,
    gate: Arc<WriteGate>,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
}

impl Client {
    /// Assemble the client from a validated configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            db_path: None,
            allow_other: false,
            gate: Arc::new(WriteGate::new(State::Boot)),
            counters: Arc::new(Counters::default()),
            conntrace: Arc::new(Conntrace::default()),
        }
    }

    /// Configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The write gate shared with FUSE.
    pub fn gate_handle(&self) -> Arc<WriteGate> {
        Arc::clone(&self.gate)
    }

    /// Shared counters.
    pub const fn counters(&self) -> &Arc<Counters> {
        &self.counters
    }

    /// Shared connection trace.
    pub const fn conntrace(&self) -> &Arc<Conntrace> {
        &self.conntrace
    }

    /// Mount with `allow_other` (`SessionACL::All`).
    pub fn with_allow_other(mut self, allow_other: bool) -> Self {
        self.allow_other = allow_other;
        self
    }

    /// Override the database path (`--db`).
    pub fn with_database_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.db_path = Some(path.into());
        self
    }

    /// The database path this client uses.
    pub fn database_path(&self) -> PathBuf {
        self.db_path
            .clone()
            .unwrap_or_else(|| database_path(&self.config))
    }

    /// Run the client until it disconnects or receives a stop signal.
    ///
    /// Returns the process exit code.
    #[cfg(feature = "fuse")]
    pub async fn run(self, ring: PskKeyRing, cluster: [u8; 16]) -> Result<i32, ClientError> {
        let db_path = self.database_path();
        tracing::info!(
            event = "startup",
            mount_id = %self.config.mount_id,
            mountpoint = %self.config.mountpoint.display(),
            database = %db_path.display(),
            "opening the client database"
        );
        let store = Arc::new(ClientDb::open(&db_path, cluster)?);
        // A previous version could leave a removed directory live and
        // nameless, or a name dangling after an overtaken create. Repair only
        // those invisible rows before the mount exposes the tree.
        match store.repair_replica_metadata() {
            Ok(report) if report.changed() => tracing::warn!(
                event = "replica_repair",
                issues = report.issues,
                roots = report.roots,
                tombstones = report.tombstones,
                nlinks = report.nlinks,
                names_removed = report.names_removed,
                paths = report.paths,
                "repaired replicated tree metadata"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                event = "replica_repair",
                error = %error,
                "cannot repair replicated tree metadata"
            ),
        }
        store.start_writeback();
        store.start_checkpoint();
        self.gate.set(State::Mounting);
        cleanup_stale(&self.config.mountpoint)?;

        let filesystem =
            crate::fuse::sqlite::SqliteFs::new(Arc::clone(&store), Arc::clone(&self.gate));
        let mount_config = crate::fuse::mount_config_with(self.allow_other);
        let session = fuser::spawn_mount(filesystem, &self.config.mountpoint, &mount_config)
            .map_err(|error| ClientError::Mount(error.to_string()))?;
        self.gate.set(State::Joining);

        let status = self.start_status(&store);
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
        spawn_signal_task(shutdown_tx);
        let mut shutdown_rx = shutdown_rx;
        let mut attempts = 0u32;
        let exit = loop {
            let started = Instant::now();
            let applied_before = store.applied_seq().unwrap_or(0);
            let exit = session::run(
                Arc::clone(&store),
                SessionOptions {
                    endpoint: transport_endpoint(&self.config)?,
                    ring: ring.clone(),
                    mount_id: self.config.mount_id.clone(),
                },
                Arc::clone(&self.gate),
                Arc::clone(&self.counters),
                Arc::clone(&self.conntrace),
                &mut shutdown_rx,
            )
            .await;
            // A rejection, a transport end, or a failed dial keeps the mount
            // up: the next handshake advertises the durable applied_seq and
            // the server replays the missing events. A first dial gets the
            // same bounded backoff, because a proxy in front of a restarting
            // origin answers 502/503/504 and a socket timeout is equally
            // transient. Authentication (4) and local failures keep their
            // fail-fast exits and are not retried here.
            let retryable = retryable_session_exit(&exit);
            if retryable {
                // A slow client may be kicked repeatedly while it is still
                // applying events. Progress (or a long healthy session) is
                // what resets the budget, not a clean exit.
                let applied_after = store.applied_seq().unwrap_or(0);
                if exit.reason == "resync"
                    && (applied_after > applied_before || started.elapsed() >= HEALTHY_SESSION)
                {
                    attempts = 0;
                }
                attempts = attempts.saturating_add(1);
                if attempts > RECONNECT_ATTEMPTS {
                    tracing::error!(event = "reconnect", attempts, "reconnect budget exhausted");
                    break session::SessionExit {
                        code: lifecycle::EXIT_DISCONNECTED,
                        reason: "reconnect budget",
                    };
                }
                let backoff = reconnect_delay(attempts);
                tracing::warn!(
                    event = "reconnect",
                    attempt = attempts,
                    ?backoff,
                    "reconnecting to replay the server log"
                );
                // The mount stays up while the session is down; writes wait
                // as EROFS instead of seeing ENOTCONN.
                self.gate.set(State::Joining);
                tokio::time::sleep(backoff).await;
                continue;
            }
            break exit;
        };

        self.gate.set(State::Unmounting);
        if let Some(task) = status {
            task.abort();
        }
        unmount(session, &self.config.mountpoint);
        store.stop_checkpoint();
        store.stop_writeback();
        let _ = store.fsync();
        let _ = store.checkpoint_truncate();
        let _ = store.gc_chunks();
        let writeback = store.writeback_stats();
        tracing::info!(
            event = "writeback",
            buffered = writeback.buffered_bytes,
            peak = writeback.peak_bytes,
            commits = writeback.commits,
            flushes = writeback.flushes,
            cap_hits = writeback.cap_hits,
            dropped = writeback.dropped_bytes,
            errors = writeback.commit_errors,
            "write-back buffer summary"
        );
        self.gate.set(State::Exited);
        tracing::info!(
            event = "exit",
            code = exit.code,
            reason = exit.reason,
            applied = store.applied_seq().unwrap_or(0),
            "client stopped"
        );
        Ok(exit.code)
    }

    /// Run without FUSE support: refuse, because the view is the product.
    #[cfg(not(feature = "fuse"))]
    pub async fn run(self, _ring: PskKeyRing, _cluster: [u8; 16]) -> Result<i32, ClientError> {
        Err(ClientError::NoFuse)
    }

    #[cfg(feature = "fuse")]
    fn start_status(&self, store: &Arc<ClientDb>) -> Option<tokio::task::JoinHandle<()>> {
        let base = env::var_os("SYNCMOUNT_RUN_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/syncmount"));
        let dir = RuntimeDir::create_in(&base, &self.config.mount_id)
            .or_else(|_| {
                let fallback = env::var_os("XDG_RUNTIME_DIR")
                    .map(|value| PathBuf::from(value).join("syncmount"))
                    .unwrap_or_else(|| base.clone());
                RuntimeDir::create_in(&fallback, &self.config.mount_id)
            })
            .ok()?;
        let writer = StatusWriter::new(dir, self.config.tuning.status_interval);
        let store = Arc::clone(store);
        let counters = Arc::clone(&self.counters);
        let conntrace = Arc::clone(&self.conntrace);
        let gate = Arc::clone(&self.gate);
        let mount_id = self.config.mount_id.clone();
        Some(tokio::spawn(async move {
            loop {
                let snapshot = build_status(&mount_id, &store, &counters, &conntrace, &gate);
                if let Err(error) = writer.write(&snapshot) {
                    tracing::warn!(event = "status", error = %error, "cannot publish the status document");
                }
                tokio::time::sleep(writer.interval()).await;
            }
        }))
    }
}

#[cfg(feature = "fuse")]
fn reconnect_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(5);
    RECONNECT_BASE
        .saturating_mul(1u32 << shift)
        .min(RECONNECT_MAX)
}

/// Whether the driver may reconnect after this session outcome.
///
/// Only transient transport outcomes are retried. A KICK, an authentication
/// rejection and every local failure stay terminal for this process, so a
/// persistent protocol or credential error is not hidden behind a restart
/// loop. The dial and handshake variants are marked retryable only when the
/// session mapped them to [`lifecycle::EXIT_DISCONNECTED`]; the same reason
/// with [`lifecycle::EXIT_STARTUP`] is permanent.
#[cfg(feature = "fuse")]
fn retryable_session_exit(exit: &session::SessionExit) -> bool {
    exit.code == lifecycle::EXIT_DISCONNECTED
        && matches!(
            exit.reason,
            "resync" | "dial" | "dial timeout" | "handshake"
        )
}

#[cfg(feature = "fuse")]
fn transport_endpoint(config: &Config) -> Result<crate::transport::Endpoint, ClientError> {
    let url = format!(
        "{}://{}:{}{}",
        config.endpoint.scheme.as_str(),
        config.endpoint.host,
        config.endpoint.port,
        config.endpoint.prefix
    );
    crate::transport::Endpoint::parse(&url)
        .map_err(|error| ClientError::Config(format!("endpoint: {error}")))
}

#[cfg(feature = "fuse")]
fn build_status(
    mount_id: &str,
    store: &ClientDb,
    counters: &Counters,
    conntrace: &Conntrace,
    gate: &WriteGate,
) -> StatusSnapshot {
    let applied = store.applied_seq().unwrap_or(0).max(0) as u64;
    let epoch = store.epoch().unwrap_or(0).max(0) as u64;
    let (ops, bytes) = store.outbox_depth().unwrap_or((0, 0));
    let pending = store.pending_outbox().unwrap_or(0);
    StatusSnapshot::new(
        mount_id.to_owned(),
        gate.state().as_str(),
        crate::protocol::frame::Seq(applied),
        epoch,
    )
    .with_outbox(status::OutboxStatus { ops, bytes })
    .with_replay(status::ReplayStatus {
        pending,
        ..status::ReplayStatus::default()
    })
    .with_counters(counters.snapshot())
    .with_conntrace(conntrace.snapshot())
}

/// Resolve the SQLite path.
///
/// `SYNCMOUNT_DB` wins; otherwise `SYNCMOUNT_STATE_DIR` (or the XDG data
/// directory) plus the endpoint namespace.
pub fn database_path(config: &Config) -> PathBuf {
    if let Some(path) = env::var_os(ENV_DB) {
        return PathBuf::from(path);
    }
    let base = env::var_os(ENV_STATE_DIR)
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_DATA_HOME").map(|value| PathBuf::from(value).join("syncmount"))
        })
        .or_else(|| {
            env::var_os("HOME").map(|value| PathBuf::from(value).join(".local/share/syncmount"))
        })
        .unwrap_or_else(|| PathBuf::from("/var/lib/syncmount"));
    let namespace = config.endpoint.prefix.trim_matches('/');
    let namespace = if namespace.is_empty() {
        "root".to_owned()
    } else {
        namespace.replace('/', "_")
    };
    base.join(namespace).join("client.db")
}

#[cfg(feature = "fuse")]
fn spawn_signal_task(shutdown: tokio::sync::mpsc::Sender<()>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
                _ = hup.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = shutdown.send(()).await;
    });
}

#[cfg(feature = "fuse")]
fn cleanup_stale(mountpoint: &Path) -> Result<(), ClientError> {
    if !is_mounted(mountpoint) {
        return Ok(());
    }
    tracing::warn!(
        event = "stale_mount",
        mountpoint = %mountpoint.display(),
        "unmounting a stale session"
    );
    if fusermount("-uz", mountpoint) {
        return Ok(());
    }
    Err(ClientError::Mount(format!(
        "{} is still mounted and cannot be released",
        mountpoint.display()
    )))
}

#[cfg(feature = "fuse")]
fn unmount(session: fuser::BackgroundSession, mountpoint: &Path) {
    // `umount_and_join` blocks on the FUSE worker threads, which can stay
    // parked when the session ended because of a handshake failure, a KICK,
    // or SIGTERM. Bound the wait and force the release from outside.
    const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(2);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(session.umount_and_join().is_ok());
    });
    match done_rx.recv_timeout(UNMOUNT_TIMEOUT) {
        Ok(true) => return,
        Ok(false) => tracing::warn!(
            event = "unmount",
            mountpoint = %mountpoint.display(),
            "clean unmount failed; forcing"
        ),
        Err(_) => tracing::warn!(
            event = "unmount",
            mountpoint = %mountpoint.display(),
            "clean unmount timed out; forcing"
        ),
    }
    let _ = fusermount("-uz", mountpoint);
}

#[cfg(feature = "fuse")]
fn fusermount(flag: &str, mountpoint: &Path) -> bool {
    Command::new("fusermount3")
        .arg(flag)
        .arg(mountpoint)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(feature = "fuse")]
fn is_mounted(mountpoint: &Path) -> bool {
    let needle = mountpoint.to_string_lossy().to_string();
    std::fs::read_to_string("/proc/mounts")
        .map(|mounts| {
            mounts.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|point| point == needle)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Why the client could not start or stay up.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("database: {0}")]
    Db(#[from] DbError),
    #[error("mount: {0}")]
    Mount(String),
    #[error("this build has no FUSE support; rebuild with the `fuse` feature")]
    NoFuse,
    #[error("configuration: {0}")]
    Config(String),
}

/// Status refresh interval used by tests.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(all(test, feature = "fuse"))]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_is_bounded_exponential_backoff() {
        let delays: Vec<Duration> = (1..=7).map(reconnect_delay).collect();
        assert_eq!(
            delays,
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
            .to_vec()
        );
        assert_eq!(reconnect_delay(0), Duration::from_secs(1));
    }

    #[test]
    fn only_transient_session_exits_are_retried() {
        let retryable = |code, reason| session::SessionExit { code, reason };
        assert!(retryable_session_exit(&retryable(
            lifecycle::EXIT_DISCONNECTED,
            "dial"
        )));
        assert!(retryable_session_exit(&retryable(
            lifecycle::EXIT_DISCONNECTED,
            "handshake"
        )));
        assert!(retryable_session_exit(&retryable(
            lifecycle::EXIT_DISCONNECTED,
            "resync"
        )));
        assert!(retryable_session_exit(&retryable(
            lifecycle::EXIT_DISCONNECTED,
            "dial timeout"
        )));

        // A permanent dial failure keeps EXIT_STARTUP.
        assert!(!retryable_session_exit(&retryable(
            lifecycle::EXIT_STARTUP,
            "dial"
        )));
        assert!(!retryable_session_exit(&retryable(
            lifecycle::EXIT_AUTH,
            "authentication"
        )));
        // A KICK is a deliberate server decision, not a transient end.
        assert!(!retryable_session_exit(&retryable(
            lifecycle::EXIT_DISCONNECTED,
            "disconnected"
        )));
    }
}
