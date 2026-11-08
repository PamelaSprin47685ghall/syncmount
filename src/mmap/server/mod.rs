//! 1.1 `--mmap` HTTP server.
//!
//! The server exposes one namespace at `{ns}/mm/v1/*`. Every request and
//! response body is an SMM1 frame; the payload is streamed to a spool file and
//! authenticated before any database work starts.
//!
//! ```text
//! http      listener, exact routes, frame receive/stream, HTTP status map
//! auth      hello proof, session keys, request MAC and sequence gate
//! checkout  checkout, file/read, dir version
//! lock      upload lock acquire/renew/release and the expiry sweeper
//! upload    signatures, begin, commit, abort, batch status
//! manifest  wire <-> database manifest conversion and canonical hash
//! spool     per-batch spool directory and begin record
//! ```
//!
//! # Authority
//!
//! `mm_dirs`, `mm_files`, `mm_versions`, `mm_chunks`, `mm_base` and
//! `mm_dir_versions` are the only authority. One commit runs in a single
//! `BEGIN IMMEDIATE`; a failed batch leaves the tree, the global sequence and
//! the batch log untouched.
//!
//! # Isolation
//!
//! Nothing here reads or writes a 1.0 table, a 1.0 protocol frame or a 1.0
//! route. The server owns its own database file and listener.

#![allow(clippy::result_large_err)]

pub mod auth;
pub mod checkout;
pub mod http;
pub mod lock;
pub mod manifest;
pub mod spool;
pub mod upload;

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::mmap::db::{MmDb, MmTx};
use crate::mmap::proto::{
    AuthError, ErrorBody, ErrorCode, Limits, ProtoError, SessionGuard, SessionKeys,
};
use crate::mmap::types::{DirRecord, LockRecord, MmRole, MmSeq};
use crate::mmap::{MmError, now_ms};

use self::spool::Spool;

/// Upload lock lease.
pub const LOCK_TTL_MS: u64 = 60_000;
/// Progress interval that renews a lock during commit.
pub const RENEW_PROGRESS_BYTES: u64 = 8 * 1024 * 1024;
/// How long a commit extends the lock before it starts.
pub const COMMIT_LOCK_EXTENSION_MS: u64 = 5 * 60 * 1000;
/// Expired leases are collected this often.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// Idle session lifetime.
pub const SESSION_TTL_MS: u64 = 10 * 60 * 1000;
/// Sessions kept in memory at once.
pub const MAX_SESSIONS: usize = 4096;
/// Temporary request spool directory name under the spool root.
pub const TMP_DIR: &str = "tmp";
/// Per-batch spool directory name under the spool root.
pub const BATCH_DIR: &str = "batches";

/// Everything one mm server process needs.
#[derive(Clone)]
pub struct MmapConfig {
    /// TCP address to bind.
    pub listen: SocketAddr,
    /// URL prefix, such as `/private-mm`.
    pub namespace: String,
    /// SQLite file owned by this server.
    pub db_path: PathBuf,
    /// Directory holding per-batch spool trees.
    pub spool_dir: PathBuf,
    /// Master key; `K_hello` and every session key derive from it.
    pub master_key: [u8; 32],
    /// Advertised and enforced caps.
    pub limits: Limits,
    /// Upload lock lease, in milliseconds.
    pub lock_ttl_ms: u64,
    /// Idle session lifetime, in milliseconds.
    pub session_ttl_ms: u64,
    /// Maximum live sessions.
    pub max_sessions: usize,
}

impl fmt::Debug for MmapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapConfig")
            .field("listen", &self.listen)
            .field("namespace", &self.namespace)
            .field("db_path", &self.db_path)
            .field("spool_dir", &self.spool_dir)
            .field("master_key", &"<redacted>")
            .field("limits", &self.limits)
            .field("lock_ttl_ms", &self.lock_ttl_ms)
            .field("session_ttl_ms", &self.session_ttl_ms)
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

impl MmapConfig {
    /// Build a loopback configuration with production defaults.
    pub fn new(
        listen: SocketAddr,
        namespace: impl Into<String>,
        db_path: impl Into<PathBuf>,
        spool_dir: impl Into<PathBuf>,
        master_key: [u8; 32],
    ) -> Self {
        Self {
            listen,
            namespace: namespace.into(),
            db_path: db_path.into(),
            spool_dir: spool_dir.into(),
            master_key,
            limits: Limits::new(),
            lock_ttl_ms: LOCK_TTL_MS,
            session_ttl_ms: SESSION_TTL_MS,
            max_sessions: MAX_SESSIONS,
        }
    }

    /// The namespace label carried inside SMM1 messages.
    ///
    /// The URL prefix keeps its leading `/`; the wire label never contains
    /// one (the protocol's `check_namespace` rejects a separator).
    pub fn wire_namespace(&self) -> &str {
        self.namespace.strip_prefix('/').unwrap_or(&self.namespace)
    }
}

/// A live session.
#[derive(Debug)]
pub struct Session {
    /// Authenticated client id, copied from HELLO.
    pub client_id: [u8; 16],
    /// Session key.
    pub keys: SessionKeys,
    /// Expiry and sequence gate.
    pub guard: SessionGuard,
    /// Last accepted request, for idle expiry.
    pub last_seen_ms: i64,
}

/// Session metadata passed to one handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// Authenticated client id.
    pub client_id: [u8; 16],
    /// Server-assigned session id.
    pub session_id: [u8; 16],
}

/// Shared server state.
pub struct ServerState {
    config: MmapConfig,
    writer: Mutex<MmDb>,
    reader: std::sync::Mutex<MmDb>,
    spool: Spool,
    sessions: std::sync::Mutex<HashMap<[u8; 16], Session>>,
    nonces: std::sync::Mutex<crate::protocol::handshake::NonceReplayGuard>,
    started_ms: i64,
}

impl fmt::Debug for ServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ServerState {
    /// The configuration this server was built with.
    pub fn config(&self) -> &MmapConfig {
        &self.config
    }

    /// Open one independent read snapshot.
    pub(crate) fn read(&self) -> Result<crate::mmap::ReadTx, Fault> {
        let reader = self
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(reader.read()?)
    }

    /// The writer mutex.
    pub fn writer(&self) -> &Mutex<MmDb> {
        &self.writer
    }

    /// The per-batch spool.
    pub fn spool(&self) -> &Spool {
        &self.spool
    }

    /// Milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> i64 {
        now_ms()
    }

    /// The server start time.
    pub fn started_ms(&self) -> i64 {
        self.started_ms
    }

    /// Number of live sessions, for `healthz`.
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Reject a message addressed to another namespace.
    pub(crate) fn check_wire_namespace(&self, namespace: &str) -> Result<(), Fault> {
        if namespace == self.config.wire_namespace() {
            Ok(())
        } else {
            Err(Fault::detail(
                ErrorCode::BadRequest,
                "message namespace does not match this server",
            ))
        }
    }
}

/// A bound mm server.
pub struct MmapServer {
    state: Arc<ServerState>,
    listener: TcpListener,
}

impl fmt::Debug for MmapServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapServer")
            .field("state", &self.state)
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl MmapServer {
    /// Open the database, recover abandoned uploads and bind the listener.
    pub async fn bind(config: MmapConfig) -> Result<Self, ServerError> {
        validate_config(&config)?;
        let mut writer = MmDb::open(&config.db_path, MmRole::Server, &config.namespace)?;
        let reader = MmDb::open(&config.db_path, MmRole::Server, &config.namespace)?;
        let spool = Spool::open(&config.spool_dir)
            .map_err(|error| ServerError::Spool(error.to_string()))?;
        recover(&mut writer, &spool)?;
        let listener = TcpListener::bind(config.listen).await?;
        let state = Arc::new(ServerState {
            config,
            writer: Mutex::new(writer),
            reader: std::sync::Mutex::new(reader),
            spool,
            sessions: std::sync::Mutex::new(HashMap::new()),
            nonces: std::sync::Mutex::new(crate::protocol::handshake::NonceReplayGuard::new()),
            started_ms: now_ms(),
        });
        Ok(Self { state, listener })
    }

    /// Bound address, including the ephemeral port chosen by the OS.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Shared state, for tests and diagnostics.
    pub fn state(&self) -> Arc<ServerState> {
        Arc::clone(&self.state)
    }

    /// Run until the listener closes.
    pub async fn run(self) {
        self.run_with_shutdown(std::future::pending()).await;
    }

    /// Run the accept loop until `shutdown` resolves.
    pub async fn run_with_shutdown(self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let sweeper_state = Arc::clone(&self.state);
        let sweeper = tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                sweeper_state.sweep_once().await;
            }
        });
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { break };
                    let _ = stream.set_nodelay(true);
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        http::serve_connection(state, stream).await;
                    });
                }
            }
        }
        sweeper.abort();
    }
}

/// Why the server could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Database open or recovery failed.
    #[error("mm database: {0}")]
    Database(#[from] MmError),
    /// Spool setup failed.
    #[error("spool: {0}")]
    Spool(String),
    /// Listener bind failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The configuration is not usable.
    #[error("configuration: {0}")]
    Config(&'static str),
}

impl From<rusqlite::Error> for ServerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(MmError::Sqlite(error))
    }
}

fn validate_config(config: &MmapConfig) -> Result<(), ServerError> {
    if !config.namespace.starts_with('/') {
        return Err(ServerError::Config("namespace must start with '/'"));
    }
    if config.namespace.len() < 2 {
        return Err(ServerError::Config("namespace must name one prefix"));
    }
    if config.namespace.ends_with('/') {
        return Err(ServerError::Config("namespace must not end with '/'"));
    }
    if config.namespace[1..].contains('/') {
        return Err(ServerError::Config(
            "namespace must be a single component; SMM1 labels cannot contain '/'",
        ));
    }
    if config.lock_ttl_ms == 0 || config.session_ttl_ms == 0 {
        return Err(ServerError::Config("timeouts must be non-zero"));
    }
    config
        .limits
        .validate()
        .map_err(|_| ServerError::Config("invalid limits"))?;
    Ok(())
}

/// Mark every upload that survived the last process as aborted and remove its
/// spool. Committed batches and directory versions stay.
fn recover(writer: &mut MmDb, spool: &Spool) -> Result<(), ServerError> {
    let tx = writer.write()?;
    {
        let mut stmt = tx
            .conn()
            .prepare("SELECT spool_path FROM mm_uploads WHERE state <> 'aborted'")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let path = PathBuf::from(row?);
            let _ = std::fs::remove_dir_all(path);
        }
    }
    tx.conn()
        .execute("UPDATE mm_uploads SET state = 'aborted'", [])?;
    tx.conn().execute("DELETE FROM mm_locks", [])?;
    tx.commit()?;
    spool.clear_batches()?;
    spool.clear_tmp()?;
    Ok(())
}

/// A terminal server error, already shaped as an SMM1 `ERROR` body.
#[derive(Debug)]
pub struct Fault {
    /// The wire body.
    pub body: ErrorBody,
}

impl Fault {
    /// A code-only fault.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            body: ErrorBody::new(code),
        }
    }

    /// A fault with a human-readable detail.
    pub fn detail(code: ErrorCode, detail: impl Into<String>) -> Self {
        let mut body = ErrorBody::new(code);
        body.detail = Some(truncate_detail(detail.into()));
        Self { body }
    }

    /// A code-specific fault with extra fields.
    pub fn body(mut body: ErrorBody) -> Self {
        body.detail = body.detail.map(truncate_detail);
        Self { body }
    }

    /// The HTTP status this fault maps to.
    pub fn status(&self) -> u16 {
        self.body.http_status()
    }

    /// `BASE_CHANGED` with the server's current base.
    pub fn base_changed(dir: &DirRecord, snapshot: MmSeq, request_base: u64) -> Self {
        let mut body = ErrorBody::new(ErrorCode::BaseChanged);
        body.detail = Some("directory changed".to_owned());
        body.dir_path = Some(dir.path.clone());
        body.dir_ino = Some(dir.ino);
        body.epoch = Some(dir.base.epoch);
        body.snapshot_seq = Some(snapshot.get());
        body.base_seq = Some(dir.base.dir_seq.get());
        body.request_base_seq = Some(request_base);
        body.dir_version = Some(dir.base.dir_version);
        Self { body }
    }

    /// `LOCK_HELD` with the current owner.
    pub fn lock_held(lock: &LockRecord) -> Self {
        let mut body = ErrorBody::new(ErrorCode::LockHeld);
        body.detail = Some("directory is being uploaded".to_owned());
        body.owner_client = Some(lock.owner_client);
        body.expires_at_ms = u64::try_from(lock.expires_at_ms).ok();
        body.retry_after_ms = Some(15_000);
        body.dir_path = Some(lock.dir_path.clone());
        body.dir_ino = Some(lock.dir_ino);
        Self { body }
    }

    /// `LOCK_LOST`.
    pub fn lock_lost(reason: impl Into<String>) -> Self {
        let mut body = ErrorBody::new(ErrorCode::LockLost);
        body.reason = Some(truncate_detail(reason.into()));
        Self { body }
    }

    /// `LOCK_EXPIRED`.
    pub fn lock_expired(lock: &LockRecord) -> Self {
        let mut body = ErrorBody::new(ErrorCode::LockExpired);
        body.reason = Some("lease expired".to_owned());
        body.owner_client = Some(lock.owner_client);
        body.expires_at_ms = u64::try_from(lock.expires_at_ms).ok();
        body.dir_path = Some(lock.dir_path.clone());
        body.dir_ino = Some(lock.dir_ino);
        Self { body }
    }

    /// `MANIFEST_INCOMPLETE`.
    pub fn manifest_incomplete(missing: Vec<String>) -> Self {
        let mut body = ErrorBody::new(ErrorCode::ManifestIncomplete);
        body.detail = Some("manifest omits direct entries".to_owned());
        body.missing = missing;
        Self { body }
    }

    /// `HASH_MISMATCH`, asking the client for a full retry.
    pub fn hash_mismatch(expected: [u8; 32], actual: [u8; 32]) -> Self {
        let mut body = ErrorBody::new(ErrorCode::HashMismatch);
        body.detail = Some("rebuilt file hash differs from the manifest".to_owned());
        body.expected = Some(expected);
        body.actual = Some(actual);
        body.retry_full = true;
        Self { body }
    }

    /// `SIZE_MISMATCH`, asking the client for a full retry.
    pub fn size_mismatch(expected: u64, actual: u64) -> Self {
        let mut body = ErrorBody::new(ErrorCode::SizeMismatch);
        body.detail = Some(format!(
            "rebuilt file is {actual} bytes, manifest says {expected}"
        ));
        body.retry_full = true;
        Self { body }
    }

    /// `INSTRUCTION_MISMATCH`.
    pub fn instruction(detail: impl Into<String>) -> Self {
        Self::detail(ErrorCode::InstructionMismatch, detail)
    }

    /// `NAME_CONFLICT`.
    pub fn name_conflict(detail: impl Into<String>) -> Self {
        Self::detail(ErrorCode::NameConflict, detail)
    }

    /// `INO_CONFLICT`.
    pub fn ino_conflict() -> Self {
        Self::detail(ErrorCode::InoConflict, "client inode is already in use")
    }

    fn internal(detail: impl Into<String>) -> Self {
        Self::detail(ErrorCode::Internal, detail)
    }
}

impl From<ProtoError> for Fault {
    fn from(error: ProtoError) -> Self {
        let code = error.error_code();
        Self::detail(code, error.to_string())
    }
}

impl From<AuthError> for Fault {
    fn from(error: AuthError) -> Self {
        Self::detail(error.code(), error.to_string())
    }
}

impl From<MmError> for Fault {
    fn from(error: MmError) -> Self {
        match error {
            MmError::NotFound => Self::new(ErrorCode::DirNotFound),
            other => Self::internal(other.to_string()),
        }
    }
}

impl From<std::io::Error> for Fault {
    fn from(error: std::io::Error) -> Self {
        if error.raw_os_error() == Some(28) {
            Self::detail(ErrorCode::NoSpace, "spool filesystem is full")
        } else {
            Self::internal(format!("i/o: {error}"))
        }
    }
}

impl From<rusqlite::Error> for Fault {
    fn from(error: rusqlite::Error) -> Self {
        Self::internal(format!("sqlite: {error}"))
    }
}

impl From<crate::mmap::rsync::RsyncError> for Fault {
    fn from(error: crate::mmap::rsync::RsyncError) -> Self {
        use crate::mmap::rsync::RsyncError as E;
        match error {
            E::StrongMismatch { .. } | E::HashMismatch => Self::hash_mismatch([0u8; 32], [0u8; 32]),
            E::LengthMismatch { expected, actual } => Self::size_mismatch(expected, actual),
            E::TooManyBlocks { .. } => Self::detail(ErrorCode::TooManyBlocks, error.to_string()),
            E::Io(_) => Self::from(std::io::Error::other(error.to_string())),
            other => Self::instruction(other.to_string()),
        }
    }
}

fn truncate_detail(mut detail: String) -> String {
    const MAX: usize = 512;
    if detail.len() > MAX {
        let mut end = MAX;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

/// Milliseconds since the Unix epoch, saturating at zero.
pub fn now_u64() -> u64 {
    u64::try_from(now_ms()).unwrap_or(0)
}

/// Join a parent directory path and one entry name.
pub fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// True when `path` equals `prefix` or lives below it.
pub fn path_is_within(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

/// True when two subtree roots overlap.
pub fn paths_overlap(left: &str, right: &str) -> bool {
    path_is_within(left, right) || path_is_within(right, left)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests;
